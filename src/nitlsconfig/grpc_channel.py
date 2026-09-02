"""Create gRPC channels to the NI gRPC Device Server from NI TLS (nitlsconfig) configuration.

Reads the local NI TLS client configuration for the NI gRPC Device Server and
produces a :class:`grpc.Channel` secured with TLS/mTLS, or a plain insecure
channel when TLS has been explicitly toggled off.

The resulting channel is a normal ``grpc.Channel``. It can be handed directly to
any NI gRPC Python API, for example::

    from nitlsconfig.grpc_channel import create_grpc_device_channel

    channel = create_grpc_device_channel("localhost", 31763)
    options = nidcpower.GrpcSessionOptions(channel, "")
    with nidcpower.Session("Dev1", grpc_options=options) as session:
        ...

Channel ownership stays with the caller, matching the NI Python driver APIs,
which never close the channel themselves. ``grpc.Channel`` is already a context
manager, so ``with create_grpc_device_channel(...) as channel:`` works as expected.

The NI gRPC Device Server is the only service this factory builds channels for.
Other services can still be read through :class:`~nitlsconfig.cli.ClientConfig`;
a configurable service name can be added later without breaking this signature.

:func:`~nitlsconfig.errors.get_tls_connection_error_elaboration` recognizes a
channel built here, so a driver API can tell the caller that a failure to connect
may be TLS-related, which gRPC's status codes cannot express on their own.

``server_mode`` Disabled selects a plain connection. Every other mode verifies
the server certificate chain and checks the hostname.

When the server certificate's CN/SAN does not match the dialed host, pass
``grpc.ssl_target_name_override`` via ``options`` instead. That substitutes the
name gRPC matches against the certificate; it does not disable verification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence, Tuple

import grpc

from nitlsconfig._service import SERVICE_NAME
from nitlsconfig.audit import (
    _TransportSecurity,
    _audit_transport_posture,
)
from nitlsconfig.channel_tag import tag_channel_target
from nitlsconfig.cli import (
    ClientCertMode,
    ClientConfig,
    ClientServerMode,
    LocationScheme,
)
from nitlsconfig.errors import TlsConfigurationError

__all__ = [
    "RetryPolicy",
    "TlsConfigurationError",
    "create_grpc_device_channel",
]

# gRPC channel argument that carries a service config JSON document.
_SERVICE_CONFIG_ARG = "grpc.service_config"

ChannelOptions = Sequence[Tuple[str, Any]]


def _format_target(server_address: str, server_port: int) -> str:
    """Join an address and port into a gRPC target, bracketing IPv6 literals.

    gRPC requires IPv6 literals in brackets: ``::1:31763`` never connects,
    while ``[::1]:31763`` does. An unbracketed address containing a colon can
    only be an IPv6 literal, since neither host names nor IPv4 addresses may
    contain one.
    """
    if ":" in server_address and not server_address.startswith("["):
        return f"[{server_address}]:{server_port}"
    return f"{server_address}:{server_port}"


@dataclass(frozen=True)
class RetryPolicy:
    """Client retry behavior, realized as a gRPC service config.

    The mechanism and backoff algorithm are defined by gRFC A6 (gRPC Retry
    Design); the values below are this package's defaults. Retries are opt-in:
    gRPC configures no retry policy unless one is supplied.

    The policy applies to every method, including non-idempotent ones.
    ``UNAVAILABLE`` does not guarantee the server never processed the request,
    so a retried operation can be applied twice. It also covers TLS handshake
    failures, which gRPC reports as ``UNAVAILABLE``.
    """

    max_attempts: int = 5
    initial_delay_ms: int = 100
    max_delay_ms: int = 1000
    backoff_multiplier: float = 2.0


@dataclass(frozen=True)
class _ClientTlsSettings:
    """Validated client TLS settings, ready to be turned into channel credentials.

    The trust anchor *scheme* is deliberately not carried here. gRPC consumes
    only the in-memory PEM, and SystemDefault is already represented by empty
    ``trusted_contents``, which :func:`_pem_bytes` maps to None. Add the scheme
    back if a future caller needs to distinguish the two.
    """

    present_client_cert: bool
    certificate_chain_contents: str
    # Kept out of the generated repr so a traceback or debug log cannot print the key.
    private_key_contents: str = field(repr=False)
    trusted_contents: str


def _milliseconds_to_duration(milliseconds: int) -> str:
    """Format milliseconds as a gRPC duration string, e.g. 100 -> '0.100s'."""
    milliseconds = max(milliseconds, 0)
    return f"{milliseconds // 1000}.{milliseconds % 1000:03d}s"


def _build_retry_service_config(policy: RetryPolicy) -> Optional[str]:
    """Build a gRPC service config JSON document that enables retries.

    Returns None when the policy asks for no retries. gRPC requires
    maxAttempts >= 2, strictly positive backoffs, and a strictly positive
    backoff multiplier, so anything less means "do not configure retries"
    rather than an error.
    """
    if (
        policy.max_attempts < 2
        or policy.initial_delay_ms <= 0
        or policy.max_delay_ms <= 0
        or policy.backoff_multiplier <= 0
    ):
        return None

    return json.dumps(
        {
            "methodConfig": [
                {
                    # An empty method name applies the policy to every method.
                    "name": [{}],
                    "retryPolicy": {
                        "maxAttempts": policy.max_attempts,
                        "initialBackoff": _milliseconds_to_duration(policy.initial_delay_ms),
                        "maxBackoff": _milliseconds_to_duration(policy.max_delay_ms),
                        "backoffMultiplier": policy.backoff_multiplier,
                        "retryableStatusCodes": ["UNAVAILABLE"],
                    },
                }
            ]
        }
    )


def _apply_retry_policy(
    options: ChannelOptions, policy: Optional[RetryPolicy]
) -> list[Tuple[str, Any]]:
    """Return channel options with the retry service config appended, if applicable."""
    channel_options = list(options)
    if policy is None:
        return channel_options

    # gRPC resolves duplicate entries by taking the first, so a caller-supplied
    # service config already takes effect and must not be overridden.
    if any(key == _SERVICE_CONFIG_ARG for key, _ in channel_options):
        return channel_options

    service_config = _build_retry_service_config(policy)
    if service_config is not None:
        channel_options.append((_SERVICE_CONFIG_ARG, service_config))
    return channel_options


def _require_contents(contents: str, description: str, service_name: str) -> str:
    """Validate that configured certificate material is actually present.

    Empty contents mean the material could not be produced (missing, unreadable,
    not yet provisioned, or named by a scheme nitlsconfig cannot resolve), never
    that the client opted out. Opting out is expressed by the configuration
    itself: ``certificate_mode`` Disabled for the client identity, and the
    SystemDefault scheme for trust anchors. Neither reaches this check.
    """
    if not contents:
        raise TlsConfigurationError(
            f"{TlsConfigurationError._MESSAGE} The client {description} is missing on this "
            f"system for service {service_name!r}."
        )
    return contents


def _load_client_tls_settings(config: ClientConfig) -> Optional[_ClientTlsSettings]:
    """Read and validate client TLS settings, or None when TLS is not in use.

    ``server_mode`` is the master switch: when it is Disabled the client uses a
    plain connection and ``certificate_mode`` is not consulted at all.
    """
    service_name = config.service_name

    # Disabled is the only mode that turns TLS off. TrustAlways, SkipHostnameValidation,
    # and Unknown all fall through to full chain and hostname verification, because gRPC's
    # Python API cannot relax either check independently: that needs a custom certificate
    # verifier, which grpcio does not bind in Python, where the TLS surface is limited to
    # grpc.ssl_channel_credentials. Verifying when asked not to fails closed, so those
    # callers get a stricter connection than requested rather than a weaker one.
    if config.server_mode == ClientServerMode.Disabled:
        return None

    # certificate_mode only decides mTLS versus one-way TLS. Disabled is the only mode
    # that skips the client certificate, so Unknown presents one and fails closed if
    # the material is not provisioned.
    present_client_cert = config.certificate_mode != ClientCertMode.Disabled

    certificate_chain_contents = ""
    private_key_contents = ""
    if present_client_cert:
        certificate_chain_contents = _require_contents(
            config.certificate_chain_contents, "certificate chain", service_name
        )
        private_key_contents = _require_contents(
            config.certificate_key_contents, "certificate key", service_name
        )

    # Trust anchors are always required: the client must verify the server.
    # SystemDefault means "use the platform certificate store" and carries no
    # contents. Every other scheme names specific anchors that nitlsconfig
    # resolves into a single PEM bundle, so the contents check below covers an
    # unrecognized scheme without rejecting one this version has yet to learn.
    trusted_location = config.trusted_certificates_location

    trusted_contents = ""
    if trusted_location.scheme != LocationScheme.SystemDefault:
        trusted_contents = _require_contents(
            config.trusted_certificates_contents, "trusted certificate bundle", service_name
        )

    return _ClientTlsSettings(
        present_client_cert=present_client_cert,
        certificate_chain_contents=certificate_chain_contents,
        private_key_contents=private_key_contents,
        trusted_contents=trusted_contents,
    )


def _pem_bytes(contents: str) -> Optional[bytes]:
    """Encode PEM text for gRPC, mapping empty contents to None.

    nitlsconfig represents the SystemDefault trust scheme as empty contents,
    meaning "use the platform default certificate store". Python requires None
    for that behavior: passing empty bytes would instead configure an empty
    trust store and fail every connection.
    """
    return contents.encode("utf-8") if contents else None


def _make_client_credentials(settings: _ClientTlsSettings) -> grpc.ChannelCredentials:
    """Build channel credentials from validated client TLS settings."""
    certificate_chain = None
    private_key = None
    if settings.present_client_cert:
        certificate_chain = _pem_bytes(settings.certificate_chain_contents)
        private_key = _pem_bytes(settings.private_key_contents)

    return grpc.ssl_channel_credentials(
        root_certificates=_pem_bytes(settings.trusted_contents),
        private_key=private_key,
        certificate_chain=certificate_chain,
    )


def create_grpc_device_channel(
    server_address: str,
    server_port: int,
    options: ChannelOptions = (),
    retry_policy: Optional[RetryPolicy] = None,
) -> grpc.Channel:
    """Create an NI gRPC Device channel to ``server_address:server_port``.

    Reads the NI TLS client configuration for the NI gRPC Device Server and builds
    a channel that verifies the server certificate and, when the configuration
    calls for mutual TLS, also presents the client certificate. The channel is
    insecure only when the client's ``server_mode`` has been explicitly set to
    Disabled.

    TLS requires a certificate exchange with the remote system, performed in
    NI Hardware Manager. See `Managing mTLS
    <https://www.ni.com/docs/en-US/bundle/hardwaremanager/page/mtls-manage.html>`_.

    Args:
        server_address: Host name or address of the NI gRPC Device Server. Also used
            to resolve NI TLS settings specific to this target. IPv6 literals may be
            passed with or without brackets.
        server_port: Port of the NI gRPC Device Server.
        options: gRPC channel arguments, as ``(key, value)`` pairs. Use this to
            tune the channel, for example to raise message size limits or to set
            ``grpc.ssl_target_name_override`` when the server certificate's
            CN/SAN differs from the dialed host. Channel arguments cannot be
            changed after the channel is built, so they must be supplied here.
        retry_policy: Optional client retry configuration. When None (the
            default) no retry service config is added and gRPC's built-in
            behavior applies. Pass ``RetryPolicy()`` for the defaults described
            on that class.

    Returns:
        A ``grpc.Channel`` owned by the caller. Close it when the last session
        using it is done.

    Raises:
        TlsConfigurationError: TLS is enabled but the configuration is invalid.
        NitlsconfigCliError: The nitlsconfig CLI could not be run or parsed.
    """
    target = _format_target(server_address, server_port)
    channel_options = _apply_retry_policy(options, retry_policy)

    settings = _load_client_tls_settings(ClientConfig(SERVICE_NAME, server_address))

    if settings is None:
        security = _TransportSecurity.Unencrypted
    elif settings.present_client_cert:
        security = _TransportSecurity.MutualTls
    else:
        security = _TransportSecurity.ServerAuthenticatedTls

    _audit_transport_posture(server_address, security)

    if settings is None:
        channel = grpc.insecure_channel(target, options=channel_options)
    else:
        channel = grpc.secure_channel(
            target, _make_client_credentials(settings), options=channel_options
        )
    tag_channel_target(channel, target)
    return channel
