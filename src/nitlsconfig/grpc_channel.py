"""Create gRPC client channels from NI-TLS (nitlsconfig) client configuration.

Reads the local NI-TLS client configuration for a service and produces a
:class:`grpc.Channel` that is either secured with TLS/mTLS or, when TLS is not
configured, a plain insecure channel.

The resulting channel is a normal ``grpc.Channel``. It can be handed directly to
any NI gRPC Python API, for example::

    from nitlsconfig.grpc_channel import create_grpc_client_channel

    channel = create_grpc_client_channel("localhost", 31763)
    options = nidcpower.GrpcSessionOptions(channel, "")
    with nidcpower.Session("Dev1", grpc_options=options) as session:
        ...

Channel ownership stays with the caller, matching the NI Python driver APIs,
which never close the channel themselves. ``grpc.Channel`` is already a context
manager, so ``with create_grpc_client_channel(...) as channel:`` works as expected.

The name carries the ``grpc`` prefix because this package also re-exports the
factory from its root, alongside any potential future non-gRPC transports.

A client ``server_mode`` of ``TrustAlways`` is not currently supported and raises
:class:`TlsConfigurationError`.

A client ``server_mode`` of ``SkipHostnameValidation`` is treated exactly like
``TrustedCertificates``: the server certificate chain is verified *and* the
hostname is checked. gRPC's Python API exposes no way to skip only the hostname
check: doing so requires a custom certificate verifier, which grpcio does not
bind in Python, where the TLS surface is limited to
``grpc.ssl_channel_credentials``. Verifying when asked not to fails closed, so
this is safe, but a caller who sets the mode gets no relaxation of the hostname
check.

When the server certificate's CN/SAN does not match the dialed host, pass
``grpc.ssl_target_name_override`` via ``options`` instead. That substitutes the
name gRPC matches against the certificate; it does not disable verification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional, Sequence, Tuple

import grpc

from nitlsconfig.cli import (
    CertificateLocation,
    ClientCertMode,
    ClientConfig,
    ClientServerMode,
    LocationScheme,
    NitlsconfigCliError,
)

__all__ = [
    "DEFAULT_SERVICE_NAME",
    "RetryPolicy",
    "TlsConfigurationError",
    "create_grpc_client_channel",
]

# The nitlsconfig service name registered by the NI gRPC Device Server. It is
# the file stem of ni-grpc-device.client.caps.yml, which grpc-device installs
# into the nitlsconfig client.d directory.
DEFAULT_SERVICE_NAME = "ni-grpc-device"

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


class TlsConfigurationError(NitlsconfigCliError):
    """Raised when the NI-TLS configuration was read successfully but is invalid."""


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
    private_key_contents: str
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


def _require_file_scheme(
    location: CertificateLocation, description: str, service_name: str
) -> None:
    """Validate that a certificate or key location is a usable File:// path.

    The ni-grpc-device client capabilities declare support for the File scheme
    only, so any other scheme is rejected rather than silently ignored.
    """
    if location.scheme != LocationScheme.File:
        raise TlsConfigurationError(
            f"Client {description} must use the File scheme for service "
            f"{service_name!r}, got {location.scheme.value!r}."
        )
    if not location.path:
        raise TlsConfigurationError(
            f"TLS is enabled but the client {description} path is missing for "
            f"service {service_name!r}."
        )


def _load_client_tls_settings(config: ClientConfig) -> Optional[_ClientTlsSettings]:
    """Read and validate client TLS settings, or None when TLS is not in use.

    ``server_mode`` is the master switch: when it is Disabled the client uses a
    plain connection and ``certificate_mode`` is not consulted at all.
    """
    service_name = config.service_name

    server_mode = config.server_mode
    if server_mode == ClientServerMode.Disabled:
        return None
    if server_mode == ClientServerMode.TrustAlways:
        # ni-grpc-device.client.caps.yml declares supports_server_mode_trust_always: false,
        # so this mode is not offered for this service.
        raise TlsConfigurationError(
            f"Client server_mode TrustAlways is not supported for service {service_name!r}."
        )
    if server_mode == ClientServerMode.Unknown:
        raise TlsConfigurationError(f"Unsupported client server_mode for service {service_name!r}.")

    # certificate_mode only decides mTLS versus one-way TLS.
    if config.certificate_mode == ClientCertMode.Unknown:
        raise TlsConfigurationError(
            f"Unsupported client certificate_mode for service {service_name!r}."
        )
    present_client_cert = config.certificate_mode != ClientCertMode.Disabled

    certificate_chain_contents = ""
    private_key_contents = ""
    if present_client_cert:
        _require_file_scheme(config.certificate_chain_location, "certificate chain", service_name)
        _require_file_scheme(config.certificate_key_location, "certificate key", service_name)
        certificate_chain_contents = config.certificate_chain_contents
        private_key_contents = config.certificate_key_contents

    # Trust anchors are always required: the client must verify the server.
    trusted_location = config.trusted_certificates_location
    trusted_available = trusted_location.scheme == LocationScheme.SystemDefault or bool(
        trusted_location.path
    )
    if not trusted_available:
        raise TlsConfigurationError(
            "TLS is enabled but the client trusted certificates path is missing for "
            f"service {service_name!r}."
        )

    trusted_contents = ""
    if trusted_location.scheme != LocationScheme.SystemDefault:
        trusted_contents = config.trusted_certificates_contents

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


def create_grpc_client_channel(
    server_address: str,
    server_port: int,
    service_name: str = DEFAULT_SERVICE_NAME,
    options: ChannelOptions = (),
    retry_policy: Optional[RetryPolicy] = None,
) -> grpc.Channel:
    """Create a gRPC channel to ``server_address:server_port`` using NI-TLS configuration.

    Reads the NI-TLS client configuration for ``service_name`` and builds a
    channel that verifies the server certificate and, when the configuration
    calls for mutual TLS, also presents the client certificate. Falls back to an
    insecure channel when the client's ``server_mode`` is Disabled, which is the
    default until the machine is configured.

    Args:
        server_address: Host name or address of the NI gRPC Device Server. IPv6
            literals may be passed with or without brackets.
        server_port: Port of the NI gRPC Device Server.
        service_name: nitlsconfig service name to read configuration from.
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

    settings = _load_client_tls_settings(ClientConfig(service_name))
    if settings is None:
        return grpc.insecure_channel(target, options=channel_options)

    return grpc.secure_channel(target, _make_client_credentials(settings), options=channel_options)
