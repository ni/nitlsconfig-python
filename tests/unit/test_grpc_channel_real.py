"""Tests that build real grpc.Channel objects, with no gRPC mocking.

Every test in test_grpc_channel.py replaces ``grpc.secure_channel``,
``grpc.insecure_channel`` and ``grpc.ssl_channel_credentials``, so those tests
never exercise gRPC itself. These tests deliberately do not, so that the objects
handed to NI driver APIs are the genuine article.

gRPC creates channels lazily: no connection, DNS lookup or handshake happens
until the first RPC, so these tests do no I/O and need no server.

Scope: this file validates that gRPC *accepts* what we build. It cannot validate
certificate material, because gRPC does not parse PEM at channel-creation time
(verified: junk PEM bytes are accepted without error and only fail during the
handshake). Proving that credentials actually authenticate requires a live
server and generated certificates.
"""

import grpc
import pytest
from fake_config import (
    FakeClientConfig,
    FILE_CERT,
    FILE_KEY,
    FILE_TRUST,
    SYSTEM_DEFAULT_TRUST,
)

from nitlsconfig import grpc_channel
from nitlsconfig.cli import ClientCertMode, ClientServerMode

# Not real key material. gRPC does not parse these at channel creation; they
# exist only so the TLS code path runs with non-empty contents.
PLACEHOLDER_PEM = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"

INSECURE = FakeClientConfig()

ONE_WAY_TLS = FakeClientConfig(
    server_mode=ClientServerMode.TrustedCertificates,
    certificate_mode=ClientCertMode.Disabled,
    trusted_certificates_location=FILE_TRUST,
    trusted_certificates_contents=PLACEHOLDER_PEM,
)

MUTUAL_TLS = FakeClientConfig(
    server_mode=ClientServerMode.TrustedCertificates,
    certificate_mode=ClientCertMode.Managed,
    certificate_chain_location=FILE_CERT,
    certificate_chain_contents=PLACEHOLDER_PEM,
    certificate_key_location=FILE_KEY,
    certificate_key_contents=PLACEHOLDER_PEM,
    trusted_certificates_location=FILE_TRUST,
    trusted_certificates_contents=PLACEHOLDER_PEM,
)

SYSTEM_DEFAULT_TLS = FakeClientConfig(
    server_mode=ClientServerMode.TrustedCertificates,
    certificate_mode=ClientCertMode.Disabled,
    trusted_certificates_location=SYSTEM_DEFAULT_TRUST,
)


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(INSECURE, id="insecure"),
        pytest.param(ONE_WAY_TLS, id="one_way_tls"),
        pytest.param(SYSTEM_DEFAULT_TLS, id="system_default_trust"),
    ],
)
def test_returns_a_usable_grpc_channel(
    monkeypatch: pytest.MonkeyPatch, config: FakeClientConfig
) -> None:
    """Every configuration produces a real channel with the API drivers rely on."""
    monkeypatch.setattr(grpc_channel, "ClientConfig", lambda service_name: config)

    with grpc_channel.create_client_channel("localhost", 31763) as channel:
        # nimi-python and nidaqmx-python pass this straight to GrpcSessionOptions,
        # which requires a grpc.Channel and calls these factories on it.
        assert isinstance(channel, grpc.Channel)
        assert callable(channel.unary_unary)
        assert callable(channel.stream_stream)


def test_channel_options_are_accepted_by_grpc(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    """Our retry service config and caller options are parsed by gRPC without complaint.

    A malformed service config does not raise; gRPC logs
    "channel stack builder failed" to stderr from native code and the channel is
    silently left without the policy. capfd captures at the file-descriptor
    level, so it sees that native output.

    Scope, established by mutation testing: this catches malformed *JSON syntax*
    only. gRPC does not validate the service config schema at channel-creation
    time, so an unknown key ("methodConfigTYPO") or a bad duration format
    ("100" instead of "0.100s") is accepted here and only takes effect - or
    fails to - once RPCs flow. The shape of the document is asserted separately
    in test_grpc_channel.py.
    """
    monkeypatch.setattr(grpc_channel, "ClientConfig", lambda service_name: MUTUAL_TLS)
    capfd.readouterr()

    with grpc_channel.create_client_channel(
        "localhost",
        31763,
        options=[("grpc.max_receive_message_length", 4 * 1024 * 1024)],
        retry_policy=grpc_channel.RetryPolicy(),
    ) as channel:
        assert isinstance(channel, grpc.Channel)

    assert "channel stack builder failed" not in capfd.readouterr().err
