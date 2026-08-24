"""End-to-end mutual TLS tests against a real in-process gRPC server.

These are the only tests that prove the credentials built from nitlsconfig
configuration actually authenticate. Everything else in the suite stops at
"gRPC accepted our bytes", which is a low bar: gRPC does not parse PEM at
channel-creation time and will happily accept junk that fails at handshake.

Two facts are asserted:

* a client configured for mTLS completes a real RPC against a server that
  requires and verifies client certificates, and
* the same client refuses a server whose certificate comes from a different CA.

The second matters most. Without it, a bug that trusted everything would look
identical to a working implementation.

Certificates are generated in memory per test session; nothing is stored in the
repository.
"""

from concurrent import futures
from typing import Iterator, Tuple

import grpc
import pytest
from certificates import CertificateAuthority, Identity
from fake_config import FakeClientConfig, FILE_CERT, FILE_KEY, FILE_TRUST

from nitlsconfig import grpc_channel
from nitlsconfig.cli import ClientCertMode, ClientServerMode

_METHOD = "/nitlsconfig.Echo/Say"
_RPC_TIMEOUT_SECONDS = 10


def _identity(data: bytes) -> bytes:
    """Serialize and deserialize as raw bytes, so no protobuf schema is needed."""
    return data


@pytest.fixture(scope="module")
def certificate_authority() -> CertificateAuthority:
    """The CA the client is configured to trust."""
    return CertificateAuthority("nitlsconfig-test-ca")


@pytest.fixture(scope="module")
def client_identity(certificate_authority: CertificateAuthority) -> Identity:
    """The client certificate presented for mutual TLS."""
    return certificate_authority.issue("nitlsconfig-test-client", server=False)


def _serve(server_identity: Identity, client_trust_pem: bytes) -> Tuple[grpc.Server, int]:
    """Start a gRPC server that requires and verifies client certificates."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    server.add_generic_rpc_handlers(
        (
            grpc.method_handlers_generic_handler(
                "nitlsconfig.Echo",
                {
                    "Say": grpc.unary_unary_rpc_method_handler(
                        lambda request, context: request,
                        request_deserializer=_identity,
                        response_serializer=_identity,
                    )
                },
            ),
        )
    )
    credentials = grpc.ssl_server_credentials(
        [(server_identity.private_key_pem, server_identity.certificate_pem)],
        root_certificates=client_trust_pem,
        require_client_auth=True,
    )
    # Port 0 lets the OS pick a free port, so parallel or repeated runs cannot collide.
    port = server.add_secure_port("localhost:0", credentials)
    server.start()
    return server, port


@pytest.fixture(scope="module")
def trusted_server(
    certificate_authority: CertificateAuthority,
) -> Iterator[int]:
    """A server whose certificate chains to the CA the client trusts."""
    identity = certificate_authority.issue("localhost", server=True)
    server, port = _serve(identity, certificate_authority.certificate_pem)
    yield port
    server.stop(grace=None)


@pytest.fixture(scope="module")
def untrusted_server(
    certificate_authority: CertificateAuthority,
) -> Iterator[int]:
    """A server whose certificate chains to a CA the client does not trust."""
    rogue = CertificateAuthority("nitlsconfig-rogue-ca")
    identity = rogue.issue("localhost", server=True)
    # Still trusts our client's CA, so the only thing under test is whether the
    # client accepts the server. Otherwise the server would reject us first.
    server, port = _serve(identity, certificate_authority.certificate_pem)
    yield port
    server.stop(grace=None)


def _mutual_tls_config(
    certificate_authority: CertificateAuthority, client_identity: Identity
) -> FakeClientConfig:
    return FakeClientConfig(
        server_mode=ClientServerMode.TrustedCertificates,
        certificate_mode=ClientCertMode.Managed,
        certificate_chain_location=FILE_CERT,
        certificate_chain_contents=client_identity.certificate_pem.decode(),
        certificate_key_location=FILE_KEY,
        certificate_key_contents=client_identity.private_key_pem.decode(),
        trusted_certificates_location=FILE_TRUST,
        trusted_certificates_contents=certificate_authority.certificate_pem.decode(),
    )


def test_mutual_tls_handshake_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    certificate_authority: CertificateAuthority,
    client_identity: Identity,
    trusted_server: int,
) -> None:
    """A real RPC completes over mutual TLS using credentials we built."""
    config = _mutual_tls_config(certificate_authority, client_identity)
    monkeypatch.setattr(
        grpc_channel,
        "ClientConfig",
        lambda service_name, server_address: config,
    )

    with grpc_channel.create_grpc_device_channel("localhost", trusted_server) as channel:
        say = channel.unary_unary(
            _METHOD, request_serializer=_identity, response_deserializer=_identity
        )
        assert say(b"ping", timeout=_RPC_TIMEOUT_SECONDS) == b"ping"


def test_server_from_untrusted_ca_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    certificate_authority: CertificateAuthority,
    client_identity: Identity,
    untrusted_server: int,
) -> None:
    """The client refuses a server that does not chain to its trust anchors.

    Without this, an implementation that trusted everything would pass every
    other test in the suite.
    """
    config = _mutual_tls_config(certificate_authority, client_identity)
    monkeypatch.setattr(
        grpc_channel,
        "ClientConfig",
        lambda service_name, server_address: config,
    )

    with grpc_channel.create_grpc_device_channel("localhost", untrusted_server) as channel:
        say = channel.unary_unary(
            _METHOD, request_serializer=_identity, response_deserializer=_identity
        )
        with pytest.raises(grpc.RpcError) as failure:
            say(b"ping", timeout=_RPC_TIMEOUT_SECONDS)

    assert failure.value.code() == grpc.StatusCode.UNAVAILABLE
