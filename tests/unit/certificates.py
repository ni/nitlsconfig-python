"""Generate throwaway certificates for TLS handshake tests.

Everything here is created in memory, at test time, and lives only for the
duration of the test session. No key material is stored in the repository.
"""

import datetime
import ipaddress
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class Identity(NamedTuple):
    """A certificate and its private key, both PEM encoded."""

    certificate_pem: bytes
    private_key_pem: bytes


class CertificateAuthority:
    """A self-signed CA that can issue server and client certificates."""

    def __init__(self, common_name: str) -> None:
        """Create a self-signed CA certificate and key."""
        self._key = _new_key()
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        self._certificate = (
            _base_builder(self._name, self._name, self._key.public_key())
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    @property
    def certificate_pem(self) -> bytes:
        """The CA certificate, used as a trust anchor."""
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def issue(self, common_name: str, server: bool) -> Identity:
        """Issue a leaf certificate signed by this CA.

        Server certificates get localhost SANs so gRPC's hostname verification
        succeeds against a channel dialed at localhost.
        """
        key = _new_key()
        builder = _base_builder(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]),
            self._name,
            key.public_key(),
        ).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )

        certificate = builder.sign(self._key, hashes.SHA256())
        return Identity(
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
            private_key_pem=key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )


def _new_key() -> rsa.RSAPrivateKey:
    # 2048 bits keeps generation fast enough to run on every test session.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _base_builder(
    subject: x509.Name, issuer: x509.Name, public_key: rsa.RSAPublicKey
) -> x509.CertificateBuilder:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
    )
