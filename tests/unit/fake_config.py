"""Shared test double for nitlsconfig.cli.ClientConfig."""

from typing import Any

from nitlsconfig.cli import CertificateLocation, ClientCertMode, ClientServerMode, LocationScheme

SERVICE_NAME = "ni-grpc-device"

FILE_CERT = CertificateLocation(LocationScheme.File, "cert.pem")
FILE_KEY = CertificateLocation(LocationScheme.File, "key.pem")
FILE_TRUST = CertificateLocation(LocationScheme.File, "trust.pem")
SYSTEM_DEFAULT_TRUST = CertificateLocation(LocationScheme.SystemDefault)


class FakeClientConfig:
    """Stand-in for ClientConfig that skips the nitlsconfig CLI."""

    def __init__(self, **overrides: Any) -> None:
        """Initialize a configuration with insecure defaults, then apply overrides."""
        self.service_name = SERVICE_NAME
        self.server_mode = ClientServerMode.Disabled
        self.certificate_mode = ClientCertMode.Disabled
        self.certificate_chain_location = CertificateLocation(LocationScheme.Unknown)
        self.certificate_chain_contents = ""
        self.certificate_key_location = CertificateLocation(LocationScheme.Unknown)
        self.certificate_key_contents = ""
        self.trusted_certificates_location = CertificateLocation(LocationScheme.Unknown)
        self.trusted_certificates_contents = ""
        # The defaults above are insecure, so a misspelled override would silently
        # leave TLS off and still let the test pass. Reject unknown names instead.
        unknown = sorted(set(overrides) - set(self.__dict__))
        if unknown:
            raise AttributeError(f"FakeClientConfig has no field(s): {', '.join(unknown)}")
        self.__dict__.update(overrides)
