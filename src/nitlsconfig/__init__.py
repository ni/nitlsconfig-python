"Python package to read settings from nitlsconfig."

from importlib.metadata import PackageNotFoundError, version

from nitlsconfig.cli import (
    CertificateLocation,
    ClientCertMode,
    ClientConfig,
    ClientServerMode,
    CommandFailedError,
    ExecutableNotFoundError,
    InvalidOutputError,
    LocationScheme,
    NitlsconfigCliError,
    ServerCertMode,
    ServerClientMode,
    ServerConfig,
    TrustedCertificateData,
)

try:
    __version__ = version("nitlsconfig")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "__version__",
    "CertificateLocation",
    "ClientCertMode",
    "ClientConfig",
    "ClientServerMode",
    "LocationScheme",
    "ServerCertMode",
    "ServerClientMode",
    "ServerConfig",
    "NitlsconfigCliError",
    "ExecutableNotFoundError",
    "CommandFailedError",
    "InvalidOutputError",
    "TrustedCertificateData",
]
