"""Python package to read settings from nitlsconfig and build connections from them.

Reading configuration is pure Python and has no third-party dependencies. The
gRPC channel factory needs grpcio, which is an optional extra::

    pip install nitlsconfig[grpc]

The gRPC names below are therefore resolved lazily: importing this package never
imports grpcio, so a caller that only reads NI-TLS configuration does not pay
for a binary dependency it will not use. Additional transports can be added the
same way without changing what a bare install requires.
"""

from importlib.metadata import version
from typing import TYPE_CHECKING, Any

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
    KnownServerData,
)

if TYPE_CHECKING:
    # Imported eagerly for type checkers and editors, which do not run __getattr__.
    from nitlsconfig.grpc_channel import (
        DEFAULT_SERVICE_NAME,
        RetryPolicy,
        TlsConfigurationError,
        create_grpc_client_channel,
    )

__version__ = version("nitlsconfig")

# Names re-exported from nitlsconfig.grpc_channel, which requires grpcio.
_GRPC_EXPORTS = frozenset(
    {
        "DEFAULT_SERVICE_NAME",
        "RetryPolicy",
        "TlsConfigurationError",
        "create_grpc_client_channel",
    }
)

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
    "KnownServerData",
    "DEFAULT_SERVICE_NAME",
    "RetryPolicy",
    "TlsConfigurationError",
    "create_grpc_client_channel",
]


def __getattr__(name: str) -> Any:
    """Resolve gRPC exports on first use, so importing this package does not need grpcio."""
    if name in _GRPC_EXPORTS:
        try:
            from nitlsconfig import grpc_channel
        except ImportError as exc:  # pragma: no cover - requires an install without the extra
            raise ImportError(
                f"nitlsconfig.{name} requires grpcio, which is not installed. "
                "Install it with: pip install nitlsconfig[grpc]"
            ) from exc
        return getattr(grpc_channel, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
