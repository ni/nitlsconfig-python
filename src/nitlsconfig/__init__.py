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
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

from nitlsconfig.audit import audit_session_connect
from nitlsconfig.cli import (
    CertificateLocation,
    ClientCertMode,
    ClientConfig,
    ClientServerMode,
    LocationScheme,
    ServerCertMode,
    ServerClientMode,
    ServerConfig,
    TrustedCertificateData,
    KnownServerData,
)
from nitlsconfig.errors import (
    CommandFailedError,
    ExecutableNotFoundError,
    InvalidOutputError,
    NitlsconfigCliError,
    NitlsconfigError,
    TlsConfigurationError,
)

if TYPE_CHECKING:
    # Imported eagerly for type checkers and editors, which do not run __getattr__.
    from nitlsconfig.grpc_channel import (
        DEFAULT_SERVICE_NAME,
        RetryPolicy,
        create_grpc_client_channel,
    )

__version__ = version("nitlsconfig")

# Names re-exported from nitlsconfig.grpc_channel, which requires grpcio.
# A plain list literal, because pyright only tracks __all__ through a small set
# of literal forms; anything computed makes it give up on the export list.
_GRPC_EXPORTS = [
    "DEFAULT_SERVICE_NAME",
    "RetryPolicy",
    "create_grpc_client_channel",
]

__all__ = [
    "__version__",
    "audit_session_connect",
    "CertificateLocation",
    "ClientCertMode",
    "ClientConfig",
    "ClientServerMode",
    "LocationScheme",
    "ServerCertMode",
    "ServerClientMode",
    "ServerConfig",
    "NitlsconfigError",
    "NitlsconfigCliError",
    "ExecutableNotFoundError",
    "CommandFailedError",
    "InvalidOutputError",
    "TlsConfigurationError",
    "TrustedCertificateData",
    "KnownServerData",
]

# The gRPC names are public API, but only on an install that can supply them.
# Listing them unconditionally would make `from nitlsconfig import *` raise
# ImportError without the grpc extra, since star-import resolves every name in
# __all__. find_spec only locates grpcio; it does not import it, so the lazy
# __getattr__ below still decides when grpcio is actually loaded.
if find_spec("grpc") is not None:
    # pyright only tracks __all__ through inline literals, so it cannot follow
    # this and warns that the export list may be incomplete. The TYPE_CHECKING
    # block above already declares these names for static consumers.
    __all__ += _GRPC_EXPORTS  # pyright: ignore[reportUnsupportedDunderAll]


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
