"""Exceptions raised by this package, and the text that explains them."""

from __future__ import annotations

from typing import Optional

from nitlsconfig.channel_tag import is_nitls_channel


class NitlsconfigError(RuntimeError):
    """Base error for every failure raised by this package."""


class NitlsconfigCliError(NitlsconfigError):
    """Base error for nitlsconfig command invocation failures."""


class ExecutableNotFoundError(NitlsconfigCliError):
    """Raised when a usable nitlsconfig executable cannot be found."""


class CommandFailedError(NitlsconfigCliError):
    """Raised when nitlsconfig exits with a non-zero return code."""


class CommandTimeoutError(NitlsconfigCliError):
    """Raised when nitlsconfig does not exit within the allotted time."""


class InvalidOutputError(NitlsconfigCliError):
    """Raised when command output cannot be parsed as expected."""


class TlsConfigurationError(NitlsconfigError):
    """Raised when the NI TLS configuration was read successfully but is invalid.

    Deliberately not a :class:`NitlsconfigCliError`: the CLI worked, and the fix
    is to provision or try again to provision this machine rather than to install
    or repair installation.
    """

    #: Static message text, matching the wording used elsewhere in the product. Call
    #: sites append the specific detail after it, as the C++ loader does.
    _MESSAGE = (
        "A TLS configuration error occurred. Use NI Hardware Manager to verify that certificates "
        "are configured and matching on both the host and remote target. Check that the remote "
        "target has a compatible TLS enabled configuration with the host."
    )


_TLS_CONNECTION_ERROR_ELABORATION = (
    "Connection to the remote system failed.\n\n"
    "Check that the remote target is reachable. Verify in NI Hardware Manager that "
    "the host has a compatible TLS enabled configuration with the remote target."
)


def get_tls_connection_error_elaboration(channel: object) -> Optional[str]:
    """Return text elaborating on a connection failure, or None for a foreign channel.

    gRPC reports a rejected TLS handshake as ``UNAVAILABLE``, the same code it
    uses for an unreachable server, so a driver API catching that error cannot
    tell the two apart and reports only that connecting failed. Pass the channel
    here to recover the missing half of the diagnosis.

    Text is returned for any channel
    :func:`~nitlsconfig.grpc_channel.create_grpc_device_channel` built, including
    one created unencrypted because ``server_mode`` is Disabled: a client
    configured for plaintext against a TLS-enabled target fails to connect for
    exactly the reason the text describes.

    Substitute it for an existing message that only says connecting failed,
    which it restates; append it to one that carries detail
    of its own, such as the RPC that failed.

    Never raises, so it is safe to call from an exception handler.
    """
    try:
        return _TLS_CONNECTION_ERROR_ELABORATION if is_nitls_channel(channel) else None
    except Exception:  # pragma: no cover - getattr on a hostile channel
        return None
