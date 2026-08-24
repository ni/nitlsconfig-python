"""Exceptions raised by this package."""

from __future__ import annotations


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
    """Raised when the NI-TLS configuration was read successfully but is invalid.

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
