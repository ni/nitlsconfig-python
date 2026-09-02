"""Audit logging for NI TLS client transports.

Records the security posture of transports this package creates, and the outcome of a
driver's gRPC session initialize RPC, to the platform audit log: the Windows Event Log
on Windows, syslog on Linux.

Transport posture is recorded by the channel factory. The session connect outcome
cannot be, because a gRPC channel connects lazily, so the driver API layer that issues
the initialize RPC calls :func:`audit_session_connect` itself.
"""

from __future__ import annotations

import logging
import sys
import threading
from enum import Enum

from nitlsconfig._service import SERVICE_NAME
from nitlsconfig.channel_tag import get_channel_target

# A record is emitted only for something that attests to the security posture of a
# connection that actually existed. Configuration errors are not audited, because no
# channel is created and nothing is transmitted; TlsConfigurationError carries that
# detail to the caller directly. We also do not record *which* server we authenticated,
# for example its certificate subject: gRPC's Python client API takes certificates as
# input only, offering no handshake callback and no way to read the server's certificate
# afterward.
#
# Auditing covers the NI gRPC Device Server only, so the service name is fixed
# package-wide rather than accepted from callers. Should another service ever need audit
# records, this module grows a service parameter again at that point.
#
# Records report what this package observed, assuming the hosting process is not hostile.
# Nothing here can defend against code in the same process, which can call the standard
# library logger directly. Untrusted *values* reaching a record are bounded and escaped
# below, because those do cross a trust boundary.

_ROLE = "Client"


class _TransportSecurity(Enum):
    """Security posture of a created transport."""

    Unencrypted = "unencrypted"
    ServerAuthenticatedTls = "server_authenticated_tls"
    MutualTls = "mutual_tls"


# Whether the audit logger has had its logging handler attached. The lock guards
# the check-then-set below: without it, threads creating channels can each attach
# a logging handler and double every record.
_logging_handler_lock = threading.Lock()
_logging_handler_attached = False

_MAX_FIELD_LENGTH = 256

# The quote is here because messages wrap every field in single quotes; without it
# a value can close the quote and append text that reads as part of our message.
_ESCAPES = {"\\": "\\\\", "'": "\\'", "\r": "\\r", "\n": "\\n"}


def _audit_field(value: object) -> str:
    """Return a bounded audit field with record-breaking characters escaped.

    Escaping runs before the bound, so the returned length is the real limit;
    escaping afterwards could double it.

    Remaining C0 controls and DEL become hex escapes: ESC would otherwise emit
    terminal control sequences when a syslog file is read, and NUL can truncate
    the record as it crosses into the platform logging API.
    """
    escaped = "".join(
        _ESCAPES[ch] if ch in _ESCAPES else (ch if " " <= ch != "\x7f" else f"\\x{ord(ch):02x}")
        for ch in str(value)
    )
    if len(escaped) <= _MAX_FIELD_LENGTH:
        return escaped

    truncated = escaped[: _MAX_FIELD_LENGTH - 3]
    # Cutting mid-escape would leave a trailing backslash that escapes the quote
    # the message puts after this field.
    if (len(truncated) - len(truncated.rstrip("\\"))) % 2:
        truncated = truncated[:-1]
    return truncated + "..."


def _make_logging_handler() -> logging.Handler:
    """Create the platform audit logging handler.

    Falls back to a null logging handler when the platform log is unreachable.
    That keeps audit records out of stderr, which ``logging`` would otherwise
    fall back to for a logger that has no logging handler of its own.
    """
    try:
        # "win32" is the value on every Windows build, 64-bit included; there is no "win64".
        if sys.platform == "win32":
            from logging.handlers import NTEventLogHandler

            return NTEventLogHandler(SERVICE_NAME)

        from logging.handlers import SysLogHandler

        return SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
    except Exception:
        # The platform logging handler failed, not `logging` itself; this diagnostic
        # goes to the host application's ordinary logger, never to the audit channel.
        logging.getLogger(__name__).warning(
            "NI TLS audit logging is unavailable on this system; audit events "
            "will not be recorded.",
            exc_info=True,
        )
        return logging.NullHandler()


def _get_audit_logger() -> logging.Logger:
    """Return the audit logger, attaching its logging handler on first use.

    Tracks setup ourselves rather than inspecting ``logger.handlers``, since
    anything else in the process may attach logging handlers to the same logger
    and would otherwise make an unconfigured logger look ready.
    """
    global _logging_handler_attached

    logger = logging.getLogger(f"nitlsconfig.audit.{SERVICE_NAME}.{_ROLE}")

    with _logging_handler_lock:
        if not _logging_handler_attached:
            logger.setLevel(logging.INFO)
            # Audit records belong in the platform audit log, not in whatever
            # logging the host application has configured on the root logger.
            logger.propagate = False

            handler = _make_logging_handler()
            # Record pattern: [<service>][<role>] <message>
            handler.setFormatter(logging.Formatter(f"[{SERVICE_NAME}][{_ROLE}] %(message)s"))
            logger.addHandler(handler)
            _logging_handler_attached = True

    return logger


def _audit_transport_posture(peer_host: str, security: _TransportSecurity) -> None:
    """Record the security posture of a client transport.

    Never raises: auditing must not disrupt transport creation.
    """
    try:
        peer_host = _audit_field(peer_host)
        message = f"Client transport for service '{SERVICE_NAME}'"
        if peer_host:
            message += f" to '{peer_host}'"

        if security is _TransportSecurity.Unencrypted:
            message += " is unencrypted (TLS disabled)."
        elif security is _TransportSecurity.ServerAuthenticatedTls:
            message += " uses one-way TLS. Not presenting a client certificate."
        else:
            message += " uses mutual TLS. Presenting a client certificate."

        logger = _get_audit_logger()
        # Mutual TLS is the secure baseline; weaker postures are auditable warnings.
        if security is _TransportSecurity.MutualTls:
            logger.info(message)
        else:
            logger.warning(message)
    except Exception:
        logging.getLogger(__name__).debug("Unable to record transport audit event.", exc_info=True)


def audit_session_connect(driver_name: str, channel: object, connected: bool) -> None:
    """Record the outcome of a driver's gRPC session initialize RPC. Never raises.

    Call this from the API layer once the initialize RPC returns, passing the
    driver's logging name (``NI-DCPower``, and so on).

    Channels this package did not create are ignored, so drivers can call this
    unconditionally. A caller who built their own channel never went through
    NI TLS, so there is no transport posture record to pair the outcome with and
    nothing to attest to; auditing it anyway would also register an Event Log
    source on machines not using NI TLS at all.
    """
    try:
        target = get_channel_target(channel)
        if not target:
            return

        driver_name = _audit_field(driver_name)
        target = _audit_field(target)

        outcome = "connected" if connected else "failed to connect"
        message = f"{driver_name} gRPC session {outcome} on hostname '{target}'"

        logger = _get_audit_logger()
        if connected:
            logger.info(message)
        else:
            logger.error(message)
    except Exception:
        logging.getLogger(__name__).debug("Unable to record session audit event.", exc_info=True)
