"""Audit logging for NI-TLS client transports.

Writes to the platform audit log similarly to other NI gRPC clients:

Windows: Windows Event Log
Linux: syslog

We use the record pattern ``[<service>][<role>] <message>``.

A record is emitted only for something that attests to the security posture of a
connection that actually existed: transport posture and session connect results.

Configuration errors are not audited, because no channel is created and nothing
is transmitted; :class:`TlsConfigurationError` carries that detail to the caller
directly.

We also do not record *which* server we authenticated, for example its
certificate subject. gRPC's Python client API takes certificates as input only:
it offers no callback during the handshake and no way to read the server's
certificate afterward.

Transport posture is emitted by the channel factory.
The session connect record cannot be: it reports the outcome of a driver's
initialize RPC, and a gRPC channel connects lazily, so the API layer that
issues that RPC has to call ``audit_session_connect`` itself.

Auditing covers the NI gRPC Device Server only, so the service name is fixed
here rather than accepted from callers. Should another service ever need audit
records, this module grows a service parameter again at that point.

Records report what this package observed, assuming the hosting process is not
hostile. Nothing here can defend against code in the same process, which can
call the standard library logger directly. Untrusted *values* reaching a record
are bounded and escaped below, because those do cross a trust boundary.
"""

from __future__ import annotations

import logging
import sys
import threading
from enum import Enum

_SERVICE_NAME = "ni-grpc-device"
_ROLE = "Client"


class TransportSecurity(Enum):
    """Security posture of a created transport."""

    Unencrypted = "unencrypted"
    ServerAuthenticatedTls = "server_authenticated_tls"
    MutualTls = "mutual_tls"


# Whether the audit logger has had its logging handler attached. The lock guards
# the check-then-set below: without it, threads creating channels can each attach
# a logging handler and double every record.
_logging_handler_lock = threading.Lock()
_logging_handler_attached = False

# Set on channels we create. Carries the address audit_session_connect reports, and
# marks the channel as ours: the API layer issuing the initialize RPC holds only the
# channel, and cannot otherwise tell whether NI-TLS had any part in building it.
_TARGET_ATTR = "_nitls_audit_target"

_MAX_FIELD_LENGTH = 256


def _audit_field(value: object) -> str:
    """Return a bounded audit field with record-breaking characters escaped.

    Escaping runs before the bound, so the returned length is the real limit;
    escaping afterwards could double it.
    """
    escaped = str(value).replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
    if len(escaped) <= _MAX_FIELD_LENGTH:
        return escaped

    truncated = escaped[: _MAX_FIELD_LENGTH - 3]
    # Cutting mid-escape would leave a trailing backslash that escapes the quote
    # the message puts after this field.
    if (len(truncated) - len(truncated.rstrip("\\"))) % 2:
        truncated = truncated[:-1]
    return truncated + "..."


def tag_channel_target(channel: object, target: str) -> None:
    """Record on a channel the ``host:port`` it was created for. Never raises."""
    try:
        setattr(channel, _TARGET_ATTR, target)
    except Exception:
        logging.getLogger(__name__).debug(
            "Unable to tag channel for audit logging; the channel will go unaudited.",
            exc_info=True,
        )


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

            return NTEventLogHandler(_SERVICE_NAME)

        from logging.handlers import SysLogHandler

        return SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
    except Exception:
        # The platform logging handler failed, not `logging` itself; this diagnostic
        # goes to the host application's ordinary logger, never to the audit channel.
        logging.getLogger(__name__).warning(
            "NI-TLS audit logging is unavailable on this system; audit events "
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

    logger = logging.getLogger(f"nitlsconfig.audit.{_SERVICE_NAME}.{_ROLE}")

    with _logging_handler_lock:
        if not _logging_handler_attached:
            logger.setLevel(logging.INFO)
            # Audit records belong in the platform audit log, not in whatever
            # logging the host application has configured on the root logger.
            logger.propagate = False

            handler = _make_logging_handler()
            handler.setFormatter(logging.Formatter(f"[{_SERVICE_NAME}][{_ROLE}] %(message)s"))
            logger.addHandler(handler)
            _logging_handler_attached = True

    return logger


def audit_transport_posture(peer_host: str, security: TransportSecurity) -> None:
    """Record the security posture of a client transport.

    Never raises: auditing must not disrupt transport creation.
    """
    try:
        peer_host = _audit_field(peer_host)
        message = f"Client transport for service '{_SERVICE_NAME}'"
        if peer_host:
            message += f" to '{peer_host}'"

        if security is TransportSecurity.Unencrypted:
            message += " is unencrypted (TLS disabled)."
        elif security is TransportSecurity.ServerAuthenticatedTls:
            message += " uses one-way TLS. Not presenting a client certificate."
        else:
            message += " uses mutual TLS. Presenting a client certificate."

        logger = _get_audit_logger()
        # Mutual TLS is the secure baseline; weaker postures are auditable warnings.
        if security is TransportSecurity.MutualTls:
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
    NI-TLS, so there is no transport posture record to pair the outcome with and
    nothing to attest to; auditing it anyway would also register an Event Log
    source on machines not using NI-TLS at all.
    """
    try:
        target = getattr(channel, _TARGET_ATTR, "")
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
