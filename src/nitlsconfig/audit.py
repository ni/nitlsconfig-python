"""Audit logging for NI-TLS client transports.

Writes to the platformaudit log similarly to other NI gRPC clients:

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
"""

from __future__ import annotations

import logging
import sys
import threading
from enum import Enum

_ROLE = "Client"


class TransportSecurity(Enum):
    """Security posture of a created transport."""

    Unencrypted = "unencrypted"
    ServerAuthenticatedTls = "server_authenticated_tls"
    MutualTls = "mutual_tls"


# Names of services whose audit logger has already had its logging handler attached.
# The lock guards the check-then-add below: without it, threads creating channels
# for the same service can each attach a logging handler and double every record.
_logging_handler_lock = threading.Lock()
_services_with_logging_handler: set[str] = set()

# Set on channels we create. Carries the address audit_session_connect reports, and
# marks the channel as ours: the API layer issuing the initialize RPC holds only the
# channel, and cannot otherwise tell whether NI-TLS had any part in building it.
_TARGET_ATTR = "_nitls_audit_target"


def tag_channel_target(channel: object, target: str) -> None:
    """Record on a channel the ``host:port`` it was created for. Never raises."""
    try:
        setattr(channel, _TARGET_ATTR, target)
    except Exception:
        pass  # A channel type without an instance dict goes unaudited rather than unnamed.


def _make_logging_handler(service_name: str) -> logging.Handler:
    """Create the platform audit logging handler.

    Falls back to a null logging handler when the platform log is unreachable.
    That keeps audit records out of stderr, which ``logging`` would otherwise
    fall back to for a logger that has no logging handler of its own.
    """
    try:
        # "win32" is the value on every Windows build, 64-bit included; there is no "win64".
        if sys.platform == "win32":
            from logging.handlers import NTEventLogHandler

            return NTEventLogHandler(service_name)

        from logging.handlers import SysLogHandler

        return SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
    except Exception:
        # The platform logging handler failed, not `logging` itself; this diagnostic
        # goes to the host application's ordinary logger, never to the audit channel.
        logging.getLogger(__name__).warning(
            "NI-TLS audit logging is unavailable on this system; TLS transport "
            "posture will not be recorded.",
            exc_info=True,
        )
        return logging.NullHandler()


def _get_audit_logger(service_name: str) -> logging.Logger:
    """Return the audit logger for a service, attaching its logging handler on first use.

    Tracks the services we have set up rather than inspecting ``logger.handlers``,
    since anything else in the process may attach logging handlers to the same
    logger and would otherwise make an unconfigured logger look ready.
    """
    logger = logging.getLogger(f"nitlsconfig.audit.{service_name}.{_ROLE}")

    with _logging_handler_lock:
        if service_name not in _services_with_logging_handler:
            logger.setLevel(logging.INFO)
            # Audit records belong in the platform audit log, not in whatever
            # logging the host application has configured on the root logger.
            logger.propagate = False

            handler = _make_logging_handler(service_name)
            handler.setFormatter(logging.Formatter(f"[{service_name}][{_ROLE}] %(message)s"))
            logger.addHandler(handler)
            _services_with_logging_handler.add(service_name)

    return logger


def audit_transport_posture(service_name: str, peer_host: str, security: TransportSecurity) -> None:
    """Record the security posture of a client transport.

    Never raises: auditing must not disrupt transport creation.
    """
    try:
        message = f"Client transport for service '{service_name}'"
        if peer_host:
            message += f" to '{peer_host}'"

        if security is TransportSecurity.Unencrypted:
            message += " is unencrypted (TLS disabled)."
        elif security is TransportSecurity.ServerAuthenticatedTls:
            message += " uses one-way TLS. Not presenting a client certificate."
        else:
            message += " uses mutual TLS. Presenting a client certificate."

        logger = _get_audit_logger(service_name)
        # Mutual TLS is the secure baseline; weaker postures are auditable warnings.
        if security is TransportSecurity.MutualTls:
            logger.info(message)
        else:
            logger.warning(message)
    except Exception:
        pass


def audit_session_connect(
    service_name: str, driver_name: str, channel: object, connected: bool
) -> None:
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

        outcome = "connected" if connected else "failed to connect"
        message = f"{driver_name} gRPC session {outcome} on hostname '{target}'"

        logger = _get_audit_logger(service_name)
        if connected:
            logger.info(message)
        else:
            logger.error(message)
    except Exception:
        pass
