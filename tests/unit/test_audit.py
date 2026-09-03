"Pytests for nitlsconfig.audit."

import importlib
import logging
import logging.handlers
import sys
from types import SimpleNamespace
from typing import Any, Iterator, List, Tuple

import pytest

from nitlsconfig import audit
from nitlsconfig.audit import (
    _TransportSecurity as TransportSecurity,
    _audit_transport_posture as audit_transport_posture,
    audit_session_connect,
)
from nitlsconfig.channel_tag import tag_channel_target

SERVICE = "ni-grpc-device"
HOST = "localhost"
make_logging_handler = audit._make_logging_handler


# We utilize a test-specific logging handler to capture audit records for test assertions.
# Otherwise, our audit records would go to the platform audit log which we are unable to check.
class RecordingHandler(logging.Handler):
    """Captures formatted records so tests can assert on the exact audit text."""

    def __init__(self) -> None:
        """Start with no captured records."""
        super().__init__()
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Record the log record instead of writing to the platform audit log."""
        self.records.append(record)


# Between tests, we want to reset the state of the audit logger
# to ensure each test starts with a clean slate.
def reset_logger() -> logging.Logger:
    """Detach our logging handler so the next call reconfigures the process-global logger."""
    # Our audit logger records that it has already attached its handler.
    audit._logging_handler_attached = False
    # Find the logger handler for the service after clearing that flag
    # and discard it as well.
    logger = logging.getLogger(f"nitlsconfig.audit.{SERVICE}.Client")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    return logger


@pytest.fixture(autouse=True)
def recorded(monkeypatch: pytest.MonkeyPatch) -> Iterator[RecordingHandler]:
    """Replace the platform logging handler so tests never touch the Event Log or syslog."""
    handler = RecordingHandler()
    # We use monkeypatch to replace the creation of the platform audit loggers with the creation
    # of our test-specific audit recording handler instead.
    monkeypatch.setattr(audit, "_make_logging_handler", lambda: handler)
    # During set-up and before giving the handler to our tests, reset the state.
    reset_logger()
    # We yield the handler to provide the test the handler object to operate against.
    yield handler
    # Once the test has run and finished with the handler,
    # reset the state before the next unit test.
    # This might appear redundant, but this particular reset
    # is important to prevent polluting behavior into other tests
    # defined outside of this file.
    reset_logger()


def only_message(recorded: RecordingHandler) -> str:
    """Return the single captured message, asserting exactly one was emitted."""
    assert len(recorded.records) == 1
    return recorded.records[0].getMessage()


def test___mutual_tls___logs_mutual_tls_posture_as_info(recorded: RecordingHandler) -> None:
    audit_transport_posture(HOST, TransportSecurity.MutualTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to 'localhost' "
        "uses mutual TLS. Presenting a client certificate."
    )
    assert recorded.records[0].levelno == logging.INFO


def test___one_way_tls___logs_one_way_posture_as_warning(recorded: RecordingHandler) -> None:
    audit_transport_posture(HOST, TransportSecurity.ServerAuthenticatedTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to 'localhost' "
        "uses one-way TLS. Not presenting a client certificate."
    )
    assert recorded.records[0].levelno == logging.WARNING


def test___unencrypted___logs_unencrypted_posture_as_warning(recorded: RecordingHandler) -> None:
    audit_transport_posture(HOST, TransportSecurity.Unencrypted)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to 'localhost' "
        "is unencrypted (TLS disabled)."
    )
    assert recorded.records[0].levelno == logging.WARNING


def test___no_peer_host___omits_host_clause(recorded: RecordingHandler) -> None:
    audit_transport_posture("", TransportSecurity.MutualTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' "
        "uses mutual TLS. Presenting a client certificate."
    )


def test___transport_fields_with_newlines___escape_record_breaking_characters(
    recorded: RecordingHandler,
) -> None:
    audit_transport_posture("host\r\nforged-entry", TransportSecurity.MutualTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to 'host\\r\\nforged-entry' "
        "uses mutual TLS. Presenting a client certificate."
    )


def test___transport_field_contains_quote___quote_is_escaped(
    recorded: RecordingHandler,
) -> None:
    audit_transport_posture("host' is unencrypted (TLS disabled). '", TransportSecurity.MutualTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to "
        "'host\\' is unencrypted (TLS disabled). \\'' "
        "uses mutual TLS. Presenting a client certificate."
    )


def test___transport_field_contains_control_characters___they_become_hex_escapes(
    recorded: RecordingHandler,
) -> None:
    audit_transport_posture("host\x00\x1b\x7f", TransportSecurity.MutualTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to 'host\\x00\\x1b\\x7f' "
        "uses mutual TLS. Presenting a client certificate."
    )


def test___audit_fields_over_maximum_length___are_truncated(recorded: RecordingHandler) -> None:
    peer_host = "h" * (audit._MAX_FIELD_LENGTH + 10)

    audit_transport_posture(peer_host, TransportSecurity.MutualTls)

    assert only_message(recorded) == (
        "Client transport for service 'ni-grpc-device' to '"
        + "h" * (audit._MAX_FIELD_LENGTH - 3)
        + "...' uses mutual TLS. Presenting a client certificate."
    )


def test___escaping_grows_a_field_past_the_maximum___bound_still_holds() -> None:
    field = audit._audit_field("\\" * audit._MAX_FIELD_LENGTH)

    assert len(field) <= audit._MAX_FIELD_LENGTH
    # A trailing lone backslash would escape the quote the message puts after the field.
    assert (len(field) - len(field.rstrip("\\"))) % 2 == 0


class FakeChannel:
    """Stands in for a grpc.Channel, which is only an attribute holder here."""


def test___session_connected___logs_connect_as_info(recorded: RecordingHandler) -> None:
    channel = FakeChannel()
    tag_channel_target(channel, "localhost:31763")

    audit_session_connect("NI-DCPower", channel, True)

    assert only_message(recorded) == (
        "NI-DCPower gRPC session connected on hostname 'localhost:31763'"
    )
    assert recorded.records[0].levelno == logging.INFO


def test___session_not_connected___logs_failure_as_error(recorded: RecordingHandler) -> None:
    channel = FakeChannel()
    tag_channel_target(channel, "localhost:31763")

    audit_session_connect("NI-DCPower", channel, False)

    assert only_message(recorded) == (
        "NI-DCPower gRPC session failed to connect on hostname 'localhost:31763'"
    )
    assert recorded.records[0].levelno == logging.ERROR


def test___session_fields_with_newlines___escape_record_breaking_characters(
    recorded: RecordingHandler,
) -> None:
    channel = FakeChannel()
    tag_channel_target(channel, "localhost\r\nforged-entry")

    audit_session_connect("driver\rname", channel, True)

    assert only_message(recorded) == (
        "driver\\rname gRPC session connected on hostname 'localhost\\r\\nforged-entry'"
    )
    assert recorded.records[0].name == f"nitlsconfig.audit.{SERVICE}.Client"


def test___untagged_channel___emits_no_record(recorded: RecordingHandler) -> None:
    audit_session_connect("NI-DCPower", FakeChannel(), True)

    assert recorded.records == []


def test___audit_logger___formats_with_service_and_role_prefix(
    recorded: RecordingHandler,
) -> None:
    audit_transport_posture(HOST, TransportSecurity.MutualTls)

    formatted = recorded.format(recorded.records[0])
    logger = logging.getLogger(f"nitlsconfig.audit.{SERVICE}.Client")
    assert formatted.startswith(f"[{SERVICE}][Client] ")
    # Audit records must not leak into the host application's logging configuration.
    assert logger.propagate is False


def test___same_service_requested_twice___reuses_one_logger(
    recorded: RecordingHandler,
) -> None:
    audit_transport_posture(HOST, TransportSecurity.MutualTls)
    audit_transport_posture(HOST, TransportSecurity.MutualTls)

    logger = logging.getLogger(f"nitlsconfig.audit.{SERVICE}.Client")
    assert len(recorded.records) == 2
    assert [h for h in logger.handlers if h is recorded] == [recorded]


def test___windows_platform___creates_windows_event_log_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows_handler = RecordingHandler()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(audit, "_WindowsEventLogHandler", lambda source: windows_handler)

    assert make_logging_handler() is windows_handler


def test___linux_platform___creates_syslog_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    syslog_handler = RecordingHandler()
    calls: List[Tuple[object, object]] = []

    class FakeSysLogHandler:
        LOG_DAEMON = 3

        def __new__(cls, address: object, facility: object) -> Any:
            calls.append((address, facility))
            return syslog_handler

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(logging.handlers, "SysLogHandler", FakeSysLogHandler)

    assert make_logging_handler() is syslog_handler
    assert calls == [("/dev/log", FakeSysLogHandler.LOG_DAEMON)]


def test___unsupported_platform___disables_audit_logging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "unsupported")

    assert isinstance(make_logging_handler(), logging.NullHandler)


def test___windows_handler___uses_preregistered_source_and_literal_message_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Capture the direct win32evtlog calls in memory. The fake deliberately has no
    # AddSourceToRegistry API: the source is pre-registered, and this package must
    # never create or overwrite an Event Log registry key.
    registered: List[Tuple[object, str]] = []
    reported: List[Tuple[object, ...]] = []
    deregistered: List[object] = []
    event_source = object()

    def register_event_source(server: object, source: str) -> object:
        registered.append((server, source))
        return event_source

    # Create a fake win32evtlog module with the constants and functions used by the handler.
    event_log = SimpleNamespace(
        EVENTLOG_INFORMATION_TYPE=4,
        EVENTLOG_WARNING_TYPE=2,
        EVENTLOG_ERROR_TYPE=1,
        RegisterEventSource=register_event_source,
        ReportEvent=lambda *args: reported.append(args),
        DeregisterEventSource=lambda handle: deregistered.append(handle),
    )
    # Keep the test platform-independent and prevent it from writing a real Windows event.
    monkeypatch.setattr(importlib, "import_module", lambda name: event_log)

    handler = audit._WindowsEventLogHandler(SERVICE)
    handler.setFormatter(logging.Formatter("[ni-grpc-device][Client] %(message)s"))
    record = logging.LogRecord(
        "nitlsconfig.audit",  # Logger name recorded with the event.
        logging.ERROR,  # Python level that must map to EVENTLOG_ERROR_TYPE.
        __file__,  # Source pathname required by LogRecord, but not sent to Event Log.
        1,  # Source line required by LogRecord, but not sent to Event Log.
        "session failed",  # Message formatted into the Event Log insertion string.
        (),  # No %-formatting arguments are needed for this message.
        None,  # No exception information is associated with this record.
    )

    handler.emit(record)

    # RegisterEventSource resolves the pre-registered source; None selects the local
    # Windows machine.
    assert registered == [(None, SERVICE)]
    # This source uses mscoree.dll as its EventMessageFile. Its generic event ID 0
    # renders the first insertion string as the complete description, avoiding Event
    # Viewer's "message was not found in the message table" fallback.
    assert reported == [
        (
            event_source,  # Handle returned by RegisterEventSource.
            event_log.EVENTLOG_ERROR_TYPE,  # ERROR maps to a Windows error event.
            0,  # No event category is configured for this source.
            0,  # mscoree.dll event ID 0 renders the first insertion string literally.
            None,  # No user security identifier is associated with the event.
            ["[ni-grpc-device][Client] session failed"],  # Complete event description.
            None,  # No binary event data.
        )
    ]
    # Every registered source handle must be released after the event is reported.
    assert deregistered == [event_source]


def test___logging_handler_cannot_be_created___does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode() -> logging.Handler:
        raise OSError("no audit logging handler here")

    monkeypatch.setattr(audit, "_make_logging_handler", explode)
    reset_logger()

    audit_transport_posture(HOST, TransportSecurity.MutualTls)


def test___logging_handler_raises___does_not_disrupt_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            raise RuntimeError("audit logging handler failed")

        def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 - logging API
            raise RuntimeError("audit logging handler failed")

    monkeypatch.setattr(audit, "_make_logging_handler", lambda: ExplodingHandler())
    reset_logger()

    channel = FakeChannel()
    tag_channel_target(channel, "localhost:31763")

    audit_transport_posture(HOST, TransportSecurity.MutualTls)
    audit_session_connect("NI-DCPower", channel, False)
