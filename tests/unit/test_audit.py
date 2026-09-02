"Pytests for nitlsconfig.audit."

import logging
from typing import Iterator, List

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
