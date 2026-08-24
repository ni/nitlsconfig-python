"""Pytests for nitlsconfig.errors."""

from nitlsconfig.channel_tag import tag_channel_target
from nitlsconfig.errors import get_tls_connection_error_elaboration


class FakeChannel:
    """Stands in for a grpc.Channel, which the elaboration never calls into."""


def test___channel_we_created___elaborates_on_connection_errors() -> None:
    channel = FakeChannel()
    tag_channel_target(channel, "localhost:31763")

    elaboration = get_tls_connection_error_elaboration(channel)

    assert elaboration is not None
    assert "NI Hardware Manager" in elaboration


def test___channel_we_did_not_create___does_not_elaborate() -> None:
    assert get_tls_connection_error_elaboration(object()) is None
