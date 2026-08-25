"Pytests for nitlsconfig.channel_tag."

from nitlsconfig.channel_tag import get_channel_target, is_nitls_channel, tag_channel_target


class FakeChannel:
    """Stands in for a grpc.Channel, which is only an attribute holder here."""


def test___tagged_channel___reports_its_target() -> None:
    channel = FakeChannel()
    tag_channel_target(channel, "localhost:31763")

    assert get_channel_target(channel) == "localhost:31763"
    assert is_nitls_channel(channel)


def test___untagged_channel___is_not_recognized_as_ours() -> None:
    assert get_channel_target(FakeChannel()) == ""
    assert not is_nitls_channel(FakeChannel())


def test___channel_carrying_a_foreign_attribute___is_not_recognized_as_ours() -> None:
    channel = FakeChannel()
    setattr(channel, "_nitls_channel_target", object())

    assert not is_nitls_channel(channel)


def test___channel_rejects_attributes___tagging_does_not_raise() -> None:
    class Slotted:
        __slots__ = ()

    tag_channel_target(Slotted(), "localhost:31763")
