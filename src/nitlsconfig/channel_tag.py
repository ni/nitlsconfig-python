"""Marks gRPC channels this package created.

A caller holding only a channel cannot tell whether NI-TLS had any part in
building it, so the channel factory tags what it creates. Two features read the
tag: audit records name the address, and connection-error elaboration speaks only
for channels we built.

The tag is advisory, not a security control. It says where a channel came from,
never that a connection is trustworthy.
"""

from __future__ import annotations

import logging

_TARGET_ATTR = "_nitls_channel_target"


def tag_channel_target(channel: object, target: str) -> None:
    """Record on a channel the ``host:port`` it was created for. Never raises."""
    try:
        setattr(channel, _TARGET_ATTR, target)
    except Exception:
        logging.getLogger(__name__).debug(
            "Unable to tag channel; it will go unaudited and will not elaborate on "
            "connection errors.",
            exc_info=True,
        )


def get_channel_target(channel: object) -> str:
    """Return the ``host:port`` a channel was created for, or empty if we did not create it."""
    target = getattr(channel, _TARGET_ATTR, "")
    return target if isinstance(target, str) else ""


def is_nitls_channel(channel: object) -> bool:
    """Return whether this package created the channel."""
    return bool(get_channel_target(channel))
