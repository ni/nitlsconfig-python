"""The NI TLS services this package builds transports for.

Only the NI gRPC Device Server is supported today. Anything else can still be
read through :class:`~nitlsconfig.cli.ClientConfig`, but has no channel factory.
"""

from __future__ import annotations

# The NI TLS registered service name for the NI gRPC Device Server: the file stem of
# ni-grpc-device.client.caps.yml, the Event Log source, and the record tag are all this
# one name, so records can be tied back to the configuration they describe.
SERVICE_NAME = "ni-grpc-device"
