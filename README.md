# nitlsconfig

Python API that reads nitlsconfig configurations through the `nitlsconfig` command line,
and builds gRPC client channels from them.

Installed and imported as `nitlsconfig`; developed at
[ni/nitlsconfig-python](https://github.com/ni/nitlsconfig-python).

## Runtime dependencies

- nitlsconfig executable, discoverable.

## Install

Reading NI-TLS configuration is pure Python and has no third-party dependencies:

- `pip install nitlsconfig`

The gRPC channel factory additionally needs grpcio, which is an optional extra:

- `pip install nitlsconfig[grpc]`

## Creating a gRPC channel

`create_grpc_device_channel` reads the local NI-TLS client configuration for the NI
gRPC Device Server and returns a `grpc.Channel` secured accordingly. The
`server_address` hostname or address is used to select matching target-specific NI-TLS
settings. Pass the channel straight to any NI gRPC Python API:

```python
import nidcpower
import nitlsconfig

with nitlsconfig.create_grpc_device_channel("localhost", 31763) as channel:
    options = nidcpower.GrpcSessionOptions(channel, "")
    with nidcpower.Session("Dev1", grpc_options=options) as session:
        ...
```

The channel is mutually authenticated, one-way TLS, or insecure depending on how
the machine is configured; no code change is needed to move between them. The
channel is owned by the caller - NI driver APIs never close it.

Retries are opt-in:

```python
channel = nitlsconfig.create_grpc_device_channel(
    "localhost", 31763, retry_policy=nitlsconfig.RetryPolicy()
)
```

`TlsConfigurationError` is raised when TLS is enabled but the configuration is
unusable. It is always importable, since handling it does not require grpcio.

`create_grpc_device_channel` and `RetryPolicy` do require grpcio; accessing them
without the `grpc` extra installed raises `ImportError` telling you which extra
to install.

## Reading configurations
```python
import nitlsconfig

# List configured services
clients = nitlsconfig.ClientConfig.list_services()
servers = nitlsconfig.ServerConfig.list_services()

if clients:
    # Read one client configuration
    client_info = nitlsconfig.ClientConfig(clients[0])
    print(client_info.service_name)
    print(client_info.certificate_mode)
    print(client_info.certificate_chain_location.scheme)
    print(client_info.certificate_chain_location.path)
    print(client_info.certificate_chain_contents)

    # Inspect target-specific configurations
    for known_server in client_info.known_servers:
        print(known_server.server_name)
        print(known_server.server_mode)
        print(known_server.trusted_certificates_location)

if servers:
    # Read one server configuration
    server_info = nitlsconfig.ServerConfig(servers[0])
    print(server_info.service_name)
    print(server_info.certificate_mode)
    print(server_info.client_mode)
    print(server_info.certificate_chain_location.scheme)
    print(server_info.certificate_key_location.scheme)
    print(server_info.trusted_certificates_location.scheme)
    print(server_info.trusted_certificates_contents)
    print(server_info.certificate_key_contents)

    # Enumerate trusted certificates
    for cert in server_info.trusted_certificates:
        print(cert.display_name)
        print(cert.trusted_certificate_location.path)
        print(cert.trusted_certificate_contents)
```


