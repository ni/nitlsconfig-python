# pypi-nitlsconfig

Python API that reads nitlsconfig configurations through `nitlsconfig` command line.

## Runtime dependencies

- nitlsconfig executable, discoverable, or explicit path to NITLSCONFIG_CLI

## Install

- pip install nitlsconfig

## Usage
```python
import nitlsconfig

# List configured services
clients = nitlsconfig.ClientConfig.list()
servers = nitlsconfig.ServerConfig.list()

# Read one client configuration
client_info = nitlsconfig.ClientConfig("ni-mqtt")
print(client_info.service_name)
print(client_info.certificate_mode)
print(client_info.certificate_chain_location.scheme)
print(client_info.certificate_chain_location.path)
print(client_info.certificate_chain_contents)

# Read one server configuration
server_info = nitlsconfig.ServerConfig("ni-windows")
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


