"Pytests."

import json
import pathlib
import platform
from typing import cast, Mapping, Optional, TypedDict

import grpc
import pytest

import nitlsconfig
import nitlsconfig.cli as nitlsconfig_cli
from nitlsconfig import grpc_channel

TEST_DIR = pathlib.Path(__file__).resolve().parents[0]
CLIENT_FIXTURE_PATH = TEST_DIR / "nitlsconfig_client.json"
SERVER_FIXTURE_PATH = TEST_DIR / "nitlsconfig_server.json"


class NitlsconfigJsonFixtures(TypedDict):
    """Data from nitlsconfig*.json fixtures."""

    client_json: str
    server_json: str
    client_list: str
    server_list: str


def _service_names(payload: Mapping[str, object], scope: str) -> list[str]:
    services = payload.get(scope, [])
    if not isinstance(services, list):
        return []
    return [
        item.get("service_name", "")
        for item in services
        if isinstance(item, dict) and isinstance(item.get("service_name", ""), str)
    ]


@pytest.fixture(scope="session")
def nitlsconfig_json_fixtures() -> NitlsconfigJsonFixtures:
    client_json = CLIENT_FIXTURE_PATH.read_text(encoding="utf-8")
    server_json = SERVER_FIXTURE_PATH.read_text(encoding="utf-8")

    if platform.system().lower() == "linux":
        client_json = client_json.replace("ni-windows", "ni-linux")
        server_json = server_json.replace("ni-windows", "ni-linux")

    client_payload = json.loads(client_json)
    server_payload = json.loads(server_json)

    return {
        "client_json": client_json,
        "server_json": server_json,
        "client_list": "\n".join(_service_names(client_payload, "client")),
        "server_list": "\n".join(_service_names(server_payload, "server")),
    }


@pytest.fixture(autouse=True)
def mock_nitlsconfig_command(
    monkeypatch: pytest.MonkeyPatch,
    nitlsconfig_json_fixtures: NitlsconfigJsonFixtures,
) -> None:
    command_responses: dict[tuple[str, ...], str] = {
        nitlsconfig_cli.build_list_command("client"): nitlsconfig_json_fixtures["client_list"],
        nitlsconfig_cli.build_list_command("server"): nitlsconfig_json_fixtures["server_list"],
        nitlsconfig_cli.build_batch_read_command("client"): nitlsconfig_json_fixtures[
            "client_json"
        ],
        nitlsconfig_cli.build_batch_read_command("server"): nitlsconfig_json_fixtures[
            "server_json"
        ],
    }

    def fake_run_nitlsconfig_command(command_args: tuple[str, ...]) -> str:
        if command_args in command_responses:
            return command_responses[command_args]
        if len(command_args) == 6 and command_args[1] == "read":
            scope, _, service_name, _, keyword, _ = command_args
            fixture_json = (
                nitlsconfig_json_fixtures["client_json"]
                if scope == "client"
                else nitlsconfig_json_fixtures["server_json"]
            )
            payload = json.loads(fixture_json)
            services = payload[scope]
            service = next(
                (item for item in services if item["service_name"] == service_name),
                None,
            )
            if service is None:
                raise AssertionError(f"Unknown fixture service: {service_name!r}")
            return str(service.get(keyword, ""))
        raise AssertionError(f"Unexpected nitlsconfig command args: {command_args!r}")

    monkeypatch.setattr(
        nitlsconfig_cli,
        "run_nitlsconfig_command",
        fake_run_nitlsconfig_command,
    )


def test_list_client() -> None:
    """Test list_client."""
    client_list = nitlsconfig.ClientConfig.list_services()
    assert "ni-test" in client_list
    assert "ni-mqtt" in client_list


def test_list_server() -> None:
    """Test list_server."""
    server_list = nitlsconfig.ServerConfig.list_services()
    assert "ni-test" in server_list
    is_linux = platform.system().lower() == "linux"
    if is_linux:
        assert "ni-linux" in server_list
    else:
        assert "ni-windows" in server_list


def test_client_info() -> None:
    """Test client_info."""
    client_info = nitlsconfig.ClientConfig("ni-test")

    assert client_info.service_name == "ni-test"
    assert client_info.certificate_mode == nitlsconfig.ClientCertMode.Unknown
    # server_mode is the master TLS switch, so its parsing must be pinned.
    assert client_info.server_mode == nitlsconfig.ClientServerMode.Unknown
    client_info = nitlsconfig.ClientConfig("ni-mqtt")

    assert client_info.service_name == "ni-mqtt"
    assert client_info.certificate_mode == nitlsconfig.ClientCertMode.Managed
    assert client_info.server_mode == nitlsconfig.ClientServerMode.TrustedCertificates
    assert client_info.certificate_chain_location.scheme == nitlsconfig.LocationScheme.File
    assert "cert.pem" in client_info.certificate_chain_location.path
    assert "BEGIN CERTIFICATE" in client_info.certificate_chain_contents
    assert "END CERTIFICATE" in client_info.certificate_chain_contents


def test_known_server_info() -> None:
    """Known server entries should expose typed fields, not only raw JSON."""
    client_info = nitlsconfig.ClientConfig("ni-mqtt")

    assert len(client_info.known_servers) == 1
    known_server = client_info.known_servers[0]

    assert known_server.raw["display_name_en"] == "NI MQTT TLS Client"
    assert known_server.display_name == "NI MQTT TLS Client"
    assert known_server.certificate_mode == "Disabled"
    assert known_server.certificate_chain_location.scheme == nitlsconfig.LocationScheme.File
    assert "cert.pem" in known_server.certificate_chain_location.path
    assert "BEGIN CERTIFICATE" in known_server.certificate_chain_contents
    assert "END CERTIFICATE" in known_server.certificate_chain_contents
    assert known_server.certificate_key_location.scheme == nitlsconfig.LocationScheme.File
    assert "key.pem" in known_server.certificate_key_location.path
    assert "BEGIN RSA PRIVATE KEY" in known_server.certificate_key_contents
    assert known_server.server_mode == "TrustedCertificates"
    assert known_server.server_name == "example-host1"
    assert known_server.trusted_certificates_location.scheme == nitlsconfig.LocationScheme.File
    assert "example-host1.pem" in known_server.trusted_certificates_location.path
    assert "BEGIN CERTIFICATE" in known_server.trusted_certificates_contents


def test_client_info_for_known_server_uses_target_specific_values() -> None:
    """Known-server settings override the generic client configuration."""
    client_info = nitlsconfig.ClientConfig("ni-mqtt", "example-host1")

    assert client_info.certificate_mode == nitlsconfig.ClientCertMode.Disabled
    assert client_info.server_mode == nitlsconfig.ClientServerMode.TrustedCertificates
    assert client_info.trusted_certificates_location == nitlsconfig.CertificateLocation(
        nitlsconfig.LocationScheme.File,
        "C:/ProgramData/National Instruments/nitlsconfig/client.d/ni-mqtt/servers/example-host1.pem",
    )
    assert "BEGIN CERTIFICATE" in client_info.trusted_certificates_contents


def test_client_info_for_unknown_server_uses_generic_values() -> None:
    """An unknown server address leaves the generic client configuration in effect."""
    client_info = nitlsconfig.ClientConfig("ni-mqtt", "unknown-server")

    assert client_info.certificate_mode == nitlsconfig.ClientCertMode.Managed
    assert client_info.trusted_certificates_location.scheme == (
        nitlsconfig.LocationScheme.SystemDefault
    )


def test_server_info() -> None:
    """Test server_info."""
    server_info = nitlsconfig.ServerConfig("ni-test")
    assert server_info.service_name == "ni-test"
    assert server_info.certificate_mode == nitlsconfig.ServerCertMode.Unknown

    is_linux = platform.system().lower() == "linux"
    if is_linux:
        server_info = nitlsconfig.ServerConfig("ni-linux")
        assert server_info.service_name == "ni-linux"
    else:
        server_info = nitlsconfig.ServerConfig("ni-windows")
        assert server_info.service_name == "ni-windows"
    assert server_info.certificate_mode == nitlsconfig.ServerCertMode.ManagedSelfSigned
    assert server_info.client_mode == nitlsconfig.ServerClientMode.ManagedSelfSigned
    assert server_info.certificate_chain_location.scheme == nitlsconfig.LocationScheme.File
    assert "cert.pem" in server_info.certificate_chain_location.path
    assert "BEGIN CERTIFICATE" in server_info.certificate_chain_contents
    assert "END CERTIFICATE" in server_info.certificate_chain_contents
    assert server_info.certificate_key_location.scheme == nitlsconfig.LocationScheme.File
    assert server_info.trusted_certificates_location.scheme == nitlsconfig.LocationScheme.Directory
    assert "trusted.d" in server_info.trusted_certificates_location.path
    assert "alpha-trusted-certificate" in server_info.trusted_certificates_contents
    assert "beta-trusted-certificate" in server_info.trusted_certificates_contents
    assert "BEGIN RSA PRIVATE KEY" in server_info.certificate_key_contents
    assert server_info.certificate_key_location.scheme == nitlsconfig.LocationScheme.File
    assert "key.pem" in server_info.certificate_key_location.path

    assert len(server_info.trusted_certificates) == 2
    assert server_info.trusted_certificates[0].display_name == "NI Test Service"
    assert (
        server_info.trusted_certificates[0].trusted_certificate_location.scheme
        == nitlsconfig.LocationScheme.File
    )
    assert "alpha.pem" in server_info.trusted_certificates[0].trusted_certificate_location.path
    assert (
        "alpha-trusted-certificate"
        in server_info.trusted_certificates[0].trusted_certificate_contents
    )
    assert server_info.trusted_certificates[1].display_name == "NI Test Service"
    assert (
        server_info.trusted_certificates[1].trusted_certificate_location.scheme
        == nitlsconfig.LocationScheme.File
    )
    assert "beta.pem" in server_info.trusted_certificates[1].trusted_certificate_location.path
    assert (
        "beta-trusted-certificate"
        in server_info.trusted_certificates[1].trusted_certificate_contents
    )


def test_real_config_drives_channel_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real ClientConfig, parsed from CLI output, produces the expected credentials.

    Every other channel test substitutes a fake config, so this is the only one
    that exercises the seam: enum parsing, CertificateLocation.from_string and
    the contents lookups all feed create_grpc_client_channel here. A mis-parsed
    server_mode would silently produce an insecure channel and be invisible
    elsewhere in the suite.

    ni-mqtt is configured for mutual TLS with SystemDefault trust anchors.
    """
    captured: dict[str, object] = {}
    real_ssl_channel_credentials = grpc.ssl_channel_credentials

    def spy(**kwargs: Optional[bytes]) -> grpc.ChannelCredentials:
        captured.update(kwargs)
        return real_ssl_channel_credentials(**kwargs)

    monkeypatch.setattr(grpc, "ssl_channel_credentials", spy)

    with grpc_channel.create_grpc_client_channel(
        "localhost", 31763, service_name="ni-mqtt"
    ) as channel:
        assert isinstance(channel, grpc.Channel)

    # SystemDefault trust anchors must arrive as None, not empty bytes.
    assert captured["root_certificates"] is None
    assert b"BEGIN CERTIFICATE" in cast(bytes, captured["certificate_chain"])
    assert b"PRIVATE KEY" in cast(bytes, captured["private_key"])


def test_real_config_with_unknown_server_mode_is_rejected() -> None:
    """ni-test has no server_mode, which must be rejected rather than silently ignored."""
    with pytest.raises(grpc_channel.TlsConfigurationError):
        grpc_channel.create_grpc_client_channel("localhost", 31763, service_name="ni-test")
