"Pytests."

import json
import pathlib
import platform
from typing import Mapping, TypedDict

import pytest

import nitlsconfig
import nitlsconfig.cli as nitlsconfig_cli

TEST_DIR = pathlib.Path(__file__).resolve().parents[0]
CLIENT_FIXTURE_PATH = TEST_DIR / "nitlsconfig_client.json"
SERVER_FIXTURE_PATH = TEST_DIR / "nitlsconfig_server.json"


class NitlsconfigJsonFixtures(TypedDict):
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
    client_info = nitlsconfig.ClientConfig("ni-mqtt")

    assert client_info.service_name == "ni-mqtt"
    assert client_info.certificate_mode == nitlsconfig.ClientCertMode.Managed
    assert client_info.certificate_chain_location.scheme == nitlsconfig.LocationScheme.File
    assert "cert.pem" in client_info.certificate_chain_location.path
    assert "BEGIN CERTIFICATE" in client_info.certificate_chain_contents
    assert "END CERTIFICATE" in client_info.certificate_chain_contents


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
