"""Read-only configuration from nitlsconfig."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import subprocess  # nosec B404 - required to invoke the trusted nitlsconfig CLI
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Tuple, TypeVar

ALLOWED_SCOPES: Tuple[str, ...] = ("client", "server")

NITLSCONFIG_CLI_ENV_VAR = "NITLSCONFIG_CLI"

# Expected JSON root keys from nitlsconfig output.
ROLE_TO_JSON_ROOT_KEY = {
    "client": "client",
    "server": "server",
}


# Command templates are based on nitlsconfigcli README and fixture scripts.
LIST_COMMAND_TEMPLATE: Tuple[str, ...] = ("{role}", "list")

CLIENT_BATCH_READ_COMMAND_TEMPLATE: Tuple[str, ...] = (
    "--output-format=json",
    "client",
    "batch-read",
    "conf",
    "version",
    "raw",
    "display_name_en",
    "conf",
    "certificate_mode",
    "conf",
    "certificate_chain_location",
    "conf",
    "certificate_chain_contents",
    "conf",
    "certificate_key_location",
    "conf",
    "certificate_key_contents",
    "conf",
    "server_mode",
    "conf",
    "server_name",
    "conf",
    "trusted_certificates_location",
    "conf",
    "trusted_certificates_contents",
)

SERVER_BATCH_READ_COMMAND_TEMPLATE: Tuple[str, ...] = (
    "--output-format=json",
    "server",
    "batch-read",
    "conf",
    "version",
    "raw",
    "display_name_en",
    "conf",
    "certificate_mode",
    "conf",
    "certificate_chain_location",
    "conf",
    "certificate_chain_contents",
    "conf",
    "certificate_key_location",
    "conf",
    "certificate_key_contents",
    "conf",
    "client_mode",
    "conf",
    "trusted_certificates_location",
    "conf",
    "trusted_certificates_contents",
    "raw",
    "trusted_certificate_location",
    "raw",
    "trusted_certificate_contents",
)


class NitlsconfigCliError(RuntimeError):
    """Base error for nitlsconfig command invocation failures."""


class ExecutableNotFoundError(NitlsconfigCliError):
    """Raised when a usable nitlsconfig executable cannot be found."""


class CommandFailedError(NitlsconfigCliError):
    """Raised when nitlsconfig exits with a non-zero return code."""


class InvalidOutputError(NitlsconfigCliError):
    """Raised when command output cannot be parsed as expected."""


class ServerCertMode(str, Enum):
    "Server TLS certificate mode."

    Disabled = "Disabled"
    Unmanaged = "Unmanaged"
    ManagedSelfSigned = "ManagedSelfSigned"
    Unknown = "Unknown"


class ServerClientMode(str, Enum):
    "Server TLS client mode."

    Disabled = "Disabled"
    Unmanaged = "Unmanaged"
    ManagedSelfSigned = "ManagedSelfSigned"
    Unknown = "Unknown"


class ClientCertMode(str, Enum):
    "Client TLS certificate mode."

    Disabled = "Disabled"
    Unmanaged = "Unmanaged"
    Managed = "Managed"
    Unknown = "Unknown"


class ClientServerMode(str, Enum):
    "Client TLS server mode."

    Disabled = "Disabled"
    TrustedCertificates = "TrustedCertificates"
    SkipHostnameValidation = "SkipHostnameValidation"
    TrustAlways = "TrustAlways"
    Unknown = "Unknown"


class LocationScheme(str, Enum):
    "Location scheme for certificate and key locations."

    File = "File"
    Directory = "Directory"
    SystemDefault = "SystemDefault"
    Unknown = "Unknown"


@dataclass(frozen=True)
class CertificateLocation:
    "Typed wrapper for certificate and key locations."

    scheme: LocationScheme
    path: str = ""

    @classmethod
    def from_string(cls, value: str) -> "CertificateLocation":
        "Parse a location string into a typed CertificateLocation object."
        if value.startswith("File://"):
            return cls(LocationScheme.File, value[len("File://") :])
        if value.startswith("Directory://"):
            return cls(LocationScheme.Directory, value[len("Directory://") :])
        if value == "SystemDefault":
            return cls(LocationScheme.SystemDefault, "")
        return cls(LocationScheme.Unknown, value)

    def to_string(self) -> str:
        "Output string representation."
        if self.scheme == LocationScheme.File:
            return f"File://{self.path}"
        if self.scheme == LocationScheme.Directory:
            return f"Directory://{self.path}"
        if self.scheme == LocationScheme.SystemDefault:
            return "SystemDefault"
        return self.path

    def __str__(self) -> str:
        "Auto string conversion."
        return self.to_string()


EnumT = TypeVar("EnumT", bound=Enum)


def _parse_enum(value: str, enum_cls: type[EnumT], unknown_member: EnumT) -> EnumT:
    "Parse a string value into an Enum member, returning unknown_member if not found."
    try:
        return enum_cls(value)
    except ValueError:
        return unknown_member


@dataclass(frozen=True)
class KnownServerData:
    """Typed wrapper for known server objects from CLI JSON."""

    raw: dict[str, Any]
    display_name: str = field()
    certificate_mode: ClientCertMode = field()
    certificate_chain_location: CertificateLocation = field()
    certificate_chain_contents: str = field()
    certificate_key_location: CertificateLocation = field()
    certificate_key_contents: str = field()
    server_mode: ClientServerMode = field()
    server_name: str = field()
    trusted_certificates_location: CertificateLocation = field()
    trusted_certificates_contents: str = field()

    @classmethod
    def from_json_obj(cls, obj: dict[str, Any]) -> "KnownServerData":
        "Parse a known server object from CLI JSON into KnownServerData."
        return cls(
            raw=obj,
            display_name=obj.get("display_name_en", ""),
            certificate_mode=_parse_enum(
                obj.get("certificate_mode", ""),
                ClientCertMode,
                ClientCertMode.Unknown,
            ),
            certificate_chain_location=CertificateLocation.from_string(
                obj.get("certificate_chain_location", "")
            ),
            certificate_chain_contents=obj.get("certificate_chain_contents", ""),
            certificate_key_location=CertificateLocation.from_string(
                obj.get("certificate_key_location", "")
            ),
            certificate_key_contents=obj.get("certificate_key_contents", ""),
            server_mode=_parse_enum(
                obj.get("server_mode", ""),
                ClientServerMode,
                ClientServerMode.Unknown,
            ),
            server_name=obj.get("server_name", ""),
            trusted_certificates_location=CertificateLocation.from_string(
                obj.get("trusted_certificates_location", "")
            ),
            trusted_certificates_contents=obj.get("trusted_certificates_contents", ""),
        )


@dataclass(frozen=True)
class TrustedCertificateData:
    """Typed wrapper for trusted certificate objects from CLI JSON."""

    raw: dict[str, Any]
    display_name: str = field()
    trusted_certificate_location: CertificateLocation = field()
    trusted_certificate_contents: str = field()

    @classmethod
    def from_json_obj(cls, obj: dict[str, Any]) -> "TrustedCertificateData":
        "Parse a trusted certificate object from CLI JSON into TrustedCertificateData."
        return cls(
            raw=obj,
            display_name=obj.get("display_name_en", ""),
            trusted_certificate_location=CertificateLocation.from_string(
                obj.get("trusted_certificate_location", "")
            ),
            trusted_certificate_contents=obj.get("trusted_certificate_contents", ""),
        )


@dataclass(frozen=True)
class ServiceData:
    """Typed wrapper for service objects from CLI JSON."""

    raw: dict[str, Any]
    known_servers: list[KnownServerData] = field(default_factory=list)
    trusted_certificates: list[TrustedCertificateData] = field(default_factory=list)

    @classmethod
    def from_json_obj(cls, obj: dict[str, Any]) -> "ServiceData":
        "Parse a service object from CLI JSON into a typed ServiceData object."
        known_servers_raw = obj.get("known_servers", [])
        known_servers: list[KnownServerData] = []
        if isinstance(known_servers_raw, list):
            for item in known_servers_raw:
                if isinstance(item, dict):
                    known_servers.append(KnownServerData.from_json_obj(item))

        trusted_certificates_raw = obj.get("trusted_certificates", [])
        trusted_certificates: list[TrustedCertificateData] = []
        if isinstance(trusted_certificates_raw, list):
            for item in trusted_certificates_raw:
                if isinstance(item, dict):
                    trusted_certificates.append(TrustedCertificateData.from_json_obj(item))

        return cls(raw=obj, known_servers=known_servers, trusted_certificates=trusted_certificates)

    def value(self, key: str, default: str = "") -> str:
        "Fetch value from dict with default, ensuring it is a string."
        value = self.raw.get(key, default)
        if isinstance(value, str):
            return value
        return default


def build_list_command(role: str) -> Tuple[str, ...]:
    """Build argv for list mode only.

    This function does not include executable resolution.
    """
    return tuple(part.format(role=role) for part in LIST_COMMAND_TEMPLATE)


def build_batch_read_command(role: str) -> Tuple[str, ...]:
    """Build argv template for batch-read mode only.

    The template mirrors existing fixture-generation scripts.
    """
    if role == "client":
        return CLIENT_BATCH_READ_COMMAND_TEMPLATE
    return SERVER_BATCH_READ_COMMAND_TEMPLATE


def run_nitlsconfig_command(
    command_args: Tuple[str, ...],
) -> str:
    """Run nitlsconfig command and return stdout.

    This helper always invokes subprocess in shell-free argv mode.
    """
    executable = "nitlsconfig"
    argv = [executable, *command_args]

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )  # nosec B603 - argv is passed shell-free and executable selection is controlled
    except FileNotFoundError as ex:
        fallback_root = os.environ.get(NITLSCONFIG_CLI_ENV_VAR)
        if fallback_root and fallback_root != executable:
            suffix = ".exe" if platform.system().lower() == "windows" else ""
            fallback_executable = pathlib.Path(fallback_root) / f"nitlsconfig{suffix}"
            fallback_executable_str = str(fallback_executable)
            fallback_argv = [fallback_executable_str, *command_args]
            try:
                completed = subprocess.run(
                    fallback_argv,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )  # nosec B603 - argv is passed shell-free and fallback executable is explicit
                argv = fallback_argv
            except FileNotFoundError as fallback_ex:
                raise ExecutableNotFoundError(
                    "Unable to find nitlsconfig executable. "
                    f"Tried {executable!r} and {NITLSCONFIG_CLI_ENV_VAR}={fallback_root!r}."
                ) from fallback_ex
        else:
            raise ExecutableNotFoundError(
                "Unable to find nitlsconfig executable. " f"Tried {executable!r}."
            ) from ex

    if completed.returncode != 0:
        command_display = " ".join(argv)
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        details = stderr if stderr else stdout
        raise CommandFailedError(
            "nitlsconfig command failed "
            f"(exit={completed.returncode}): {command_display}. "
            f"Output: {details}"
        )

    return completed.stdout


def run_nitlsconfig_json_command(
    command_args: Tuple[str, ...],
) -> Any:
    """Run nitlsconfig command and parse stdout as JSON."""
    stdout = run_nitlsconfig_command(
        command_args=command_args,
    )

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as ex:
        snippet = stdout[:240].replace("\n", "\\n")
        raise InvalidOutputError(
            "Failed to parse nitlsconfig JSON output. " f"Command output starts with: {snippet!r}"
        ) from ex


def _list_services(scope: str) -> list[str]:
    """List configured services for the requested scope.

    Output is parsed line-by-line and normalized by stripping whitespace and
    dropping empty lines.
    """
    stdout = run_nitlsconfig_command(command_args=build_list_command(scope))
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def _read_services(scope: str) -> list[ServiceData]:
    """Read full service configurations for the requested scope.

    Parsed output preserves the original key casing and values from the CLI JSON.
    """
    payload = run_nitlsconfig_json_command(command_args=build_batch_read_command(scope))

    if not isinstance(payload, dict):
        raise InvalidOutputError("nitlsconfig JSON output root must be an object")

    if scope not in ROLE_TO_JSON_ROOT_KEY:
        raise InvalidOutputError(f"Unsupported scope for nitlsconfig JSON output: {scope!r}")

    root_key = ROLE_TO_JSON_ROOT_KEY[scope]
    if root_key not in payload:
        raise InvalidOutputError(f"nitlsconfig JSON output missing expected root key: {root_key!r}")

    services = payload[root_key]
    if not isinstance(services, list):
        raise InvalidOutputError(f"nitlsconfig JSON root key {root_key!r} must contain a list")

    normalized: list[ServiceData] = []
    for item in services:
        if isinstance(item, dict):
            normalized.append(ServiceData.from_json_obj(item))
        else:
            raise InvalidOutputError("nitlsconfig service entries must be objects")
    return normalized


class _BaseConfig:
    """Shared read-only behavior for service configuration wrappers."""

    _scope = ""

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self._data = self._find_service_data(service_name)

    @classmethod
    def list_services(cls) -> list[str]:
        return _list_services(cls._scope)

    @classmethod
    def _read_all(cls) -> list[ServiceData]:
        return _read_services(cls._scope)

    @classmethod
    def _find_service_data(cls, service_name: str) -> ServiceData:
        for item in cls._read_all():
            if item.value("service_name") == service_name:
                return item

        # Keep behavior compatible with minimal list-only service entries.
        if service_name in cls.list_services():
            return ServiceData(raw={"service_name": service_name})

        raise InvalidOutputError(f"Service not found: {service_name!r}")

    def _value(self, key: str, default: str = "") -> str:
        return self._data.value(key, default)

    def _location(self, key: str) -> CertificateLocation:
        return CertificateLocation.from_string(self._value(key))

    @property
    def certificate_mode_raw(self) -> str:
        return self._value("certificate_mode")

    @property
    def certificate_chain_location_raw(self) -> str:
        return self._value("certificate_chain_location")

    @property
    def certificate_chain_contents_raw(self) -> str:
        return self._value("certificate_chain_contents")


class ServerConfig(_BaseConfig):
    """Read-only view for server-side TLS configuration."""

    _scope = "server"

    @property
    def certificate_mode(self) -> ServerCertMode:
        "Parse certificate_mode string into ServerCertMode enum, defaulting to Unknown."
        return _parse_enum(
            self.certificate_mode_raw,
            ServerCertMode,
            ServerCertMode.Unknown,
        )

    @property
    def certificate_chain_location(self) -> CertificateLocation:
        "Return the parsed certificate_chain_location from the service configuration."
        return self._location("certificate_chain_location")

    @property
    def certificate_chain_contents(self) -> str:
        "Return the raw certificate_chain_contents string from the service configuration."
        return self._value("certificate_chain_contents")

    @property
    def certificate_key_location(self) -> CertificateLocation:
        "Return the parsed certificate_key_location from the service configuration."
        return self._location("certificate_key_location")

    @property
    def certificate_key_contents(self) -> str:
        "Return the raw certificate_key_contents string from the service configuration."
        return self._value("certificate_key_contents")

    @property
    def client_mode(self) -> ServerClientMode:
        "Parse client_mode string into ServerClientMode enum, defaulting to Unknown."
        return _parse_enum(
            self._value("client_mode"),
            ServerClientMode,
            ServerClientMode.Unknown,
        )

    @property
    def trusted_certificates_location(self) -> CertificateLocation:
        "Return the parsed trusted_certificates_location from the service configuration."
        return self._location("trusted_certificates_location")

    @property
    def trusted_certificates_contents(self) -> str:
        "Return the raw trusted_certificates_contents string from the service configuration."
        return self._value("trusted_certificates_contents")

    @property
    def trusted_certificates(self) -> list[TrustedCertificateData]:
        "Return the list of TrustedCertificateData from the service configuration."
        return self._data.trusted_certificates

    def __str__(self) -> str:
        "Auto string conversion for debugging and display."
        return f"ServerConfig(name={self.service_name}, certificate_mode={self.certificate_mode}, client_mode={self.client_mode})"


class ClientConfig(_BaseConfig):
    """Read-only view for client-side TLS configuration."""

    _scope = "client"

    def __init__(self, service_name: str, server_address: Optional[str] = None) -> None:
        """Read client configuration, optionally resolved for a server address.

        When ``server_address`` matches a known server, its configuration is used.
        Otherwise, the generic service configuration remains in effect.
        """
        self.service_name = service_name
        self.server_address = server_address
        self._data = self._find_service_data(service_name)
        self._resolved_data = self._data
        if server_address is not None:
            known_server = next(
                (item for item in self._data.known_servers if item.server_name == server_address),
                None,
            )
            if known_server is not None:
                self._resolved_data = ServiceData(raw=known_server.raw)

    def _value(self, key: str, default: str = "") -> str:
        return self._resolved_data.value(key, default)

    @property
    def certificate_mode(self) -> ClientCertMode:
        "Parse certificate_mode string into ClientCertMode enum, defaulting to Unknown."
        return _parse_enum(
            self.certificate_mode_raw,
            ClientCertMode,
            ClientCertMode.Unknown,
        )

    @property
    def server_mode(self) -> ClientServerMode:
        "Parse server_mode string into ClientServerMode enum, defaulting to Unknown."
        return _parse_enum(
            self._value("server_mode"),
            ClientServerMode,
            ClientServerMode.Unknown,
        )

    @property
    def certificate_key_location(self) -> CertificateLocation:
        "Return the parsed certificate_key_location from the service configuration."
        return self._location("certificate_key_location")

    @property
    def certificate_key_contents(self) -> str:
        "Return the raw certificate_key_contents string from the service configuration."
        return self._value("certificate_key_contents")

    @property
    def known_servers(self) -> list[KnownServerData]:
        "Return the typed known-server configurations from the service configuration."
        return self._data.known_servers

    @property
    def certificate_chain_contents(self) -> str:
        "Return the raw certificate_chain_contents string from the service configuration."
        return self._value("certificate_chain_contents")

    @property
    def certificate_chain_location(self) -> CertificateLocation:
        "Return the parsed certificate_chain_location from the service configuration."
        return self._location("certificate_chain_location")

    @property
    def trusted_certificates_contents(self) -> str:
        "Return the raw trusted_certificates_contents string from the service configuration."
        return self._value("trusted_certificates_contents")

    @property
    def trusted_certificates_location(self) -> CertificateLocation:
        "Return the parsed trusted_certificates_location from the service configuration."
        return self._location("trusted_certificates_location")

    def __str__(self) -> str:
        "Auto string conversion for debugging and display."
        return f"ClientConfig(name={self.service_name}, certificate_mode={self.certificate_mode})"


def nitlsconfig_main(argv: Optional[list[str]] = None) -> int:
    """Console entry point for read-only service listing."""
    parser = argparse.ArgumentParser(prog="nitlsconfig-read")
    parser.add_argument("scope", choices=ALLOWED_SCOPES)
    parser.add_argument("command", choices=["list"], nargs="?", default="list")
    args = parser.parse_args(argv)

    try:
        if args.command == "list":
            config_cls = ClientConfig if args.scope == "client" else ServerConfig
            for service in config_cls.list_services():
                print(service)
            return 0
    except NitlsconfigCliError as ex:
        print(str(ex), file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(nitlsconfig_main())
