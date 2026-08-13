"Pytests for nitlsconfig.grpc_channel."

import json
from typing import Any, Optional, Sequence, Tuple

import grpc
import pytest
from fake_config import (
    FakeClientConfig,
    FILE_CERT,
    FILE_KEY,
    FILE_TRUST,
    SYSTEM_DEFAULT_TRUST,
)

from nitlsconfig import grpc_channel
from nitlsconfig.cli import (
    CertificateLocation,
    ClientCertMode,
    ClientServerMode,
    LocationScheme,
)

TARGET = "localhost:31763"


class RecordedChannel:
    """Records how the channel was created so tests can assert on it."""

    def __init__(
        self,
        secure: bool,
        target: str,
        options: Sequence[Tuple[str, Any]],
        credentials: Optional[dict[str, Any]] = None,
    ) -> None:
        """Record the arguments used to create the channel."""
        self.secure = secure
        self.target = target
        self.options = list(options)
        self.credentials = credentials


@pytest.fixture(autouse=True)
def fake_grpc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace grpc channel construction so no real connection is attempted."""

    def fake_ssl_channel_credentials(**kwargs: Any) -> dict[str, Any]:
        return kwargs

    def fake_secure_channel(
        target: str, credentials: dict[str, Any], options: Sequence[Tuple[str, Any]] = ()
    ) -> RecordedChannel:
        return RecordedChannel(True, target, options, credentials)

    def fake_insecure_channel(
        target: str, options: Sequence[Tuple[str, Any]] = ()
    ) -> RecordedChannel:
        return RecordedChannel(False, target, options)

    monkeypatch.setattr(grpc, "ssl_channel_credentials", fake_ssl_channel_credentials)
    monkeypatch.setattr(grpc, "secure_channel", fake_secure_channel)
    monkeypatch.setattr(grpc, "insecure_channel", fake_insecure_channel)


def create_channel(
    monkeypatch: pytest.MonkeyPatch, config: FakeClientConfig, **kwargs: Any
) -> RecordedChannel:
    """Create a channel using the supplied configuration instead of the real CLI."""
    monkeypatch.setattr(
        grpc_channel,
        "ClientConfig",
        lambda service_name, server_address: config,
    )
    channel = grpc_channel.create_grpc_client_channel("localhost", 31763, **kwargs)
    assert isinstance(channel, RecordedChannel)
    return channel


def test_server_mode_disabled_is_insecure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = create_channel(monkeypatch, FakeClientConfig())

    assert not channel.secure
    assert channel.target == TARGET


@pytest.mark.parametrize(
    ("server_address", "expected_target"),
    [
        pytest.param("localhost", "localhost:31763", id="host_name"),
        pytest.param("127.0.0.1", "127.0.0.1:31763", id="ipv4"),
        pytest.param("::1", "[::1]:31763", id="ipv6_literal"),
        pytest.param("[::1]", "[::1]:31763", id="ipv6_already_bracketed"),
    ],
)
def test_ipv6_addresses_are_bracketed(
    monkeypatch: pytest.MonkeyPatch, server_address: str, expected_target: str
) -> None:
    """An unbracketed IPv6 literal such as '::1:31763' never connects.

    Verified against a live gRPC server: the bracketed form connects and the
    bare form times out. The failure surfaces at the first RPC rather than at
    channel creation, so it is invisible without this assertion.
    """
    monkeypatch.setattr(
        grpc_channel,
        "ClientConfig",
        lambda service_name, server_address: FakeClientConfig(),
    )

    channel = grpc_channel.create_grpc_client_channel(server_address, 31763)

    assert isinstance(channel, RecordedChannel)
    assert channel.target == expected_target


def test_certificate_mode_does_not_enable_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # server_mode is the master switch: certificate_mode must not enable TLS on its own.
    config = FakeClientConfig(
        server_mode=ClientServerMode.Disabled,
        certificate_mode=ClientCertMode.Managed,
        certificate_chain_location=FILE_CERT,
        certificate_key_location=FILE_KEY,
    )

    channel = create_channel(monkeypatch, config)

    assert not channel.secure


def test_system_default_trust_uses_platform_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # None means "use the platform trust store". Empty bytes would build an empty
    # trust store and fail every connection.
    config = FakeClientConfig(
        server_mode=ClientServerMode.TrustedCertificates,
        certificate_mode=ClientCertMode.Disabled,
        trusted_certificates_location=SYSTEM_DEFAULT_TRUST,
    )

    channel = create_channel(monkeypatch, config)

    assert channel.secure
    assert channel.credentials == {
        "root_certificates": None,
        "private_key": None,
        "certificate_chain": None,
    }


def test_mutual_tls_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = FakeClientConfig(
        server_mode=ClientServerMode.TrustedCertificates,
        certificate_mode=ClientCertMode.Managed,
        certificate_chain_location=FILE_CERT,
        certificate_chain_contents="CERT",
        certificate_key_location=FILE_KEY,
        certificate_key_contents="KEY",
        trusted_certificates_location=FILE_TRUST,
        trusted_certificates_contents="ROOT",
    )

    channel = create_channel(monkeypatch, config)

    assert channel.secure
    assert channel.credentials == {
        "root_certificates": b"ROOT",
        "private_key": b"KEY",
        "certificate_chain": b"CERT",
    }


def test_one_way_tls_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = FakeClientConfig(
        server_mode=ClientServerMode.TrustedCertificates,
        certificate_mode=ClientCertMode.Disabled,
        trusted_certificates_location=FILE_TRUST,
        trusted_certificates_contents="ROOT",
    )

    channel = create_channel(monkeypatch, config)

    assert channel.credentials is not None
    assert channel.credentials["root_certificates"] == b"ROOT"
    assert channel.credentials["private_key"] is None
    assert channel.credentials["certificate_chain"] is None


def test_directory_trust_anchors_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # nitlsconfig resolves a Directory of anchors into one PEM bundle, so Directory
    # is a working trust source and must not be rejected as an unsupported scheme.
    config = FakeClientConfig(
        server_mode=ClientServerMode.TrustedCertificates,
        certificate_mode=ClientCertMode.Disabled,
        trusted_certificates_location=CertificateLocation(LocationScheme.Directory, "trusted.d"),
        trusted_certificates_contents="ROOT_A\nROOT_B",
    )

    channel = create_channel(monkeypatch, config)

    assert channel.credentials is not None
    assert channel.credentials["root_certificates"] == b"ROOT_A\nROOT_B"


def test_skip_hostname_validation_matches_trusted_certificates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # grpc's Python API cannot skip only the hostname check, so this mode is
    # deliberately treated as TrustedCertificates.
    def config(server_mode: ClientServerMode) -> FakeClientConfig:
        return FakeClientConfig(
            server_mode=server_mode,
            certificate_mode=ClientCertMode.Disabled,
            trusted_certificates_location=FILE_TRUST,
            trusted_certificates_contents="ROOT",
        )

    strict = create_channel(monkeypatch, config(ClientServerMode.TrustedCertificates))
    skipped = create_channel(monkeypatch, config(ClientServerMode.SkipHostnameValidation))

    assert skipped.secure
    assert skipped.credentials == strict.credentials
    assert skipped.options == strict.options


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(
            FakeClientConfig(server_mode=ClientServerMode.TrustAlways),
            id="trust_always_unsupported",
        ),
        pytest.param(
            FakeClientConfig(server_mode=ClientServerMode.Unknown),
            id="unknown_server_mode",
        ),
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Unknown,
                trusted_certificates_location=SYSTEM_DEFAULT_TRUST,
            ),
            id="unknown_certificate_mode",
        ),
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Managed,
                certificate_chain_location=CertificateLocation(LocationScheme.Directory, "d"),
                certificate_key_location=FILE_KEY,
                trusted_certificates_location=FILE_TRUST,
            ),
            id="non_file_certificate_scheme",
        ),
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Managed,
                certificate_chain_location=CertificateLocation(LocationScheme.File),
                certificate_key_location=FILE_KEY,
                trusted_certificates_location=FILE_TRUST,
            ),
            id="empty_certificate_path",
        ),
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Disabled,
                trusted_certificates_location=CertificateLocation(LocationScheme.File),
            ),
            id="missing_trust_anchors",
        ),
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Disabled,
                trusted_certificates_location=CertificateLocation(LocationScheme.Unknown),
            ),
            id="unknown_trust_scheme",
        ),
        # A File trust bundle that produced nothing must fail rather than fall back
        # to the platform trust store, which would silently widen trust far beyond
        # the configured anchors.
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Disabled,
                trusted_certificates_location=FILE_TRUST,
                trusted_certificates_contents="",
            ),
            id="empty_trusted_contents",
        ),
        # A configured client certificate whose material is empty must fail rather
        # than silently downgrade the connection to one-way TLS. Opting out of mTLS
        # is expressed by certificate_mode Disabled, not by empty contents.
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Managed,
                certificate_chain_location=FILE_CERT,
                certificate_chain_contents="",
                certificate_key_location=FILE_KEY,
                certificate_key_contents="KEY",
                trusted_certificates_location=FILE_TRUST,
                trusted_certificates_contents="ROOT",
            ),
            id="empty_certificate_chain_contents",
        ),
        pytest.param(
            FakeClientConfig(
                server_mode=ClientServerMode.TrustedCertificates,
                certificate_mode=ClientCertMode.Managed,
                certificate_chain_location=FILE_CERT,
                certificate_chain_contents="CERT",
                certificate_key_location=FILE_KEY,
                certificate_key_contents="",
                trusted_certificates_location=FILE_TRUST,
                trusted_certificates_contents="ROOT",
            ),
            id="empty_certificate_key_contents",
        ),
    ],
)
def test_invalid_configuration_raises(
    monkeypatch: pytest.MonkeyPatch, config: FakeClientConfig
) -> None:
    monkeypatch.setattr(
        grpc_channel,
        "ClientConfig",
        lambda service_name, server_address: config,
    )

    with pytest.raises(grpc_channel.TlsConfigurationError):
        grpc_channel.create_grpc_client_channel("localhost", 31763)


def test_service_name_and_address_are_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The helper discards service_name, so plumbing needs its own check.
    requested = []

    def record_client_config(service_name: str, server_address: str) -> FakeClientConfig:
        requested.append((service_name, server_address))
        return FakeClientConfig()

    monkeypatch.setattr(grpc_channel, "ClientConfig", record_client_config)

    grpc_channel.create_grpc_client_channel("localhost", 31763)
    grpc_channel.create_grpc_client_channel("localhost", 31763, service_name="other-service")

    assert requested == [
        (grpc_channel.DEFAULT_SERVICE_NAME, "localhost"),
        ("other-service", "localhost"),
    ]


def test_no_retry_policy_omits_service_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = create_channel(monkeypatch, FakeClientConfig())

    assert channel.options == []


def test_retry_policy_service_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = create_channel(
        monkeypatch, FakeClientConfig(), retry_policy=grpc_channel.RetryPolicy()
    )

    (key, value) = channel.options[0]
    assert key == "grpc.service_config"
    retry_policy = json.loads(value)["methodConfig"][0]["retryPolicy"]
    assert retry_policy == {
        "maxAttempts": 5,
        "initialBackoff": "0.100s",
        "maxBackoff": "1.000s",
        "backoffMultiplier": 2.0,
        "retryableStatusCodes": ["UNAVAILABLE"],
    }


def test_caller_service_config_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller_options = [("grpc.service_config", "{}")]

    channel = create_channel(
        monkeypatch,
        FakeClientConfig(),
        options=caller_options,
        retry_policy=grpc_channel.RetryPolicy(),
    )

    assert channel.options == caller_options


@pytest.mark.parametrize(
    "retry_policy",
    [
        pytest.param(grpc_channel.RetryPolicy(max_attempts=1), id="single_attempt"),
        pytest.param(grpc_channel.RetryPolicy(initial_delay_ms=0), id="no_initial_delay"),
        pytest.param(grpc_channel.RetryPolicy(max_delay_ms=0), id="no_max_delay"),
        pytest.param(grpc_channel.RetryPolicy(backoff_multiplier=0), id="no_backoff_multiplier"),
    ],
)
def test_disabled_retry_policy_omits_service_config(
    monkeypatch: pytest.MonkeyPatch, retry_policy: grpc_channel.RetryPolicy
) -> None:
    # gRPC rejects these values, so they mean "no retries" rather than an error.
    channel = create_channel(monkeypatch, FakeClientConfig(), retry_policy=retry_policy)

    assert channel.options == []


def test_retry_delays_format_as_durations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = create_channel(
        monkeypatch,
        FakeClientConfig(),
        retry_policy=grpc_channel.RetryPolicy(initial_delay_ms=2500, max_delay_ms=90000),
    )

    retry_policy = json.loads(channel.options[0][1])["methodConfig"][0]["retryPolicy"]
    assert retry_policy["initialBackoff"] == "2.500s"
    assert retry_policy["maxBackoff"] == "90.000s"


def test_caller_options_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = create_channel(
        monkeypatch,
        FakeClientConfig(),
        options=[("grpc.max_receive_message_length", 1024)],
    )

    assert channel.options == [("grpc.max_receive_message_length", 1024)]
