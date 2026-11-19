"""Guard the credentials protocol without using real secrets."""

import importlib.util
from datetime import UTC, datetime, timedelta

import pytest

from rb_credentials import (
    CallableCredentials,
    Credential,
    CredentialsUnavailable,
    EnvironmentCredentials,
    KeyringCredentials,
    parse_address,
    providers_for,
    resolve_credential,
)


def test_environment_provider_reads_the_mapped_variable() -> None:
    provider = EnvironmentCredentials({"api": "API_TOKEN"}, {"API_TOKEN": "value"})
    credential = provider.resolve("api")
    assert credential is not None
    assert credential.token.get_secret_value() == "value"


def test_unknown_name_and_missing_variable_return_none() -> None:
    provider = EnvironmentCredentials({"api": "API_TOKEN"}, {})
    assert provider.resolve("api") is None
    assert provider.resolve("other") is None


def test_the_first_provider_with_a_value_wins() -> None:
    empty = CallableCredentials(lambda name: None)
    answering = CallableCredentials(lambda name: "second")
    credential = resolve_credential(empty, answering, name="api")
    assert credential.token.get_secret_value() == "second"


def test_missing_credential_names_the_credential_not_a_value() -> None:
    with pytest.raises(CredentialsUnavailable) as failure:
        resolve_credential(CallableCredentials(lambda name: None), name="api")
    assert "api" in str(failure.value)


def test_token_is_masked_and_blank_tokens_are_rejected() -> None:
    credential = Credential(name="api", token="secret-value")
    assert "secret-value" not in repr(credential)
    assert credential.token.get_secret_value() == "secret-value"
    with pytest.raises(ValueError):
        Credential(name="api", token="  ")


def test_expiry_is_explicit() -> None:
    expired = Credential(
        name="api", token="value", expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    assert expired.is_expired()
    assert not Credential(name="api", token="value").is_expired()


def test_keyring_without_the_extra_returns_none() -> None:
    provider = KeyringCredentials({"api": "service/account"})
    if importlib.util.find_spec("keyring") is None:
        assert provider.resolve("api") is None


def test_addresses_are_parsed_by_scheme() -> None:
    assert parse_address("env:API_TOKEN") == ("env", "API_TOKEN", None)
    assert parse_address("keyring:service/account") == ("keyring", "service", "account")
    for address in ("API_TOKEN", "env:", "keyring:service", "vault:path"):
        with pytest.raises(ValueError):
            parse_address(address)


def test_providers_built_from_a_mapping_resolve_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("API_TOKEN", "token")
    providers = providers_for({"api": "env:API_TOKEN"})
    assert resolve_credential(*providers, name="api").token.get_secret_value() == "token"
