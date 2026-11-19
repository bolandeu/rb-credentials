"""The store: the family's naming conventions, the keychain with its index, and the env-var fallback."""

from __future__ import annotations

import json

import pytest

from rb_credentials import CredentialsUnavailable, Store, StoreUnavailable
from rb_credentials import store as store_module


class FakeKeyring:
    """The small part of keyring the store uses, in memory."""

    class errors:  # mirrors keyring.errors
        class KeyringError(Exception): ...

        class PasswordDeleteError(KeyringError): ...

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], str] = {}
        self.fail = False

    def get_password(self, service: str, user: str) -> str | None:
        if self.fail:
            raise self.errors.KeyringError("no secret service")
        return self.entries.get((service, user))

    def set_password(self, service: str, user: str, value: str) -> None:
        if self.fail:
            raise self.errors.KeyringError("no secret service")
        self.entries[(service, user)] = value

    def delete_password(self, service: str, user: str) -> None:
        if self.fail:
            raise self.errors.KeyringError("no secret service")
        if (service, user) not in self.entries:
            raise self.errors.PasswordDeleteError("absent")
        del self.entries[(service, user)]

    def get_keyring(self) -> object:
        return self


@pytest.fixture
def keyring(monkeypatch: pytest.MonkeyPatch) -> FakeKeyring:
    fake = FakeKeyring()
    monkeypatch.setattr(store_module, "_keyring", lambda: fake)
    return fake


def test_the_family_names() -> None:
    store = Store("serp")
    assert store.service_name("xmlriver") == "serp:xmlriver"
    assert store.env_var_name("xmlriver", "api_key") == "SERP_XMLRIVER_API_KEY"
    assert store.env_var_name("deploy:example.com", "api_key") == "SERP_DEPLOY_EXAMPLE_COM_API_KEY"


def test_a_stored_secret_round_trips(keyring: FakeKeyring) -> None:
    store = Store("demo")
    store.store_secret("openai", "sk-1")
    assert store.get_secret("openai") == "sk-1"
    assert store.stored_names() == ["openai"]
    store.delete("openai")
    assert store.get_secret("openai") is None
    assert store.stored_names() == []


def test_env_wins_over_the_keychain_field_by_field(keyring: FakeKeyring, monkeypatch: pytest.MonkeyPatch) -> None:
    store = Store("demo")
    store.store("host", {"user": "u", "password": "p"})
    monkeypatch.setenv("DEMO_HOST_PASSWORD", "rotated")
    credential = store.get("host", env_fields=["user", "password"])
    assert credential == {"user": "u", "password": "rotated"}


def test_a_multi_field_credential_survives_as_one_blob(keyring: FakeKeyring) -> None:
    store = Store("demo")
    store.store("site", {"cookie": "c", "csrf": "t"})
    assert json.loads(keyring.entries[("demo:site", "site")]) == {"cookie": "c", "csrf": "t"}
    assert store.get("site") == {"cookie": "c", "csrf": "t"}


def test_locate_names_the_source_without_the_value(keyring: FakeKeyring, monkeypatch: pytest.MonkeyPatch) -> None:
    store = Store("demo")
    store.store_secret("openai", "stored")
    monkeypatch.setenv("DEMO_OTHER_API_KEY", "from-env")
    assert store.locate("openai", ["api_key"])["api_key"] == ("stored", "keychain", "demo:openai")
    assert store.locate("other", ["api_key"])["api_key"] == ("from-env", "env", "DEMO_OTHER_API_KEY")


def test_a_shared_namespace_is_read_but_never_written(keyring: FakeKeyring) -> None:
    Store("neighbour").store_secret("openai", "theirs")
    store = Store("demo", shared_namespaces=("neighbour",))
    assert store.get_secret("openai") == "theirs"
    assert store.stored_names() == []


def test_without_a_keyring_the_environment_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_module, "_keyring", lambda: None)
    store = Store("demo")
    monkeypatch.setenv("DEMO_OPENAI_API_KEY", "from-env")
    assert store.get_secret("openai") == "from-env"
    assert store.backend() is None
    with pytest.raises(StoreUnavailable):
        store.store_secret("openai", "x")


def test_require_names_the_variable_to_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_module, "_keyring", lambda: None)
    store = Store("demo")
    with pytest.raises(CredentialsUnavailable) as excinfo:
        store.require("openai")
    assert "DEMO_OPENAI_API_KEY" in str(excinfo.value)


def test_a_broken_keyring_falls_back_to_the_environment(keyring: FakeKeyring, monkeypatch: pytest.MonkeyPatch) -> None:
    keyring.fail = True
    store = Store("demo")
    monkeypatch.setenv("DEMO_OPENAI_API_KEY", "from-env")
    assert store.get_secret("openai") == "from-env"
    assert store.stored_names() == []


# --- the name-and-address API that predates the store ---------------------------------


def test_parse_address_understands_env_and_keyring() -> None:
    from rb_credentials import parse_address

    assert parse_address("env:OPENAI_KEY") == ("env", "OPENAI_KEY", None)
    assert parse_address("keyring:openai/bob") == ("keyring", "openai", "bob")
    with pytest.raises(ValueError):
        parse_address("file:/tmp/secret")


def test_providers_resolve_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    from rb_credentials import providers_for, resolve_credential

    monkeypatch.setenv("OPENAI_KEY", "sk-env")
    credential = resolve_credential(*providers_for({"openai": "env:OPENAI_KEY"}), name="openai")
    assert credential.token.get_secret_value() == "sk-env"
    assert credential.name == "openai"


def test_resolve_names_the_missing_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    from rb_credentials import providers_for, resolve_credential

    monkeypatch.delenv("ABSENT_KEY", raising=False)
    with pytest.raises(CredentialsUnavailable) as excinfo:
        resolve_credential(*providers_for({"absent": "env:ABSENT_KEY"}), name="absent")
    assert "absent" in str(excinfo.value)


def test_a_callable_provider_adapts_any_reader() -> None:
    from rb_credentials import CallableCredentials, resolve_credential

    provider = CallableCredentials(lambda name: "value" if name == "x" else None)
    assert resolve_credential(provider, name="x").token.get_secret_value() == "value"


def test_an_expired_credential_says_so() -> None:
    from datetime import UTC, datetime, timedelta

    from rb_credentials import Credential

    past = datetime.now(UTC) - timedelta(minutes=1)
    assert Credential(name="a", token="t", expires_at=past).is_expired()
    assert not Credential(name="a", token="t").is_expired()


def test_a_legacy_variable_is_read_after_the_family_one(monkeypatch: pytest.MonkeyPatch, keyring: FakeKeyring) -> None:
    store = Store("serp")
    monkeypatch.setenv("XMLRIVER_API_KEY", "legacy")
    assert store.get("xmlriver", env_fields=["api_key"], legacy_env={"api_key": "XMLRIVER_API_KEY"}) == {
        "api_key": "legacy"
    }
    monkeypatch.setenv("SERP_XMLRIVER_API_KEY", "family")
    located = store.locate("xmlriver", ["api_key"], legacy_env={"api_key": "XMLRIVER_API_KEY"})
    assert located["api_key"] == ("family", "env", "SERP_XMLRIVER_API_KEY")


def test_deleting_an_absent_credential_is_not_an_error(keyring: FakeKeyring) -> None:
    Store("demo").delete("never-stored")


def test_the_backend_is_reported_for_doctor(keyring: FakeKeyring) -> None:
    assert Store("demo").backend()


def test_a_broken_index_does_not_break_listing(keyring: FakeKeyring) -> None:
    keyring.entries[("demo", "__stored_credentials__")] = "not json"
    assert Store("demo").stored_names() == []


def test_the_real_keyring_backend_is_detected() -> None:
    """Without monkeypatching: with the extra installed a backend exists, without it the store says so."""
    backend = store_module._keyring()
    if backend is None:
        assert Store("demo").backend() is None
    else:
        assert Store("demo").backend()


def test_the_reason_a_keychain_could_not_be_read_is_public(keyring: FakeKeyring) -> None:
    store = Store("demo")
    assert store.unavailable_reason is None
    keyring.fail = True
    store.stored("openai")
    assert "secret service" in (store.unavailable_reason or "")


def test_one_raw_value_per_slot(keyring: FakeKeyring) -> None:
    store = Store("google-oauth")
    store.set_value("service_account", '{"k": 1}')
    assert store.get_value("service_account") == '{"k": 1}'
    store.set_value("api_key", "key-1", name="psi")
    assert store.get_value("api_key", "psi") == "key-1"
    store.delete_value("service_account")
    assert store.get_value("service_account") is None
    store.delete_value("never-there")


def test_slot_errors_are_store_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_module, "_keyring", lambda: None)
    store = Store("demo")
    with pytest.raises(StoreUnavailable):
        store.set_value("service_account", "{}")
    with pytest.raises(StoreUnavailable):
        store.delete_value("service_account")


def test_a_failing_keychain_on_slots(keyring: FakeKeyring) -> None:
    store = Store("demo")
    keyring.fail = True
    assert store.get_value("service_account") is None
    assert store.unavailable_reason
    with pytest.raises(StoreUnavailable):
        store.set_value("service_account", "{}")
    with pytest.raises(StoreUnavailable):
        store.delete_value("service_account")
