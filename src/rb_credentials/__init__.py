"""Resolve named credentials without storing, logging or printing secrets.

The package knows credential names; the environment knows addresses. A caller
maps a name such as ``github`` to an address such as an environment variable or
a keychain entry and passes that mapping in. No address is hard-coded here, and
nothing in this module writes a secret anywhere.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator

__all__ = [
    "CallableCredentials",
    "Credential",
    "CredentialProvider",
    "CredentialsUnavailable",
    "EnvironmentCredentials",
    "KeyringCredentials",
    "parse_address",
    "providers_for",
    "resolve_credential",
]


class CredentialsUnavailable(Exception):
    """No provider produced a usable credential for the requested name."""


class Credential(BaseModel):
    """A secret value with an optional expiry and scopes."""

    model_config = ConfigDict(extra="forbid")

    name: str
    token: SecretStr
    expires_at: datetime | None = None
    scopes: tuple[str, ...] = ()

    @field_validator("token")
    @classmethod
    def _not_blank(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("credential token must not be blank")
        return value

    def is_expired(self, *, now: datetime | None = None, leeway: timedelta = timedelta(0)) -> bool:
        """Report whether the credential has expired, with optional leeway."""
        if self.expires_at is None:
            return False
        return self.expires_at <= (now or datetime.now(UTC)) + leeway


@runtime_checkable
class CredentialProvider(Protocol):
    """Read one credential by name, or return None when this provider has none."""

    def resolve(self, name: str) -> Credential | None: ...


class EnvironmentCredentials:
    """Read addresses from a mapping of credential name to environment variable."""

    def __init__(
        self, mapping: Mapping[str, str], environ: Mapping[str, str] | None = None
    ) -> None:
        self.mapping = dict(mapping)
        self.environ = os.environ if environ is None else environ

    def resolve(self, name: str) -> Credential | None:
        variable = self.mapping.get(name)
        if variable is None:
            return None
        raw = self.environ.get(variable)
        if not raw:
            return None
        return Credential(name=name, token=raw)


class CallableCredentials:
    """Adapt any reader function to the provider protocol."""

    def __init__(self, reader: Callable[[str], str | None]) -> None:
        self.reader = reader

    def resolve(self, name: str) -> Credential | None:
        raw = self.reader(name)
        return Credential(name=name, token=raw) if raw else None


class KeyringCredentials:
    """Read addresses like ``service/account`` from the OS keychain.

    The keychain backend comes from the optional ``keyring`` extra. Without it,
    every lookup returns None instead of falling back to a plaintext file.
    """

    def __init__(self, mapping: Mapping[str, str]) -> None:
        self.mapping = dict(mapping)

    def resolve(self, name: str) -> Credential | None:
        address = self.mapping.get(name)
        if address is None or "/" not in address:
            return None
        service, _, account = address.partition("/")
        try:
            keyring = importlib.import_module("keyring")
        except ModuleNotFoundError:
            return None
        try:
            raw = keyring.get_password(service, account)
        except Exception:
            return None
        return Credential(name=name, token=raw) if raw else None


def parse_address(address: str) -> tuple[str, str, str | None]:
    """Split ``env:NAME`` or ``keyring:service/account`` into its parts."""
    scheme, _, value = address.partition(":")
    if scheme == "env" and value:
        return ("env", value, None)
    if scheme == "keyring":
        service, _, account = value.partition("/")
        if service and account:
            return ("keyring", service, account)
    raise ValueError(f"Unsupported credential address scheme: {scheme or 'missing'}")


def providers_for(mapping: Mapping[str, str]) -> tuple[CredentialProvider, ...]:
    """Build providers from a name-to-address mapping owned by the caller."""
    environment: dict[str, str] = {}
    keychain: dict[str, str] = {}
    for name, address in mapping.items():
        scheme, first, second = parse_address(address)
        if scheme == "env":
            environment[name] = first
        else:
            keychain[name] = f"{first}/{second}"
    return (EnvironmentCredentials(environment), KeyringCredentials(keychain))


def resolve_credential(*providers: CredentialProvider, name: str) -> Credential:
    """Return the first credential a provider offers, or raise without a value."""
    for provider in providers:
        credential = provider.resolve(name)
        if credential is not None:
            return credential
    raise CredentialsUnavailable(
        f"No credential is configured for {name!r}. Ask the environment owner to map it."
    )
