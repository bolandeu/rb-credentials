"""The credential store: multi-field credentials in the OS keychain, environment variables where no keychain exists.

A package owns a namespace (its command name) and asks the store about a provider: `openai`, a deploy target
`example.com`, a profile name. One credential is a small dict of named fields stored as one JSON blob per provider:
a single `api_key`, or session cookies, or a host's username and password — the store does not care.

Addresses stay with the caller: the store never hard-codes a variable name, a keychain service or a secret. The
conventions it does implement are the ones every tool of the family shares:

- keychain service `<namespace>:<provider>`, indexed per namespace so `auth status` can list what is stored
  (`keyring` cannot enumerate);
- environment variable `<NAMESPACE>_<PROVIDER>_<FIELD>`, which wins field-by-field over the keychain;
- read-only access to another tool's namespace (`shared_namespaces`), never a write.

A machine without a secret service (headless Linux, a container) is not an error: reads fall back to the
environment, and `backend()` reports the absence for `doctor`.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping

from . import CredentialsUnavailable, StoreUnavailable

__all__ = ["Store"]

# keyring is an optional extra: a caller that only reads environment variables never imports it.
log = logging.getLogger(__name__)

_INDEX_USER = "__stored_credentials__"
_DEFAULT_FIELD = "api_key"


def _keyring():
    """The keyring backend, or None when the extra is not installed / no backend works."""
    try:
        import keyring
        import keyring.errors
        from keyring.backends import fail
    except ImportError:  # the `keyring` extra is not installed: env vars only
        return None
    if isinstance(keyring.get_keyring(), fail.Keyring):
        return None
    return keyring


class Store:
    """Credentials of one package: namespace for the keychain and the environment names."""

    def __init__(self, namespace: str, *, shared_namespaces: tuple[str, ...] = ()) -> None:
        self.namespace = namespace
        self.shared_namespaces = tuple(shared_namespaces)
        self._keychain_problem: str | None = None
        self._warned_missing = False

    # --- names the store builds -------------------------------------------------

    def service_name(self, provider: str) -> str:
        return f"{self.namespace}:{provider}"

    def env_var_name(self, provider: str, field: str) -> str:
        return re.sub(r"[^A-Z0-9]", "_", f"{self.namespace}_{provider}_{field}".upper())

    def _namespaces(self) -> tuple[str, ...]:
        return (self.namespace, *self.shared_namespaces)

    @property
    def _keyring(self):
        return _keyring()

    @property
    def unavailable_reason(self) -> str | None:
        """Why the keychain could not be read, or None: `doctor` and `auth status` report it."""
        return self._keychain_problem

    # --- the stored set ---------------------------------------------------------

    def backend(self) -> str | None:
        """Name of the active keyring backend, or None when only the environment can supply secrets."""
        keyring = self._keyring
        if keyring is None:
            return None
        backend = keyring.get_keyring()
        return f"{type(backend).__module__}.{type(backend).__name__}"

    def stored(self, provider: str, namespace: str | None = None) -> dict[str, str]:
        """The fields stored in the keychain for one provider in one namespace (empty when absent)."""
        keyring = self._keyring
        if keyring is None:
            return {}
        try:
            raw = keyring.get_password(self.service_name_for(provider, namespace or self.namespace), provider)
        except keyring.errors.KeyringError as exc:
            if self._keychain_problem is None:
                self._keychain_problem = str(exc)
                log.debug("OS credential store unavailable (%s); using environment variables only", exc)
            return {}
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("stored credential for '%s' is not valid JSON; ignoring it", provider)
            return {}

    def service_name_for(self, provider: str, namespace: str) -> str:
        return f"{namespace}:{provider}"

    def stored_names(self) -> list[str]:
        """Names of the providers stored in this namespace's keychain (environment-only ones are not listed)."""
        keyring = self._keyring
        if keyring is None:
            return []
        try:
            raw = keyring.get_password(self.namespace, _INDEX_USER)
        except keyring.errors.KeyringError:
            return []
        if not raw:
            return []
        try:
            names = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("the stored-credentials index of '%s' is not valid JSON; ignoring it", self.namespace)
            return []
        return sorted(names)

    def _update_index(self, provider: str, *, present: bool) -> None:
        keyring = self._keyring
        if keyring is None:
            return
        names = set(self.stored_names())
        names = names | {provider} if present else names - {provider}
        try:
            keyring.set_password(self.namespace, _INDEX_USER, json.dumps(sorted(names)))
        except keyring.errors.KeyringError as exc:  # the credential itself is stored; only listing suffers
            log.warning("could not update the stored-credentials index (%s)", exc)

    # --- reading ----------------------------------------------------------------

    def read_from_env(self, provider: str, fields: list[str]) -> dict[str, str]:
        """Whichever of `fields` are set in the environment for this provider."""
        result: dict[str, str] = {}
        for field in fields:
            value = os.environ.get(self.env_var_name(provider, field))
            if value is not None:
                result[field] = value
        return result

    def get(
        self,
        provider: str,
        *,
        env_fields: list[str] | None = None,
        legacy_env: Mapping[str, str] | None = None,
        legacy_env_first: bool = False,
    ) -> dict[str, str] | None:
        """The whole credential of a provider: stored fields merged with the environment (env wins per field)."""
        stored = self.stored(provider)
        fields = env_fields or list(stored) or [_DEFAULT_FIELD]
        located = self.locate(provider, fields, legacy_env=legacy_env, legacy_env_first=legacy_env_first)
        merged = {**stored, **{field: value for field, (value, _, _) in located.items()}}
        return merged or None

    def locate(
        self,
        provider: str,
        fields: list[str],
        *,
        legacy_env: Mapping[str, str] | None = None,
        legacy_env_first: bool = False,
    ) -> dict[str, tuple[str, str, str]]:
        """Per present field: (value, source "env"|"keychain", where: the variable name or the service).

        Order per field, first hit wins: own env var, each shared namespace's env var, the keychain (own namespace
        first, then shared), then the legacy variable — or right after the env vars with `legacy_env_first`.
        For `auth status`, which reports the source and never the value.
        """
        legacy = dict(legacy_env or {})
        namespaces = self._namespaces()
        stored = {
            ns: (self.stored(provider) if ns == self.namespace else self.stored(provider, ns)) for ns in namespaces
        }
        located: dict[str, tuple[str, str, str]] = {}
        for field in fields:
            env_names = [re.sub(r"[^A-Z0-9]", "_", f"{ns}_{provider}_{field}".upper()) for ns in namespaces]
            legacy_names = [legacy[field]] if field in legacy else []
            env_first = env_names + legacy_names if legacy_env_first else env_names
            for name in env_first:
                if (value := os.environ.get(name)) is not None:
                    located[field] = (value, "env", name)
                    break
            else:
                for ns in namespaces:
                    if field in stored[ns]:
                        located[field] = (stored[ns][field], "keychain", self.service_name_for(provider, ns))
                        break
                else:
                    for name in [] if legacy_env_first else legacy_names:
                        if (value := os.environ.get(name)) is not None:
                            located[field] = (value, "env", name)
        self._warn_if_missing(provider, [field for field in fields if field not in located])
        return located

    def _warn_if_missing(self, provider: str, missing: list[str]) -> None:
        if missing and self._keychain_problem is not None and not self._warned_missing:
            self._warned_missing = True
            log.warning(
                "OS credential store unavailable (%s) and %s not set in the environment for '%s'",
                self._keychain_problem,
                ", ".join(missing),
                provider,
            )

    def get_secret(self, provider: str, field: str = _DEFAULT_FIELD) -> str | None:
        """The common single-secret case: one field, `api_key` by default."""
        credential = self.get(provider, env_fields=[field])
        return credential.get(field) if credential else None

    def read_secret_from_env(self, provider: str, field: str = _DEFAULT_FIELD) -> str | None:
        return self.read_from_env(provider, [field]).get(field)

    # --- writing ----------------------------------------------------------------

    def store(self, provider: str, fields: Mapping[str, str]) -> None:
        """Write one provider's fields into the keychain and add it to the namespace index."""
        keyring = self._keyring
        if keyring is None:
            raise StoreUnavailable(f"no OS credential store: install the 'keyring' extra to store '{provider}'")
        try:
            keyring.set_password(self.service_name(provider), provider, json.dumps(dict(fields)))
        except keyring.errors.KeyringError as exc:
            raise StoreUnavailable(f"could not store '{provider}': {exc}") from exc
        self._update_index(provider, present=True)

    def store_secret(self, provider: str, secret: str, field: str = _DEFAULT_FIELD) -> None:
        self.store(provider, {field: secret})

    def delete(self, provider: str) -> None:
        """Remove a provider's credential; deleting an absent one is not an error."""
        keyring = self._keyring
        if keyring is None:
            raise StoreUnavailable(f"no OS credential store: nothing to delete for '{provider}'")
        try:
            keyring.delete_password(self.service_name(provider), provider)
        except keyring.errors.PasswordDeleteError:
            pass
        except keyring.errors.KeyringError as exc:
            raise StoreUnavailable(f"could not delete '{provider}': {exc}") from exc
        self._update_index(provider, present=False)

    # --- helpers for the callers -------------------------------------------------

    def require(self, provider: str, field: str = _DEFAULT_FIELD) -> str:
        """A secret that must exist: raises `CredentialsUnavailable` naming the provider and the place to set it."""
        value = self.get_secret(provider, field)
        if value is None:
            raise CredentialsUnavailable(
                f"no credential for '{provider}': set {self.env_var_name(provider, field)} "
                f"or store it with `auth login {provider}`"
            )
        return value
