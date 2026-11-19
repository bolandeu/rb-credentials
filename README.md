# rb-credentials

Resolve named credentials without storing, logging or printing secrets.

The package knows credential names; the environment knows addresses. You map a
name such as `github` to an address such as an environment variable or a
keychain entry, and the package resolves it to a `Credential` whose token is a
`SecretStr`. No address is hard-coded, and nothing is written to disk.

## Install

```sh
uv add rb-credentials
uv add "rb-credentials[keyring]"
```

## Use

```python
from rb_credentials import providers_for, resolve_credential

providers = providers_for({"github": "env:GITHUB_TOKEN"})
credential = resolve_credential(*providers, name="github")
token = credential.token.get_secret_value()
```

Addresses:

- `env:NAME` reads the environment variable `NAME`.
- `keyring:service/account` reads the OS keychain through the optional
  `keyring` extra. Without the extra the lookup returns nothing; there is no
  plaintext fallback.

Provide your own source with `CallableCredentials`, or implement
`CredentialProvider`:

```python
from rb_credentials import CallableCredentials, providers_for, resolve_credential

providers = (*providers_for({}), CallableCredentials(lambda name: vault.read(name)))
credential = resolve_credential(*providers, name="github")
```

A missing credential raises `CredentialsUnavailable` with the credential name
and never with a value. Pass a `Credential` or a ready client into your
operations; do not read the environment inside them.

## Rules

- Secrets stay in `SecretStr`, never in `str`, arguments, results or logs.
- Expiry is explicit: `credential.is_expired()` and `expires_at`.
- No storage, no caching, no plaintext file.

## Develop

```sh
uv sync
uv run poe check
uv build
uvx --from 'twine>=6,<7' twine check dist/*
```

The library version is independent of any project that depends on it.
