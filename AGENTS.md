# AGENTS.md

Pointers for agents working on this package.

- What the package is: `CONTEXT.md`. Take terms only from there.
- Code rules for review: the Standard, sections «Library API» and «Credentials».
- The gate before a commit: `gate check`, run on this machine. It is the only gate: no workflow runs it.
- Three names: distribution `rb-credentials`, import `rb_credentials`, no command (a library).
- The public API is the contract: names in `__all__`, full annotations, no printing, no argument parsing.
  Breaking it is a deliberate release with a changelog entry, never a side effect.
- Addresses are deployment: this package knows credential names, the caller supplies an address
  (`env:NAME`, `keyring:service`); nothing here hard-codes a host, a variable name or a secret.
