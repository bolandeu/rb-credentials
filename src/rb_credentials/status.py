"""The `<cli> auth status [--check] --json` envelope (tools `docs/standard-release.md` §8), one implementation.

A package finds its credential and probes its service; this module owns the shape they all report in, so two tools
cannot disagree on it: codes 0/3, the same nine keys per `credentials[]` record, the same vocabulary of statuses.
Credential values never arrive here — `scrub` is handed them only to erase them from a message.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

__all__ = [
    "EXIT_OK",
    "EXIT_PROBLEM",
    "Health",
    "HealthStatus",
    "Quota",
    "entry",
    "exit_code",
    "is_problem",
    "iso",
    "problems",
    "report",
    "scrub",
]

EXIT_OK = 0
EXIT_PROBLEM = 3
HEALTHY = frozenset({"ok", "unchecked"})
# A problem even for an optional provider: a credential is there but wrong.
ALWAYS_PROBLEMS = frozenset({"invalid", "expired"})

HealthStatus = Literal["ok", "invalid", "expired", "quota_exhausted", "unreachable"]


@dataclass(frozen=True)
class Quota:
    remaining: int | None = None
    limit: int | None = None
    unit: str = "requests"


@dataclass(frozen=True)
class Health:
    """Result of a provider's live check. Never put a credential value in `message`."""

    status: HealthStatus = "ok"
    expires_at: datetime | None = None
    quota: Quota | None = None
    message: str | None = None


def scrub(message: str | None, secrets: Sequence[str | None]) -> str | None:
    """`message` with every secret replaced by `***`."""
    if message is None:
        return None
    for secret in secrets:
        if secret:
            message = message.replace(secret, "***")
    return message


def iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if moment else None


def entry(
    name: str,
    *,
    required: bool = True,
    fields: Sequence[str] = (),
    source: str = "missing",
    source_ref: str | None = None,
    status: str = "missing",
    expires_at: datetime | None = None,
    quota: Quota | None = None,
    message: str | None = None,
) -> dict:
    """One `credentials[]` record — all nine keys, in one order for every tool.

    `name` is the whole record name, `<provider>` or `<provider>:<target>`; a package with per-target credentials
    enumerates its own targets and calls this once per target. `fields` are the declared credential fields, in the
    declared order, never "what happened to be found": that would differ between two machines.
    """
    return {
        "provider": name,
        "required": required,
        "fields": list(fields),
        "source": source,
        "source_ref": source_ref,
        "status": status,
        "expires_at": iso(expires_at),
        "quota": vars(quota) if quota else None,
        "message": message,
    }


def report(tool: str, version: str, entries: list[dict]) -> dict:
    """The envelope: which tool, which version, when, and the records. The command adds `ok` and the exit-3 error."""
    return {
        "tool": tool,
        "version": version,
        "checked_at": iso(datetime.now(UTC)),
        "credentials": entries,
    }


def is_problem(record: dict) -> bool:
    """Whether a record fails `auth status`: invalid/expired always, anything not ok/unchecked if required."""
    if record["status"] in ALWAYS_PROBLEMS:
        return True
    return record["required"] and record["status"] not in HEALTHY


def problems(report: dict) -> dict[str, str]:
    """Provider → status for every record that fails; the payload of the command's exit-3 error."""
    return {record["provider"]: record["status"] for record in report["credentials"] if is_problem(record)}


def exit_code(report: dict) -> int:
    """`EXIT_PROBLEM` when any record fails, `EXIT_OK` otherwise."""
    return EXIT_PROBLEM if problems(report) else EXIT_OK
