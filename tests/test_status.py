"""The `auth status` envelope: the shape every tool of the family reports in (ADR 0017)."""

from __future__ import annotations

from datetime import UTC, datetime

from rb_credentials import status

ENTRY_KEYS = ["provider", "required", "fields", "source", "source_ref", "status", "expires_at", "quota", "message"]


def test_entry_has_the_nine_keys_in_one_order() -> None:
    record = status.entry("demo")
    assert list(record) == ENTRY_KEYS
    assert (record["provider"], record["required"], record["status"], record["source"]) == (
        "demo",
        True,
        "missing",
        "missing",
    )


def test_fields_are_the_declared_ones_in_declared_order() -> None:
    record = status.entry("yandex", fields=("token", "client_id"), required=False)
    assert (record["fields"], record["required"]) == (["token", "client_id"], False)


def test_expiry_is_utc_z_without_microseconds_and_quota_is_a_plain_dict() -> None:
    moment = datetime(2026, 11, 19, 12, 0, 0, 123456, tzinfo=UTC)
    record = status.entry("demo", expires_at=moment, quota=status.Quota(remaining=5, limit=10))
    assert record["expires_at"] == "2026-11-19T12:00:00Z"
    assert record["quota"] == {"remaining": 5, "limit": 10, "unit": "requests"}


def test_report_carries_tool_version_and_a_utc_timestamp() -> None:
    payload = status.report("dataio", "1.2.3", [status.entry("demo")])
    assert list(payload) == ["tool", "version", "checked_at", "credentials"]
    assert payload["checked_at"].endswith("Z") and "." not in payload["checked_at"]


def test_scrub_erases_every_secret_and_passes_none_through() -> None:
    assert status.scrub("token abc123 refused for abc123", ["abc123", None, ""]) == "token *** refused for ***"
    assert status.scrub(None, ["abc123"]) is None


def test_problems_are_invalid_always_and_anything_but_ok_unchecked_when_required() -> None:
    payload = status.report(
        "tool",
        "1.0",
        [
            status.entry("bad", required=False, status="invalid"),
            status.entry("gone", required=True, status="missing"),
            status.entry("fine", required=True, status="unchecked"),
            status.entry("optional_gone", required=False, status="missing"),
        ],
    )
    assert status.problems(payload) == {"bad": "invalid", "gone": "missing"}
    assert status.exit_code(payload) == status.EXIT_PROBLEM == 3


def test_no_problem_is_exit_0() -> None:
    payload = status.report("tool", "1.0", [status.entry("fine", status="ok")])
    assert (status.problems(payload), status.exit_code(payload)) == ({}, 0)


def test_health_defaults_to_ok_and_quota_defaults_are_requests() -> None:
    assert status.Health() == status.Health(status="ok", expires_at=None, quota=None, message=None)
    assert status.Quota() == status.Quota(remaining=None, limit=None, unit="requests")
