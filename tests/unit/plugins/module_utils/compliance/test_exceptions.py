from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)

if TYPE_CHECKING:
    from collections.abc import Callable

PREFIX = "xccdf_org.ssgproject.content_rule_"
RULE = PREFIX + "sshd_disable_root_login"
OTHER_RULE = PREFIX + "audit_rules_login_events"
BENCHMARK = "xccdf_org.ssgproject.content_benchmark_UBUNTU2404"
PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
STIG = "xccdf_org.ssgproject.content_profile_stig"
VERSION = "0.1.82"
NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
STARTED = "2026-10-25T10:00:00Z"
MISSING = object()


def quote(value: object) -> str:
    if value is None:
        return "null"
    return "'" + str(value).replace("'", "''") + "'"


def dump(value: object, indent: int = 0) -> str:
    pad = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in cast("dict[str, object]", value).items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:\n{dump(cast('object', item), indent + 2)}")
            elif isinstance(item, list):
                lines.append(f"{pad}{key}: []\n")
            elif isinstance(item, dict):
                lines.append(f"{pad}{key}:\n")
            else:
                lines.append(f"{pad}{key}: {quote(item)}\n")
        return "".join(lines)
    for item in cast("list[object]", value):
        if isinstance(item, dict):
            body = dump(cast("object", item), indent + 2)
            lines.append(pad + "- " + body[indent + 2 :])
        else:
            lines.append(f"{pad}- {quote(item)}\n")
    return "".join(lines)


def entry(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": "EXC-001",
        "rule": RULE,
        "framework": "cis",
        "scope": {"hosts": ["web01"]},
        "justification": "The legacy deployment tool logs in as root until it is replaced.",
        "owner": "platform-team",
        "approval": {"approver": "security-lead", "date": "2026-10-02"},
        "created": "2026-10-01",
        "expires": "2027-03-31",
        "risk": "medium",
    }
    for key, value in overrides.items():
        if value is MISSING:
            del values[key]
        else:
            values[key] = value
    return values


def document(*entries: dict[str, object], version: object = "1.0") -> str:
    return "---\n" + dump({"schema_version": version, "exceptions": list(entries)})


def parse(*entries: dict[str, object], now: datetime = NOW) -> exceptions.ExceptionSet:
    return exceptions.parse_exceptions(document(*entries), now)


def invalid(text: str, message: str, now: datetime = NOW) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        exceptions.parse_exceptions(text, now)


def invalid_entry(message: str, **overrides: object) -> None:
    invalid(document(entry(**overrides)), message)


def finding(rule_id: str, outcome: model.Outcome) -> model.Finding:
    disabled = "linux_compliance_rule_x_enabled" if outcome is model.Outcome.DISABLED else None
    return model.Finding(
        rule_id=rule_id,
        outcome=outcome,
        evaluated_outcome=outcome,
        severity=model.Severity.MEDIUM,
        message=None,
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=disabled,
        flags=(),
    )


def scan_run(
    outcomes: dict[str, model.Outcome] | None = None,
    *,
    started: str = STARTED,
    status: model.ScanStatus = model.ScanStatus.COMPLETED,
    version: str = VERSION,
    profile: str = PROFILE,
) -> model.ScanRun:
    if outcomes is None:
        outcomes = {RULE: model.Outcome.FAIL, OTHER_RULE: model.Outcome.PASS}
    return model.ScanRun(
        run_id="run-1",
        started_at=started,
        finished_at=started,
        host=model.HostIdentity("reported-name", "ubuntu", "24.04", "x86_64", None),
        scanner=model.ScannerInfo("openscap", "1.3.10"),
        content=model.Provenance("ssg-ubuntu2404-ds.xml", version, "a" * 64),
        benchmark_id=BENCHMARK,
        profile_id=profile,
        status=status,
        error_message=None if status is model.ScanStatus.COMPLETED else "scanner failed",
        findings=tuple(finding(rule_id, outcome) for rule_id, outcome in outcomes.items()),
    )


def target(
    host: str = "web01", groups: tuple[str, ...] = ("linux_compliance",)
) -> exceptions.Target:
    return exceptions.Target(host, groups)


def instant(text: str) -> datetime:
    return datetime.strptime(text, model.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def evaluate(
    *entries: dict[str, object],
    run: model.ScanRun | None = None,
    where: exceptions.Target | None = None,
    now: datetime = NOW,
    controller: datetime | None = None,
    max_scan_lag: timedelta = exceptions.DEFAULT_MAX_SCAN_LAG,
) -> exceptions.Evaluation:
    selected = scan_run() if run is None else run
    return exceptions.evaluate_run(
        selected,
        parse(*entries, now=now),
        target() if where is None else where,
        instant(selected.started_at) if controller is None else controller,
        max_scan_lag=max_scan_lag,
    )


def by_rule(evaluation: exceptions.Evaluation) -> dict[str, model.Finding]:
    return {item.rule_id: item for item in evaluation.run.findings}


def statuses(evaluation: exceptions.Evaluation) -> dict[str, str]:
    return {item.record.exception_id: item.status.value for item in evaluation.results}


def test_parses_a_valid_file() -> None:
    text = document(entry(id="EXC-B"), entry(id="EXC-A", rule=OTHER_RULE))
    parsed = exceptions.parse_exceptions(text, NOW)
    assert parsed.source_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert [record.exception_id for record in parsed.records] == ["EXC-A", "EXC-B"]
    record = parsed.records[1]
    assert record.rule_id == RULE
    assert record.framework is model.FrameworkId.CIS
    assert record.scope == exceptions.Scope(("web01",), (), None)
    assert record.owner == "platform-team"
    assert record.approver == "security-lead"
    assert record.approved_on == date(2026, 10, 2)
    assert record.created == date(2026, 10, 1)
    assert record.expires == date(2027, 3, 31)
    assert record.expires_at == "2027-03-31T00:00:00Z"
    assert record.risk is exceptions.Risk.MEDIUM


def test_parses_plain_yaml_with_comments_and_block_justification() -> None:
    text = (
        "---\n"
        "# Accepted risks for the web tier\n"
        "schema_version: '1.0'\n"
        "exceptions:\n"
        "  - id: EXC-2026-001\n"
        f"    rule: {RULE}\n"
        "    framework: stig\n"
        "    scope:\n"
        "      groups: [legacy_web, dmz]\n"
        "      benchmark:\n"
        f"        id: {BENCHMARK}\n"
        f"        version: {VERSION}\n"
        f"      profiles: [{STIG}]\n"
        "    justification: >-\n"
        "      The vendor appliance needs it.\n"
        "      Migration is tracked in OPS-12.\n"
        "    owner: Web@Example.com\n"
        "    approval:\n"
        "      approver: CISO\n"
        "      date: 2026-10-01\n"
        "    created: 2026-10-01\n"
        "    expires: 2026-12-31\n"
        "    risk: high\n"
    )
    record = exceptions.parse_exceptions(text, NOW).records[0]
    assert record.justification == "The vendor appliance needs it. Migration is tracked in OPS-12."
    assert record.scope.groups == ("dmz", "legacy_web")
    assert record.scope.benchmark == exceptions.BenchmarkScope(BENCHMARK, VERSION)
    assert record.scope.profiles == (STIG,)
    assert (record.owner, record.approver) == ("web@example.com", "ciso")
    assert record.framework is model.FrameworkId.STIG
    assert record.risk is exceptions.Risk.HIGH


def test_an_empty_list_of_exceptions_is_valid() -> None:
    assert exceptions.parse_exceptions(document(), NOW).records == ()


def test_justification_whitespace_is_trimmed() -> None:
    record = parse(entry(justification="  needed for now  ")).records[0]
    assert record.justification == "needed for now"
    text = document(entry()).replace(
        "    justification: 'The legacy deployment tool logs in as root until it is replaced.'\n",
        "    justification: |\n      Line one.\n        Indented line two.\n\n",
    )
    record = exceptions.parse_exceptions(text, NOW).records[0]
    assert record.justification == "Line one.\n  Indented line two."


def test_justification_length_counts_surrounding_whitespace_like_the_schema() -> None:
    exact = "x" * exceptions.MAX_JUSTIFICATION_LENGTH
    assert parse(entry(justification=exact)).records[0].justification == exact
    invalid_entry("justification exceeds 4096 characters", justification=" " + exact)


@pytest.mark.parametrize("key", exceptions.ENTRY_KEYS)
def test_every_field_is_required(key: str) -> None:
    invalid_entry(f"is missing keys: {key}", **{key: MISSING})


@pytest.mark.parametrize("key", exceptions.ENTRY_KEYS)
def test_no_field_may_be_null(key: str) -> None:
    invalid_entry(rf"exceptions\[0\]\.{key} must not be null or empty", **{key: None})


@pytest.mark.parametrize(
    "key", ["id", "rule", "framework", "justification", "owner", "created", "expires", "risk"]
)
def test_no_text_field_may_be_empty(key: str) -> None:
    invalid_entry(rf"exceptions\[0\]\.{key} must not be empty", **{key: ""})


@pytest.mark.parametrize("key", exceptions.APPROVAL_KEYS)
def test_approval_needs_approver_and_date(key: str) -> None:
    approval: dict[str, object] = {"approver": "security-lead", "date": "2026-10-02"}
    del approval[key]
    invalid_entry(f"approval is missing keys: {key}", approval=approval)
    invalid_entry(rf"approval\.{key} must not be null", approval={**approval, key: None})
    invalid_entry(rf"approval\.{key} must not be empty", approval={**approval, key: ""})


def test_empty_and_wrongly_typed_structures_are_rejected() -> None:
    invalid_entry("approval must be a mapping", approval="security-lead")
    invalid_entry(r"approval must not be null or empty", approval={})
    invalid_entry(r"scope must not be null or empty", scope={})
    invalid_entry("scope must be a mapping", scope=["web01"])
    invalid_entry(r"scope\.hosts must not be empty", scope={"hosts": []})
    invalid_entry(r"scope\.hosts must be a sequence", scope={"hosts": "web01"})
    invalid_entry(r"scope\.groups must not be null", scope={"groups": None})
    invalid_entry(r"scope\.hosts\[0\] must not be empty", scope={"hosts": [""]})
    invalid_entry(r"scope\.hosts\[0\] must be a string", scope={"hosts": [None]})
    invalid_entry(r"justification must be a string", justification=["x"])
    invalid_entry(r"owner must be a string", owner={"name": "x"})


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({**entry(), "comment": "x"}, r"exceptions\[0\] has unknown keys: 'comment'"),
        (entry(scope={"hosts": ["web01"], "regions": ["eu"]}), "scope has unknown keys"),
        (entry(approval={"approver": "a", "date": "2026-10-02", "role": "x"}), "approval has"),
        (
            entry(
                scope={
                    "benchmark": {"id": BENCHMARK, "version": VERSION, "profile": "x"},
                    "profiles": [PROFILE],
                }
            ),
            "benchmark has unknown keys: 'profile'",
        ),
    ],
)
def test_unknown_keys_are_rejected(value: dict[str, object], message: str) -> None:
    invalid(document(value), message)


def test_documents_loaded_elsewhere_get_the_same_validation() -> None:
    loaded: dict[str, object] = {"schema_version": "1.0", "exceptions": [entry()]}
    assert exceptions.parse_document(loaded, NOW)[0].exception_id == "EXC-001"
    for scope, message in (
        ({}, "scope must name hosts, groups, profiles or a benchmark"),
        ({"hosts": ["web01"], 1: "x"}, "scope has unknown keys: '1'"),
    ):
        broken: dict[str, object] = {"schema_version": "1.0", "exceptions": [entry(scope=scope)]}
        with pytest.raises(exceptions.ExceptionsError, match=message):
            exceptions.parse_document(broken, NOW)
    with pytest.raises(exceptions.ExceptionsError, match="timezone-aware"):
        exceptions.parse_document(loaded, cast("datetime", None))


def test_document_structure_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    invalid("---\n- a\n", "document must be a mapping")
    invalid("---\nexceptions: []\n", "document is missing keys: schema_version")
    invalid("---\nschema_version: '1.0'\n", "document is missing keys: exceptions")
    invalid("---\nschema_version: '1.0'\nexceptions: x\n", "exceptions must be a sequence")
    invalid("---\nschema_version: '1.0'\nexceptions:\n", "exceptions must not be null")
    invalid("---\nschema_version: '1.0'\nexceptions: []\nextra: x\n", "unknown keys: 'extra'")
    invalid(document(version="2.0"), "unsupported schema_version '2.0'")
    invalid("---\nschema_version: 1.0\nexceptions: []\n", "line 2: the plain value '1.0'")
    monkeypatch.setattr(exceptions, "MAX_EXCEPTIONS", 1)
    invalid(document(entry(id="A"), entry(id="B")), "more than 1 entries")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"id": "-leading-dash"}, r"exceptions\[0\]\.id has an invalid format"),
        ({"id": "EXC 1"}, r"\.id has an invalid format"),
        ({"id": "E" * 65}, r"\.id exceeds 64 characters"),
        ({"rule": "sshd_disable_root_login"}, r"\.rule has an invalid format"),
        ({"rule": BENCHMARK}, r"\.rule has an invalid format"),
        ({"framework": "iso27001"}, r"\.framework must be one of: cis, stig, nist_800_53"),
        ({"risk": "none"}, r"\.risk must be one of: low, medium, high, critical"),
        ({"risk": "MEDIUM"}, r"\.risk must be one of"),
        ({"owner": "team\u200b"}, r"\.owner contains control or formatting characters"),
        ({"owner": "x" * 255}, r"\.owner exceeds 254 characters"),
        ({"justification": "x" * 4097}, r"\.justification exceeds 4096 characters"),
        ({"justification": "bad \u202e text"}, r"line [0-9]+: .*bidi characters"),
        ({"justification": "bad \x1b text"}, r"line [0-9]+: control"),
        ({"created": "2026/10/01"}, r"\.created has an invalid format"),
        ({"created": "2026-02-30"}, r"\.created is not a valid calendar date"),
        ({"expires": "2027-13-01"}, r"\.expires is not a valid calendar date"),
        ({"scope": {"hosts": ["bad host"]}}, r"scope\.hosts\[0\] has an invalid format"),
        ({"scope": {"hosts": ["web01", "web01"]}}, r"scope\.hosts contains duplicates"),
        ({"scope": {"groups": ["bad group"]}}, r"scope\.groups\[0\] has an invalid format"),
        ({"scope": {"groups": ["all"]}}, "must not name the implicit group 'all'"),
        ({"scope": {"groups": ["web", "ungrouped"]}}, "implicit group 'ungrouped'"),
        (
            {"scope": {"benchmark": {"id": BENCHMARK}, "profiles": [PROFILE]}},
            "benchmark is missing keys: version",
        ),
        (
            {"scope": {"benchmark": {"id": RULE, "version": "1"}, "profiles": [PROFILE]}},
            r"benchmark\.id has an invalid",
        ),
        (
            {"scope": {"benchmark": {"id": BENCHMARK, "version": ""}, "profiles": [PROFILE]}},
            r"version must not be empty",
        ),
        (
            {"scope": {"benchmark": "x", "profiles": [PROFILE]}},
            r"scope\.benchmark must be a mapping",
        ),
        (
            {"scope": {"benchmark": {"id": BENCHMARK, "version": VERSION}}},
            r"scope\.profiles is required when exceptions\[0\]\.scope\.benchmark is set",
        ),
        (
            {"scope": {"hosts": ["web01"], "benchmark": {"id": BENCHMARK, "version": VERSION}}},
            r"scope\.profiles is required",
        ),
        ({"scope": {"profiles": [RULE]}}, r"scope\.profiles\[0\] has an invalid format"),
        ({"scope": {"profiles": [PROFILE, PROFILE]}}, r"scope\.profiles contains duplicates"),
        ({"scope": {"profiles": []}}, r"scope\.profiles must not be empty"),
        ({"scope": {"profiles": PROFILE}}, r"scope\.profiles must be a sequence"),
    ],
)
def test_field_values_are_validated(overrides: dict[str, object], message: str) -> None:
    invalid_entry(message, **overrides)


def test_scope_lists_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exceptions, "MAX_SCOPE_ITEMS", 2)
    invalid_entry(r"scope\.hosts has more than 2 items", scope={"hosts": ["a", "b", "c"]})


@pytest.mark.parametrize(
    ("created", "accepted"),
    [("2026-10-25", True), ("2026-10-24", True), ("2026-10-26", False)],
)
def test_created_must_not_be_in_the_future(created: str, accepted: bool) -> None:
    values = entry(
        created=created,
        approval={"approver": "security-lead", "date": created},
        expires="2027-01-31",
    )
    if accepted:
        assert parse(values).records[0].created == date.fromisoformat(created)
    else:
        invalid(document(values), r"exceptions\[0\]\.created is in the future")


@pytest.mark.parametrize(
    ("expires", "message"),
    [
        ("2026-10-01", r"\.expires must be after exceptions\[0\]\.created"),
        ("2026-09-30", r"\.expires must be after"),
        ("2027-10-02", "is valid for more than 365 days"),
    ],
)
def test_expiry_must_follow_creation_within_the_cap(expires: str, message: str) -> None:
    invalid_entry(message, expires=expires)


def test_validity_of_exactly_the_cap_is_accepted() -> None:
    created = date(2026, 10, 1)
    expires = created + timedelta(days=exceptions.MAX_VALIDITY_DAYS)
    assert parse(entry(expires=expires.isoformat())).records[0].expires == expires


@pytest.mark.parametrize(
    ("approval_date", "message"),
    [
        ("2026-09-30", r"approval\.date is before exceptions\[0\]\.created"),
        ("2026-10-26", r"approval\.date is in the future"),
    ],
)
def test_approval_date_window(approval_date: str, message: str) -> None:
    invalid_entry(message, approval={"approver": "security-lead", "date": approval_date})


def test_approval_must_precede_expiry() -> None:
    invalid_entry(
        r"approval\.date must be before exceptions\[0\]\.expires",
        expires="2026-10-02",
        approval={"approver": "security-lead", "date": "2026-10-02"},
    )


@pytest.mark.parametrize(
    ("owner", "approver"),
    [
        ("platform-team", "platform-team"),
        ("platform-team", "Platform-Team"),
        ("alice@example.com", "Alice@Example.COM"),
        ("alice@example.com", "\uff41lice@example.com"),
        ("alice@example.com", "alice"),
        ("alice", "ALICE@corp.example"),
        ("alice@example.com", "\uff21\uff2c\uff29\uff23\uff25@\uff45xample.com"),
        ("alice+audit@example.org", "alice@example.org"),
        ("alice+audit@example.org", "alice"),
        ("alice+one@example.org", "alice+two@example.org"),
        ("alice@a.example", "alice@b.example"),
        ("alice+x@a.example", "ALICE@b.example"),
    ],
)
def test_owner_cannot_approve_their_own_exception(owner: str, approver: str) -> None:
    invalid_entry(
        "approver must not be the owner",
        owner=owner,
        approval={"approver": approver, "date": "2026-10-02"},
    )


@pytest.mark.parametrize(
    ("owner", "approver"),
    [
        ("alice", "bob"),
        ("alice.smith@example.org", "alicesmith@example.org"),
        ("alice-ops@example.org", "alice@example.org"),
        ("alice@example.com", "bob"),
        ("alice", "alicia@example.com"),
    ],
)
def test_different_people_may_own_and_approve(owner: str, approver: str) -> None:
    record = parse(entry(owner=owner, approval={"approver": approver, "date": "2026-10-02"}))
    assert (record.records[0].owner, record.records[0].approver) == (owner, approver)


@pytest.mark.parametrize(
    "value",
    [
        "\u0430lice@example.com",
        "alice@example.com.",
        "Web Team",
        "web team@example.com",
        "alice@localhost",
        "-alice",
        "a" * 65,
        "x" * 65 + "@example.com",
        "alice@-example.com",
        "\u00e9lodie",
    ],
)
def test_owner_and_approver_must_be_an_email_or_a_handle(value: str) -> None:
    message = "must be an email address or a handle"
    invalid_entry(rf"\.owner {message}", owner=value)
    invalid_entry(
        rf"approval\.approver {message}", approval={"approver": value, "date": "2026-10-02"}
    )


def test_person_names_are_canonicalised() -> None:
    record = parse(
        entry(owner="\uff30latform-Team", approval={"approver": "Sec.Lead", "date": "2026-10-02"})
    ).records[0]
    assert (record.owner, record.approver) == ("platform-team", "sec.lead")
    assert exceptions.normalize_person("Alice@Example.Com", "x") == "alice@example.com"


def test_a_name_that_grows_beyond_the_limit_when_normalised_is_rejected() -> None:
    value = "\ufb00" * 127 + "@example.com"
    with pytest.raises(exceptions.ExceptionsError, match="email address or a handle"):
        exceptions.normalize_person(value, "owner")


def test_same_person() -> None:
    assert exceptions.same_person("alice", "alice")
    assert exceptions.same_person("alice", "alice@x.example")
    assert exceptions.same_person("alice@x.example", "alice")
    assert exceptions.same_person("alice@x.example", "alice@y.example")
    assert exceptions.same_person("alice+x@example.org", "alice@example.org")
    assert exceptions.same_person("alice+x@example.org", "alice+y@example.org")
    assert not exceptions.same_person("alice", "bob")
    assert not exceptions.same_person("alice.x@example.org", "alice@example.org")
    assert not exceptions.same_person("bob@x.example", "alice")


def test_today_is_the_utc_date_of_now() -> None:
    values = entry(created="2026-10-26", approval={"approver": "ciso", "date": "2026-10-26"})
    behind = datetime(2026, 10, 25, 23, 30, tzinfo=timezone(timedelta(hours=-2)))
    assert parse(values, now=behind).records[0].created == date(2026, 10, 26)
    ahead = datetime(2026, 10, 26, 5, 0, tzinfo=timezone(timedelta(hours=14)))
    invalid(document(values), "created is in the future", now=ahead)


@pytest.mark.parametrize("now", [datetime.fromisoformat("2026-10-25T12:00:00"), "2026-10-25", None])
def test_now_must_be_timezone_aware(now: object) -> None:
    invalid(document(entry()), "timezone-aware datetime", now=cast("datetime", now))


@pytest.mark.parametrize("other", ["EXC-001", "exc-001"])
def test_duplicate_ids_are_rejected(other: str) -> None:
    invalid(
        document(entry(), entry(id=other, rule=OTHER_RULE)),
        f"duplicate exception id '{other}' \\(also 'EXC-001'\\)",
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("schema_version: '1.0'\n", "must start with a line"),
        ("---\nschema_version: '1.0'\nschema_version: '1.0'\nexceptions: []\n", "duplicate key"),
        ("---\nschema_version: '1.0'\nexceptions:\n  - id: &a x\n", "unsupported YAML construct"),
        ("---\nschema_version: '1.0'\nexceptions: [\n", "flow sequence must end"),
        ("---\n\tschema_version: '1.0'\n", "tab characters"),
    ],
)
def test_malformed_files_are_rejected_with_the_line(text: str, message: str) -> None:
    invalid(text, f"exceptions file: line [0-9]+: .*{message}")


def test_duplicate_keys_inside_an_entry_are_rejected() -> None:
    text = document(entry()).replace("    owner:", "    owner: 'x'\n    owner:", 1)
    invalid(text, "line [0-9]+: duplicate key 'owner'")


def test_the_file_must_be_text() -> None:
    invalid(cast("str", b"---\n"), "the exceptions file must be text")


def test_host_scope_waives_a_failure_with_metadata() -> None:
    evaluation = evaluate(entry())
    waived = by_rule(evaluation)[RULE]
    assert waived.outcome is model.Outcome.WAIVED
    assert waived.evaluated_outcome is model.Outcome.FAIL
    assert waived.exception.state is model.ExceptionState.ACTIVE
    assert waived.exception.exception_id == "EXC-001"
    assert waived.exception.expires_at == "2027-03-31T00:00:00Z"
    reason = cast("str", waived.exception.reason)
    for part in (
        "The legacy deployment tool",
        "risk: medium",
        "framework: cis",
        "owner: platform-team",
        "approved by security-lead on 2026-10-02",
        "created 2026-10-01",
        "expires 2027-03-31",
    ):
        assert part in reason
    assert by_rule(evaluation)[OTHER_RULE].outcome is model.Outcome.PASS
    result = evaluation.results[0]
    assert (result.status, result.outcome, result.expired, result.superseded_by) == (
        exceptions.Status.WAIVED,
        model.Outcome.FAIL,
        False,
        None,
    )


@pytest.mark.parametrize(
    ("scope", "where", "status"),
    [
        ({"hosts": ["web01", "web02"]}, target("web02"), "waived"),
        ({"hosts": ["web02"]}, target("web01"), "unmatched"),
        ({"hosts": ["reported-name"]}, target("web01"), "unmatched"),
        ({"groups": ["legacy"]}, target("db01", ("legacy", "dmz")), "waived"),
        ({"groups": ["legacy"]}, target("db01", ("dmz",)), "unmatched"),
        ({"groups": ["legacy"]}, target("db01", ()), "unmatched"),
        (
            {"benchmark": {"id": BENCHMARK, "version": VERSION}, "profiles": [PROFILE]},
            target("any"),
            "waived",
        ),
        (
            {"benchmark": {"id": BENCHMARK, "version": "0.1.81"}, "profiles": [PROFILE]},
            target("any"),
            "unmatched",
        ),
        (
            {
                "benchmark": {"id": BENCHMARK.replace("2404", "2204"), "version": VERSION},
                "profiles": [PROFILE],
            },
            target("any"),
            "unmatched",
        ),
        (
            {"benchmark": {"id": BENCHMARK, "version": VERSION}, "profiles": [STIG]},
            target("any"),
            "unmatched",
        ),
        (
            {"benchmark": {"id": BENCHMARK, "version": VERSION}, "profiles": [STIG, PROFILE]},
            target("any"),
            "waived",
        ),
        ({"profiles": [PROFILE]}, target("any"), "waived"),
        ({"profiles": [STIG]}, target("any"), "unmatched"),
        ({"hosts": ["web01"], "profiles": [STIG]}, target("web01"), "unmatched"),
        ({"hosts": ["web01"], "groups": ["legacy"]}, target("web01", ("legacy",)), "waived"),
        ({"hosts": ["web01"], "groups": ["legacy"]}, target("web01", ("dmz",)), "unmatched"),
        ({"hosts": ["web01"], "groups": ["legacy"]}, target("web02", ("legacy",)), "unmatched"),
        (
            {
                "hosts": ["web01"],
                "benchmark": {"id": BENCHMARK, "version": "9"},
                "profiles": [PROFILE],
            },
            target("web01"),
            "unmatched",
        ),
    ],
)
def test_scope_matching(scope: dict[str, object], where: exceptions.Target, status: str) -> None:
    evaluation = evaluate(entry(scope=scope), where=where)
    assert statuses(evaluation) == {"EXC-001": status}
    expected = model.Outcome.WAIVED if status == "waived" else model.Outcome.FAIL
    assert by_rule(evaluation)[RULE].outcome is expected
    if status == "unmatched":
        assert by_rule(evaluation)[RULE].exception == model.ExceptionStatus.none()
        assert evaluation.results[0].outcome is None


def test_a_cis_waiver_does_not_cover_a_stig_scan_of_the_same_benchmark() -> None:
    cis_only = entry(
        framework="cis",
        scope={"benchmark": {"id": BENCHMARK, "version": VERSION}, "profiles": [PROFILE]},
    )
    stig_run = scan_run(profile=STIG)
    stig = evaluate(cis_only, run=stig_run, where=target("any"))
    assert statuses(stig) == {"EXC-001": "unmatched"}
    assert by_rule(stig)[RULE].outcome is model.Outcome.FAIL
    cis = evaluate(cis_only, run=scan_run(), where=target("any"))
    assert by_rule(cis)[RULE].outcome is model.Outcome.WAIVED


def test_an_exception_for_a_rule_that_was_not_scanned_is_unmatched() -> None:
    run = scan_run({OTHER_RULE: model.Outcome.FAIL})
    evaluation = evaluate(entry(), run=run)
    assert statuses(evaluation) == {"EXC-001": "unmatched"}
    assert by_rule(evaluation)[OTHER_RULE].outcome is model.Outcome.FAIL


@pytest.mark.parametrize(
    "outcome",
    [
        model.Outcome.ERROR,
        model.Outcome.PASS,
        model.Outcome.NOTAPPLICABLE,
        model.Outcome.NOTCHECKED,
        model.Outcome.DISABLED,
    ],
)
def test_only_failures_are_waived(outcome: model.Outcome) -> None:
    run = scan_run({RULE: outcome})
    evaluation = evaluate(entry(), run=run)
    assert by_rule(evaluation)[RULE] == run.findings[0]
    result = evaluation.results[0]
    assert (result.status, result.outcome) == (exceptions.Status.NOT_FAILING, outcome)


def test_an_error_is_never_waived_even_when_the_exception_is_valid() -> None:
    run = scan_run({RULE: model.Outcome.ERROR, OTHER_RULE: model.Outcome.FAIL})
    evaluation = evaluate(entry(), entry(id="EXC-002", rule=OTHER_RULE), run=run)
    assert by_rule(evaluation)[RULE].outcome is model.Outcome.ERROR
    assert by_rule(evaluation)[RULE].exception.state is model.ExceptionState.NONE
    assert by_rule(evaluation)[OTHER_RULE].outcome is model.Outcome.WAIVED
    assert statuses(evaluation) == {"EXC-001": "not_failing", "EXC-002": "waived"}


@pytest.mark.parametrize("status", [model.ScanStatus.FAILED, model.ScanStatus.TIMED_OUT])
def test_a_run_that_did_not_complete_is_never_waived(status: model.ScanStatus) -> None:
    run = scan_run({RULE: model.Outcome.ERROR}, status=status, version="unknown")
    evaluation = evaluate(entry(scope={"hosts": ["web01"]}), run=run)
    assert evaluation.run.status is status
    assert all(item.outcome is model.Outcome.ERROR for item in evaluation.run.findings)
    assert statuses(evaluation) == {"EXC-001": "not_failing"}


@pytest.mark.parametrize(
    ("started", "status"),
    [
        ("2027-03-30T23:59:59Z", "waived"),
        ("2027-03-31T00:00:00Z", "expired"),
        ("2027-03-31T12:00:00Z", "expired"),
        ("2027-04-01T00:00:00Z", "expired"),
    ],
)
def test_expiry_boundary_at_midnight_utc(started: str, status: str) -> None:
    run = scan_run(started=started)
    evaluation = evaluate(entry(), run=run, now=NOW)
    assert statuses(evaluation) == {"EXC-001": status}
    item = by_rule(evaluation)[RULE]
    if status == "expired":
        assert item.outcome is model.Outcome.FAIL
        assert item.exception.state is model.ExceptionState.EXPIRED
        assert item.exception.exception_id == "EXC-001"
        assert evaluation.results[0].expired
    else:
        assert item.outcome is model.Outcome.WAIVED


@pytest.mark.parametrize(("offset", "status"), [(-1, "expired"), (0, "expired"), (1, "waived")])
def test_expires_yesterday_today_and_tomorrow(offset: int, status: str) -> None:
    scan_day = date(2026, 12, 15)
    expires = scan_day + timedelta(days=offset)
    values = entry(expires=expires.isoformat())
    started = f"{scan_day.isoformat()}T09:30:00Z"
    now = datetime(2026, 12, 15, 9, 30, tzinfo=timezone.utc)
    evaluation = evaluate(values, run=scan_run(started=started), now=now)
    assert statuses(evaluation) == {"EXC-001": status}


def test_expiry_is_reported_for_exceptions_that_did_not_suppress_anything() -> None:
    run = scan_run({RULE: model.Outcome.PASS}, started="2027-04-02T00:00:00Z")
    result = evaluate(entry(), run=run).results[0]
    assert (result.status, result.expired) == (exceptions.Status.NOT_FAILING, True)
    unmatched = evaluate(entry(scope={"hosts": ["x"]}), run=run).results[0]
    assert (unmatched.status, unmatched.expired) == (exceptions.Status.UNMATCHED, True)


def test_an_exception_does_not_apply_to_scans_before_its_approval() -> None:
    values = entry(created="2026-10-01", approval={"approver": "ciso", "date": "2026-10-05"})
    for started, status in (
        ("2026-10-04T23:59:59Z", "not_yet_effective"),
        ("2026-10-05T00:00:00Z", "waived"),
    ):
        evaluation = evaluate(values, run=scan_run(started=started))
        assert statuses(evaluation) == {"EXC-001": status}
    early = evaluate(values, run=scan_run(started="2026-10-04T23:59:59Z"))
    assert by_rule(early)[RULE].outcome is model.Outcome.FAIL
    assert by_rule(early)[RULE].exception.state is model.ExceptionState.NONE


@pytest.mark.parametrize(
    "controller",
    [instant("2026-10-05T00:00:00Z"), instant("2026-10-05T12:00:00Z"), NOW],
)
def test_approval_is_judged_at_the_scan_start_not_at_the_controller_time(
    controller: datetime,
) -> None:
    values = entry(created="2026-10-01", approval={"approver": "ciso", "date": "2026-10-05"})
    run = scan_run(started="2026-10-04T23:59:59Z")
    evaluation = evaluate(values, run=run, controller=controller)
    assert evaluation.timing.evaluated_at >= instant("2026-10-05T00:00:00Z")
    assert statuses(evaluation) == {"EXC-001": "not_yet_effective"}
    assert by_rule(evaluation)[RULE].outcome is model.Outcome.FAIL
    assert by_rule(evaluation)[RULE].exception == model.ExceptionStatus.none()


def test_overlapping_exceptions_choose_the_earliest_expiry() -> None:
    evaluation = evaluate(
        entry(id="EXC-LATE", expires="2027-03-31"),
        entry(id="EXC-SOON", expires="2026-12-31"),
        entry(id="EXC-TIE", expires="2026-12-31"),
    )
    assert statuses(evaluation) == {
        "EXC-LATE": "superseded",
        "EXC-SOON": "waived",
        "EXC-TIE": "superseded",
    }
    assert by_rule(evaluation)[RULE].exception.exception_id == "EXC-SOON"
    superseded = {item.record.exception_id: item.superseded_by for item in evaluation.results}
    assert superseded == {"EXC-LATE": "EXC-SOON", "EXC-SOON": None, "EXC-TIE": "EXC-SOON"}


def test_a_valid_exception_wins_over_an_expired_one() -> None:
    run = scan_run(started="2027-01-15T00:00:00Z")
    now = datetime(2027, 1, 15, tzinfo=timezone.utc)
    evaluation = evaluate(
        entry(id="EXC-OLD", expires="2027-01-01"),
        entry(id="EXC-NEW", created="2027-01-10", approval={"approver": "a", "date": "2027-01-10"}),
        run=run,
        now=now,
    )
    assert statuses(evaluation) == {"EXC-NEW": "waived", "EXC-OLD": "superseded"}
    old = next(item for item in evaluation.results if item.record.exception_id == "EXC-OLD")
    assert old.expired


def test_an_expired_exception_wins_over_one_not_yet_in_effect() -> None:
    run = scan_run(started="2027-01-15T00:00:00Z")
    now = datetime(2027, 1, 20, tzinfo=timezone.utc)
    evaluation = evaluate(
        entry(id="EXC-OLD", expires="2027-01-01"),
        entry(id="EXC-NEW", created="2027-01-16", approval={"approver": "a", "date": "2027-01-16"}),
        run=run,
        now=now,
    )
    assert statuses(evaluation) == {"EXC-NEW": "superseded", "EXC-OLD": "expired"}
    assert by_rule(evaluation)[RULE].exception.state is model.ExceptionState.EXPIRED


def test_a_run_that_already_carries_exception_data_is_rejected() -> None:
    evaluation = evaluate(entry())
    with pytest.raises(exceptions.ExceptionsError, match="already carries exception data"):
        exceptions.evaluate_run(evaluation.run, parse(entry()), target(), instant(STARTED))


def test_a_host_clock_ahead_of_the_controller_is_refused() -> None:
    run = scan_run(started="2026-10-25T10:05:01Z")
    with pytest.raises(exceptions.ExceptionsError, match="later than the controller time"):
        evaluate(entry(), run=run, controller=instant("2026-10-25T10:00:00Z"))
    within = scan_run(started="2026-10-25T10:05:00Z")
    evaluation = evaluate(entry(), run=within, controller=instant("2026-10-25T10:00:00Z"))
    assert evaluation.timing.evaluated_at == instant("2026-10-25T10:05:00Z")
    assert evaluation.to_dict()["scan_lag_seconds"] == -300


def test_a_host_clock_behind_the_controller_cannot_keep_a_lapsed_waiver() -> None:
    values = entry(expires="2026-10-01", approval={"approver": "ciso", "date": "2026-09-02"})
    values["created"] = "2026-09-01"
    run = scan_run(started="2026-09-30T23:59:59Z")
    evaluation = evaluate(values, run=run, controller=NOW)
    assert statuses(evaluation) == {"EXC-001": "expired"}
    item = by_rule(evaluation)[RULE]
    assert item.outcome is model.Outcome.FAIL
    assert item.exception == model.ExceptionStatus.none()
    assert evaluation.results[0].expired
    assert evaluation.timing.evaluated_at == NOW.replace(microsecond=0)
    assert evaluation.timing.scan_lag_exceeded


def test_a_scan_exactly_on_the_expiry_boundary() -> None:
    boundary = scan_run(started="2027-03-31T00:00:00Z")
    on_time = evaluate(entry(), run=boundary)
    assert statuses(on_time) == {"EXC-001": "expired"}
    assert by_rule(on_time)[RULE].exception.state is model.ExceptionState.EXPIRED
    just_before = scan_run(started="2027-03-30T23:59:59Z")
    late = evaluate(entry(), run=just_before, controller=instant("2027-03-31T00:00:00Z"))
    assert statuses(late) == {"EXC-001": "expired"}
    assert by_rule(late)[RULE].outcome is model.Outcome.FAIL
    assert by_rule(late)[RULE].exception == model.ExceptionStatus.none()
    in_time = evaluate(entry(), run=just_before, controller=instant("2027-03-30T23:59:59Z"))
    assert by_rule(in_time)[RULE].outcome is model.Outcome.WAIVED


@pytest.mark.parametrize(
    ("lag", "limit", "exceeded"),
    [
        (timedelta(hours=24), timedelta(hours=24), False),
        (timedelta(hours=24, seconds=1), timedelta(hours=24), True),
        (timedelta(hours=2), timedelta(hours=1), True),
        (timedelta(0), timedelta(hours=1), False),
    ],
)
def test_old_scans_are_flagged(lag: timedelta, limit: timedelta, exceeded: bool) -> None:
    controller = instant(STARTED) + lag
    evaluation = evaluate(entry(), controller=controller, max_scan_lag=limit)
    timing = evaluation.to_dict()
    assert timing["scan_lag_exceeded"] is exceeded
    assert timing["scan_lag_seconds"] == int(lag.total_seconds())
    assert timing["max_scan_lag_seconds"] == int(limit.total_seconds())
    assert by_rule(evaluation)[RULE].outcome is model.Outcome.WAIVED


@pytest.mark.parametrize(
    "limit", [timedelta(0), timedelta(seconds=-1), timedelta(days=366), cast("timedelta", 24)]
)
def test_the_scan_lag_limit_is_validated(limit: timedelta) -> None:
    with pytest.raises(exceptions.ExceptionsError, match="maximum scan lag"):
        evaluate(entry(), max_scan_lag=limit)


def test_the_controller_time_must_be_timezone_aware() -> None:
    with pytest.raises(exceptions.ExceptionsError, match="timezone-aware"):
        evaluate(entry(), controller=datetime.fromisoformat("2026-10-25T10:00:00"))


def test_the_evaluation_document() -> None:
    evaluation = evaluate(
        entry(
            scope={
                "hosts": ["web01"],
                "groups": ["legacy"],
                "benchmark": {"id": BENCHMARK, "version": VERSION},
                "profiles": [PROFILE],
            }
        ),
        entry(id="EXC-002", rule=OTHER_RULE, scope={"groups": ["nowhere"]}),
        where=target("web01", ("legacy", "dmz", "legacy")),
    )
    data = evaluation.to_dict()
    assert data["schema_version"] == exceptions.EVALUATION_SCHEMA_VERSION
    assert data["evaluated_at"] == STARTED
    assert data["scan_started_at"] == STARTED
    assert data["controller_time"] == STARTED
    assert data["scan_lag_seconds"] == 0
    assert data["max_scan_lag_seconds"] == 86400
    assert data["scan_lag_exceeded"] is False
    assert data["max_validity_days"] == exceptions.MAX_VALIDITY_DAYS
    assert data["target"] == {"groups": ["dmz", "legacy"], "host": "web01"}
    assert data["summary"] == {
        "waived": 1,
        "expired": 0,
        "not_yet_effective": 0,
        "not_failing": 0,
        "superseded": 0,
        "unmatched": 1,
    }
    listed = cast("list[dict[str, object]]", data["exceptions"])
    assert listed[1]["scope"] == {"groups": ["nowhere"]}
    assert listed[0] == {
        "approval": {"approver": "security-lead", "date": "2026-10-02"},
        "created": "2026-10-01",
        "expired": False,
        "expires": "2027-03-31",
        "expires_at": "2027-03-31T00:00:00Z",
        "framework": "cis",
        "id": "EXC-001",
        "justification": "The legacy deployment tool logs in as root until it is replaced.",
        "outcome": "fail",
        "owner": "platform-team",
        "risk": "medium",
        "rule": RULE,
        "scope": {
            "benchmark": {"id": BENCHMARK, "version": VERSION},
            "groups": ["legacy"],
            "hosts": ["web01"],
            "profiles": [PROFILE],
        },
        "status": "waived",
        "superseded_by": None,
    }
    run = model.loads(json.dumps(data["scan_run"]))
    assert run == evaluation.run
    assert data["source_sha256"] == evaluation.source_sha256


def evaluation_document(**statuses_by_id: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "source_sha256": "f" * 64,
        "exceptions": [{"id": key, "status": value} for key, value in statuses_by_id.items()],
    }


def test_stale_exceptions_are_unmatched_on_every_host() -> None:
    first = evaluate(entry(), entry(id="EXC-002", rule=OTHER_RULE, scope={"hosts": ["web02"]}))
    second = evaluate(
        entry(),
        entry(id="EXC-002", rule=OTHER_RULE, scope={"hosts": ["web02"]}),
        where=target("web03"),
    )
    assert exceptions.stale_exception_ids([first.to_dict(), second.to_dict()]) == ["EXC-002"]
    third = evaluate(
        entry(),
        entry(id="EXC-002", rule=OTHER_RULE, scope={"hosts": ["web02"]}),
        where=target("web02"),
    )
    documents = (first.to_dict(), second.to_dict(), third.to_dict())
    assert exceptions.stale_exception_ids(documents) == []


STALE_INPUT_CASES: list[tuple[object, str]] = cast(
    "list[tuple[object, str]]",
    [
        ("x", "evaluations must be a list"),
        ([{"exceptions": []}], r"evaluations\[0\] has an unsupported schema_version 'None'"),
        ([{"schema_version": "2.0"}], "unsupported schema_version '2.0'"),
        ([{"schema_version": 1.0}], "unsupported schema_version '1.0'"),
        ([{"schema_version": "9" * 40}], "unsupported schema_version '9999999999999999'$"),
        ([], "at least one evaluation is required"),
        (["x"], r"evaluations\[0\] must be a mapping"),
        ([{"schema_version": "1.0", "exceptions": []}], "is not an exceptions evaluation"),
        (
            [{"schema_version": "1.0", "source_sha256": "f", "exceptions": "x"}],
            "is not an exceptions evaluation",
        ),
        (
            [{"schema_version": "1.0", "source_sha256": "f", "exceptions": ["x"]}],
            "must contain mappings",
        ),
        (
            [{"schema_version": "1.0", "source_sha256": "f", "exceptions": [{"id": "A"}]}],
            "need an id and a known status",
        ),
        (
            [
                {
                    "schema_version": "1.0",
                    "source_sha256": "f",
                    "exceptions": [{"id": 1, "status": "waived"}],
                }
            ],
            "need an id",
        ),
        (
            [
                {
                    "schema_version": "1.0",
                    "source_sha256": "f",
                    "exceptions": [{"id": "A", "status": "gone"}],
                }
            ],
            "known status",
        ),
        (
            [
                {
                    "schema_version": "1.0",
                    "source_sha256": "f",
                    "exceptions": [{"id": "A", "status": ["x"]}],
                }
            ],
            "known status",
        ),
        (
            [
                {
                    "schema_version": "1.0",
                    "source_sha256": "f",
                    "exceptions": [{"id": "A", "status": "waived"}] * 2,
                }
            ],
            "lists 'A' twice",
        ),
        (
            [
                evaluation_document(A="unmatched"),
                {**evaluation_document(A="unmatched"), "source_sha256": "e"},
            ],
            "different exceptions files",
        ),
        (
            [evaluation_document(A="unmatched"), evaluation_document(B="unmatched")],
            "different exceptions files",
        ),
    ],
)


@pytest.mark.parametrize(("value", "message"), STALE_INPUT_CASES)
def test_stale_exceptions_rejects_bad_input(value: object, message: str) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        exceptions.stale_exception_ids(value)


def test_stale_exceptions_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exceptions, "MAX_EVALUATIONS", 1)
    documents = [evaluation_document(A="unmatched")] * 2
    with pytest.raises(exceptions.ExceptionsError, match="more than 1 evaluations"):
        exceptions.stale_exception_ids(documents)


def test_load_scan_run_accepts_json_text_and_mappings() -> None:
    run = scan_run()
    assert exceptions.load_scan_run(model.dumps(run)) == run
    assert exceptions.load_scan_run(run.to_dict()) == run


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (42, "the scan run must be a mapping or JSON text"),
        ("{", "invalid scan run: document is not valid JSON"),
        ({"run_id": float("nan")}, "invalid scan run: Out of range float"),
        ({"run_id": {1, 2}}, "invalid scan run: Object of type set"),
        ({"run_id": "x"}, "invalid scan run: scan_run is missing keys"),
    ],
)
def test_load_scan_run_rejects_invalid_input(value: object, message: str) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        exceptions.load_scan_run(value)


def test_make_target_validates_inventory_values(monkeypatch: pytest.MonkeyPatch) -> None:
    built = exceptions.make_target("web01", ["b", "a", "b"])
    assert built == exceptions.Target("web01", ("a", "b"))
    assert exceptions.make_target("web01", ("a",)).groups == ("a",)
    for host, groups, message in (
        ("web01", "a", "groups must be a list"),
        ("", [], "target.host must not be empty"),
        (None, [], "target.host must be a string"),
        ("web01", [1], r"target.groups\[0\] must be a string"),
    ):
        with pytest.raises(exceptions.ExceptionsError, match=message):
            exceptions.make_target(host, groups)
    with pytest.raises(exceptions.ExceptionsError, match=r"target\.groups must be a tuple"):
        exceptions.Target("web01", cast("tuple[str, ...]", ["a"]))
    monkeypatch.setattr(exceptions, "MAX_SCOPE_ITEMS", 1)
    with pytest.raises(exceptions.ExceptionsError, match=r"target\.groups has too many items"):
        exceptions.make_target("web01", [f"g{index}" for index in range(17)])


MID_SCAN_START = "2027-03-30T23:00:00Z"
MID_SCAN_CONTROLLER = datetime(2027, 3, 31, 1, 0, tzinfo=timezone.utc)


def lapsed_mid_scan() -> exceptions.Evaluation:
    return evaluate(
        entry(),
        run=scan_run(started=MID_SCAN_START),
        now=MID_SCAN_CONTROLLER,
        controller=MID_SCAN_CONTROLLER,
    )


def test_a_waiver_that_lapses_after_the_scan_start_is_listed_as_lapsed() -> None:
    evaluation = lapsed_mid_scan()
    assert statuses(evaluation) == {"EXC-001": "expired"}
    assert by_rule(evaluation)[RULE].exception == model.ExceptionStatus.none()
    assert by_rule(evaluation)[RULE].outcome is model.Outcome.FAIL
    assert evaluation.lapsed_rule_ids() == (RULE,)
    expired_at_start = evaluate(entry(), run=scan_run(started="2027-03-31T00:00:00Z"), now=NOW)
    assert statuses(expired_at_start) == {"EXC-001": "expired"}
    assert expired_at_start.lapsed_rule_ids() == ()
    assert evaluate(entry()).lapsed_rule_ids() == ()


S = exceptions.Status
R = exceptions.Review


@pytest.mark.parametrize(
    ("seen", "verdict"),
    [
        ([S.UNMATCHED], R.STALE),
        ([S.UNMATCHED, S.UNMATCHED], R.STALE),
        ([S.UNMATCHED, S.NOT_FAILING], R.NOT_FAILING),
        ([S.SUPERSEDED, S.SUPERSEDED], R.SUPERSEDED),
        ([S.SUPERSEDED, S.UNMATCHED, S.NOT_FAILING], R.SUPERSEDED),
        ([S.NOT_YET_EFFECTIVE, S.SUPERSEDED], R.NOT_YET_EFFECTIVE),
        ([S.WAIVED, S.NOT_YET_EFFECTIVE, S.UNMATCHED], R.IN_EFFECT),
        ([S.WAIVED, S.EXPIRED], R.EXPIRED),
        ([S.EXPIRED], R.EXPIRED),
    ],
)
def test_review_takes_the_most_urgent_status(
    seen: list[exceptions.Status], verdict: exceptions.Review
) -> None:
    assert exceptions.review(seen) is verdict
    assert exceptions.review(tuple(reversed(seen))) is verdict


def test_removal_candidates_are_stale_superseded_or_not_failing_everywhere() -> None:
    files = (
        entry(id="EXC-A-WAIVES", expires="2026-12-31"),
        entry(id="EXC-B-SUPERSEDED", expires="2027-03-31", scope={"hosts": ["web01", "web02"]}),
        entry(id="EXC-C-PASSES", rule=OTHER_RULE),
        entry(id="EXC-D-STALE", scope={"hosts": ["elsewhere"]}),
        entry(id="EXC-E-SOMETIMES", scope={"hosts": ["web02"]}, expires="2026-11-30"),
    )
    first = evaluate(*files)
    second = evaluate(*files, where=target("web02"))
    documents = [first.to_dict(), second.to_dict()]
    assert statuses(first)["EXC-B-SUPERSEDED"] == "superseded"
    assert statuses(second)["EXC-B-SUPERSEDED"] == "superseded"
    assert exceptions.review_exceptions(documents) == {
        "EXC-A-WAIVES": R.IN_EFFECT,
        "EXC-B-SUPERSEDED": R.SUPERSEDED,
        "EXC-C-PASSES": R.NOT_FAILING,
        "EXC-D-STALE": R.STALE,
        "EXC-E-SOMETIMES": R.IN_EFFECT,
    }
    assert exceptions.removal_candidate_ids(documents) == [
        "EXC-B-SUPERSEDED",
        "EXC-C-PASSES",
        "EXC-D-STALE",
    ]
    assert exceptions.stale_exception_ids(documents) == ["EXC-D-STALE"]


def test_review_refuses_unknown_evaluation_versions() -> None:
    document = evaluate(entry()).to_dict()
    for version in ("2.0", "0.9", None, 1):
        changed = {**document, "schema_version": version}
        for check in (
            exceptions.stale_exception_ids,
            exceptions.removal_candidate_ids,
            exceptions.review_exceptions,
        ):
            with pytest.raises(exceptions.ExceptionsError, match="unsupported schema_version"):
                check([document, changed])


def round_trip(evaluation: exceptions.Evaluation) -> dict[str, object]:
    loaded: dict[str, object] = json.loads(json.dumps(evaluation.to_dict()))
    return loaded


Built = tuple[exceptions.Evaluation, str]


def built(*entries: dict[str, object], **options: Any) -> Built:
    evaluation = evaluate(*entries, **options)
    return evaluation, document(*entries)


def overlapping() -> Built:
    return built(entry(id="EXC-LATE"), entry(id="EXC-SOON", expires="2026-12-31"))


def expired_at_scan_start() -> Built:
    return built(entry(), run=scan_run(started="2027-03-31T00:00:00Z"), now=NOW)


def before_approval() -> Built:
    return built(
        entry(created="2026-10-01", approval={"approver": "ciso", "date": "2026-10-05"}),
        run=scan_run(started="2026-10-04T23:59:59Z"),
        controller=NOW,
    )


def failed_run() -> Built:
    return built(entry(), run=scan_run({RULE: model.Outcome.ERROR}, status=FAILED))


def two_rules() -> Built:
    return built(entry(), entry(id="EXC-002", rule=OTHER_RULE))


def no_exceptions() -> Built:
    return built()


def lapsed_built() -> Built:
    return lapsed_mid_scan(), document(entry())


FAILED = model.ScanStatus.FAILED
BUILDERS = (
    two_rules,
    overlapping,
    expired_at_scan_start,
    lapsed_built,
    before_approval,
    failed_run,
    no_exceptions,
)


@pytest.mark.parametrize("build", BUILDERS)
def test_verify_evaluation_accepts_every_document_evaluate_run_writes(
    build: Callable[[], Built],
) -> None:
    evaluation, text = build()
    verified = exceptions.verify_evaluation(round_trip(evaluation), text)
    assert verified == evaluation
    assert verified.lapsed_rule_ids() == evaluation.lapsed_rule_ids()


def edit(document: dict[str, object], path: tuple[str | int, ...], value: object) -> object:
    copied: object = json.loads(json.dumps(document))
    node = copied
    for step in path[:-1]:
        node = cast("dict[str | int, object]", node)[step]
    cast("dict[str | int, object]", node)[path[-1]] = value
    return copied


TAMPERING: list[tuple[tuple[str | int, ...], object]] = [
    (("exceptions", 0, "status"), "unmatched"),
    (("exceptions", 0, "expired"), True),
    (("exceptions", 0, "outcome"), "pass"),
    (("exceptions", 0, "superseded_by"), "EXC-002"),
    (("exceptions", 0, "expires_at"), "2027-03-30T00:00:00Z"),
    (("exceptions", 0, "expires"), "2027-03-30"),
    (("exceptions", 0, "justification"), "A different justification."),
    (("exceptions", 0, "risk"), "low"),
    (("exceptions", 0, "scope"), {"hosts": ["web02"]}),
    (("exceptions", 0, "note"), "x"),
    (("exceptions",), []),
    (("summary", "waived"), 0),
    (("summary", "unmatched"), 5),
    (("scan_run", "findings", 1, "outcome"), "fail"),
    (("scan_run", "findings", 1, "exception"), model.ExceptionStatus.none().to_dict()),
    (("scan_run", "findings", 1, "exception", "reason"), "Accepted by everybody."),
    (("scan_run", "findings", 1, "exception", "exception_id"), "EXC-002"),
    (("scan_run", "findings", 0, "outcome"), "waived"),
    (("scan_run", "findings", 0, "outcome"), "fail"),
    (("evaluated_at",), "2026-10-25T09:00:00Z"),
    (("scan_started_at",), "2026-10-25T09:00:00Z"),
    (("scan_lag_seconds",), 7),
    (("scan_lag_exceeded",), True),
    (("max_validity_days",), 3650),
    (("max_validity_days",), 365.0),
    (("target", "host"), "web02"),
]


@pytest.mark.parametrize(("path", "value"), TAMPERING)
def test_verify_evaluation_detects_every_edit(path: tuple[str | int, ...], value: object) -> None:
    evaluation, text = two_rules()
    with pytest.raises(exceptions.ExceptionsError):
        exceptions.verify_evaluation(edit(round_trip(evaluation), path, value), text)


def test_verify_evaluation_needs_the_exceptions_file_it_names() -> None:
    evaluation, text = two_rules()
    data = round_trip(evaluation)
    for other in (text + "\n", document_text_without_second_entry(), document()):
        with pytest.raises(exceptions.ExceptionsError, match="not made from this exceptions file"):
            exceptions.verify_evaluation(data, other)
    with pytest.raises(exceptions.ExceptionsError, match="exceptions file: line 1"):
        exceptions.verify_evaluation(data, "not yaml")
    with pytest.raises(exceptions.ExceptionsError, match="exceptions file must be text"):
        exceptions.verify_evaluation(data, None)
    forged = edit(data, ("source_sha256",), "b" * 64)
    with pytest.raises(exceptions.ExceptionsError, match="not made from this exceptions file"):
        exceptions.verify_evaluation(forged, text)


def document_text_without_second_entry() -> str:
    return document(entry())


def test_an_evaluation_rebuilt_from_a_made_up_file_is_refused() -> None:
    made_up = document(
        entry(owner="mallory", approval={"approver": "trent", "date": "2026-10-02"}),
        entry(id="EXC-002", rule=OTHER_RULE, owner="mallory"),
    )
    real = document(entry())
    parsed = exceptions.parse_exceptions(made_up, NOW)
    forged = exceptions.evaluate_run(scan_run(), parsed, target(), instant(STARTED))
    assert exceptions.verify_evaluation(round_trip(forged), made_up) == forged
    with pytest.raises(exceptions.ExceptionsError, match="not made from this exceptions file"):
        exceptions.verify_evaluation(round_trip(forged), real)
    relabelled = edit(
        round_trip(forged), ("source_sha256",), hashlib.sha256(real.encode()).hexdigest()
    )
    with pytest.raises(exceptions.ExceptionsError, match="does not match a new evaluation"):
        exceptions.verify_evaluation(relabelled, real)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("schema_version",), "2.0", "unsupported schema_version '2.0'"),
        (("schema_version",), 1, "unsupported schema_version '1'"),
        (("controller_time",), "yesterday", "controller_time is not a UTC timestamp"),
        (("controller_time",), 5, "controller_time must be a string"),
        (("controller_time",), "2020-01-01T00:00:00Z", "created is in the future"),
        (("max_scan_lag_seconds",), True, "max_scan_lag_seconds must be an integer"),
        (("max_scan_lag_seconds",), "60", "max_scan_lag_seconds must be an integer"),
        (("max_scan_lag_seconds",), 0, "maximum scan lag must be positive"),
        (("target",), {"host": "web01"}, "target is missing keys: groups"),
        (("target", "host"), "", "target.host must not be empty"),
        (("scan_run",), 5, "the scan run must be a mapping"),
        (("extra",), "x", "evaluation has unknown keys: 'extra'"),
        (("target",), None, "target must not be null"),
    ],
)
def test_verify_evaluation_rejects_malformed_documents(
    path: tuple[str | int, ...], value: object, message: str
) -> None:
    evaluation, text = built(entry())
    with pytest.raises(exceptions.ExceptionsError, match=message):
        exceptions.verify_evaluation(edit(round_trip(evaluation), path, value), text)


def test_a_benchmark_scope_version_must_be_a_version_token() -> None:
    for version in ("0.1 82", "all controls compliant", "-1", "1/2"):
        scope = {"benchmark": {"id": BENCHMARK, "version": version}, "profiles": [PROFILE]}
        invalid_entry(r"scope\.benchmark\.version has an invalid format", scope=scope)
    for version in ("0.1.82", "v1.2+build~rc1", "2:1.0-3"):
        scope = {"benchmark": {"id": BENCHMARK, "version": version}, "profiles": [PROFILE]}
        assert parse(entry(scope=scope)).records[0].scope.benchmark is not None


def test_verify_evaluation_rejects_values_that_are_not_json() -> None:
    evaluation, text = built(entry())
    with pytest.raises(exceptions.ExceptionsError, match="not JSON data"):
        exceptions.verify_evaluation({**round_trip(evaluation), "summary": {1, 2}}, text)


def test_verify_evaluation_needs_every_key() -> None:
    evaluation, text = two_rules()
    document = round_trip(evaluation)
    for key in exceptions.EVALUATION_KEYS:
        partial = {name: value for name, value in document.items() if name != key}
        with pytest.raises(exceptions.ExceptionsError, match=f"missing keys: {key}"):
            exceptions.verify_evaluation(partial, text)
    with pytest.raises(exceptions.ExceptionsError, match="evaluation must be a mapping"):
        exceptions.verify_evaluation([document], text)
