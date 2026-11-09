from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tests.unit.tools.test_generate_catalogue import RULE, read, source_document
from tools.roles import generate_catalogue as gen
from tools.roles import generate_toggles

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
NO_RULES: list[str] = []


def tag(
    name: str,
    *,
    rule_patterns: list[str] | None = None,
    groups: list[str] | None = None,
    exclusions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "rule_patterns": rule_patterns or [],
        "groups": groups or [],
        "exclusions": exclusions or [],
    }


def tagged_document() -> dict[str, object]:
    document = source_document()
    document["untagged_families"] = [{"family": "auditd", "reason": "Audit rules record changes"}]
    document["subsystem_tags"] = [
        tag(
            "file_permissions",
            rule_patterns=["auditd"],
            exclusions=[
                {
                    "reason": "An audit file stays with auditd",
                    "rules": ["file_permissions_etc_audit_auditd"],
                }
            ],
        ),
        tag("services", rule_patterns=["cron"], groups=["cron_and_at"]),
        tag(
            "ssh",
            rule_patterns=["ssh"],
            groups=["files"],
            exclusions=[
                {
                    "reason": "Not about SSH",
                    "rules": [
                        "dir_perms_world_writable",
                        "file_permissions_crontab",
                        "no_files_unowned_by_user",
                        "sysctl_fs_protected_symlinks",
                    ],
                }
            ],
        ),
    ]
    document["ledger_family_aliases"] = {"permissions": ["file_permissions"]}
    return document


def build(tmp_path: Path, document: dict[str, object] | None = None) -> gen.Catalogue:
    return gen.build(
        gen.parse_source(tagged_document() if document is None else document), read(tmp_path)
    )


def tags_of(document: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", document["subsystem_tags"])


def test_a_tag_is_derived_from_its_rule_patterns_and_groups(tmp_path: Path) -> None:
    built = build(tmp_path)
    assert built.tags == {"services": [RULE + "file_permissions_crontab"]}
    assert gen.rule_tags(built) == {RULE + "file_permissions_crontab": ("services",)}


def test_the_tags_and_aliases_are_rendered_into_the_catalogue(tmp_path: Path) -> None:
    built = build(tmp_path)
    data = cast("dict[str, object]", yaml.safe_load(gen.render_catalogue(built)))
    assert data[generate_toggles.TAGS_KEY] == {"services": [RULE + "file_permissions_crontab"]}
    assert data[generate_toggles.ALIASES_KEY] == {"permissions": ["file_permissions"]}
    errors = toggles.Errors()
    loaded = toggles.with_tags(
        toggles.load_catalogue(
            data[generate_toggles.RULES_KEY],
            data[generate_toggles.AUDIT_ONLY_KEY],
            data[generate_toggles.FAMILIES_KEY],
            {"linux_compliance_services_enabled": False},
            errors,
        ),
        data[generate_toggles.TAGS_KEY],
        errors,
    )
    assert errors.items == []
    switched_off = toggles.disabled_rules(
        loaded.rules, loaded.toggles, None, umbrellas=loaded.umbrellas, tags=loaded.tags
    )
    assert [item["rule_id"] for item in switched_off] == [
        RULE + "file_permissions_crontab",
        RULE + "service_cron_enabled",
    ]


def test_the_reference_lists_the_tags_their_rules_exclusions_and_additions(tmp_path: Path) -> None:
    reference = gen.reference(build(tmp_path))
    assert "## Subsystem tags" in reference
    assert "- `auditd`: Audit rules record changes." in reference
    assert "| `services` | `cron` | `cron_and_at` | 1 |" in reference
    assert "| `ssh` | `ssh` | `files` | 0 |" in reference
    services = (
        "### Tag `services`\n\n| Rule | Family |\n|---|---|\n"
        "| `file_permissions_crontab` | `file_permissions` |"
    )
    assert services in reference
    assert "### Tag `ssh`\n\nIt tags no rule of another family" in reference
    excluded = (
        "- `dir_perms_world_writable`, `file_permissions_crontab`, `no_files_unowned_by_user`, "
        "`sysctl_fs_protected_symlinks`: Not about SSH."
    )
    assert excluded in reference
    assert "- `file_permissions_etc_audit_auditd`: An audit file stays with auditd." in reference
    assert (
        "| `linux_compliance_services_enabled` | 1 | 1 | `file_permissions_crontab` |" in reference
    )
    assert "## What a toggle switches off through tags" in reference


def test_the_reference_says_that_a_heading_family_is_also_an_umbrella(tmp_path: Path) -> None:
    document = tagged_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[5]["umbrella"] = "services"
    reference = gen.reference(build(tmp_path, document))
    assert "`services` is both a topic and an umbrella" in reference
    assert "switches off its own rules and those of `ssh`" in reference


def test_a_rule_of_an_untagged_family_needs_an_exclusion(tmp_path: Path) -> None:
    document = tagged_document()
    tags_of(document)[0]["exclusions"] = []
    with pytest.raises(gen.GenerationError) as raised:
        build(tmp_path, document)
    message = str(raised.value)
    assert message.startswith("1 subsystem tag problem(s): ")
    assert (
        f"{RULE}file_permissions_etc_audit_auditd matches the subsystem tag file_permissions "
        "(rule pattern 'auditd') but belongs to auditd, whose rules are never tagged: list it "
        "in an exclusion of the tag file_permissions with a reason"
    ) in message


def test_an_untagged_family_rule_found_by_a_group_names_the_group(tmp_path: Path) -> None:
    document = tagged_document()
    tags_of(document)[1] = tag(
        "services", rule_patterns=["cron"], groups=["auditing", "cron_and_at"]
    )
    with pytest.raises(gen.GenerationError, match=r"\(group 'auditing'\) but belongs to auditd"):
        build(tmp_path, document)


def test_an_exclusion_keeps_a_rule_of_a_taggable_family_untagged(tmp_path: Path) -> None:
    document = tagged_document()
    tags_of(document)[1]["exclusions"] = [
        {
            "reason": "The crontab mode is not about the service",
            "rules": ["file_permissions_crontab"],
        }
    ]
    assert build(tmp_path, document).tags == {}


def test_without_untagged_families_an_audit_rule_is_tagged(tmp_path: Path) -> None:
    document = tagged_document()
    document["untagged_families"] = []
    tags_of(document)[0]["exclusions"] = []
    assert build(tmp_path, document).tags["file_permissions"] == [
        RULE + "file_permissions_etc_audit_auditd"
    ]


def test_unused_entries_and_stale_exclusions_fail_the_generation(tmp_path: Path) -> None:
    document = tagged_document()
    tags_of(document)[1] = tag(
        "services",
        rule_patterns=["cron", "telnet"],
        groups=["cron_and_at", "nfs"],
        exclusions=[
            {"reason": "Gone", "rules": ["missing_rule"]},
            {"reason": "Own family", "rules": ["service_cron_enabled"]},
            {"reason": "Not matched", "rules": ["sshd_disable_root_login"]},
        ],
    )
    with pytest.raises(gen.GenerationError) as raised:
        build(tmp_path, document)
    message = str(raised.value)
    assert message.startswith("5 subsystem tag problem(s): ")
    assert (
        "the rule_patterns entry 'telnet' of the subsystem tag services matches no rule" in message
    )
    assert "the groups entry 'nfs' of the subsystem tag services matches no rule" in message
    for short in ("missing_rule", "service_cron_enabled", "sshd_disable_root_login"):
        assert (
            f"the subsystem tag services excludes {short}, which is not a pinned rule of another "
            "family that the tag matches"
        ) in message


def test_a_rule_pattern_matches_the_short_identifier_in_lower_case() -> None:
    entry = gen.Tag(name="kernel_modules", rule_patterns=("usb-storage",), groups=(), exclusions={})
    assert gen.tag_matches(RULE + "kernel_module_USB-storage_disabled", (), entry) == [
        ("rule_patterns", "usb-storage")
    ]
    assert gen.tag_matches(RULE + "x", ("usb-storage",), entry) == []


def test_the_groups_of_a_rule_are_the_union_over_the_datastreams(tmp_path: Path) -> None:
    groups = gen.rule_groups(read(tmp_path))
    assert groups[RULE + "file_permissions_crontab"] == frozenset(
        {"services", "cron_and_at", "system", "permissions", "files"}
    )


def mutated(change: str, value: object) -> dict[str, object]:
    document = copy.deepcopy(tagged_document())
    if change.startswith("tag."):
        tags_of(document)[1][change.removeprefix("tag.")] = value
    else:
        document[change] = value
    return document


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (mutated("subsystem_tags", "x"), "subsystem_tags must be a list"),
        (mutated("subsystem_tags", ["x"]), r"subsystem_tags\[0\] must be a mapping with exactly"),
        (mutated("tag.name", "nfs"), r"subsystem_tags\[1\]\.name must be a family of the registry"),
        (
            mutated("tag.rule_patterns", ["Cron"]),
            r"subsystem_tags\[1\]\.rule_patterns must be a list",
        ),
        (mutated("tag.rule_patterns", ["x"]), r"subsystem_tags\[1\]\.rule_patterns must be a list"),
        (mutated("tag.groups", ["b", "a"]), r"subsystem_tags\[1\]\.groups must be sorted"),
        (mutated("tag.exclusions", "x"), r"subsystem_tags\[1\]\.exclusions must be a list"),
        (
            mutated("tag.exclusions", [{"reason": "x"}]),
            r"subsystem_tags\[1\]\.exclusions\[0\] must be a mapping with exactly",
        ),
        (
            mutated("tag.exclusions", [{"reason": "", "rules": ["a"]}]),
            r"subsystem_tags\[1\]\.exclusions\[0\]\.reason must be a non-empty printable",
        ),
        (
            mutated("tag.exclusions", [{"reason": "x", "rules": NO_RULES}]),
            r"subsystem_tags\[1\]\.exclusions\[0\]\.rules must list at least one rule",
        ),
        (
            mutated(
                "tag.exclusions", [{"reason": "x", "rules": ["a"]}, {"reason": "y", "rules": ["a"]}]
            ),
            r"subsystem_tags\[1\] excludes a twice",
        ),
        (
            mutated("subsystem_tags", [tag("ssh", groups=["files"])]),
            None,
        ),
        (
            mutated(
                "subsystem_tags", [tag("ssh", rule_patterns=["ssh"]), tag("services", groups=["x"])]
            ),
            "subsystem_tags must be sorted by name and name each family once",
        ),
        (
            mutated(
                "subsystem_tags", [tag("ssh", rule_patterns=["ssh"]), tag("ssh", groups=["x"])]
            ),
            "subsystem_tags must be sorted by name and name each family once",
        ),
        (
            mutated("subsystem_tags", [tag("ssh")]),
            r"subsystem_tags\[0\] needs at least one rule pattern",
        ),
        (mutated("untagged_families", "x"), "untagged_families must be a list"),
        (mutated("untagged_families", [{"family": "auditd"}]), r"untagged_families\[0\] must be a"),
        (
            mutated("untagged_families", [{"family": "nfs", "reason": "x"}]),
            r"untagged_families\[0\]\.family must be a family of the registry listed once",
        ),
        (
            mutated(
                "untagged_families",
                [{"family": "auditd", "reason": "x"}, {"family": "auditd", "reason": "y"}],
            ),
            r"untagged_families\[1\]\.family must be a family of the registry listed once",
        ),
        (
            mutated("untagged_families", [{"family": "auditd", "reason": ""}]),
            r"untagged_families\[0\]\.reason must be a non-empty printable",
        ),
        (
            mutated("ledger_family_aliases", {"permissions": ["nfs"]}),
            "ledger_family_aliases: the alias permissions must list registered families",
        ),
    ],
)
def test_an_invalid_tag_source_is_refused(document: dict[str, object], message: str | None) -> None:
    if message is None:
        assert [item.name for item in gen.parse_source(document).tags] == ["ssh"]
        return
    with pytest.raises(gen.GenerationError, match=message):
        gen.parse_source(document)


def test_the_repository_tags_cover_the_reviewed_examples() -> None:
    source = gen.load_source(REPOSITORY_ROOT / gen.SOURCE)
    names = {item.name for item in source.tags}
    assert {
        "aide",
        "apparmor",
        "cron",
        "faillock",
        "journald",
        "pwhistory",
        "pwquality",
        "rsyslog",
        "selinux",
        "smartcard",
        "sssd",
        "time_sync",
    } <= names
    assert set(source.untagged) == {"auditd", "auditd_conf", "auditd_rules_time"}
    assert source.aliases == {}
    excluded = {short for item in source.tags for short in item.exclusions}
    assert {
        "audit_rules_mac_modification_etc_apparmor",
        "audit_rules_mac_modification_etc_apparmor_d",
    } <= excluded
    for item in source.tags:
        for reason in item.exclusions.values():
            assert re.fullmatch(r"[A-Z].*[A-Za-z0-9)]", reason), reason
