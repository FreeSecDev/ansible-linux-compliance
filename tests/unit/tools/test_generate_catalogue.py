from __future__ import annotations

import copy
import hashlib
import re
import runpy
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import generate_catalogue as gen
from tools.roles import generate_toggles, profile_values

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
XCCDF = "http://checklists.nist.gov/xccdf/1.2"
RULE = "xccdf_org.ssgproject.content_rule_"
PROFILE = "xccdf_org.ssgproject.content_profile_"

FIRST_STREAM: dict[str, list[str]] = {
    "auditing": ["audit_rules_immutable", "grub2_audit_argument"],
    "auditing/file_permissions_auditd": ["file_permissions_etc_audit_auditd"],
    "services/cron_and_at": ["file_permissions_crontab", "service_cron_enabled"],
    "services/ssh": ["sshd_disable_root_login"],
    "system/permissions/files": [
        "sysctl_fs_protected_symlinks",
        "dir_perms_world_writable",
        "no_files_unowned_by_user",
    ],
    "system/permissions/mounting": ["kernel_module_usb-storage_disabled"],
}
SECOND_STREAM: dict[str, list[str]] = {
    "services/ssh": ["sshd_disable_root_login", "sshd_set_idle_timeout"],
    "system/permissions/files": ["file_permissions_crontab"],
}


def family(
    name: str,
    *,
    disruptive: bool = True,
    topic_groups: list[str] | None = None,
    rule_prefixes: list[str] | None = None,
    fallback_groups: list[str] | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "disruptive": disruptive,
        "title": f"The {name} topic",
        "why": f"Why {name}",
        "topic_groups": topic_groups or [],
        "rule_prefixes": rule_prefixes or [],
        "fallback_groups": fallback_groups or [],
    }


def source_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "families": [
            family(
                "file_permissions",
                disruptive=False,
                rule_prefixes=["dir_perms_", "file_permissions_"],
                fallback_groups=["files"],
            ),
            family("sysctl", disruptive=False, rule_prefixes=["sysctl_"]),
            family("auditd", topic_groups=["auditing"]),
            family("services", fallback_groups=["services"]),
            family("kernel_modules", rule_prefixes=["kernel_module_"]),
            family("ssh", topic_groups=["ssh"]),
            family("mounts"),
        ],
        "native_rules": [
            {
                "rule_id": RULE + "file_permissions_crontab",
                "revert_strategy": "recorded_value",
                "runbook": None,
                "parameters": {"path": "/etc/crontab", "max_mode": "0600"},
            }
        ],
        "subsystem_tags": [],
        "untagged_families": [],
        "ledger_family_aliases": {},
    }


def source(document: dict[str, object] | None = None) -> gen.Source:
    return gen.parse_source(source_document() if document is None else document)


def group_element(name: str, children: dict[str, object]) -> str:
    rules = cast("list[str]", children.get("", []))
    body = "".join(
        f'<Rule id="{RULE}{rule}" selected="false" severity="medium"><title>{rule}</title></Rule>'
        for rule in rules
    )
    body += "".join(
        group_element(child, cast("dict[str, object]", value))
        for child, value in children.items()
        if child
    )
    return f'<Group id="xccdf_org.ssgproject.content_group_{name}">{body}</Group>'


def benchmark(name: str, groups: dict[str, list[str]], profiles: dict[str, list[str]]) -> bytes:
    tree: dict[str, object] = {}
    for path, rules in groups.items():
        node = tree
        for part in path.split("/"):
            node = cast("dict[str, object]", node.setdefault(part, {}))
        cast("list[str]", node.setdefault("", [])).extend(rules)
    profile_xml = "".join(
        f'<Profile id="{PROFILE}{profile}"><title>{profile}</title>'
        + "".join(f'<select idref="{RULE}{rule}" selected="true"/>' for rule in rules)
        + "</Profile>"
        for profile, rules in profiles.items()
    )
    groups_xml = "".join(
        group_element(group, cast("dict[str, object]", children))
        for group, children in tree.items()
    )
    return (
        f'<Benchmark xmlns="{XCCDF}" id="xccdf_org.ssgproject.content_benchmark_{name}">'
        f"<title>{name}</title><version>0.1.82</version>{profile_xml}{groups_xml}</Benchmark>"
    ).encode()


def all_rules(groups: dict[str, list[str]]) -> list[str]:
    return sorted({rule for rules in groups.values() for rule in rules})


STREAMS: dict[str, tuple[dict[str, list[str]], dict[str, list[str]]]] = {
    "first": (
        FIRST_STREAM,
        {"server": all_rules(FIRST_STREAM), "small": ["sshd_disable_root_login"]},
    ),
    "second": (SECOND_STREAM, {"stig": all_rules(SECOND_STREAM)}),
}


def write_content(directory: Path) -> list[gen.Stream]:
    directory.mkdir(parents=True, exist_ok=True)
    streams: list[gen.Stream] = []
    for name, (groups, profiles) in STREAMS.items():
        data = benchmark(name, groups, profiles)
        path = directory / f"ssg-{name}-ds.xml"
        path.write_bytes(data)
        streams.append(
            gen.Stream(
                name=name,
                path=path,
                sha256=hashlib.sha256(data).hexdigest(),
                profile_ids=tuple(PROFILE + profile for profile in profiles),
            )
        )
    return streams


def read(tmp_path: Path) -> list[gen.StreamRules]:
    return [gen.read_stream(stream) for stream in write_content(tmp_path / "content")]


def built(tmp_path: Path, document: dict[str, object] | None = None) -> gen.Catalogue:
    return gen.build(source(document), read(tmp_path))


def write_root(root: Path) -> Path:
    streams = write_content(root / "build" / "content")
    manifest = cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / gen.MANIFEST).read_text(encoding="utf-8")),
    )
    manifest["datastreams"] = [
        {
            "name": stream.name,
            "os_family": "test",
            "os_version": "1",
            "path": f"scap-security-guide-0.1.82/ssg-{stream.name}-ds.xml",
            "source_sha256": stream.sha256,
            "source_size_bytes": stream.path.stat().st_size,
            "removed_sce_checks": 0,
            "removed_sce_scripts": 0,
            "removed_fix_elements": 0,
            "sha256": stream.sha256,
            "size_bytes": stream.path.stat().st_size,
            "benchmark_id": f"xccdf_org.ssgproject.content_benchmark_{stream.name}",
            "benchmark_version": "0.1.82",
            "profiles": [{"id": profile, "title": profile} for profile in stream.profile_ids],
        }
        for stream in streams
    ]
    (root / "content").mkdir(parents=True, exist_ok=True)
    (root / gen.MANIFEST).write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (root / gen.SOURCE).write_text(yaml.safe_dump(source_document()), encoding="utf-8")
    (root / gen.CATALOGUE).parent.mkdir(parents=True, exist_ok=True)
    (root / gen.REFERENCE).parent.mkdir(parents=True, exist_ok=True)
    return root


def families_of(catalogue: gen.Catalogue) -> dict[str, str]:
    return {
        toggles.rule_short_id(str(rule["rule_id"])): str(rule["family"]) for rule in catalogue.rules
    }


def test_every_selected_rule_gets_exactly_one_family_by_the_documented_order(
    tmp_path: Path,
) -> None:
    assert families_of(built(tmp_path)) == {
        "audit_rules_immutable": "auditd",
        "grub2_audit_argument": "auditd",
        "file_permissions_etc_audit_auditd": "auditd",
        "file_permissions_crontab": "file_permissions",
        "service_cron_enabled": "services",
        "sshd_disable_root_login": "ssh",
        "sshd_set_idle_timeout": "ssh",
        "sysctl_fs_protected_symlinks": "sysctl",
        "dir_perms_world_writable": "file_permissions",
        "no_files_unowned_by_user": "file_permissions",
        "kernel_module_usb-storage_disabled": "kernel_modules",
    }


def test_native_rules_keep_their_strategy_and_every_other_rule_is_audit_only(
    tmp_path: Path,
) -> None:
    catalogue = built(tmp_path)
    by_id = {str(rule["rule_id"]): rule for rule in catalogue.rules}
    crontab = by_id[RULE + "file_permissions_crontab"]
    assert crontab["revert_strategy"] == "recorded_value"
    assert crontab["parameters"] == {"path": "/etc/crontab", "max_mode": "0600"}
    usb = by_id[RULE + "kernel_module_usb-storage_disabled"]
    assert usb == {
        "rule_id": RULE + "kernel_module_usb-storage_disabled",
        "family": "kernel_modules",
        "disruptive": True,
        "reversible": True,
        "revert_strategy": "audit_only",
        "toggle": "linux_compliance_rule_kernel_module_usb_storage_disabled_enabled",
        "runbook": None,
        "parameters": {},
    }
    assert [rule["rule_id"] for rule in catalogue.rules] == sorted(by_id)


def test_the_rendered_catalogue_is_compact_and_expands_to_the_built_one(tmp_path: Path) -> None:
    catalogue = built(tmp_path)
    text = gen.render_catalogue(catalogue)
    data = cast("dict[str, object]", yaml.safe_load(text))
    assert list(data) == [
        generate_toggles.FAMILIES_KEY,
        generate_toggles.RULES_KEY,
        generate_toggles.AUDIT_ONLY_KEY,
        generate_toggles.TAGS_KEY,
        generate_toggles.ALIASES_KEY,
    ]
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    assert audit_only["mounts"] == []
    assert audit_only["ssh"] == [RULE + "sshd_disable_root_login", RULE + "sshd_set_idle_timeout"]
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        data[generate_toggles.RULES_KEY],
        data[generate_toggles.AUDIT_ONLY_KEY],
        data[generate_toggles.FAMILIES_KEY],
        {},
        errors,
    )
    assert errors.items == []
    assert loaded.rules == catalogue.rules
    assert "  - name: file_permissions\n    disruptive: false\n" in text


def test_the_reference_reports_every_family_and_profile(tmp_path: Path) -> None:
    reference = gen.reference(built(tmp_path))
    assert reference.startswith("# Control families\n")
    assert (
        "| 1 | `file_permissions` | none | The file_permissions topic | no | "
        "Why file_permissions | 3 | 1 | 2 |"
    ) in reference
    assert "| 7 | `mounts` | none | The mounts topic | yes | Why mounts | 0 | 0 | 0 |" in reference
    assert "|  | All |  |  |  |  | 11 | 1 | 10 |" in reference
    assert "## Umbrellas" in reference
    assert "### `first` (content 0.1.82)" in reference
    assert "| Family | `server` | `small` |" in reference
    assert "| `ssh` | 1 | 1 |" in reference
    assert "| All families | 10 | 1 |" in reference
    assert "| Native remediation | 1 | 0 |" in reference
    assert "| `mounts` | none | none | none |" in reference
    assert (
        "| `file_permissions` | none | `dir_perms_`, `file_permissions_` | `files` |" in reference
    )
    assert gen.outputs(built(tmp_path))[gen.REFERENCE] == reference


def test_the_reference_lists_each_umbrella_with_its_families(tmp_path: Path) -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[0]["umbrella"] = "system"
    families[1]["umbrella"] = "system"
    catalogue = built(tmp_path, document)
    reference = gen.reference(catalogue)
    count = sum(rule["family"] in {"file_permissions", "sysctl"} for rule in catalogue.rules)
    assert "## Umbrellas" in reference
    assert (
        f"| `linux_compliance_system_enabled` | `file_permissions`, `sysctl` | {count} |"
        in reference
    )
    assert "| 1 | `file_permissions` | `system` | The file_permissions topic |" in reference
    assert "`linux_compliance_ssh_enabled` |" not in reference.split("## Umbrellas", 1)[1]


def test_a_rule_below_topic_groups_of_several_umbrellas_is_an_error() -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[3]["topic_groups"] = ["services"]
    families[3]["fallback_groups"] = []
    with pytest.raises(gen.GenerationError, match="which map to families of several umbrellas"):
        gen.family_of(RULE + "sshd_x", ["services", "ssh"], source(document))
    families[3]["umbrella"] = "remote"
    families[5]["umbrella"] = "access"
    with pytest.raises(gen.GenerationError, match="which map to families of several umbrellas"):
        gen.family_of(RULE + "sshd_x", ["services", "ssh"], source(document))


def test_the_innermost_topic_group_decides_when_the_families_share_an_umbrella() -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[3]["topic_groups"] = ["services"]
    families[3]["fallback_groups"] = []
    families[3]["umbrella"] = "remote"
    families[5]["umbrella"] = "remote"
    mapping = source(document)
    assert gen.family_of(RULE + "sshd_x", ["services", "ssh"], mapping) == (
        "ssh",
        ("topic_groups", "ssh"),
    )
    assert gen.family_of(RULE + "x", ["services"], mapping) == (
        "services",
        ("topic_groups", "services"),
    )


def test_a_family_that_heads_an_umbrella_refines_with_its_families() -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[3]["topic_groups"] = ["services"]
    families[3]["fallback_groups"] = []
    families[5]["umbrella"] = "services"
    mapping = source(document)
    assert gen.registry(mapping)[5] == {"name": "ssh", "disruptive": True, "umbrella": "services"}
    assert gen.family_of(RULE + "sshd_x", ["services", "ssh"], mapping)[0] == "ssh"


@pytest.mark.parametrize(
    ("umbrella", "message"),
    [
        ("Remote", "families[5].umbrella must be a family or umbrella name, got 'Remote'"),
        (None, "families[5].umbrella must be a family or umbrella name, got None"),
        ("verify_x", "families[5].umbrella must be a family or umbrella name, got 'verify_x'"),
    ],
)
def test_an_invalid_umbrella_in_the_mapping_is_an_error(umbrella: object, message: str) -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[5]["umbrella"] = umbrella
    with pytest.raises(gen.GenerationError, match=re.escape(message)):
        gen.parse_source(document)


def test_an_umbrella_of_two_levels_in_the_mapping_is_an_error() -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[3]["umbrella"] = "ssh"
    families[5]["umbrella"] = "remote"
    with pytest.raises(gen.GenerationError, match="family ssh heads an umbrella"):
        gen.parse_source(document)


def test_a_rule_that_nothing_decides_maps_to_no_family() -> None:
    with pytest.raises(gen.GenerationError, match=r"\(groups system/other\) maps to no family"):
        gen.family_of(RULE + "x", ["system", "other"], source())
    with pytest.raises(gen.GenerationError, match=r"\(groups none\) maps to no family"):
        gen.family_of(RULE + "x", [], source())


def test_the_innermost_fallback_group_decides() -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[6]["fallback_groups"] = ["system"]
    assert gen.family_of(RULE + "x", ["system", "files"], source(document)) == (
        "file_permissions",
        ("fallback_groups", "files"),
    )
    assert gen.family_of(RULE + "x", ["system", "other"], source(document))[0] == "mounts"


def test_every_problem_of_the_mapping_is_reported(tmp_path: Path) -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[3]["fallback_groups"] = []
    families[6]["rule_prefixes"] = ["mount_option_"]
    cast("list[dict[str, object]]", document["native_rules"]).append(
        {
            "rule_id": RULE + "partition_for_tmp",
            "revert_strategy": "irreversible",
            "runbook": "docs/x.md",
            "parameters": {},
        }
    )
    with pytest.raises(gen.GenerationError) as raised:
        built(tmp_path, document)
    message = str(raised.value)
    assert message.startswith("3 problem(s): ")
    assert f"{RULE}service_cron_enabled (groups services/cron_and_at) maps to no family" in message
    assert "the rule_prefixes entry 'mount_option_' of mounts decides no rule" in message
    assert f"the native rule {RULE}partition_for_tmp is not selected by any pinned profile" in (
        message
    )


def test_two_datastreams_that_disagree_on_a_family_are_an_error(tmp_path: Path) -> None:
    document = source_document()
    families = cast("list[dict[str, object]]", document["families"])
    families[0]["rule_prefixes"] = ["dir_perms_"]
    families[3]["fallback_groups"] = ["cron_and_at", "services"]
    with pytest.raises(gen.GenerationError, match="maps to services in first and to"):
        built(tmp_path, document)


def test_an_invalid_generated_catalogue_is_an_error(tmp_path: Path) -> None:
    document = source_document()
    native = cast("list[dict[str, object]]", document["native_rules"])
    native[0]["runbook"] = "docs/remediation.md"
    with pytest.raises(gen.GenerationError, match="the generated catalogue is invalid"):
        built(tmp_path, document)


def child(node: object, part: str) -> object:
    if isinstance(node, list):
        return cast("list[object]", node)[int(part)]
    return cast("dict[str, object]", node)[part]


def mutated(path: str, value: object) -> dict[str, object]:
    document = copy.deepcopy(source_document())
    *parents, last = path.split(".")
    target: object = document
    for part in parents:
        target = child(target, part)
    if isinstance(target, list):
        cast("list[object]", target)[int(last)] = value
    else:
        cast("dict[str, object]", target)[last] = value
    return document


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "must be a mapping with exactly"),
        ({"schema_version": 1}, "must be a mapping with exactly"),
        (mutated("schema_version", 2), "schema_version must be 1"),
        (mutated("native_rules", "x"), "native_rules must be a list"),
        (mutated("families.0", "x"), r"families\[0\] must be a mapping with exactly"),
        (mutated("families.0.disruptive", "no"), r"families\[0\]\.disruptive must be a boolean"),
        (mutated("families.0.title", ""), r"families\[0\]\.title must be a non-empty printable"),
        (mutated("families.0.why", "a\nb"), r"families\[0\]\.why must be a non-empty printable"),
        (mutated("families.0.name", 3), r"families\[0\]\.name must be a non-empty printable"),
        (
            mutated("families.0.rule_prefixes", "file_"),
            r"families\[0\]\.rule_prefixes must be a list of names",
        ),
        (
            mutated("families.0.rule_prefixes", ["file"]),
            r"families\[0\]\.rule_prefixes must be a list of names",
        ),
        (
            mutated("families.0.fallback_groups", ["b", "a"]),
            r"families\[0\]\.fallback_groups must be sorted and free of duplicates",
        ),
        (
            mutated("families.0.topic_groups", ["a", "a"]),
            r"families\[0\]\.topic_groups must be sorted and free of duplicates",
        ),
        (
            mutated("families.1.rule_prefixes", ["file_"]),
            "the rule prefix 'file_' is the start of 'file_permissions_'",
        ),
        (
            mutated("families.2.fallback_groups", ["files"]),
            "the group 'files' is mapped by file_permissions and auditd",
        ),
        (
            mutated("families.5.topic_groups", ["services"]),
            "the group 'services' is mapped by services and ssh",
        ),
        (mutated("families.0.name", "audit"), "invalid or reserved family name 'audit'"),
        (mutated("families.2.disruptive", value=False), "family auditd is always disruptive"),
        (mutated("native_rules.0", "x"), r"native_rules\[0\] must be a mapping with exactly"),
        (
            mutated("native_rules.0.revert_strategy", "audit_only"),
            "must be a native revert strategy, got 'audit_only'",
        ),
        (
            mutated("native_rules.0.revert_strategy", "guess"),
            "must be a native revert strategy, got 'guess'",
        ),
        (
            mutated("native_rules.0.rule_id", "crontab"),
            "is not a ComplianceAsCode rule identifier",
        ),
        (
            mutated(
                "native_rules", [cast("list[object]", source_document()["native_rules"])[0]] * 2
            ),
            "native_rules lists a rule twice",
        ),
    ],
)
def test_an_invalid_mapping_source_is_refused(document: object, message: str) -> None:
    with pytest.raises(gen.GenerationError, match=message):
        gen.parse_source(document)


def test_an_unreadable_source_is_refused(tmp_path: Path) -> None:
    with pytest.raises(gen.GenerationError, match="cannot be read as YAML"):
        gen.load_source(tmp_path / "missing.yml")
    broken = tmp_path / "broken.yml"
    broken.write_text("---\n{\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="cannot be read as YAML"):
        gen.load_source(broken)


def test_a_datastream_with_another_digest_or_without_a_profile_is_refused(tmp_path: Path) -> None:
    stream = write_content(tmp_path)[0]
    with pytest.raises(gen.GenerationError, match="first: content digest mismatch"):
        gen.read_stream(gen.Stream(stream.name, stream.path, "0" * 64, stream.profile_ids))
    with pytest.raises(gen.GenerationError, match="is not in benchmark"):
        gen.read_stream(gen.Stream(stream.name, stream.path, stream.sha256, (PROFILE + "x",)))


def test_the_rules_of_a_stream_are_the_union_of_its_profiles(tmp_path: Path) -> None:
    first = read(tmp_path)[0]
    assert gen.selected_rules(first) == [RULE + rule for rule in all_rules(FIRST_STREAM)]
    assert first.groups[RULE + "file_permissions_etc_audit_auditd"] == (
        "auditing",
        "file_permissions_auditd",
    )
    assert first.version == "0.1.82"


def test_main_writes_then_checks_the_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_root(tmp_path)
    assert gen.main(["--root", str(root), "--check"]) == 1
    assert "the catalogue is out of date; run make catalogue" in capsys.readouterr().err
    assert gen.main(["--root", str(root)]) == 0
    assert "run make toggles next" in capsys.readouterr().out
    assert (root / gen.CATALOGUE).is_file()
    assert (root / gen.REFERENCE).is_file()
    assert gen.main(["--root", str(root), "--check"]) == 0
    assert "match the pinned content" in capsys.readouterr().out


def test_main_reports_missing_content_and_a_broken_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_root(tmp_path)
    (root / "build" / "content" / "ssg-second-ds.xml").unlink()
    assert gen.main(["--root", str(root)]) == 2
    assert "ssg-second-ds.xml is missing; run make content" in capsys.readouterr().err
    (root / gen.MANIFEST).write_text("---\n[]\n", encoding="utf-8")
    assert gen.main(["--root", str(root)]) == 2
    assert f"{gen.MANIFEST}: manifest must be a mapping" in capsys.readouterr().err


def test_main_runs_as_a_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_root(tmp_path)
    assert gen.main(["--root", str(root)]) == 0
    monkeypatch.setattr(sys, "argv", ["generate_catalogue", "--root", str(root), "--check"])
    monkeypatch.delitem(sys.modules, "tools.roles.generate_catalogue", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.roles.generate_catalogue", run_name="__main__")
    assert raised.value.code == 0
    assert "match the pinned content" in capsys.readouterr().out


def repository_source() -> gen.Source:
    return gen.load_source(REPOSITORY_ROOT / gen.SOURCE)


def repository_catalogue() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / gen.CATALOGUE).read_text(encoding="utf-8")),
    )


def test_the_repository_mapping_is_valid_and_matches_the_registry() -> None:
    mapping = repository_source()
    data = repository_catalogue()
    assert gen.registry(mapping) == data[generate_toggles.FAMILIES_KEY]
    assert list(cast("dict[str, object]", data[generate_toggles.AUDIT_ONLY_KEY])) == [
        item.name for item in mapping.families
    ]
    native = cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY])
    assert {str(rule["rule_id"]) for rule in native} == set(mapping.native_rules)
    for rule in native:
        details = dict(mapping.native_rules[str(rule["rule_id"])])
        value = details.pop(gen.PROFILE_VALUE_KEY, None)
        pinned = details.pop(gen.PROFILE_VALUE_ID_KEY, None)
        if pinned is not None:
            value = str(pinned).removeprefix(profile_values.VALUE_PREFIX)
        parameters = cast("dict[str, object]", rule["parameters"])
        hand_written = {
            key: parameters[key] for key in parameters if key not in gen.GENERATED_PARAMETERS
        }
        assert {key: rule[key] for key in details if key != "parameters"} == {
            key: details[key] for key in details if key != "parameters"
        }
        assert hand_written == details["parameters"]
        assert parameters.get("value_id") == value
        assert ("profile_values" in parameters) is (value is not None)


def test_the_repository_mapping_covers_the_required_topics() -> None:
    families = repository_source().families
    names = {item.name for item in families} | {item.scope for item in families}
    assert {
        "auditd",
        "sysctl",
        "file_permissions",
        "ssh",
        "pam",
        "services",
        "accounts",
        "logging",
        "mounts",
        "firewall",
        "bootloader",
        "packages",
        "crypto_policy",
        "kernel_modules",
    } <= names


def test_the_repository_disruptive_families_are_the_pinned_ones() -> None:
    disruptive = {item.name for item in repository_source().families if item.disruptive}
    assert disruptive == set(toggles.DISRUPTIVE_FAMILIES)


def test_the_repository_mapping_lists_non_disruptive_families_first() -> None:
    flags = [item.disruptive for item in repository_source().families]
    assert flags == sorted(flags)
    assert repository_source().families[-1].name == "bootloader"
