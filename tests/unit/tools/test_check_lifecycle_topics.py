from __future__ import annotations

import copy
import runpy
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import check_lifecycle_topics as lifecycle
from tools.roles import generate_toggles
from tools.roles import promote_native_rule as promote

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SSH_RULE = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
REMOVE = object()
NO_ITEMS: list[object] = []
NO_KEYS: dict[str, object] = {}

VALID: dict[str, object] = {
    "family": "file_permissions",
    "disruptive": False,
    "audit": {"applied_outcomes": ["notapplicable"], "reason": "Containers are not machines."},
    "state": {
        "files": [{"path": "/etc/crontab"}, {"path": "/etc/cron.d/x", "platforms": ["ubuntu"]}],
        "packages": [{"name": "cron", "platforms": ["ubuntu"]}],
        "services": [{"name": "cron"}],
        "sysctl": [{"name": "kernel.dmesg_restrict"}],
        "users": [{"name": "root"}],
        "groups": [{"name": "root"}],
    },
    "applied": {
        "files": [
            {"path": "/etc/crontab", "mode": "0600"},
            {"path": "/etc/cron.d/x", "changes": ["checksum"], "platforms": ["ubuntu"]},
        ],
        "packages": [{"name": "cron", "installed": True}],
    },
    "pre_states": [
        {"name": "as built", "audit": True},
        {
            "name": "customised",
            "audit": False,
            "files": [{"path": "/etc/crontab", "mode": "0640", "owner": "root", "group": "root"}],
        },
    ],
    "unselected_platforms": [{"platform": "rhel_compatible", "reason": "No profile selects it."}],
}


def reference_only(target: Path) -> Path:
    """Write the repository catalogue with only the reference rule native, the rest audit_only."""
    data = cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / generate_toggles.CATALOGUE).read_text(encoding="utf-8")),
    )
    rules = cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY])
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    for rule in rules:
        if rule["family"] != "file_permissions":
            family = str(rule["family"])
            audit_only[family] = sorted([*audit_only[family], str(rule["rule_id"])])
    data[generate_toggles.RULES_KEY] = [
        rule for rule in rules if rule["family"] == "file_permissions"
    ]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("---\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return target


def make_root(
    tmp_path: Path, declarations: dict[str, object], *, catalogue: Path | None = None
) -> Path:
    root = tmp_path / "repository"
    rules = root / generate_toggles.CATALOGUE
    rules.parent.mkdir(parents=True)
    shutil.copyfile(catalogue or reference_only(tmp_path / "reference" / "rules.yml"), rules)
    versions = root / lifecycle.VERSIONS
    versions.parent.mkdir(parents=True)
    shutil.copyfile(REPOSITORY_ROOT / lifecycle.VERSIONS, versions)
    for config in (REPOSITORY_ROOT / lifecycle.MOLECULE).glob("*/molecule.yml"):
        target = root / lifecycle.MOLECULE / config.parent.name / config.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(config, target)
    topics = root / lifecycle.TOPICS
    topics.mkdir(parents=True)
    for family, content in declarations.items():
        text = content if isinstance(content, str) else "---\n" + yaml.safe_dump(content)
        (topics / f"{family}.yml").write_text(text, encoding="utf-8")
    return root


def changed(**updates: object) -> dict[str, object]:
    declaration = copy.deepcopy(VALID)
    for key, value in updates.items():
        if value is REMOVE:
            declaration.pop(key)
        else:
            declaration[key] = value
    return declaration


def errors_for(tmp_path: Path, declaration: object) -> list[str]:
    root = make_root(tmp_path, {"file_permissions": declaration})
    return lifecycle.check(root)[1]


def test_the_repository_declares_every_native_topic(capsys: pytest.CaptureFixture[str]) -> None:
    assert lifecycle.main(["--root", str(REPOSITORY_ROOT)]) == 0
    assert "file_permissions" in capsys.readouterr().out


def test_a_complete_declaration_passes(tmp_path: Path) -> None:
    assert errors_for(tmp_path, VALID) == []


def test_a_native_topic_without_a_declaration_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = make_root(tmp_path, {})
    assert lifecycle.main(["--root", str(root)]) == 1
    error = capsys.readouterr().err
    assert "the native topic file_permissions has no lifecycle declaration" in error
    assert "every native topic needs a valid lifecycle declaration" in error


def test_a_missing_topic_directory_counts_as_no_declaration(tmp_path: Path) -> None:
    root = make_root(tmp_path, {})
    (root / lifecycle.TOPICS).rmdir()
    assert lifecycle.check(root)[1] == [
        (
            f"{lifecycle.TOPICS / 'file_permissions.yml'}: the native topic file_permissions "
            "has no lifecycle declaration"
        )
    ]


def test_a_declaration_for_a_topic_without_a_native_rule_fails(tmp_path: Path) -> None:
    root = make_root(tmp_path, {"file_permissions": VALID, "sysctl": changed(family="sysctl")})
    assert lifecycle.check(root)[1] == [
        (
            f"{lifecycle.TOPICS / 'sysctl.yml'}: sysctl has no native rule in "
            f"{generate_toggles.CATALOGUE}, so it must not have a lifecycle declaration"
        )
    ]


def test_a_new_native_topic_needs_its_own_declaration(tmp_path: Path) -> None:
    catalogue = reference_only(tmp_path / "rules.yml")
    assert promote.main(["--catalogue", str(catalogue), "--rule", SSH_RULE]) == 0
    root = make_root(tmp_path, {"file_permissions": VALID}, catalogue=catalogue)
    native, errors = lifecycle.check(root)
    assert native == ["file_permissions", "ssh"]
    assert errors == [
        f"{lifecycle.TOPICS / 'ssh.yml'}: the native topic ssh has no lifecycle declaration"
    ]


def test_a_disruptive_topic_must_describe_its_containment(tmp_path: Path) -> None:
    catalogue = reference_only(tmp_path / "rules.yml")
    assert promote.main(["--catalogue", str(catalogue), "--rule", SSH_RULE]) == 0
    ssh = {
        "family": "ssh",
        "disruptive": True,
        "state": {"files": [{"path": "/etc/ssh/x"}]},
        "applied": {"files": [{"path": "/etc/ssh/x", "exists": True}]},
    }
    root = make_root(tmp_path, {"file_permissions": VALID, "ssh": ssh}, catalogue=catalogue)
    assert lifecycle.check(root)[1] == [
        f"{root / lifecycle.TOPICS / 'ssh.yml'}: a disruptive topic must describe its containment"
    ]
    ssh["containment"] = "The connection is docker exec, which does not use sshd."
    root = make_root(
        tmp_path / "again", {"file_permissions": VALID, "ssh": ssh}, catalogue=catalogue
    )
    assert lifecycle.check(root)[1] == []


@pytest.mark.parametrize(
    ("declaration", "message"),
    [
        ([], "the declaration must be a mapping"),
        (changed(extra=1), "the declaration has the unknown key 'extra'"),
        (changed(state=REMOVE), "the declaration needs 'state'"),
        (changed(family="sysctl"), "family must be 'file_permissions', the name of the file"),
        (changed(disruptive="no"), "disruptive must be false, as in the registry"),
        (changed(disruptive=True), "disruptive must be false, as in the registry"),
        (changed(containment="text"), "containment is only for a disruptive topic"),
        (changed(state=[]), "state must be a mapping"),
        (changed(state={"files": [], "mounts": []}), "state has the unknown key 'mounts'"),
        (changed(state={"files": [], "applied": None}), "state has the unknown key 'applied'"),
        (changed(state={"files": {}}, applied=REMOVE), "state.files must be a list"),
        (changed(state={"files": ["x"]}, applied=REMOVE), "state.files[0] must be a mapping"),
        (
            changed(state={"files": [{"path": "/x", "mode": "0600"}]}, applied=REMOVE),
            "state.files[0] has the unknown key 'mode'",
        ),
        (
            changed(state={"files": [{"path": "relative"}]}, applied=REMOVE),
            "state.files[0] needs a valid path",
        ),
        (
            changed(state={"users": [{"name": "bad name"}]}, applied=REMOVE, pre_states=REMOVE),
            "state.users[0] needs a valid name",
        ),
        (
            changed(state={"files": [{"path": "/x"}, {"path": "/x"}]}, applied=REMOVE),
            "state.files[1] declares /x twice",
        ),
        (
            changed(state={"files": [{"path": "/x", "platforms": "ubuntu"}]}, applied=REMOVE),
            "state.files[0] needs a non-empty list of platforms",
        ),
        (
            changed(state={"files": [{"path": "/x", "platforms": NO_ITEMS}]}, applied=REMOVE),
            "state.files[0] needs a non-empty list of platforms",
        ),
        (
            changed(state={"files": [{"path": "/x", "platforms": ["debian"]}]}, applied=REMOVE),
            "state.files[0] names the unknown platform 'debian'",
        ),
        (changed(state={}, applied=REMOVE, pre_states=REMOVE), "state declares no item"),
        (changed(applied=REMOVE), "the declaration needs 'applied'"),
        (changed(applied=NO_KEYS), "applied declares no expectation"),
        (changed(applied={"files": NO_ITEMS}), "applied declares no expectation"),
        (changed(unselected_platforms=NO_KEYS), "unselected_platforms must be a list"),
        (changed(unselected_platforms=["x"]), "unselected_platforms[0] must be a mapping"),
        (
            changed(unselected_platforms=[{"platform": "ubuntu", "reason": "r", "x": 1}]),
            "unselected_platforms[0] has the unknown key 'x'",
        ),
        (
            changed(unselected_platforms=[{"platform": "debian", "reason": "r"}]),
            "unselected_platforms[0] needs a known platform",
        ),
        (
            changed(unselected_platforms=[{"reason": "r"}]),
            "unselected_platforms[0] needs a known platform",
        ),
        (
            changed(
                unselected_platforms=[
                    {"platform": "ubuntu", "reason": "r"},
                    {"platform": "ubuntu", "reason": "r"},
                ]
            ),
            "unselected_platforms[1] lists ubuntu twice",
        ),
        (
            changed(unselected_platforms=[{"platform": "ubuntu", "reason": " "}]),
            "unselected_platforms[0] needs a reason",
        ),
        (
            changed(
                unselected_platforms=[
                    {"platform": "ubuntu", "reason": "r"},
                    {"platform": "rhel_compatible", "reason": "r"},
                ]
            ),
            "unselected_platforms lists every platform",
        ),
        (changed(applied=[]), "applied must be a mapping"),
        (changed(applied={"mounts": []}), "applied has the unknown key 'mounts'"),
        (changed(applied={"files": {}}), "applied.files must be a list"),
        (changed(applied={"files": [1]}), "applied.files[0] must be a mapping"),
        (
            changed(applied={"files": [{"path": "/etc/crontab", "mode": "0600", "size": 1}]}),
            "applied.files[0] has the unknown key 'size'",
        ),
        (
            changed(applied={"files": [{"path": "/etc/crontab"}]}),
            "applied.files[0] expects nothing",
        ),
        (
            changed(applied={"files": [{"path": "/etc/crontab", "mode": 600}]}),
            "applied.files[0] needs a four-digit octal mode string",
        ),
        (
            changed(applied={"files": [{"path": "/etc/crontab", "mode": "600"}]}),
            "applied.files[0] needs a four-digit octal mode string",
        ),
        (
            changed(applied={"files": [{"path": "/etc/crontab", "changes": "mode"}]}),
            "applied.files[0] needs a non-empty list of changes",
        ),
        (
            changed(applied={"files": [{"path": "/etc/crontab", "changes": ["size"]}]}),
            "applied.files[0] cannot require a change of 'size'",
        ),
        (
            changed(
                applied={"files": [{"path": "/etc/crontab", "mode": "0600", "changes": ["mode"]}]}
            ),
            "applied.files[0] both sets and requires a change of 'mode'",
        ),
        (
            changed(applied={"files": [{"mode": "0600"}]}),
            "applied.files[0] needs a valid path",
        ),
        (
            changed(applied={"files": [{"path": "/etc/passwd", "mode": "0600"}]}),
            "applied.files[0] expects /etc/passwd, which state.files does not declare",
        ),
        (
            changed(
                applied={
                    "files": [
                        {"path": "/etc/crontab", "mode": "0600"},
                        {"path": "/etc/crontab", "owner": "root"},
                    ]
                }
            ),
            "applied.files[1] expects /etc/crontab twice",
        ),
        (
            changed(
                applied={"files": [{"path": "/etc/crontab", "mode": "0600", "platforms": ["x"]}]}
            ),
            "applied.files[0] names the unknown platform 'x'",
        ),
        (changed(audit=[]), "audit must be a mapping"),
        (
            changed(audit={"applied_outcomes": ["notapplicable"], "reason": "r", "x": 1}),
            "unknown key 'x'",
        ),
        (changed(audit={"reason": "r"}), "audit.applied_outcomes must be a non-empty list"),
        (changed(audit={"applied_outcomes": [""], "reason": "r"}), "must be a non-empty list"),
        (
            changed(audit={"applied_outcomes": ["fail"], "reason": "r"}),
            "audit.applied_outcomes cannot add 'fail'",
        ),
        (
            changed(audit={"applied_outcomes": ["notapplicable"], "reason": " "}),
            "audit.reason must explain why the audit cannot show pass or fixed",
        ),
        (changed(pre_states={}), "pre_states must be a list"),
        (changed(pre_states=[]), "pre_states must not be empty"),
        (changed(pre_states=["x"]), "pre_states[0] must be a mapping"),
        (
            changed(pre_states=[{"name": "a", "extra": 1}]),
            "pre_states[0] has the unknown key 'extra'",
        ),
        (changed(pre_states=[{"audit": True}]), "pre_states[0] needs a name"),
        (changed(pre_states=[{"name": "a"}, {"name": "a"}]), "pre_states[1] repeats the name 'a'"),
        (
            changed(pre_states=[{"name": "a", "audit": "yes"}]),
            "pre_states[0].audit must be a boolean",
        ),
        (
            changed(pre_states=[{"name": "a", "files": NO_KEYS}]),
            "pre_states[0].files must be a list",
        ),
        (
            changed(pre_states=[{"name": "a", "files": [1]}]),
            "pre_states[0].files[0] must be a mapping",
        ),
        (
            changed(
                pre_states=[
                    {"name": "a", "files": [{"path": "/etc/crontab", "mode": "0640", "x": 1}]}
                ]
            ),
            "pre_states[0].files[0] has the unknown key 'x'",
        ),
        (
            changed(pre_states=[{"name": "a", "files": [{"path": "/etc/passwd", "mode": "0640"}]}]),
            "pre_states[0].files[0] sets /etc/passwd, which state.files does not declare",
        ),
        (
            changed(pre_states=[{"name": "a", "files": [{"path": "x", "mode": "0640"}]}]),
            "pre_states[0].files[0] needs a valid path",
        ),
        (
            changed(pre_states=[{"name": "a", "files": [{"path": "/etc/crontab"}]}]),
            "pre_states[0].files[0] sets no mode, owner or group",
        ),
        (
            changed(pre_states=[{"name": "a", "files": [{"path": "/etc/crontab", "mode": "64"}]}]),
            "pre_states[0].files[0] needs a four-digit octal mode string",
        ),
        (
            changed(
                pre_states=[{"name": "a", "files": [{"path": "/etc/crontab", "owner": "a b"}]}]
            ),
            "pre_states[0].files[0] needs a valid owner",
        ),
        (
            changed(pre_states=[{"name": "a", "files": [{"path": "/etc/crontab", "group": 0}]}]),
            "pre_states[0].files[0] needs a valid group",
        ),
    ],
)
def test_an_invalid_declaration_is_reported(
    tmp_path: Path, declaration: object, message: str
) -> None:
    errors = errors_for(tmp_path, declaration)
    assert any(message in error for error in errors), errors


def test_a_minimal_declaration_needs_family_disruptive_state_and_applied(tmp_path: Path) -> None:
    minimal = {
        "family": "file_permissions",
        "disruptive": False,
        "state": {"users": [{"name": "root"}]},
        "applied": {"users": [{"name": "root", "exists": True}]},
    }
    assert errors_for(tmp_path, minimal) == []


def test_the_repository_declarations_pass_against_the_repository_catalogue(tmp_path: Path) -> None:
    topics = REPOSITORY_ROOT / lifecycle.TOPICS
    declarations = {
        path.stem: cast("object", yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted(topics.glob("*.yml"))
    }
    root = make_root(tmp_path, declarations, catalogue=REPOSITORY_ROOT / generate_toggles.CATALOGUE)
    native, errors = lifecycle.check(root)
    assert native == ["file_permissions", "banners", "pwquality"]
    assert errors == []


def test_a_rewritten_file_and_unchanged_rules_are_accepted(tmp_path: Path) -> None:
    declaration = changed(
        state={"files": [{"path": "/etc/crontab", "rewritten": True}]},
        applied={"files": [{"path": "/etc/crontab", "mode": "0600"}]},
        pre_states=[
            {
                "name": "compliant",
                "unchanged": [
                    {"rule": "file_permissions_crontab", "status": "compliant"},
                ],
            },
            {
                "name": "missing on one platform",
                "unchanged": [
                    {
                        "rule": "file_permissions_crontab",
                        "status": "notapplicable",
                        "platforms": ["ubuntu"],
                    }
                ],
            },
        ],
    )
    assert errors_for(tmp_path, declaration) == []


@pytest.mark.parametrize(
    ("declaration", "message"),
    [
        (
            changed(state={"files": [{"path": "/etc/crontab", "rewritten": "yes"}]}),
            "state.files[0].rewritten must be a boolean",
        ),
        (
            changed(state={"users": [{"name": "root", "rewritten": True}]}, applied=REMOVE),
            "state.users[0] has the unknown key 'rewritten'",
        ),
        (
            changed(pre_states=[{"name": "a", "unchanged": NO_KEYS}]),
            "pre_states[0].unchanged must be a list",
        ),
        (
            changed(pre_states=[{"name": "a", "unchanged": ["x"]}]),
            "pre_states[0].unchanged[0] must be a mapping",
        ),
        (
            changed(
                pre_states=[{"name": "a", "unchanged": [{"rule": "sshd_x", "status": "compliant"}]}]
            ),
            "pre_states[0].unchanged[0] needs the short identifier of a native rule of the topic",
        ),
        (
            changed(
                pre_states=[
                    {
                        "name": "a",
                        "unchanged": [
                            {"rule": "file_permissions_crontab", "status": "compliant"},
                            {"rule": "file_permissions_crontab", "status": "compliant"},
                        ],
                    }
                ]
            ),
            "pre_states[0].unchanged[1] lists file_permissions_crontab twice",
        ),
        (
            changed(
                pre_states=[
                    {
                        "name": "a",
                        "unchanged": [{"rule": "file_permissions_crontab", "status": "applied"}],
                    }
                ]
            ),
            "pre_states[0].unchanged[0] needs the status compliant or notapplicable",
        ),
        (
            changed(
                pre_states=[
                    {
                        "name": "a",
                        "unchanged": [
                            {"rule": "file_permissions_crontab", "status": "compliant", "x": 1}
                        ],
                    }
                ]
            ),
            "pre_states[0].unchanged[0] has the unknown key 'x'",
        ),
        (
            changed(
                pre_states=[
                    {
                        "name": "a",
                        "unchanged": [
                            {
                                "rule": "file_permissions_crontab",
                                "status": "compliant",
                                "platforms": ["debian"],
                            }
                        ],
                    }
                ]
            ),
            "pre_states[0].unchanged[0] names the unknown platform 'debian'",
        ),
    ],
)
def test_an_invalid_rewritten_flag_or_unchanged_rule_is_reported(
    tmp_path: Path, declaration: object, message: str
) -> None:
    errors = errors_for(tmp_path, declaration)
    assert any(message in error for error in errors), errors


def test_identity_attributes_of_a_file_may_be_expected(tmp_path: Path) -> None:
    expectation = {"path": "/etc/crontab", "inode": 5, "mtime": 1.0, "attributes": ["e"]}
    assert errors_for(tmp_path, changed(applied={"files": [expectation]})) == []


def test_an_unreadable_declaration_stops_the_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = make_root(tmp_path, {"file_permissions": "---\nfamily: [\n"})
    assert lifecycle.main(["--root", str(root)]) == 2
    assert "cannot be read as YAML" in capsys.readouterr().err


@pytest.mark.parametrize(
    "versions", ["---\n[]\n", "---\nother: {}\n", "---\nmolecule_images: {}\n"]
)
def test_the_platforms_come_from_the_molecule_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], versions: str
) -> None:
    root = make_root(tmp_path, {"file_permissions": VALID})
    (root / lifecycle.VERSIONS).write_text(versions, encoding="utf-8")
    assert lifecycle.main(["--root", str(root)]) == 2
    assert "has no molecule_images mapping" in capsys.readouterr().err


def test_the_platforms_are_the_image_keys_of_the_repository() -> None:
    assert lifecycle.platforms(REPOSITORY_ROOT) == frozenset({"ubuntu", "rhel_compatible"})


def test_the_check_categories_match_the_harness() -> None:
    harness = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "extensions/molecule/shared/vars/lifecycle.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    assert harness["lifecycle_state_keys"] == lifecycle.CATEGORY_KEYS


def test_the_module_runs_as_a_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["check_lifecycle_topics", "--root", str(REPOSITORY_ROOT)])
    sys.modules.pop("tools.roles.check_lifecycle_topics", None)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("tools.roles.check_lifecycle_topics", run_name="__main__")
    assert exit_info.value.code == 0
    assert "file_permissions" in capsys.readouterr().out


LIBVIRT_PRE_STATE: dict[str, object] = {
    "name": "customised ownership",
    "audit": True,
    "requires": ["libvirt"],
    "files": [{"path": "/etc/crontab", "owner": "daemon", "group": "adm"}],
}


def without_scenario(root: Path, name: str) -> Path:
    config = root / lifecycle.MOLECULE / name / "molecule.yml"
    config.unlink()
    config.parent.rmdir()
    return root


def test_the_repository_scenarios_run_every_platform_with_both_drivers() -> None:
    platforms = lifecycle.platforms(REPOSITORY_ROOT)
    assert lifecycle.scenarios(REPOSITORY_ROOT, platforms) == {
        "docker": platforms,
        "libvirt": platforms,
    }


def test_the_harness_knows_the_drivers_of_the_check() -> None:
    harness = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "extensions/molecule/shared/vars/lifecycle.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    assert harness["lifecycle_known_drivers"] == list(lifecycle.DRIVERS)
    assert harness["lifecycle_unrestricted_drivers"] == sorted(lifecycle.UNRESTRICTED_DRIVERS)


def test_a_topic_may_require_libvirt(tmp_path: Path) -> None:
    declaration = changed(requires=["libvirt"], pre_states=[LIBVIRT_PRE_STATE])
    assert errors_for(tmp_path, declaration) == []


def test_a_pre_state_may_require_libvirt(tmp_path: Path) -> None:
    pre_states = [*cast("list[object]", VALID["pre_states"]), LIBVIRT_PRE_STATE]
    assert errors_for(tmp_path, changed(pre_states=pre_states)) == []


@pytest.mark.parametrize(
    ("declaration", "message"),
    [
        (changed(requires="libvirt"), "requires needs a non-empty list of drivers"),
        (changed(requires=NO_ITEMS), "requires needs a non-empty list of drivers"),
        (changed(requires=["vagrant"]), "requires names the unknown driver 'vagrant'"),
        (changed(requires=["libvirt", "libvirt"]), "requires names a driver twice"),
        (
            changed(pre_states=[{**LIBVIRT_PRE_STATE, "requires": ["qemu"]}]),
            "pre_states[0].requires names the unknown driver 'qemu'",
        ),
        (
            changed(requires=["docker"], pre_states=[LIBVIRT_PRE_STATE]),
            "pre_states[0] requires libvirt, which the topic does not require",
        ),
    ],
)
def test_an_invalid_driver_requirement_is_reported(
    tmp_path: Path, declaration: object, message: str
) -> None:
    errors = errors_for(tmp_path, declaration)
    assert any(message in error for error in errors), errors


def test_a_required_driver_must_run_every_selected_platform(tmp_path: Path) -> None:
    root = make_root(
        tmp_path, {"file_permissions": changed(requires=["libvirt"], unselected_platforms=REMOVE)}
    )
    without_scenario(root, "libvirt-rhel-compatible-lifecycle")
    assert lifecycle.check(root)[1] == [
        (
            f"{root / lifecycle.TOPICS / 'file_permissions.yml'}: the declaration requires "
            f"libvirt, but no libvirt scenario in {lifecycle.MOLECULE} runs the platform "
            "rhel_compatible, which unselected_platforms does not list"
        )
    ]


def test_a_required_driver_need_not_run_an_unselected_platform(tmp_path: Path) -> None:
    root = make_root(tmp_path, {"file_permissions": changed(requires=["libvirt"])})
    without_scenario(root, "libvirt-rhel-compatible-lifecycle")
    assert lifecycle.check(root)[1] == []


def test_a_pre_state_driver_must_run_every_selected_platform(tmp_path: Path) -> None:
    pre_states = [*cast("list[object]", VALID["pre_states"]), LIBVIRT_PRE_STATE]
    root = make_root(
        tmp_path,
        {"file_permissions": changed(pre_states=pre_states, unselected_platforms=REMOVE)},
    )
    without_scenario(root, "libvirt-ubuntu-lifecycle")
    errors = lifecycle.check(root)[1]
    assert len(errors) == 1
    assert "no libvirt scenario in extensions/molecule runs the platform ubuntu" in errors[0]


def test_a_declaration_without_a_requirement_needs_no_driver_coverage(tmp_path: Path) -> None:
    root = make_root(tmp_path, {"file_permissions": changed(unselected_platforms=REMOVE)})
    without_scenario(root, "libvirt-ubuntu-lifecycle")
    without_scenario(root, "libvirt-rhel-compatible-lifecycle")
    assert lifecycle.check(root)[1] == []


def test_a_pre_state_without_a_requirement_runs_in_the_docker_scenarios(tmp_path: Path) -> None:
    root = make_root(tmp_path, {"file_permissions": changed(unselected_platforms=REMOVE)})
    without_scenario(root, "docker-rhel-compatible-lifecycle")
    errors = lifecycle.check(root)[1]
    assert len(errors) == 1
    assert "requires docker, but no docker scenario" in errors[0]
    assert "rhel_compatible" in errors[0]


def test_a_topic_requirement_applies_to_its_pre_states_without_one(tmp_path: Path) -> None:
    declaration = changed(requires=["libvirt"], unselected_platforms=REMOVE)
    root = make_root(tmp_path, {"file_permissions": declaration})
    without_scenario(root, "docker-ubuntu-lifecycle")
    without_scenario(root, "docker-rhel-compatible-lifecycle")
    assert lifecycle.check(root)[1] == []


def test_without_coverage_every_driver_counts_as_running_every_platform(tmp_path: Path) -> None:
    path = tmp_path / "file_permissions.yml"
    path.write_text("---\n" + yaml.safe_dump(changed(requires=["libvirt"])), encoding="utf-8")
    platforms = lifecycle.platforms(REPOSITORY_ROOT)
    assert lifecycle.check_declaration(path, "file_permissions", platforms, disruptive=False) == []


@pytest.mark.parametrize(
    ("directory", "config", "message"),
    [
        ("vagrant-ubuntu", "---\nplatforms:\n  - image: ubuntu\n", "a scenario name must start"),
        ("libvirt-empty", "---\nplatforms: []\n", "the scenario has no platforms"),
        ("libvirt-list", "---\n[]\n", "the scenario has no platforms"),
        ("libvirt-debian", "---\nplatforms:\n  - image: debian\n", "every platform needs"),
        ("libvirt-scalar", "---\nplatforms:\n  - ubuntu\n", "every platform needs"),
    ],
)
def test_an_invalid_scenario_stops_the_check(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    directory: str,
    config: str,
    message: str,
) -> None:
    root = make_root(tmp_path, {"file_permissions": VALID})
    scenario = root / lifecycle.MOLECULE / directory
    scenario.mkdir()
    (scenario / "molecule.yml").write_text(config, encoding="utf-8")
    assert lifecycle.main(["--root", str(root)]) == 2
    assert message in capsys.readouterr().err
