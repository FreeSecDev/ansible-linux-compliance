from __future__ import annotations

import importlib.machinery
from pathlib import Path

import pytest
import yaml

from tools.lint import check_repo_rules as rules

COMPILED_NAMES = (
    "plugins/module_utils/compliance/process.so",
    "plugins/module_utils/compliance/process.cpython-312-x86_64-linux-gnu.so",
    "plugins/module_utils/compliance/process.abi3.so",
    "plugins/module_utils/compliance/process.abi3t-x86_64-linux-gnu.so",
    "plugins/modules/scan.cpython-314-darwin.so",
    "plugins/modules/scan.pyd",
    "plugins/modules/scan.cp312-win_amd64.pyd",
    "plugins/filter/remediation_plan.pyc",
    "plugins/filter/__pycache__/remediation_plan.cpython-312.pyc",
    "plugins/filter/remediation_plan.cpython-312.opt-1.pyc",
    "plugins/filter/remediation_plan.pyo",
    "plugins/filter/remediation_plan.cpython-313-iphoneos.fwork",
    "plugins/filter/REMEDIATION_PLAN.SO",
    "plugins/filter/remediation_plan.PyD",
    "tools/lint/repo_rules/seams.so",
    "tests/unit/tools/helper.pyc",
    "content/blob.so",
)


@pytest.mark.parametrize("name", COMPILED_NAMES)
def test_a_compiled_module_file_is_refused_anywhere(tmp_path: Path, name: str) -> None:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"\x7fELF")
    violations = rules.check_file(target, tmp_path)
    message = (
        f"compiled module file ({target.suffix.lower()}) is not allowed: the import system "
        "loads it before or instead of the Python source"
    )
    assert [(violation.line, violation.message) for violation in violations] == [(1, message)]


def test_a_compiled_module_file_is_refused_without_being_read(tmp_path: Path) -> None:
    target = tmp_path / "plugins" / "modules" / "scan.so"
    target.mkdir(parents=True)
    assert len(rules.check_paths([target], tmp_path)) == 1


def test_the_compiled_suffixes_are_pinned() -> None:
    assert frozenset({".so", ".pyd", ".pyc", ".pyo", ".fwork"}) == rules.COMPILED_MODULE_SUFFIXES


def test_every_suffix_that_the_import_system_loads_without_source_is_refused() -> None:
    loaded = [
        *importlib.machinery.EXTENSION_SUFFIXES,
        *(suffix.replace(".so", ".fwork") for suffix in importlib.machinery.EXTENSION_SUFFIXES),
        *importlib.machinery.BYTECODE_SUFFIXES,
        ".cp312-win_amd64.pyd",
        ".pyd",
    ]
    assert {Path(f"module{suffix}").suffix for suffix in loaded} <= rules.COMPILED_MODULE_SUFFIXES
    assert set(importlib.machinery.SOURCE_SUFFIXES).isdisjoint(rules.COMPILED_MODULE_SUFFIXES)


def test_make_lint_repo_passes_every_compiled_suffix_to_the_guard() -> None:
    makefile = (rules.REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "COMPILED_MODULE_PATHSPECS" not in makefile
    lint_repo = makefile.split("\nlint-repo:", 1)[1].split("\n\n", 1)[0]
    assert "\t$(TRACKED) | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py" in lint_repo


def test_the_pre_commit_hook_passes_every_compiled_suffix_to_the_guard() -> None:
    config = yaml.safe_load(
        (rules.REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    hook = next(
        hook for repo in config["repos"] for hook in repo["hooks"] if hook["id"] == "repo-rules"
    )
    assert hook["types_or"] == ["file", "symlink"]
    assert "files" not in hook
    assert "exclude" not in hook
