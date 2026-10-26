from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ADRS = (
    REPOSITORY_ROOT / "docs/adr/0004-audited-process-execution.md",
    REPOSITORY_ROOT / "docs/adr/0011-control-toggles-and-cleanup.md",
)
CITATION = re.compile(r"in `(tools/lint/(?:check_repo_rules|repo_rules/[a-z_]+)\.py)`")
CONSTANT = re.compile(r"`([A-Z][A-Z0-9_]{2,})`")


def defined_constants(module: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.parse(module.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def cited_constants(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    flat = " ".join(text.split())
    for match in CITATION.finditer(flat):
        start = max(flat.rfind("(", 0, match.start()), flat.rfind(". ", 0, match.start()))
        found.extend(
            (name, match.group(1)) for name in CONSTANT.findall(flat[start : match.start()])
        )
    return found


@pytest.mark.parametrize("adr", ADRS, ids=[path.name for path in ADRS])
def test_every_guard_constant_is_cited_in_the_module_that_defines_it(adr: Path) -> None:
    citations = cited_constants(adr.read_text(encoding="utf-8"))
    assert citations
    wrong = [
        (name, module)
        for name, module in citations
        if name not in defined_constants(REPOSITORY_ROOT / module)
    ]
    assert wrong == []


def test_the_citations_named_by_frees_153_point_at_the_name_sets_module() -> None:
    cited = {
        name: module
        for adr in ADRS
        for name, module in cited_constants(adr.read_text(encoding="utf-8"))
    }
    names = "tools/lint/repo_rules/names.py"
    for constant in (
        "EXTRA_IMPORTS",
        "KNOWN_SUBMODULE_ATTRIBUTES",
        "RESERVED_ATTRIBUTES",
        "STDLIB_MODULE_NAMES",
        "FILE_IO_HELPER",
    ):
        assert cited[constant] == names, constant


def test_a_citation_of_the_entry_point_is_detected_as_wrong() -> None:
    text = "the allow-list (`EXTRA_IMPORTS` in `tools/lint/check_repo_rules.py`) applies"
    assert cited_constants(text) == [("EXTRA_IMPORTS", "tools/lint/check_repo_rules.py")]
    entry = REPOSITORY_ROOT / "tools/lint/check_repo_rules.py"
    assert "EXTRA_IMPORTS" not in defined_constants(entry)


def test_the_split_amendment_names_the_replaced_and_the_added_meta_test() -> None:
    text = " ".join(ADRS[0].read_text(encoding="utf-8").split())
    assert "every guard test passes unchanged" not in text
    assert "except one meta-test" in text
    assert "replaced by `test_no_module_exceeds_the_module_line_limit`" in text
    assert "added, `test_the_repository_guard_is_a_package_of_small_modules`" in text
