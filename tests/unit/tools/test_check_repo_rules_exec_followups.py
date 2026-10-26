from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

OS_SYSTEM = '"""Helpers."""\nimport os\nos.system("true")\n'
NON_ASCII = "path with a non-ASCII component is not allowed"
DOTLESS_I = chr(0x0131)
DOTTED_CAPITAL_I = chr(0x0130)
LONG_S = chr(0x017F)
KELVIN = chr(0x212A)
E_ACUTE = chr(0x00E9)


def write(root: Path, name: str, text: str) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def messages(root: Path, *targets: Path) -> list[str]:
    return [violation.message for violation in rules.check_paths(targets, root)]


@pytest.mark.parametrize(
    "name",
    [
        f"roles/remediate/l{DOTLESS_I}brary/sneaky.py",
        f"roles/remediate/L{DOTTED_CAPITAL_I}BRARY/sneaky.py",
        f"playbooks/filter_plugin{LONG_S}/sneaky.py",
        f"roles/r/{KELVIN}ibrary/sneaky.py",
        f"roles/r/tasks/caf{E_ACUTE}.yml",
    ],
)
def test_a_non_ascii_path_component_is_refused(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, OS_SYSTEM))
    assert any(NON_ASCII in message for message in found), found


def test_the_dotless_i_is_not_folded_to_a_load_directory_by_casefold() -> None:
    assert f"l{DOTLESS_I}brary".casefold() != "library"
    assert f"l{DOTLESS_I}brary".upper() == "LIBRARY"


def test_a_non_ascii_symbolic_link_is_refused_as_both(tmp_path: Path) -> None:
    (tmp_path / "target.yml").write_text("---\n[]\n", encoding="utf-8")
    link = tmp_path / f"l{DOTLESS_I}nk.yml"
    link.symlink_to("target.yml")
    found = messages(tmp_path, link)
    assert any(NON_ASCII in message for message in found)
    assert any("symbolic link is not allowed" in message for message in found)


def test_a_missing_index_modes_listing_is_a_guard_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = write(tmp_path, "x.yml", "---\n[]\n")
    missing = tmp_path / "build" / "lint-repo-index-modes"
    assert rules.main(["--index-modes", str(missing), str(target)]) == rules.USAGE_ERROR == 2
    error = capsys.readouterr().err
    assert f"error: cannot read the --index-modes listing {missing}: No such file or directory" in (
        error
    )
    assert "Traceback" not in error


def test_an_unreadable_index_modes_listing_is_a_guard_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = write(tmp_path, "x.yml", "---\n[]\n")
    assert rules.main(["--index-modes", str(tmp_path), str(target)]) == 2
    assert "error: cannot read the --index-modes listing" in capsys.readouterr().err


def test_a_readable_index_modes_listing_is_used(tmp_path: Path) -> None:
    listing = tmp_path / "modes"
    listing.write_bytes(b"100644 0000000000000000000000000000000000000000 0\tx.yml\0")
    target = write(tmp_path, "x.yml", "---\n[]\n")
    assert rules.main(["--index-modes", str(listing), str(target)]) == 0
