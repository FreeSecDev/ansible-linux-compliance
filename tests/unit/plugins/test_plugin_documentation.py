"""Every plugin's DOCUMENTATION, EXAMPLES and RETURN parse as YAML, as ansible-test sanity needs."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

PLUGINS = Path(__file__).resolve().parents[3] / "plugins"
BLOCKS = ("DOCUMENTATION", "EXAMPLES", "RETURN")


def _block(node: ast.stmt) -> tuple[str, str] | None:
    """Return the name and the text of a documentation block assignment, or ``None``."""
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id not in BLOCKS:
        return None
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
        return None
    return target.id, node.value.value


def _blocks() -> list[tuple[str, str, str]]:
    """Return the path, the name and the text of every documentation block of the plugins."""
    found: list[tuple[str, str, str]] = []
    for path in sorted(PLUGINS.rglob("*.py")):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            block = _block(node)
            if block is not None:
                found.append((str(path.relative_to(PLUGINS.parent)), *block))
    return found


def test_the_plugins_have_documentation_blocks() -> None:
    names = {(block[0], block[1]) for block in _blocks()}
    assert ("plugins/filter/pam_service_files.py", "DOCUMENTATION") in names
    assert ("plugins/filter/pam_conf.py", "DOCUMENTATION") in names
    assert ("plugins/filter/pwquality_decide.py", "DOCUMENTATION") in names


@pytest.mark.parametrize(
    ("path", "name", "text"), _blocks(), ids=[f"{block[0]}:{block[1]}" for block in _blocks()]
)
def test_every_documentation_block_parses_as_yaml(path: str, name: str, text: str) -> None:
    parsed = yaml.safe_load(text)
    assert parsed is not None, f"{path} {name} is empty"
    if name == "DOCUMENTATION":
        assert isinstance(parsed, dict), f"{path} {name} is not a mapping"
