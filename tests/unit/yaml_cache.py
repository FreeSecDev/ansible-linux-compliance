"""Parse a repository YAML file once per test session (FREES-199).

Many tests read the remediation catalogue, ``roles/remediate/vars/rules.yml``, and the pure
Python parser took most of their time. :func:`load` parses a file once per test process with
``tools.yaml_loader``, which uses libyaml when PyYAML has it, and keys the result by the
resolved path and the SHA-256 of the content: a changed file, or a copy of it in a temporary
root, is parsed again. Every call returns a deep copy, so a test that changes the data cannot
change what another test reads.
"""

from __future__ import annotations

import copy
import hashlib
from typing import TYPE_CHECKING

from tools import yaml_loader

if TYPE_CHECKING:
    from pathlib import Path

_PARSED: dict[tuple[str, str], object] = {}


def load(path: Path) -> object:
    """Return the data of the YAML file ``path``, parsed once per path and content."""
    text = path.read_text(encoding="utf-8")
    key = (str(path.resolve()), hashlib.sha256(text.encode("utf-8")).hexdigest())
    if key not in _PARSED:
        _PARSED[key] = yaml_loader.safe_load(text)
    return copy.deepcopy(_PARSED[key])


def parsed_paths() -> set[str]:
    """Return the resolved paths that this process has parsed, for the tests of the cache."""
    return {path for path, _ in _PARSED}
