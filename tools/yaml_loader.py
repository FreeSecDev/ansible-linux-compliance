"""Parse repository YAML with PyYAML's safe loader, the libyaml one when PyYAML has it (FREES-206).

The generators and checkers below ``tools/roles`` parse large files such as the remediation
catalogue, and the libyaml loader is much faster than the pure Python one. PyYAML defines
``yaml.CSafeLoader`` only when it was built with libyaml, so a direct reference raises an
``AttributeError`` that a caller's ``except yaml.YAMLError`` does not catch. :func:`safe_load`
falls back to ``yaml.SafeLoader``; both loaders construct the same safe types, and both raise
``yaml.YAMLError`` for text that is not valid YAML.
"""

from __future__ import annotations

from typing import cast

import yaml


def safe_load(text: str) -> object:
    """Return the data of the YAML ``text``, parsed with the safe loader.

    Raises:
        yaml.YAMLError: When ``text`` is not valid YAML.
    """
    if yaml.__with_libyaml__:
        return cast("object", yaml.load(text, Loader=yaml.CSafeLoader))
    return cast("object", yaml.safe_load(text))
