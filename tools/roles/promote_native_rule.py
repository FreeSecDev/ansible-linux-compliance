"""Promote one catalogued rule of a disruptive family to a native rule in a test copy of a role.

``make test-remediate-disruptive`` (FREES-153) runs the real remediate role in check mode
against a copy of the collection in ``build/``. The pinned catalogue has no native rule of a
disruptive family yet: every such rule is ``audit_only``, which the plan reports as
``not_implemented`` before the allow-list is consulted (ADR 0011). To show end to end that
the allow-list gates a disruptive rule, this tool moves one rule of the copy from the
``audit_only`` lists to the native rules, with its family, the disruptive flag of that
family, the derived toggle and the reversible ``recorded_state`` strategy. Everything else
of the copy stays as generated, so no task file of the family exists and the role must fail
closed if the rule is ever planned for apply.

The tool refuses a catalogue below the repository's own ``roles/`` directory, also through a
symbolic link, and a hard link to the repository catalogue, which it recognises by the device
and inode numbers (FREES-157). It also refuses a rule that is not an ``audit_only`` rule and a
family that is not disruptive, and the result must pass the same validation as the generated
catalogue.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import generate_toggles

if TYPE_CHECKING:
    from collections.abc import Sequence

GenerationError = generate_toggles.GenerationError
REPOSITORY_ROLES: Path = Path(__file__).resolve().parents[2] / "roles"
REPOSITORY_CATALOGUE: Path = REPOSITORY_ROLES / "remediate" / "vars" / "rules.yml"
NATIVE_STRATEGY: str = "recorded_state"


def promote(data: dict[str, object], rule_id: str) -> dict[str, object]:
    """Return ``data`` with ``rule_id`` moved from the ``audit_only`` lists to the native rules."""
    families = cast("list[dict[str, object]]", data[generate_toggles.FAMILIES_KEY])
    disruptive = {str(item["name"]): item["disruptive"] is True for item in families}
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    family = next((name for name, rules in audit_only.items() if rule_id in rules), None)
    if family is None:
        message = f"{rule_id} is not an audit_only rule of the catalogue"
        raise GenerationError(message)
    if not disruptive[family]:
        message = f"{rule_id} belongs to {family}, which is not a disruptive family"
        raise GenerationError(message)
    promoted = dict(data)
    promoted[generate_toggles.AUDIT_ONLY_KEY] = {
        name: [item for item in rules if item != rule_id] for name, rules in audit_only.items()
    }
    rules = cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY])
    promoted[generate_toggles.RULES_KEY] = [
        *rules,
        {
            "rule_id": rule_id,
            "family": family,
            "disruptive": True,
            "reversible": True,
            "revert_strategy": NATIVE_STRATEGY,
            "toggle": toggles.rule_toggle_name(rule_id),
            "runbook": None,
            "parameters": {},
        },
    ]
    return promoted


def _is_repository_file(catalogue: Path) -> bool:
    """Return whether ``catalogue`` is, links to or is a hard link of the repository catalogue."""
    if catalogue.resolve().is_relative_to(REPOSITORY_ROLES):
        return True
    target = catalogue.stat()
    repository = REPOSITORY_CATALOGUE.stat()
    return (target.st_dev, target.st_ino) == (repository.st_dev, repository.st_ino)


def rewrite(catalogue: Path, rule_id: str) -> None:
    """Promote ``rule_id`` in the catalogue file ``catalogue``, which must be a copy."""
    if _is_repository_file(catalogue):
        message = f"{catalogue} is the catalogue of the repository; promote only in a copy"
        raise GenerationError(message)
    data = cast("dict[str, object]", yaml.safe_load(catalogue.read_text(encoding="utf-8")))
    promoted = promote(data, rule_id)
    catalogue.write_text("---\n" + yaml.safe_dump(promoted, sort_keys=False), encoding="utf-8")
    generate_toggles.load_catalogue(catalogue)


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--rule", required=True)
    arguments = parser.parse_args(argv)
    catalogue = cast("Path", arguments.catalogue)
    rule_id = cast("str", arguments.rule)
    try:
        rewrite(catalogue, rule_id)
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"promoted {rule_id} to a native rule in {catalogue}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
