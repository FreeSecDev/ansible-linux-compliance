"""Check that each role's ``defaults/main.yml`` matches its ``meta/argument_specs.yml``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Sequence

ENTRY_POINT: Final[str] = "main"
TYPE_CLASSES: Final[dict[str, type]] = {
    "str": str,
    "path": str,
    "bool": bool,
    "int": int,
    "float": float,
    "list": list,
    "dict": dict,
}


def load_mapping(path: Path) -> dict[str, object] | None:
    """Return the YAML mapping in ``path``, or ``None`` when it is missing or not a mapping."""
    if not path.is_file():
        return None
    loaded = cast("object", yaml.safe_load(path.read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        return None
    return cast("dict[str, object]", loaded)


def matches_type(value: object, type_name: str) -> bool:
    """Return whether ``value`` is acceptable for the argument spec type ``type_name``."""
    expected = TYPE_CLASSES[type_name]
    if isinstance(value, bool) and expected is not bool:
        return False
    return isinstance(value, expected)


def check_option(role: str, name: str, spec: object, default: object) -> list[str]:
    """Return findings for one option, given its spec and the value from the defaults file."""
    where = f"{role}: {name}"
    if not name.startswith(f"linux_compliance_{role}_"):
        return [f"{where}: variable must be prefixed linux_compliance_{role}_"]
    if not isinstance(spec, dict):
        return [f"{where}: option spec must be a mapping"]
    option = cast("dict[str, object]", spec)
    findings: list[str] = []
    type_name = option.get("type")
    if not isinstance(type_name, str) or type_name not in TYPE_CLASSES:
        return [f"{where}: type must be one of {', '.join(sorted(TYPE_CLASSES))}"]
    if not option.get("description"):
        findings.append(f"{where}: description is missing")
    if "default" not in option:
        findings.append(f"{where}: default is missing from the argument spec")
    elif option["default"] != default or type(option["default"]) is not type(default):
        findings.append(f"{where}: defaults/main.yml does not equal the argument spec default")
    if not matches_type(default, type_name):
        findings.append(f"{where}: default does not have the declared type {type_name}")
    if type_name == "list" and not option.get("elements"):
        findings.append(f"{where}: list options must declare elements")
    return findings


def check_role(role_dir: Path) -> list[str]:
    """Return findings for the role in ``role_dir``."""
    role = role_dir.name
    specs = load_mapping(role_dir / "meta" / "argument_specs.yml")
    if specs is None:
        return [f"{role}: meta/argument_specs.yml is missing or not a mapping"]
    entry_points = specs.get("argument_specs")
    if not isinstance(entry_points, dict) or ENTRY_POINT not in entry_points:
        return [f"{role}: argument_specs must define the {ENTRY_POINT} entry point"]
    entry = cast("dict[str, object]", entry_points)[ENTRY_POINT]
    options = cast("dict[str, object]", entry).get("options") if isinstance(entry, dict) else None
    if not isinstance(options, dict):
        return [f"{role}: the {ENTRY_POINT} entry point must define options"]
    spec_options = cast("dict[str, object]", options)
    defaults = load_mapping(role_dir / "defaults" / "main.yml")
    if defaults is None:
        return [f"{role}: defaults/main.yml is missing or not a mapping"]
    findings = [
        f"{role}: {name}: defined in defaults/main.yml but not in the argument spec"
        for name in sorted(set(defaults) - set(spec_options))
    ]
    for name in sorted(spec_options):
        if name not in defaults:
            findings.append(f"{role}: {name}: missing from defaults/main.yml")
        else:
            findings.extend(check_option(role, name, spec_options[name], defaults[name]))
    return findings


def check_roles(roles_dir: Path) -> list[str]:
    """Return findings for every role directory below ``roles_dir``."""
    return [
        finding
        for role_dir in sorted(roles_dir.iterdir())
        if role_dir.is_dir()
        for finding in check_role(role_dir)
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roles_dir", nargs="?", type=Path, default=Path("roles"))
    arguments = parser.parse_args(argv)
    findings = check_roles(arguments.roles_dir)
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"{len(findings)} role specification problem(s)", file=sys.stderr)
        return 1
    print(f"role argument specs match defaults in {arguments.roles_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
