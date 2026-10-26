"""Generate the standard library name sets of the repository guard.

``STDLIB_MODULE_NAMES`` and ``KNOWN_SUBMODULE_ATTRIBUTES`` in
``tools/lint/repo_rules/names.py`` are checked-in constants: the union over every
Python version in ``SNAPSHOT_VERSIONS``, because plugins run on Python 3.9 to 3.14
while the guard itself runs on the controller interpreter (ADR 0004). The data per
version is kept in ``tools/lint/name_sets.json``.

Regenerate both with ``make name-sets``. That target runs
``tools/lint/name_set_probe.py`` in a clean interpreter (``python -I -S``) of every
version, with the modules from ``--modules`` as arguments, and passes the probe
outputs to this script, which updates the snapshots of the probed versions and
rewrites the two constants in the guard source. ``--check`` reports instead of
writing and exits with status 1 when anything would change.

The probed modules are the allow-listed imports of the guard, each parent package
of a dotted allow-listed import (``import collections.abc`` binds
``collections``, so the attributes of ``collections`` are reachable), and the
per-file extra imports. The parents of the extra imports are left out on
purpose: their components (``parsers``, ``expat``) are reserved for the file that
owns the entry, and listing them as shared submodule attributes would lift that
reservation.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, cast

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

LINT_DIRECTORY: Final[Path] = Path(__file__).resolve().parent
PROBE_SCRIPT: Final[Path] = LINT_DIRECTORY / "name_set_probe.py"
SNAPSHOT_FILE: Final[Path] = LINT_DIRECTORY / "name_sets.json"
GUARD_FILE: Final[Path] = LINT_DIRECTORY / "repo_rules" / "names.py"
SNAPSHOT_VERSIONS: Final[tuple[str, ...]] = ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15")
STDLIB_CONSTANT: Final[str] = "STDLIB_MODULE_NAMES"
ATTRIBUTE_CONSTANT: Final[str] = "KNOWN_SUBMODULE_ATTRIBUTES"
CONSTANT_TYPE: Final[str] = "Final[frozenset[str]]"
INDENT: Final[str] = "    "
WRAP_WIDTH: Final[int] = 93
PROBE_KEYS: Final[frozenset[str]] = frozenset(
    {"python", "version", "modules", "stdlib_module_names", "submodule_attributes"}
)
SNAPSHOT_KEYS: Final[frozenset[str]] = PROBE_KEYS - {"version"}


class NameSetError(ValueError):
    """Raised when a probe output, the snapshot file or the guard source is invalid."""


def _fail(message: str) -> NoReturn:
    raise NameSetError(message)


@dataclass(frozen=True, slots=True)
class Snapshot:
    """The name sets of one Python version, as the probe reported them."""

    python: str
    modules: tuple[str, ...]
    stdlib_module_names: frozenset[str]
    submodule_attributes: frozenset[str]

    def as_json(self) -> dict[str, object]:
        """Return the snapshot as a JSON-ready mapping with sorted lists."""
        return {
            "python": self.python,
            "modules": list(self.modules),
            "stdlib_module_names": sorted(self.stdlib_module_names),
            "submodule_attributes": sorted(self.submodule_attributes),
        }


def _parents(name: str) -> Iterable[str]:
    """Yield every proper parent package of the dotted module ``name``."""
    parts = name.split(".")
    for end in range(1, len(parts)):
        yield ".".join(parts[:end])


def probe_modules() -> tuple[str, ...]:
    """Return the sorted modules whose attributes the probe must read."""
    allowed = set(rules.ALLOWED_IMPORTS)
    allowed.update(parent for name in rules.ALLOWED_IMPORTS for parent in _parents(name))
    allowed.update(name for names in rules.EXTRA_IMPORTS.values() for name in names)
    return tuple(sorted(allowed))


def _strings(value: object, field: str) -> tuple[str, ...]:
    """Return ``value`` as a tuple of strings or fail naming ``field``."""
    if not isinstance(value, list):
        _fail(f"{field} must be a list of strings")
    items = cast("list[object]", value)
    if not all(isinstance(item, str) for item in items):
        _fail(f"{field} must be a list of strings")
    return tuple(cast("list[str]", items))


def _text(value: object, field: str) -> str:
    """Return ``value`` as a non-empty string or fail naming ``field``."""
    if not isinstance(value, str) or not value:
        _fail(f"{field} must be a non-empty string")
    return value


def _snapshot(
    data: object, keys: frozenset[str], where: str
) -> tuple[Mapping[str, object], Snapshot]:
    """Validate the mapping ``data`` with exactly ``keys`` and build a snapshot from it."""
    if not isinstance(data, dict):
        _fail(f"{where} must be a JSON object")
    fields = cast("dict[str, object]", data)
    if frozenset(fields) != keys:
        _fail(f"{where} must have exactly the keys {sorted(keys)}")
    snapshot = Snapshot(
        python=_text(fields["python"], f"{where}: python"),
        modules=_strings(fields["modules"], f"{where}: modules"),
        stdlib_module_names=frozenset(
            _strings(fields["stdlib_module_names"], f"{where}: stdlib_module_names")
        ),
        submodule_attributes=frozenset(
            _strings(fields["submodule_attributes"], f"{where}: submodule_attributes")
        ),
    )
    return fields, snapshot


def parse_probe(text: str) -> tuple[str, Snapshot]:
    """Return the ``major.minor`` version and the snapshot of one probe output."""
    try:
        data: object = json.loads(text)
    except json.JSONDecodeError as error:
        _fail(f"the probe output is not JSON: {error}")
    fields, snapshot = _snapshot(data, PROBE_KEYS, "the probe output")
    version = _text(fields["version"], "the probe output: version")
    if version not in SNAPSHOT_VERSIONS:
        _fail(f"Python {version} is not one of {', '.join(SNAPSHOT_VERSIONS)}")
    if not snapshot.python.startswith(f"{version}."):
        _fail(f"the probe output names Python {snapshot.python} for version {version}")
    return version, snapshot


def load_snapshots(path: Path) -> dict[str, Snapshot]:
    """Read the snapshot file; a missing file holds no snapshots."""
    if not path.exists():
        return {}
    try:
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        _fail(f"{path} is not JSON: {error}")
    if not isinstance(data, dict):
        _fail(f"{path} must be a JSON object")
    entries = cast("dict[str, object]", data)
    snapshots: dict[str, Snapshot] = {}
    for version, entry in entries.items():
        if version not in SNAPSHOT_VERSIONS:
            _fail(f"{path}: Python {version} is not one of {', '.join(SNAPSHOT_VERSIONS)}")
        snapshots[version] = _snapshot(entry, SNAPSHOT_KEYS, f"{path}: {version}")[1]
    return snapshots


def dump_snapshots(snapshots: Mapping[str, Snapshot]) -> str:
    """Render the snapshots as the canonical JSON text of the snapshot file."""
    ordered = {
        version: snapshots[version].as_json()
        for version in SNAPSHOT_VERSIONS
        if version in snapshots
    }
    return json.dumps(ordered, indent=2) + "\n"


def union(snapshots: Mapping[str, Snapshot]) -> tuple[frozenset[str], frozenset[str]]:
    """Return the union of the module names and of the submodule attributes."""
    names: set[str] = set()
    attributes: set[str] = set()
    for snapshot in snapshots.values():
        names.update(snapshot.stdlib_module_names)
        attributes.update(snapshot.submodule_attributes)
    return frozenset(names), frozenset(attributes)


def render_constant(name: str, words: Iterable[str]) -> str:
    """Return the guard source line block that assigns ``words`` to ``name``."""
    lines = textwrap.wrap(
        " ".join(sorted(words)), width=WRAP_WIDTH, break_long_words=False, break_on_hyphens=False
    )
    body = [f'{INDENT}"{line} "' for line in lines[:-1]]
    body.extend(f'{INDENT}"{line}"' for line in lines[-1:])
    return "\n".join([f"{name}: {CONSTANT_TYPE} = _words(", *body, ")"])


def _constant_span(tree: ast.Module, name: str) -> tuple[int, int]:
    """Return the first and last line of the module-level assignment of ``name``."""
    spans = [
        (node.lineno, node.end_lineno or node.lineno)
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == name
    ]
    if len(spans) != 1:
        _fail(f"the guard source must assign {name} exactly once at module level")
    return spans[0]


def replace_constants(source: str, names: Iterable[str], attributes: Iterable[str]) -> str:
    """Return ``source`` with both name-set constants replaced by rendered values."""
    tree = ast.parse(source)
    lines = source.splitlines()
    replacements = sorted(
        (
            (_constant_span(tree, STDLIB_CONSTANT), render_constant(STDLIB_CONSTANT, names)),
            (
                _constant_span(tree, ATTRIBUTE_CONSTANT),
                render_constant(ATTRIBUTE_CONSTANT, attributes),
            ),
        ),
        reverse=True,
    )
    for (first, last), text in replacements:
        lines[first - 1 : last] = text.splitlines()
    return "\n".join(lines) + "\n"


def _version_key(version: str) -> int:
    return SNAPSHOT_VERSIONS.index(version)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probes", nargs="*", type=Path, help="Probe output files to merge.")
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT_FILE, help="Snapshot file.")
    parser.add_argument("--guard", type=Path, default=GUARD_FILE, help="Guard source file.")
    parser.add_argument(
        "--modules", action="store_true", help="Print the modules to probe and exit."
    )
    parser.add_argument("--check", action="store_true", help="Report instead of writing.")
    return parser


def _merge(snapshots: dict[str, Snapshot], probes: Sequence[Path]) -> None:
    """Replace the snapshots of the versions in ``probes`` with the probed data."""
    expected = probe_modules()
    for path in probes:
        version, snapshot = parse_probe(path.read_text(encoding="utf-8"))
        if snapshot.modules != expected:
            _fail(f"{path} probed {list(snapshot.modules)}, expected {list(expected)}")
        snapshots[version] = snapshot


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    arguments = _parser().parse_args(argv)
    if arguments.modules:
        print("\n".join(probe_modules()))
        return 0
    snapshot_path = cast("Path", arguments.snapshot)
    guard_path = cast("Path", arguments.guard)
    try:
        snapshots = load_snapshots(snapshot_path)
        _merge(snapshots, cast("list[Path]", arguments.probes))
        if not snapshots:
            _fail(f"no snapshots: {snapshot_path} is missing and no probe output was given")
        names, attributes = union(snapshots)
        guard_source = guard_path.read_text(encoding="utf-8")
        new_guard = replace_constants(guard_source, names, attributes)
    except NameSetError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    old_snapshot = snapshot_path.read_text(encoding="utf-8") if snapshot_path.exists() else ""
    contents = {
        snapshot_path: (old_snapshot, dump_snapshots(snapshots)),
        guard_path: (guard_source, new_guard),
    }
    stale = [path for path, (old, new) in contents.items() if old != new]
    if arguments.check:
        for path in stale:
            print(f"out of date: {path}", file=sys.stderr)
        return 1 if stale else 0
    for path in stale:
        path.write_text(contents[path][1], encoding="utf-8")
    print(f"name sets up to date for Python {', '.join(sorted(snapshots, key=_version_key))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
