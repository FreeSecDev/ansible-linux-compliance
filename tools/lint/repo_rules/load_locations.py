"""Locations from which Ansible loads code, and what may live there (FREES-156).

Ansible adds the ``library``, ``module_utils``, ``doc_fragments`` and ``*_plugins``
subdirectories of every playbook directory and every role to its search paths, searches
``collections/ansible_collections`` next to every playbook and ``plugins/`` below
``ANSIBLE_HOME``, and runs a module through its shebang, as a binary or through the shell
unless it is a new-style Python module. Only ``plugins/`` at the repository root may hold
the collection's code, as Python source, and the deny-by-default rules apply to it (ADR 0004).
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from tools.lint.repo_rules.common import PLUGINS_DIRECTORY, Violation

if TYPE_CHECKING:
    from collections.abc import Mapping

LOAD_DIRECTORY_NAMES: Final[frozenset[str]] = frozenset(
    {
        "library",
        "module_utils",
        "doc_fragments",
        "collections",
        "ansible_collections",
        PLUGINS_DIRECTORY,
    }
)
PLUGIN_DIRECTORY_SUFFIX: Final[str] = "_plugins"
MODULE_DIRECTORY: Final[Path] = Path(PLUGINS_DIRECTORY, "modules")
NON_LOADING_DIRECTORIES: Final[frozenset[Path]] = frozenset(
    {
        Path("tests/unit/plugins"),
        Path("tests/unit/plugins/module_utils"),
        Path("typings/ansible/module_utils"),
    }
)
PYTHON_ONLY_TREES: Final[frozenset[Path]] = frozenset({Path("tests/unit"), Path("typings")})
PYTHON_ONLY_SUFFIXES: Final[frozenset[str]] = frozenset({".py", ".pyi"})
EXECUTABLE_ALLOW_LIST: Final[frozenset[tuple[str, str]]] = frozenset({("tools", ".sh")})
SYMLINK_ALLOW_LIST: Final[frozenset[Path]] = frozenset(
    {Path(".claude/skills"), Path("tests/playbooks/fixtures/remediate/link-to-target")}
)
GIT_EXECUTABLE_MODE: Final[str] = "100755"
GIT_SYMLINK_MODE: Final[str] = "120000"
PYTHON_SHEBANGS: Final[frozenset[str]] = frozenset(
    {"#!/usr/bin/python", "#!/usr/bin/python3", "#!/usr/bin/env python", "#!/usr/bin/env python3"}
)
NEW_STYLE_MODULE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?:from +\.{2,} *module_utils.* +import |"
    rb"from +ansible_collections\.[^.]+\.[^.]+\.plugins\.module_utils.* +import |"
    rb"import +ansible_collections\.[^.]+\.[^.]+\.plugins\.module_utils.*|"
    rb"from +ansible\.module_utils.* +import |"
    rb"import +ansible\.module_utils\.)"
)
TEXT_BYTES: Final[bytes] = bytes(
    sorted({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
)


def repository_path(path: Path, root: Path) -> Path | None:
    """Return ``path`` relative to ``root`` without following a final symbolic link."""
    try:
        return (path.parent.resolve() / path.name).relative_to(root.resolve())
    except ValueError:
        return None


def folded(path: Path) -> Path:
    """Return ``path`` with every component case-folded.

    Ansible finds a load directory with ``os.path.isdir``, which ignores case on the
    default macOS and Windows filesystems, so ``Library`` is ``library`` there (FREES-156).
    """
    return Path(*(part.casefold() for part in path.parts))


def is_load_directory_name(name: str) -> bool:
    """Return whether Ansible loads code from a directory called ``name``, in any case."""
    name = name.casefold()
    return name in LOAD_DIRECTORY_NAMES or name.endswith(PLUGIN_DIRECTORY_SUFFIX)


def index_modes(listing: bytes) -> Mapping[Path, str]:
    """Return the Git index mode of every path in a ``git ls-files -s -z`` listing."""
    modes: dict[Path, str] = {}
    for record in listing.split(b"\0"):
        header, separator, name = record.partition(b"\t")
        if separator:
            mode = header.decode("ascii", errors="replace").split(" ", 1)[0]
            modes[Path(name.decode("utf-8", errors="surrogateescape"))] = mode
    return MappingProxyType(modes)


def load_location(relative: Path, configured: frozenset[Path] = frozenset()) -> Path | None:
    """Return the load directory that holds the repository file ``relative``, if any.

    Names are compared case-folded. Nothing below the repository's own ``plugins/``, spelt
    exactly so, and none of the ``NON_LOADING_DIRECTORIES``, matched exactly, is a load
    directory by its name; ``configured`` holds the directories that an ``ansible.cfg``
    names, which are load directories wherever they are and in any case.
    """
    parts = relative.parts
    collection_plugins = parts[:1] == (PLUGINS_DIRECTORY,)
    configured_folded = {folded(directory) for directory in configured}
    for index in range(len(parts) - 1):
        directory = Path(*parts[: index + 1])
        if folded(directory) in configured_folded:
            return directory
        if collection_plugins or directory in NON_LOADING_DIRECTORIES:
            continue
        if is_load_directory_name(parts[index]):
            return directory
    return None


def _is_allowed_executable(relative: Path) -> bool:
    return any(
        relative.parts[:1] == (directory,) and relative.suffix == suffix
        for directory, suffix in EXECUTABLE_ALLOW_LIST
    )


def _python_only_tree(relative: Path) -> Path | None:
    parents = folded(relative).parents
    return next((tree for tree in PYTHON_ONLY_TREES if tree in parents), None)


def _is_link(mode: int, index_mode: str | None) -> bool:
    return stat.S_ISLNK(mode) or index_mode == GIT_SYMLINK_MODE


def _is_executable(mode: int, index_mode: str | None) -> bool:
    return (stat.S_ISREG(mode) and bool(mode & 0o111)) or index_mode == GIT_EXECUTABLE_MODE


def non_ascii_findings(path: Path, relative: Path) -> list[Violation]:
    """Refuse a repository path with a non-ASCII component (FREES-159).

    Python's ``casefold`` and the filesystems disagree outside ASCII: NTFS upper-cases the
    dotless i (U+0131) to ``I``, so ``l\u0131brary`` is ``library`` there but not to
    ``folded``. With ASCII-only names every filesystem and ``casefold`` agree, so
    ``folded`` is exact.
    """
    if all(part.isascii() for part in relative.parts):
        return []
    return [
        Violation(
            path,
            1,
            "path with a non-ASCII component is not allowed: case-insensitive filesystems "
            "fold such names differently (NTFS maps U+0131 to 'I'), so the guard cannot tell "
            "whether Ansible loads code from it",
        )
    ]


def location_findings(
    path: Path,
    relative: Path,
    configured: frozenset[Path] = frozenset(),
    index_mode: str | None = None,
) -> list[Violation]:
    """Apply the rules that depend on where a file is and what kind of file it is.

    A symbolic link outside ``SYMLINK_ALLOW_LIST`` is refused, because Ansible and the
    guard would follow it to a file that no rule checked at this path. A regular file with
    an executable bit is refused outside ``EXECUTABLE_ALLOW_LIST``. A file in a load
    directory is refused, a file under ``plugins/`` must be Python source, and the
    ``PYTHON_ONLY_TREES`` may hold only Python source and stubs. ``index_mode`` is the
    mode of the file in the Git index, so a link or an executable bit that only the index
    records is refused as well.
    """
    try:
        mode = path.lstat().st_mode
    except OSError:
        return []
    violations = non_ascii_findings(path, relative)
    if _is_link(mode, index_mode):
        if relative in SYMLINK_ALLOW_LIST:
            return violations
        return [
            *violations,
            Violation(
                path,
                1,
                "symbolic link is not allowed: Ansible and the guard would follow it to a "
                "file that no rule checked at this path",
            ),
        ]
    if _is_executable(mode, index_mode) and not _is_allowed_executable(relative):
        violations.append(
            Violation(
                path,
                1,
                "executable file is not allowed outside tools/**/*.sh: Ansible runs an "
                "executable module, inventory or vault password file directly",
            )
        )
    directory = load_location(relative, configured)
    if directory is not None:
        violations.append(
            Violation(
                path,
                1,
                f"file in the Ansible load location {directory.as_posix()}/ is not allowed: "
                "the collection's code belongs in plugins/ (ADR 0004)",
            )
        )
    if folded(relative).parts[:1] == (PLUGINS_DIRECTORY,) and relative.suffix != ".py":
        violations.append(
            Violation(
                path,
                1,
                f"only Python source (.py) may live under plugins/, not "
                f"{relative.suffix or 'a file without a suffix'}: Ansible runs a module of "
                "any type",
            )
        )
    tree = _python_only_tree(relative)
    if tree is not None and relative.suffix not in PYTHON_ONLY_SUFFIXES:
        violations.append(
            Violation(
                path,
                1,
                f"only Python source and stubs may live under {tree.as_posix()}/: any other "
                "file could make it an Ansible load location",
            )
        )
    return violations


def python_findings(path: Path, relative: Path | None, data: bytes) -> list[Violation]:
    """Reject a non-Python shebang anywhere, and a module that Ansible would not run as Python.

    Ansible runs a file in ``plugins/modules`` as a new-style Python module only if it
    contains no control byte and imports ``module_utils`` the way ``NEW_STYLE_MODULE``
    matches; any other module runs as a binary, through its shebang or through the shell.
    """
    violations: list[Violation] = []
    first = data.split(b"\n", 1)[0].rstrip(b"\r").decode("utf-8", errors="replace")
    if first.startswith("#!") and first.strip() not in PYTHON_SHEBANGS:
        violations.append(
            Violation(
                path,
                1,
                f"shebang {first.strip()!r} is not allowed: a Python file may only name a "
                "Python interpreter",
            )
        )
    if relative is None or MODULE_DIRECTORY not in folded(relative).parents:
        return violations
    if data.translate(None, TEXT_BYTES):
        violations.append(
            Violation(
                path, 1, "module contains a control byte: Ansible would run it as a binary module"
            )
        )
    if NEW_STYLE_MODULE.search(data) is None:
        violations.append(
            Violation(
                path,
                1,
                "module must import ansible.module_utils or the collection's module_utils: "
                "Ansible runs any other module through its shebang or the shell",
            )
        )
    return violations
