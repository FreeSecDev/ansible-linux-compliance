"""Enforce repository-wide source rules on the files passed as arguments.

Rules:

* No compiled module file (``.so``, ``.pyd``, ``.pyc``, ``.pyo``, ``.fwork``, in any
  case) is tracked: the import system loads an extension module or bytecode before, or
  instead of, a ``.py`` source of the same name (FREES-153).
* Only the repository's ``plugins/`` may hold code that Ansible loads (FREES-156). A file
  in a ``library``, ``module_utils``, ``doc_fragments``, ``*_plugins``, ``collections``,
  ``ansible_collections`` or ``plugins`` directory anywhere else, or in a directory that an
  ``ansible.cfg`` names as a module or plugin path, is refused, and Python there also gets the
  deny-by-default rules below. The mirrored ``tests/unit/plugins`` and
  ``typings/ansible/module_utils`` are not load locations; ``tests/unit/`` and ``typings/``
  hold only Python source and stubs. Every file under ``plugins/`` ends in ``.py``, a module
  in ``plugins/modules`` matches Ansible's new-style Python pattern and has no control byte,
  a Python shebang names Python, a symbolic link or an executable file outside its
  allow-list is refused, and ``ansible.cfg``, ``molecule.yml``, YAML keys, workflow values,
  makefiles and shell scripts may not set a search path for modules, plugins, roles or
  collections.
* Every YAML file starts with ``---`` followed by a newline.
* YAML files contain no comments, except a trailing ``# vX.Y.Z`` version
  annotation on a ``uses: owner/repo@<40-hex>`` or ``rev: <40-hex>`` line.
* YAML files contain no banned Ansible command-execution modules. A document
  whose root is a sequence is a playbook or task file: only the keys of its plays
  and tasks (followed through ``tasks``, ``pre_tasks``, ``post_tasks``,
  ``handlers``, ``block``, ``rescue`` and ``always`` at any depth, aliases and
  merge keys) and their ``action`` and ``local_action`` values are checked, so
  module parameters and ``vars`` data may contain the banned words. A templated
  module name in an action and a templated task key are denied, and included task
  files, playbooks and role entry points must be relative ``.yml`` or ``.yaml``
  paths without ``..`` that are not templated, except ``{{ role_path }}/tasks/``
  followed by a literal relative path. Role names
  of role includes and of the ``roles`` of a play must be plain or fully qualified
  names, not templates or paths (FREES-137). Any other document is checked for
  banned keys at any depth, and a ``redirect`` to a banned module is denied
  (FREES-128).
* Python files contain no comments, except a shebang on the first line.
* Python files under ``plugins/`` are checked deny-by-default: they import only
  allow-listed standard library modules, ``ansible.module_utils`` and this
  collection, never use ``os`` except as ``os.path``, never use ``exec``, ``eval``,
  ``compile`` or ``__import__``, never reference process, fork or ``run_command``
  attributes, never import or name ``subprocess``, ``pty``, ``posix``, ``sys`` or
  ``os`` as an imported name or attribute, never use ``vars``, ``globals``,
  ``locals``, ``__dict__`` or ``get_type_hints``, never pass ``shell=True``,
  ``use_unsafe_shell`` or the test-only ``owner_uid``, ``state_dir``, ``lock_timeout``,
  ``policies``, ``trusted_dirs``, ``runner``, ``clock``, ``limits`` and ``registry`` keywords,
  never use a ``**``
  dict splat in a call, never use the attribute ``__self__``, and
  only call ``getattr`` with a literal permitted name. The string-based reflection names
  ``builtins``, ``operator``, ``eval``, ``exec``, ``compile``, ``attrgetter``,
  ``methodcaller``, ``_evaluate`` and ``evaluate_forward_ref`` are banned as attributes, a
  module-level ``__getattr__`` is banned, so are the function internals ``__kwdefaults__``,
  ``__defaults__``, ``__code__``, ``__closure__`` and ``__globals__``, assigning to an
  attribute of an imported name (including ``setattr``) is banned, and underscore-prefixed
  attributes may only be read, called or assigned through ``self`` or ``cls`` inside a class
  (dunder reads such as ``__name__`` stay allowed; dunder assignment does not). Underscore-prefixed
  names may not be imported. Dunder attributes are denied by default: only reading ``__name__``
  is allowed, plus the single form
  ``object.__setattr__(self, "<literal>", value)`` in ``__post_init__``. Frame and code
  attributes and the ``types`` module (except ``MappingProxyType``) are banned on every
  object, and attributes named like standard library or collection modules are banned when the
  chain starts at a module name (``dataclasses.inspect``). Only ``super().__init__()`` and
  ``super().__post_init__()`` may call a dunder on ``super()``, and ``super`` and ``object``
  may never be rebound. A name bound to a module, and a submodule reached by attribute
  (``os.path``, ``json.decoder``, or ``from json import decoder``), may only appear as the base
  of an attribute access, and
  ``self`` and ``cls`` are exempt only as the never rebound first parameter of a method. This is
  static analysis, not a sandbox (ADR 0004).
  ``xml.parsers.expat`` may be imported (as ``from xml.parsers import expat``)
  only by ``plugins/module_utils/compliance/xmlsafe.py``, the shared hardened
  XML parser that every other plugin file parses through. The components of that
  dotted name that no allow-listed import provides (``parsers`` and ``expat``) are
  reserved for the same file: everywhere else they are banned as attribute names on
  any object, as literal ``getattr`` names, as ``match`` class pattern keywords and as
  imported names or import path components, so ``xmlsafe.expat.ParserCreate()`` and
  ``from .xmlsafe import expat`` fail. Only
  ``plugins/module_utils/compliance/process.py`` is exempt (ADR 0004).
  ``plugins/module_utils/compliance/fileio.py`` may additionally ``import`` ``os``, ``fcntl``,
  ``errno`` and ``time`` and use only the attributes listed in ``FILE_IO_ATTRIBUTES``, always as
  ``module.attribute``; it keeps every other rule. Only
  ``plugins/module_utils/compliance/ledger.py`` may import ``fileio`` or name it as an attribute
  or ``getattr`` literal (ADR 0011).
  A parameter named like a banned keyword (a test seam) must be keyword-only, and only the files
  in ``SEAM_OWNERS`` may define one. They may pass their own seams on unchanged, as ``name=name``
  from a keyword-only parameter of the enclosing function or as ``name=self._name`` in a class whose
  ``__init__`` takes the seam, and may assign ``self._name`` only directly in ``__init__``,
  never from a function nested in it (FREES-137, FREES-153).

Violations are printed as ``path:line: message`` and the exit status is 1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.lint.repo_rules.ansible_tasks import TASK_FILE_SUFFIXES, check_banned_modules
from tools.lint.repo_rules.common import (
    COMPILED_MODULE_SUFFIXES,
    PLUGINS_DIRECTORY,
    REPO_ROOT,
    Violation,
)
from tools.lint.repo_rules.isolation import check_process_isolation, is_process_scope
from tools.lint.repo_rules.names import (
    ALLOWED_IMPORTS,
    BANNED_KEYWORDS,
    BANNED_MODULE_ATTRIBUTES,
    COLLECTION_MODULE_ATTRIBUTES,
    DUNDER_READS,
    EXTRA_IMPORTS,
    FILE_IO_ATTRIBUTES,
    FILE_IO_HELPER,
    FILE_IO_IMPORTERS,
    KNOWN_SUBMODULE_ATTRIBUTES,
    PROCESS_HELPER,
    PROTECTED_NAMES,
    RESERVED_ATTRIBUTES,
    SEAM_OWNERS,
    SHARED_SUBMODULE_ATTRIBUTES,
    STDLIB_MODULE_ATTRIBUTES,
    STDLIB_MODULE_NAMES,
    SUBMODULE_ATTRIBUTES,
)
from tools.lint.repo_rules.repository import check_file, check_paths, check_python_comments
from tools.lint.repo_rules.yaml_text import (
    Comment,
    check_document_start,
    check_yaml_comments,
    is_allowed_annotation,
    scan_yaml_comments,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "ALLOWED_IMPORTS",
    "BANNED_KEYWORDS",
    "BANNED_MODULE_ATTRIBUTES",
    "COLLECTION_MODULE_ATTRIBUTES",
    "COMPILED_MODULE_SUFFIXES",
    "DUNDER_READS",
    "EXTRA_IMPORTS",
    "FILE_IO_ATTRIBUTES",
    "FILE_IO_HELPER",
    "FILE_IO_IMPORTERS",
    "KNOWN_SUBMODULE_ATTRIBUTES",
    "PLUGINS_DIRECTORY",
    "PROCESS_HELPER",
    "PROTECTED_NAMES",
    "REPO_ROOT",
    "RESERVED_ATTRIBUTES",
    "SEAM_OWNERS",
    "SHARED_SUBMODULE_ATTRIBUTES",
    "STDLIB_MODULE_ATTRIBUTES",
    "STDLIB_MODULE_NAMES",
    "SUBMODULE_ATTRIBUTES",
    "TASK_FILE_SUFFIXES",
    "Comment",
    "Violation",
    "check_banned_modules",
    "check_document_start",
    "check_file",
    "check_paths",
    "check_process_isolation",
    "check_python_comments",
    "check_yaml_comments",
    "is_allowed_annotation",
    "is_process_scope",
    "main",
    "scan_yaml_comments",
]


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Files to check.")
    arguments = parser.parse_args(argv)
    violations = check_paths(arguments.paths)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        print(f"{len(violations)} repository rule violation(s)", file=sys.stderr)
        return 1
    print(f"repository rules satisfied in {len(arguments.paths)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
