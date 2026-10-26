"""Print the standard library name sets of the running interpreter as JSON.

The repository guard (``tools/lint/check_repo_rules.py``) bans attribute names that
equal a standard library module (``STDLIB_MODULE_NAMES``) or a module-typed
attribute of an allow-listed module (``KNOWN_SUBMODULE_ATTRIBUTES``) in plugin
code. Plugins run on Python 3.9 to 3.14, so the guard keeps both sets as checked-in
constants, the union over every supported interpreter, which
``tools/lint/generate_name_sets.py`` builds from the output of this probe.

Run the probe in a clean interpreter, with the modules to inspect as arguments::

    python3.9 -I tools/lint/name_set_probe.py collections collections.abc json

``-I`` keeps the user site directory, ``PYTHON*`` variables and the script
directory off ``sys.path``, so only the standard library is imported and nothing
that a test session or a plugin happened to import earlier changes the result.
The probe imports every named module first and then reads the module-typed
attributes of each, so a package attribute that one import adds to another
module (``collections.abc`` on ``collections``) is always seen.

The probe uses only the standard library and Python 3.9 syntax, because it runs on
every supported interpreter. Python 3.9 has no ``sys.stdlib_module_names``; there,
the names are enumerated from the built-in modules and the standard library
directories. Platform-specific names are normalised: every
``_sysconfigdata_<abi>_<platform>_<multiarch>`` module (for example
``_sysconfigdata__linux_x86_64-linux-gnu``) becomes ``_sysconfigdata``, so the
result does not depend on the build platform.
"""

from __future__ import annotations

import importlib
import json
import pkgutil
import sys
import sysconfig
import types
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

SYSCONFIGDATA_PREFIX = "_sysconfigdata_"
SYSCONFIGDATA = "_sysconfigdata"
DYNLOAD_DIRECTORY = "lib-dynload"
STDLIB_PATHS = ("stdlib", "platstdlib")


def normalise(name: str) -> str:
    """Return the platform-independent form of the module name ``name``."""
    return SYSCONFIGDATA if name.startswith(SYSCONFIGDATA_PREFIX) else name


def enumerate_stdlib() -> set[str]:
    """Return the top-level standard library module names found on disk.

    This is the fallback for interpreters without ``sys.stdlib_module_names``
    (Python 3.9). It covers the built-in modules, the pure Python modules and
    packages of the standard library directories and the extension modules in
    ``lib-dynload``. It over-approximates on purpose: test packages such as
    ``test`` are kept, which only makes the guard stricter.
    """
    directories: list[str] = []
    for key in STDLIB_PATHS:
        directory = Path(sysconfig.get_path(key))
        directories.extend(str(path) for path in (directory, directory / DYNLOAD_DIRECTORY))
    names = set(sys.builtin_module_names)
    names.update(info.name for info in pkgutil.iter_modules(sorted(set(directories))))
    return names


def stdlib_module_names() -> list[str]:
    """Return the sorted, normalised standard library module names of this interpreter."""
    names: Iterable[str] | None = getattr(sys, "stdlib_module_names", None)
    if names is None:
        names = enumerate_stdlib()
    return sorted({normalise(name) for name in names})


def module_attributes(modules: Sequence[types.ModuleType]) -> frozenset[str]:
    """Return the names of the attributes of ``modules`` whose values are modules.

    Each value is read with ``getattr``, as plugin code would read it, so a
    ``lazy import`` binding (Python 3.15 and later), which the module dictionary
    holds as an unresolved proxy, is resolved to the module it names.
    """
    return frozenset(
        attribute
        for module in modules
        for attribute in sorted(vars(module))
        if isinstance(getattr(module, attribute), types.ModuleType)
    )


def submodule_attributes(modules: Sequence[str]) -> list[str]:
    """Return the sorted names of the module-typed attributes of ``modules``.

    Every module is imported before any attribute is read. Reading an attribute
    can resolve a lazy import, which may bind further submodules, so the
    attributes are read again until the result no longer changes.
    """
    loaded = [importlib.import_module(name) for name in modules]
    found = module_attributes(loaded)
    while (again := module_attributes(loaded)) != found:
        found = again
    return sorted(found)


def probe(modules: Sequence[str]) -> dict[str, object]:
    """Return the name sets of this interpreter for the allow-listed ``modules``."""
    return {
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "version": f"{sys.version_info[0]}.{sys.version_info[1]}",
        "modules": sorted(modules),
        "stdlib_module_names": stdlib_module_names(),
        "submodule_attributes": submodule_attributes(sorted(modules)),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Print the probe result for the modules named in ``argv`` as JSON."""
    modules = list(sys.argv[1:] if argv is None else argv)
    print(json.dumps(probe(modules), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
