"""Read every pwquality file state with the real libpwquality of a Molecule image (FREES-200).

``bash tools/lint/pwquality_readers.sh`` runs this script as root in throwaway containers of the
Ubuntu 24.04 and Rocky Linux 9 Molecule images, with ``--network none`` and read-only mounts. For
every state of ``states.json`` it puts the main file and the drop-ins in place below
``/etc/security``, reads them with ``pwquality_read_config`` of the image's ``libpwquality.so.1``
through ``ctypes``, applies the ``pam_pwquality`` arguments of the state with
``pwquality_set_option``, as the PAM module does after reading the files, and prints what the
library holds. It never runs on a workstation, and it uses only the standard library and the
syntax of Python 3.9, the Python of the Rocky Linux image.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import shutil
import sys
from pathlib import Path
from typing import Final, Protocol, cast

LIBRARY: Final[str] = "libpwquality.so.1"
MAIN: Final[str] = "etc/security/pwquality.conf"
DIRECTORY: Final[str] = "etc/security/pwquality.conf.d"
TARGETS: Final[str] = "tmp/frees200-pwquality-targets"
MISSING_TARGET: Final[str] = "/nonexistent/frees200-pwquality-link"
SETTING_IDS: Final[dict[str, int]] = {
    "difok": 1,
    "minlen": 3,
    "dcredit": 4,
    "ucredit": 5,
    "lcredit": 6,
    "ocredit": 7,
    "minclass": 8,
    "maxrepeat": 9,
    "maxclassrepeat": 11,
    "gecoscheck": 12,
    "maxsequence": 14,
    "dictcheck": 15,
    "usercheck": 16,
    "enforcing": 17,
    "retry": 18,
    "enforce_for_root": 19,
    "local_users_only": 20,
}
UNSET: Final[int] = -999999


class Library(Protocol):
    """The functions of libpwquality that the probe calls."""

    def pwquality_default_settings(self) -> int:
        """Return new settings with the defaults of the library."""
        ...

    def pwquality_read_config(self, settings: int, path: None, error: object) -> int:
        """Read the default configuration into ``settings`` and return the error code."""
        ...

    def pwquality_set_option(self, settings: int, option: bytes) -> int:
        """Apply one module argument, as pam_pwquality does."""
        ...

    def pwquality_get_int_value(self, settings: int, setting: int, value: object) -> int:
        """Store the value of an integer setting in ``value``."""
        ...

    def pwquality_free_settings(self, settings: int) -> None:
        """Free ``settings``."""
        ...


def load() -> Library:
    """Load libpwquality and declare the signatures of the functions that the probe calls."""
    library = ctypes.CDLL(LIBRARY)
    library.pwquality_default_settings.restype = ctypes.c_void_p
    library.pwquality_read_config.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.pwquality_set_option.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.pwquality_get_int_value.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
    ]
    library.pwquality_free_settings.argtypes = [ctypes.c_void_p]
    return cast("Library", library)


def install(root: Path, state: dict[str, object]) -> None:
    """Put the main file and the drop-ins of ``state`` in place below ``root``."""
    main = root / MAIN
    directory = root / DIRECTORY
    targets = root / TARGETS
    for path in (directory, targets):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
    if main.exists() or main.is_symlink():
        main.unlink()
    directory.mkdir(parents=True)
    targets.mkdir(parents=True)
    content = state.get("main")
    if isinstance(content, str):
        main.write_bytes(base64.b64decode(content))
    for entry in cast("list[dict[str, str]]", state.get("dropins", [])):
        path = directory / entry["name"]
        kind = entry["type"]
        if kind == "directory":
            path.mkdir()
        elif kind == "link":
            target = targets / entry["name"]
            target.write_bytes(base64.b64decode(entry["content"]))
            path.symlink_to(target)
        elif kind == "dangling":
            path.symlink_to(MISSING_TARGET)
        else:
            path.write_bytes(base64.b64decode(entry["content"]))


def read(library: Library, arguments: list[str]) -> list[int]:
    """Return the error code and the value of every setting of :data:`SETTING_IDS` in order.

    That is what libpwquality holds after reading the files and applying ``arguments``.
    """
    settings = library.pwquality_default_settings()
    error = ctypes.c_void_p()
    code = library.pwquality_read_config(settings, None, ctypes.pointer(error))
    for argument in arguments:
        library.pwquality_set_option(settings, base64.b64decode(argument))
    values = [code]
    for identifier in SETTING_IDS.values():
        value = ctypes.c_int(UNSET)
        library.pwquality_get_int_value(settings, identifier, ctypes.pointer(value))
        values.append(value.value)
    library.pwquality_free_settings(settings)
    return values


def probe(states: Path, root: Path, library: Library) -> dict[str, object]:
    """Return the reading of every state of ``states``."""
    found: dict[str, object] = {}
    for key, state in sorted(
        cast("dict[str, dict[str, object]]", json.loads(states.read_text())).items()
    ):
        install(root, state)
        found[key] = read(library, cast("list[str]", state.get("arguments", [])))
    return found


def main(arguments: list[str] | None = None) -> int:
    """Run the probe: ``pwquality_readers_probe.py <states.json>``, as root in a container."""
    parser = argparse.ArgumentParser(
        description="Read pwquality states with the real libpwquality."
    )
    parser.add_argument("states", type=Path)
    parser.add_argument("--root", type=Path, default=Path("/"))
    options = parser.parse_args(arguments)
    readings = probe(options.states, options.root, load())
    json.dump(readings, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
