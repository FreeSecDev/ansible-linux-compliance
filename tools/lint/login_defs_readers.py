"""Record what the real readers of login.defs read, the oracle of the login_defs family (FREES-198).

The ``login_defs`` family of the remediate role decides every line of ``/etc/login.defs`` as its
readers read it (ADR 0024, amendment of 2026-10-31). Their verdicts are kept in
``tests/fixtures/login_defs_readers/verdicts.json``, produced by the real readers in this
repository's Molecule images and never by an emulation: ``useradd`` and ``chage`` of shadow-utils
on Ubuntu 24.04 and Rocky Linux 9, and on Rocky Linux libeconf through ``ctypes``, with the call
that util-linux ``login`` makes for ``FAIL_DELAY``. ``tests/unit/roles/test_login_defs_readers.py``
checks every decision of the role against them.

Regenerate the table with ``bash tools/lint/login_defs_readers.sh UBUNTU_IMAGE ROCKY_IMAGE``. That
script decides the cases of ``tests/fixtures/login_defs_readers/cases.json`` with the role's own
decision tasks, writes one directory per file state (the text of every case and every text the
role writes) with ``prepare``, runs ``tools/lint/login_defs_readers_shadow.sh`` and ``econf`` in
throwaway containers of the images with ``--network none`` and read-only mounts, where ``install``
puts each state in place, and builds the table with ``merge``.

This file runs on the controller and, for ``install`` and ``econf``, on the Python 3.9 of the Rocky
Linux image, so it uses only the standard library and Python 3.9 syntax.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import locale
import multiprocessing
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

LIBECONF: Final[str] = "libeconf.so.0"
ECONF_KEY: Final[bytes] = b"FAIL_DELAY"
ECONF_ARGUMENTS: Final[tuple[bytes, ...]] = (b"/etc", b"login", b"defs", b"= \t", b"#")
UNSIGNED_INT: Final[int] = 2**32
BROKEN_LINK_TARGET: Final[str] = "/nonexistent/login-defs-reader-link"
STATES_FILE: Final[str] = "states.json"
SHADOW_FIELDS: Final[tuple[str, ...]] = (
    "minimum",
    "maximum",
    "warning",
    "home_mode",
    "home_created",
)
PLATFORMS: Final[tuple[str, ...]] = ("ubuntu", "rocky")

DESCRIPTION: Final[str] = "Record what the real readers of login.defs read (FREES-198)."
FIXTURES: Final[tuple[str, ...]] = ("tests", "fixtures", "login_defs_readers")
COLLECTIONS: Final[tuple[str, ...]] = ("build", "collections")
DECIDE_TIMEOUT_SECONDS: Final[float] = 900.0

State = dict[str, object]


def read_json(path: Path) -> object:
    """Return the JSON document in ``path``."""
    return json.loads(path.read_text(encoding="utf-8"))


def run_playbook(arguments: list[str], environment: dict[str, str]) -> None:
    """Run the playbook CLI of ansible-core in this process, a fresh one that ``decide`` spawns."""
    os.environ.clear()
    os.environ.update(environment)
    locale.setlocale(locale.LC_ALL, "")
    cli = importlib.import_module("ansible.cli.playbook")
    raise SystemExit(cli.PlaybookCLI(arguments).run())


def repository_root() -> Path:
    """Return the checkout that holds this file, below ``tools/lint``."""
    return Path(__file__).resolve().parents[2]


def decide(cases: Path, output: Path, collections: Path | None = None) -> None:
    """Decide every case with the role's decision tasks, on the controller and in memory only.

    ``tests/fixtures/login_defs_readers/decide.yml`` includes ``login_defs_decide.yml`` of the
    remediate role for every case and writes the decisions to ``output``; nothing else is written.
    The playbook runs in a spawned process, so the global state of ansible-core never reaches the
    caller.
    """
    with tempfile.TemporaryDirectory() as home:
        arguments = [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "-e",
            "ansible_python_interpreter=" + sys.executable,
            "-e",
            f"readers_cases_path={cases}",
            "-e",
            f"readers_output_path={output}",
            str(repository_root().joinpath(*FIXTURES, "decide.yml")),
        ]
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": home,
            "LC_ALL": "C.UTF-8",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_COLLECTIONS_PATH": str(
                collections or repository_root().joinpath(*COLLECTIONS)
            ),
        }
        process = multiprocessing.get_context("spawn").Process(
            target=run_playbook, args=(arguments, environment)
        )
        process.start()
        process.join(DECIDE_TIMEOUT_SECONDS)
        if process.is_alive():
            process.kill()
            process.join()
        if process.exitcode != 0:
            message = f"the decisions of the login_defs cases failed with {process.exitcode}"
            raise RuntimeError(message)


def state_of(text: str, dropins: Mapping[str, str], links: Sequence[str]) -> State:
    """Return the file state of a case: login.defs, its drop-ins and its links to no file."""
    return {"text": text, "dropins": dict(sorted(dropins.items())), "links": sorted(links)}


def state_key(state: State) -> str:
    """Return the SHA-256 that names a file state in the table."""
    canonical = json.dumps(state, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def case_state(case: Mapping[str, object], text: str | None = None) -> State:
    """Return the state of a case, or of the text written for it next to the same drop-ins."""
    dropins = cast("Mapping[str, str]", case.get("dropins", {}))
    links = cast("Sequence[str]", case.get("links", []))
    return state_of(str(case["text"]) if text is None else text, dropins, links)


def collect_states(
    cases: Sequence[Mapping[str, object]], decisions: Mapping[str, Mapping[str, object]]
) -> dict[str, State]:
    """Return every state the table needs: each case as given and each text the role writes."""
    states: dict[str, State] = {}
    for case in cases:
        before = case_state(case)
        states[state_key(before)] = before
        written = decisions[str(case["name"])].get("written")
        if isinstance(written, str):
            after = case_state(case, written)
            states[state_key(after)] = after
    return states


def write_states(states: Mapping[str, State], directory: Path) -> None:
    """Write one directory per state, and the states by key."""
    directory.mkdir(parents=True, exist_ok=True)
    for key, state in states.items():
        target = directory / key
        target.mkdir()
        (target / "login.defs").write_bytes(str(state["text"]).encode("utf-8", "surrogateescape"))
        dropins = cast("Mapping[str, str]", state["dropins"])
        if dropins:
            (target / "dropins").mkdir()
            for name, text in dropins.items():
                (target / "dropins" / name).write_bytes(text.encode("utf-8", "surrogateescape"))
        links = cast("Sequence[str]", state["links"])
        (target / "links").write_text("".join(f"{name}\n" for name in links), encoding="ascii")
    (directory / STATES_FILE).write_text(
        json.dumps(states, sort_keys=True) + "\n", encoding="utf-8"
    )


def install(state_directory: Path, root: Path) -> None:
    """Put a state in place below ``root``: login.defs, and the drop-in directory only when used."""
    etc = root / "etc"
    (etc / "login.defs").write_bytes((state_directory / "login.defs").read_bytes())
    dropin_directory = etc / "login.defs.d"
    if dropin_directory.is_symlink() or dropin_directory.is_file():
        dropin_directory.unlink()
    elif dropin_directory.is_dir():
        shutil.rmtree(dropin_directory)
    sources = state_directory / "dropins"
    links = (state_directory / "links").read_text(encoding="ascii").split()
    if not sources.is_dir() and not links:
        return
    dropin_directory.mkdir()
    if sources.is_dir():
        for source in sorted(sources.iterdir()):
            (dropin_directory / source.name).write_bytes(source.read_bytes())
    for name in links:
        (dropin_directory / name).symlink_to(BROKEN_LINK_TARGET)


def configure(library: ctypes.CDLL) -> None:
    """Declare the libeconf 0.4.1 functions that ``read_econf`` calls."""
    handle_pointer = ctypes.POINTER(ctypes.c_void_p)
    library.econf_readDirs.argtypes = [handle_pointer] + [ctypes.c_char_p] * 6
    library.econf_getStringValue.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    library.econf_getUInt64Value.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    library.econf_freeFile.argtypes = [ctypes.c_void_p]


def read_econf(library: ctypes.CDLL, key: bytes = ECONF_KEY) -> int | str:
    """Read ``key`` as util-linux ``getlogindefs_num`` does through libeconf.

    Returns the number that ``login`` uses (``strtoull`` in base 10, cast to an unsigned int),
    ``"error"`` when libeconf reads no configuration, ``"nokey"`` when the key is not set and
    ``"null"`` when it is set without a value, where ``login`` would pass a null pointer.
    """
    handle = ctypes.c_void_p()
    if library.econf_readDirs(ctypes.pointer(handle), None, *ECONF_ARGUMENTS):
        return "error"
    try:
        text = ctypes.c_char_p()
        if library.econf_getStringValue(handle, None, key, ctypes.pointer(text)):
            return "nokey"
        if text.value is None:
            return "null"
        number = ctypes.c_uint64(0)
        library.econf_getUInt64Value(handle, None, key, ctypes.pointer(number))
        return int(number.value) % UNSIGNED_INT
    finally:
        library.econf_freeFile(handle)


def econf_readings(directory: Path, library: ctypes.CDLL, root: Path) -> dict[str, int | str]:
    """Install every state of ``directory`` below ``root`` in turn and read it with libeconf."""
    configure(library)
    readings: dict[str, int | str] = {}
    for key in sorted(cast("Mapping[str, State]", read_json(directory / STATES_FILE))):
        install(directory / key, root)
        readings[key] = read_econf(library)
    return readings


def parse_shadow(text: str) -> tuple[dict[str, str], dict[str, dict[str, object]]]:
    """Read the output of ``login_defs_readers_shadow.sh``: the versions and a reading per state."""
    versions: dict[str, str] = {}
    readings: dict[str, dict[str, object]] = {}
    for line in text.splitlines():
        if line.startswith("#"):
            name, _, version = line[1:].partition("\t")
            versions[name] = version
            continue
        key, *fields = line.split("\t")
        if len(fields) != len(SHADOW_FIELDS):
            message = f"malformed shadow reading: {line!r}"
            raise ValueError(message)
        reading: dict[str, object] = {}
        for index, name in enumerate(SHADOW_FIELDS):
            value = fields[index]
            if name == "home_created":
                reading[name] = value == "yes"
            elif name == "home_mode" or not value.lstrip("-").isdigit():
                reading[name] = value
            else:
                reading[name] = int(value)
        readings[key] = reading
    return versions, readings


def merge(directory: Path) -> dict[str, object]:
    """Build the verdict table from the outputs that the containers left in ``directory``."""
    states = cast("Mapping[str, State]", read_json(directory / STATES_FILE))
    readers: dict[str, dict[str, str]] = {}
    shadow: dict[str, dict[str, dict[str, object]]] = {}
    for platform in PLATFORMS:
        readers[platform], shadow[platform] = parse_shadow(
            (directory / f"{platform}-shadow.tsv").read_text(encoding="utf-8")
        )
    econf = cast("Mapping[str, object]", read_json(directory / "rocky-econf.json"))
    table: dict[str, object] = {}
    for key in sorted(states):
        rocky = dict(shadow["rocky"][key])
        rocky["libeconf"] = econf[key]
        table[key] = {"ubuntu": shadow["ubuntu"][key], "rocky": rocky}
    return {"readers": readers, "states": table}


def main(
    argv: Sequence[str] | None = None, library: ctypes.CDLL | None = None, root: Path = Path("/")
) -> int:
    """Run one subcommand; ``library`` and ``root`` exist so that unit tests need no container."""
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    commands = parser.add_subparsers(dest="command", required=True)
    decide_command = commands.add_parser("decide")
    decide_command.add_argument("cases", type=Path)
    decide_command.add_argument("output", type=Path)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("cases", type=Path)
    prepare.add_argument("decisions", type=Path)
    prepare.add_argument("directory", type=Path)
    install_command = commands.add_parser("install")
    install_command.add_argument("state", type=Path)
    econf = commands.add_parser("econf")
    econf.add_argument("directory", type=Path)
    merge_command = commands.add_parser("merge")
    merge_command.add_argument("directory", type=Path)
    merge_command.add_argument("output", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command == "decide":
        decide(arguments.cases, arguments.output)
    elif arguments.command == "prepare":
        cases = cast("dict[str, list[dict[str, object]]]", read_json(arguments.cases))
        decisions = cast("dict[str, dict[str, object]]", read_json(arguments.decisions))
        write_states(collect_states(cases["cases"], decisions), arguments.directory)
    elif arguments.command == "install":
        install(arguments.state, root)
    elif arguments.command == "econf":
        readings = econf_readings(arguments.directory, library or ctypes.CDLL(LIBECONF), root)
        sys.stdout.write(json.dumps(readings, sort_keys=True) + "\n")
    else:
        table = json.dumps(merge(arguments.directory), indent=1, sort_keys=True)
        arguments.output.write_text(table + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
