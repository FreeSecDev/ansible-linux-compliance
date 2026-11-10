"""How the PAM directory entries are sorted into files to read and entries that refuse."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    pam_conf,
    pam_service_files,
    pwquality_decide,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pam_files,
)

if TYPE_CHECKING:
    from pathlib import Path

MAIN = "/etc/security/pwquality.conf"
DROPIN = "/etc/security/pwquality.conf.d/50-freesecdev-minlen.conf"
MINLEN: dict[str, object] = {
    "setting": "minlen",
    "value": "14",
    "method": "main_file",
    "main": MAIN,
    "dropin": DROPIN,
    "content": "",
}
DENY: dict[str, object] = {
    "reader": "faillock",
    "setting": "deny",
    "comparison": "at_most",
    "required": "4",
    "stack_checked": True,
}
BROKEN = {"path": "/etc/pam.d/system-auth", "kind": "broken_link"}
FILE_STAT = {"exists": True, "isreg": True, "isdir": False}
DIRECTORY_STAT = {"exists": True, "isreg": False, "isdir": True}
FIFO_STAT = {"exists": True, "isreg": False, "isdir": False}
NOTHING: dict[str, object] = {}
NO_ENTRIES: list[object] = []
WRONG_SHAPES: list[tuple[tuple[object, object, object], str]] = [
    (("files", NOTHING, NOTHING), "the PAM directory entries must be a list"),
    ((NO_ENTRIES, NO_ENTRIES, NOTHING), "the stats of the links must be a mapping"),
    ((NO_ENTRIES, NOTHING, ["/etc/pam.d/x"]), "the skipped paths must be a mapping"),
    ((["entry"], NOTHING, NOTHING), "every PAM directory entry must be a mapping"),
    (([{"path": "x", "isreg": True}], NOTHING, NOTHING), "needs an absolute path, got 'x'"),
    (([{"path": "/etc/pam.d/x"}], NOTHING, NOTHING), "needs a boolean isreg"),
    (([{"path": "/etc/pam.d/x", 1: True}], NOTHING, NOTHING), "must be a mapping"),
]


def entry(path: str, *, isreg: bool = False, isdir: bool = False, islnk: bool = False) -> object:
    return {"path": path, "isreg": isreg, "isdir": isdir, "islnk": islnk}


def lstat_entry(path: Path) -> dict[str, object]:
    """Return what ``ansible.builtin.find`` with ``file_type: any`` reports for ``path``."""
    mode = os.lstat(path).st_mode
    return {
        "path": str(path),
        "isreg": stat.S_ISREG(mode),
        "isdir": stat.S_ISDIR(mode),
        "islnk": stat.S_ISLNK(mode),
    }


def followed_stat(path: Path) -> dict[str, object]:
    """Return what ``ansible.builtin.stat`` with ``follow: true`` reports for ``path``."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return {"exists": False}
    return {"exists": True, "isreg": stat.S_ISREG(mode), "isdir": stat.S_ISDIR(mode)}


def test_a_directory_laid_out_as_authselect_does_is_sorted_as_libpam_opens_it(
    tmp_path: Path,
) -> None:
    pam = tmp_path / "pam.d"
    authselect = tmp_path / "authselect"
    pam.mkdir()
    authselect.mkdir()
    (authselect / "system-auth").write_text("password requisite pam_pwquality.so minlen=8\n")
    (authselect / "subdirectory").mkdir()
    (pam / "passwd").write_text("password include system-auth\n")
    (pam / ".hidden").write_text("")
    (pam / "system-auth").symlink_to("../authselect/system-auth")
    (pam / "linked-directory").symlink_to("../authselect/subdirectory")
    (pam / "directory").mkdir()
    (pam / "broken").symlink_to("../authselect/missing")
    (pam / "fifo").symlink_to(tmp_path / "pipe")
    os.mkfifo(tmp_path / "pipe")
    os.mkfifo(pam / "pipe")
    entries = [lstat_entry(path) for path in sorted(pam.iterdir())]
    targets = {
        str(path): followed_stat(path) for path in sorted(pam.iterdir()) if path.is_symlink()
    }
    sorted_entries = pam_files.sort_entries(entries, targets, [])
    assert sorted_entries == {
        "read": [str(pam / ".hidden"), str(pam / "passwd"), str(pam / "system-auth")],
        "unreadable": [
            {"path": str(pam / "broken"), "kind": "broken_link"},
            {"path": str(pam / "fifo"), "kind": "link"},
            {"path": str(pam / "pipe"), "kind": "special"},
        ],
    }
    assert pam_files.describe(sorted_entries["unreadable"]) == [
        f"{pam}/broken is a symbolic link that resolves to nothing",
        f"{pam}/fifo {pam_files.KINDS['link']}",
        f"{pam}/pipe is neither a regular file, a directory nor a symbolic link",
    ]


def test_an_entry_that_find_skipped_is_unreadable_even_when_it_was_listed() -> None:
    entries = [entry("/etc/pam.d/login", isreg=True), entry("/etc/pam.d/sshd", isreg=True)]
    result = pam_service_files.pam_service_files(entries, {}, {"/etc/pam.d/sshd": "EACCES"})
    assert result == {
        "read": ["/etc/pam.d/login"],
        "unreadable": [{"path": "/etc/pam.d/sshd", "kind": "unlisted"}],
    }
    assert pam_service_files.pam_service_files(entries, {}) == {
        "read": ["/etc/pam.d/login", "/etc/pam.d/sshd"],
        "unreadable": [],
    }


def test_a_link_is_sorted_by_what_it_resolves_to() -> None:
    links = [entry(f"/etc/pam.d/{name}", islnk=True) for name in ("a", "b", "c", "d")]
    targets = {
        "/etc/pam.d/a": FILE_STAT,
        "/etc/pam.d/b": DIRECTORY_STAT,
        "/etc/pam.d/c": FIFO_STAT,
        "/etc/pam.d/d": {"exists": False},
    }
    assert pam_service_files.pam_service_files(links, targets, {}) == {
        "read": ["/etc/pam.d/a"],
        "unreadable": [
            {"path": "/etc/pam.d/c", "kind": "link"},
            {"path": "/etc/pam.d/d", "kind": "broken_link"},
        ],
    }
    assert pam_service_files.FilterModule().filters() == {
        "pam_service_files": pam_service_files.pam_service_files
    }


LINK_SHAPES: list[tuple[tuple[object, object, object], str]] = [
    (([entry("/etc/pam.d/x", islnk=True)], NOTHING, NOTHING), "has no stat through the link"),
    (
        ([entry("/etc/pam.d/x", islnk=True)], {"/etc/pam.d/x": "stat"}, NOTHING),
        "the stat of the link /etc/pam.d/x must be a mapping",
    ),
    (
        ([entry("/etc/pam.d/x", islnk=True)], {"/etc/pam.d/x": {"exists": "yes"}}, NOTHING),
        "needs a boolean exists",
    ),
    ((NO_ENTRIES, NOTHING, {"pam.d/x": "EACCES"}), "a skipped PAM path must be absolute"),
]


@pytest.mark.parametrize(("arguments", "message"), WRONG_SHAPES + LINK_SHAPES)
def test_input_of_the_wrong_shape_is_refused(
    arguments: tuple[object, object, object], message: str
) -> None:
    with pytest.raises(pam_files.PamEntryError, match=message):
        pam_service_files.pam_service_files(*arguments)


@pytest.mark.parametrize(
    ("unreadable", "message"),
    [
        ("broken", "the unreadable PAM entries must be a list"),
        (["broken"], "every unreadable PAM entry must be a mapping"),
        ([{"kind": "broken_link"}], "needs an absolute path"),
        ([{"path": "/etc/pam.d/x", "kind": "fifo"}], "needs a kind of"),
    ],
)
def test_an_unreadable_entry_of_the_wrong_shape_is_refused(
    unreadable: object, message: str
) -> None:
    with pytest.raises(pam_files.PamEntryError, match=message):
        pam_files.describe(unreadable)


def test_an_unreadable_pam_entry_refuses_a_pwquality_rule_before_anything_else() -> None:
    pam = [
        {"path": "/etc/pam.d/login", "content": "password requisite pam_pwquality.so\n"},
        BROKEN,
    ]
    decision = pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", pam)
    assert decision == {
        "line": "minlen = 14",
        "found": None,
        "text": None,
        "note": None,
        "status": "overridden",
        "reason": "/etc/pam.d/system-auth is a symbolic link that resolves to nothing, which "
        "libpam may open but the collection does not read, so a pam_pwquality argument there "
        "could override the file",
    }
    assert pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", pam[:1])["status"] == (
        "compliant"
    )
    with pytest.raises(pwquality_decide.DecisionInputError, match="needs a kind of"):
        pwquality_decide.pwquality_decide(
            MINLEN, [], "", [{"path": "/etc/pam.d/x", "kind": "fifo"}]
        )


def test_an_unreadable_pam_entry_refuses_a_faillock_rule_as_an_unreadable_stack() -> None:
    stack = {"/etc/pam.d/login": "auth required pam_unix.so\n"}
    assert pam_conf.pam_conf_decision("deny = 4\n", DENY, stack)["status"] == "compliant"
    decision = pam_conf.pam_conf_decision("deny = 4\n", DENY, stack, [BROKEN])
    assert decision["status"] == "unreadable_stack"
    assert decision["new_text"] is None
    assert decision["reason"] == (
        "libpam reads service files that the collection cannot read as it does "
        "(/etc/pam.d/system-auth is a symbolic link that resolves to nothing), so it cannot tell "
        "whether a pam_faillock line overrides the file; nothing is written"
    )
    with pytest.raises(pam_files.PamEntryError, match="must be a list"):
        pam_conf.pam_conf_decision("", DENY, stack, "broken")
