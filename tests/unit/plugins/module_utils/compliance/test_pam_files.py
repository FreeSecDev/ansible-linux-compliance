"""How the PAM directory entries are sorted into files to read and entries that refuse."""

from __future__ import annotations

import inspect
import os
import stat
from typing import TYPE_CHECKING

import pytest
import yaml

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
REMEMBER: dict[str, object] = {
    "reader": "pwhistory",
    "setting": "remember",
    "comparison": "at_least",
    "required": "24",
    "stack_checked": True,
}
ENFORCE: dict[str, object] = {
    "reader": "pwhistory",
    "setting": "enforce_for_root",
    "comparison": "present",
    "required": "",
    "stack_checked": False,
}
BROKEN = {"path": "/etc/pam.d/system-auth", "kind": "broken_link"}
LOOP = "Too many levels of symbolic links"
NOT_DIR = "Not a directory"
FILE_STAT = {"exists": True, "isreg": True, "isdir": False}
DIRECTORY_STAT = {"exists": True, "isreg": False, "isdir": True}
FIFO_STAT = {"exists": True, "isreg": False, "isdir": False}
NOTHING: dict[str, object] = {}
NO_ENTRIES: list[object] = []
NOT_A_LINK: dict[str, object] = {"exists": True, "islnk": False}
MODULES: dict[str, object] = {"directory": "/usr/lib64/security/", "stats": {}, "links": {}}
DIRECTORIES: dict[str, object] = {"/etc/pam.d": DIRECTORY_STAT}
RESOLVED: dict[str, object] = {"/etc/pam.d": NOT_A_LINK}
WRONG_SHAPES: list[tuple[tuple[object, object, object, object, object], str]] = [
    (("files", NOTHING, NOTHING, NOTHING, NOTHING), "the PAM directory entries must be a list"),
    (
        (NO_ENTRIES, NO_ENTRIES, NOTHING, NOTHING, NOTHING),
        "the stats of the links must be a mapping",
    ),
    (
        (NO_ENTRIES, NOTHING, ["/etc/pam.d/x"], NOTHING, NOTHING),
        "the skipped paths must be a mapping",
    ),
    ((NO_ENTRIES, NOTHING, None, NOTHING, NOTHING), "the skipped paths must be a mapping"),
    (
        (["entry"], NOTHING, NOTHING, NOTHING, NOTHING),
        "every PAM directory entry must be a mapping",
    ),
    (
        ([{"path": "x", "isreg": True}], NOTHING, NOTHING, NOTHING, NOTHING),
        "needs an absolute path, got 'x'",
    ),
    (([{"path": "/etc/pam.d/x"}], NOTHING, NOTHING, NOTHING, NOTHING), "needs a boolean isreg"),
    (
        ([{"path": "/etc/pam.d/x", 1: True}], NOTHING, NOTHING, NOTHING, NOTHING),
        "must be a mapping",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, NOTHING, []),
        "the resolutions of the PAM directories and links must be a mapping",
    ),
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
    """Return what the role passes for ``path`` from ``ansible.builtin.stat`` with ``follow: true``.

    The module returns ``exists: false`` on ``FileNotFoundError`` and fails on any other
    ``OSError`` with its ``strerror`` as ``msg``; the task runs with ``failed_when: false`` and
    passes a mapping with only that ``msg`` for a result that has no ``stat``.
    """
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return {"exists": False}
    except OSError as error:
        return {"msg": error.strerror}
    return {"exists": True, "isreg": stat.S_ISREG(mode), "isdir": stat.S_ISDIR(mode)}


def resolution(path: Path) -> dict[str, object]:
    """Return what the role passes for ``path`` from ``ansible.builtin.stat``, ``follow: false``."""
    mode = os.lstat(path).st_mode
    if not stat.S_ISLNK(mode):
        return NOT_A_LINK
    return {
        "exists": True,
        "islnk": True,
        "lnk_source": os.path.realpath(path),
        "lnk_target": str(path.readlink()),
    }


def link_to(target: str, source: str | None = None) -> dict[str, object]:
    """Return the resolution of a link to ``target`` that the module resolves to ``source``."""
    return {
        "exists": True,
        "islnk": True,
        "lnk_source": target if source is None else source,
        "lnk_target": target,
    }


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
    (pam / "loop").symlink_to("loop")
    (pam / "cycle-a").symlink_to("cycle-b")
    (pam / "cycle-b").symlink_to("cycle-a")
    (pam / "not-a-directory").symlink_to("passwd/x")
    os.mkfifo(tmp_path / "pipe")
    os.mkfifo(pam / "pipe")
    entries = [lstat_entry(path) for path in sorted(pam.iterdir())]
    links = [path for path in sorted(pam.iterdir()) if path.is_symlink()]
    targets = {str(path): followed_stat(path) for path in links}
    directories = {**DIRECTORIES, str(pam): followed_stat(pam)}
    resolved = {**RESOLVED, str(pam): resolution(pam)} | {
        str(path): resolution(path) for path in links
    }
    sorted_entries = pam_files.sort_entries(entries, targets, [], directories, resolved)
    assert sorted_entries == {
        "read": [str(pam / ".hidden"), str(pam / "passwd"), str(pam / "system-auth")],
        "unreadable": [
            {"path": str(pam / "broken"), "kind": "broken_link"},
            {"path": str(pam / "cycle-a"), "kind": "unfollowed_link", "detail": LOOP},
            {"path": str(pam / "cycle-b"), "kind": "unfollowed_link", "detail": LOOP},
            {"path": str(pam / "fifo"), "kind": "link"},
            {"path": str(pam / "loop"), "kind": "unfollowed_link", "detail": LOOP},
            {"path": str(pam / "not-a-directory"), "kind": "unfollowed_link", "detail": NOT_DIR},
            {"path": str(pam / "pipe"), "kind": "special"},
        ],
    }
    unfollowed = (
        "is a symbolic link that stat could not follow (a loop, a path through something that "
        "is not a directory, or another error)"
    )
    assert pam_files.describe(sorted_entries["unreadable"]) == [
        f"{pam}/broken is a symbolic link that resolves to nothing",
        f"{pam}/cycle-a {unfollowed}: {LOOP}",
        f"{pam}/cycle-b {unfollowed}: {LOOP}",
        f"{pam}/fifo {pam_files.KINDS['link']}",
        f"{pam}/loop {unfollowed}: {LOOP}",
        f"{pam}/not-a-directory {unfollowed}: {NOT_DIR}",
        f"{pam}/pipe is neither a regular file, a directory nor a symbolic link",
    ]


def test_an_entry_that_find_skipped_is_unreadable_even_when_it_was_listed() -> None:
    entries = [entry("/etc/pam.d/login", isreg=True), entry("/etc/pam.d/sshd", isreg=True)]
    result = pam_service_files.pam_service_files(
        entries, {}, {"/etc/pam.d/sshd": "EACCES"}, DIRECTORIES, RESOLVED
    )
    assert result == {
        "read": ["/etc/pam.d/login"],
        "unreadable": [{"path": "/etc/pam.d/sshd", "kind": "unlisted"}],
    }
    assert pam_service_files.pam_service_files(entries, {}, {}, DIRECTORIES, RESOLVED) == {
        "read": ["/etc/pam.d/login", "/etc/pam.d/sshd"],
        "unreadable": [],
    }
    skipped_directory = {"/etc/pam.d": "EACCES"}
    assert pam_service_files.pam_service_files(
        [], {}, skipped_directory, DIRECTORIES, RESOLVED
    ) == {
        "read": [],
        "unreadable": [{"path": "/etc/pam.d", "kind": "unlisted"}],
    }


@pytest.mark.parametrize("name", ["skipped", "directories", "resolved"])
def test_the_skipped_paths_and_the_directory_stats_cannot_be_left_out(name: str) -> None:
    parameter = inspect.signature(pam_service_files.pam_service_files).parameters[name]
    assert parameter.default is inspect.Parameter.empty
    option = yaml.safe_load(pam_service_files.DOCUMENTATION)["options"][name]
    assert "default" not in option
    assert option["required"] is True


def test_a_link_is_sorted_by_what_it_resolves_to() -> None:
    links = [entry(f"/etc/pam.d/{name}", islnk=True) for name in ("a", "b", "c", "d")]
    targets = {
        "/etc/pam.d/a": FILE_STAT,
        "/etc/pam.d/b": DIRECTORY_STAT,
        "/etc/pam.d/c": FIFO_STAT,
        "/etc/pam.d/d": {"exists": False},
    }
    resolved = RESOLVED | {"/etc/pam.d/a": link_to("/etc/security/a")}
    assert pam_service_files.pam_service_files(links, targets, {}, DIRECTORIES, resolved) == {
        "read": ["/etc/pam.d/a"],
        "unreadable": [
            {"path": "/etc/pam.d/c", "kind": "link"},
            {"path": "/etc/pam.d/d", "kind": "broken_link"},
        ],
    }
    assert pam_service_files.FilterModule().filters() == {
        "pam_service_files": pam_service_files.pam_service_files
    }


def test_a_link_whose_stat_failed_or_is_missing_is_unreadable_and_never_read() -> None:
    links = [entry(f"/etc/pam.d/{name}", islnk=True) for name in ("failed", "missing", "file")]
    results: list[dict[str, object]] = [
        {"link": "/etc/pam.d/failed", "failed": False, "msg": "Too many levels of symbolic links"},
        {"link": "/etc/pam.d/file", "failed": False, "stat": FILE_STAT},
    ]
    targets = {
        str(result["link"]): result["stat"] if "stat" in result else {"msg": result["msg"]}
        for result in results
    }
    resolved = RESOLVED | {"/etc/pam.d/file": link_to("/etc/authselect/file")}
    assert pam_service_files.pam_service_files(links, targets, {}, DIRECTORIES, resolved) == {
        "read": ["/etc/pam.d/file"],
        "unreadable": [
            {"path": "/etc/pam.d/failed", "kind": "unfollowed_link", "detail": LOOP},
            {"path": "/etc/pam.d/missing", "kind": "unfollowed_link"},
        ],
    }
    skipped = pam_service_files.pam_service_files(
        links, targets, {"/etc/pam.d/failed": "ELOOP"}, DIRECTORIES, resolved
    )
    assert skipped["read"] == ["/etc/pam.d/file"]
    assert {"path": "/etc/pam.d/missing", "kind": "unfollowed_link"} in skipped["unreadable"]


LINK = [entry("/etc/pam.d/x", islnk=True)]
LINK_SHAPES: list[tuple[tuple[object, object, object, object, object], str]] = [
    (
        (LINK, {"/etc/pam.d/x": "stat"}, NOTHING, DIRECTORIES, RESOLVED),
        "the stat of the link /etc/pam.d/x must be a mapping",
    ),
    (
        (LINK, {"/etc/pam.d/x": {"exists": "yes"}}, NOTHING, DIRECTORIES, RESOLVED),
        "needs a boolean exists",
    ),
    (
        (NO_ENTRIES, NOTHING, {"pam.d/x": "EACCES"}, NOTHING, NOTHING),
        "a skipped PAM path must be absolute",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, [], NOTHING),
        "the stats of the PAM directories must be a mapping",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, {"/etc/pam.d": "stat"}, NOTHING),
        "the stat of the PAM directory /etc/pam.d must be a mapping",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, {"pam.d": {}}, NOTHING),
        "every PAM directory needs an absolute path",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, {"/etc/pam.d": {"exists": "yes"}}, NOTHING),
        "needs a boolean exists",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, DIRECTORIES, {"/etc/pam.d": "stat"}),
        "the resolution of /etc/pam.d must be a mapping",
    ),
    (
        (NO_ENTRIES, NOTHING, NOTHING, DIRECTORIES, {"/etc/pam.d": {"exists": True}}),
        "the resolution of /etc/pam.d needs a boolean islnk",
    ),
    (
        (
            NO_ENTRIES,
            NOTHING,
            NOTHING,
            DIRECTORIES,
            {"/etc/pam.d": {"exists": True, "islnk": True}},
        ),
        "needs the absolute lnk_source of a symbolic link, got None",
    ),
    (
        (
            NO_ENTRIES,
            NOTHING,
            NOTHING,
            DIRECTORIES,
            {"/etc/pam.d": {"exists": True, "islnk": True, "lnk_source": "/etc/x"}},
        ),
        "needs the lnk_target of a symbolic link, got None",
    ),
    (
        (
            NO_ENTRIES,
            NOTHING,
            NOTHING,
            DIRECTORIES,
            {"/etc/pam.d": link_to("") | {"lnk_source": "/etc/x"}},
        ),
        "needs the lnk_target of a symbolic link, got ''",
    ),
    (
        (LINK, {"/etc/pam.d/x": FILE_STAT}, NOTHING, DIRECTORIES, RESOLVED | {"/etc/pam.d/x": 1}),
        "the resolution of /etc/pam.d/x must be a mapping",
    ),
]


def test_a_pam_directory_that_stat_could_not_inspect_is_unreadable(tmp_path: Path) -> None:
    loop = tmp_path / "pam.d"
    loop.symlink_to("pam.d")
    missing = tmp_path / "missing.d"
    plain = tmp_path / "file.d"
    plain.write_text("")
    real = tmp_path / "real.d"
    real.mkdir()
    (real / "login").write_text("")
    directories = DIRECTORIES | {
        str(path): followed_stat(path) for path in (loop, missing, plain, real)
    }
    assert directories[str(loop)] == {"msg": LOOP}
    entries = [lstat_entry(real / "login")]
    resolved = RESOLVED | {str(real): resolution(real)}
    assert pam_service_files.pam_service_files(entries, {}, {}, directories, resolved) == {
        "read": [str(real / "login")],
        "unreadable": [{"path": str(loop), "kind": "uninspected_directory", "detail": LOOP}],
    }
    assert pam_files.describe([{"path": str(loop), "kind": "uninspected_directory"}]) == [
        (
            f"{loop} is a PAM directory that stat could not inspect (a loop, a path through "
            "something that is not a directory, or another error)"
        )
    ]


def test_a_pam_directory_that_stat_could_not_inspect_refuses_every_family() -> None:
    directories = {"/etc/pam.d": {}, "/usr/lib/pam.d": DIRECTORY_STAT}
    resolved = {"/usr/lib/pam.d": NOT_A_LINK}
    entries = pam_service_files.pam_service_files([], {}, {}, directories, resolved)["unreadable"]
    pam: list[object] = [
        {"path": "/usr/lib/pam.d/login", "content": "password requisite pam_pwquality.so\n"},
        *entries,
    ]
    pwq = pwquality_decide.pwquality_decide(MINLEN, [], "", pam, MODULES)
    assert (pwq["status"], pwq["text"]) == ("overridden", None)
    assert str(pwq["reason"]).startswith("/etc/pam.d is a PAM directory that stat could not")
    stack = {"/usr/lib/pam.d/login": "auth required pam_unix.so\n"}
    for rule in (DENY, REMEMBER, ENFORCE):
        decision = pam_conf.pam_conf_decision("", rule, stack, entries)
        assert (decision["status"], decision["new_text"]) == ("unreadable_stack", None)
        assert "/etc/pam.d is a PAM directory that stat could not inspect" in str(
            decision["reason"]
        )


@pytest.mark.parametrize(("arguments", "message"), WRONG_SHAPES + LINK_SHAPES)
def test_input_of_the_wrong_shape_is_refused(
    arguments: tuple[object, object, object, object, object], message: str
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
        ([{"path": "/etc/pam.d/x", "kind": "link", "detail": 1}], "needs a text detail, got 1"),
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
    decision = pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", pam, MODULES)
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
    assert pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", pam[:1], MODULES)[
        "status"
    ] == ("compliant")
    with pytest.raises(pwquality_decide.DecisionInputError, match="needs a kind of"):
        pwquality_decide.pwquality_decide(
            MINLEN, [], "", [{"path": "/etc/pam.d/x", "kind": "fifo"}], MODULES
        )


def test_an_unreadable_pam_entry_refuses_a_faillock_rule_as_an_unreadable_stack() -> None:
    stack = {"/etc/pam.d/login": "auth required pam_unix.so\n"}
    assert pam_conf.pam_conf_decision("deny = 4\n", DENY, stack, ())["status"] == "compliant"
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


@pytest.mark.parametrize("main", ["", "minlen = 8\n", "# minlen = 14\n"])
def test_an_unreadable_pam_entry_refuses_a_pwquality_rule_that_would_be_applied(
    main: str,
) -> None:
    pam: list[dict[str, object]] = [
        {"path": "/etc/pam.d/login", "content": "password requisite pam_pwquality.so\n"},
    ]
    applied = pwquality_decide.pwquality_decide(MINLEN, [], main, pam, MODULES)
    assert applied["status"] == "applied"
    assert applied["text"] is not None
    for unreadable in ({**BROKEN, "kind": kind} for kind in pam_files.KINDS):
        decision = pwquality_decide.pwquality_decide(MINLEN, [], main, [*pam, unreadable], MODULES)
        assert decision["status"] == "overridden"
        assert decision["text"] is None
        assert str(decision["reason"]).startswith(
            f"/etc/pam.d/system-auth {pam_files.KINDS[str(unreadable['kind'])]}, which libpam"
        )


@pytest.mark.parametrize(
    ("rule", "text", "module", "status"),
    [
        (DENY, "", "pam_faillock", "applied"),
        (DENY, "deny = 10\n", "pam_faillock", "applied"),
        (REMEMBER, "", "pam_pwhistory", "applied"),
        (REMEMBER, "remember = 5\n", "pam_pwhistory", "applied"),
        (REMEMBER, "remember = 24\n", "pam_pwhistory", "compliant"),
        (ENFORCE, "", "pam_pwhistory", "applied"),
        (ENFORCE, "enforce_for_root\n", "pam_pwhistory", "compliant"),
    ],
)
def test_an_unreadable_pam_entry_refuses_a_faillock_or_pwhistory_rule_whatever_the_file_says(
    rule: dict[str, object], text: str, module: str, status: str
) -> None:
    stack = {"/etc/pam.d/login": "auth required pam_unix.so\n"}
    assert pam_conf.pam_conf_decision(text, rule, stack, ())["status"] == status
    for unreadable in ({**BROKEN, "kind": kind} for kind in pam_files.KINDS):
        decision = pam_conf.pam_conf_decision(text, rule, stack, [unreadable])
        assert decision["status"] == "unreadable_stack"
        assert decision["new_text"] is None
        assert decision["reason"] == (
            "libpam reads service files that the collection cannot read as it does "
            f"(/etc/pam.d/system-auth {pam_files.KINDS[str(unreadable['kind'])]}), so it cannot "
            f"tell whether a {module} line overrides the file; nothing is written"
        )


def test_a_link_that_resolves_below_proc_sys_or_dev_is_unreadable_and_never_read() -> None:
    names = ("environ", "kernel", "shm", "dev", "site")
    links = [entry(f"/etc/pam.d/{name}", islnk=True) for name in names]
    targets = {f"/etc/pam.d/{name}": FILE_STAT for name in names}
    sources = {
        "environ": "/proc/4242/environ",
        "kernel": "/sys/kernel/x",
        "shm": "/dev/disk/by-label/password",
        "dev": "/dev",
        "site": "/etc/security/site",
    }
    resolved = RESOLVED | {f"/etc/pam.d/{name}": link_to(sources[name]) for name in names}
    result = pam_service_files.pam_service_files(links, targets, {}, DIRECTORIES, resolved)
    assert result == {
        "read": ["/etc/pam.d/site"],
        "unreadable": [
            {"path": f"/etc/pam.d/{name}", "kind": "virtual_file", "detail": sources[name]}
            for name in ("dev", "environ", "kernel", "shm")
        ],
    }
    assert pam_files.describe(result["unreadable"])[1] == (
        "/etc/pam.d/environ resolves to a path below /proc, /sys or /dev, which can read "
        "differently in the process that calls libpam than in the collection's: /proc/4242/environ"
    )
    assert not pam_files.is_virtual("/procfs/x")
    assert not pam_files.is_virtual("/device")


def test_a_link_whose_resolution_is_missing_or_failed_is_never_read() -> None:
    names = ("unresolved", "failed", "gone")
    links = [entry(f"/etc/pam.d/{name}", islnk=True) for name in names]
    targets = {f"/etc/pam.d/{name}": FILE_STAT for name in names}
    resolved = RESOLVED | {
        "/etc/pam.d/failed": {"msg": "Permission denied"},
        "/etc/pam.d/gone": {},
    }
    assert pam_service_files.pam_service_files(links, targets, {}, DIRECTORIES, resolved) == {
        "read": [],
        "unreadable": [
            {"path": "/etc/pam.d/failed", "kind": "unfollowed_link", "detail": "Permission denied"},
            {
                "path": "/etc/pam.d/gone",
                "kind": "unfollowed_link",
                "detail": "it could not be resolved",
            },
            {
                "path": "/etc/pam.d/unresolved",
                "kind": "unfollowed_link",
                "detail": "it was not resolved",
            },
        ],
    }


def test_a_regular_file_that_resolution_finds_is_no_longer_a_link_is_read() -> None:
    links = [entry("/etc/pam.d/swapped", islnk=True)]
    targets = {"/etc/pam.d/swapped": FILE_STAT}
    resolved = RESOLVED | {"/etc/pam.d/swapped": NOT_A_LINK}
    assert pam_service_files.pam_service_files(links, targets, {}, DIRECTORIES, resolved) == {
        "read": ["/etc/pam.d/swapped"],
        "unreadable": [],
    }


def test_a_pam_directory_that_resolves_below_proc_is_unreadable_and_nothing_in_it_is_read() -> None:
    entries = [
        entry("/usr/share/pam.d/environ", isreg=True),
        entry("/etc/pam.d/login", isreg=True),
    ]
    directories = DIRECTORIES | {"/usr/share/pam.d": DIRECTORY_STAT, "/usr/lib/pam.d": {}}
    resolved = RESOLVED | {"/usr/share/pam.d": link_to("/proc/self")}
    assert pam_service_files.pam_service_files(entries, {}, {}, directories, resolved) == {
        "read": ["/etc/pam.d/login"],
        "unreadable": [
            {"path": "/usr/lib/pam.d", "kind": "uninspected_directory"},
            {"path": "/usr/share/pam.d", "kind": "virtual_file", "detail": "/proc/self"},
        ],
    }
    unresolved = pam_service_files.pam_service_files(
        entries, {}, {}, directories | {"/usr/lib/pam.d": DIRECTORY_STAT}, RESOLVED
    )
    assert unresolved["unreadable"] == [
        {
            "path": "/usr/lib/pam.d",
            "kind": "uninspected_directory",
            "detail": "it was not resolved",
        },
        {
            "path": "/usr/share/pam.d",
            "kind": "uninspected_directory",
            "detail": "it was not resolved",
        },
    ]
    assert unresolved["read"] == ["/etc/pam.d/login"]


@pytest.mark.parametrize(
    ("directories", "fallback"),
    [
        ({}, True),
        ({"/etc/pam.d": {"exists": False}, "/usr/lib/pam.d": {"exists": False}}, True),
        ({"/etc/pam.d": FILE_STAT, "/usr/lib/pam.d": {"exists": False}}, True),
        ({"/etc/pam.d": {"msg": LOOP}, "/usr/lib/pam.d": {"exists": False}}, True),
        ({"/usr/share/pam.d": DIRECTORY_STAT, "/etc/pam.d": {"exists": False}}, True),
        ({"/etc/pam.d": DIRECTORY_STAT}, False),
        ({"/etc/pam.d": {"exists": False}, "/usr/lib/pam.d": DIRECTORY_STAT}, False),
    ],
)
def test_etc_pam_conf_is_unreadable_when_libpam_would_read_it_instead_of_the_directories(
    directories: dict[str, object], *, fallback: bool
) -> None:
    resolved = dict.fromkeys(directories, NOT_A_LINK)
    unreadable = pam_service_files.pam_service_files([], {}, {}, directories, resolved)[
        "unreadable"
    ]
    entry_of_pam_conf = {"path": "/etc/pam.conf", "kind": "pam_conf_fallback"}
    assert (entry_of_pam_conf in unreadable) is fallback


@pytest.mark.parametrize(
    "unreadable",
    [
        {"path": "/etc/pam.conf", "kind": "pam_conf_fallback"},
        {"path": "/etc/pam.d/environ", "kind": "virtual_file", "detail": "/proc/4242/environ"},
        {"path": "/etc/pam.d/loop", "kind": "unfollowed_link", "detail": LOOP},
    ],
)
def test_the_pam_conf_fallback_and_a_virtual_file_refuse_every_family_with_the_detail(
    unreadable: dict[str, object],
) -> None:
    described = pam_files.describe([unreadable])[0]
    assert str(unreadable.get("detail", "")) in described
    pam: list[object] = [
        {"path": "/etc/pam.d/login", "content": "password requisite pam_pwquality.so\n"},
        unreadable,
    ]
    pwq = pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", pam, MODULES)
    assert (pwq["status"], pwq["text"]) == ("overridden", None)
    assert str(pwq["reason"]).startswith(described + ", which libpam may open")
    stack = {"/etc/pam.d/login": "auth required pam_unix.so\n"}
    for rule in (DENY, REMEMBER, ENFORCE):
        decision = pam_conf.pam_conf_decision("", rule, stack, [unreadable])
        assert (decision["status"], decision["new_text"]) == ("unreadable_stack", None)
        assert f"({described})" in str(decision["reason"])


@pytest.mark.parametrize(
    ("target", "source", "kind", "detail"),
    [
        ("/proc/self/cwd/pwq", "/home/ansible/pwq", "virtual_file", "/proc/self/cwd/pwq"),
        ("../../proc/self/cwd/pwq", "/root/pwq", "virtual_file", "../../proc/self/cwd/pwq"),
        ("//proc/self/root/etc/x", "/etc/x", "virtual_file", "//proc/self/root/etc/x"),
        ("/dev/fd/3", "/etc/security/opened", "virtual_file", "/dev/fd/3"),
        (
            "/sys/../proc/self/cwd/x",
            "/root/x",
            "indirect_link",
            "/sys/../proc/self/cwd/x, which resolves to /root/x",
        ),
        ("/proc/self/environ", "/proc/4242/environ", "virtual_file", "/proc/4242/environ"),
        (
            "/etc/security/hop",
            "/etc/security/site",
            "indirect_link",
            "/etc/security/hop, which resolves to /etc/security/site",
        ),
        (
            "/etc/security/sub/../site",
            "/etc/security/site",
            "indirect_link",
            "/etc/security/sub/../site, which resolves to /etc/security/site",
        ),
        (
            "site",
            "/etc/security/site",
            "indirect_link",
            "site, which resolves to /etc/security/site",
        ),
        ("../security/site", "/etc/security/site", None, None),
        ("/../etc/security/./site", "/etc/security/site", None, None),
        ("../../../etc/security/site", "/etc/security/site", None, None),
    ],
)
def test_a_link_is_read_only_when_its_target_is_the_path_that_it_resolves_to(
    target: str, source: str, kind: str | None, detail: str | None
) -> None:
    links = [entry("/etc/pam.d/site", islnk=True)]
    targets = {"/etc/pam.d/site": FILE_STAT}
    resolved = RESOLVED | {"/etc/pam.d/site": link_to(target, source)}
    result = pam_service_files.pam_service_files(links, targets, {}, DIRECTORIES, resolved)
    if kind is None:
        assert result == {"read": ["/etc/pam.d/site"], "unreadable": []}
        return
    assert result == {
        "read": [],
        "unreadable": [{"path": "/etc/pam.d/site", "kind": kind, "detail": detail}],
    }
    pam: list[object] = [
        {"path": "/etc/pam.d/login", "content": "password requisite pam_pwquality.so\n"},
        *result["unreadable"],
    ]
    pwq = pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", pam, MODULES)
    assert (pwq["status"], pwq["text"]) == ("overridden", None)
    assert str(pwq["reason"]).startswith(
        f"/etc/pam.d/site {pam_files.KINDS[kind]}: {detail}, which libpam may open"
    )
    decision = pam_conf.pam_conf_decision("", DENY, {}, result["unreadable"])
    assert (decision["status"], decision["new_text"]) == ("unreadable_stack", None)


def test_a_link_through_the_working_directory_of_the_reader_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pam = tmp_path / "pam.d"
    pam.mkdir()
    (tmp_path / "pwq").write_text("password requisite pam_pwquality.so minlen=14\n")
    (tmp_path / "hop").symlink_to("/proc/self/cwd/pwq")
    (pam / "cwd").symlink_to("/proc/self/cwd/pwq")
    (pam / "chained").symlink_to(tmp_path / "hop")
    (pam / "plain").symlink_to(tmp_path / "pwq")
    monkeypatch.chdir(tmp_path)
    links = sorted(pam.iterdir())
    entries = [lstat_entry(path) for path in links]
    targets = {str(path): followed_stat(path) for path in links}
    assert all(stat["isreg"] is True for stat in targets.values())
    resolved = (
        RESOLVED | {str(pam): resolution(pam)} | {str(path): resolution(path) for path in links}
    )
    assert resolution(pam / "cwd")["lnk_source"] == os.path.realpath(tmp_path / "pwq")
    directories = {**DIRECTORIES, str(pam): followed_stat(pam)}
    result = pam_files.sort_entries(entries, targets, [], directories, resolved)
    real = os.path.realpath(tmp_path / "pwq")
    assert result == {
        "read": [str(pam / "plain")],
        "unreadable": [
            {
                "path": str(pam / "chained"),
                "kind": "indirect_link",
                "detail": f"{tmp_path / 'hop'}, which resolves to {real}",
            },
            {"path": str(pam / "cwd"), "kind": "virtual_file", "detail": "/proc/self/cwd/pwq"},
        ],
    }


def test_a_pam_directory_reached_through_a_further_link_is_unreadable() -> None:
    entries = [entry("/usr/lib/pam.d/login", isreg=True), entry("/etc/pam.d/sshd", isreg=True)]
    directories = DIRECTORIES | {"/usr/lib/pam.d": DIRECTORY_STAT}
    resolved = RESOLVED | {"/usr/lib/pam.d": link_to("/opt/pam.d", "/srv/pam.d")}
    assert pam_service_files.pam_service_files(entries, {}, {}, directories, resolved) == {
        "read": ["/etc/pam.d/sshd"],
        "unreadable": [
            {
                "path": "/usr/lib/pam.d",
                "kind": "indirect_link",
                "detail": "/opt/pam.d, which resolves to /srv/pam.d",
            }
        ],
    }
