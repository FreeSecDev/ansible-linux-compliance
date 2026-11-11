"""The real libpam is the oracle of the pwquality family's PAM reading (FREES-212).

``make pam-reader-verdicts`` runs every ``libpam`` case of ``tools.pam.reader_corpus`` with the
real libpam of both Molecule images, ``pam_pwquality.so`` replaced by a module that records the
arguments that libpam passes to it, and records them in the ``libpam_cases`` of
``tests/fixtures/pam_conf/reader_verdicts.json``. These tests rebuild, for every case and image,
what the role would pass to the ``pwquality_decide`` filter (the entries of the PAM directories
sorted by ``pam_service_files`` and the text of every file it reads) and require that the
decision is the one expected, that no decision is ``compliant`` or ``applied`` while libpam passes
an argument that loosens the rule, that every argument that libpam passes is one that the family
reads whenever it reads the files at all, and that the line assembly of ``pam_reader`` matches
libpam's own wherever the family relies on it. The ``faillock`` and ``pwhistory`` families refuse
on the same unreadable entries.
"""

from __future__ import annotations

import functools
import json
import posixpath
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    pam_conf,
    pam_service_files,
    pwquality_decide,
    pwquality_pam_modules,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pam_reader,
    pwquality,
)
from tools.pam import reader_corpus

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TABLE = REPOSITORY_ROOT / reader_corpus.TABLE
PLATFORMS = ("ubuntu", "rhel_compatible")
VARIANTS = {"ubuntu": "buffer", "rhel_compatible": "getline"}
SHIPPED_DIRECTORIES = {
    "ubuntu": ("/etc/pam.d", "/usr/lib/pam.d"),
    "rhel_compatible": reader_corpus.PAM_DIRECTORIES,
}
PROCESS_ENVIRON = "/proc/4242/environ"
MODULE_CWD = "/home/ansible"
FACTS = {"ubuntu": ("Debian", "x86_64"), "rhel_compatible": ("RedHat", "x86_64")}
SHIPPED_MODULES = ("pam_deny.so", "pam_permit.so", "pam_pwquality.so", "pam_unix.so")
FILE_STAT = {"exists": True, "isreg": True, "isdir": False}
DIRECTORY_STAT = {"exists": True, "isreg": False, "isdir": True}
NOT_A_LINK = {"exists": True, "islnk": False}
MINLEN = {
    "setting": "minlen",
    "value": "14",
    "method": "main_file",
    "main": "/etc/security/pwquality.conf",
    "dropin": "/etc/security/pwquality.conf.d/50-freesecdev-minlen.conf",
    "content": "",
}
DENY = {
    "reader": "faillock",
    "setting": "deny",
    "comparison": "at_most",
    "required": "4",
    "stack_checked": True,
}
ARGUMENTS = "pam_pwquality arguments override the file"
UNASSEMBLED = "has a NUL byte or a line of 1023 bytes or more"
DIFFERENTLY = "assemble differently"
INCLUDES = "includes "
VIRTUAL = "resolves to a path below /proc, /sys or /dev"
INDIRECT = "is a symbolic link whose target is reached through a further symbolic link"
PAM_CONF = "/etc/pam.conf is what libpam reads instead of the service files"
EXPECTED: dict[str, tuple[str, str | None]] = {
    "libpam-plain": ("overridden", ARGUMENTS),
    "libpam-plain-required": ("compliant", None),
    "libpam-local-users-only": ("compliant", None),
    "libpam-comment-backslash": ("overridden", ARGUMENTS),
    "libpam-comment-1022-bytes": ("compliant", None),
    "libpam-comment-1023-bytes": ("overridden", UNASSEMBLED),
    "libpam-nul": ("overridden", UNASSEMBLED),
    "libpam-bracket-argument": ("overridden", ARGUMENTS),
    "libpam-glued-control": ("overridden", ARGUMENTS),
    "libpam-upper-type": ("overridden", ARGUMENTS),
    "libpam-silent-type": ("overridden", ARGUMENTS),
    "libpam-cr-argument": ("overridden", ARGUMENTS),
    "libpam-continued-arguments": ("overridden", ARGUMENTS),
    "libpam-continued-blank": ("overridden", DIFFERENTLY),
    "libpam-continued-comment": ("overridden", DIFFERENTLY),
    "libpam-continued-at-end": ("overridden", ARGUMENTS),
    "libpam-include-upper": ("overridden", INCLUDES),
    "libpam-include-dash": ("overridden", INCLUDES),
    "libpam-include-continued-target": ("overridden", INCLUDES),
    "libpam-include-continued-control": ("overridden", INCLUDES),
    "libpam-include-at-continued": ("overridden", INCLUDES),
    "libpam-substack-upper": ("overridden", INCLUDES),
    "libpam-include-silent-type": ("overridden", INCLUDES),
    "libpam-include-name": ("overridden", ARGUMENTS),
    "libpam-environ-link": ("overridden", VIRTUAL),
    "libpam-pam-conf-fallback": ("overridden", PAM_CONF),
    "libpam-pam-conf-vendor-directory": ("overridden", PAM_CONF),
    "libpam-pam-conf-pam-d-is-a-file": ("overridden", PAM_CONF),
    "libpam-pam-conf-ignored": ("compliant", None),
    "libpam-cwd-link": ("overridden", VIRTUAL),
    "libpam-chained-link": ("overridden", INDIRECT),
    "libpam-renamed-module": ("overridden", ARGUMENTS),
    "libpam-dot-module": ("overridden", ARGUMENTS),
    "libpam-module-copy-elsewhere": ("overridden", ARGUMENTS),
    "libpam-link-to-module-copy-elsewhere": ("overridden", ARGUMENTS),
    "libpam-sufficient-skip": ("overridden", ARGUMENTS),
    "libpam-sufficient-skip-required": ("compliant", None),
}
CASES = {case.case_id: case for case in reader_corpus.LIBPAM_CASES}


@functools.cache
def rows() -> dict[str, dict[str, object]]:
    document = cast("dict[str, object]", json.loads(TABLE.read_text(encoding="utf-8")))
    return {
        str(row["id"]): row for row in cast("list[dict[str, object]]", document["libpam_cases"])
    }


def calls(case_id: str, platform: str) -> list[list[str]]:
    readings = cast("dict[str, dict[str, object]]", rows()[case_id]["readings"])
    return cast("list[list[str]]", readings[platform]["calls"])


def loosens(argument: str) -> bool:
    """Return whether libpwquality would take an argument over ``minlen = 14`` or stop enforcing."""
    data = pwquality.text_bytes(argument)
    return pwquality.option_override(data, "minlen", 14) or (
        pwquality.option_value(data) == ("enforcing", 0)
    )


def hop(link: str, target: str) -> str:
    """Return the path that the target of ``link`` names, as the kernel joins it."""
    return posixpath.normpath(posixpath.join(posixpath.dirname(link), target))


def module_realpath(case: reader_corpus.LibpamCase, path: str) -> str:
    """Return what ``os.path.realpath`` gives for ``path`` in the Ansible module's process.

    The links of the case are followed; ``/proc/self/environ`` is the module's own environment
    and ``/proc/self/cwd`` its working directory, which is not where libpam runs.
    """
    links = dict(case.links)
    while path in links:
        path = hop(path, links[path])
    if path == "/proc/self/environ":
        return PROCESS_ENVIRON
    if path.startswith("/proc/self/cwd/"):
        return MODULE_CWD + path.removeprefix("/proc/self/cwd")
    return path


def module_stat(case: reader_corpus.LibpamCase, platform: str, path: str) -> dict[str, object]:
    """Return the stat, through links and with a checksum, of a module path on the image.

    The modules of :data:`SHIPPED_MODULES` are in the module directory of the image, each with
    its own checksum; a link of the case leads to one of them, and a copy of the case is a
    regular file with a checksum of its own.
    """
    directory = str(pwquality.module_directory(*FACTS[platform]))
    links = dict(case.links)
    path = posixpath.normpath(path)
    while path in links:
        path = hop(path, links[path])
    copies = dict(case.copies)
    if path in copies:
        return {"exists": True, "isreg": True, "checksum": f"sha256 of a copy of {copies[path]}"}
    name = path.removeprefix(directory)
    if name not in SHIPPED_MODULES:
        return {"exists": False}
    return {"exists": True, "isreg": True, "checksum": f"sha256 of {name}"}


def module_link_stat(case: reader_corpus.LibpamCase, platform: str, path: str) -> dict[str, object]:
    """Return the stat, without following a link, of a module path on the image (FREES-205).

    A link of the case has the path that ``os.path.realpath`` gives as ``lnk_source``; any other
    path is not a link, or does not exist when the stat through links finds nothing either.
    """
    links = dict(case.links)
    path = posixpath.normpath(path)
    if path in links:
        return {
            "exists": True,
            "islnk": True,
            "lnk_source": module_realpath(case, path),
            "lnk_target": links[path],
        }
    if module_stat(case, platform, path)["exists"] is not True:
        return {"exists": False}
    return dict(NOT_A_LINK)


def modules_of(
    case: reader_corpus.LibpamCase, platform: str, view: list[object]
) -> dict[str, object]:
    """Return what the role passes to ``pwquality_decide`` as the modules of the PAM lines."""
    plan = pwquality_pam_modules.pwquality_pam_modules(view, *FACTS[platform])
    paths = cast("list[str]", plan["paths"])
    return {
        "directory": plan["directory"],
        "stats": {path: module_stat(case, platform, path) for path in paths},
        "links": {path: module_link_stat(case, platform, path) for path in paths},
    }


def role_view(case: reader_corpus.LibpamCase, platform: str) -> list[object]:
    """Return the PAM list that the role passes to ``pwquality_decide`` on the image of a case.

    The PAM directories are those that the image ships, less those that the case removes, plus
    those that its files create; a case file at the path of a directory replaces it. Only the
    files of the case are modelled, not those that the image ships.
    """
    files = dict(case.files)
    links = dict(case.links)
    directories: dict[str, object] = {}
    for directory in reader_corpus.PAM_DIRECTORIES:
        created = any(path.startswith(directory + "/") for path in (*files, *links))
        if directory in files:
            directories[directory] = FILE_STAT
        elif created or (directory in SHIPPED_DIRECTORIES[platform] and directory not in case.away):
            directories[directory] = DIRECTORY_STAT
        else:
            directories[directory] = {"exists": False}
    listed = [name for name, stat in directories.items() if stat == DIRECTORY_STAT]
    entries: list[object] = [
        {"path": path, "isreg": True, "isdir": False, "islnk": False}
        for path in files
        if path.rpartition("/")[0] in listed
    ]
    entries += [
        {"path": path, "isreg": False, "isdir": False, "islnk": True}
        for path in links
        if path.rpartition("/")[0] in listed
    ]
    sources = {path: module_realpath(case, path) for path in links}
    resolved: dict[str, object] = dict.fromkeys(listed, NOT_A_LINK)
    resolved.update(
        {
            path: {"exists": True, "islnk": True, "lnk_source": source, "lnk_target": links[path]}
            for path, source in sources.items()
        }
    )
    targets = dict.fromkeys(links, FILE_STAT)
    sorted_entries = pam_service_files.pam_service_files(
        entries, targets, {}, directories, resolved
    )
    texts = files | {path: files.get(source, "") for path, source in sources.items()}
    read = cast("list[str]", sorted_entries["read"])
    return [{"path": path, "content": texts[path]} for path in read] + sorted_entries["unreadable"]


def decide(case: reader_corpus.LibpamCase, platform: str) -> dict[str, object]:
    view = role_view(case, platform)
    modules = modules_of(case, platform, view)
    return pwquality_decide.pwquality_decide(MINLEN, [], "minlen = 14\n", view, modules)


def test_the_table_records_every_libpam_case_of_the_corpus_on_both_images() -> None:
    assert set(rows()) == set(CASES) == set(EXPECTED)
    for case_id, case in CASES.items():
        row = rows()[case_id]
        assert row["files"] == [list(item) for item in case.files]
        assert row["links"] == [list(item) for item in case.links]
        assert row["away"] == list(case.away)
        assert row["environment"] == case.environment
        assert row["copies"] == [list(item) for item in case.copies]
        readings = cast("dict[str, dict[str, object]]", row["readings"])
        assert set(readings) == set(PLATFORMS)
        assert all(
            set(reading) == set(reader_corpus.LIBPAM_READING_KEYS) for reading in readings.values()
        )


@pytest.mark.parametrize("case_id", sorted(CASES))
@pytest.mark.parametrize("platform", PLATFORMS)
def test_the_decision_is_the_expected_one_and_never_looser_than_libpam(
    case_id: str, platform: str
) -> None:
    decision = decide(CASES[case_id], platform)
    status, reason = EXPECTED[case_id]
    assert decision["status"] == status, decision
    assert reason is None or reason in str(decision["reason"]), decision
    if any(loosens(argument) for call in calls(case_id, platform) for argument in call):
        assert (decision["status"], decision["text"]) == ("overridden", None)


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_every_argument_that_libpam_passes_is_read_when_the_files_are_read(case_id: str) -> None:
    case = CASES[case_id]
    for platform in PLATFORMS:
        view = role_view(case, platform)
        files = [
            (str(item["path"]), str(item["content"]))
            for item in cast("list[dict[str, object]]", view)
            if "content" in item
        ]
        modules = modules_of(case, platform, view)
        stats = cast("dict[str, dict[str, object]]", modules["stats"])
        links = cast("dict[str, dict[str, object]]", modules["links"])
        identities = pwquality.Modules(cast("str", modules["directory"]), stats, links)
        reading = pwquality.read_pam(pwquality.PamStack(files, identities))
        if reading.problems or reading.includes or len(files) < len(view):
            continue
        model = [argument for _path, argument in reading.arguments]
        for call in calls(case_id, platform):
            assert all(argument in model for argument in call), (platform, call, model)


def test_the_cases_that_loosen_the_rule_on_one_image_only_are_refused_on_both() -> None:
    one_image = {
        case_id
        for case_id in CASES
        if len(
            {
                platform
                for platform in PLATFORMS
                if any(loosens(argument) for call in calls(case_id, platform) for argument in call)
            }
        )
        == 1
    }
    assert one_image == {
        "libpam-comment-1023-bytes",
        "libpam-continued-blank",
        "libpam-continued-comment",
        "libpam-include-upper",
        "libpam-include-dash",
        "libpam-include-at-continued",
        "libpam-pam-conf-vendor-directory",
    }
    for case_id in one_image:
        assert {decide(CASES[case_id], platform)["status"] for platform in PLATFORMS} == {
            "overridden"
        }


@pytest.mark.parametrize(
    "case_id",
    sorted(case_id for case_id, case in CASES.items() if case.stack),
)
def test_the_service_file_is_assembled_as_libpam_does_wherever_the_family_reads_it(
    case_id: str,
) -> None:
    case = CASES[case_id]
    stack_lines = cast("dict[str, dict[str, object]]", rows()[case_id]["stack_lines"])
    if pam_reader.unassembled(case.stack):
        assert stack_lines["ubuntu"]["lines"] != stack_lines["rhel_compatible"]["lines"] or (
            "\0" in case.stack
        )
        return
    for platform in PLATFORMS:
        model = [
            pam_reader.strtok(line)
            for line in pam_reader.assembled_lines(case.stack, VARIANTS[platform], exact=True)
        ]
        assert model == stack_lines[platform]["lines"], platform


@pytest.mark.parametrize(
    "case_id",
    [
        "libpam-environ-link",
        "libpam-pam-conf-fallback",
        "libpam-pam-conf-pam-d-is-a-file",
        "libpam-cwd-link",
        "libpam-chained-link",
    ],
)
def test_the_faillock_and_pwhistory_families_refuse_on_the_same_entries(case_id: str) -> None:
    for platform in PLATFORMS:
        view = cast("list[dict[str, object]]", role_view(CASES[case_id], platform))
        unreadable = [item for item in view if "kind" in item]
        stack = {str(item["path"]): str(item["content"]) for item in view if "content" in item}
        decision = pam_conf.pam_conf_decision("deny = 4\n", DENY, stack, unreadable)
        assert (decision["status"], decision["new_text"]) == ("unreadable_stack", None)


def test_a_module_reached_under_another_name_is_read_as_libpam_loads_it() -> None:
    case = CASES["libpam-renamed-module"]
    assert "pam_pwquality" not in reader_corpus.RENAMED_MODULE
    for platform in PLATFORMS:
        assert calls(case.case_id, platform) == [["minlen=1", "enforcing=0"]]
        decision = decide(case, platform)
        assert decision["reason"] == (
            f"pam_pwquality arguments override the file: {reader_corpus.SERVICE_FILE}: minlen=1"
        )


def test_the_family_decides_the_values_not_whether_libpam_runs_pam_pwquality() -> None:
    for platform in PLATFORMS:
        for case_id in ("libpam-sufficient-skip", "libpam-sufficient-skip-required"):
            assert calls(case_id, platform) == []
        required = decide(CASES["libpam-sufficient-skip-required"], platform)
        assert required["status"] == "compliant"
        assert decide(CASES["libpam-sufficient-skip"], platform)["status"] == "overridden"
