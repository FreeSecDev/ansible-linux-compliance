from __future__ import annotations

import errno
import fcntl
import os
import runpy
import stat
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    fileio,
)

OWNER = os.getuid()
OTHER = OWNER + 1
NAME = "state.json"


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return tmp_path / "base"


@pytest.fixture
def directory(base: Path) -> fileio.SafeDirectory:
    opened = fileio.open_directory(str(base / "state"), owner_uid=OWNER, create=True)
    assert opened is not None
    return opened


def zeros(count: int) -> bytes:
    return b"\x00" * count


def ones(count: int) -> bytes:
    return b"\x01" * count


def foreign(path: Path, owner: int) -> fileio.SafeDirectory:
    return fileio.SafeDirectory(os.open(path, os.O_RDONLY | os.O_DIRECTORY), owner_uid=owner)


def patch_os(monkeypatch: pytest.MonkeyPatch, name: str, replacement: Any) -> None:
    original = getattr(os, name)
    supported = set(os.supports_dir_fd)
    if original in supported:
        supported.add(replacement)
    monkeypatch.setattr(os, name, replacement)
    monkeypatch.setattr(os, "supports_dir_fd", supported)


def reason_of(call: Any, *arguments: Any, **keywords: Any) -> str:
    with pytest.raises(fileio.SafeFileError) as excinfo:
        call(*arguments, **keywords)
    assert excinfo.value.reason in fileio.REASONS
    return excinfo.value.reason


def open_descriptors() -> int:
    return len(list(Path("/proc/self/fd").iterdir()))


def test_open_directory_creates_every_missing_component_with_mode_0700(base: Path) -> None:
    opened = fileio.open_directory(str(base / "a" / "b"), owner_uid=OWNER, create=True)
    assert opened is not None
    opened.close()
    for part in (base / "a", base / "a" / "b"):
        assert stat.S_IMODE(part.stat().st_mode) == 0o700


def test_open_directory_reopens_an_existing_directory(base: Path) -> None:
    first = fileio.open_directory(str(base / "a"), owner_uid=OWNER, create=True)
    assert first is not None
    first.close()
    again = fileio.open_directory(str(base / "a"), owner_uid=OWNER)
    assert again is not None
    again.close()


def test_open_directory_for_reading_does_not_create_anything(base: Path) -> None:
    assert fileio.open_directory(str(base / "missing"), owner_uid=OWNER) is None
    assert not base.exists()


@pytest.mark.skipif(OWNER == 0, reason="the expected owner is the current user")
def test_open_directory_default_owner_is_root(base: Path) -> None:
    base.mkdir(mode=0o700)
    assert reason_of(fileio.open_directory, str(base)) == "wrong_owner"


@pytest.mark.skipif(OWNER != 0, reason="needs root to be the current user")
def test_open_directory_default_owner_accepts_root(base: Path) -> None:
    base.mkdir(mode=0o700)
    opened = fileio.open_directory(str(base))
    assert opened is not None
    opened.close()


@pytest.mark.parametrize(
    "path",
    [
        "relative/path",
        "",
        "/",
        "//",
        "/a/./b",
        "/a/../b",
        "/a/\x00b",
        "/" + "a" * fileio.MAX_PATH_LENGTH,
        None,
        b"/bytes",
    ],
)
def test_open_directory_rejects_unsafe_paths(path: Any) -> None:
    assert reason_of(fileio.open_directory, path, owner_uid=OWNER, create=True) == "unsafe_path"


def test_open_directory_refuses_a_symlinked_final_directory(base: Path, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    base.mkdir()
    (base / "state").symlink_to(target)
    assert (
        reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER, create=True)
        == "symlink"
    )
    assert reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER) == "symlink"


def test_open_directory_refuses_a_symlinked_ancestor(base: Path, tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "state").mkdir(parents=True, mode=0o700)
    base.symlink_to(real)
    assert reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER) == "symlink"
    assert (
        reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER, create=True)
        == "symlink"
    )
    assert not (real / "created").exists()


def test_open_directory_refuses_a_dangling_symlink_even_when_creating(
    base: Path, tmp_path: Path
) -> None:
    base.mkdir()
    (base / "state").symlink_to(tmp_path / "nowhere")
    assert (
        reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER, create=True)
        == "symlink"
    )
    assert not (tmp_path / "nowhere").exists()


def test_open_directory_refuses_a_file_in_place_of_a_directory(base: Path) -> None:
    base.mkdir()
    (base / "state").write_text("x", encoding="utf-8")
    assert reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER) == "not_directory"
    assert (
        reason_of(fileio.open_directory, str(base / "state" / "child"), owner_uid=OWNER)
        == "not_directory"
    )


def test_open_directory_refuses_the_wrong_owner(base: Path) -> None:
    base.mkdir(mode=0o700)
    before = open_descriptors()
    assert reason_of(fileio.open_directory, str(base), owner_uid=OTHER) == "wrong_owner"
    assert open_descriptors() == before


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o705, 0o770, 0o707, 0o701, 0o710])
def test_open_directory_refuses_group_or_world_permission_bits(base: Path, mode: int) -> None:
    base.mkdir()
    base.chmod(mode)
    before = open_descriptors()
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER) == "unsafe_mode"
    assert open_descriptors() == before


def test_open_directory_does_not_repair_an_existing_directory(base: Path) -> None:
    base.mkdir()
    base.chmod(0o755)
    reason_of(fileio.open_directory, str(base), owner_uid=OWNER, create=True)
    assert stat.S_IMODE(base.stat().st_mode) == 0o755


def test_open_directory_needs_directory_relative_operations(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_support: set[Any] = set()
    monkeypatch.setattr(os, "supports_dir_fd", no_support)
    assert (
        reason_of(fileio.open_directory, str(base), owner_uid=OWNER, create=True)
        == "unsupported_platform"
    )


def test_open_directory_reports_an_unreadable_root(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open

    def deny_root(path: str, *arguments: Any, **keywords: Any) -> int:
        if path == "/" and not keywords:
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, *arguments, **keywords)

    patch_os(monkeypatch, "open", deny_root)
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER) == "io_error"


def test_creating_a_directory_survives_a_concurrent_creator(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base.mkdir(mode=0o700)
    real_open = os.open
    calls: list[str] = []

    def vanish_once(path: str, flags: int, *arguments: Any, **keywords: Any) -> int:
        if path == base.name and not calls:
            calls.append(path)
            raise FileNotFoundError(errno.ENOENT, "gone")
        return real_open(path, flags, *arguments, **keywords)

    patch_os(monkeypatch, "open", vanish_once)
    opened = fileio.open_directory(str(base), owner_uid=OWNER, create=True)
    assert opened is not None
    opened.close()


def test_open_failures_are_reported_as_errors(base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base.mkdir(mode=0o700)
    real_open = os.open

    def fail(code: int) -> Any:
        def opener(path: str, *arguments: Any, **keywords: Any) -> int:
            if path == base.name:
                raise OSError(code, "boom")
            return real_open(path, *arguments, **keywords)

        return opener

    patch_os(monkeypatch, "open", fail(errno.EACCES))
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER) == "io_error"
    patch_os(monkeypatch, "open", fail(errno.ELOOP))
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER) == "symlink"
    patch_os(monkeypatch, "open", fail(errno.EMLINK))
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER) == "symlink"


def test_directory_creation_failures_are_reported_as_errors(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(*_arguments: Any, **_keywords: Any) -> None:
        raise PermissionError(errno.EACCES, "denied")

    patch_os(monkeypatch, "mkdir", deny)
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER, create=True) == "io_error"


def test_a_directory_that_cannot_be_reopened_after_creation_is_an_error(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open
    seen: list[str] = []

    def second_open_fails(path: str, *arguments: Any, **keywords: Any) -> int:
        if path == base.name:
            seen.append(path)
            if len(seen) == 2:
                raise OSError(errno.EIO, "boom")
        return real_open(path, *arguments, **keywords)

    patch_os(monkeypatch, "open", second_open_fails)
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER, create=True) == "io_error"


def test_a_directory_whose_mode_cannot_be_set_is_an_error(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(*_arguments: Any) -> None:
        raise PermissionError(errno.EPERM, "denied")

    before = open_descriptors()
    monkeypatch.setattr(os, "fchmod", deny)
    assert reason_of(fileio.open_directory, str(base), owner_uid=OWNER, create=True) == "io_error"
    assert open_descriptors() == before


def test_names_must_be_plain(directory: fileio.SafeDirectory) -> None:
    for bad in ["", ".", "..", "a/b", "/abs", "a\x00b", "x" * 201, None, 3]:
        assert reason_of(directory.read, bad, 10) == "unsafe_path"
        assert reason_of(directory.write, bad, b"x") == "unsafe_path"


def test_read_of_a_missing_file_is_none(directory: fileio.SafeDirectory) -> None:
    assert directory.read(NAME, 100) is None


def test_write_then_read_round_trips_with_mode_0600(
    directory: fileio.SafeDirectory, base: Path
) -> None:
    directory.write(NAME, b"hello")
    assert directory.read(NAME, 100) == b"hello"
    target = base / "state" / NAME
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert sorted(path.name for path in (base / "state").iterdir()) == [NAME]


def test_write_replaces_the_old_content_atomically(
    directory: fileio.SafeDirectory, base: Path
) -> None:
    directory.write(NAME, b"one")
    inode = (base / "state" / NAME).stat().st_ino
    directory.write(NAME, b"two")
    assert directory.read(NAME, 100) == b"two"
    assert (base / "state" / NAME).stat().st_ino != inode


def test_write_ignores_a_loose_umask(directory: fileio.SafeDirectory, base: Path) -> None:
    previous = os.umask(0)
    try:
        directory.write(NAME, b"x")
    finally:
        os.umask(previous)
    assert stat.S_IMODE((base / "state" / NAME).stat().st_mode) == 0o600


def test_write_replaces_a_symlink_without_following_it(
    directory: fileio.SafeDirectory, base: Path, tmp_path: Path
) -> None:
    victim = tmp_path / "victim"
    victim.write_text("precious", encoding="utf-8")
    (base / "state" / NAME).symlink_to(victim)
    directory.write(NAME, b"new")
    assert victim.read_text(encoding="utf-8") == "precious"
    assert not (base / "state" / NAME).is_symlink()
    assert directory.read(NAME, 100) == b"new"


def test_write_handles_partial_writes(
    directory: fileio.SafeDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write

    def trickle(descriptor: int, data: Any) -> int:
        return real_write(descriptor, bytes(data[:3]))

    monkeypatch.setattr(os, "write", trickle)
    directory.write(NAME, b"0123456789")
    monkeypatch.undo()
    assert directory.read(NAME, 100) == b"0123456789"


def test_read_refuses_a_symlinked_file(
    directory: fileio.SafeDirectory, base: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret"
    secret.write_text("x", encoding="utf-8")
    secret.chmod(0o600)
    (base / "state" / NAME).symlink_to(secret)
    assert reason_of(directory.read, NAME, 100) == "symlink"


def test_read_refuses_a_dangling_symlink(directory: fileio.SafeDirectory, base: Path) -> None:
    (base / "state" / NAME).symlink_to(base / "nowhere")
    assert reason_of(directory.read, NAME, 100) == "symlink"


def test_read_refuses_a_fifo_without_blocking(directory: fileio.SafeDirectory, base: Path) -> None:
    os.mkfifo(base / "state" / NAME, 0o600)
    assert reason_of(directory.read, NAME, 100) == "not_regular"


def test_read_refuses_a_directory(directory: fileio.SafeDirectory, base: Path) -> None:
    (base / "state" / NAME).mkdir(mode=0o700)
    assert reason_of(directory.read, NAME, 100) == "not_regular"


def test_read_refuses_the_wrong_owner(directory: fileio.SafeDirectory, base: Path) -> None:
    directory.write(NAME, b"x")
    other = foreign(base / "state", OTHER)
    try:
        assert reason_of(other.read, NAME, 100) == "wrong_owner"
    finally:
        other.close()


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o606, 0o666, 0o601])
def test_read_refuses_group_or_world_permission_bits(
    directory: fileio.SafeDirectory, base: Path, mode: int
) -> None:
    directory.write(NAME, b"x")
    (base / "state" / NAME).chmod(mode)
    assert reason_of(directory.read, NAME, 100) == "unsafe_mode"


def test_read_refuses_a_hard_linked_file(directory: fileio.SafeDirectory, base: Path) -> None:
    directory.write(NAME, b"x")
    os.link(base / "state" / NAME, base / "alias")
    assert reason_of(directory.read, NAME, 100) == "hardlinked"


def test_read_refuses_an_oversized_file_by_size(directory: fileio.SafeDirectory) -> None:
    directory.write(NAME, b"x" * 11)
    assert reason_of(directory.read, NAME, 10) == "too_large"
    assert directory.read(NAME, 11) == b"x" * 11


def test_read_bounds_a_file_that_grows_while_reading(
    directory: fileio.SafeDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory.write(NAME, b"12345")

    def endless(_descriptor: int, _count: int) -> bytes:
        return b"x" * 20

    monkeypatch.setattr(os, "read", endless)
    assert reason_of(directory.read, NAME, 10) == "too_large"


def test_read_reports_a_failing_read(
    directory: fileio.SafeDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory.write(NAME, b"12345")

    def broken(_descriptor: int, _count: int) -> bytes:
        raise OSError(errno.EIO, "boom")

    before = open_descriptors()
    monkeypatch.setattr(os, "read", broken)
    assert reason_of(directory.read, NAME, 10) == "io_error"
    assert open_descriptors() == before


def test_read_reports_an_unopenable_file(
    directory: fileio.SafeDirectory, base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (base / "state" / NAME).write_text("x", encoding="utf-8")
    real_open = os.open

    def deny(path: str, *arguments: Any, **keywords: Any) -> int:
        if path == NAME:
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, *arguments, **keywords)

    patch_os(monkeypatch, "open", deny)
    assert reason_of(directory.read, NAME, 10) == "io_error"


def test_a_file_swapped_for_a_symlink_just_before_the_open_is_refused(
    directory: fileio.SafeDirectory, base: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory.write(NAME, b"genuine")
    secret = tmp_path / "secret"
    secret.write_text("attacker controlled", encoding="utf-8")
    secret.chmod(0o600)
    real_open = os.open

    def swap_then_open(path: str, *arguments: Any, **keywords: Any) -> int:
        if path == NAME:
            (base / "state" / NAME).unlink()
            (base / "state" / NAME).symlink_to(secret)
        return real_open(path, *arguments, **keywords)

    patch_os(monkeypatch, "open", swap_then_open)
    assert reason_of(directory.read, NAME, 100) == "symlink"


def test_a_directory_swapped_for_a_symlink_after_opening_is_not_followed(
    base: Path, tmp_path: Path
) -> None:
    opened = fileio.open_directory(str(base / "state"), owner_uid=OWNER, create=True)
    assert opened is not None
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    (base / "state").rename(base / "moved")
    (base / "state").symlink_to(attacker)
    opened.write(NAME, b"data")
    opened.close()
    assert list(attacker.iterdir()) == []
    assert (base / "moved" / NAME).read_bytes() == b"data"


def test_a_temporary_name_collision_is_an_error_and_leaves_no_trace(
    directory: fileio.SafeDirectory, base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "urandom", zeros)
    (base / "state" / ".state.json.0000000000000000.tmp").write_text("squatter", encoding="utf-8")
    assert reason_of(directory.write, NAME, b"x") == "io_error"
    assert (base / "state" / ".state.json.0000000000000000.tmp").read_text() == "squatter"


def test_a_planted_temporary_symlink_is_never_followed(
    directory: fileio.SafeDirectory, base: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    victim.write_text("precious", encoding="utf-8")
    monkeypatch.setattr(os, "urandom", ones)
    (base / "state" / ".state.json.0101010101010101.tmp").symlink_to(victim)
    assert reason_of(directory.write, NAME, b"x") == "io_error"
    assert victim.read_text(encoding="utf-8") == "precious"


@pytest.mark.parametrize("failing", ["fsync", "rename", "write", "fchmod"])
def test_an_interrupted_write_leaves_the_old_file_intact(
    directory: fileio.SafeDirectory, base: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    directory.write(NAME, b"old")

    def boom(*_arguments: Any, **_keywords: Any) -> None:
        raise OSError(errno.EIO, "boom")

    monkeypatch.setattr(os, failing, boom)
    assert reason_of(directory.write, NAME, b"new") == "io_error"
    monkeypatch.undo()
    assert directory.read(NAME, 100) == b"old"
    assert [path.name for path in (base / "state").iterdir()] == [NAME]


def test_a_failing_directory_fsync_is_reported_and_leaves_no_temporary_file(
    directory: fileio.SafeDirectory, base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync
    calls: list[int] = []

    def second_fails(descriptor: int) -> None:
        calls.append(descriptor)
        if len(calls) == 2:
            raise OSError(errno.EIO, "boom")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", second_fails)
    assert reason_of(directory.write, NAME, b"new") == "io_error"
    assert [path.name for path in (base / "state").iterdir()] == [NAME]


def test_an_interrupt_during_a_write_cleans_up_and_propagates(
    directory: fileio.SafeDirectory, base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory.write(NAME, b"old")

    def interrupt(*_arguments: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "fsync", interrupt)
    with pytest.raises(KeyboardInterrupt):
        directory.write(NAME, b"new")
    monkeypatch.undo()
    assert directory.read(NAME, 100) == b"old"
    assert [path.name for path in (base / "state").iterdir()] == [NAME]


def test_new_files_must_be_owned_by_the_expected_user(base: Path) -> None:
    opened = fileio.open_directory(str(base), owner_uid=OWNER, create=True)
    assert opened is not None
    other = foreign(base, OTHER)
    try:
        assert reason_of(other.write, NAME, b"x") == "wrong_owner"
    finally:
        other.close()
        opened.close()
    assert list(base.iterdir()) == []


def test_a_closed_directory_refuses_every_operation(directory: fileio.SafeDirectory) -> None:
    directory.close()
    directory.close()
    assert reason_of(directory.read, NAME, 1) == "io_error"
    assert reason_of(directory.write, NAME, b"x") == "io_error"
    assert reason_of(directory.lock, 0.1) == "io_error"


def test_the_lock_is_exclusive_and_times_out(base: Path) -> None:
    first = fileio.open_directory(str(base), owner_uid=OWNER, create=True)
    second = fileio.open_directory(str(base), owner_uid=OWNER)
    assert first is not None
    assert second is not None
    first.lock(1.0)
    assert reason_of(second.lock, 0.1) == "lock_timeout"
    first.close()
    second.lock(1.0)
    second.close()


def test_the_lock_waits_for_the_holder(base: Path) -> None:
    first = fileio.open_directory(str(base), owner_uid=OWNER, create=True)
    second = fileio.open_directory(str(base), owner_uid=OWNER)
    assert first is not None
    assert second is not None
    first.lock(1.0)
    release = threading.Timer(0.15, first.close)
    release.start()
    second.lock(5.0)
    release.join()
    second.close()


def test_a_lock_failure_other_than_contention_is_an_error(
    directory: fileio.SafeDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_descriptor: int, _operation: int) -> None:
        raise OSError(errno.ENOLCK, "no locks")

    monkeypatch.setattr(fcntl, "flock", broken)
    assert reason_of(directory.lock, 0.1) == "io_error"


def test_concurrent_locked_writers_do_not_lose_updates(base: Path) -> None:
    count = 8
    errors: list[BaseException] = []

    def work(index: int) -> None:
        try:
            opened = fileio.open_directory(str(base), owner_uid=OWNER, create=True)
            assert opened is not None
            try:
                opened.lock(30.0)
                current = opened.read(NAME, 1000) or b""
                opened.write(NAME, current + f"{index},".encode())
            finally:
                opened.close()
        except (AssertionError, fileio.SafeFileError, OSError) as error:
            errors.append(error)

    threads = [threading.Thread(target=work, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    final = (base / NAME).read_text(encoding="utf-8").split(",")[:-1]
    assert sorted(final, key=int) == [str(index) for index in range(count)]


def test_a_vanishing_entry_while_classifying_a_failure_is_still_an_error(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base.mkdir()
    (base / "state").write_text("x", encoding="utf-8")
    real_stat = os.stat

    def vanish(path: Any, *arguments: Any, **keywords: Any) -> os.stat_result:
        if keywords.get("follow_symlinks") is False:
            raise FileNotFoundError(errno.ENOENT, "gone")
        return real_stat(path, *arguments, **keywords)

    patch_os(monkeypatch, "stat", vanish)
    assert reason_of(fileio.open_directory, str(base / "state"), owner_uid=OWNER) == "not_directory"


def temporary_name(digits: str = "0123456789abcdef") -> str:
    return f".{NAME}.{digits}.tmp"


def test_sweep_removes_only_stale_temporary_files_of_the_expected_shape(
    directory: fileio.SafeDirectory, base: Path, tmp_path: Path
) -> None:
    state = base / "state"
    stale = state / temporary_name()
    stale.write_text("sensitive", encoding="utf-8")
    keep = [
        state / NAME,
        state / ".state.json.XYZ.tmp",
        state / ".state.json.0123456789abcdef.tmp.bak",
        state / ".other.json.0123456789abcdef.tmp",
        state / "x.state.json.0123456789abcdef.tmp",
    ]
    for path in keep:
        path.write_text("keep", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.write_text("precious", encoding="utf-8")
    link = state / temporary_name("aaaaaaaaaaaaaaaa")
    link.symlink_to(victim)
    folder = state / temporary_name("bbbbbbbbbbbbbbbb")
    folder.mkdir()
    assert directory.sweep_temporaries(NAME) == 1
    assert not stale.exists()
    assert all(path.exists() for path in keep)
    assert link.is_symlink()
    assert victim.read_text(encoding="utf-8") == "precious"
    assert folder.is_dir()


def test_sweep_leaves_files_of_another_owner(base: Path) -> None:
    opened = fileio.open_directory(str(base), owner_uid=OWNER, create=True)
    assert opened is not None
    (base / temporary_name()).write_text("x", encoding="utf-8")
    other = foreign(base, OTHER)
    try:
        assert other.sweep_temporaries(NAME) == 0
    finally:
        other.close()
        opened.close()
    assert (base / temporary_name()).exists()


def test_sweep_reports_unlink_and_stat_failures_as_not_removed(
    directory: fileio.SafeDirectory, base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (base / "state" / temporary_name()).write_text("x", encoding="utf-8")
    real_stat = os.stat
    real_unlink = os.unlink

    def refuse(*_arguments: Any, **_keywords: Any) -> None:
        raise PermissionError(errno.EACCES, "denied")

    patch_os(monkeypatch, "unlink", refuse)
    assert directory.sweep_temporaries(NAME) == 0
    monkeypatch.setattr(os, "unlink", real_unlink)

    def vanish(path: Any, *arguments: Any, **keywords: Any) -> os.stat_result:
        if keywords.get("follow_symlinks") is False:
            raise FileNotFoundError(errno.ENOENT, "gone")
        return real_stat(path, *arguments, **keywords)

    patch_os(monkeypatch, "stat", vanish)
    assert directory.sweep_temporaries(NAME) == 0
    assert (base / "state" / temporary_name()).exists()


def test_sweep_reports_a_listing_failure(
    directory: fileio.SafeDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_descriptor: int) -> None:
        raise OSError(errno.EIO, "boom")

    monkeypatch.setattr(os, "scandir", broken)
    assert reason_of(directory.sweep_temporaries, NAME) == "io_error"


def test_sweep_validates_the_name_and_the_open_state(directory: fileio.SafeDirectory) -> None:
    assert reason_of(directory.sweep_temporaries, "a/b") == "unsafe_path"
    directory.close()
    assert reason_of(directory.sweep_temporaries, NAME) == "io_error"


def test_missing_open_flags_fail_closed_with_a_structured_error(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(os, "O_NOFOLLOW")
    assert (
        reason_of(fileio.open_directory, str(base), owner_uid=OWNER, create=True)
        == "unsupported_platform"
    )


def test_a_missing_fcntl_module_fails_closed_with_a_structured_error(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "fcntl", None)
    monkeypatch.delitem(sys.modules, fileio.__name__)
    namespace = runpy.run_module(fileio.__name__, run_name="pr_frees56_without_fcntl")
    assert namespace["_flock_supported"]() is False
    error = namespace["SafeFileError"]
    with pytest.raises(error) as excinfo:
        namespace["open_directory"](str(base), owner_uid=OWNER, create=True)
    assert excinfo.value.reason == "unsupported_platform"
    assert not base.exists()
    with pytest.raises(error) as excinfo:
        namespace["_try_lock"](0)
    assert excinfo.value.reason == "unsupported_platform"


def test_filesystem_megabytes_reads_the_size_and_tolerates_a_missing_path(tmp_path: Path) -> None:
    size = fileio.filesystem_megabytes(str(tmp_path))
    assert isinstance(size, int)
    assert size > 0
    assert fileio.filesystem_megabytes(str(tmp_path / "missing")) is None
