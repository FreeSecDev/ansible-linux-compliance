"""The shared content path check: resolved chain and followed symlinks (FREES-138, FREES-139)."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
)

SYNTHETIC = Path(__file__).resolve().parents[4] / "fixtures" / "catalog" / "synthetic-ds.xml"
UID = os.getuid()
OTHER = UID + 1
NAME = "ssg-demo-ds.xml"


def directory(path: Path, permissions: int = 0o755) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(permissions)
    return path


def datastream(folder: Path) -> Path:
    target = directory(folder) / NAME
    shutil.copyfile(SYNTHETIC, target)
    target.chmod(0o644)
    return target


@pytest.fixture
def root(tmp_path: Path) -> Path:
    tmp_path.chmod(0o755)
    return tmp_path


@pytest.fixture
def image_mode(root: Path) -> Path:
    """``<root>/opt`` is a relative symlink to ``var/opt``, as on image-mode RHEL."""
    real = datastream(root / "var" / "opt" / "freesecdev" / "content")
    for folder in (root / "var", root / "var" / "opt", root / "var" / "opt" / "freesecdev"):
        folder.chmod(0o755)
    (root / "opt").symlink_to("var/opt")
    return real


def owned_by(monkeypatch: pytest.MonkeyPatch, owners: dict[Path, int] | None, uid: int) -> None:
    """Report ``uid`` as the owner of ``owners`` (every path when ``owners`` is None)."""
    original = Path.lstat

    def lstat(self: Path) -> os.stat_result:
        info = original(self)
        if owners is not None and self not in owners:
            return info
        fields = list(info[:10])
        fields[stat.ST_UID] = uid if owners is None else owners[self]
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lstat)


def refused(path: Path, match: str, owner_uid: int = UID) -> None:
    with pytest.raises(catalog.UnsafeContentError, match=match) as raised:
        catalog.vetted_content_path(str(path), owner_uid=owner_uid)
    assert catalog.error_type(raised.value) == "unsafe_content_dir"


def vetted(path: Path, owner_uid: int = UID) -> str:
    return catalog.vetted_content_path(str(path), owner_uid=owner_uid)


def test_an_image_mode_opt_link_is_resolved_to_var_opt(root: Path, image_mode: Path) -> None:
    given = root / "opt" / "freesecdev" / "content"
    assert vetted(given / NAME) == str(image_mode)
    assert vetted(given) == str(image_mode)


def test_a_root_owned_image_mode_layout_is_accepted_for_root(
    root: Path, image_mode: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned_by(monkeypatch, None, catalog.ROOT_UID)
    given = root / "opt" / "freesecdev" / "content" / NAME
    assert vetted(given, catalog.ROOT_UID) == str(image_mode)


@pytest.mark.skipif(UID == 0, reason="the layout belongs to root when the tests run as root")
@pytest.mark.usefixtures("image_mode")
def test_a_layout_of_the_test_user_is_refused_for_root(root: Path) -> None:
    refused(root / "opt" / "freesecdev" / "content" / NAME, "unexpected owner", catalog.ROOT_UID)


def test_an_absolute_link_and_a_link_chain_are_resolved(root: Path) -> None:
    real = datastream(root / "data" / "content")
    (root / "srv").symlink_to(root / "data")
    (root / "hop").symlink_to("srv")
    assert vetted(root / "srv" / "content" / NAME) == str(real)
    assert vetted(root / "hop" / "content" / NAME) == str(real)


def test_dot_dot_in_a_link_target_is_resolved_against_the_real_directory(root: Path) -> None:
    real = datastream(root / "data" / "content")
    directory(root / "deep" / "inner")
    (root / "deep" / "inner" / "up").symlink_to("../../data")
    (root / "top").symlink_to("/" + "../" * 4 + str(root / "data").lstrip("/"))
    assert vetted(root / "deep" / "inner" / "up" / "content" / NAME) == str(real)
    assert vetted(root / "top" / "content" / NAME) == str(real)


@pytest.mark.usefixtures("image_mode")
def test_a_link_that_another_user_owns_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned_by(monkeypatch, {root / "opt": OTHER}, OTHER)
    refused(
        root / "opt" / "freesecdev" / "content" / NAME,
        "a symlink on the way to content_path has an unexpected owner",
    )


def test_a_link_in_a_sticky_directory_needs_an_accepted_owner(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = datastream(root / "data" / "content")
    sticky = directory(root / "tmp", 0o1777)
    (sticky / "content").symlink_to(root / "data" / "content")
    assert vetted(sticky / "content" / NAME) == str(real)
    owned_by(monkeypatch, {sticky / "content": OTHER}, OTHER)
    refused(sticky / "content" / NAME, "a symlink on the way to content_path has an unexpected")


@pytest.mark.parametrize("permissions", [0o777, 0o775, 0o757])
def test_a_link_in_a_writable_directory_is_refused(root: Path, permissions: int) -> None:
    datastream(root / "data" / "content")
    shared = directory(root / "shared", permissions)
    (shared / "opt").symlink_to("../data")
    refused(shared / "opt" / "content" / NAME, "or an ancestor is writable by group or others")


def test_a_link_in_a_directory_that_another_user_owns_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    datastream(root / "data" / "content")
    foreign = directory(root / "foreign")
    (foreign / "opt").symlink_to("../data")
    owned_by(monkeypatch, {foreign: OTHER}, OTHER)
    refused(foreign / "opt" / "content" / NAME, "or an ancestor has an unexpected owner")


@pytest.mark.parametrize("permissions", [0o777, 0o775])
def test_a_link_chain_that_resolves_through_a_writable_directory_is_refused(
    root: Path, permissions: int
) -> None:
    datastream(root / "pub" / "opt" / "content")
    directory(root / "pub", permissions)
    (root / "opt").symlink_to("pub/opt")
    (root / "hop").symlink_to("opt")
    directory(root / "safe")
    (root / "safe" / "up").symlink_to("../pub/opt")
    for given in (root / "opt", root / "hop", root / "safe" / "up"):
        refused(given / "content" / NAME, "or an ancestor is writable by group or others")


@pytest.mark.usefixtures("image_mode")
def test_a_link_chain_through_a_directory_that_another_user_owns_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned_by(monkeypatch, {root / "var": OTHER}, OTHER)
    refused(
        root / "opt" / "freesecdev" / "content" / NAME, "or an ancestor has an unexpected owner"
    )


def test_symlink_loops_are_refused(root: Path) -> None:
    (root / "a").symlink_to("b")
    (root / "b").symlink_to("a")
    (root / "self").symlink_to("self")
    (root / "climb").symlink_to("climb/x")
    for given in (root / "a", root / "self", root / "climb"):
        refused(given / NAME, "follows more than 40 symlinks, probably a loop")


def test_forty_links_are_followed_and_the_forty_first_is_refused(root: Path) -> None:
    real = datastream(root / "data")
    (root / "link1").symlink_to("data")
    for index in range(2, catalog.MAX_SYMLINKS + 2):
        (root / f"link{index}").symlink_to(f"link{index - 1}")
    assert vetted(root / f"link{catalog.MAX_SYMLINKS}" / NAME) == str(real)
    refused(root / f"link{catalog.MAX_SYMLINKS + 1}" / NAME, "follows more than 40 symlinks")


def test_a_dangling_link_or_a_missing_directory_is_invalid_content(root: Path) -> None:
    (root / "dangling").symlink_to("absent")
    for given in (root / "dangling" / NAME, root / "absent" / NAME, root / NAME):
        with pytest.raises(catalog.CatalogError, match="cannot be read") as raised:
            vetted(given)
        assert catalog.error_type(raised.value) == "invalid_content"


def test_the_final_component_is_never_followed(root: Path) -> None:
    real = datastream(root / "data")
    (root / "data" / "link-ds.xml").symlink_to(real)
    (root / "linked-dir").symlink_to("data")
    for given in (root / "data" / "link-ds.xml", root / "linked-dir"):
        with pytest.raises(catalog.CatalogError, match="neither a regular file nor a directory"):
            vetted(given)


def test_a_file_as_a_directory_component_is_refused(root: Path) -> None:
    real = datastream(root / "data")
    refused(real / NAME, "content_path component is not a directory")
    (root / "to-file").symlink_to(real)
    refused(root / "to-file" / NAME, "content_path component is not a directory")


@pytest.mark.usefixtures("image_mode")
def test_a_link_that_cannot_be_read_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_readlink(self: Path) -> Path:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "readlink", failing_readlink)
    refused(root / "opt" / "freesecdev" / "content" / NAME, "content_path cannot be inspected")


@pytest.mark.usefixtures("image_mode")
def test_a_component_that_cannot_be_inspected_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Path.lstat
    blocked = root / "var" / "opt"

    def failing_lstat(self: Path) -> os.stat_result:
        if self == blocked:
            raise PermissionError(13, "Permission denied")
        return original(self)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    refused(
        root / "opt" / "freesecdev" / "content" / NAME,
        "content_path cannot be inspected: Permission denied",
    )


@pytest.mark.parametrize("permissions", [0o664, 0o646, 0o666])
def test_a_writable_datastream_is_refused_through_any_name(root: Path, permissions: int) -> None:
    real = datastream(root / "data")
    real.chmod(permissions)
    hard = directory(root / "other") / NAME
    os.link(real, hard)
    for given in (real, hard, root / "data"):
        refused(given, "the datastream is writable by group or others")


def test_a_datastream_that_another_user_owns_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = datastream(root / "data")
    owned_by(monkeypatch, {real: OTHER}, OTHER)
    refused(real, "the datastream has an unexpected owner")


def test_a_writable_content_directory_given_as_content_path_is_refused(root: Path) -> None:
    datastream(root / "data")
    (root / "data").chmod(0o777)
    refused(root / "data", "or an ancestor is writable by group or others")
    (root / "data").chmod(0o1777)
    assert vetted(root / "data") == str(root / "data" / NAME)


def changing_lstat(
    monkeypatch: pytest.MonkeyPatch, target: Path, after: int, replacement: int | None
) -> None:
    """Report ``target`` unchanged ``after`` times, then missing or with another mode."""
    original = Path.lstat
    calls = [0]

    def lstat(self: Path) -> os.stat_result:
        if self != target:
            return original(self)
        calls[0] += 1
        if calls[0] <= after:
            return original(self)
        if replacement is None:
            raise FileNotFoundError(2, "No such file or directory")
        fields = list(original(self)[:10])
        fields[stat.ST_MODE] = replacement
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lstat)


def test_a_datastream_that_vanishes_during_the_check_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = datastream(root / "data")
    changing_lstat(monkeypatch, real, 1, None)
    refused(real, "content_path vanished while it was inspected")


def test_a_content_directory_that_vanishes_during_the_check_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    datastream(root / "data")
    changing_lstat(monkeypatch, root / "data", 2, None)
    refused(root / "data", "content_path vanished while it was inspected")


def test_a_datastream_replaced_by_a_fifo_during_the_check_is_refused(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = datastream(root / "data")
    changing_lstat(monkeypatch, real, 1, stat.S_IFIFO | 0o644)
    refused(real, "the datastream is not a regular file")


def test_the_check_opens_nothing(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = datastream(root / "data")
    opened: list[str] = []
    original = Path.open

    def recording_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append(str(self))
        return cast("Any", original(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", recording_open)
    assert vetted(real) == str(real)
    assert vetted(root / "data") == str(real)
    assert opened == []


def test_effective_uid_is_the_owner_of_the_process_directory() -> None:
    assert catalog.effective_uid() == os.geteuid()


def test_effective_uid_falls_back_to_root(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_stat(self: Path, *_args: Any, **_kwargs: Any) -> os.stat_result:
        raise FileNotFoundError(2, "No such file or directory", str(self))

    monkeypatch.setattr(Path, "stat", failing_stat)
    assert catalog.effective_uid() == catalog.ROOT_UID
