"""Content directory rules of the audit: what root may open (FREES-134, FREES-139)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
)
from tests.unit.plugins.module_utils.compliance.test_audit import UID, Harness, mode


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    tmp_path.chmod(0o755)
    return Harness(tmp_path)


def refused_content(harness: Harness, content_path: str, match: str) -> None:
    with pytest.raises(audit.AuditError, match=match) as raised:
        harness.run(content_path=content_path)
    assert raised.value.error_type == "unsafe_content_dir"
    assert raised.value.evidence_dir is None
    assert harness.runner.specs == []
    assert not harness.output_root.exists()


def owned_by(monkeypatch: pytest.MonkeyPatch, owners: dict[Path, int]) -> None:
    original = Path.lstat

    def lstat(self: Path) -> os.stat_result:
        info = original(self)
        if self not in owners:
            return info
        fields = list(info[:10])
        fields[stat.ST_UID] = owners[self]
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lstat)


def test_a_symlinked_content_directory_that_another_user_owns_is_refused(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = harness.root / "linked"
    link.symlink_to(harness.content_dir)
    owned_by(monkeypatch, {link: UID + 1})
    refused_content(
        harness,
        str(link / "synthetic-ds.xml"),
        "a symlink on the way to content_path has an unexpected owner",
    )


def test_a_vetted_symlinked_content_directory_is_copied_from_its_real_path(
    harness: Harness,
) -> None:
    link = harness.root / "linked"
    link.symlink_to(harness.content_dir)
    result = harness.run(content_path=str(link / "synthetic-ds.xml"))
    assert result["run_status"] == "completed"
    assert result["planned"]["content_path"] == str(harness.datastream)
    assert result["content"]["source_path"] == str(harness.datastream)
    assert result["content"]["private_copy"] == str(
        harness.run_dir / "content" / "synthetic-ds.xml"
    )
    assert harness.runner.scanned == [
        (str(harness.run_dir / "content" / "synthetic-ds.xml"), result["content"]["sha256"])
    ]


def test_an_image_mode_opt_link_is_scanned_through_var_opt(harness: Harness) -> None:
    real = harness.root / "var" / "opt" / "freesecdev"
    real.mkdir(parents=True)
    for directory in (harness.root / "var", harness.root / "var" / "opt", real):
        directory.chmod(0o755)
    harness.content_dir.rename(real / "content")
    (harness.root / "opt").symlink_to("var/opt")
    given = harness.root / "opt" / "freesecdev" / "content"
    result = harness.run(content_path=str(given))
    resolved = str(real / "content" / "synthetic-ds.xml")
    assert result["run_status"] == "completed"
    assert result["planned"]["content_path"] == resolved
    assert result["content"]["source_path"] == resolved


def test_a_symlink_in_a_writable_directory_is_refused(harness: Harness) -> None:
    shared = harness.root / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    (shared / "linked").symlink_to(harness.content_dir)
    refused_content(
        harness, str(shared / "linked" / "synthetic-ds.xml"), "or an ancestor is writable"
    )


@pytest.mark.parametrize(
    ("permissions", "content_path"),
    [(0o777, "file"), (0o777, "directory"), (0o775, "file"), (0o757, "directory"), (0o770, "file")],
)
def test_a_content_directory_writable_by_group_or_others_is_refused(
    harness: Harness, permissions: int, content_path: str
) -> None:
    harness.content_dir.chmod(permissions)
    target = harness.datastream if content_path == "file" else harness.content_dir
    refused_content(harness, str(target), "writable by group or others")
    assert mode(harness.content_dir) == permissions
    harness.content_dir.chmod(0o755)
    assert harness.run(content_path=str(target))["run_status"] == "completed"


@pytest.mark.parametrize("permissions", [0o777, 0o775, 0o757])
def test_a_writable_ancestor_of_the_content_directory_is_refused(
    harness: Harness, permissions: int
) -> None:
    shared = harness.root / "shared"
    shared.mkdir()
    shared.chmod(permissions)
    inner = shared / "content"
    harness.content_dir.rename(inner)
    refused_content(harness, str(inner / "synthetic-ds.xml"), "or an ancestor is writable")
    shared.chmod(0o755)
    assert harness.run(content_path=str(inner / "synthetic-ds.xml"))["run_status"] == "completed"


@pytest.mark.parametrize("permissions", [0o1777, 0o1775])
def test_a_sticky_ancestor_of_the_content_directory_is_accepted(
    harness: Harness, permissions: int
) -> None:
    sticky = harness.root / "sticky"
    sticky.mkdir()
    sticky.chmod(permissions)
    inner = sticky / "content"
    harness.content_dir.rename(inner)
    result = harness.run(content_path=str(inner / "synthetic-ds.xml"))
    assert result["run_status"] == "completed"
    assert result["content"]["source_path"] == str(inner / "synthetic-ds.xml")


def test_a_sticky_content_directory_is_accepted(harness: Harness) -> None:
    harness.content_dir.chmod(0o1777)
    result = harness.run(content_path=str(harness.content_dir))
    assert result["run_status"] == "completed"
    assert result["planned"]["content_path"] == str(harness.datastream)


def test_a_content_directory_with_a_non_root_owner_is_refused(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned_by(monkeypatch, {harness.content_dir: UID + 1})
    refused_content(harness, str(harness.datastream), "or an ancestor has an unexpected owner")


def test_an_ancestor_with_a_non_root_owner_is_refused(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned_by(monkeypatch, {harness.root: UID + 1})
    refused_content(harness, str(harness.datastream), "or an ancestor has an unexpected owner")


@pytest.mark.skipif(UID == 0, reason="the content belongs to root when the tests run as root")
def test_production_refuses_content_that_a_non_root_user_owns(harness: Harness) -> None:
    with pytest.raises(audit.AuditError, match="unexpected owner") as raised:
        audit.Auditor(registry=harness.registry).run(harness.job(), check_mode=True)
    assert raised.value.error_type == "unsafe_content_dir"
    assert harness.runner.specs == []


def test_a_datastream_with_a_non_root_owner_is_refused(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned_by(monkeypatch, {harness.datastream: UID + 1})
    refused_content(harness, str(harness.datastream), "the datastream has an unexpected owner")


@pytest.mark.parametrize("permissions", [0o664, 0o646, 0o666])
def test_a_datastream_writable_by_group_or_others_is_refused(
    harness: Harness, permissions: int
) -> None:
    harness.datastream.chmod(permissions)
    refused_content(harness, str(harness.content_dir), "the datastream is writable")


def test_a_content_check_never_opens_the_datastream(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.content_dir.chmod(0o777)
    opened: list[str] = []
    original = Path.open

    def recording_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append(str(self))
        return cast("Any", original(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", recording_open)
    refused_content(harness, str(harness.datastream), "writable by group or others")
    assert str(harness.datastream) not in opened


def test_an_uninspectable_content_component_is_refused(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Path.lstat

    def failing_lstat(self: Path) -> os.stat_result:
        if self == harness.content_dir:
            raise PermissionError(13, "Permission denied")
        return original(self)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    refused_content(harness, str(harness.datastream), "content_path cannot be inspected")


def test_a_content_path_that_cannot_be_resolved_is_invalid_content(harness: Harness) -> None:
    second = harness.content_dir / "second-ds.xml"
    second.write_bytes(harness.datastream.read_bytes())
    for target in (harness.content_dir / "absent-ds.xml", harness.content_dir):
        with pytest.raises(audit.AuditError) as raised:
            harness.run(content_path=str(target))
        assert raised.value.error_type == "invalid_content"
    assert harness.runner.specs == []
    assert not harness.output_root.exists()


def test_only_the_scc_backend_accepts_stream_names_longer_than_64(harness: Harness) -> None:
    long = harness.content_dir / ("U_" + "x" * 96 + "-ds.xml")
    harness.datastream.rename(long)
    with pytest.raises(audit.AuditError, match=r"\{1,64\}") as raised:
        audit.plan(harness.job(content_path=str(long)), owner_uid=UID)
    assert raised.value.error_type == "invalid_argument"
    planned = audit.plan(harness.job(content_path=str(long), backend="scc"), owner_uid=UID)
    assert planned.content_path == str(long)
    too_long = harness.content_dir / ("U_" + "x" * 130 + "-ds.xml")
    long.rename(too_long)
    with pytest.raises(audit.AuditError, match=r"\{1,128\}"):
        audit.plan(harness.job(content_path=str(too_long), backend="scc"), owner_uid=UID)
    assert {"scc"} == audit.LONG_CONTENT_NAME_BACKENDS
