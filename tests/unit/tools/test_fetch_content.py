from __future__ import annotations

import copy
import hashlib
import http.client
import io
import runpy
import stat
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import pytest
import yaml

from tools.content import fetch_content as fetch

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = "scap-security-guide-9.9.9"
PATH_A = f"{ROOT}/ssg-alpha1-ds.xml"
PATH_B = f"{ROOT}/ssg-beta2-ds.xml"
DATA_A = b"<synthetic>alpha datastream</synthetic>\n" * 50
DATA_B = b"<synthetic>beta datastream</synthetic>\n" * 20
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
BASE = "https://downloads.example.test/releases/download/v9.9.9"
ARCHIVE_URL = f"{BASE}/scap-security-guide-9.9.9.zip"


def make_zip(path: Path, members: dict[str, bytes] | None = None) -> bytes:
    chosen = {PATH_A: DATA_A, PATH_B: DATA_B} if members is None else members
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in chosen.items():
            bundle.writestr(name, data)
    return path.read_bytes()


def manifest_document(archive: bytes, **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "source": {"name": "Synthetic", "version": "v9.9.9", "licence": "BSD-3-Clause"},
        "archive": {
            "download_base_url": BASE,
            "file_name": "scap-security-guide-9.9.9.zip",
            "sha512": hashlib.sha512(archive).hexdigest(),
            "size_bytes": len(archive),
        },
        "datastreams": [
            {
                "name": name,
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "benchmark_id": "xccdf_org.example.synthetic_benchmark_demo",
                "profiles": [{"id": PROFILE, "title": "Synthetic baseline"}],
            }
            for name, path, data in (("alpha1", PATH_A, DATA_A), ("beta2", PATH_B, DATA_B))
        ],
    }
    document.update(overrides)
    return document


@pytest.fixture
def archive_file(tmp_path: Path) -> Path:
    path = tmp_path / "archive.zip"
    make_zip(path)
    return path


@pytest.fixture
def manifest(archive_file: Path) -> fetch.Manifest:
    return fetch.parse_manifest(manifest_document(archive_file.read_bytes()))


def opener_for(data: bytes) -> Callable[[str], fetch.Readable]:
    def opener(url: str) -> fetch.Readable:
        assert url == ARCHIVE_URL
        return io.BytesIO(data)

    return opener


def forbidden_opener(_url: str) -> fetch.Readable:
    message = "the network must not be used"
    raise AssertionError(message)


MISSING = object()


def apply_edit(document: dict[str, Any], location: tuple[str | int, ...], value: object) -> None:
    target: Any = document
    for key in location[:-1]:
        target = target[key]
    if value is MISSING:
        del target[location[-1]]
    else:
        target[location[-1]] = value


class TestManifest:
    """Test manifest behaviour."""

    def test_a_valid_manifest_is_parsed(self, manifest: fetch.Manifest) -> None:
        assert manifest.version == "v9.9.9"
        assert manifest.archive.url == ARCHIVE_URL
        assert [stream.name for stream in manifest.datastreams] == ["alpha1", "beta2"]
        assert manifest.datastreams[0].file_name == "ssg-alpha1-ds.xml"
        assert manifest.datastreams[0].profiles == (
            fetch.ProfileEntry(PROFILE, "Synthetic baseline"),
        )

    def test_a_trailing_slash_on_the_base_url_is_tolerated(self, archive_file: Path) -> None:
        document = manifest_document(archive_file.read_bytes())
        document["archive"]["download_base_url"] = BASE + "/"
        assert fetch.parse_manifest(document).archive.url == ARCHIVE_URL

    @pytest.mark.parametrize(
        ("location", "value"),
        [
            (("schema_version",), 2),
            (("schema_version",), True),
            (("source",), MISSING),
            (("source",), "text"),
            (
                (
                    "source",
                    "version",
                ),
                "9.9.9",
            ),
            (("archive",), MISSING),
            (
                (
                    "archive",
                    "download_base_url",
                ),
                "http://downloads.example.test/x",
            ),
            (
                (
                    "archive",
                    "download_base_url",
                ),
                "https://user:pw@example.test/x",
            ),
            (
                (
                    "archive",
                    "download_base_url",
                ),
                "https://example.test:0/x",
            ),
            (
                (
                    "archive",
                    "download_base_url",
                ),
                "https://example.test:abc/x",
            ),
            (
                (
                    "archive",
                    "download_base_url",
                ),
                7,
            ),
            (
                (
                    "archive",
                    "file_name",
                ),
                "../evil.zip",
            ),
            (
                (
                    "archive",
                    "file_name",
                ),
                "other.zip",
            ),
            (
                (
                    "archive",
                    "sha512",
                ),
                "abc",
            ),
            (
                (
                    "archive",
                    "sha512",
                ),
                "G" * 128,
            ),
            (
                (
                    "archive",
                    "size_bytes",
                ),
                0,
            ),
            (
                (
                    "archive",
                    "size_bytes",
                ),
                True,
            ),
            (
                (
                    "archive",
                    "size_bytes",
                ),
                fetch.MAX_ARCHIVE_BYTES + 1,
            ),
            (
                (
                    "archive",
                    "size_bytes",
                ),
                "10",
            ),
            (("datastreams",), []),
            (("datastreams",), "text"),
            (("datastreams",), ["text"]),
            (
                (
                    "datastreams",
                    0,
                    "name",
                ),
                "Bad Name",
            ),
            (
                (
                    "datastreams",
                    0,
                    "sha256",
                ),
                "abc",
            ),
            (
                (
                    "datastreams",
                    0,
                    "sha256",
                ),
                hashlib.sha256(b"x").hexdigest().upper(),
            ),
            (
                (
                    "datastreams",
                    0,
                    "size_bytes",
                ),
                fetch.MAX_MEMBER_BYTES + 1,
            ),
            (
                (
                    "datastreams",
                    0,
                    "benchmark_id",
                ),
                "",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                f"{ROOT}/../ssg-alpha1-ds.xml",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                "/abs/ssg-alpha1-ds.xml",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                f"{ROOT}//ssg-alpha1-ds.xml",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                f"{ROOT}/ssg-alpha1-ds.xml/",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                f"{ROOT}/playbook.yml",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                f"{ROOT}/other-alpha1-ds.xml",
            ),
            (
                (
                    "datastreams",
                    0,
                    "path",
                ),
                f"{ROOT}\\ssg-alpha1-ds.xml",
            ),
            (
                (
                    "datastreams",
                    0,
                    "profiles",
                ),
                MISSING,
            ),
            (
                (
                    "datastreams",
                    0,
                    "profiles",
                ),
                [],
            ),
            (
                (
                    "datastreams",
                    0,
                    "profiles",
                ),
                ["text"],
            ),
            (
                (
                    "datastreams",
                    0,
                    "profiles",
                ),
                [{"id": "", "title": "t"}],
            ),
            (
                (
                    "datastreams",
                    0,
                    "profiles",
                ),
                [{"id": "p", "title": 3}],
            ),
            (
                (
                    "datastreams",
                    0,
                    "profiles",
                ),
                [{"id": "p", "title": "a"}, {"id": "p", "title": "b"}],
            ),
            (
                (
                    "datastreams",
                    1,
                    "name",
                ),
                "alpha1",
            ),
            (
                (
                    "datastreams",
                    1,
                    "path",
                ),
                PATH_A,
            ),
            (
                (
                    "datastreams",
                    1,
                    "path",
                ),
                f"other/{PATH_A.rsplit('/', maxsplit=1)[-1]}",
            ),
        ],
    )
    def test_malformed_manifests_are_rejected(
        self, archive_file: Path, location: tuple[str | int, ...], value: object
    ) -> None:
        document = copy.deepcopy(manifest_document(archive_file.read_bytes()))
        apply_edit(document, location, value)
        with pytest.raises(fetch.ContentError):
            fetch.parse_manifest(document)

    def test_a_manifest_that_is_not_a_mapping_is_rejected(self) -> None:
        with pytest.raises(fetch.ContentError, match="manifest must be a mapping"):
            fetch.parse_manifest(["a"])

    def test_load_manifest_reads_a_yaml_file(self, tmp_path: Path, archive_file: Path) -> None:
        path = tmp_path / "manifest.yml"
        path.write_text(yaml.safe_dump(manifest_document(archive_file.read_bytes())))
        assert fetch.load_manifest(path).version == "v9.9.9"

    @pytest.mark.parametrize("content", [b"a: [", b"\xff\xfe\x00"])
    def test_load_manifest_reports_unreadable_files(self, tmp_path: Path, content: bytes) -> None:
        path = tmp_path / "manifest.yml"
        path.write_bytes(content)
        with pytest.raises(fetch.ContentError, match="cannot read manifest"):
            fetch.load_manifest(path)
        with pytest.raises(fetch.ContentError, match="cannot read manifest"):
            fetch.load_manifest(tmp_path / "missing.yml")


class FakeResponse:
    """Fake response behaviour."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes = b"") -> None:
        self.status = status
        self.headers = headers
        self.body = io.BytesIO(body)
        self.closed = False

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, size: int) -> bytes:
        return self.body.read(size)

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    """Fake connection behaviour."""

    script: ClassVar[list[Any]] = []
    created: ClassVar[list[FakeConnection]] = []

    def __init__(self, host: str, port: int | None, **keywords: object) -> None:
        self.host = host
        self.port = port
        self.keywords = keywords
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.closed = False
        FakeConnection.created.append(self)

    def request(self, method: str, target: str, headers: dict[str, str]) -> None:
        self.requests.append((method, target, headers))
        step = FakeConnection.script[len(FakeConnection.created) - 1]
        if isinstance(step, BaseException):
            raise step

    def getresponse(self) -> FakeResponse:
        step: Any = FakeConnection.script[len(FakeConnection.created) - 1]
        if isinstance(step, FakeResponse):
            return step
        raise step()

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> type[FakeConnection]:
    FakeConnection.script = []
    FakeConnection.created = []
    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConnection)
    return FakeConnection


class TestDownload:
    """Test download behaviour."""

    def test_https_url_validation(self) -> None:
        assert fetch.check_https_url("https://example.test/a") == "https://example.test/a"
        for url in ("http://example.test/a", "ftp://example.test", "https:///a", "file:///etc/x"):
            with pytest.raises(fetch.ContentError, match="only HTTPS"):
                fetch.check_https_url(url)

    def test_a_direct_response_is_streamed_and_closed(
        self, connections: type[FakeConnection]
    ) -> None:
        connections.script = [FakeResponse(200, {}, b"payload")]
        source = fetch.https_open("https://downloads.example.test/a/b.zip?x=1")
        assert source.read(100) == b"payload"
        source.close()
        connection = connections.created[0]
        assert (connection.host, connection.port) == ("downloads.example.test", None)
        assert connection.requests == [("GET", "/a/b.zip?x=1", {"Accept-Encoding": "identity"})]
        assert connection.closed
        assert "context" in connection.keywords

    def test_redirects_are_followed_over_https(self, connections: type[FakeConnection]) -> None:
        connections.script = [
            FakeResponse(302, {"Location": "https://cdn.example.test:8443/real.zip"}),
            FakeResponse(301, {"Location": "/other.zip"}),
            FakeResponse(200, {}, b"ok"),
        ]
        source = fetch.https_open("https://downloads.example.test")
        assert source.read(10) == b"ok"
        assert [(c.host, c.port) for c in connections.created] == [
            ("downloads.example.test", None),
            ("cdn.example.test", 8443),
            ("cdn.example.test", 8443),
        ]
        assert connections.created[0].requests[0][1] == "/"
        assert connections.created[2].requests[0][1] == "/other.zip"
        assert connections.created[0].closed

    def test_a_redirect_to_plain_http_is_refused(self, connections: type[FakeConnection]) -> None:
        connections.script = [FakeResponse(302, {"Location": "http://cdn.example.test/a.zip"})]
        with pytest.raises(fetch.ContentError, match="only HTTPS"):
            fetch.https_open("https://downloads.example.test/a.zip")

    @pytest.mark.parametrize(
        ("response", "message"),
        [
            (FakeResponse(404, {}), "HTTP status 404"),
            (FakeResponse(302, {}), "HTTP status 302"),
            (FakeResponse(500, {"Location": "https://x.example.test/"}), "HTTP status 500"),
        ],
    )
    def test_other_statuses_fail(
        self, connections: type[FakeConnection], response: FakeResponse, message: str
    ) -> None:
        connections.script = [response]
        with pytest.raises(fetch.ContentError, match=message):
            fetch.https_open("https://downloads.example.test/a.zip")
        assert response.closed
        assert connections.created[0].closed

    def test_too_many_redirects_fail(self, connections: type[FakeConnection]) -> None:
        connections.script = [
            FakeResponse(302, {"Location": "https://a.example.test/"})
            for _ in range(fetch.MAX_REDIRECTS + 1)
        ]
        with pytest.raises(fetch.ContentError, match="too many redirects"):
            fetch.https_open("https://downloads.example.test/a.zip")

    @pytest.mark.parametrize(
        "error", [OSError("boom"), http.client.HTTPException("bad"), TimeoutError()]
    )
    def test_connection_errors_are_clean(
        self, connections: type[FakeConnection], error: BaseException
    ) -> None:
        connections.script = [error]
        with pytest.raises(fetch.ContentError, match="download failed"):
            fetch.https_open("https://downloads.example.test/a.zip")
        assert connections.created[0].closed

    def test_response_errors_are_clean(self, connections: type[FakeConnection]) -> None:
        def raiser() -> BaseException:
            return http.client.BadStatusLine("x")

        connections.script = [raiser]
        with pytest.raises(fetch.ContentError, match="BadStatusLine"):
            fetch.https_open("https://downloads.example.test/a.zip")

    def test_the_default_opener_refuses_http(self) -> None:
        with pytest.raises(fetch.ContentError, match="only HTTPS"):
            fetch.https_open("http://downloads.example.test/a.zip")


def with_extra_bytes(data: bytes) -> bytes:
    return data + b"extra"


def without_last_byte(data: bytes) -> bytes:
    return data[:-1]


def empty_payload(_data: bytes) -> bytes:
    return b""


class TestDownloadArchive:
    """Test download archive behaviour."""

    def test_a_verified_archive_is_kept(self, tmp_path: Path, archive_file: Path) -> None:
        data = archive_file.read_bytes()
        manifest = fetch.parse_manifest(manifest_document(data))
        out = tmp_path / "out"
        out.mkdir()
        path = fetch.download_archive(manifest.archive, out, opener_for(data))
        assert path.read_bytes() == data
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_the_source_is_closed_and_the_partial_file_removed_on_failure(
        self, tmp_path: Path, archive_file: Path
    ) -> None:
        data = archive_file.read_bytes()
        manifest = fetch.parse_manifest(manifest_document(data))
        closed: list[bool] = []

        class Source(io.BytesIO):
            """Source behaviour."""

            def close(self) -> None:
                closed.append(True)
                super().close()

        out = tmp_path / "out"
        out.mkdir()
        tampered = b"X" + data[1:]
        with pytest.raises(fetch.ContentError, match="SHA-512"):
            fetch.download_archive(manifest.archive, out, lambda _url: Source(tampered))
        assert closed == [True]
        assert list(out.iterdir()) == []

    @pytest.mark.parametrize(
        ("payload", "message"),
        [
            (with_extra_bytes, "larger than the manifest"),
            (without_last_byte, "size"),
            (empty_payload, "size"),
        ],
    )
    def test_size_deviations_fail(
        self,
        tmp_path: Path,
        archive_file: Path,
        payload: Callable[[bytes], bytes],
        message: str,
    ) -> None:
        data = archive_file.read_bytes()
        manifest = fetch.parse_manifest(manifest_document(data))
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match=message):
            fetch.download_archive(manifest.archive, out, opener_for(payload(data)))
        assert list(out.iterdir()) == []

    @pytest.mark.parametrize(
        "error",
        [TimeoutError(), ConnectionResetError(), http.client.IncompleteRead(b"x")],
    )
    def test_read_errors_are_clean_and_leave_no_partial_file(
        self, tmp_path: Path, archive_file: Path, error: BaseException
    ) -> None:
        manifest = fetch.parse_manifest(manifest_document(archive_file.read_bytes()))
        out = tmp_path / "out"
        out.mkdir()

        class Failing(io.BytesIO):
            """Source whose read fails."""

            def read(self, _size: int | None = -1) -> bytes:
                raise error

        with pytest.raises(fetch.ContentError, match="download failed"):
            fetch.download_archive(manifest.archive, out, lambda _url: Failing())
        assert list(out.iterdir()) == []

    def test_a_non_https_archive_url_is_refused_before_any_request(self, tmp_path: Path) -> None:
        archive = fetch.Archive("http://example.test/a.zip", "0" * 128, 10)
        with pytest.raises(fetch.ContentError, match="only HTTPS"):
            fetch.download_archive(archive, tmp_path, forbidden_opener)


class TestVerifyArchiveFile:
    """Test verify archive file behaviour."""

    def test_a_good_file_passes(self, archive_file: Path, manifest: fetch.Manifest) -> None:
        fetch.verify_archive_file(archive_file, manifest.archive)

    def test_a_modified_file_fails(self, archive_file: Path, manifest: fetch.Manifest) -> None:
        data = archive_file.read_bytes()
        archive_file.write_bytes(b"Y" + data[1:])
        with pytest.raises(fetch.ContentError, match="SHA-512"):
            fetch.verify_archive_file(archive_file, manifest.archive)

    def test_a_different_size_fails(self, archive_file: Path, manifest: fetch.Manifest) -> None:
        archive_file.write_bytes(archive_file.read_bytes() + b"0")
        with pytest.raises(fetch.ContentError, match="size"):
            fetch.verify_archive_file(archive_file, manifest.archive)

    def test_missing_files_and_non_regular_files_fail(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        with pytest.raises(fetch.ContentError, match="cannot read"):
            fetch.verify_archive_file(tmp_path / "missing.zip", manifest.archive)
        with pytest.raises(fetch.ContentError, match="not a regular file"):
            fetch.verify_archive_file(tmp_path, manifest.archive)
        link = tmp_path / "link.zip"
        link.symlink_to(archive_file)
        with pytest.raises(fetch.ContentError, match="not a regular file"):
            fetch.verify_archive_file(link, manifest.archive)

    def test_an_error_without_a_message_names_its_type(
        self, tmp_path: Path, manifest: fetch.Manifest, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(_self: Path) -> object:
            raise OSError

        monkeypatch.setattr(Path, "lstat", refuse)
        with pytest.raises(fetch.ContentError, match="OSError"):
            fetch.verify_archive_file(tmp_path / "x.zip", manifest.archive)


def listing(directory: Path) -> list[str]:
    return sorted(item.name for item in directory.iterdir())


def write_duplicate_member(archive: Path) -> None:
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(PATH_A, DATA_A)
        bundle.writestr(PATH_A, DATA_A)


class TestExtraction:
    """Test extraction behaviour."""

    def test_only_the_listed_datastreams_are_extracted(
        self, tmp_path: Path, manifest: fetch.Manifest
    ) -> None:
        archive = tmp_path / "mixed.zip"
        make_zip(
            archive,
            {
                PATH_A: DATA_A,
                PATH_B: DATA_B,
                f"{ROOT}/ansible/playbook.yml": b"- ansible.builtin.shell: x\n",
                f"{ROOT}/bash/fix.sh": b"#!/bin/sh\nrm -rf /\n",
                "../escape.txt": b"escaped",
                "/absolute.txt": b"absolute",
            },
        )
        out = tmp_path / "out"
        out.mkdir()
        written = fetch.extract_datastreams(archive, manifest.datastreams, out)
        assert [path.name for path in written] == ["ssg-alpha1-ds.xml", "ssg-beta2-ds.xml"]
        assert listing(out) == ["ssg-alpha1-ds.xml", "ssg-beta2-ds.xml"]
        assert (out / "ssg-alpha1-ds.xml").read_bytes() == DATA_A
        assert stat.S_IMODE((out / "ssg-alpha1-ds.xml").stat().st_mode) == 0o644
        assert not (tmp_path / "escape.txt").exists()
        assert not Path("/absolute.txt").exists()

    def test_an_existing_destination_is_replaced(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        out = tmp_path / "out"
        out.mkdir()
        (out / "ssg-alpha1-ds.xml").write_bytes(b"old")
        fetch.extract_datastreams(archive_file, manifest.datastreams[:1], out)
        assert (out / "ssg-alpha1-ds.xml").read_bytes() == DATA_A

    def test_a_missing_member_fails(self, tmp_path: Path, manifest: fetch.Manifest) -> None:
        archive = tmp_path / "partial.zip"
        make_zip(archive, {PATH_A: DATA_A})
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="exactly once in the archive, found 0"):
            fetch.extract_datastreams(archive, manifest.datastreams, out)
        assert listing(out) == []

    def test_a_duplicate_member_fails(self, tmp_path: Path, manifest: fetch.Manifest) -> None:
        archive = tmp_path / "dup.zip"
        with pytest.warns(UserWarning, match="Duplicate"):
            write_duplicate_member(archive)
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="found 2"):
            fetch.extract_datastreams(archive, manifest.datastreams[:1], out)

    @pytest.mark.parametrize("mode", [0o120777, 0o040755, 0o010644, 0o020644, 0o140755])
    def test_non_regular_members_are_refused(
        self, tmp_path: Path, manifest: fetch.Manifest, mode: int
    ) -> None:
        archive = tmp_path / "special.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            info = zipfile.ZipInfo(PATH_A)
            info.external_attr = mode << 16
            bundle.writestr(info, "/etc/passwd")
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="not a regular file"):
            fetch.extract_datastreams(archive, manifest.datastreams[:1], out)
        assert listing(out) == []

    def test_a_regular_unix_member_is_accepted(
        self, tmp_path: Path, manifest: fetch.Manifest
    ) -> None:
        archive = tmp_path / "unix.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            info = zipfile.ZipInfo(PATH_A)
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, DATA_A)
        out = tmp_path / "out"
        out.mkdir()
        assert len(fetch.extract_datastreams(archive, manifest.datastreams[:1], out)) == 1

    def test_an_encrypted_member_is_refused(self, tmp_path: Path, manifest: fetch.Manifest) -> None:
        archive = tmp_path / "encrypted.zip"
        make_zip(archive, {PATH_A: DATA_A})
        data = bytearray(archive.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = data.find(signature) + offset
            data[position] |= 0x01
        archive.write_bytes(bytes(data))
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="encrypted"):
            fetch.extract_datastreams(archive, manifest.datastreams[:1], out)

    def test_a_size_that_differs_from_the_manifest_is_refused(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        stream = manifest.datastreams[0]
        wrong = fetch.Datastream(
            stream.name, stream.path, stream.sha256, stream.size_bytes + 1, "b", stream.profiles
        )
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="the manifest records"):
            fetch.extract_datastreams(archive_file, [wrong], out)

    def test_a_digest_mismatch_leaves_no_file(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        stream = manifest.datastreams[0]
        wrong = fetch.Datastream(
            stream.name, stream.path, "0" * 64, stream.size_bytes, "b", stream.profiles
        )
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="SHA-256"):
            fetch.extract_datastreams(archive_file, [wrong], out)
        assert listing(out) == []

    def test_a_corrupt_member_leaves_no_file(
        self, tmp_path: Path, manifest: fetch.Manifest
    ) -> None:
        archive = tmp_path / "corrupt.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as bundle:
            bundle.writestr(PATH_A, DATA_A)
        data = bytearray(archive.read_bytes())
        data[data.find(DATA_A[:16]) + 3] ^= 0xFF
        archive.write_bytes(bytes(data))
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="cannot extract"):
            fetch.extract_datastreams(archive, manifest.datastreams[:1], out)
        assert listing(out) == []

    def test_a_damaged_deflate_stream_leaves_no_file(
        self, tmp_path: Path, manifest: fetch.Manifest
    ) -> None:
        archive = tmp_path / "damaged.zip"
        random_like = bytes((index * 37 + 11) % 251 for index in range(4096))
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr(PATH_A, random_like)
        stream = fetch.Datastream(
            "alpha1",
            PATH_A,
            hashlib.sha256(random_like).hexdigest(),
            len(random_like),
            "b",
            manifest.datastreams[0].profiles,
        )
        data = bytearray(archive.read_bytes())
        for position in range(60, 120):
            data[position] ^= 0xA5
        archive.write_bytes(bytes(data))
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="cannot extract"):
            fetch.extract_datastreams(archive, [stream], out)
        assert listing(out) == []

    def test_an_unsupported_compression_method_is_a_clean_error(
        self,
        tmp_path: Path,
        archive_file: Path,
        manifest: fetch.Manifest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unsupported(*_arguments: object, **_keywords: object) -> object:
            message = "compression"
            raise NotImplementedError(message)

        monkeypatch.setattr(zipfile.ZipFile, "open", unsupported)
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(fetch.ContentError, match="NotImplementedError"):
            fetch.extract_datastreams(archive_file, manifest.datastreams[:1], out)
        assert listing(out) == []

    def test_keyboard_interrupts_still_clean_up(
        self,
        tmp_path: Path,
        archive_file: Path,
        manifest: fetch.Manifest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def interrupted(*_arguments: object, **_keywords: object) -> object:
            raise KeyboardInterrupt

        monkeypatch.setattr(zipfile.ZipFile, "open", interrupted)
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(KeyboardInterrupt):
            fetch.extract_datastreams(archive_file, manifest.datastreams[:1], out)
        assert listing(out) == []

    def test_a_file_that_is_not_a_zip_is_a_clean_error(
        self, tmp_path: Path, manifest: fetch.Manifest
    ) -> None:
        not_zip = tmp_path / "not.zip"
        not_zip.write_bytes(b"plain text, not an archive")
        with pytest.raises(fetch.ContentError, match="BadZipFile"):
            fetch.extract_datastreams(not_zip, manifest.datastreams, tmp_path)
        with pytest.raises(fetch.ContentError, match="FileNotFoundError"):
            fetch.extract_datastreams(tmp_path / "missing.zip", manifest.datastreams, tmp_path)

    def test_an_unwritable_output_directory_is_a_clean_error(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        with pytest.raises(fetch.ContentError, match="cannot read the archive"):
            fetch.extract_datastreams(archive_file, manifest.datastreams[:1], tmp_path / "absent")


class TestSelectAndFetch:
    """Test select and fetch behaviour."""

    def test_select(self, manifest: fetch.Manifest) -> None:
        assert fetch.select(manifest, []) == manifest.datastreams
        assert fetch.select(manifest, ["beta2", "beta2"]) == (manifest.datastreams[1],)
        with pytest.raises(fetch.ContentError, match="not in the manifest: nope"):
            fetch.select(manifest, ["alpha1", "nope"])

    def test_offline_mode_never_touches_the_network(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        out = tmp_path / "nested" / "out"
        written = fetch.fetch(manifest, out, archive_file, opener=forbidden_opener)
        assert [path.name for path in written] == ["ssg-alpha1-ds.xml", "ssg-beta2-ds.xml"]
        assert archive_file.exists()

    def test_offline_mode_verifies_the_archive_first(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        archive_file.write_bytes(b"Z" + archive_file.read_bytes()[1:])
        out = tmp_path / "out"
        with pytest.raises(fetch.ContentError, match="SHA-512"):
            fetch.fetch(manifest, out, archive_file, opener=forbidden_opener)
        assert listing(out) == []

    def test_download_mode_extracts_and_removes_the_archive(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        out = tmp_path / "out"
        written = fetch.fetch(manifest, out, None, ["beta2"], opener_for(archive_file.read_bytes()))
        assert [path.name for path in written] == ["ssg-beta2-ds.xml"]
        assert listing(out) == ["ssg-beta2-ds.xml"]

    def test_download_mode_removes_the_archive_after_an_extraction_failure(
        self, tmp_path: Path
    ) -> None:
        archive = tmp_path / "wrong-member.zip"
        data = make_zip(archive, {PATH_A: DATA_A, f"{ROOT}/other": b"x"})
        manifest = fetch.parse_manifest(manifest_document(data))
        out = tmp_path / "out"
        with pytest.raises(fetch.ContentError, match="found 0"):
            fetch.fetch(manifest, out, None, [], opener_for(data))
        assert listing(out) == []

    def test_an_unknown_datastream_name_fails_before_any_work(
        self, tmp_path: Path, manifest: fetch.Manifest
    ) -> None:
        out = tmp_path / "out"
        with pytest.raises(fetch.ContentError, match="not in the manifest"):
            fetch.fetch(manifest, out, None, ["nope"], forbidden_opener)
        assert not out.exists()

    def test_a_symlinked_output_directory_is_refused(
        self, tmp_path: Path, archive_file: Path, manifest: fetch.Manifest
    ) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(fetch.ContentError, match="symlink"):
            fetch.fetch(manifest, link, archive_file)
        assert listing(real) == []


class TestCommandLine:
    """Test command line behaviour."""

    def write_manifest(self, tmp_path: Path, archive: bytes) -> Path:
        path = tmp_path / "manifest.yml"
        path.write_text(yaml.safe_dump(manifest_document(archive)))
        return path

    def test_offline_run(
        self, tmp_path: Path, archive_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest_path = self.write_manifest(tmp_path, archive_file.read_bytes())
        out = tmp_path / "out"
        arguments = [
            "--manifest",
            str(manifest_path),
            "--output-dir",
            str(out),
            "--from-file",
            str(archive_file),
            "--datastream",
            "alpha1",
        ]
        assert fetch.main(arguments) == 0
        assert capsys.readouterr().out == f"verified {out / 'ssg-alpha1-ds.xml'}\n"

    def test_errors_exit_with_status_one(
        self, tmp_path: Path, archive_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest_path = self.write_manifest(tmp_path, archive_file.read_bytes())
        archive_file.write_bytes(b"tampered")
        arguments = [
            "--manifest",
            str(manifest_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--from-file",
            str(archive_file),
        ]
        assert fetch.main(arguments) == 1
        assert "error:" in capsys.readouterr().err

    def test_defaults_point_at_the_repository_manifest_and_build_directory(self) -> None:
        assert fetch.DEFAULT_MANIFEST == fetch.REPO_ROOT / "content" / "manifest.yml"
        assert fetch.DEFAULT_OUTPUT == fetch.REPO_ROOT / "build" / "content"

    def test_running_the_file_as_a_script(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["fetch_content", "--manifest", str(tmp_path / "none")])
        with pytest.raises(SystemExit) as raised:
            runpy.run_path(fetch.__file__, run_name="__main__")
        assert raised.value.code == 1
