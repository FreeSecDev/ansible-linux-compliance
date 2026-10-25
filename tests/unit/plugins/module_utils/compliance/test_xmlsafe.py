from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    xmlsafe,
)


class Recorder:
    """Recorder behaviour."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def start(self, name: str, attributes: dict[str, str]) -> None:
        self.events.append(("start", name))
        self.events.extend(("attribute", f"{key}={value}") for key, value in attributes.items())

    def end(self, name: str) -> None:
        self.events.append(("end", name))

    def text(self, data: str) -> None:
        self.events.append(("text", data))


class Explosive(Recorder):
    """Explosive behaviour."""

    def start(self, name: str, attributes: dict[str, str]) -> None:
        super().start(name, attributes)
        message = "stop"
        raise RuntimeError(message)


def parse(data: bytes, bounds: xmlsafe.XmlBounds | None = None) -> Recorder:
    recorder = Recorder()
    xmlsafe.parse_chunks([data], recorder, bounds)
    return recorder


def skip_declaration_scan(_previous: bytes, _chunk: bytes) -> bytes:
    return b""


def test_events_use_clark_notation_and_keep_attributes() -> None:
    recorder = parse(b'<a xmlns="urn:x" k="v"><b>text</b><c/></a>')
    assert recorder.events == [
        ("start", "{urn:x}a"),
        ("attribute", "k=v"),
        ("start", "{urn:x}b"),
        ("text", "text"),
        ("end", "{urn:x}b"),
        ("start", "{urn:x}c"),
        ("end", "{urn:x}c"),
        ("end", "{urn:x}a"),
    ]


def test_names_without_a_namespace_stay_plain() -> None:
    assert parse(b"<a/>").events == [("start", "a"), ("end", "a")]


def test_chunk_boundaries_may_fall_anywhere() -> None:
    document = b"<a><b>hello</b></a>"
    recorder = Recorder()
    xmlsafe.parse_chunks([document[:5], document[5:11], document[11:]], recorder)
    assert ("text", "hello") in recorder.events


@pytest.mark.parametrize(
    "document",
    [
        b'<?xml version="1.0"?><!DOCTYPE a SYSTEM "http://127.0.0.1:9/x.dtd"><a/>',
        b'<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>',
        b'<a/><!ENTITY e "x">',
    ],
)
def test_declarations_are_rejected_before_parsing(document: bytes) -> None:
    recorder = Recorder()
    with pytest.raises(xmlsafe.XmlSafetyError, match="DOCTYPE and ENTITY"):
        xmlsafe.parse_chunks([document], recorder)
    assert recorder.events == []


def test_declarations_are_rejected_across_chunk_boundaries() -> None:
    document = b"<!DOCTYPE a><a/>"
    for split in range(1, len(b"<!DOCTYPE")):
        with pytest.raises(xmlsafe.XmlSafetyError, match="DOCTYPE and ENTITY"):
            xmlsafe.parse_chunks([document[:split], document[split:]], Recorder())


@pytest.mark.parametrize(
    "document",
    [
        b'<!DOCTYPE a SYSTEM "http://127.0.0.1:9/x.dtd"><a/>',
        b'<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>',
    ],
)
def test_the_parser_handlers_reject_declarations_even_if_the_scan_is_bypassed(
    monkeypatch: pytest.MonkeyPatch, document: bytes
) -> None:
    monkeypatch.setattr(xmlsafe, "_scan_for_declarations", skip_declaration_scan)
    with pytest.raises(xmlsafe.XmlSafetyError, match="DOCTYPE, ENTITY"):
        xmlsafe.parse_chunks([document], Recorder())


def test_external_entities_are_rejected_by_the_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xmlsafe, "_scan_for_declarations", skip_declaration_scan)
    document = b'<!DOCTYPE a [<!ENTITY % p SYSTEM "http://127.0.0.1:9/p">%p;]><a/>'
    with pytest.raises(xmlsafe.XmlSafetyError):
        xmlsafe.parse_chunks([document], Recorder())


@pytest.mark.parametrize("mark", [b"\xff\xfe", b"\xfe\xff"])
def test_utf16_and_utf32_are_rejected(mark: bytes) -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="UTF-16 or UTF-32"):
        parse(mark + "<a/>".encode("utf-16-le"))


def test_a_nul_byte_is_rejected() -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="NUL"):
        parse(b"<a>\x00</a>")


@pytest.mark.parametrize("chunks", [[], [b""]])
def test_an_empty_document_is_rejected(chunks: list[bytes]) -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="empty"):
        xmlsafe.parse_chunks(chunks, Recorder())


@pytest.mark.parametrize("document", [b"<a><b></a>", b"<a>", b"not xml", b"<a></a><b/>"])
def test_malformed_documents_are_rejected(document: bytes) -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="not well-formed"):
        parse(document)


def test_the_element_count_is_bounded() -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="more than 3 elements"):
        parse(b"<a><b/><b/><b/></a>", xmlsafe.XmlBounds(max_elements=3, max_depth=10))
    assert len(parse(b"<a><b/><b/></a>", xmlsafe.XmlBounds(max_elements=3)).events) == 6


def test_the_depth_is_bounded() -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="deeper than 3"):
        parse(b"<a><a><a><a/></a></a></a>", xmlsafe.XmlBounds(max_depth=3))
    parse(b"<a><a><a/></a></a>", xmlsafe.XmlBounds(max_depth=3))


def test_errors_from_the_receiver_propagate() -> None:
    with pytest.raises(RuntimeError, match="stop"):
        xmlsafe.parse_chunks([b"<a/>"], Explosive())


def test_default_bounds_are_documented_values() -> None:
    bounds = xmlsafe.XmlBounds()
    assert (bounds.max_elements, bounds.max_depth) == (5_000_000, 64)


def test_a_regular_file_is_streamed_in_chunks(tmp_path: Path) -> None:
    path = tmp_path / "data.xml"
    path.write_bytes(b"x" * 10)
    assert b"".join(xmlsafe.iter_file_chunks(str(path), 10)) == b"x" * 10


def test_a_file_over_the_bound_is_rejected_before_reading(tmp_path: Path) -> None:
    path = tmp_path / "data.xml"
    path.write_bytes(b"x" * 11)
    with pytest.raises(xmlsafe.XmlSafetyError, match="larger than 10 bytes"):
        next(xmlsafe.iter_file_chunks(str(path), 10))


def test_a_file_that_grows_while_reading_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "data.xml"
    path.write_bytes(b"x" * 11)
    real = Path.lstat

    def understated(self: Path) -> os.stat_result:
        info = real(self)
        values = list(info)
        values[6] = 3
        return os.stat_result(values)

    monkeypatch.setattr(Path, "lstat", understated)
    with pytest.raises(xmlsafe.XmlSafetyError, match="larger than 10 bytes"):
        list(xmlsafe.iter_file_chunks(str(path), 10))


def test_a_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.xml"
    target.write_bytes(b"<a/>")
    link = tmp_path / "link.xml"
    link.symlink_to(target)
    with pytest.raises(xmlsafe.XmlSafetyError, match="not a regular file"):
        next(xmlsafe.iter_file_chunks(str(link), 100))


def test_a_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="not a regular file"):
        next(xmlsafe.iter_file_chunks(str(tmp_path), 100))


def test_a_missing_file_is_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match="cannot be read"):
        next(xmlsafe.iter_file_chunks(str(tmp_path / "missing.xml"), 100))


def test_an_error_without_a_message_names_its_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_self: Path) -> os.stat_result:
        raise OSError

    monkeypatch.setattr(Path, "lstat", refuse)
    with pytest.raises(xmlsafe.XmlSafetyError, match="OSError"):
        next(xmlsafe.iter_file_chunks(str(tmp_path / "x.xml"), 100))


def test_a_handle_can_be_read_twice(tmp_path: Path) -> None:
    path = tmp_path / "data.xml"
    path.write_bytes(b"x" * 10)
    with xmlsafe.open_regular(str(path), 10) as handle:
        first = b"".join(xmlsafe.iter_handle_chunks(handle, 10))
        second = b"".join(xmlsafe.iter_handle_chunks(handle, 10))
    assert first == second == b"x" * 10


def test_a_read_error_on_an_open_handle_is_a_clean_error() -> None:
    class Broken:
        """Handle whose seek fails."""

        def seek(self, _offset: int) -> Any:
            raise OSError

    with pytest.raises(xmlsafe.XmlSafetyError, match="OSError"):
        list(xmlsafe.iter_handle_chunks(cast("Any", Broken()), 10))


def test_text_is_parsed_like_its_utf8_bytes() -> None:
    document = '<a xmlns="urn:x">café</a>'
    recorder = Recorder()
    xmlsafe.parse_text(document, recorder)
    assert recorder.events == parse(document.encode("utf-8")).events
    assert ("text", "café") in recorder.events


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("<a>\ud800</a>", "not valid Unicode text"),
        ("", "empty"),
        ("<!DOCTYPE a><a/>", "DOCTYPE and ENTITY"),
        ("<a>\x00</a>", "NUL"),
        ("<a><a><a/></a></a>", "deeper than 2"),
    ],
)
def test_text_gets_every_check_of_the_byte_parser(document: str, message: str) -> None:
    with pytest.raises(xmlsafe.XmlSafetyError, match=message):
        xmlsafe.parse_text(document, Recorder(), xmlsafe.XmlBounds(max_depth=2))


def test_errors_from_the_receiver_propagate_for_text() -> None:
    with pytest.raises(RuntimeError, match="stop"):
        xmlsafe.parse_text("<a/>", Explosive())


def test_the_subject_names_the_file_in_messages(tmp_path: Path) -> None:
    path = tmp_path / "data.xml"
    path.write_bytes(b"x" * 11)
    with pytest.raises(xmlsafe.XmlSafetyError, match=r"^the results file is larger than 10 bytes$"):
        next(xmlsafe.iter_file_chunks(str(path), 10, subject="results"))
    with pytest.raises(xmlsafe.XmlSafetyError, match=r"^the results path is not a regular file$"):
        next(xmlsafe.iter_file_chunks(str(tmp_path), 10, subject="results"))
    with pytest.raises(xmlsafe.XmlSafetyError, match=r"^the results file cannot be read: "):
        next(xmlsafe.iter_file_chunks(str(tmp_path / "missing.xml"), 10, subject="results"))
    grown = r"^the results file is larger than 5 bytes$"
    with xmlsafe.open_regular(str(path), 11) as handle, pytest.raises(ValueError, match=grown):
        list(xmlsafe.iter_handle_chunks(handle, 5, subject="results"))


def test_without_a_subject_the_messages_are_generic(tmp_path: Path) -> None:
    path = tmp_path / "data.xml"
    path.write_bytes(b"x" * 11)
    with pytest.raises(xmlsafe.XmlSafetyError, match=r"^the file is larger than 10 bytes$"):
        next(xmlsafe.iter_file_chunks(str(path), 10))
    with pytest.raises(xmlsafe.XmlSafetyError, match=r"^the path is not a regular file$"):
        next(xmlsafe.iter_file_chunks(str(tmp_path), 10))


def test_a_read_error_names_the_subject() -> None:
    class Broken:
        """Handle whose seek fails."""

        def seek(self, _offset: int) -> Any:
            raise OSError

    with pytest.raises(xmlsafe.XmlSafetyError, match=r"^the results file cannot be read: OSError$"):
        list(xmlsafe.iter_handle_chunks(cast("Any", Broken()), 10, subject="results"))
