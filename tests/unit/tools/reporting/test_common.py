from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tools.reporting import common
from tools.reporting.common import InvalidInputError, SectionStatus

if TYPE_CHECKING:
    from collections.abc import Callable


BOOLEAN: object = True


def build_upper(data: bytes) -> str:
    return data.decode("ascii").upper()


def build_reject(_data: bytes) -> str:
    message = "rejected on purpose"
    raise InvalidInputError(message)


def test_run_parser_available_keeps_path_hash_and_size(write: Callable[..., Path]) -> None:
    path = write("a.txt", b"abc")
    result = common.run_parser(path, "demo", 100, build_upper)
    assert result.status is SectionStatus.AVAILABLE
    assert result.data == "ABC"
    assert result.reason is None
    assert result.artifact == common.ArtifactRef(str(path), hashlib.sha256(b"abc").hexdigest(), 3)


def test_run_parser_missing_file_is_unavailable(tmp_path: Path) -> None:
    result = common.run_parser(tmp_path / "absent", "demo", 100, build_upper)
    assert result.status is SectionStatus.UNAVAILABLE
    assert result.data is None
    assert result.artifact.sha256 is None


@pytest.mark.parametrize(
    ("content", "expected"),
    [(b"", "empty"), (b"x" * 11, "larger than 10")],
)
def test_run_parser_empty_or_huge_is_error(
    write: Callable[..., Path], content: bytes, expected: str
) -> None:
    result = common.run_parser(write("a.txt", content), "demo", 10, build_upper)
    assert result.status is SectionStatus.ERROR
    assert result.reason is not None
    assert expected in result.reason
    assert result.data is None


def test_run_parser_directory_is_error(tmp_path: Path) -> None:
    result = common.run_parser(tmp_path, "demo", 10, build_upper)
    assert result.status is SectionStatus.ERROR
    assert result.reason == "input path is not a regular file"


def test_run_parser_symlink_is_error(tmp_path: Path, write: Callable[..., Path]) -> None:
    target = write("real.txt", b"abc")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    result = common.run_parser(link, "demo", 100, build_upper)
    assert result.status is SectionStatus.ERROR


def test_run_parser_uninspectable_path_is_error(write: Callable[..., Path]) -> None:
    file_path = write("plain", b"abc")
    result = common.run_parser(file_path / "child", "demo", 100, build_upper)
    assert result.status is SectionStatus.ERROR
    assert result.reason == "input file cannot be inspected"


def test_run_parser_unreadable_file_is_error(
    write: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write("a.txt", b"abc")

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise PermissionError

    monkeypatch.setattr(Path, "open", refuse)
    result = common.run_parser(path, "demo", 100, build_upper)
    assert result.status is SectionStatus.ERROR
    assert result.reason == "input file cannot be read"


def test_run_parser_keeps_reference_when_content_is_rejected(write: Callable[..., Path]) -> None:
    result = common.run_parser(write("a.txt", b"abc"), "demo", 100, build_reject)
    assert result.status is SectionStatus.ERROR
    assert result.reason == "rejected on purpose"
    assert result.artifact.sha256 == hashlib.sha256(b"abc").hexdigest()


def test_run_parser_cleans_control_characters_in_the_path(tmp_path: Path) -> None:
    result = common.run_parser(tmp_path / "bad\x07name", "demo", 100, build_upper)
    assert result.artifact.path.endswith("badname")


def test_clean_text_removes_controls_and_cuts() -> None:
    assert common.clean_text("a\x00b\u202ec\u2028d\ne\tf") == "abcd\ne\tf"
    assert common.clean_text("abcdef", 3) == "abc"


@pytest.mark.parametrize(
    "payload",
    [b"\xff\xfe", b"{", b'{"a": 1, "a": 2}', b"NaN", b"[Infinity]", b"[" * 100000],
)
def test_load_json_rejects_bad_documents(payload: bytes) -> None:
    with pytest.raises(InvalidInputError):
        common.load_json(payload)


def test_load_json_accepts_plain_documents() -> None:
    assert common.load_json(b'{"a": [1, 2.5, null]}') == {"a": [1, 2.5, None]}


def test_decode_text_rejects_non_utf8() -> None:
    with pytest.raises(InvalidInputError):
        common.decode_text(b"\xff")


def test_typed_accessors() -> None:
    assert common.as_object({"a": 1}, "x") == {"a": 1}
    assert common.as_list([1], "x") == [1]
    assert common.as_text("  ok\x00 ", "x") == "  ok "
    assert common.as_count(3, "x") == 3
    assert common.as_rate(1, "x") == 1.0
    assert common.require({"a": 1}, "a", "x") == 1
    assert common.optional_text({"a": "b"}, "a", "x") == "b"
    assert common.optional_text({}, "a", "x") is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: common.as_object([], "x"),
        lambda: common.as_list({}, "x"),
        lambda: common.as_text(1, "x"),
        lambda: common.as_text("\x00", "x"),
        lambda: common.as_count(BOOLEAN, "x"),
        lambda: common.as_count(-1, "x"),
        lambda: common.as_count(10**10, "x"),
        lambda: common.as_count(1.5, "x"),
        lambda: common.as_rate(BOOLEAN, "x"),
        lambda: common.as_rate(1.5, "x"),
        lambda: common.as_rate("0.5", "x"),
        lambda: common.require({}, "a", "x"),
        lambda: common.optional_text({"a": 1}, "a", "x"),
    ],
)
def test_typed_accessors_reject(call: Callable[[], object]) -> None:
    with pytest.raises(InvalidInputError):
        call()


def test_dig_follows_keys_and_indexes() -> None:
    document = {"a": [{"b": 5}]}
    assert common.dig(document, "a", 0, "b") == 5
    assert common.dig(document, "a", 1) is None
    assert common.dig(document, "a", "b") is None
    assert common.dig(document, "z") is None
    assert common.dig(5, 0) is None


def test_maybe_helpers() -> None:
    assert common.maybe_text("x") == "x"
    assert common.maybe_text("\x00") is None
    assert common.maybe_text(3) is None
    assert common.maybe_count(3) == 3
    assert common.maybe_count(BOOLEAN) is None
    assert common.maybe_count(-1) is None
    assert common.maybe_count("3") is None
    assert common.maybe_count(5, 4) is None


def test_severity_counts_lists_every_severity() -> None:
    counts = common.severity_counts(["high", "high", "unknown"])
    assert counts == {
        "critical": 0,
        "high": 2,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 1,
    }


class Colour(Enum):
    """An enum value to serialize."""

    RED = "red"


@dataclass(frozen=True)
class Pair:
    """A dataclass to serialize."""

    left: int
    right: tuple[str, ...]


class WithDict:
    """An object with its own mapping."""

    def to_dict(self) -> dict[str, object]:
        return {"k": Colour.RED}


def test_to_json_converts_supported_values() -> None:
    value = {"p": Pair(1, ("a",)), "e": Colour.RED, "d": WithDict(), "n": None, "f": 1.5}
    assert common.to_json(value) == {
        "p": {"left": 1, "right": ["a"]},
        "e": "red",
        "d": {"k": "red"},
        "n": None,
        "f": 1.5,
    }


def test_to_json_rejects_unsupported_values() -> None:
    with pytest.raises(TypeError):
        common.to_json(object())
    with pytest.raises(TypeError):
        common.to_json(Pair)


def test_dumps_is_sorted_ascii_and_newline_terminated() -> None:
    text = common.dumps({"b": 1, "a": "é"})
    assert text == '{\n  "a": "\\u00e9",\n  "b": 1\n}\n'
    with pytest.raises(ValueError, match="Out of range"):
        common.dumps({"a": float("nan")})
