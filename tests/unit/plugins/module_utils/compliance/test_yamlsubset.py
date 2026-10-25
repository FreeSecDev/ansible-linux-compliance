from __future__ import annotations

from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    yamlsubset,
)


def load(body: str) -> object:
    return yamlsubset.load("---\n" + body)


def rejects(text: str, message: str, line: int | None = None) -> None:
    with pytest.raises(yamlsubset.YamlSubsetError, match=message) as excinfo:
        yamlsubset.load(text)
    if line is not None:
        assert excinfo.value.line == line
        assert str(excinfo.value).startswith(f"line {line}: ")


def test_loads_nested_mappings_sequences_and_scalars() -> None:
    text = (
        "schema_version: '1.0'\n"
        "exceptions:\n"
        "  - id: EXC-1\n"
        "    scope:\n"
        '      hosts: [web01, "web02"]\n'
        "      groups:\n"
        "      - legacy\n"
        "      - dmz\n"
        "    created: 2026-10-01\n"
        "  - id: EXC-2\n"
    )
    assert load(text) == {
        "schema_version": "1.0",
        "exceptions": [
            {
                "id": "EXC-1",
                "scope": {"hosts": ["web01", "web02"], "groups": ["legacy", "dmz"]},
                "created": "2026-10-01",
            },
            {"id": "EXC-2"},
        ],
    }


def test_top_level_sequence_and_nested_sequences() -> None:
    assert load("- a\n- - b\n  - c\n-\n  - d\n-\n- e\n") == ["a", ["b", "c"], ["d"], None, "e"]


def test_comments_blank_lines_and_trailing_comments_are_ignored() -> None:
    text = "# leading\n\na: b # trailing\n   \nc: d#not-a-comment\ne: 'q' # c\nf: [x] # c\ng: # c\n"
    assert load(text) == {"a": "b", "c": "d#not-a-comment", "e": "q", "f": ["x"], "g": None}


def test_document_without_final_newline() -> None:
    assert yamlsubset.load("---\na: b") == {"a": "b"}


@pytest.mark.parametrize("body", ["a:\n", "a: ~\n", "a: null\n", "a: NULL\n", "a: Null\n"])
def test_null_values(body: str) -> None:
    assert load(body) == {"a": None}


def test_absent_value_followed_by_sibling_is_null() -> None:
    assert load("a:\nb: c\n") == {"a": None, "b": "c"}


def test_plain_values_keep_colons_without_space_and_dates_as_text() -> None:
    assert load("a: http://example.com/x\nb: 0.1.82\nc: 2026-10-01\nd: a b  c\n") == {
        "a": "http://example.com/x",
        "b": "0.1.82",
        "c": "2026-10-01",
        "d": "a b  c",
    }


def test_quoted_values() -> None:
    text = "a: 'it''s'\nb: \"q\\\"\\\\\\n\\t\\/\"\nc: ''\nd: \"yes\"\ne: '1.0'\n"
    assert load(text) == {"a": "it's", "b": 'q"\\\n\t/', "c": "", "d": "yes", "e": "1.0"}


def test_flow_sequences() -> None:
    assert load("a: []\nb: [ ]\nc: [ x , 'y z', \"w\" ]\nd: [~, null]\n") == {
        "a": [],
        "b": [],
        "c": ["x", "y z", "w"],
        "d": [None, None],
    }


def test_literal_block_scalars_and_chomping() -> None:
    assert load("a: |\n  one\n    two\n\n  three\nb: x\n") == {
        "a": "one\n  two\n\nthree\n",
        "b": "x",
    }
    assert load("a: |-\n  one\n\n") == {"a": "one"}
    assert load("a: |+\n  one\n\n\nb: c\n") == {"a": "one\n\n\n", "b": "c"}
    assert load("a: | # header comment\n  one\n") == {"a": "one\n"}


def test_folded_block_scalars() -> None:
    assert load("a: >\n  one\n  two\n\n  three\n") == {"a": "one two\nthree\n"}
    assert load("a: >\n\n  one\n") == {"a": "\none\n"}
    assert load("a: >-\n  one\n  two\n\n\n  three\n\nb: x\n") == {
        "a": "one two\n\nthree",
        "b": "x",
    }


def test_block_scalar_content_and_comments() -> None:
    text = "a: |\n  # kept\n  k: v\n# real comment\nb: c\n"
    assert load(text) == {"a": "# kept\nk: v\n", "b": "c"}


def test_empty_block_scalars() -> None:
    assert load("a: |\nb: c\n") == {"a": "", "b": "c"}
    assert load("a: |+\n\nb: c\n") == {"a": "\n", "b": "c"}
    assert load("a: >-\n") == {"a": ""}


def test_block_scalar_in_a_sequence_item_mapping() -> None:
    assert load("a:\n  - b: |\n      text\n    c: d\n") == {"a": [{"b": "text\n", "c": "d"}]}


def test_block_scalar_ends_at_a_less_indented_comment() -> None:
    assert load("a: |\n    one\n  # comment\nb: c\n") == {"a": "one\n", "b": "c"}


@pytest.mark.parametrize(
    ("text", "message", "line"),
    [
        ("---\na: b\n---\nc: d\n", "only one document", 3),
        ("---\na: b\n...\n", "only one document", 3),
        ("---\n--- a\n", "only one document", 2),
        ("---\n%YAML 1.2\n", "directives are not supported", 2),
        ("%YAML 1.2\n---\na: b\n", "must start with a line that is exactly '---'", 1),
        ("a: b\n", "must start with a line", 1),
        ("--- \na: b\n", "must start with a line", 1),
        ("---\na:\tb\n", "tab characters", 2),
        ("---\na: b\r\n", "carriage returns", 2),
        ("---\na: b\x00\n", "control, surrogate", 2),
        ("---\na: \u202eb\n", "bidi", 2),
        ("---\na: \u2028\n", "separator", 2),
        ("---\na: \ud800\n", "surrogate", 2),
        ("\ufeff---\na: b\n", "bidi", 1),
        ("---\n", "no content", 2),
        ("---\n# only a comment\n\n", "no content", 4),
        ("---\n  a: b\n", "must not be indented", 2),
        ("---\n- a\nb: c\n", "unexpected content after the top-level node", 3),
        ("---\na: b\n  c: d\n", "unexpected indentation", 3),
        ("---\na: b\nc d\n", "expected 'key: value'", 3),
        ("---\na: b\n- c\n", "expected 'key: value'", 3),
        ('---\n"a": b\n', "expected 'key: value'", 2),
        ("---\na:b\n", "expected 'key: value'", 2),
        ("---\n<<: b\n", "expected 'key: value'", 2),
        ("---\nyes: b\n", "the key 'yes' is not read as a string", 2),
        ("---\nnull: b\n", "the key 'null' is not read as a string", 2),
        ("---\na: b\na: c\n", "duplicate key 'a'", 3),
        ("---\nx:\n  a: 1x\n  a: 2x\n", "duplicate key 'a'", 4),
        ("---\n- a\n  - b\n", "unexpected indentation", 3),
        ("---\na:\n  - b\n  c: d\n", "unexpected indentation", 4),
        ("---\n-   a: b\n  c: d\n", "unexpected indentation", 3),
        ("---\na: b\n  continued\n", "unexpected indentation", 3),
        ("---\na: &anchor b\n", "unsupported YAML construct starting with '&'", 2),
        ("---\na: *alias\n", "starting with '\\*'", 2),
        ("---\na: !tag b\n", "starting with '!'", 2),
        ("---\na: {b: c}\n", "starting with '{'", 2),
        ("---\na: - b\n", "starting with '-'", 2),
        ("---\na: -5\n", "starting with '-'", 2),
        ("---\n? a\n", "expected 'key: value'", 2),
        ("---\na: ? b\n", "starting with '\\?'", 2),
        ("---\na: '@b'\nc: @d\n", "starting with '@'", 3),
        ("---\na: %b\n", "starting with '%'", 2),
        ("---\na: b: c\n", "must not contain ': '", 2),
        ("---\na: b:\n", "or end with ':'", 2),
        ("---\n- a b: c\n", "must not contain ': '", 2),
        ("---\na: yes\n", "the plain value 'yes' is not read as a string", 2),
        ("---\na: Off\n", "'Off' is not read", 2),
        ("---\na: y\n", "'y' is not read", 2),
        ("---\na: =\n", "'=' is not read", 2),
        ("---\na: 1.0\n", "'1.0' is not read", 2),
        ("---\na: 1234\n", "'1234' is not read", 2),
        ("---\na: +12\n", "'\\+12' is not read", 2),
        ("---\na: 1e5\n", "'1e5' is not read", 2),
        ("---\na: 0x1F\n", "'0x1F' is not read", 2),
        ("---\na: 0o17\n", "'0o17' is not read", 2),
        ("---\na: 1:20\n", "'1:20' is not read", 2),
        ("---\na: .5\n", "'.5' is not read", 2),
        ("---\na: .inf\n", "'.inf' is not read", 2),
        ("---\na: .NaN\n", "'.NaN' is not read", 2),
        ("---\na: [1]\n", "'1' is not read", 2),
        ("---\na: 'b\n", "must end on the same line", 2),
        ('---\na: "b\n', "must end on the same line", 2),
        ('---\na: "b\\x41"\n', "unsupported escape", 2),
        ('---\na: "b\\', "unsupported escape", 2),
        ("---\na: 'b' c\n", "unexpected text after a quoted value", 2),
        ("---\na: 'b'# c\n", "unexpected text after a quoted value", 2),
        ("---\na: [b\n", "flow sequence must end on the same line", 2),
        ("---\na: [b,\n", "flow sequence must end on the same line", 2),
        ("---\na: [\n", "flow sequence must end on the same line", 2),
        ("---\na: ['b'\n", "flow sequence must end on the same line", 2),
        ("---\na: ['b' c]\n", "expected ',' or ']'", 2),
        ("---\na: [b,]\n", "must not end with a comma", 2),
        ("---\na: [b, , c]\n", "unsupported item in a flow sequence", 2),
        ("---\na: [-b]\n", "unsupported item", 2),
        ("---\na: [[b]]\n", "unsupported item", 2),
        ("---\na: [b:c]\n", "unsupported character in a flow sequence item", 2),
        ("---\na: [b #c]\n", "unsupported character", 2),
        ("---\na: [it's]\n", "unsupported character", 2),
        ("---\na: [b] c\n", "unexpected text after a quoted value or flow sequence", 2),
        ("---\na: |2\n  b\n", "unsupported block scalar header", 2),
        ("---\na: |x\n", "unsupported block scalar header", 2),
        ("---\na: |#c\n", "unsupported block scalar header", 2),
        ("---\na: >\n  b\n    more\n", "must not have more-indented lines", 4),
        ("---\na: |\n  b\n     \n  c\n", "whitespace-only line in a block scalar", 4),
        ("---\na: |\n     \n  b\n", "leading blank line in a block scalar", 4),
        ("---\na: |\n    b\n  c\n", "unexpected indentation", 4),
    ],
)
def test_rejects(text: str, message: str, line: int) -> None:
    rejects(text, message, line)


def test_rejects_text_that_is_not_a_string() -> None:
    with pytest.raises(yamlsubset.YamlSubsetError, match="the document must be text"):
        yamlsubset.load(cast("str", b"---\n"))


def test_rejects_oversized_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yamlsubset, "MAX_DOCUMENT_CHARS", 10)
    rejects("---\na: bcdefgh\n", "exceeds 10 characters", 1)


def test_rejects_documents_nested_too_deeply() -> None:
    text = (
        "---\n" + "".join(f"{'  ' * level}k{level}:\n" for level in range(8)) + "  " * 8 + "x: z\n"
    )
    rejects(text, "nested deeper than 8 levels", 10)
    allowed = (
        "---\n" + "".join(f"{'  ' * level}k{level}:\n" for level in range(7)) + "  " * 7 + "x: z\n"
    )
    assert isinstance(yamlsubset.load(allowed), dict)


def test_rejects_too_many_sequence_items(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yamlsubset, "MAX_SEQUENCE_ITEMS", 2)
    assert load("- a\n- b\n") == ["a", "b"]
    rejects("---\n- a\n- b\n- c\n", "more than 2 items", 4)
