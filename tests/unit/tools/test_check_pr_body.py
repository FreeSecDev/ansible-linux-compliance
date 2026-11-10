"""The pull request body footer check (FREES-204).

The squash commit message is the pull request body, so the body's last line must be the
``Refs: FREES-<n>`` footer, in a paragraph of trailer lines only. Dependabot pull requests
are exempt (FREES-81).
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

from tools.lint import check_pr_body

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GENERATED = "🤖 Generated with [Claude Code](https://claude.com/claude-code)"


@pytest.mark.parametrize(
    "body",
    [
        "Refs: FREES-1",
        f"## What\n\nText.\n\n{GENERATED}\n\nRefs: FREES-204",
        f"Text.\n\n{GENERATED}\n\nRefs: FREES-204\n",
        f"Text.\n\n{GENERATED}\n\nRefs: FREES-204\n\n\n",
        f"Text.\r\n\r\n{GENERATED}\r\n\r\nRefs: FREES-204\r\n",
        "Text.\n\nRefs: FREES-204   \n",
        "Text.\n\nCo-Authored-By: Claude <noreply@anthropic.com>\nRefs: FREES-204",
        "Text.\n\nRefs: FREES-207, FREES-210",
    ],
)
def test_a_body_that_ends_with_the_footer_is_valid(body: str) -> None:
    assert check_pr_body.footer_findings(body) == []


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ("", "the pull request body is empty"),
        ("\n \n\r\n", "the pull request body is empty"),
        (f"Text.\n\nRefs: FREES-204\n\n{GENERATED}", "not a Refs footer"),
        ("Text.\n\nRefs: FREES-204\nCo-Authored-By: Claude <noreply@anthropic.com>", "not a Refs"),
        ("Text.\n\nrefs: FREES-204", "not a Refs footer"),
        ("Text.\n\nRefs: FREES-0", "not a Refs footer"),
        ("Text.\n\nRefs: FREES-204,FREES-205", "not a Refs footer"),
        ("Text.\n\nRefs: FREES-204 and more", "not a Refs footer"),
        ("Text.\n\nRefs: #204", "not a Refs footer"),
        ("Text.\n\n`Refs: FREES-204`", "not a Refs footer"),
        (f"Text.\n\n{GENERATED}\nRefs: FREES-204", "is not a trailer"),
        ("Text right above the footer\nRefs: FREES-204", "is not a trailer"),
    ],
)
def test_a_body_without_the_footer_last_is_refused(body: str, fragment: str) -> None:
    findings = check_pr_body.footer_findings(body)
    assert len(findings) == 1
    assert fragment in findings[0]


def test_each_line_that_is_not_a_trailer_is_named() -> None:
    body = "Text.\n\nfirst prose\nCo-Authored-By: A <a@example.org>\nsecond prose\nRefs: FREES-1"
    findings = check_pr_body.footer_findings(body)
    assert [finding.split(":", 1)[0] for finding in findings] == [
        "the footer paragraph holds a line that is not a trailer, 'first prose'",
        "the footer paragraph holds a line that is not a trailer, 'second prose'",
    ]


@pytest.mark.parametrize(
    ("head_ref", "body", "valid"),
    [
        ("chore/FREES-204-review-policy-followups", "Refs: FREES-204", True),
        ("chore/FREES-204-review-policy-followups", "Refs: FREES-1, FREES-204", True),
        ("chore/FREES-204-review-policy-followups", "Refs: FREES-20", False),
        ("chore/FREES-204-review-policy-followups", "Refs: FREES-2040", False),
        ("fix/FREES-207-process-policy-copy", "Refs: FREES-207, FREES-210", True),
        ("dependabot/uv/dev-tools-bf61a79f8a", "Refs: FREES-81", True),
        ("", "Refs: FREES-1", True),
    ],
)
def test_the_footer_lists_the_key_of_the_branch(head_ref: str, body: str, valid: bool) -> None:
    findings = check_pr_body.footer_findings(body, head_ref)
    assert (findings == []) is valid
    if not valid:
        assert findings == [
            f"the footer {body!r} does not list FREES-204, the key of the branch {head_ref!r}"
        ]


def test_main_accepts_a_valid_body(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    body = tmp_path / "body.md"
    body.write_text(f"Text.\n\n{GENERATED}\n\nRefs: FREES-204\n", encoding="utf-8")
    arguments = ["--body-file", str(body), "--author", "stefanfluit"]
    assert check_pr_body.main([*arguments, "--head-ref", "chore/FREES-204-x"]) == 0
    assert "ends with its Refs footer" in capsys.readouterr().out


def test_main_refuses_a_body_without_the_footer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = tmp_path / "body.md"
    body.write_text(f"Text.\n\nRefs: FREES-204\n\n{GENERATED}\n", encoding="utf-8")
    assert check_pr_body.main(["--body-file", str(body)]) == 1
    error = capsys.readouterr().err
    assert error.startswith("error: the last line of the body is ")
    assert "attribution lines come before it" in error


def test_main_exempts_dependabot_without_reading_the_body(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "absent.md"
    assert check_pr_body.main(["--body-file", str(missing), "--author", "dependabot[bot]"]) == 0
    assert "exempt: dependabot[bot]" in capsys.readouterr().out


@pytest.mark.parametrize("author", ["dependabot", "renovate[bot]", "github-actions[bot]"])
def test_only_dependabot_is_exempt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], author: str
) -> None:
    body = tmp_path / "body.md"
    body.write_text("Bump things.\n", encoding="utf-8")
    assert check_pr_body.main(["--body-file", str(body), "--author", author]) == 1
    assert "not a Refs footer" in capsys.readouterr().err


def test_script_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    body = tmp_path / "body.md"
    body.write_text("Refs: FREES-1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_pr_body", "--body-file", str(body)])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(check_pr_body.__file__, run_name="__main__")
    assert raised.value.code == 0
    assert "Refs footer" in capsys.readouterr().out


def test_the_template_ends_with_a_footer_that_must_be_filled_in() -> None:
    template = REPOSITORY_ROOT / ".github" / "pull_request_template.md"
    text = template.read_text(encoding="utf-8")
    assert text.rstrip().splitlines()[-1] == "Refs: FREES-NNN"
    assert "not a Refs footer" in check_pr_body.footer_findings(text)[0]
    filled = text.replace("Refs: FREES-NNN", "Refs: FREES-204")
    assert check_pr_body.footer_findings(filled, "chore/FREES-204-x") == []
