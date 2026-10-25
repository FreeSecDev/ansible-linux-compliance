from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

from tools.skills import validate_skills as skills

SECTIONS = "\n\n".join(f"## {section}\n\ntext" for section in skills.REQUIRED_SECTIONS)


def skill_text(
    name: str = "demo",
    description: str = "A demo skill.",
    body: str | None = None,
    extra: str = "",
) -> str:
    content = SECTIONS if body is None else body
    return f"---\nname: {name}\ndescription: {description}\n{extra}---\n\n# Demo\n\n{content}\n"


def write_skill(root: Path, name: str, text: str | None = None) -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        skill_text(name) if text is None else text, encoding="utf-8"
    )
    return directory


def parse(directory: Path) -> tuple[skills.Skill | None, list[str]]:
    report = skills.Report()
    return skills.parse_skill(directory, report), report.errors


def body_errors(directory: Path, known: frozenset[str] = frozenset({"demo"})) -> list[str]:
    skill, errors = parse(directory)
    assert skill is not None
    assert errors == []
    report = skills.Report()
    skills.check_body(skill, known, report)
    return report.errors


def test_report_add_formats_location() -> None:
    report = skills.Report()
    report.add(Path("a/b"), "problem")
    report.add("text", "other")
    assert report.errors == ["a/b: problem", "text: other"]


def test_parse_valid_skill(tmp_path: Path) -> None:
    skill, errors = parse(write_skill(tmp_path, "demo"))
    assert errors == []
    assert skill is not None
    assert skill.frontmatter["name"] == "demo"
    assert "## Inputs" in skill.body


def test_parse_missing_file(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    directory.mkdir()
    skill, errors = parse(directory)
    assert skill is None
    assert errors == [f"{directory}: missing SKILL.md"]


def test_parse_skill_md_is_a_directory(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    (directory / "SKILL.md").mkdir(parents=True)
    skill, errors = parse(directory)
    assert skill is None
    assert "missing SKILL.md" in errors[0]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "must start with a '---' frontmatter delimiter"),
        ("\n", "must start with a '---' frontmatter delimiter"),
        ("name: demo\n", "must start with a '---' frontmatter delimiter"),
        ("﻿---\nname: demo\n---\n", "must start with a '---' frontmatter delimiter"),
        (" ---\nname: demo\n---\n", "must start with a '---' frontmatter delimiter"),
        ("---\nname: demo\n", "frontmatter is not terminated by '---'"),
        ("---", "frontmatter is not terminated by '---'"),
        ("---\n", "frontmatter is not terminated by '---'"),
        ("---\n---\n", "frontmatter must be a mapping"),
        ("---\n---", "frontmatter must be a mapping"),
        ("---\n- a\n- b\n---\n", "frontmatter must be a mapping"),
        ("---\njust text\n---\n", "frontmatter must be a mapping"),
        ("---\nkey: [unclosed\n---\n", "frontmatter is not valid YAML"),
        ("---\nname: a: b: c\n---\n", "frontmatter is not valid YAML"),
    ],
)
def test_parse_rejects_malformed_frontmatter(tmp_path: Path, text: str, message: str) -> None:
    skill, errors = parse(write_skill(tmp_path, "demo", text))
    assert skill is None
    assert len(errors) == 1
    assert message in errors[0]


def test_parse_accepts_closing_delimiter_at_end_of_file(tmp_path: Path) -> None:
    skill, errors = parse(write_skill(tmp_path, "demo", "---\nname: demo\n---"))
    assert errors == []
    assert skill is not None
    assert skill.body == ""


def test_parse_accepts_crlf(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    directory.mkdir()
    (directory / "SKILL.md").write_bytes(b"---\r\nname: demo\r\ndescription: d\r\n---\r\nbody\r\n")
    skill, errors = parse(directory)
    assert errors == []
    assert skill is not None
    assert skill.frontmatter == {"name": "demo", "description": "d"}


def test_parse_horizontal_rule_in_body_does_not_end_frontmatter_early(tmp_path: Path) -> None:
    skill, errors = parse(
        write_skill(tmp_path, "demo", "---\nname: demo\n---\n\ntext\n\n---\n\nmore\n")
    )
    assert errors == []
    assert skill is not None
    assert "more" in skill.body


def test_parse_non_utf8_file_is_reported_not_raised(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    directory.mkdir()
    (directory / "SKILL.md").write_bytes(b"---\nname: demo\n---\n\xff\xfe\n")
    skill, errors = parse(directory)
    assert skill is None
    assert "cannot be read as UTF-8 text" in errors[0]


def test_parse_unicode_frontmatter(tmp_path: Path) -> None:
    text = '---\nname: demo\ndescription: "Überprüfung 検査 🔒"\n---\nbody\n'
    skill, errors = parse(write_skill(tmp_path, "demo", text))
    assert errors == []
    assert skill is not None
    assert skill.frontmatter["description"] == "Überprüfung 検査 🔒"


def test_parse_coerces_non_string_keys(tmp_path: Path) -> None:
    skill, _ = parse(write_skill(tmp_path, "demo", "---\n1: a\nname: demo\n---\n"))
    assert skill is not None
    assert set(skill.frontmatter) == {"1", "name"}


def make_skill(directory: Path, frontmatter: dict[str, object]) -> skills.Skill:
    return skills.Skill(directory=directory, frontmatter=frontmatter, body="")


def frontmatter_errors(directory: Path, frontmatter: dict[str, object]) -> list[str]:
    report = skills.Report()
    skills.check_frontmatter(make_skill(directory, frontmatter), report)
    return report.errors


def test_frontmatter_valid(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    assert (
        frontmatter_errors(directory, {"name": "demo", "description": "ok", "license": "MIT"}) == []
    )


def test_frontmatter_unknown_keys_sorted(tmp_path: Path) -> None:
    errors = frontmatter_errors(
        tmp_path / "demo", {"name": "demo", "description": "ok", "zeta": 1, "alpha": 2}
    )
    assert len(errors) == 1
    assert "unsupported frontmatter keys: alpha, zeta" in errors[0]


@pytest.mark.parametrize(
    "name",
    [None, 5, True, "", "Demo", "demo_x", "-demo", "demo-", "de--mo", "de mo", "demo\n", "démo"],
)
def test_frontmatter_invalid_names(tmp_path: Path, name: object) -> None:
    frontmatter: dict[str, object] = {"description": "ok"}
    if name is not None:
        frontmatter["name"] = name
    errors = frontmatter_errors(tmp_path / "demo", frontmatter)
    assert len(errors) == 1
    assert "name must be lowercase letters, digits and single hyphens" in errors[0]


def test_frontmatter_name_too_long(tmp_path: Path) -> None:
    name = "a" * (skills.MAX_NAME_LENGTH + 1)
    errors = frontmatter_errors(tmp_path / name, {"name": name, "description": "ok"})
    assert errors[0].endswith(f"name exceeds {skills.MAX_NAME_LENGTH} characters")


def test_frontmatter_name_at_limit_is_accepted(tmp_path: Path) -> None:
    name = "a" * skills.MAX_NAME_LENGTH
    assert frontmatter_errors(tmp_path / name, {"name": name, "description": "ok"}) == []


def test_frontmatter_name_directory_mismatch(tmp_path: Path) -> None:
    errors = frontmatter_errors(tmp_path / "other", {"name": "demo", "description": "ok"})
    assert errors[0].endswith("name 'demo' does not match directory 'other'")


@pytest.mark.parametrize("description", [None, "", "   \n", 5, ["a"], True])
def test_frontmatter_invalid_descriptions(tmp_path: Path, description: object) -> None:
    frontmatter: dict[str, object] = {"name": "demo"}
    if description is not None:
        frontmatter["description"] = description
    errors = frontmatter_errors(tmp_path / "demo", frontmatter)
    assert len(errors) == 1
    assert "description must be a non-empty string" in errors[0]


def test_frontmatter_description_length_boundary(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    at_limit = "d" * skills.MAX_DESCRIPTION_LENGTH
    assert frontmatter_errors(directory, {"name": "demo", "description": at_limit}) == []
    errors = frontmatter_errors(directory, {"name": "demo", "description": at_limit + "d"})
    assert errors[0].endswith(f"description exceeds {skills.MAX_DESCRIPTION_LENGTH} characters")


def test_body_valid(tmp_path: Path) -> None:
    assert body_errors(write_skill(tmp_path, "demo")) == []


def test_body_missing_sections(tmp_path: Path) -> None:
    directory = write_skill(tmp_path, "demo", skill_text(body="## Inputs\n\ntext"))
    errors = body_errors(directory)
    assert len(errors) == len(skills.REQUIRED_SECTIONS) - 1
    assert any("missing required section '## When to use'" in error for error in errors)


def test_body_empty(tmp_path: Path) -> None:
    errors = body_errors(write_skill(tmp_path, "demo", skill_text(body="")))
    assert len(errors) == len(skills.REQUIRED_SECTIONS)


def test_body_sections_inside_code_fence_do_not_count(tmp_path: Path) -> None:
    fenced = "```markdown\n" + SECTIONS + "\n```"
    errors = body_errors(write_skill(tmp_path, "demo", skill_text(body=fenced)))
    assert len(errors) == len(skills.REQUIRED_SECTIONS)


def test_body_sections_inside_tilde_fence_do_not_count(tmp_path: Path) -> None:
    fenced = "~~~\n" + SECTIONS + "\n~~~"
    errors = body_errors(write_skill(tmp_path, "demo", skill_text(body=fenced)))
    assert len(errors) == len(skills.REQUIRED_SECTIONS)


def test_body_fence_closed_only_by_matching_marker(tmp_path: Path) -> None:
    fenced = "```\n~~~\n" + SECTIONS + "\n```\n" + SECTIONS
    assert body_errors(write_skill(tmp_path, "demo", skill_text(body=fenced))) == []


def test_body_line_limit(tmp_path: Path) -> None:
    padding = "\n".join("x" for _ in range(skills.MAX_BODY_LINES))
    errors = body_errors(write_skill(tmp_path, "demo", skill_text(body=SECTIONS + "\n" + padding)))
    assert any("body exceeds" in error for error in errors)


def test_body_local_links(tmp_path: Path) -> None:
    directory = write_skill(tmp_path, "demo")
    (directory / "references").mkdir()
    (directory / "references" / "ok.md").write_text("x\n", encoding="utf-8")
    links = (
        "[ok](references/ok.md) [anchor](references/ok.md#top) [web](https://example.org/x) "
        "[plain](http://example.org) [self](#local) [mail](mailto:a@b.c) "
        "[gone](references/gone.md) "
        "[gone2](missing/file.md#x)"
    )
    (directory / "SKILL.md").write_text(skill_text(body=SECTIONS + "\n" + links), encoding="utf-8")
    errors = body_errors(directory)
    assert [error.rsplit(": ", 1)[1] for error in errors] == [
        "broken local link 'references/gone.md'",
        "broken local link 'missing/file.md#x'",
    ]


@pytest.mark.parametrize(
    "target",
    ["/etc/passwd", "/", "bad%00name", "a\x00b", "x" * 5000],
)
def test_body_hostile_link_targets_are_reported_not_raised(tmp_path: Path, target: str) -> None:
    directory = write_skill(tmp_path, "demo")
    body = SECTIONS + f"\n[link]({target})"
    (directory / "SKILL.md").write_text(skill_text(body=body), encoding="utf-8")
    errors = body_errors(directory)
    assert len(errors) <= 1
    assert all("broken local link" in error for error in errors)


@pytest.mark.parametrize("target", ["/etc/passwd", "/", "a\x00b", "x" * 5000])
def test_link_target_exists_rejects_hostile_targets(tmp_path: Path, target: str) -> None:
    assert skills.link_target_exists(tmp_path, target) is False


def test_link_target_exists_accepts_directory_and_parent(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    assert skills.link_target_exists(tmp_path, "sub") is True
    assert skills.link_target_exists(tmp_path / "sub", "../sub#anchor") is True


def test_body_links_in_code_fence_are_ignored(tmp_path: Path) -> None:
    directory = write_skill(tmp_path, "demo")
    body = SECTIONS + "\n```\n[x](missing.md)\n```\n"
    (directory / "SKILL.md").write_text(skill_text(body=body), encoding="utf-8")
    assert body_errors(directory) == []


def test_body_skill_references(tmp_path: Path) -> None:
    interaction = (
        "## Interaction with other skills\n\n- Uses `known-skill` and `unknown-skill` and `make`."
    )
    sections = "\n\n".join(
        f"## {section}\n\ntext"
        for section in skills.REQUIRED_SECTIONS
        if section != skills.INTERACTION_SECTION
    )
    directory = write_skill(tmp_path, "demo", skill_text(body=sections + "\n\n" + interaction))
    errors = body_errors(directory, frozenset({"known-skill"}))
    assert [error.rsplit(": ", 1)[1] for error in errors] == [
        "references unknown skill 'unknown-skill'",
        "references unknown skill 'make'",
    ]


def test_section_text_boundaries() -> None:
    lines = ["intro", "## A", "a1", "a2", "## B", "b1", "## A", "a3"]
    assert skills.section_text(lines, "A") == "a1\na2\na3"
    assert skills.section_text(lines, "missing") == ""
    assert skills.section_text([], "A") == ""


def test_prose_lines_unterminated_fence_hides_rest() -> None:
    assert skills.prose_lines("a\n```\nb\nc") == ["a"]
    assert skills.prose_lines("") == []
    assert skills.prose_lines("  ```\nb\n  ```\nc") == ["c"]


def test_validate_missing_root(tmp_path: Path) -> None:
    report = skills.validate(tmp_path / "nope", frozenset())
    assert report.errors == [f"{tmp_path / 'nope'}: skills directory does not exist"]


def test_validate_root_is_a_file(tmp_path: Path) -> None:
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")
    assert "does not exist" in skills.validate(target, frozenset()).errors[0]


def test_validate_empty_root_reports_required(tmp_path: Path) -> None:
    report = skills.validate(tmp_path, frozenset({"b", "a"}))
    assert report.errors == [
        f"{tmp_path}: required skill 'a' is missing",
        f"{tmp_path}: required skill 'b' is missing",
    ]


def test_validate_ignores_plain_files_in_root(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("x", encoding="utf-8")
    assert skills.validate(tmp_path, frozenset()).errors == []


def test_validate_reports_directory_without_skill_file(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    report = skills.validate(tmp_path, frozenset({"empty"}))
    assert report.errors == [f"{tmp_path / 'empty'}: missing SKILL.md"]


def test_validate_full_pass_with_external_reference(tmp_path: Path) -> None:
    interaction = "## Interaction with other skills\n\n- Delegates to `sibling`."
    sections = "\n\n".join(
        f"## {section}\n\ntext"
        for section in skills.REQUIRED_SECTIONS
        if section != skills.INTERACTION_SECTION
    )
    write_skill(tmp_path, "demo", skill_text(body=sections + "\n\n" + interaction))
    assert skills.validate(tmp_path, frozenset({"demo"}), frozenset({"sibling"})).errors == []
    assert skills.validate(tmp_path, frozenset({"demo"})).errors != []


def test_validate_collects_errors_from_several_skills(tmp_path: Path) -> None:
    write_skill(tmp_path, "good")
    write_skill(tmp_path, "bad", "no frontmatter\n")
    write_skill(tmp_path, "wrong-name", skill_text(name="other"))
    errors = skills.validate(tmp_path, frozenset({"good", "bad", "wrong-name"})).errors
    assert any("bad/SKILL.md: must start" in error for error in errors)
    assert any("does not match directory 'wrong-name'" in error for error in errors)


def test_required_skills_constant_matches_agents_table() -> None:
    assert len(skills.REQUIRED_SKILLS) == 17
    assert "python-quality" in skills.REQUIRED_SKILLS


def test_main_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_skill(tmp_path, "demo")
    assert skills.main([str(tmp_path), "--required", "demo"]) == 0
    assert f"validated skills in {tmp_path}" in capsys.readouterr().out


def test_main_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert skills.main([str(tmp_path)]) == 1
    error = capsys.readouterr().err
    assert "required skill 'architecture' is missing" in error
    assert "17 skill validation error(s)" in error


def test_main_required_empty_and_external(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert skills.main([str(tmp_path), "--required", "--external", "x"]) == 0
    assert "validated" in capsys.readouterr().out


def test_main_default_root_is_agents_skills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_skill(tmp_path / ".agents" / "skills", "demo")
    monkeypatch.chdir(tmp_path)
    assert skills.main(["--required", "demo"]) == 0
    assert "validated skills in .agents/skills" in capsys.readouterr().out


def test_script_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_skill(tmp_path, "demo")
    monkeypatch.setattr(sys, "argv", ["validate_skills", str(tmp_path), "--required", "demo"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(skills.__file__, run_name="__main__")
    assert raised.value.code == 0
    assert "validated" in capsys.readouterr().out
