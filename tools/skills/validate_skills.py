"""Validate repository-scoped agent skills under ``.agents/skills``."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, cast

import yaml

REQUIRED_SKILLS: Final[frozenset[str]] = frozenset(
    {
        "architecture",
        "ansible-collection",
        "ansible-modules",
        "compliance-frameworks",
        "molecule-testing",
        "packer-images",
        "aws-infrastructure",
        "github-actions",
        "container-security",
        "python-quality",
        "security-review",
        "jira-management",
        "documentation",
        "reporting-dashboard",
        "release-engineering",
        "dependency-management",
        "code-review",
    }
)

REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "When to use",
    "Inputs",
    "Outputs",
    "Conventions",
    "Quality gates",
    "Common failures",
    "Security requirements",
    "Documentation requirements",
    "Completion criteria",
    "Interaction with other skills",
)

NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LOCAL_LINK_PATTERN: Final[re.Pattern[str]] = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)")
SKILL_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"`([a-z0-9]+(?:-[a-z0-9]+)*)`")
INTERACTION_SECTION: Final[str] = "Interaction with other skills"
FENCE_MARKERS: Final[frozenset[str]] = frozenset({"```", "~~~"})
MAX_NAME_LENGTH: Final[int] = 64
MAX_DESCRIPTION_LENGTH: Final[int] = 1024
MAX_BODY_LINES: Final[int] = 500
ALLOWED_FRONTMATTER_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
)


@dataclass(frozen=True)
class Skill:
    """A parsed skill definition."""

    directory: Path
    frontmatter: dict[str, object]
    body: str


@dataclass
class Report:
    """Accumulated validation errors."""

    errors: list[str] = field(default_factory=list[str])

    def add(self, location: Path | str, message: str) -> None:
        """Record a validation error for ``location``."""
        self.errors.append(f"{location}: {message}")


def read_frontmatter(skill_file: Path, report: Report) -> tuple[list[str], int] | None:
    """Read ``skill_file`` and return its lines and the closing delimiter index."""
    try:
        text = skill_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        report.add(skill_file, f"cannot be read as UTF-8 text: {error}")
        return None
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        report.add(skill_file, "must start with a '---' frontmatter delimiter")
        return None
    closing = next((index for index, line in enumerate(lines[1:], start=1) if line == "---"), None)
    if closing is None:
        report.add(skill_file, "frontmatter is not terminated by '---'")
        return None
    return lines, closing


def parse_skill(directory: Path, report: Report) -> Skill | None:
    """Parse ``SKILL.md`` in ``directory`` and return ``None`` when it is unusable."""
    skill_file = directory / "SKILL.md"
    if not skill_file.is_file():
        report.add(directory, "missing SKILL.md")
        return None
    split = read_frontmatter(skill_file, report)
    if split is None:
        return None
    lines, closing = split
    try:
        loaded: object = yaml.safe_load("\n".join(lines[1:closing]))
    except yaml.YAMLError as error:
        report.add(skill_file, f"frontmatter is not valid YAML: {error}")
        return None
    if not isinstance(loaded, dict):
        report.add(skill_file, "frontmatter must be a mapping")
        return None
    frontmatter = {str(key): value for key, value in cast("dict[object, object]", loaded).items()}
    return Skill(directory=directory, frontmatter=frontmatter, body="\n".join(lines[closing + 1 :]))


def check_frontmatter(skill: Skill, report: Report) -> None:
    """Validate the frontmatter fields defined by the Agent Skills format."""
    location = skill.directory / "SKILL.md"
    unknown = set(skill.frontmatter) - ALLOWED_FRONTMATTER_KEYS
    if unknown:
        report.add(location, f"unsupported frontmatter keys: {', '.join(sorted(unknown))}")
    name = skill.frontmatter.get("name")
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        report.add(location, "name must be lowercase letters, digits and single hyphens")
    elif len(name) > MAX_NAME_LENGTH:
        report.add(location, f"name exceeds {MAX_NAME_LENGTH} characters")
    elif name != skill.directory.name:
        report.add(location, f"name '{name}' does not match directory '{skill.directory.name}'")
    description = skill.frontmatter.get("description")
    if not isinstance(description, str) or not description.strip():
        report.add(location, "description must be a non-empty string")
    elif len(description) > MAX_DESCRIPTION_LENGTH:
        report.add(location, f"description exceeds {MAX_DESCRIPTION_LENGTH} characters")


def prose_lines(body: str) -> list[str]:
    """Return the lines of ``body`` that are outside fenced code blocks."""
    lines: list[str] = []
    fence: str | None = None
    for line in body.splitlines():
        marker = line.lstrip()[:3]
        if fence is None and marker in FENCE_MARKERS:
            fence = marker
        elif fence is not None and marker == fence:
            fence = None
        elif fence is None:
            lines.append(line)
    return lines


def link_target_exists(directory: Path, target: str) -> bool:
    """Return whether a relative link ``target`` resolves to an existing path."""
    path = target.split("#", 1)[0]
    if Path(path).is_absolute():
        return False
    try:
        return (directory / path).resolve().exists()
    except (OSError, ValueError):
        return False


def check_body(skill: Skill, known_skills: frozenset[str], report: Report) -> None:
    """Validate required sections, local links and skill cross-references."""
    location = skill.directory / "SKILL.md"
    lines = prose_lines(skill.body)
    headings = {line[3:].strip() for line in lines if line.startswith("## ")}
    for section in REQUIRED_SECTIONS:
        if section not in headings:
            report.add(location, f"missing required section '## {section}'")
    if len(skill.body.splitlines()) > MAX_BODY_LINES:
        report.add(location, f"body exceeds {MAX_BODY_LINES} lines; move detail to references/")
    for target in LOCAL_LINK_PATTERN.findall("\n".join(lines)):
        if not link_target_exists(skill.directory, target):
            report.add(location, f"broken local link '{target}'")
    for referenced in SKILL_REF_PATTERN.findall(section_text(lines, INTERACTION_SECTION)):
        if referenced not in known_skills:
            report.add(location, f"references unknown skill '{referenced}'")


def section_text(lines: list[str], heading: str) -> str:
    """Return the text of the level-two section titled ``heading``."""
    collected: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            inside = line[3:].strip() == heading
            continue
        if inside:
            collected.append(line)
    return "\n".join(collected)


def validate(
    skills_root: Path,
    required: frozenset[str],
    external: frozenset[str] = frozenset(),
) -> Report:
    """Validate every skill directory below ``skills_root``.

    ``external`` names skills kept in a sibling repository that may be referenced
    but are not present here.
    """
    report = Report()
    if not skills_root.is_dir():
        report.add(skills_root, "skills directory does not exist")
        return report
    directories = sorted(path for path in skills_root.iterdir() if path.is_dir())
    present = frozenset(path.name for path in directories)
    known = present | external
    for missing in sorted(required - present):
        report.add(skills_root, f"required skill '{missing}' is missing")
    for directory in directories:
        skill = parse_skill(directory, report)
        if skill is None:
            continue
        check_frontmatter(skill, report)
        check_body(skill, known, report)
    return report


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("skills_root", type=Path, nargs="?", default=Path(".agents/skills"))
    parser.add_argument(
        "--required",
        nargs="*",
        default=None,
        help="Override the required skill set, for repositories that carry a subset.",
    )
    parser.add_argument(
        "--external",
        nargs="*",
        default=[],
        help="Skills kept in a sibling repository that may be referenced but are absent.",
    )
    arguments = parser.parse_args(argv)
    required = REQUIRED_SKILLS if arguments.required is None else frozenset(arguments.required)
    report = validate(arguments.skills_root, required, frozenset(arguments.external))
    for error in report.errors:
        print(error, file=sys.stderr)
    if report.errors:
        print(f"{len(report.errors)} skill validation error(s)", file=sys.stderr)
        return 1
    print(f"validated skills in {arguments.skills_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
