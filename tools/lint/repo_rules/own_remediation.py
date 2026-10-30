"""Remediation is the collection's own Ansible; the scanner's remediation is never used (FREES-188).

ADR 0025 decides that every remediation is native Ansible written in this repository, that the
scanner content (the OVAL) is used only to audit and as a reference in golden tests, and that a
rule without a native implementation is reported as ``not_implemented`` and never remediated by
another tool. This rule group makes that decision a check:

* Python under ``tools/`` or ``plugins/`` may not name the XCCDF ``fix`` element: a string
  constant that is ``fix`` or ``fixtext`` with an optional namespace, prefix or path (an
  f-string counts with its placeholders), a ``fix`` tag in markup, a ``local-name()`` test for it
  or an XCCDF fix system URN. ``PINNED_EXCEPTIONS`` lists the only constants that may remain,
  exactly and with their number per file (a file that no longer has any of them passes): the
  STIG checklist export shows ``fixtext`` to the reader (``tools/reporting/stig_content.py``),
  the process helper refuses the ``generate fix`` sequence and the remediation words
  (``process.py``), and the Grype parser reads the ``fix`` object of a Grype vulnerability,
  which is not XCCDF.
* No file of the repository may be remediation content of ComplianceAsCode or OpenSCAP: a file
  named ``ssg-*``, ``*-playbook-*.yml`` or ``*-script-*.sh`` as the release archive names them,
  ``*-ks.cfg``, a path below ``scap-security-guide*``, a generated Bash fix, a generated
  playbook header, an XCCDF ``fix`` element or fix system, the OpenSCAP kickstart add-on, or a
  YAML task list tagged with the complexity, disruption, reboot and strategy tags of the
  generated playbooks. The repository ships only what it tracks, so nothing of that kind can
  reach the collection tarball either.
* Files that run (YAML outside ``docs/`` and ``changelogs/``, makefiles, files below
  ``.github/``, shell scripts and templates, container files, files with a shebang, and Python
  outside ``tests/unit/``) may not invoke the scanner's remediation (its ``remediate`` options and
  sub-commands, ``generate fix`` and the fix type option, also as consecutive items of a list) or
  run a script that the scanner or its content provides (a script or playbook path below the
  fetched content, the release archive, the SCC installation or the distribution's SSG
  directories, or named like a release archive member).

The module spells the element name as ``FIX`` and writes its patterns so that they do not match
its own source. The SCE check scripts that the pinned datastreams embed are checks that
``oscap`` runs while it audits; T-AUDIT-2 of the threat model covers them, and nothing here runs
them. This is static analysis of the tracked files, not a sandbox (ADR 0004).
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.common import PYTHON_SUFFIXES, YAML_SUFFIXES, Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

FIX_READER: Final[str] = "fix_reader"
INVOCATION: Final[str] = "invocation"
FIX_SCOPES: Final[frozenset[str]] = frozenset({"tools", "plugins"})
DOCUMENTATION_SCOPES: Final[frozenset[str]] = frozenset({"docs", "changelogs"})
UNIT_TESTS: Final[tuple[str, str]] = ("tests", "unit")
EXECUTED_DIRECTORY: Final[str] = ".github"
MAKEFILE_NAMES: Final[frozenset[str]] = frozenset({"makefile", "gnumakefile"})
SCRIPT_SUFFIXES: Final[frozenset[str]] = frozenset({".sh", ".bash", ".zsh", ".ksh", ".mk"})
SCRIPT_TEMPLATE_SUFFIX: Final[str] = ".sh.tmpl"
CONTAINER_FILE_PREFIXES: Final[tuple[str, ...]] = ("containerfile", "dockerfile")
SHEBANG: Final[bytes] = b"#!"
PLACEHOLDER: Final[str] = "{}"

FIX: Final[str] = "fi" + "x"
PINNED_EXCEPTIONS: Final[dict[tuple[Path, str], tuple[str, ...]]] = {
    (Path("tools/reporting/stig_content.py"), FIX_READER): (FIX + "text",),
    (Path("plugins/module_utils/compliance/process.py"), FIX_READER): (FIX,),
    (Path("plugins/module_utils/compliance/process.py"), INVOCATION): (
        "-" + "-remediate",
        "generate " + FIX,
    ),
    (Path("tools/reporting/parsers/grype.py"), FIX_READER): (FIX, FIX),
}

FIX_ELEMENT: Final[re.Pattern[str]] = re.compile(
    r"(?:\{[^{}]*\}|[A-Za-z_][\w.-]*:|\.{0,2}/{1,2})?fi[x](?:text)?(?:\[[^\]]*\])?"
)
FIX_MARKUP: Final[re.Pattern[str]] = re.compile(
    r"</?(?:[A-Za-z_][\w.-]*:)?fi[x](?:text)?[\s>/]"
    r"|local-name\(\)\s*=\s*['\"]fi[x]"
    r"|urn:xccdf:fi[x]\b"
)
UPSTREAM_NAMES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"ssg-.*"),
    re.compile(r".+-(?:playbook|script)-.+\.(?:ya?ml|sh)"),
    re.compile(r".+-ks\.cfg"),
)
UPSTREAM_DIRECTORY: Final[re.Pattern[str]] = re.compile(r"scap-security-guide(?:-[\d.]+)?")
UPSTREAM_MARKERS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("a generated Bash fix", re.compile(r"\bBEGIN\s+fi[x]\s+\(\d+\s*/\s*\d+\)")),
    ("a generated Bash fix", re.compile(r"\bEND\s+fi[x]\s+for\s+'")),
    (
        "a remediation generated by OpenSCAP",
        re.compile(r"This\s+file\s+(?:can\s+be|was)\s+generated\s+by\s+OpenSCAP"),
    ),
    (
        "a generated Bash fix",
        re.compile(r"Remediation\s+is\s+applicable\s+only\s+in\s+certain\s+platforms"),
    ),
    ("an XCCDF fix element", re.compile(r"<(?:[A-Za-z_][\w.-]*:)?fi[x][\s>/]")),
    ("an XCCDF fix system", re.compile(r"urn:xccdf:fi[x]:")),
    ("the OpenSCAP kickstart add-on", re.compile(r"%addon\s+(?:org_fedora|com_redhat)_oscap")),
)
PLAYBOOK_TAGS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(rf"^[ \t]*-[ \t]+{tag}[ \t]*$", re.MULTILINE)
    for tag in (
        r"(?:low|medium|high)_complexity",
        r"(?:low|medium|high)_disruption",
        r"(?:no_)?reboot_needed",
        r"[a-z]+_strategy",
    )
)
INVOCATIONS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"-\-remediate\b"),
    re.compile(r"-\-fix-type\b"),
    re.compile(r"\bgenerate\s+fi[x]\b"),
    re.compile(r"\bxccdf\s+remediate\b"),
    re.compile(r"(?<![\w./-])osca[p](?![\w-])[^\n]*?(?<![\w./-])remediate(?![\w-])"),
)
SCANNER_SCRIPTS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:scap-security-guide|build/content|/opt/scc|/usr/share/xml/scap"
        r"|/usr/share/scap-security-guide)[^\s'\"]*\.(?:sh|bash|ks|py|pl|ps1|ya?ml)\b"
    ),
    re.compile(r"(?<![\w.-])ssg-[\w.-]*\.(?:sh|bash|ks|py|ya?ml)\b"),
    re.compile(r"(?<![\w.-])[\w.]+-(?:playbook|script)-[\w.-]+\.(?:ya?ml|sh)\b"),
)

FIX_MESSAGE: Final[str] = (
    "reads the XCCDF fix content of the scanner ({text!r}); remediation is the collection's own "
    "Ansible and values come from the profile's XCCDF values (ADR 0025)"
)
INVOCATION_MESSAGE: Final[str] = (
    "runs the scanner's remediation or a script it provides ({text!r}); remediation is the "
    "collection's own Ansible and a rule without it is not_implemented (ADR 0025)"
)
NAME_MESSAGE: Final[str] = (
    "is named like ComplianceAsCode remediation content ({text!r}); scanner remediation content "
    "is never committed or shipped (ADR 0025)"
)
MARKER_MESSAGE: Final[str] = (
    "holds {text} of ComplianceAsCode or OpenSCAP; scanner remediation content is never "
    "committed or shipped (ADR 0025)"
)
PLAYBOOK_MESSAGE: Final[str] = (
    "is tagged like a playbook generated by ComplianceAsCode; scanner remediation content is "
    "never committed or shipped (ADR 0025)"
)
PIN_MESSAGE: Final[str] = (
    "the pinned exception for {kind} no longer matches exactly: expected {expected}, found "
    "{found}; change PINNED_EXCEPTIONS only with a security review (ADR 0025)"
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_documentation(relative: Path) -> bool:
    return relative.parts[:1] != () and relative.parts[0] in DOCUMENTATION_SCOPES


def is_executed(relative: Path, data: bytes) -> bool:
    """Return whether ``relative`` runs or is read by something that runs it.

    That is YAML outside ``docs/`` and ``changelogs/``, every file below ``.github/``,
    makefiles, shell scripts and their templates, container files and files with a shebang.
    """
    if _is_documentation(relative):
        return False
    name = relative.name.casefold()
    return (
        relative.suffix.lower() in YAML_SUFFIXES | SCRIPT_SUFFIXES
        or relative.parts[:1] == (EXECUTED_DIRECTORY,)
        or name in MAKEFILE_NAMES
        or name.endswith(SCRIPT_TEMPLATE_SUFFIX)
        or name.startswith(CONTAINER_FILE_PREFIXES)
        or data.startswith(SHEBANG)
    )


def _strings(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield the line and text of every string the code can use, f-strings with placeholders.

    Expression statements (docstrings) are skipped: they cannot be read by the code.
    """
    skipped: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant | ast.JoinedStr):
            skipped.update(id(child) for child in ast.walk(node.value))
        elif isinstance(node, ast.JoinedStr):
            skipped.update(id(child) for child in ast.walk(node) if child is not node)
    for node in ast.walk(tree):
        if id(node) in skipped:
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            yield (
                node.lineno,
                "".join(
                    part.value
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                    else PLACEHOLDER
                    for part in node.values
                ),
            )


def _sequences(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield every list, tuple and set of string constants, joined as an argument vector."""
    for node in ast.walk(tree):
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            words = [
                element.value
                for element in node.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            ]
            if len(words) > 1:
                yield node.lineno, " ".join(words)


def _yaml_sequences(text: str) -> Iterator[tuple[int, str]]:
    """Yield every YAML sequence of scalars, joined as an argument vector."""
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        nodes: list[yaml.Node] = list(iter(loader.get_node, None))
    except yaml.YAMLError:
        return
    finally:
        loader.dispose()
    seen: set[int] = set()
    while nodes:
        node = nodes.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            words = [str(item.value) for item in node.value if isinstance(item, yaml.ScalarNode)]
            if len(words) > 1:
                yield node.start_mark.line + 1, " ".join(words)
            nodes.extend(node.value)
        elif isinstance(node, yaml.MappingNode):
            nodes.extend(item for pair in node.value for item in pair)


def _invocations(line: int, text: str) -> Iterator[tuple[int, str]]:
    for pattern in (*INVOCATIONS, *SCANNER_SCRIPTS):
        for match in pattern.finditer(text):
            yield line + text.count("\n", 0, match.start()), match.group(0)


def _fix_names(line: int, text: str) -> Iterator[tuple[int, str]]:
    if FIX_ELEMENT.fullmatch(text) is not None:
        yield line, text
    else:
        yield from ((line, match.group(0)) for match in FIX_MARKUP.finditer(text))


def python_findings(relative: Path, data: bytes) -> dict[str, set[tuple[int, str]]]:
    """Return the fix-reader and invocation findings of one Python file, by kind."""
    found: dict[str, set[tuple[int, str]]] = {FIX_READER: set(), INVOCATION: set()}
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError):
        return found
    strings = list(_strings(tree))
    if relative.parts[:1] != () and relative.parts[0] in FIX_SCOPES:
        for line, text in strings:
            found[FIX_READER].update(_fix_names(line, text))
    if relative.parts[:2] != UNIT_TESTS:
        for line, text in [*strings, *_sequences(tree)]:
            found[INVOCATION].update(_invocations(line, text))
    return found


def _text_findings(relative: Path, data: bytes) -> dict[str, set[tuple[int, str]]]:
    found: dict[str, set[tuple[int, str]]] = {INVOCATION: set()}
    if not is_executed(relative, data):
        return found
    text = data.decode("utf-8", errors="replace")
    found[INVOCATION].update(_invocations(1, text))
    if relative.suffix.lower() in YAML_SUFFIXES:
        for line, words in _yaml_sequences(text):
            found[INVOCATION].update((line, match) for _, match in _invocations(1, words))
    return found


def _pinned(
    path: Path, relative: Path, kind: str, found: set[tuple[int, str]], message: str
) -> list[Violation]:
    """Return the violations of one kind, dropping exactly the pinned exception of the file.

    A file without any finding passes: dropping an exception only makes the rule stricter, and a
    unit test keeps the pins equal to the repository's files.
    """
    pinned = PINNED_EXCEPTIONS.get((relative, kind))
    texts = Counter(text for _, text in found)
    if not texts or (pinned is not None and texts == Counter(pinned)):
        return []
    violations = [Violation(path, line, message.format(text=text)) for line, text in found]
    if pinned is not None:
        violations.append(
            Violation(
                path,
                1,
                PIN_MESSAGE.format(
                    kind=kind, expected=sorted(pinned), found=sorted(texts.elements())
                ),
            )
        )
    return violations


def _upstream_content(path: Path, relative: Path, data: bytes) -> list[Violation]:
    name = relative.name.casefold()
    violations = [
        Violation(path, 1, NAME_MESSAGE.format(text=relative.name))
        for pattern in UPSTREAM_NAMES
        if pattern.fullmatch(name) is not None
    ]
    violations.extend(
        Violation(path, 1, NAME_MESSAGE.format(text=part))
        for part in relative.parts[:-1]
        if UPSTREAM_DIRECTORY.fullmatch(part.casefold()) is not None
    )
    text = data.decode("utf-8", errors="replace")
    for description, pattern in UPSTREAM_MARKERS:
        violations.extend(
            Violation(path, _line_of(text, match.start()), MARKER_MESSAGE.format(text=description))
            for match in pattern.finditer(text)
        )
    tags = [pattern.search(text) for pattern in PLAYBOOK_TAGS]
    if all(match is not None for match in tags):
        first = min(match.start() for match in tags if match is not None)
        violations.append(Violation(path, _line_of(text, first), PLAYBOOK_MESSAGE))
    return violations


def own_remediation_findings(path: Path, relative: Path | None, data: bytes) -> list[Violation]:
    """Return every place where ``path`` would use the scanner's remediation (ADR 0025)."""
    if relative is None:
        return []
    violations = _upstream_content(path, relative, data)
    if path.suffix.lower() in PYTHON_SUFFIXES:
        found = python_findings(relative, data)
    else:
        found = _text_findings(relative, data)
    messages = {FIX_READER: FIX_MESSAGE, INVOCATION: INVOCATION_MESSAGE}
    for kind, items in found.items():
        violations.extend(_pinned(path, relative, kind, items, messages[kind]))
    return sorted(set(violations))


def pinned_paths() -> Iterable[Path]:
    """Return the files that hold a pinned exception."""
    return sorted({relative for relative, _ in PINNED_EXCEPTIONS})
