"""Jinja that runs commands: command lookups, computed lookups and delimiter overrides (FREES-159).

Ansible templates every string it loads from a playbook, a role, a vars file or an inventory,
evaluates ``when``, ``changed_when``, ``failed_when``, ``until``, ``assert`` ``that`` and
``debug`` ``var`` as bare expressions, and renders template files. The ``pipe`` and ``lines``
lookups run a shell command on the controller, so a lookup is allowed only as a call of
``lookup``, ``query`` or ``q`` whose first argument is a literal name of a reviewed lookup of
ansible-core (``REVIEWED_LOOKUPS``), and a ``with_<name>`` loop only with such a name. A
``#jinja2:`` header and the delimiter options could hide a template from this check, so they
are refused, and so is ``allow_unsafe``, which templates the result of a lookup (ADR 0004).
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Final

import jinja2
import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from jinja2.lexer import Token

LOOKUP_FUNCTIONS: Final[frozenset[str]] = frozenset({"lookup", "query", "q"})
COMMAND_LOOKUPS: Final[frozenset[str]] = frozenset({"pipe", "lines"})
REVIEWED_LOOKUPS: Final[frozenset[str]] = frozenset(
    {
        "config",
        "csvfile",
        "dict",
        "env",
        "file",
        "fileglob",
        "first_found",
        "indexed_items",
        "ini",
        "inventory_hostnames",
        "items",
        "list",
        "nested",
        "password",
        "random_choice",
        "sequence",
        "subelements",
        "template",
        "together",
        "unvault",
        "url",
        "varnames",
        "vars",
    }
)
LOOKUP_PREFIXES: Final[tuple[str, ...]] = ("ansible.builtin.", "ansible.legacy.")
LOOP_PREFIX: Final[str] = "with_"
OVERRIDE_HEADER: Final[str] = "#jinja2:"
DELIMITER_OPTIONS: Final[frozenset[str]] = frozenset(
    {
        "block_start_string",
        "block_end_string",
        "variable_start_string",
        "variable_end_string",
        "comment_start_string",
        "comment_end_string",
        "line_statement_prefix",
        "line_comment_prefix",
    }
)
UNSAFE_OPTIONS: Final[frozenset[str]] = frozenset({"allow_unsafe", "allow_unsafe_lookups"})
REFUSED_NAMES: Final[frozenset[str]] = DELIMITER_OPTIONS | UNSAFE_OPTIONS
TEMPLATE_MARKERS: Final[tuple[str, ...]] = ("{{", "{%", "{#")
EXPRESSION_KEYS: Final[frozenset[str]] = frozenset(
    {"when", "changed_when", "failed_when", "until", "that", "var"}
)
UNTEMPLATED_TAGS: Final[frozenset[str]] = frozenset({"!unsafe", "!vault"})
TEMPLATE_SUFFIXES: Final[frozenset[str]] = frozenset({".j2", ".jinja", ".jinja2"})
RENDERED_DIRECTORIES: Final[frozenset[str]] = frozenset({"templates", "files", "vars", "defaults"})
ANSIBLE_TREES: Final[tuple[Path, ...]] = (
    Path("roles"),
    Path("playbooks"),
    Path("tests/playbooks"),
    Path("extensions"),
)
INCLUDE_TAGS: Final[frozenset[str]] = frozenset({"include", "import", "extends", "from"})
INCLUDE_FOLLOWERS: Final[frozenset[str]] = frozenset({"block_end", "name"})
LEX_ERROR: Final[str] = "template cannot be checked for lookups"
TEMPLATE_LOOKUP: Final[str] = "template"
TEMPLATE_CALL_TOKENS: Final[int] = 5
MAX_DEPTH: Final[int] = 8
CALL_END: Final[frozenset[str]] = frozenset({"comma", "rparen"})
CALL_TOKENS: Final[int] = 3
_ENVIRONMENT: Final[jinja2.Environment] = jinja2.Environment(autoescape=True)


def is_template_file(relative: Path) -> bool:
    """Return whether Ansible may render ``relative`` as a template or load it as variables.

    That is a file with a template suffix or below a ``templates``, ``files``, ``vars`` or
    ``defaults`` directory anywhere, and every file below ``ANSIBLE_TREES``: the ``template``
    lookup and module and ``{% include %}`` render a role's ``files/`` too, and
    ``include_vars`` and the ``host_group_vars`` plugin load ``.json`` and extensionless
    files (FREES-159).
    """
    folded = [part.casefold() for part in relative.parts]
    in_tree = any(
        folded[: len(tree.parts)] == list(tree.parts) and len(folded) > len(tree.parts)
        for tree in ANSIBLE_TREES
    )
    return (
        in_tree
        or relative.suffix.lower() in TEMPLATE_SUFFIXES
        or bool(RENDERED_DIRECTORIES.intersection(folded[:-1]))
    )


def is_possibly_template(text: str) -> bool:
    """Return whether Ansible would template ``text``, as ``is_possibly_template`` decides."""
    return text.startswith(OVERRIDE_HEADER) or any(marker in text for marker in TEMPLATE_MARKERS)


def lookup_problem(name: str) -> str | None:
    """Return why the lookup ``name`` is refused, or ``None`` for a reviewed lookup."""
    bare = next(
        (name[len(prefix) :] for prefix in LOOKUP_PREFIXES if name.startswith(prefix)), None
    )
    if bare is None:
        if "." in name:
            return f"lookup {name!r} is not an ansible-core lookup that this guard reviewed"
        bare = name
    if bare in COMMAND_LOOKUPS:
        return f"lookup {name!r} runs a command on the controller"
    if bare not in REVIEWED_LOOKUPS:
        return f"lookup {name!r} is not an ansible-core lookup that this guard reviewed"
    return None


def _tokens(text: str, state: str | None) -> list[Token] | str:
    r"""Return the Jinja tokens of ``text`` or the lexer error.

    Jinja decodes string escapes with ``unicode-escape``, which warns about an unknown
    escape such as a regular expression's ``\\.``; Ansible renders those strings, so the
    warning is not an error here either.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            return list(_ENVIRONMENT.lexer.tokenize(text, state=state))
        except jinja2.TemplateSyntaxError as error:
            return str(error.message)


def _bare_lookup(name: str) -> str:
    return next(
        (name[len(prefix) :] for prefix in LOOKUP_PREFIXES if name.startswith(prefix)), name
    )


def target_problem(name: str) -> str | None:
    """Return why a literal template or vars file target is refused, or ``None``.

    It must be a relative path without ``..`` that is not templated, so that it stays
    inside the search path of the role or playbook that names it (FREES-159).
    """
    if name.startswith(("/", "~")) or ".." in name.split("/") or is_possibly_template(name):
        return f"target {name!r} must be a relative path without '..' that is not templated"
    return None


def _template_lookup_problem(tokens: list[Token], index: int) -> str:
    """Require a literal relative template as the first term of the ``template`` lookup."""
    following = tokens[index + 1 : index + 1 + TEMPLATE_CALL_TOKENS]
    types = [token.type for token in following]
    if (
        len(types) == TEMPLATE_CALL_TOKENS
        and types[2:4] == ["comma", "string"]
        and types[4] in CALL_END
    ):
        problem = target_problem(str(following[3].value))
        return "" if problem is None else f"template lookup {problem}"
    return (
        "the template lookup must name a literal template as its first term; a computed "
        "name could render any file"
    )


def _call_problem(tokens: list[Token], index: int) -> str:
    name = tokens[index].value
    following = tokens[index + 1 : index + 1 + CALL_TOKENS]
    types = [token.type for token in following]
    if len(types) == CALL_TOKENS and types[:2] == ["lparen", "string"] and types[2] in CALL_END:
        lookup = str(following[1].value)
        problem = lookup_problem(lookup)
        if problem is not None:
            return problem
        if _bare_lookup(lookup) == TEMPLATE_LOOKUP:
            return _template_lookup_problem(tokens, index)
        return ""
    return (
        f"{name} must be called with a literal lookup name as its first argument; a computed "
        "lookup name could run any lookup"
    )


def _include_problem(tokens: list[Token], index: int) -> str:
    """Return why an ``include``, ``import``, ``extends`` or ``from`` tag is refused, or ``""``.

    The tag must name a literal relative template, so that the template it loads is one
    the check scans; a computed name could load any template.
    """
    tag = tokens[index].value
    following = tokens[index + 1 : index + 3]
    if (
        len(following) == len(INCLUDE_FOLLOWERS)
        and following[0].type == "string"
        and following[1].type in INCLUDE_FOLLOWERS
    ):
        problem = target_problem(str(following[0].value))
        return "" if problem is None else f"{tag} {problem}"
    return f"{tag} must name a literal template; a computed name could load any template"


def _token_findings(tokens: list[Token], depth: int) -> Iterator[tuple[int, str]]:
    for index, token in enumerate(tokens):
        if (
            token.type == "name"
            and token.value in INCLUDE_TAGS
            and index > 0
            and tokens[index - 1].type == "block_begin"
        ):
            problem = _include_problem(tokens, index)
            if problem:
                yield token.lineno, problem
        elif token.type == "name" and token.value in LOOKUP_FUNCTIONS:
            problem = _call_problem(tokens, index)
            if problem:
                yield token.lineno, problem
        elif token.type == "name" and token.value in REFUSED_NAMES:
            yield token.lineno, f"Jinja option {token.value!r} is not allowed (ADR 0004)"
        elif token.type == "string" and is_possibly_template(str(token.value)):
            for line, message in template_findings(str(token.value), depth + 1):
                yield token.lineno + line - 1, message


def template_findings(text: str, depth: int = 0) -> Iterator[tuple[int, str]]:
    """Yield ``(line, message)`` for refused Jinja in the template ``text``.

    String constants that are templates themselves are checked too, because Ansible
    templates them when it renders the outer template.
    """
    if depth > MAX_DEPTH:
        yield 1, "templates nested too deeply to be checked"
        return
    if text.startswith(OVERRIDE_HEADER):
        yield 1, f"a {OVERRIDE_HEADER!r} header is not allowed: it changes the Jinja delimiters"
        return
    tokens = _tokens(text, None)
    if isinstance(tokens, str):
        yield 1, f"{LEX_ERROR}: {tokens}"
        return
    yield from _token_findings(tokens, depth)


def expression_findings(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line, message)`` for refused Jinja in the bare expression ``text``.

    An expression that does not lex cannot be compiled by Ansible either, so it runs nothing.
    """
    tokens = _tokens(text, "variable")
    if not isinstance(tokens, str):
        yield from _token_findings(tokens, 0)


def _scalar_findings(node: yaml.ScalarNode, *, expression: bool) -> Iterator[tuple[int, str]]:
    text = str(node.value)
    if is_possibly_template(text):
        yield from template_findings(text)
    elif expression:
        yield from expression_findings(text)


def _key_findings(key: yaml.ScalarNode) -> Iterator[tuple[int, str]]:
    name = str(key.value)
    if name.startswith(LOOP_PREFIX):
        problem = lookup_problem(name[len(LOOP_PREFIX) :])
        if problem is not None:
            yield 1, f"loop {name!r}: {problem}"
    elif name in REFUSED_NAMES:
        yield 1, f"Jinja option {name!r} is not allowed (ADR 0004)"


def _children(node: yaml.Node, *, expression: bool) -> Iterator[tuple[yaml.Node, bool, bool]]:
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            is_expression = isinstance(key, yaml.ScalarNode) and key.value in EXPRESSION_KEYS
            yield key, True, False
            yield value, False, is_expression
    else:
        yield from ((item, False, expression) for item in node.value)


def _node_findings(documents: Iterable[yaml.Node]) -> Iterator[tuple[int, str]]:
    stack: list[tuple[yaml.Node, bool, bool]] = [(node, False, False) for node in documents]
    seen: set[tuple[int, bool, bool]] = set()
    while stack:
        node, is_key, expression = stack.pop()
        if (id(node), is_key, expression) in seen:
            continue
        seen.add((id(node), is_key, expression))
        if isinstance(node, yaml.ScalarNode):
            if node.tag in UNTEMPLATED_TAGS:
                continue
            start = node.start_mark.line + 1
            if is_key:
                for _, message in _key_findings(node):
                    yield start, message
            for line, message in _scalar_findings(node, expression=expression):
                yield start + line - 1, message
        else:
            stack.extend(_children(node, expression=expression))


def yaml_jinja_findings(path: Path, documents: Iterable[yaml.Node]) -> list[Violation]:
    """Reject command lookups, computed lookups and delimiter overrides in YAML documents."""
    return sorted({Violation(path, line, message) for line, message in _node_findings(documents)})
