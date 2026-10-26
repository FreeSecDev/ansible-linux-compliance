"""Enforce repository-wide source rules on the files passed as arguments.

Rules:

* Every YAML file starts with ``---`` followed by a newline.
* YAML files contain no comments, except a trailing ``# vX.Y.Z`` version
  annotation on a ``uses: owner/repo@<40-hex>`` or ``rev: <40-hex>`` line.
* YAML files contain no banned Ansible command-execution modules. A document
  whose root is a sequence is a playbook or task file: only the keys of its plays
  and tasks (followed through ``tasks``, ``pre_tasks``, ``post_tasks``,
  ``handlers``, ``block``, ``rescue`` and ``always`` at any depth, aliases and
  merge keys) and their ``action`` and ``local_action`` values are checked, so
  module parameters and ``vars`` data may contain the banned words. A templated
  module name in an action is denied, and included task files, playbooks and role
  entry points must have a ``.yml`` or ``.yaml`` suffix. Any other document is
  checked for banned keys at any depth, and a ``redirect`` to a banned module is
  denied (FREES-128).
* Python files contain no comments, except a shebang on the first line.
* Python files under ``plugins/`` are checked deny-by-default: they import only
  allow-listed standard library modules, ``ansible.module_utils`` and this
  collection, never use ``os`` except as ``os.path``, never use ``exec``, ``eval``,
  ``compile`` or ``__import__``, never reference process, fork or ``run_command``
  attributes, never import or name ``subprocess``, ``pty``, ``posix``, ``sys`` or
  ``os`` as an imported name or attribute, never use ``vars``, ``globals``,
  ``locals``, ``__dict__`` or ``get_type_hints``, never pass ``shell=True``,
  ``use_unsafe_shell`` or the test-only ``owner_uid``, ``state_dir``, ``lock_timeout``,
  ``policies``, ``trusted_dirs``, ``runner``, ``clock``, ``limits`` and ``registry`` keywords,
  never use a ``**``
  dict splat in a call, never use the attribute ``__self__``, and
  only call ``getattr`` with a literal permitted name. The string-based reflection names
  ``builtins``, ``operator``, ``eval``, ``exec``, ``compile``, ``attrgetter``,
  ``methodcaller``, ``_evaluate`` and ``evaluate_forward_ref`` are banned as attributes, a
  module-level ``__getattr__`` is banned, so are the function internals ``__kwdefaults__``,
  ``__defaults__``, ``__code__``, ``__closure__`` and ``__globals__``, assigning to an
  attribute of an imported name (including ``setattr``) is banned, and underscore-prefixed
  attributes may only be read, called or assigned through ``self`` or ``cls`` inside a class
  (dunder reads such as ``__name__`` stay allowed; dunder assignment does not). Underscore-prefixed
  names may not be imported. Dunder attributes are denied by default: only reading ``__name__``
  is allowed, plus the single form
  ``object.__setattr__(self, "<literal>", value)`` in ``__post_init__``. Frame and code
  attributes and the ``types`` module (except ``MappingProxyType``) are banned on every
  object, and attributes named like standard library or collection modules are banned when the
  chain starts at a module name (``dataclasses.inspect``). Only ``super().__init__()`` and
  ``super().__post_init__()`` may call a dunder on ``super()``, and ``super`` and ``object``
  may never be rebound. A name bound to a module, and a submodule reached by attribute
  (``os.path``, ``json.decoder``, or ``from json import decoder``), may only appear as the base
  of an attribute access, and
  ``self`` and ``cls`` are exempt only as the never rebound first parameter of a method. This is
  static analysis, not a sandbox (ADR 0004).
  ``xml.parsers.expat`` may be imported (as ``from xml.parsers import expat``)
  only by ``plugins/module_utils/compliance/xmlsafe.py``, the shared hardened
  XML parser that every other plugin file parses through. The components of that
  dotted name that no allow-listed import provides (``parsers`` and ``expat``) are
  reserved for the same file: everywhere else they are banned as attribute names on
  any object, as literal ``getattr`` names, as ``match`` class pattern keywords and as
  imported names or import path components, so ``xmlsafe.expat.ParserCreate()`` and
  ``from .xmlsafe import expat`` fail. Only
  ``plugins/module_utils/compliance/process.py`` is exempt (ADR 0004).
  ``plugins/module_utils/compliance/fileio.py`` may additionally ``import`` ``os``, ``fcntl``,
  ``errno`` and ``time`` and use only the attributes listed in ``FILE_IO_ATTRIBUTES``, always as
  ``module.attribute``; it keeps every other rule. Only
  ``plugins/module_utils/compliance/ledger.py`` may import ``fileio`` or name it as an attribute
  or ``getattr`` literal (ADR 0011).

Violations are printed as ``path:line: message`` and the exit status is 1.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

YAML_SUFFIXES: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
PYTHON_SUFFIXES: Final[frozenset[str]] = frozenset({".py"})
DOCUMENT_START: Final[str] = "---\n"
BANNED_MODULES: Final[frozenset[str]] = frozenset(
    {"shell", "command", "raw", "script", "win_shell", "win_command"}
)
COLLECTION_PREFIXES: Final[tuple[str, ...]] = (
    "ansible.builtin.",
    "ansible.legacy.",
    "ansible.windows.",
    "community.windows.",
)
ACTION_KEYS: Final[frozenset[str]] = frozenset({"action", "local_action"})
MODULE_KEY: Final[str] = "module"
TASK_LIST_KEYS: Final[frozenset[str]] = frozenset(
    {"tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always"}
)
TASK_INCLUDE_MODULES: Final[frozenset[str]] = frozenset(
    {"include_tasks", "import_tasks", "include", "import_playbook"}
)
ROLE_INCLUDE_MODULES: Final[frozenset[str]] = frozenset({"include_role", "import_role"})
INCLUDE_FILE_KEYS: Final[frozenset[str]] = frozenset({"file", "_raw_params"})
ROLE_ENTRY_POINT_KEYS: Final[frozenset[str]] = frozenset({"tasks_from", "handlers_from"})
TASK_FILE_SUFFIXES: Final[tuple[str, ...]] = (".yml", ".yaml")
TEMPLATE_MARKERS: Final[tuple[str, ...]] = ("{{", "{%", "{#")
MERGE_TAG: Final[str] = "tag:yaml.org,2002:merge"
REDIRECT_KEY: Final[str] = "redirect"
VERSION_ANNOTATION: Final[re.Pattern[str]] = re.compile(r"# v\d+\.\d+\.\d+")
PINNED_USES: Final[re.Pattern[str]] = re.compile(
    r"\s*(?:-\s+)?uses:\s+[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}\s*"
)
PINNED_REV: Final[re.Pattern[str]] = re.compile(r"\s*(?:-\s+)?rev:\s+[0-9a-f]{40}\s*")
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
PLUGINS_DIRECTORY: Final[str] = "plugins"
PROCESS_HELPER: Final[Path] = Path("plugins/module_utils/compliance/process.py")
FILE_IO_HELPER: Final[Path] = Path("plugins/module_utils/compliance/fileio.py")
FILE_IO_IMPORTERS: Final[frozenset[Path]] = frozenset(
    {Path("plugins/module_utils/compliance/ledger.py"), FILE_IO_HELPER}
)
FILE_IO_MODULE: Final[str] = "fileio"
LEDGER_MODULE: Final[Path] = Path("plugins/module_utils/compliance/ledger.py")
FILE_IO_ATTRIBUTES: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "errno": frozenset({"ELOOP", "EMLINK", "ENOTDIR"}),
        "fcntl": frozenset({"flock", "LOCK_EX", "LOCK_NB"}),
        "os": frozenset(
            {
                "O_CLOEXEC",
                "O_CREAT",
                "O_DIRECTORY",
                "O_EXCL",
                "O_NOFOLLOW",
                "O_NONBLOCK",
                "O_RDONLY",
                "O_WRONLY",
                "close",
                "fchmod",
                "fstat",
                "scandir",
                "fsync",
                "mkdir",
                "open",
                "read",
                "rename",
                "stat",
                "supports_dir_fd",
                "unlink",
                "urandom",
                "write",
            }
        ),
        "time": frozenset({"monotonic", "sleep"}),
    }
)
NO_RESTRICTION: Final[Mapping[str, frozenset[str]]] = MappingProxyType({})
ALLOWED_IMPORTS: Final[frozenset[str]] = frozenset(
    {
        "__future__",
        "collections.abc",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "json",
        "os.path",
        "pathlib",
        "re",
        "stat",
        "types",
        "typing",
        "unicodedata",
    }
)
RESTRICTED_FROM_IMPORTS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {"types": frozenset({"MappingProxyType"})}
)
EXTRA_IMPORTS: Final[Mapping[Path, frozenset[str]]] = MappingProxyType(
    {
        Path("plugins/module_utils/compliance/xmlsafe.py"): frozenset({"xml.parsers.expat"}),
    }
)
COLLECTION_PREFIX: Final[str] = "ansible_collections.freesecdev.linux_compliance"
ALLOWED_IMPORT_PREFIXES: Final[tuple[str, ...]] = ("ansible.module_utils", COLLECTION_PREFIX)
ANSIBLE_PACKAGES: Final[frozenset[str]] = frozenset({"ansible", "ansible.module_utils"})
MODULE_NAMES: Final[frozenset[str]] = frozenset(
    {"subprocess", "pty", "posix", "_posixsubprocess", "os", "sys"}
)
REFLECTION_NAMES: Final[frozenset[str]] = frozenset({"vars", "globals", "locals", "get_type_hints"})
BANNED_NAMES: Final[frozenset[str]] = (
    frozenset(
        {
            "exec",
            "eval",
            "compile",
            "__import__",
            "__builtins__",
            "__getattr__",
            "__class__",
            "__loader__",
            "__spec__",
        }
    )
    | REFLECTION_NAMES
    | (MODULE_NAMES - {"os"})
)
DYNAMIC_ATTRIBUTE_BUILTINS: Final[frozenset[str]] = frozenset({"getattr", "setattr", "delattr"})
BANNED_ATTRIBUTES: Final[frozenset[str]] = (
    frozenset(
        {
            "system",
            "popen",
            "run_command",
            "create_subprocess_exec",
            "create_subprocess_shell",
            "Popen",
            "import_module",
            "exec",
            "__import__",
            "__builtins__",
            "__subclasses__",
            "__globals__",
            "__kwdefaults__",
            "__defaults__",
            "__closure__",
            "builtins",
            "operator",
            "eval",
            "compile",
            "attrgetter",
            "methodcaller",
            "_evaluate",
            "evaluate_forward_ref",
            "evaluate",
            "call_evaluate_function",
            "annotationlib",
            "bltns",
            "_bltin",
            "stdlib_re",
            "_os",
            "_sys",
            "currentframe",
            "f_builtins",
            "f_globals",
            "f_locals",
            "f_back",
            "f_code",
            "gi_frame",
            "gi_code",
            "cr_frame",
            "cr_code",
            "ag_frame",
            "ag_code",
            "tb_frame",
            "tb_next",
            "co_code",
            "co_consts",
            "co_names",
            "CodeType",
            "FunctionType",
            "LambdaType",
            "MethodType",
            "__bases__",
            "__base__",
            "__mro__",
            "__code__",
            "__loader__",
            "__dict__",
            "__self__",
        }
    )
    | REFLECTION_NAMES
    | MODULE_NAMES
)
BANNED_ATTRIBUTE_PREFIXES: Final[tuple[str, ...]] = ("spawn", "fork", "posix_spawn", "_create_")
EXEC_FAMILY: Final[re.Pattern[str]] = re.compile(r"f?exec[lv][a-z]*")
BANNED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "use_unsafe_shell",
        "owner_uid",
        "state_dir",
        "lock_timeout",
        "policies",
        "trusted_dirs",
        "runner",
        "clock",
        "limits",
        "registry",
    }
)
DUNDER: Final[re.Pattern[str]] = re.compile(r"__\w+__")
OWN_NAMES: Final[frozenset[str]] = frozenset({"self", "cls"})
DUNDER_READS: Final[frozenset[str]] = frozenset({"__name__"})
SUPER_DUNDERS: Final[frozenset[str]] = frozenset({"__init__", "__post_init__"})
POST_INIT: Final[str] = "__post_init__"


def _words(text: str) -> frozenset[str]:
    """Return the whitespace-separated words of ``text`` as a set."""
    return frozenset(text.split())


STDLIB_MODULE_NAMES: Final[frozenset[str]] = _words(
    "__future__ _abc _aix_support _android_support _apple_support _ast _ast_unparse _asyncio "
    "_bisect _blake2 _bootlocale _bootsubprocess _bz2 _codecs _codecs_cn _codecs_hk "
    "_codecs_iso2022 _codecs_jp _codecs_kr _codecs_tw _collections _collections_abc _colorize "
    "_compat_pickle _compression _contextvars _crypt _csv _ctypes _ctypes_test _curses "
    "_curses_panel _datetime _dbm _decimal _elementtree _frozen_importlib "
    "_frozen_importlib_external _functools _gdbm _hashlib _heapq _hmac _imp _interpchannels "
    "_interpqueues _interpreters _io _ios_support _json _locale _lsprof _lzma _markupbase "
    "_math_integer _md5 _msi _multibytecodec _multiprocessing _opcode _opcode_metadata _operator "
    "_osx_support _overlapped _peg_parser _pickle _posixshmem _posixsubprocess _py_abc "
    "_py_warnings _pydatetime _pydecimal _pyio _pylong _pyrepl _queue _random _remote_debugging "
    "_scproxy _sha1 _sha2 _sha256 _sha3 _sha512 _signal _sitebuiltins _socket _sqlite3 _sre _ssl "
    "_stat _statistics _string _strptime _struct _suggestions _symtable _sysconfig _sysconfigdata "
    "_testbuffer _testimportmultiple _testinternalcapi _testmultiphase _thread _threading_local "
    "_tkinter _tokenize _tracemalloc _types _typing _uuid _warnings _weakref _weakrefset _winapi "
    "_wmi _xxsubinterpreters _xxtestfuzz _zoneinfo _zstd abc aifc annotationlib antigravity "
    "argparse array ast asynchat asyncio asyncore atexit audioop base64 bdb binascii binhex bisect "
    "builtins bz2 cProfile calendar cgi cgitb chunk cmath cmd code codecs codeop collections "
    "colorsys compileall compression concurrent configparser contextlib contextvars copy copyreg "
    "crypt csv ctypes curses dataclasses datetime dbm decimal difflib dis distutils doctest email "
    "encodings ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch formatter "
    "fractions ftplib functools gc genericpath getopt getpass gettext glob graphlib grp gzip "
    "hashlib heapq hmac html http idlelib imaplib imghdr imp importlib inspect io ipaddress "
    "itertools json keyword lib2to3 linecache locale logging lzma mailbox mailcap marshal math "
    "mimetypes mmap modulefinder msilib msvcrt multiprocessing netrc nis nntplib nt ntpath "
    "nturl2path numbers opcode operator optparse os ossaudiodev parser pathlib pdb pickle "
    "pickletools pipes pkgutil platform plistlib poplib posix posixpath pprint profile profiling "
    "pstats pty pwd py_compile pyclbr pydoc pydoc_data pyexpat queue quopri random re readline "
    "reprlib resource rlcompleter runpy sched secrets select selectors shelve shlex shutil signal "
    "site smtpd smtplib sndhdr socket socketserver spwd sqlite3 sre_compile sre_constants "
    "sre_parse ssl stat statistics string stringprep struct subprocess sunau symbol symtable sys "
    "sysconfig syslog tabnanny tarfile telnetlib tempfile termios textwrap this threading time "
    "timeit tkinter token tokenize tomllib trace traceback tracemalloc tty turtle turtledemo types "
    "typing unicodedata unittest urllib uu uuid venv warnings wave weakref webbrowser winreg "
    "winsound wsgiref xdrlib xml xmlrpc xxsubtype zipapp zipfile zipimport zlib zoneinfo"
)

KNOWN_SUBMODULE_ATTRIBUTES: Final[frozenset[str]] = _words(
    "_abc _casefix _collections_abc _compiler _constants _hashlib _heapq _local _locale _os "
    "_parser _sre _sys _thread abc annotationlib bltns builtins codecs collections contextlib copy "
    "copyreg decoder encoder enum errno errors fnmatch functools genericpath grp inspect io "
    "itertools keyword model ntpath operator os path posixpath pwd re scanner shutil sre_compile "
    "sre_parse st stat stdlib_re sys types warnings"
)
SETATTR_ARGUMENTS: Final[int] = 3
SUPER_ARGUMENTS: Final[int] = 2
FUNCTIONS: Final[tuple[type, ...]] = (ast.FunctionDef, ast.AsyncFunctionDef)
ALLOWED_COMPONENTS: Final[frozenset[str]] = frozenset(
    part for name in ALLOWED_IMPORTS for part in name.split(".")
) - frozenset({"types"})
STDLIB_MODULE_ATTRIBUTES: Final[frozenset[str]] = (
    STDLIB_MODULE_NAMES - ALLOWED_COMPONENTS - frozenset({"__future__"})
)
COLLECTION_MODULE_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    path.stem for path in (REPO_ROOT / PLUGINS_DIRECTORY).rglob("*.py") if path.stem != "__init__"
)
BANNED_MODULE_ATTRIBUTES: Final[frozenset[str]] = (
    STDLIB_MODULE_ATTRIBUTES | COLLECTION_MODULE_ATTRIBUTES
)
PROTECTED_NAMES: Final[frozenset[str]] = frozenset({"super", "object"})


def _dotted_parts(names: Iterable[str]) -> frozenset[str]:
    """Return every component after the first of the dotted module ``names``."""
    return frozenset(part for name in names for part in name.split(".")[1:])


SHARED_SUBMODULE_ATTRIBUTES: Final[frozenset[str]] = KNOWN_SUBMODULE_ATTRIBUTES | _dotted_parts(
    ALLOWED_IMPORTS
)
SUBMODULE_ATTRIBUTES: Final[frozenset[str]] = SHARED_SUBMODULE_ATTRIBUTES | _dotted_parts(
    name for names in EXTRA_IMPORTS.values() for name in names
)
RESERVED_ATTRIBUTES: Final[Mapping[str, str]] = MappingProxyType(
    {
        part: ", ".join(
            sorted(
                str(path) for path, names in EXTRA_IMPORTS.items() if part in _dotted_parts(names)
            )
        )
        for part in sorted(SUBMODULE_ATTRIBUTES - SHARED_SUBMODULE_ATTRIBUTES)
    }
)
OS_MODULE: Final[str] = "os"
OS_PATH: Final[str] = "path"
SHEBANG_PREFIX: Final[str] = "#!"
BLOCK_STYLES: Final[frozenset[str]] = frozenset({"|", ">"})
LINE_BREAK: Final[re.Pattern[str]] = re.compile(r"\r\n|[\n\r\x85\u2028\u2029]")
COMMENT_START: Final[re.Pattern[str]] = re.compile(r"(?:^|(?<=[ \t\r\n\x85\u2028\u2029]))#")


@dataclass(frozen=True, order=True, slots=True)
class Violation:
    """A single rule violation at ``path:line``."""

    path: Path
    line: int
    message: str

    def __str__(self) -> str:
        """Render the violation as ``path:line: message``."""
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True, slots=True)
class Comment:
    """A YAML comment with the code that precedes it on the same line."""

    line: int
    code: str
    text: str


class _TokenSource(Protocol):
    """Typed view of the untyped PyYAML scanner interface."""

    def check_token(self) -> bool:
        """Return whether another token is available."""
        ...

    def get_token(self) -> yaml.Token:
        """Consume and return the next token."""
        ...


def _line_breaks(text: str) -> list[tuple[int, int]]:
    """Return the ``(start, end)`` span of every line break in ``text``."""
    return [(match.start(), match.end()) for match in LINE_BREAK.finditer(text)]


def _block_content_start(text: str, indicator: int) -> int:
    """Return the offset of the line that follows the block scalar indicator."""
    match = LINE_BREAK.search(text, indicator)
    return len(text) if match is None else match.end()


def _scalar_spans(text: str) -> list[tuple[int, int]]:
    """Return the character spans that YAML scalars occupy in ``text``.

    The spans come from the PyYAML scanner, so quoted, plain and block scalars
    follow YAML semantics. Block scalar spans start on the line after the
    indicator, which leaves a header comment outside the span. A scanner
    error ends the scan; the spans found so far are returned.
    """
    spans: list[tuple[int, int]] = []
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError:
        return spans
    source = cast("_TokenSource", loader)
    try:
        while source.check_token():
            token = source.get_token()
            if not isinstance(token, yaml.ScalarToken):
                continue
            start = token.start_mark.index
            if token.style in BLOCK_STYLES:
                start = _block_content_start(text, start)
            spans.append((start, token.end_mark.index))
    except yaml.YAMLError:
        return spans
    finally:
        loader.dispose()
    return spans


def scan_yaml_comments(text: str) -> list[Comment]:
    """Return every YAML comment in ``text``.

    A ``#`` starts a comment when it is at the start of a line or follows
    whitespace and lies outside every scalar span reported by the scanner.
    """
    spans = _scalar_spans(text)
    breaks = _line_breaks(text)
    line_ends = [start for start, _ in breaks]
    line_starts = [0, *(end for _, end in breaks)]
    comments: list[Comment] = []
    for match in COMMENT_START.finditer(text):
        offset = match.start()
        if any(start <= offset < end for start, end in spans):
            continue
        index = bisect.bisect_right(line_starts, offset) - 1
        line_end = line_ends[index] if index < len(line_ends) else len(text)
        comments.append(
            Comment(index + 1, text[line_starts[index] : offset], text[offset:line_end].rstrip())
        )
    return comments


def is_allowed_annotation(comment: Comment) -> bool:
    """Return whether ``comment`` is a permitted version annotation on a pinned line."""
    if VERSION_ANNOTATION.fullmatch(comment.text) is None:
        return False
    return (
        PINNED_USES.fullmatch(comment.code) is not None
        or PINNED_REV.fullmatch(comment.code) is not None
    )


def check_document_start(path: Path, text: str) -> list[Violation]:
    """Require the YAML document-start marker on the first line."""
    if text.startswith(DOCUMENT_START):
        return []
    return [Violation(path, 1, "YAML file must start with '---' followed by a newline")]


def check_yaml_comments(path: Path, text: str) -> list[Violation]:
    """Reject YAML comments other than a version annotation on a pinned line."""
    return [
        Violation(path, comment.line, f"comment is not allowed: {comment.text!r}")
        for comment in scan_yaml_comments(text)
        if not is_allowed_annotation(comment)
    ]


def _module_name(value: str) -> str:
    """Strip a known collection prefix from ``value`` and return the module name."""
    for prefix in COLLECTION_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _is_banned(value: str) -> bool:
    """Return whether ``value`` names a banned module, with or without prefix."""
    return _module_name(value.strip()) in BANNED_MODULES


def _merged_items(mapping: yaml.MappingNode) -> list[tuple[yaml.Node, yaml.Node]]:
    """Return the key-value pairs of ``mapping`` with YAML merge keys (``<<``) expanded.

    Ansible constructs the merged mapping, so a task can take its module key from
    an anchor that is defined anywhere in the document. Every pair is returned,
    including keys that a later key overrides, and merge cycles terminate.
    """
    items: list[tuple[yaml.Node, yaml.Node]] = []
    seen: set[int] = set()
    pending: list[yaml.Node] = [mapping]
    while pending:
        node = pending.pop()
        if id(node) in seen or not isinstance(node, yaml.MappingNode):
            continue
        seen.add(id(node))
        for key, value in node.value:
            if key.tag != MERGE_TAG:
                items.append((key, value))
            elif isinstance(value, yaml.SequenceNode):
                pending.extend(reversed(value.value))
            else:
                pending.append(value)
    return items


def _scalar_items(mapping: yaml.MappingNode) -> Iterable[tuple[str, yaml.ScalarNode, yaml.Node]]:
    """Yield ``(name, key, value)`` for every scalar key of ``mapping``, merges expanded."""
    for key, value in _merged_items(mapping):
        if isinstance(key, yaml.ScalarNode):
            yield str(key.value), key, value


def _is_templated(text: str) -> bool:
    """Return whether ``text`` contains a Jinja expression, statement or comment."""
    return any(marker in text for marker in TEMPLATE_MARKERS)


def _action_modules(value: yaml.Node) -> Iterable[yaml.ScalarNode]:
    """Yield the scalars that name the module of an ``action`` style value.

    Every ``module`` key of the mapping form is yielded, so a duplicated key
    cannot hide a banned module behind an allowed one.
    """
    if isinstance(value, yaml.ScalarNode):
        yield value
    elif isinstance(value, yaml.MappingNode):
        for name, _, inner in _scalar_items(value):
            if name == MODULE_KEY and isinstance(inner, yaml.ScalarNode):
                yield inner


def _action_findings(value: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield a finding for each banned or templated module named by an ``action`` value.

    Ansible takes the module name from the first word of the string form and of
    the ``module`` key of the mapping form, so ``module: shell echo hi`` names
    ``shell``. A templated module name cannot be checked statically and is denied.
    """
    for module in _action_modules(value):
        words = str(module.value).split(maxsplit=1)
        if not words:
            continue
        if _is_banned(words[0]):
            yield module, f"banned module: {module.value!r}"
        elif _is_templated(words[0]):
            yield module, f"templated module name in an action is not allowed: {module.value!r}"


def _node_text(node: yaml.Node) -> str:
    """Return the value of a scalar node, or the kind of any other node."""
    if isinstance(node, yaml.ScalarNode):
        return str(node.value)
    return "sequence" if isinstance(node, yaml.SequenceNode) else "mapping"


def _is_task_file_name(node: yaml.Node) -> bool:
    """Return whether ``node`` is a scalar file name with a YAML suffix."""
    return isinstance(node, yaml.ScalarNode) and str(node.value).strip().endswith(
        TASK_FILE_SUFFIXES
    )


def _include_findings(
    key: yaml.ScalarNode, value: yaml.Node, name: str
) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for an included task or playbook file that the check cannot scan.

    The included file is itself a task file or a playbook. The check scans every
    YAML file of the repository, so the target must be a ``.yml`` or ``.yaml``
    file: a target without that suffix (``tasks.json``) or with a templated suffix
    could load tasks from a file that is never scanned.
    """
    if isinstance(value, yaml.MappingNode):
        targets = [inner for field, _, inner in _scalar_items(value) if field in INCLUDE_FILE_KEYS]
    else:
        targets = [value]
    if not targets:
        yield key, f"{name} needs a file name ending in .yml or .yaml"
    for target in targets:
        if not _is_task_file_name(target):
            yield target, f"{name} target must end in .yml or .yaml: {_node_text(target)!r}"


def _role_include_findings(value: yaml.Node, name: str) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for a role entry point that the check cannot scan.

    Without a suffix Ansible also tries ``.json`` and the bare name, which the
    check never scans, so ``tasks_from`` and ``handlers_from`` need ``.yml`` or
    ``.yaml``. The default entry point is ``main``; a repository test keeps every
    file below a ``tasks`` or ``handlers`` directory a YAML file. The free-form
    ``key=value`` string is checked word by word.
    """
    if isinstance(value, yaml.ScalarNode):
        for word in str(value.value).split():
            field, separator, entry = word.partition("=")
            if (
                separator
                and field in ROLE_ENTRY_POINT_KEYS
                and not entry.endswith(TASK_FILE_SUFFIXES)
            ):
                yield value, f"{name} {field} must end in .yml or .yaml: {entry!r}"
    elif isinstance(value, yaml.MappingNode):
        for field, _, inner in _scalar_items(value):
            if field in ROLE_ENTRY_POINT_KEYS and not _is_task_file_name(inner):
                yield inner, f"{name} {field} must end in .yml or .yaml: {_node_text(inner)!r}"


def _task_findings(task: yaml.MappingNode) -> Iterable[tuple[yaml.Node, str]]:
    """Yield the findings for one mapping that Ansible may load as a play or a task.

    Only the keys of the mapping itself can name the module of a task. Their
    values are module parameters or keyword data (``vars``, ``set_fact``
    arguments, ``loop`` items, ``module_defaults``) and are not inspected, except
    for ``action`` and ``local_action`` and the file names of includes.
    """
    for name, key, value in _scalar_items(task):
        module = _module_name(name.strip())
        if module in BANNED_MODULES:
            yield key, f"banned module: {key.value!r}"
        elif name in ACTION_KEYS:
            yield from _action_findings(value)
        elif module in TASK_INCLUDE_MODULES:
            yield from _include_findings(key, value, name)
        elif module in ROLE_INCLUDE_MODULES:
            yield from _role_include_findings(value, name)


def _task_mappings(root: yaml.Node) -> Iterable[yaml.MappingNode]:
    """Yield every mapping that Ansible may load as a play or a task below ``root``.

    ``root`` is a task list: the top-level sequence of a playbook or task file.
    Every mapping in a task list is treated as both a play and a task, and the
    task lists of plays (``tasks``, ``pre_tasks``, ``post_tasks``, ``handlers``)
    and of blocks (``block``, ``rescue``, ``always``) are followed to any depth,
    through aliases and merge keys. A task list that is a mapping instead of a
    sequence, and a sequence nested in a task list, are treated as tasks too,
    which fails safe.
    """
    seen: set[int] = set()
    pending: list[yaml.Node] = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            pending.extend(reversed(node.value))
        elif isinstance(node, yaml.MappingNode):
            yield node
            pending.extend(
                value for name, _, value in _scalar_items(node) if name in TASK_LIST_KEYS
            )


def _walk_nodes(root: yaml.Node) -> Iterable[yaml.Node]:
    """Yield every distinct node below ``root`` without following alias cycles."""
    seen: set[int] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                pending.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)


def _anywhere_findings(root: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for banned module keys, action values and redirects at any depth.

    A ``redirect`` to a banned module (``plugin_routing`` in ``meta/runtime.yml``)
    would make an allowed-looking name an alias of that module, so it is denied.
    """
    for node in _walk_nodes(root):
        if not isinstance(node, yaml.MappingNode):
            continue
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                continue
            if _is_banned(str(key.value)):
                yield key, f"banned module: {key.value!r}"
            elif key.value in ACTION_KEYS:
                yield from _action_findings(value)
            elif (
                key.value == REDIRECT_KEY
                and isinstance(value, yaml.ScalarNode)
                and _is_banned(str(value.value))
            ):
                yield value, f"redirect to a banned module: {value.value!r}"


def _banned_findings(root: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield each banned-module finding of one YAML document once.

    A document whose root is a sequence may be a playbook or a task file: every
    role ``tasks/`` and ``handlers/`` file and every included file is one. Only the
    keys of its plays and tasks name modules, so only they are checked. A
    document with any other root can never be loaded as plays or tasks; it stays
    checked deny-by-default for banned keys and action values at any depth.
    """
    findings: Iterable[tuple[yaml.Node, str]]
    if isinstance(root, yaml.SequenceNode):
        findings = (finding for task in _task_mappings(root) for finding in _task_findings(task))
    else:
        findings = _anywhere_findings(root)
    reported: set[tuple[int, str]] = set()
    for node, message in findings:
        if (id(node), message) not in reported:
            reported.add((id(node), message))
            yield node, message


def _invalid_yaml(path: Path, error: yaml.YAMLError) -> Violation:
    """Describe a YAML error as a violation at the line the parser reports."""
    mark = getattr(error, "problem_mark", None)
    line = 1 if mark is None else int(mark.line) + 1
    return Violation(path, line, f"invalid YAML: {error}")


def check_banned_modules(path: Path, text: str) -> list[Violation]:
    """Reject banned command-execution modules and report unparsable YAML."""
    violations: list[Violation] = []
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError as error:
        return [_invalid_yaml(path, error)]
    try:
        loader.check_node()
        for document in iter(loader.get_node, None):
            violations.extend(
                Violation(path, node.start_mark.line + 1, message)
                for node, message in _banned_findings(document)
            )
    except yaml.YAMLError as error:
        violations.append(_invalid_yaml(path, error))
    finally:
        loader.dispose()
    return violations


def check_python_comments(path: Path, data: bytes) -> list[Violation]:
    """Reject every Python comment except a shebang on the first line."""
    violations: list[Violation] = []
    try:
        for token in tokenize.tokenize(io.BytesIO(data).readline):
            if token.type != tokenize.COMMENT:
                continue
            line = token.start[0]
            if line == 1 and token.string.startswith(SHEBANG_PREFIX):
                continue
            violations.append(Violation(path, line, f"comment is not allowed: {token.string!r}"))
    except (tokenize.TokenError, SyntaxError, UnicodeDecodeError) as error:
        violations.append(Violation(path, 1, f"cannot tokenize Python: {error}"))
    return violations


def is_process_scope(path: Path, root: Path) -> bool:
    """Return whether ``path`` is plugin code that may not run processes itself."""
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return relative.parts[:1] == (PLUGINS_DIRECTORY,) and relative != PROCESS_HELPER


def _is_banned_attribute(name: str) -> bool:
    return (
        name in BANNED_ATTRIBUTES
        or name.startswith(BANNED_ATTRIBUTE_PREFIXES)
        or EXEC_FAMILY.fullmatch(name) is not None
    )


def _is_private(name: str, *, include_dunder: bool = False) -> bool:
    """Return whether ``name`` starts with an underscore; dunders only on request."""
    if not name.startswith("_"):
        return False
    return include_dunder or DUNDER.fullmatch(name) is None


def _binding_names(node: ast.AST) -> Iterable[str]:
    """Yield every name that ``node`` binds, rebinds or deletes."""
    if isinstance(node, ast.Name):
        if not isinstance(node.ctx, ast.Load):
            yield node.id
    elif isinstance(node, ast.arg):
        yield node.arg
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        yield from (alias.asname or alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        yield from node.names
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        yield node.name
    elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        yield from (node.name,) if node.name else ()
    elif isinstance(node, ast.MatchMapping):
        yield from (node.rest,) if node.rest else ()


def _rebinds(method: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    """Return whether ``method`` rebinds, deletes or shadows its first parameter ``name``."""
    first = [*method.args.posonlyargs, *method.args.args][0]
    return any(
        name in _binding_names(node)
        for node in ast.walk(method)
        if node is not first and node is not method
    )


@dataclass(frozen=True, slots=True)
class _Scope:
    """Facts about one parsed module that the per-node checks need."""

    call_targets: set[int]
    os_path_bases: set[int]
    imported: frozenset[str]
    modules: frozenset[str]
    parents: dict[int, ast.AST]
    restricted: Mapping[str, frozenset[str]]
    restricted_bases: set[int]
    fileio_attribute_allowed: bool
    reserved: Mapping[str, str]

    def ancestors(self, node: ast.AST) -> Iterable[ast.AST]:
        """Yield the parents of ``node``, nearest first."""
        current = self.parents.get(id(node))
        while current is not None:
            yield current
            current = self.parents.get(id(current))

    def own_method(self, node: ast.expr) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Return the method whose never rebound first parameter ``node`` names, if any."""
        if not (isinstance(node, ast.Name) and node.id in OWN_NAMES):
            return None
        for ancestor in self.ancestors(node):
            if not isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [*ancestor.args.posonlyargs, *ancestor.args.args]
            if (
                isinstance(self.parents.get(id(ancestor)), ast.ClassDef)
                and params
                and params[0].arg == node.id
                and not any(
                    isinstance(d, ast.Name) and d.id == "staticmethod"
                    for d in ancestor.decorator_list
                )
                and not _rebinds(ancestor, node.id)
            ):
                return ancestor
        return None

    def is_own(self, node: ast.expr) -> bool:
        """Return whether ``node`` is the intact ``self`` or ``cls`` parameter of a method."""
        return self.own_method(node) is not None

    def at_module_level(self, node: ast.AST) -> bool:
        """Return whether no function or class encloses ``node``."""
        return not any(
            isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            for ancestor in self.ancestors(node)
        )

    def is_module_rooted(self, node: ast.expr) -> bool:
        """Return whether ``node`` is an attribute chain rooted in a module-bound name."""
        current = node
        while isinstance(current, ast.Attribute):
            current = current.value
        return isinstance(current, ast.Name) and current.id in self.modules

    def is_imported(self, node: ast.expr) -> bool:
        """Return whether ``node`` is rooted in a name that an import statement binds."""
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        return isinstance(current, ast.Name) and current.id in self.imported


def _bound_names(nodes: Iterable[ast.AST]) -> frozenset[str]:
    """Return every name that an import statement binds."""
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            names.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names)
    return frozenset(names)


def _module_exists(base: Path) -> bool:
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def _imports_module(node: ast.ImportFrom, name: str, path: Path) -> bool:
    """Return whether ``from module import name`` binds a module."""
    module = node.module or ""
    if node.level:
        base = path.resolve().parent
        for _ in range(node.level - 1):
            base = base.parent
        return _module_exists(base.joinpath(*filter(None, module.split(".")), name))
    if name in SUBMODULE_ATTRIBUTES:
        return True
    full = f"{module}.{name}"
    if module == COLLECTION_PREFIX or module.startswith(COLLECTION_PREFIX + "."):
        return _module_exists(
            REPO_ROOT.joinpath(*full.split(".")[len(COLLECTION_PREFIX.split(".")) :])
        )
    return module in ANSIBLE_PACKAGES and name.islower()


def _module_names(nodes: Iterable[ast.AST], path: Path) -> frozenset[str]:
    """Return every name that an import statement binds to a module."""
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            names.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(
                a.asname or a.name for a in node.names if _imports_module(node, a.name, path)
            )
    return frozenset(names)


def _is_allowed_import(name: str, extra: frozenset[str]) -> bool:
    return (
        name in ALLOWED_IMPORTS
        or name in extra
        or any(
            name == prefix or name.startswith(prefix + ".") for prefix in ALLOWED_IMPORT_PREFIXES
        )
    )


def _not_allowed(name: str) -> str:
    return f"import of {name!r} is not allowed in plugins outside {PROCESS_HELPER}"


def _alias_findings(node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    """Yield a description for each import bound to a banned name with ``as``."""
    for alias in node.names:
        if alias.asname and (_is_banned_attribute(alias.asname) or alias.asname in BANNED_NAMES):
            yield f"import under the name {alias.asname!r} is not allowed in plugins"


def _private_import_findings(node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    """Yield a description for each underscore-prefixed module or name that ``node`` imports."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            if any(_is_private(part) for part in alias.name.split(".")):
                yield f"import of private module {alias.name!r} is not allowed in plugins"
        return
    module = node.module or ""
    if any(_is_private(part) for part in module.split(".")):
        yield f"import from private module {module!r} is not allowed in plugins"
    for alias in node.names:
        if _is_private(alias.name, include_dunder=True):
            yield f"import of private name {alias.name!r} is not allowed in plugins"
        elif alias.name in STDLIB_MODULE_ATTRIBUTES:
            yield f"import of module name {alias.name!r} through another module is not allowed"


def _reserved_findings(names: Iterable[str], reserved: Mapping[str, str]) -> Iterable[str]:
    """Yield a description for each name that only another plugin file may import."""
    for name in names:
        if name in reserved:
            yield f"import of {name!r} is restricted to {reserved[name]}"


def _plain_import_findings(
    node: ast.Import,
    extra: frozenset[str],
    restricted: frozenset[str],
    reserved: Mapping[str, str],
) -> Iterable[str]:
    """Yield a description for each ``import x`` name that is not allow-listed."""
    for alias in node.names:
        if alias.name in RESTRICTED_FROM_IMPORTS or not _is_allowed_import(alias.name, extra):
            yield _not_allowed(alias.name)
        elif alias.name in restricted and alias.asname:
            yield f"import of {alias.name!r} under another name is not allowed in plugins"
        else:
            yield from _reserved_findings(alias.name.split("."), reserved)


def _import_findings(
    node: ast.Import | ast.ImportFrom,
    extra: frozenset[str],
    restricted: frozenset[str],
    reserved: Mapping[str, str],
) -> Iterable[str]:
    """Yield a description for each import on ``node`` that is not allow-listed."""
    yield from _alias_findings(node)
    yield from _private_import_findings(node)
    if isinstance(node, ast.Import):
        yield from _plain_import_findings(node, extra, restricted, reserved)
        return
    module = node.module or ""
    if module in restricted and not node.level and module != OS_MODULE:
        yield f"from-import of {module!r} is not allowed in plugins"
    if (
        not node.level
        and module != OS_MODULE
        and not _is_allowed_import(module, extra)
        and not all(f"{module}.{alias.name}" in extra for alias in node.names)
    ):
        yield _not_allowed(module)
    else:
        names = [*module.split("."), *(alias.name for alias in node.names)]
        yield from _reserved_findings(names, reserved)
    for alias in node.names:
        if module in RESTRICTED_FROM_IMPORTS and alias.name not in RESTRICTED_FROM_IMPORTS[module]:
            yield _not_allowed(f"{module}.{alias.name}")
        elif alias.name == "*":
            yield f"star import from {module!r} is not allowed in plugins"
        elif module == OS_MODULE and not node.level and alias.name != OS_PATH:
            yield _not_allowed(f"os.{alias.name}")
        elif _is_banned_attribute(alias.name) or alias.name in BANNED_NAMES:
            yield f"import of {alias.name!r} is not allowed in plugins"


def _dynamic_attribute_findings(node: ast.Call, name: str, scope: _Scope) -> Iterable[str]:
    """Yield descriptions for ``getattr`` style calls with an unsafe target or name."""
    attribute = node.args[1] if len(node.args) > 1 else None
    if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        yield "getattr, setattr and delattr need a literal attribute name"
    elif attribute.value == FILE_IO_MODULE and not scope.fileio_attribute_allowed:
        yield f"attribute {FILE_IO_MODULE!r} is restricted to ledger.py"
    elif attribute.value in scope.reserved:
        yield f"attribute {attribute.value!r} is restricted to {scope.reserved[attribute.value]}"
    elif _is_banned_attribute(attribute.value) or (
        attribute.value in BANNED_MODULE_ATTRIBUTES and scope.is_module_rooted(node.args[0])
    ):
        yield f"attribute {attribute.value!r} is not allowed in plugins"
    elif DUNDER.fullmatch(attribute.value):
        if name != "getattr" or attribute.value not in DUNDER_READS:
            yield f"dunder attribute {attribute.value!r} is not allowed in plugins"
    elif _is_private(attribute.value) and not scope.is_own(node.args[0]):
        yield f"underscore-prefixed attribute {attribute.value!r} of another object is not allowed"
    if name != "getattr" and node.args and scope.is_imported(node.args[0]):
        yield f"{name} on an imported module is not allowed in plugins"


def _call_findings(node: ast.Call, scope: _Scope) -> Iterable[str]:
    """Yield descriptions for forbidden keywords and dynamic attribute access."""
    for keyword in node.keywords:
        if keyword.arg is None:
            yield "dict splat (**) in a call is not allowed in plugins"
        if keyword.arg in BANNED_KEYWORDS:
            yield f"keyword {keyword.arg!r} is not allowed in plugins"
        if (
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        ):
            yield "shell=True is forbidden"
    if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_ATTRIBUTE_BUILTINS:
        yield from _dynamic_attribute_findings(node, node.func.id, scope)


def _name_findings(node: ast.Name, scope: _Scope) -> Iterable[str]:
    """Yield descriptions for banned builtins and for uses of ``os`` other than ``os.path``."""
    if node.id in BANNED_NAMES:
        yield f"use of {node.id} is not allowed in plugins"
    if node.id in DYNAMIC_ATTRIBUTE_BUILTINS and id(node) not in scope.call_targets:
        yield f"{node.id} may only be called directly"
    permitted = scope.os_path_bases | scope.restricted_bases
    if node.id == OS_MODULE and id(node) not in permitted:
        yield "os may only be used as os.path in plugins"
    if node.id in scope.restricted and node.id != OS_MODULE and id(node) not in permitted:
        yield f"{node.id} may only be used through its permitted attributes in plugins"
    parent = scope.parents.get(id(node))
    if node.id in scope.modules and not (
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and isinstance(node.ctx, ast.Load)
    ):
        yield f"module name {node.id!r} may only be used as {node.id}.attribute in plugins"


def _is_guarded_store(node: ast.Attribute, scope: _Scope) -> bool:
    """Return whether ``node`` is the allowed ``object.__setattr__`` form."""
    call = scope.parents.get(id(node))
    if not (
        isinstance(call, ast.Call)
        and call.func is node
        and node.attr == "__setattr__"
        and isinstance(node.value, ast.Name)
        and node.value.id == "object"
        and len(call.args) == SETATTR_ARGUMENTS
        and not call.keywords
    ):
        return False
    target, field = call.args[0], call.args[1]
    method = scope.own_method(target)
    return (
        method is not None
        and isinstance(target, ast.Name)
        and target.id == "self"
        and method.name == POST_INIT
        and next((a for a in scope.ancestors(call) if isinstance(a, FUNCTIONS)), None) is method
        and isinstance(field, ast.Constant)
        and isinstance(field.value, str)
        and not _is_banned_attribute(field.value)
        and DUNDER.fullmatch(field.value) is None
    )


def _is_restricted_attribute(node: ast.Attribute, scope: _Scope) -> bool:
    """Return whether ``node`` is one of the permitted attributes of a restricted module."""
    return isinstance(node.value, ast.Name) and node.attr in scope.restricted.get(
        node.value.id, frozenset()
    )


def _is_attribute_base(node: ast.Attribute, scope: _Scope) -> bool:
    """Return whether ``node`` is the value of an enclosing attribute access."""
    parent = scope.parents.get(id(node))
    return isinstance(parent, ast.Attribute) and parent.value is node


def _is_super_call(node: ast.Attribute, scope: _Scope) -> bool:
    """Return whether ``node`` calls __init__ or __post_init__ on ``super()``."""
    call = scope.parents.get(id(node))
    receiver = node.value
    if not (
        isinstance(call, ast.Call)
        and call.func is node
        and node.attr in SUPER_DUNDERS
        and isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Name)
        and receiver.func.id == "super"
        and not receiver.keywords
    ):
        return False
    args = receiver.args
    return not args or (
        len(args) == SUPER_ARGUMENTS and isinstance(args[0], ast.Name) and scope.is_own(args[1])
    )


def _attribute_findings(node: ast.Attribute, scope: _Scope) -> Iterable[str]:
    """Yield descriptions for banned, dunder, private and imported-module attribute use."""
    if _is_guarded_store(node, scope):
        return
    if _is_banned_attribute(node.attr) or (
        node.attr in BANNED_MODULE_ATTRIBUTES and scope.is_module_rooted(node.value)
    ):
        yield f"attribute {node.attr!r} is not allowed in plugins"
    stored = not isinstance(node.ctx, ast.Load)
    if DUNDER.fullmatch(node.attr):
        if not _is_banned_attribute(node.attr) and (
            stored or not (node.attr in DUNDER_READS or _is_super_call(node, scope))
        ):
            yield f"dunder attribute {node.attr!r} is not allowed in plugins"
    elif _is_private(node.attr) and not scope.is_own(node.value):
        yield f"underscore-prefixed attribute {node.attr!r} of another object is not allowed"
    if stored and scope.is_imported(node.value):
        yield f"assigning attribute {node.attr!r} of an imported module is not allowed in plugins"
    if node.attr == FILE_IO_MODULE and not scope.fileio_attribute_allowed:
        yield f"attribute {FILE_IO_MODULE!r} is restricted to ledger.py"
    if node.attr in scope.reserved:
        yield f"attribute {node.attr!r} is restricted to {scope.reserved[node.attr]}"
    if (
        node.attr in SUBMODULE_ATTRIBUTES
        and scope.is_module_rooted(node.value)
        and not _is_attribute_base(node, scope)
        and not _is_restricted_attribute(node, scope)
    ):
        yield f"module {node.attr!r} may only be used as {node.attr}.attribute in plugins"


def _definition_findings(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, scope: _Scope
) -> Iterable[str]:
    """Yield a description for a module-level ``__getattr__`` definition."""
    if node.name == "__getattr__" and scope.at_module_level(node):
        yield "module-level __getattr__ is not allowed in plugins"


def _declaration_findings(node: ast.Global | ast.Nonlocal, scope: _Scope) -> Iterable[str]:
    """Yield a description for each module name that ``node`` declares global or nonlocal."""
    for name in node.names:
        if name in scope.modules:
            yield f"module name {name!r} may not be declared global or nonlocal in plugins"


def _binding_findings(node: ast.AST) -> Iterable[str]:
    """Yield a description for each protected builtin name that ``node`` binds."""
    for name in PROTECTED_NAMES.intersection(_binding_names(node)):
        yield f"the name {name!r} may not be rebound in plugins"


def _pattern_findings(node: ast.MatchClass, scope: _Scope) -> Iterable[str]:
    """Yield a description for each reserved name that a class pattern reads as a keyword."""
    for name in node.kwd_attrs:
        if name in scope.reserved:
            yield f"attribute {name!r} is restricted to {scope.reserved[name]}"


def _process_findings(node: ast.AST, scope: _Scope, extra: frozenset[str]) -> Iterable[str]:
    """Yield a description for each forbidden construct on ``node`` itself."""
    yield from _binding_findings(node)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        yield from _import_findings(node, extra, frozenset(scope.restricted), scope.reserved)
    elif isinstance(node, ast.Name):
        yield from _name_findings(node, scope)
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        yield from _declaration_findings(node, scope)
    elif isinstance(node, ast.Attribute):
        yield from _attribute_findings(node, scope)
    elif isinstance(node, ast.Subscript):
        if not isinstance(node.ctx, ast.Load) and scope.is_imported(node.value):
            yield "assigning an item of an imported module attribute is not allowed in plugins"
    elif isinstance(node, ast.Call):
        yield from _call_findings(node, scope)
    elif isinstance(node, ast.MatchClass):
        yield from _pattern_findings(node, scope)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        yield from _definition_findings(node, scope)


def _restricted_bases(
    nodes: Iterable[ast.AST], restricted: Mapping[str, frozenset[str]]
) -> set[int]:
    """Return the ids of module names used as the base of a permitted attribute."""
    return {
        id(node.value)
        for node in nodes
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.attr in restricted.get(node.value.id, frozenset())
    }


def _reserved_for(extra_imports: frozenset[str]) -> Mapping[str, str]:
    """Return the reserved attribute names that a file with ``extra_imports`` may not use."""
    owned = _dotted_parts(extra_imports)
    return MappingProxyType(
        {name: owner for name, owner in RESERVED_ATTRIBUTES.items() if name not in owned}
    )


def check_process_isolation(
    path: Path,
    data: bytes,
    extra_imports: frozenset[str] = frozenset(),
    restricted: Mapping[str, frozenset[str]] = NO_RESTRICTION,
    *,
    fileio_attribute_allowed: bool = False,
) -> list[Violation]:
    """Reject, by default, anything in plugin code that could run a process.

    Only allow-listed imports are accepted, ``exec``, ``eval``, ``compile`` and
    ``__import__`` are banned, ``os`` is usable only as ``os.path``, attribute
    names that run or spawn processes are banned wherever they appear, and
    ``getattr`` style calls need a literal, permitted attribute name.
    """
    try:
        tree = ast.parse(data, filename=str(path))
    except (SyntaxError, ValueError) as error:
        return [Violation(path, 1, f"cannot parse Python: {error}")]
    nodes = list(ast.walk(tree))
    call_targets = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
    os_path_bases = {
        id(node.value)
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr == OS_PATH
        and isinstance(node.value, ast.Name)
        and node.value.id == OS_MODULE
    }
    scope = _Scope(
        call_targets,
        os_path_bases,
        _bound_names(nodes),
        _module_names(nodes, path),
        {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)},
        restricted,
        _restricted_bases(nodes, restricted),
        fileio_attribute_allowed,
        _reserved_for(extra_imports),
    )
    return sorted(
        {
            Violation(path, getattr(node, "lineno", 1), message)
            for node in nodes
            for message in _process_findings(node, scope, extra_imports)
        }
    )


def _file_io_import_findings(path: Path, data: bytes) -> list[Violation]:
    """Reject imports of the file-I/O helper by any file except its sanctioned importers."""
    try:
        tree = ast.parse(data, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    findings: list[Violation] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or "", *(alias.name for alias in node.names)]
        if any(name.split(".")[-1] == FILE_IO_MODULE for name in names):
            findings.append(
                Violation(
                    path,
                    getattr(node, "lineno", 1),
                    f"import of {FILE_IO_MODULE!r} is restricted to ledger.py",
                )
            )
    return findings


def check_file(path: Path, root: Path = REPO_ROOT) -> list[Violation]:
    """Apply every rule that matches the suffix and location of ``path``."""
    suffix = path.suffix.lower()
    if suffix not in YAML_SUFFIXES | PYTHON_SUFFIXES:
        return []
    try:
        data = path.read_bytes()
    except OSError as error:
        return [Violation(path, 1, f"cannot read file: {error}")]
    if suffix in PYTHON_SUFFIXES:
        violations = check_python_comments(path, data)
        if is_process_scope(path, root):
            relative = path.resolve().relative_to(root.resolve())
            extra = EXTRA_IMPORTS.get(relative, frozenset())
            restricted = FILE_IO_ATTRIBUTES if relative == FILE_IO_HELPER else NO_RESTRICTION
            if restricted:
                extra = extra | frozenset(restricted)
            violations.extend(
                check_process_isolation(
                    path,
                    data,
                    extra,
                    restricted,
                    fileio_attribute_allowed=relative == LEDGER_MODULE,
                )
            )
            if relative not in FILE_IO_IMPORTERS:
                violations.extend(_file_io_import_findings(path, data))
        return violations
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [Violation(path, 1, f"file is not valid UTF-8: {error}")]
    return [
        *check_document_start(path, text),
        *check_yaml_comments(path, text),
        *check_banned_modules(path, text),
    ]


def check_paths(paths: Iterable[Path], root: Path = REPO_ROOT) -> list[Violation]:
    """Check every path and return the violations in sorted order."""
    return sorted(violation for path in paths for violation in check_file(path, root))


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Files to check.")
    arguments = parser.parse_args(argv)
    violations = check_paths(arguments.paths)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        print(f"{len(violations)} repository rule violation(s)", file=sys.stderr)
        return 1
    print(f"repository rules satisfied in {len(arguments.paths)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
