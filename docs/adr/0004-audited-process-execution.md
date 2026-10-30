# 0004. Single audited helper for external process execution

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-47
- **Pull requests:** pending (FREES-47)

## Context

OpenSCAP must be executed as a binary. `AnsibleModule.run_command` accepts argument lists but does not
offer a timeout, and scattered process calls are hard to review.

## Decision

All external process execution in target-side code goes through
`plugins/module_utils/compliance/process.py`, which resolves the binary to an absolute path, accepts only an
argument list, runs with `shell=False`, an explicit minimal environment, a mandatory timeout and bounded
output capture, and returns a typed result. Callers validate every user-derived argument against an
allow-list or strict pattern before calling it. Ruff, Bandit and a repository test forbid `subprocess`
usage anywhere else.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| `AnsibleModule.run_command` everywhere | No timeout; harder to enforce environment and output bounds |
| Unrestricted `subprocess` per module | Not reviewable; inconsistent validation |

## Benefits

One place to review, test adversarially and keep at 100% branch coverage.

## Trade-offs

Uses `subprocess` directly rather than the Ansible wrapper, which is documented here as deliberate.

## Security implications

Eliminates shell injection paths, enforces timeouts and keeps secrets out of child environments.

## Operational consequences

Adding a new executable requires extending the helper's allow-list and a security review.

## Amendment 2026-10-25: implemented API (FREES-47)

`plugins/module_utils/compliance/process.py` is the only file in `plugins/` that may import `subprocess`. It is
standard-library only and supports Python 3.9 to 3.14. The shipped interface is:

| Item | Contract |
|---|---|
| `CommandSpec` | Frozen. `executable` (bare name matching `[a-z][a-z0-9_-]{0,63}`), `args` (tuple of str), `timeout_seconds` (required, above 0 and at most `MAX_TIMEOUT_SECONDS`, 3600), `max_output_bytes` (1 to 16 MiB, default 1 MiB, applied to stdout and stderr each), `env_allow`, `cwd` (absolute existing directory or `None`) |
| Arguments | Each is a non-empty `str` of at most 4096 characters without NUL or other control characters, at most 64 arguments. Shell metacharacters are data because no shell is involved |
| Options | An argument starting with `-` must name an option in the executable's `ExecutablePolicy.allowed_options`; `--name=value` is matched on the name. `FORBIDDEN_OPTIONS` (`--fetch-remote-resources`) is rejected for every executable, even if a policy lists it, so remote fetching cannot be enabled |
| Allow-list | `ALLOWED_EXECUTABLES` holds only `oscap`. Its sub-commands are allow-listed as leading argument sequences: `xccdf eval` and `info`, each followed only by allow-listed options (`--profile`, `--results-arf`, `--results`, `--report`, `--tailoring-file`) and positional values, and `--version` alone. Any other sequence is refused, so `xccdf remediate`, `xccdf generate fix`, `oval eval` and a bare `xccdf` never run. The words `remediate` and `--remediate` and the sequence `generate fix` are refused anywhere in the arguments for every executable, because running upstream fix scripts is excluded by ADR 0003. A policy with no command prefixes permits nothing. Adding an executable, sub-command or option requires a security review |
| `resolve_executable(name, *, trusted_dirs, owner_uid)` (keyword-only seams since FREES-137) | Searches only `TRUSTED_DIRECTORIES` (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`), never `PATH`. Rejects names with separators or traversal, trusted directories and files that are not owned by `owner_uid` (root, 0, by default) or are writable by group or others, symlinks that resolve outside the trusted directories, non-regular files and non-executable files. A missing file raises `ProcessExecutionError`. It returns the vetted path inside the trusted directory, not the symlink target |
| `confined_path(base, candidate)` | Returns the normalised absolute path, rejects NUL, escapes from `base` and any symlink below `base`. Callers still validate their own path arguments |
| `run(spec)` | Returns a frozen `CommandResult` (`argv`, `returncode`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `duration_seconds`, `timed_out`). The child gets `shell=False`, `stdin=DEVNULL`, `close_fds=True`, `start_new_session=True` and an explicit environment |
| Environment | Always `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `LANG=C`. `env_allow` may additionally copy `TZ` and `TMPDIR` from the parent; any other name is a policy error. The environment is never returned or logged |
| Exceptions | `ProcessPolicyError` (also a `ValueError`; nothing ran) and `ProcessExecutionError` (also a `RuntimeError`; missing binary, start failure, read failure), both under `ProcessError`. Untrusted values appear only as `repr` truncated to 64 characters |

Deviations and decisions:

- The implementation uses `subprocess.Popen` with `selectors` and chunked reads from both pipes instead of
  `subprocess.run`, so memory is bounded by `max_output_bytes` and the pipes cannot deadlock. Output beyond the cap
  is drained and discarded, not kept, and the truncation flag is set.
- The whole process group is killed with `SIGKILL` after the leader exits (the leader is waited for without being
  reaped, so the group id cannot be reused) and when the timeout expires. Detached members of the group therefore do
  not outlive the run. A timeout is reported as `timed_out=True`, not as an exception,
  so the caller maps it to outcome `error` (ADR 0013). A descendant that left the group with `setsid` and keeps the
  output pipes open is bounded by the timeout; the result then has `timed_out=True` even if the leader exited with
  status 0, which fails safe. Output path options (`--results`, `--report`) are not confined by the helper; callers
  must pass them through `confined_path`.
- `run` accepts the keyword-only parameters `policies`, `trusted_dirs` and `owner_uid`. They exist solely so that
  unit tests can run harmless system utilities from a directory they own and are never passed by production code.
  `run` validates the specification again before use, so a specification altered after construction cannot skip the
  argument checks. Arguments that the operating system cannot encode, such as a lone surrogate, are policy errors.
- Trusted-directory vetting and `exec` are separate steps, so a file replaced between them is not detected. The
  trusted directories and binaries must be root-owned and not writable by group or others.
- A symlink inside a trusted directory that points elsewhere, such as an `update-alternatives` link under `/etc`,
  is refused. This is deliberate and conservative.
- `tools/lint/check_repo_rules.py` (the rules live in `tools/lint/repo_rules/`, this one in `isolation.py`) applies
  a deny-by-default rule to Python files under `plugins/` other than
  `process.py`. They may import only allow-listed standard library modules (`__future__`, `collections`,
  `collections.abc`, `dataclasses`, `datetime`, `enum`, `functools`, `hashlib`, `itertools`, `json`, `os.path`,
  `pathlib`, `re`, `stat`, `types`, `typing`, `unicodedata`; `xml.parsers.expat` for `openscap.py` only), `ansible.module_utils` and this
  collection; star imports and `from os import` of anything but `path` fail. `os` is usable only as `os.path`. `exec`,
  `eval`, `compile` and `__import__` are banned. Attribute names `system`, `popen`, `run_command`, `Popen`,
  `import_module`, `create_subprocess_*`, `exec*`, `spawn*`, `fork*`, `posix_spawn*` and class-walking dunders are
  banned wherever they appear, as are the names `subprocess`, `pty`, `posix`, `_posixsubprocess`, `os` and `sys` as
  imported names, aliases or attributes (so re-exports such as `process.subprocess` fail), the whole `exec*` family
  including `fexecve`, the reflection helpers `vars`, `globals`, `locals`, `__dict__` and `get_type_hints`, and
  private `_create_*` internals. `getattr`, `setattr` and `delattr` need a literal permitted name. `shell=True`,
  `use_unsafe_shell` and the test-only keywords `owner_uid`, `policies` and `trusted_dirs` are banned in plugin code,
  so no module can weaken the ownership or trusted-directory checks. This is static analysis, not a sandbox; it makes bypasses deliberate and visible
  in review. The prefix rules over-approximate on purpose.
- Bandit runs twice (`make security`): on everything except `process.py` with no skips, so a `subprocess` use
  anywhere else is reported, and on `process.py` alone with only B404 and B603 skipped. Ruff S404 and S603 are
  ignored only for `process.py`. Both are justified in `pyproject.toml`.
- `ansible-test sanity` flags `subprocess.Popen` with `ansible-bad-function`, which recommends `run_command`; that has
  no timeout, output bound or process-group handling. The helper calls `subprocess.Popen` directly and the exception
  is declared honestly in `tests/sanity/ignore-2.20.txt` and `tests/sanity/ignore-2.21.txt`, each holding exactly
  `plugins/module_utils/compliance/process.py pylint:ansible-bad-function`. ansible-lint refuses that ignore
  (`sanity[cannot-ignore]`) and cannot be configured to allow it, so `.ansible-lint-ignore` skips that one rule for
  those two files, and is excluded from the built collection. This departs from the Ansible Automation Platform
  certification ignore policy, which the collection does not target. A repository test fails if the ignore files
  contain anything else.

## Amendment 2026-10-25: OpenSCAP backend (FREES-48)

The OpenSCAP backend (`plugins/module_utils/compliance/openscap.py`) is the first caller of the helper. It required
narrow policy changes; everything else is unchanged.

- `oscap` option allow-list: `--tailoring-file` was added so that an operator tailoring file can be passed to
  `oscap xccdf eval`. The sub-command prefixes, `FORBIDDEN_OPTIONS`, the forbidden words (`remediate`, `generate fix`)
  and the rule that every `-` argument must be allow-listed still apply, and a test asserts that the new entry opens
  no other option. The backend never passes `--remediate`, `--fetch-remote-resources` or `--report`.
- Import allow-list for `plugins/`: `xml.parsers.expat` is allowed **only in `plugins/module_utils/compliance/openscap.py`**
  (`EXTRA_IMPORTS` in `tools/lint/repo_rules/names.py`); every other plugin file that imports it fails the guard, which
  tests show for several paths. The XCCDF parser needs the expat parser object to turn off parameter entity parsing
  (`SetParamEntityParsing`) and to force UTF-8, which the high-level `ElementTree` parser does not expose. The parser does
  not import `xml.etree.ElementTree` at all: it never stores elements, so Bandit B405 and Ruff S405 do not apply and no
  suppression is needed. Other XML modules (`xml.dom`, `xml.sax`, `xml.etree.cElementTree`) stay denied.
- The test-only seams of `OpenScapBackend` and the parser, `runner`, `clock` and `limits`, join `owner_uid`, `policies`
  and `trusted_dirs` as keywords that the guard bans in every plugin file (`process.py` stays exempt). The backend defines
  them as parameters and never passes them as call keywords. A `**` dict splat in a call is banned everywhere under
  `plugins/`, because it could carry a banned keyword; no plugin code used one. The guard remains static analysis, not a
  sandbox. Guard gaps that predate this change (reassigning module constants, `__kwdefaults__`, `setattr` on modules) are
  tracked in FREES-125.
- Residual risk (N2): `read_results` calls `lstat` and then `open`, so a path swapped for a symlink or FIFO in between is
  followed. `O_NOFOLLOW` with `fstat` is not available under the `os.path`-only rule. The output directory is created by
  the backend, is mode 0700 and never reused, so only the same user or root could swap it.
- Known limitation (N4): options are allow-listed per executable, not per sub-command, so `oscap info --tailoring-file x`
  passes the policy. It is harmless today; a per-sub-command table is a follow-up if a second sub-command needs options.

## Amendment 2026-10-25: reflection and private-access bans (FREES-125)

FREES-125 closes the routes that the independent reviews of FREES-47 and FREES-48 left open. All rules apply under
`plugins/` outside `process.py`, and each has regression tests in `tests/unit/tools/test_check_repo_rules.py` (first round) and
`tests/unit/tools/test_check_repo_rules_hardening.py` (later rounds).

- String-based reflection: the attribute names `builtins`, `operator`, `eval`, `exec`, `compile`, `attrgetter`,
  `methodcaller`, `_evaluate` and `evaluate_forward_ref` are banned (also as imported or aliased names and as literal
  `getattr` names), and a module-level `__getattr__` is banned. This stops `typing.operator.attrgetter("os")(os.path)`,
  `dataclasses.builtins.eval(...)` and `typing.ForwardRef(...)._evaluate`.
- Function internals: `__kwdefaults__`, `__defaults__`, `__code__`, `__closure__` and `__globals__` are banned wherever
  they appear as attribute names.
- Imported modules are read-only: assigning, augmenting or deleting an attribute or item whose root is a name bound by
  an import statement, and `setattr` or `delattr` on such a name, are banned.
- Cross-module private access: any underscore-prefixed attribute may only be read, called or assigned through `self` or
  `cls`, the first parameter of an enclosing method in a class body (R-C below). `openscap._expat.ParserCreate()`,
  `openscap._parse_stream(...)` and `backend._runner = ...` fail, as do importing underscore-prefixed names or modules
  and `getattr` with an underscore-prefixed literal on another object.

### Second round: dunders, aliases and import-time policy (FREES-125 review)

The independent review of the first round showed that dunder methods bypassed every name-based ban
(`process.__getattribute__("subprocess").__getattribute__("Popen")` ran a shell, `process.__setattr__("ALLOWED_EXECUTABLES", ...)`
followed by `process.run(...)` succeeded) and that aliases of imported modules defeated the assignment ban. The guard is now
deny-by-default for these:

- Dunders (G1): reading `__name__`, `__qualname__`, `__doc__` and `__module__` is the only dunder attribute access that is
  allowed. Every other dunder attribute read, call, write or delete is banned (`__getattribute__`, `__setattr__`, `__delattr__`,
  `__self__`, `__class__`, `__dict__`, `__call__`, `__init_subclass__`), as are dunder names in `getattr` and `setattr`
  literals, imports of dunder names, and the names `__class__`, `__loader__` and `__spec__`. Dunder methods that a class
  defines remain allowed. The single exception is `object.__setattr__(self, "<literal>", value)` with exactly three
  positional arguments, `self` as the intact first parameter of the method, a literal field name that is not itself banned,
  and `__post_init__` as the directly enclosing function. `model.py` uses it to normalise frozen dataclass fields; its former
  `_store` helper was inlined for this reason.
- Frame and code introspection: the attribute names `currentframe`, `f_builtins`, `f_globals`, `f_locals`, `f_back`, `f_code`,
  `gi_frame`, `gi_code`, `cr_frame`, `cr_code`, `ag_frame`, `ag_code`, `tb_frame`, `tb_next`, `co_code`, `co_consts`,
  `co_names`, `CodeType`, `FunctionType`, `LambdaType` and `MethodType` are banned.
- `types`: only `from types import MappingProxyType` is allowed; `import types` and any other name fail.
- R-B, no module traversal: when an attribute chain is rooted at a name bound to a module, an attribute (and a
  `from m import name` name, and a literal `getattr` name on such a chain) that is the name of a standard library
  top-level module outside the import allow-list (`sys.stdlib_module_names`, so `dataclasses.inspect`, `enum.sys`,
  `pathlib.posixpath` and `pathlib.io` fail) or of a module of this collection (stems of `plugins/**/*.py`, so
  `scanner.process` fails) is banned. The rule is deliberately limited to module-rooted chains: an enumeration of the
  module-typed attributes of every allow-listed module found no route to a module that does not start at a module name,
  so ordinary attributes such as `{}.copy()`, `obj.time`, `other.scanner` and `error.code` stay allowed. The explicit
  frame, code and reflection names above stay banned on every object, and so do module aliases that are not module names:
  `bltns` (`enum.bltns` is `builtins`), `_bltin`, `stdlib_re` (`typing.stdlib_re` is `re`), `_os` and `_sys`.
- `super()`: only `super().__init__(...)` and `super().__post_init__()` (or the `super(Cls, self)` form with `self` or `cls`
  the intact first parameter) may call a dunder on `super()`. The allow-list (`SUPER_DUNDERS`) is the minimum plugin code
  needs, by least privilege: `__new__`, `__call__`, `__init_subclass__`, `__reduce__`, `__reduce_ex__`, `__getattr__`,
  `__get__`, `__set_name__`, `__repr__`, `__format__` and every other dunder on `super()` (including `__dict__`,
  `__class__`, `__getattribute__`, `__setattr__`, `__delattr__`) and any non-call use stay denied. The names `super` and
  `object` are protected builtins: any binding of them (assignment, augmented or annotated assignment, walrus, `for`,
  `with`, `except` and `match` targets, import-as, `def`, `class`, parameters, `global`, `nonlocal`, `del`) is banned, so
  the allowed forms cannot be turned into a dunder call on another object. No merged plugin module calls `super()`; widen
  the set only with a documented need. Reaching an allow-listed module through an attribute chain (for example
  `json.decoder.re`) grants no capability beyond importing it directly, so it stays allowed.
- Submodule values: a module-rooted attribute that is itself a module (`os.path`, `json.decoder`, `collections.abc`,
  `xml.parsers.expat`; computed at lint time from the dotted allow-list components and the module-typed attributes of each
  allow-listed module) may appear only as the base of another attribute access. `x = os.path`, `f(json.decoder)` and
  `return collections.abc` fail, which closes the gap where a stored submodule escaped R-A, the read-only rule and R-B.
  A from-import of such a name (`from json import decoder`, `from typing import functools`, also with `as`) binds a tracked
  module name, so R-A and R-B apply to it as well. The name sets are checked-in constants (`STDLIB_MODULE_NAMES`,
  `KNOWN_SUBMODULE_ATTRIBUTES` in `tools/lint/repo_rules/names.py`), the union over CPython 3.9 to 3.15, not values read from
  the controller interpreter, because plugins run on 3.9 to 3.14. A unit test asserts that the sets of the running
  interpreter are subsets, so a new Python release fails CI instead of opening a gap. The reflection names `evaluate`,
  `call_evaluate_function` and `annotationlib` (the 3.14 counterparts of `ForwardRef._evaluate`) are banned.
  `openscap.py` therefore imports `from xml.parsers import expat` (an import, so R-A applies to the name) instead of
  storing `xml.parsers.expat` in `_expat`; the per-file allowance names that exact form and no other `xml.parsers` name.
- R-A, module names are not values: a name bound by an import of a module (`import a.b`, `import a as b`, or `from pkg import
  mod` where `mod` is an allow-listed standard library module, a file or package of this collection, or a lower-case name
  imported straight from `ansible` or `ansible.module_utils`) may appear only as the base of an attribute access,
  `name.attribute`. Assignment, an argument, a return or yield, a container element, a comparison, a decorator argument, a
  default value, a walrus target, unpacking, `del`, and `global` or `nonlocal` declarations all fail.
- R-C, `self` is really `self`: `self` and `cls` are exempt from the private-attribute rule only when they are the first
  parameter of a method (not a `staticmethod`) and the method never rebinds, deletes or shadows the name by assignment,
  `for`, `with`, `except`, `import`, `match` capture, a nested `def`, `class` or `lambda` parameter, or `global` or
  `nonlocal`.
- Import-time policy binding (defence in depth): `process.py` builds `check_policy` and `run` in a factory (`bind_policy`)
  that deep-copies the allowed executables (each `ExecutablePolicy` is rebuilt with frozenset and tuple fields, so nothing
  shared with the public mapping is reachable), the trusted directories and the forbidden options, words and sequences into
  immutable structures held only in the closures. Rebinding `ALLOWED_EXECUTABLES`, `TRUSTED_DIRECTORIES` or the `FORBIDDEN_*` module globals after import
  has no effect on them, and a test proves that `run()` still refuses `sh` after those globals are monkeypatched.
- Plugin refactors needed to satisfy the bans without exempting any file: the `compile` ban removed `re.compile`, so the
  compliance modules keep patterns as string constants and call `re.fullmatch` and `re.search` (`_TOKEN` became
  `_IDENTIFIER_PATTERN` because Ruff S105 reads `_TOKEN` as a password); `OpenScapBackend._evaluate` became
  `_run_evaluation`; and the `_store` helper was inlined as `object.__setattr__(self, "<literal>", ...)` in each
  `__post_init__`, because the single permitted `__setattr__` form needs a literal field name. The public Python API is
  unchanged (`ScanRun.scanner` and `_Reader.array` keep their names).

- File-I/O helper reach (merged with ADR 0011): `fileio` may not be named as an attribute or as a literal `getattr` name in any
  plugin file except `ledger.py` (`ledger.fileio.open_directory(...)`, `getattr(ledger, "fileio")`, `compliance.fileio`), in
  addition to the existing import restriction. The permitted attributes of `fileio.py` (`FILE_IO_ATTRIBUTES`) are exempt from
  the submodule-value rule, so `os.stat(...)` keeps working there. The ledger and file-I/O helper replaced `re.compile` with
  string patterns for the same reason as the other compliance modules.

Accepted residual risk (lead architect): private state on objects stays reachable through an unbound method call such as
`C.f(obj)`, which writes `obj._runner` through the `self` of `f`. It grants no ability to execute anything: a runner cannot
weaken `process.run` (the `**` splat and the test-only keywords are banned and the policy is bound at import time), and
plugin code can already build any `ScanRun` directly. The guard remains static analysis, not a sandbox: it reviews syntax,
it does not track data flow, and independent security review stays required.

Unused allow-list entries, on `main` before this change and left in place: the dunder reads `__qualname__`, `__doc__` and
`__module__`, and the imports `collections` (bare), `functools`, `itertools` and `os.path`. No guarded plugin uses them
today; remove them if they stay unused.

## Amendment 2026-10-25: shared XML helper (FREES-42)

- Import allow-list for `plugins/`: `xml.parsers.expat` is now allowed in exactly two files,
  `plugins/module_utils/compliance/openscap.py` and `plugins/module_utils/compliance/xmlsafe.py` (`EXTRA_IMPORTS` in
  `tools/lint/repo_rules/names.py`). `xmlsafe.py` holds the same layered defences as the XCCDF results parser (byte
  scan for DOCTYPE and ENTITY, UTF-8 forced, parameter entities off, element and depth bounds, no stored elements) as a
  public API, so that `catalog.py` and later parsers use it without importing private names of `openscap.py`. Every
  other plugin file that imports expat still fails the guard, and a test shows it for several paths. `openscap.py`
  keeps its own copy of the parser for now; moving it onto `xmlsafe.py` is a follow-up.
- The public bounds parameter of `xmlsafe` is named `bounds`, because `limits` stays banned as a call keyword.

## Amendment 2026-10-25: one XML parser (FREES-126)

- Import allow-list for `plugins/`: `xml.parsers.expat` is allowed in exactly one file,
  `plugins/module_utils/compliance/xmlsafe.py` (`EXTRA_IMPORTS` in `tools/lint/repo_rules/names.py`), in the form
  `from xml.parsers import expat`. `plugins/module_utils/compliance/openscap.py` has lost the allowance that FREES-48
  gave it and fails the guard if it imports expat in any form, as does every other plugin file; tests in
  `tests/unit/tools/test_check_repo_rules.py` show this for `openscap.py` and several other paths. The guard tests that
  exercise the allowed file (`EXPAT_FILE` in `tests/unit/tools/test_check_repo_rules_hardening.py`) now name
  `xmlsafe.py`.
- `openscap.py` contains no XML parsing code. Its results parser is an event receiver for `xmlsafe.parse_chunks` (files,
  through `xmlsafe.open_regular` and `xmlsafe.iter_handle_chunks`) and `xmlsafe.parse_text` (text), and keeps only the
  XCCDF semantics: the namespace checks, the leaf-element and mixed-content rules, and the extraction. It passes its
  bounds (`XmlLimits`, default 2,000,000 elements and depth 64, now taken from `xmlsafe`) and re-raises `xmlsafe.XmlSafetyError` as
  `XccdfParseError` with the same message, so the public API and every message are unchanged. An `OSError` raised when the results handle is closed, the
  only file operation outside `xmlsafe`, becomes "the results file cannot be read: ..." as before (independent review
  of PR #16).
- `xmlsafe.py` gained only what the move needed, and nothing weaker: `parse_text` (UTF-8 encoding of a text document,
  then `parse_chunks`, so every check applies) and a keyword-only `subject` for `open_regular`, `iter_handle_chunks`
  and `iter_file_chunks`, which only changes the wording of error messages ("the results file" instead of "the file").
  The size bounds, the DOCTYPE, ENTITY, NUL, UTF-16 and UTF-32 rejection, the expat settings and the element and depth
  bounds are the code that both parsers already had in identical form.
- The one property in which the two parsers differed was the default element bound: 2,000,000 in `openscap.py` and
  5,000,000 in `xmlsafe.py`. The stricter value is now the `xmlsafe` default, so datastreams parsed by `catalog.py` are
  bounded at 2,000,000 elements too. The pinned datastreams have 154,758 (RHEL 9) and 69,788 (Ubuntu 24.04) elements,
  and `make test-content-golden` still passes.
- `subject` is not a test seam and not a banned keyword; it cannot change what is accepted. No new exemption was added
  to the guard.
- A differential test (`tests/unit/plugins/module_utils/compliance/test_openscap_differential.py`) compares the parser
  with expected data generated from the old parser on `main` at `fdc788c` for every XML fixture, both entry points,
  element, depth and size bounds, small read chunks and the symlink, directory, missing and empty cases. The test file
  passes unchanged against both implementations.

## Amendment 2026-10-25: no raw expat through `xmlsafe` (FREES-131)

The independent review of PR #16 (FREES-126) found that raw expat was still reachable from every plugin file. The guard
derived the names `parsers` and `expat` from the dotted `EXTRA_IMPORTS` entry `xml.parsers.expat` and treated them like
the submodules of the global allow-list, so they only had to be the base of an attribute access. As a result,
`xmlsafe.expat.ParserCreate()` and `from .xmlsafe import expat` passed the guard in any plugin file and gave a raw expat
parser with no declaration scan, no bounds and no reject handlers.

- Reserved names: the components of an `EXTRA_IMPORTS` name that no allow-listed import provides (today `parsers` and
  `expat`, `RESERVED_ATTRIBUTES` in `tools/lint/repo_rules/names.py`) may be used only in the file that owns the entry,
  `plugins/module_utils/compliance/xmlsafe.py`. In every other plugin file, they are banned:
  - as an attribute name on any object, whether read, called, stored or deleted (`xmlsafe.expat.ParserCreate()`,
    `x = xmlsafe.expat`, `xmlsafe.parsers.expat`, `obj.expat`);
  - as a literal `getattr`, `setattr` or `delattr` name (`getattr(xmlsafe, "expat")`);
  - as a keyword of a `match` class pattern (`case object(expat=e)`);
  - as an imported name or a component of an import path (`from .xmlsafe import expat`,
    `from <collection>.xmlsafe.expat import ParserCreate`, `import <collection>.xmlsafe.expat as e`).

  The message names the owning file. `SUBMODULE_ATTRIBUTES` still contains both names, so in `xmlsafe.py` itself the
  submodule-value rule still applies and `x = xml.parsers.expat` and `x = expat` stay denied. The global names
  (`SHARED_SUBMODULE_ATTRIBUTES`: `path`, `abc`, `decoder` and the others) are unchanged. No rule was weakened and no
  exemption was added. Regression tests in `tests/unit/tools/test_check_repo_rules_hardening.py` cover 20 forms in
  `openscap.py`, `catalog.py`, the three modules under `plugins/modules/`, other `module_utils` files and an action
  plugin, and show that `xmlsafe.py` keeps the forms it uses. The `match` and `getattr` forms on a module name were
  already denied by R-A; the new rule also covers them on other objects.
- Close errors in one place: `xmlsafe.RegularFile(path, max_bytes, *, subject="")` is a context manager that opens
  through `open_regular` and closes the handle on exit. An `OSError` from the close becomes `xmlsafe.CloseError`, an
  `XmlSafetyError` with the read-error wording ("the file cannot be read: ...", "the results file ..." with
  `subject="results"`), the `OSError` as its cause and as `os_error`. An error raised in the block wins over a
  failing close, so a digest mismatch or a parse error is reported as such. `iter_file_chunks`, `catalog.verify_digest`,
  `catalog.read_benchmarks` and `openscap.read_results` use it. Before this change, a failing close in the two catalog
  functions surfaced as a bare `OSError`, so `benchmark_info` and `profile_info` failed with a traceback instead of
  `CatalogError` (`invalid_content`). It is now a `CatalogError` with the read-error message. `openscap.read_results`
  no longer handles `OSError` itself. It maps `CloseError` to `XccdfParseError` with the same message and keeps the
  `OSError` as the cause, as PR #16 established.

## Amendment 2026-10-26: generated name sets and allow-list cleanup (FREES-129)

Non-blocking follow-ups from the final review of PR #11 (FREES-125) and the reviews of PR #20 (FREES-131) and PR #17
(FREES-49). Every change tightens the guard; none adds an exemption.

- Generated name sets (regeneration note): `STDLIB_MODULE_NAMES` and `KNOWN_SUBMODULE_ATTRIBUTES` stay checked-in
  constants in `tools/lint/repo_rules/names.py`, but they are now generated. `tools/lint/name_set_probe.py` (standard
  library only, Python 3.9 syntax) runs in a clean interpreter, `python -I -S`, so neither the test session nor a `.pth`
  file of a virtual environment can add to or hide from the result; it imports every probed module first and then
  reads each module-typed attribute with `getattr`, which also resolves `lazy import` bindings of Python 3.15
  (`pathlib.shutil`). Python 3.9 has no `sys.stdlib_module_names`, so the probe enumerates the built-in modules, the
  standard library directories and `lib-dynload` there. Platform-specific names are normalised:
  `_sysconfigdata__linux_x86_64-linux-gnu` and every other `_sysconfigdata_*` name become `_sysconfigdata`. That entry
  replaces the platform name in the set; the old name contains `-`, so it could never be an attribute, and an
  underscore-prefixed `getattr` literal on another object is banned anyway. `tools/lint/generate_name_sets.py` keeps the
  probe output per version in `tools/lint/name_sets.json` (3.9.25, 3.10.21, 3.11.16, 3.12.14, 3.13.15 and 3.14.6 from
  `uv`, and 3.15.1) and writes the union into the guard. Regenerate with `make name-sets` after changing the import
  allow-list or when a Python release adds names; `python -m tools.lint.generate_name_sets --check` reports drift.
- The probed modules are the import allow-list, every parent package of a dotted entry (`collections` for
  `collections.abc`, `os` for `os.path`, because `import collections.abc` binds `collections`) and the per-file extra
  imports without their parents (their components `parsers` and `expat` stay reserved for `xmlsafe.py`, FREES-131).
  Compared with the hand-written sets, the generated ones add `_ctypes_test` and `_sysconfigdata` (module names) and
  `path` and `st` (attributes of `os`) and drop only the platform-specific `_sysconfigdata__linux_x86_64-linux-gnu`.
- Independence from interpreter state: the subset test no longer reads `vars()` of modules in the test process, where
  an `import json.tool` anywhere would have added `tool` and failed the test. `tests/unit/tools/test_name_sets.py` runs
  the probe in a subprocess and asserts that the probed sets are subsets of the constants and, when the interpreter is
  the release a snapshot was recorded on, that the generator reproduces that snapshot exactly. The CI job `name-sets`
  runs it on each pinned release from 3.9.25 to 3.14.6 (`fail-fast: false`) and `ci-gate` needs it; the `test` job runs
  it on the project interpreter. A test pins the matrix to the recorded releases.
- Allow-list cleanup: the import allow-list no longer contains `collections` (bare), `functools` and `itertools`, and
  the only dunder read left is `__name__` (`__qualname__`, `__doc__` and `__module__` were removed). No plugin file on
  `main` used them, including `audit.py` and `compliance_scan.py` from PR #17 (FREES-49), and the open PR #18 adds no
  use. They are now denied, and `functools` and `itertools` are also banned as module-rooted attributes
  (`typing.functools`). `os.path` is kept: `audit.py` (PR #17) uses `os.path.normpath` and `os.path.commonpath`, and
  the `os`-only-as-`os.path` rule and the file-I/O helper rules are built on it.
- Test seams: `registry` (the backend registry seam of `audit.Auditor`, PR #17) joins `BANNED_KEYWORDS`, and the
  `Auditor` docstring names it with `owner_uid` and `clock`. A review of
  every keyword-only parameter in `plugins/` found no other unbanned seam; the remaining keyword-only parameters
  (`accept`, `create`, `default`, `dry_run`, `max_length`, `multiline`, `pattern`, `replace`, `reveal`, `sensitive`,
  `subject`, `write`, and `final` and `check_mode` from `audit.py`) are production arguments, and so are the
  keyword-only parameters that the open PR #18 adds (`required`, `max_scan_lag`, `has_content`, `breaks`,
  `final_newline`, `nested_sequence`), which were reviewed here so that it needs no classification change. `tests/unit/tools/test_check_repo_rules_followups.py` now fails for any
  keyword-only plugin parameter that is neither a banned seam nor on that reviewed list, so a new seam cannot be added
  without a decision.
- `xmlsafe.open_regular` is private (`_open_regular`). Only `RegularFile` (and through it `iter_file_chunks`) calls
  it, so a future plugin cannot open a file in a way that lets a close-time `OSError` escape as a bare `OSError`.
  `audit.copy_content` (PR #17) was the one caller outside `xmlsafe.py` and now opens the datastream through
  `RegularFile`: a failing close of the source is a `CloseError`, reported as `invalid_content` like every other read
  failure of the source, instead of `evidence_write_failed`, and a unit test covers it. The
  existing rules enforce this: an underscore-prefixed attribute of another module and an import of an
  underscore-prefixed name fail the guard, which tests show for five plugin paths.

## Amendment 2026-10-26: keyword-only seams, include targets and role names (FREES-137)

Non-blocking follow-ups from the review of PR #21 (FREES-128, FREES-129). Every change tightens the guard.

- Positional seams: several functions took a test seam positionally (`process.resolve_executable(name, search_dirs,
  owner_uid)`, `fileio.open_directory(path, owner_uid)`, `audit.plan(job, owner_uid)`, `audit.inspect_output_root`,
  `catalog.vetted_content_path(path, owner_uid)` from PR #29, `openscap.parse_results` and `read_results` with
  `limits`, and private helpers), so
  plugin code could pass a weaker value without naming the banned keyword. Every seam is now keyword-only, with the
  production value as the default of the public functions. `search_dirs` was the trusted-directory seam under another
  name and is now `trusted_dirs`, which the guard bans; `check_policy` takes `policies` keyword-only and defaults to
  the policy bound at import. `openscap.register` names its argument `target`, because the registry it fills is the
  production registry, not the `registry` seam of `audit.Auditor`. In `catalog.vetted_content_path` the owner is a
  production value for the discover modules (the effective user), so an omitted `owner_uid` now means
  `catalog.effective_uid()` and `benchmark_report` and `profile_report` omit it; the audit forwards its own seam,
  root in production.
- Guard: a function or lambda parameter named like a banned keyword must be keyword-only everywhere under `plugins/`,
  and only the files in `SEAM_OWNERS` may define one (`audit.py`: `owner_uid`, `registry`, `clock`; `catalog.py` and
  `fileio.py`: `owner_uid`; `ledger.py`: `state_dir`, `owner_uid`, `lock_timeout`; `openscap.py`: `runner`, `clock`, `limits`).
  Because a keyword-only seam can only be set by keyword, the owners need to forward their seams; a banned keyword in
  a call is accepted only in its owner and only unchanged: `name=name` where `name` is a never rebound keyword-only
  parameter of the enclosing function or lambda, or `name=self._name` where `self` is the intact first parameter of a
  method of a class whose `__init__` takes `name` keyword-only. Literals, expressions, other names, other objects and
  `cls` are refused.
- Reserved seam attributes (review of PR #30): `_<name>` for every banned keyword (`_owner_uid`, `_registry`,
  `_clock`, `_runner`, `_limits`, `_state_dir`, `_lock_timeout`, `_policies`, `_trusted_dirs`, `_use_unsafe_shell`)
  is reserved for the files that own the seam. Before, a non-owner plugin could set the seam of an owner object with
  `self._owner_uid = 1000` in a subclass of `audit.Auditor`, with a class attribute `_owner_uid = 1000` of such a
  subclass, or with `C.f(audit.Auditor())` where `C.f` assigns `self._owner_uid`, because the attribute counted only
  as its own private attribute; `Auditor` reads `self._owner_uid` at run time, so the root-owner check was undone.
  Now every other file may not name a reserved attribute at all: no read, store or delete through any object, no
  `getattr`, `setattr` or `delattr` literal, no `object.__setattr__` literal and no `match` class pattern keyword. No
  file, the owners included, may bind a reserved name in a class body (an assignment, an annotation, a method or a
  nested class of that name). An owner may read its own seam attributes and may store or delete them only on `self`
  inside `__init__`; `setattr`, `delattr` and `object.__setattr__` may not name them. Subclassing an owner class
  outside its module is not denied: with the reserved names a subclass cannot read or set a seam, cannot pass a seam
  keyword and cannot reach the private helpers, so it gains nothing a plain plugin lacks, and a base-class check would
  be unsound anyway because the base can be any expression (`base = audit.Auditor`). The defaults of the seams and the
  value that `__init__` stores from its keyword-only parameter remain review items of the owner files; the
  class-attribute gap is closed. `process.py` stays exempt; the classification test in
  `tests/unit/tools/test_check_repo_rules_followups.py` now also fails for any positional parameter under `plugins/`,
  `process.py` included, whose name is a banned keyword. `fileio.open_directory` is still importable only by
  `ledger.py`, which forwards `owner_uid=self._owner_uid`. The `remediation_*` filters of PR #22 and the audit code
  define no seam and pass unchanged apart from the keyword-only calls.
- Include targets: an include or import target and `tasks_from`/`handlers_from` must be a relative YAML path without
  a `..` component that is not templated and does not start with `/` or `~`. `..` is refused even when it would stay
  inside the repository, because a role installed from the collection is resolved against paths of the consuming
  playbook too. The one templated form is `{{ role_path }}/tasks/` followed by a literal relative path, so no variable
  chooses an included file anywhere. The first version of this PR also allowed one pinned dispatch variable,
  `__linux_compliance_remediate_family.name`, validated by the `remediation_plan` filter; the review showed that a
  role parameter, an include parameter or an extra variable outranks the plan fact the role sets, so a play could
  pass a plan with a family named `../x` and load a file outside the role. The remediate role now dispatches with one
  static include of the literal `{{ role_path }}/tasks/<family>.yml` per catalogued family, gated on that family's
  plan entry, in `roles/remediate/tasks/dispatch.yml`, which `tools/roles/generate_role_guards.py` generates from the
  registry (`make role-guards`; `make lint-role-guards` fails on drift). A test playbook that chose a helper with
  `tasks_from: "file_permissions_{{ case.helper }}.yml"` now uses one static include per helper.
- Internal role variables (review of PR #30): the same precedence lets a role parameter, an include parameter or an
  extra variable replace any internal `__linux_compliance_<role>_*` fact, and a play's `set_fact` replace a constant
  that a role loads with `include_vars`. Every entry point of the audit, remediate and verify roles (remediate
  `main`; audit `main`, `evaluate`, `stale`; verify `main`, `baseline`, `preflight`) now starts with the generated
  `tasks/internal_variables.yml`: it sets every fact and registered variable of the role to a sentinel and asserts
  that each reads back as the sentinel, gives every task and loop variable the sentinel as a task variable of the
  assertion and asserts the same, and asserts that every constant from the role's variable files is undefined or
  equal to the file. Anything else was supplied from outside, and the role stops before it scans, changes or compares
  anything. This follows the read-back pattern with which the verify role already refuses an `-e` baseline. A role
  parameter that is not in the argument specification is already refused by Ansible's argument validation, and the
  `vars` of a `roles` entry rank below the facts the role sets; `make test-role-guards` covers the include
  parameters of every entry point, the extra variables and the role parameters. Residual: a caller that includes a
  family file directly with `tasks_from` and include parameters can still drive it, but only with
  `linux_compliance_remediate_enabled: true` and only into the literal helper files of the role, which is no more than
  calling the native modules itself.
- Symlinks are not resolved by the YAML check. A repository test fails when a symlink below the repository resolves
  outside it or is a symlinked directory other than `.claude/skills`, so a symlinked `roles/*/tasks` cannot hide
  content from the guard; the tracked symlinks are `.claude/skills` and a remediate test fixture file.
- Role names of role includes and of the `roles` of a play must be plain or fully qualified names; templated names
  and paths are refused, and a free-form role include may not be templated. A templated task key is refused as
  defence in depth.
- Python 3.15 is not added to the `name-sets` CI matrix. Plugins run on managed nodes with Python 3.9 to 3.14, the
  target range of the supported ansible-core 2.20 and 2.21 (`MANAGED_NODE_PYTHONS` in the `Makefile`); 3.15 becomes a
  target only with ansible-core 2.22, which is not released. The guard name sets already include the 3.15.1 probe
  (FREES-129). Add 3.15 to the matrix and to `MANAGED_NODE_PYTHONS` when the collection adopts ansible-core 2.22.
- The guard module grew past 1500 lines. `max-module-lines` stays 1500; `make lint-pylint` excludes the guard from
  the main pass and lints it alone with `--max-module-lines=1700`, with the reason in `pyproject.toml`, because the
  guard is run by path as one stand-alone script and Pylint has no per-file limit without a comment. A unit test pins
  both limits and fails when any other module exceeds 1500 lines.

## Amendment 2026-10-26: the guard is a package (FREES-141)

- The repository guard is split into the package `tools/lint/repo_rules/`, one module per rule group, because the
  single module had reached its 1700-line limit. The change is behaviour-identical: no rule, message, order or exit
  status changed and coverage stays at 100%. Every existing guard test passes unchanged except one meta-test: the
  test that pinned the 1700-line exception was replaced by `test_no_module_exceeds_the_module_line_limit`. One
  meta-test was added, `test_the_repository_guard_is_a_package_of_small_modules`.
  - `common.py`: `Violation`, `REPO_ROOT` and the file suffixes.
  - `yaml_text.py`: the document-start marker and the YAML comment ban (ADR 0005).
  - `ansible_tasks.py`: banned command modules, task keys, includes, role entry points and role names.
  - `names.py`: every name set of the Python rules, including `ALLOWED_IMPORTS`, `EXTRA_IMPORTS`, `FILE_IO_HELPER`,
    `FILE_IO_ATTRIBUTES`, `BANNED_KEYWORDS`, `SEAM_OWNERS`, `RESERVED_ATTRIBUTES` and the generated
    `STDLIB_MODULE_NAMES` and `KNOWN_SUBMODULE_ATTRIBUTES`. The earlier amendments and ADR 0011 name this file
    inline where they cite these constants (FREES-153); `make name-sets` rewrites it.
  - `python_scope.py`: the per-file facts (`Scope`) and binding helpers that the Python rules share.
  - `imports.py`, `seams.py` and `attributes.py`: the import, test seam, and name, attribute and call rules.
  - `isolation.py`: `check_process_isolation`, which applies the Python rules to one plugin file.
  - `repository.py`: `check_file` and `check_paths`, which select the rules by suffix and location.
- `tools/lint/check_repo_rules.py` stays the command-line entry point with the same arguments, output and exit
  status, still run by path from `make lint-repo` and pre-commit. It keeps the rule summary as its module
  documentation, re-exports the public names, and puts the repository root on `sys.path` only when it runs by path.
- The per-file Pylint exception of the previous amendment is removed. Every guard module is below 600 lines,
  `make lint-pylint` lints the package in its main pass with the global `max-module-lines` of 1500, and a unit test
  fails when any module exceeds 1500 lines.

## Amendment 2026-10-26: guard and role-guard follow-ups (FREES-153)

The behaviour-changing items left over from FREES-141 and the non-blocking findings of its review. Each tightens a
rule; none adds an exemption, and no lint limit was raised.

- Seam storage (`tools/lint/repo_rules/seams.py`): an owner file may store or delete its seam attribute only directly
  in the body of `__init__`. A store from a function or `async` function nested in `__init__`, at any depth, is
  refused with the existing message, because such a function can run after construction and replace the seam.
- Compiled modules (`COMPILED_MODULE_SUFFIXES` in `tools/lint/repo_rules/common.py`, which `check_file` in
  `repository.py` tests first): a file ending in `.so`, `.pyd`, `.pyc`, `.pyo` or `.fwork`, in any case and
  with any ABI tag (`.cpython-312-x86_64-linux-gnu.so`, `.abi3.so`, `.cp312-win_amd64.pyd`), is refused anywhere in
  the repository without being read. The import system loads an extension module or bytecode before, or instead of,
  a `.py` source of the same name, so such a file would run code that no rule has seen. The suffixes cover every
  entry of `importlib.machinery.EXTENSION_SUFFIXES` and `BYTECODE_SUFFIXES`, the Windows `.pyd` forms and the
  `.fwork` files of the Apple framework loader, which a unit test checks against the running interpreter.
  `make lint-repo` passes these suffixes to the guard with case-insensitive pathspecs, and the pre-commit hook matches
  them as well; the existing `git ls-files` check for `__pycache__` and `.py[cod]` stays.
- Package size: the test that keeps every guard module below 600 lines walks the package with `rglob`, so a module in
  a subpackage is covered; a test shows it with a 601-line module in a subpackage.
- Internal role variables, second read-back: a value supplied from outside a role is fixed for the run, so a forged
  value equal to the sentinel string `__linux_compliance_unset__` passed the read-back of FREES-137. The generated
  guard now resets the facts to a second sentinel, `__linux_compliance_unset_again__`, reads every fact and task
  variable back again, and resets the facts to the first sentinel. A forged value cannot equal both, so the sentinel
  string is refused by the second read-back, through `-e`, include parameters and the task variables alike, as long
  as the value is fixed. Residual, widened by FREES-157: an extra variable, an include parameter and a role parameter
  are all templated per task, so a template that evaluates differently per task could still pass both read-backs.
  FREES-157 adds a name-based parameter check and a run-start check for the shipped playbooks; see its amendment.
- Internal role variables, type checks: the key facts of each guarded role are checked for their type and shape in
  the task right after the role sets them, so a replaced value is refused before it is used even if a read-back were
  passed: remediate (toggle names, plan, results, the dispatched flag), audit (toggle names, toggle resolution, the
  exceptions evaluation), verify (comparison, the dispatched flag) and evidence (output directory, bundle plan).
  `tests/unit/roles/test_role_type_checks.py` fails when such a `set_fact` is not followed by its check.
- Guarded roles: the evidence role names `__linux_compliance_evidence_*` variables, including the controller output
  directory, but was not guarded. It is now in `GUARDED_ROLES`, and its entry points `main.yml` and `summary.yml`
  import the generated guard. `tools/roles/generate_role_guards.py` fails when a role below `roles/` names an internal
  variable of its own and is not guarded, and a unit test checks the same against the repository.

## Amendment 2026-10-26: every location from which Ansible loads code (FREES-156)

The independent review of FREES-153 showed that the deny-by-default rules saw only Python under `plugins/`. A
`roles/remediate/library/sneaky.py` that calls `getattr(__import__("o"+"s"), "sys"+"tem")("true")` passed the guard,
Ruff, Bandit, ansible-lint and the unit tests, and so did an executable shell module in `plugins/modules` or
`roles/*/library`. The guard now knows where Ansible loads code from and what may live there.

**Load locations, checked against ansible-core 2.21.5.** For every playbook directory (`ansible/cli/playbook.py`,
`ansible/playbook/__init__.py`) and every role (`ansible/playbook/role/__init__.py`) Ansible calls
`add_all_plugin_dirs`, which adds the `subdir` of every plugin loader: `library`, `module_utils`, `doc_fragments`
and `action_plugins`, `become_plugins`, `cache_plugins`, `callback_plugins`, `cliconf_plugins`, `connection_plugins`,
`filter_plugins`, `httpapi_plugins`, `inventory_plugins`, `lookup_plugins`, `netconf_plugins`, `shell_plugins`,
`strategy_plugins`, `terminal_plugins`, `test_plugins` and `vars_plugins`. The shell loader also searches the
relative path `shell_plugins` from the working directory. The collection finder searches `collections/` next to every
playbook and every configured collection path for `ansible_collections/`, and the default plugin paths are
`plugins/<type>` below `ANSIBLE_HOME`. Molecule 26.10 adds no module or plugin path of its own; its scenario playbooks
are ordinary playbook directories. `ansible.cfg` and `ANSIBLE_*` variables add `library`, `module_utils`, the
`*_plugins` paths, `roles_path`, `collections_path`, `home` and `playbook_dir`. No `ansible.cfg` is tracked, and
the `Makefile` sets only `ANSIBLE_HOME` and `ANSIBLE_COLLECTIONS_PATH`, both below the untracked `build/`.
`tests/unit/tools/test_check_repo_rules_load_inventory.py` reads these facts from the installed ansible-core, so a
release that adds a loader or a search-path setting fails the tests.

**Policy.** The collection's code lives in the repository's own `plugins/`, as Python source, under the strict
rules. Nothing tracked had to live in another load location, so no file there needed the full rules as an exemption.

- A directory named like a load location (`LOAD_DIRECTORY_NAMES`, or ending in `PLUGIN_DIRECTORY_SUFFIX`, in
  `tools/lint/repo_rules/load_locations.py`) anywhere outside the root `plugins/` is a load location, wherever it is:
  a role, `playbooks/`, a Molecule scenario or `shared/`, `tests/playbooks/`, an integration target or the repository
  root. Every file in it is refused, and a Python file there also gets the full deny-by-default rules, so the reviewed
  module reports `use of __import__` and the computed `getattr` as well. `importlib.import_module` with a computed
  name and `getattr` on a module with a computed name were already refused by those rules, which a test shows in
  every location.
- The unit tests and stubs that mirror the collection layout are not load locations (`NON_LOADING_DIRECTORIES` in
  `tools/lint/repo_rules/load_locations.py`), because no playbook or role can sit next to them: their trees
  (`PYTHON_ONLY_TREES` in `tools/lint/repo_rules/load_locations.py`) may hold only `.py` and `.pyi` files. A load
  directory nested deeper inside them is still refused.
- Every file under `plugins/` must end in `.py`, so an extensionless module, a `.sh`, `.ps1`, `.psm1` or `.cs` file
  and a module documentation sidecar are refused. Ansible runs a module as new-style Python only if it matches its
  `NEW_STYLE_PYTHON_MODULE_RE` and has no control byte in its header; otherwise it runs the file as a binary or through
  its shebang, and a file without a shebang through the shell. A `.py` file that is both valid Python and a shell
  script therefore passed every rule. A file in `plugins/modules` must now match the same pattern
  (`NEW_STYLE_MODULE` in `tools/lint/repo_rules/load_locations.py`, compared with ansible-core's by a test) and contain
  no control byte (`TEXT_BYTES` in `tools/lint/repo_rules/load_locations.py`), and a Python file anywhere may only
  have a Python shebang (`PYTHON_SHEBANGS` in `tools/lint/repo_rules/load_locations.py`).
- A symbolic link is refused unless it is listed (`SYMLINK_ALLOW_LIST` in `tools/lint/repo_rules/load_locations.py`:
  `.claude/skills` and the remediation test fixture). The guard placed a file by its resolved path, so a
  `plugins/modules/x.py` link to `tools/x.py` was checked as tools code; a link named like a load directory would load
  a whole directory that no rule sees. Neither the guard nor Ansible now follows a link that is not listed.
- An executable file is refused outside `tools/**/*.sh` (`EXECUTABLE_ALLOW_LIST` in
  `tools/lint/repo_rules/load_locations.py`), because Ansible runs an executable inventory, vault password file or
  module directly.
- `ansible.cfg` may not set any of the search-path settings (`CONFIG_PATH_SETTINGS` in
  `tools/lint/repo_rules/load_config.py`), and a file in a directory that a module or plugin setting names is refused as
  a load location; the guard reads the `ansible.cfg` at the root, every one passed to it and every one in a directory
  between the root and a checked file. The same settings are refused as keys of `molecule.yml`. The matching
  environment variables and `ANSIBLE_CONFIG` (`PATH_ENVIRONMENT_VARIABLES` in `tools/lint/repo_rules/load_config.py`)
  are refused as YAML keys anywhere, in the values of workflows, actions and `molecule.yml`, in makefiles and in shell
  scripts, and so are `--module-path` and `-M`. Only a makefile may set `ANSIBLE_HOME` and `ANSIBLE_COLLECTIONS_PATH`
  (`MAKE_ENVIRONMENT_VARIABLES` in `tools/lint/repo_rules/load_config.py`), which an existing test pins to `build/`.

**Wiring.** `make lint-repo` passes every tracked and new file to the guard, without a suffix pathspec, so
extensionless files, symbolic links and executables are seen; the case-insensitive compiled-module pathspecs of
FREES-153 are no longer needed and were removed. The pre-commit hook passes every file and symbolic link
(`types: []` to clear the default `[file]`, which would drop symbolic links, `types_or: [file, symlink]` and no
`files` filter). Unit tests pin both.

**Changed tests.** The generic plugin file of the existing guard tests moved from `plugins/modules/other.py` to
`plugins/module_utils/other.py`, because a module now must import `module_utils`; the deny-by-default rules are the
same in both. `test_code_outside_plugins_is_out_of_scope` no longer lists `tests/plugins/x.py`, which is now a load
location, and `test_a_plugins_directory_below_the_root_is_a_load_location` shows it. The expat test imports
`ansible.module_utils.basic` so that its two `plugins/modules` cases stay new-style modules.

**Residuals.** The guard does not interpret Python that starts Ansible itself, such as a test that runs
`ansible-playbook` with its own environment; such code is controller-side test or tool code and is reviewed as such.
It reads `ansible.cfg` only inside the repository; a configuration outside it, or an `ANSIBLE_CONFIG` set by the
operator, is outside the repository's control. Ansible reads `ansible.cfg` only from the working directory,
`ANSIBLE_CONFIG`, `~/.ansible.cfg` and `/etc/ansible`; the guard's search of the directories between the root and a
checked file is a superset of the first.

**Review of PR #42.** The independent review requested these changes, which are part of the same amendment:

- **Case-insensitive filesystems.** `add_all_plugin_dirs` joins the loader's `subdir` to the path and calls
  `os.path.isdir`, which ignores case on APFS, the macOS default, and on Windows. So `roles/remediate/Library/`,
  `Filter_Plugins/` and `playbooks/LIBRARY/` are load directories on such a controller, and `roles/` ships in the
  collection. The guard now compares case-folded names: `is_load_directory_name`, the directories that an
  `ansible.cfg` names, the root `plugins` component for the `.py`-only rule, `plugins/modules` for the new-style rule,
  the trees that may hold only Python (`folded` in `tools/lint/repo_rules/load_locations.py`), and the file names
  `ansible.cfg`, `molecule.yml`, the makefiles and the navigator settings files. A case variant of the root `plugins`
  directory (`Plugins/`) is not the collection's own and is refused as a load location. The exemptions match exactly,
  so `tests/unit/plugins/Module_Utils/` and a case variant of a listed symbolic link or of `tools/` are not exempt.
- **Index modes.** A file whose Git index mode is executable (`100755`) or a symbolic link (`120000`) is refused even
  if the working tree disagrees, for example after a `--no-verify` commit or on a checkout with `core.fileMode=false`
  or `core.symlinks=false` (`GIT_EXECUTABLE_MODE` and `GIT_SYMLINK_MODE` in `tools/lint/repo_rules/load_locations.py`).
  `make lint-repo` writes `git ls-files -s -z` to `build/lint-repo-index-modes` and passes it to the guard with
  `--index-modes`, because the guard itself runs no process. The pre-commit hook needs no listing, because pre-commit
  stashes unstaged changes, so the working tree matches the index.
- **Deny-by-default in load directories.** The claim stands and is now tested. The second copy of the check in
  `is_process_scope` was redundant, which is why removing it failed no test. It was removed, so
  `is_process_scope` again means plugin code only, and `check_file` applies the rules to every Python file in a load
  location. Disabling that branch fails 256 tests, which assert the `__import__`, `getattr` and `os.system` findings
  in every location.
- **Search paths in other configuration files.** Environment files (`.env`, `.envrc`, `.env.*`, `*.env`) and `.ini`,
  `.toml` and `.cfg` files, such as `tox.ini` with `setenv` or `pyproject.toml`, are scanned for the search-path
  environment variables and `--module-path`, as makefiles and shell scripts are (`ENVIRONMENT_TEXT_SUFFIXES` in
  `tools/lint/repo_rules/load_config.py`). An ansible-navigator settings file (`NAVIGATOR_FILE_NAMES` in
  `tools/lint/repo_rules/load_config.py`) may set `ansible.config.path` only to a file named `ansible.cfg`, which the
  guard parses.
- **Ticketed separately, out of scope here:** the `ansible.builtin.expect` module and the `pipe` and `lines` lookups,
  the interpreter and SSH argument variables, pinning of `galaxy.yml` dependencies and `requirements.yml`, and
  configuration settings that run code without adding a search path (`jinja2_extensions`, `vault_password_file`,
  `become_exe`, `ssh_executable`, `ssh_args`, `interpreter_python`).

## Amendment 2026-10-26: the SCC command line (FREES-145)

The SCC backend of [ADR 0019](0019-scc-scanner-backend-and-ci-image.md) is the second caller of the helper. It runs
an executable that is not in a trusted directory, so the policy model gains three fields. Every existing policy
leaves them empty and behaves as before.

- `ExecutablePolicy.fixed_path`: the one absolute path of the executable. `run` vets it before every run with
  `vet_fixed_executable`: every directory from `/` to the one that holds the file must be a real directory (not a
  symlink), owned by root and not writable by group or others; an ancestor above the holding directory may be
  writable only with the sticky bit, as for the ancestors of an audit output root, and the holding directory never.
  The file must be a regular, executable file that is not a symlink, owned by root and not writable by group or
  others. The trusted directories are not searched and `/opt/scc` is not added to them, so a `cscc` elsewhere is
  never run.
- `ExecutablePolicy.argument_forms`: exact complete argument lists, token for token, where `<path>` stands for one
  absolute, normalised path. When a policy has forms, command prefixes and options are not consulted. The forbidden
  words and sequences are still checked first.
- `ExecutablePolicy.environment`: fixed values added to the child environment, limited to `TZ` and `HOME` and to a
  plain value alphabet, checked when the policy is bound and again in `run`.

The shipped `cscc` policy is the fixed path `/opt/scc/cscc`, `--version` alone, the one scan form
`-o <path> -u <path> -q -d` and `TZ=UTC0`. Every other SCC option, including the remote, update, install,
`--getOpt`, `-dn` and `-isr` forms, is refused; unit tests in
`tests/unit/plugins/module_utils/compliance/test_process_fixed.py` cover them.

Repository guard: `install_root` (the SCC installation of the backend, `/opt/scc` in production) joins
`BANNED_KEYWORDS`, and `scc.py` owns the seams `runner`, `clock`, `limits` and `install_root` in `SEAM_OWNERS`. The
results parser of `openscap.py` gains the production keyword `assume_utc` and the helper the internal keyword
`holds_executable`; both are classified in `tests/unit/tools/test_check_repo_rules_followups.py`. The SCC
publishing guard of ADR 0019 allows the SCC identifiers in exactly two plugin files, `scc.py` and `process.py`
(`ALLOWED_FILES` in `tests/unit/tools/test_scc_image.py`), which are still checked for publishing commands; any
other plugin file that names them fails.

## Amendment 2026-10-26: command execution without the banned modules (FREES-159)

The reviews of PR #42 showed that a role could still run a command without `shell`, `command`, `raw` or
`script`: through `ansible.builtin.expect`, through the `pipe` and `lines` lookups on the controller, and through
variables and settings that choose the interpreter, the executable or its arguments. Every list below was read
from ansible-core 2.21.5, and `tests/unit/tools/test_check_repo_rules_exec_inventory.py` derives it from the
installed ansible-core again, so a release that adds a lookup, a module, an option or a setting fails the tests
until it is classified.

**Lookups** (`tools/lint/repo_rules/jinja_calls.py`).

- `pipe` and `lines` run their terms with `subprocess.Popen(term, ..., shell=True)` (`plugins/lookup/pipe.py`,
  `plugins/lookup/lines.py`) and are refused. They are the only ansible-core lookups that start a process; the test
  checks every `plugins/lookup/*.py` for `subprocess`, `Popen`, `os.system`, `os.popen`, `os.exec*` and
  `run_command`. The other 23 (`REVIEWED_LOOKUPS`: `config`, `csvfile`, `dict`, `env`, `file`, `fileglob`,
  `first_found`, `indexed_items`, `ini`, `inventory_hostnames`, `items`, `list`, `nested`, `password`,
  `random_choice`, `sequence`, `subelements`, `template`, `together`, `unvault`, `url`, `varnames`, `vars`) are
  allowed. `env` only reads `os.environ` of the controller.
- A lookup may only be used as a call of `lookup`, `query` or `q` (the Jinja globals that `_jinja_bits.py` defines)
  whose first argument is a string literal followed by `,` or `)`, and the literal must name a reviewed lookup,
  bare or as `ansible.builtin.` or `ansible.legacy.`. Everything else is refused: `pipe` and `lines` in every form, a
  computed name (`lookup(name)`, `query(var)`, `lookup('pi' 'pe')`, `lookup('pi' ~ 'pe')`), an indirect use
  (`(lookup)(...)`, `{% set f = lookup %}`, `x.lookup`), and any other name, because a bare name that ansible-core
  does not ship is redirected to a collection (`passwordstore` and `dig` run in `community.general`). A
  `with_<name>` loop key follows the same rule.
- The check reads Jinja with the Jinja 3.1.6 lexer, now a pinned direct development dependency, so escapes
  (`'\x70ipe'`) and adjacent string literals are read as Jinja reads them. It covers every YAML scalar that Ansible
  would template (one that contains `{{`, `{%` or `{#` or starts with `#jinja2:`) in every YAML file outside
  `.github/` (role defaults and vars, plays, blocks, tasks, include and role `vars`, `set_fact`, `loop`,
  inventories, `host_vars`, `group_vars` and Molecule files); the values of `when`, `changed_when`, `failed_when`,
  `until`, `that` and `var`, which Ansible evaluates as bare expressions; and string constants inside a
  template, which Ansible templates when it renders the outer one. Workflows hold GitHub expressions, not Jinja,
  and `!unsafe` and `!vault` values are never templated. A template that does not lex is refused; a bare
  expression that does not lex cannot be compiled by Ansible either and is ignored.
- Every tracked file outside `.github/` is read as one template, whatever its suffix and location (independent
  reviews of PR #45 at 403e751 and b5538dd, `tools/lint/repo_rules/rendered_files.py`), because the `template`
  lookup and module render any file they are pointed at and `vars_files` loads any path. That covers a role's
  `files/`, which `{% include %}` also renders, the values of an INI inventory, and vars files of any suffix.
  `.github/` holds GitHub expressions, not Jinja, and GitHub runs it, not Ansible.
  - A file is binary only when its content starts with the magic bytes of a known binary format and its suffix
    names that format (`BINARY_FORMATS`: PNG, JPEG, GIF, ICO, WebP, gzip, bzip2, xz, zstd, zip, tar, PDF, WOFF,
    WOFF2, OpenType, TrueType, qcow2). A binary is still checked when it holds a template marker, because the
    template module would render it. A NUL byte in any other file is refused: ansible-core 2.21.5 renders a file
    with a NUL and runs its lookups, so a NUL cannot mark a file as binary. Text that is not UTF-8 is refused.
  - A file that Ansible may also load value by value (a file below `roles/`, `playbooks/`, `tests/playbooks/` or
    `extensions/`, below a `templates`, `files`, `vars` or `defaults` directory, with a template suffix, inventory
    text, or `.json`) is checked strictly: a template that does not lex is refused, because each value is
    templated on its own. Any other file can only be rendered whole, and a template that does not lex fails to
    compile before any lookup runs, so a lexer error there is not a finding; its lookups and other refused Jinja
    are. YAML files are checked value by value by the YAML rules and whole by this rule.
  - Every `.json` file, and an extensionless file in an inventory, `host_vars`, `group_vars`, `vars` or
    `defaults` directory, is also composed as YAML, as `include_vars`, the `host_group_vars` plugin and the `yaml`
    inventory plugin load it, so its keys and decoded values get the YAML lookup and variable rules. Reading an
    INI inventory whole is a superset of what its parser passes to the templar: a value whose quoting or escapes
    (`\x27`) would change the expression does not lex and is refused.
  - No tracked file needed an exception or a rewrite.
- Load and render targets (`tools/lint/repo_rules/exec_targets.py`): a `vars_files` entry, the `file`, free form
  and `dir` of `include_vars`, the `src` of the `template` module and the first term of the `template` lookup must
  be a literal relative path, without `..` except in `vars_files`, which Ansible resolves against the playbook,
  and must resolve inside the repository and outside `.github/`. The one templated form is `{{ role_path }}/` in a
  file of a role or `{{ playbook_dir }}/` in a playbook, followed by a literal path, resolved against the role or
  the playbook directory (`roles/audit/tasks/toggles.yml` and `tests/playbooks/remediate-check-mode.yml` load
  `roles/remediate/vars/rules.yml` that way). A vars file must be `.yml`, `.yaml` or `.json`, the files that the
  guard reads value by value, and `extensions` of `include_vars` is refused, so `include_vars` with `dir` loads
  only those suffixes. With every file scanned, the target rule is defence in depth: it keeps a target from
  leaving the repository, where nothing is scanned, and keeps vars files to the suffixes whose values are checked
  one by one.
- An `include`, `import`, `extends` or `from` tag must name a literal relative template without `..` that is not
  itself templated, followed by the end of the tag or a keyword (`as`, `import`, `ignore missing`,
  `with context`); a computed name (`{% include name %}`, `'a' ~ x`, a list) could load any template and is
  refused, like a computed lookup name.
- A `#jinja2:` header (`JINJA2_OVERRIDE`) changes the delimiters of the rest of the template, so a lookup between
  `[[` and `]]` would be invisible to the check. The header is refused in YAML values, string constants and template
  files, and so are the delimiter options (the `*_string` and `*_prefix` fields of `TemplateOverrides`) as YAML keys,
  for example as parameters of `ansible.builtin.template`, and as Jinja keyword arguments. `allow_unsafe` and
  `allow_unsafe_lookups`, which made a lookup result templatable before data tagging, are refused as Jinja names;
  ansible-core 2.21 no longer reads them, but `base.yml` still documents them.

**Modules** (`tools/lint/repo_rules/ansible_tasks.py`, `tools/lint/repo_rules/exec_modules.py`). Every module in
`ansible/modules/` is classified by the test.

- `expect` runs its `command` and `cron` installs its `job` in a crontab, so both are refused like the four banned
  modules, as tasks, `action` and `local_action` values and redirect targets, bare and with the `ansible.builtin.`
  and `ansible.legacy.` prefixes (`TASK_ONLY_BANNED_MODULES`). They are not refused as keys of data documents, where
  `expect` is a word of the Molecule contract cases and `cron` is the schedule of a workflow. Cron hardening in the
  benchmarks (the cron daemon enabled, the permissions of `/etc/crontab` and `/etc/cron.*`, `cron.allow`) is
  done with `file`, `copy`, `service` and `systemd`, so the collection does not need the `cron` module today. If a
  remediation ever needs to remove a crontab entry, add a narrow `state: absent` allowance with tests.
- These parameters name a command, an executable, its options or a file of code that the module runs, and are
  refused in the mapping and free forms, through `args`, in `action` and `local_action` and in `module_defaults`
  (`MODULE_PARAMETERS`): `validate` of `assemble`, `blockinfile`, `copy`, `lineinfile`, `replace` and `template`;
  `dpkg_options` of `apt` (`--pre-invoke`); `conf_file` of `dnf` and `dnf5` (a plugin path); `executable` and
  `ssh_opts` of `git` (`ProxyCommand`); `mount_binary` of `mount_facts`; `use` of `package` and `service` (the
  action runs the module it names, which can be `ansible.builtin.command`); `executable`, `extra_args`,
  `virtualenv_command` and `virtualenv_python` of `pip`; `boot_time_command`, `reboot_command`, `search_paths` and
  `test_command` of `reboot`; `fact_path` of `setup` and `gather_facts` (executable fact files), also as a play
  keyword; `executable` of `subversion`; `extra_opts` of `unarchive` (`tar --to-command`).
- Reviewed and allowed: `user` `shell` (the login shell; hardening sets system accounts to `nologin`), `service`
  and `sysvinit` `arguments` (passed to an installed init script), `hostname` `use` (a strategy name), the
  `iptables` flag options, `rolespec_validate` and `provided_arguments`. Package managers run the maintainer scripts
  of what they install; that is their purpose, not a command of the caller's choice.

**Variables** (`tools/lint/repo_rules/exec_variables.py`).

- Refused, from the `DOCUMENTATION` of the connection and become plugins (every option whose name ends in `args`,
  `exe`, `executable`, `flags`, `command` or `cmd`, and `pkcs11_provider`): `ansible_ssh_args`,
  `ansible_ssh_common_args`, `ansible_ssh_extra_args`, `ansible_scp_extra_args`, `ansible_sftp_extra_args`,
  `ansible_ssh_executable`, `ansible_scp_executable`, `ansible_sftp_executable`, `ansible_ssh_pkcs11_provider`
  (`plugins/connection/ssh.py`), `ansible_winrm_kinit_cmd`, `ansible_winrm_kinit_args`
  (`plugins/connection/winrm.py`), `ansible_become_exe`, `ansible_sudo_exe`, `ansible_su_exe`,
  `ansible_become_flags`, `ansible_sudo_flags`, `ansible_su_flags`, `ansible_runas_flags` (`plugins/become/`) and
  the keywords `become_exe` and `become_flags`. From `MAGIC_VARIABLE_MAPPING` (`constants.py`):
  `ansible_shell_executable` and `ansible_docker_extra_args`, and `docker_extra_args`, which the
  `community.docker.docker` connection also reads. From `config/base.yml`: `ansible_python_interpreter`,
  `ansible_interpreter_python_fallback`, `ansible_facts_modules` and the internal `_ansible_ansiballz_*_config`
  and `_ansible_coverage_remote_output` (a debugger or coverage hook in every module). From
  `executor/module_common.py`: every `ansible_<name>_interpreter` and `discovered_interpreter_<name>` (and
  `ansible_discovered_interpreter_<name>`), which a cached fact can set. From the `package` and `service` actions:
  `ansible_package_use`, `pkg_mgr`, `ansible_pkg_mgr`, `service_mgr` and `ansible_service_mgr`, which choose the
  module they run. Also `ansible_playbook_python`, which the test plays use as their interpreter, every `_ansible_*`
  name, and, for plugins of other collections, every `ansible_*` name ending in `_args`, `_exe`, `_executable`,
  `_flags`, `_cmd` or `_command`.
- Selectors may name only a plugin of ansible-core, bare or as `ansible.builtin.` or `ansible.legacy.`:
  `ansible_connection` and the keyword `connection` (`local`, `psrp`, `ssh`, `winrm`), `ansible_become_method` and
  `become_method` (`runas`, `su`, `sudo`) and `ansible_shell_type` (`cmd`, `powershell`, `sh`).
- `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUSERBASE`,
  `BASH_ENV`, `ENV`, `PERL5LIB`, `PERL5OPT`, `RUBYOPT` and `NODE_OPTIONS` are refused as YAML keys, because as a
  task `environment` they change which program or library a module runs.
- A setting is found as a mapping key in any YAML file, at any depth; as `name=value` in a YAML value (`add_host`,
  `set_fact` and include free forms, `--extra-vars`) and as a quoted Jinja dictionary key (`{'name': value}`); and as
  `name=value` or `"name": value` in inventory text (files below `inventory`, `inventories`, `host_vars` and
  `group_vars`, and files named `hosts` or `inventory`) and in configuration text (makefiles, shell scripts,
  environment, `.ini`, `.toml` and `.cfg` files). Naming or reading a variable (`when: ansible_connection ==
  'local'`, `hostvars[h].ansible_python_interpreter`, a list of names) is not setting it.
- The reviewed exceptions (`ALLOWED_SETTINGS`) are keyed by file, name and exact value, and a test fails if one is
  unused. The controller-local test plays and inventories in `tests/playbooks/` set `ansible_python_interpreter` to
  `{{ ansible_playbook_python }}`, the interpreter of the running `ansible-playbook`, in 16 files, and
  `tests/playbooks/inventory/evidence-gate.yml` sets `ansible_ssh_common_args` to
  `-o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes` for a host that must be unreachable. The
  Molecule entries are the `community.docker.docker` connection of the instance records
  (`extensions/molecule/shared/create.yml` writes it as the Jinja dictionary key `'connection'`, and
  `shared/vars/guard_cases.yml` holds the simulated record and its `ansible_connection`) and the bypass cases that
  the Molecule guard must refuse: `ansible_docker_extra_args` and `docker_extra_args` set to
  `-H tcp://192.0.2.1:2375` in `shared/vars/guard_cases.yml`, and in `selftest/bypass.yml` `ansible_connection` set
  to `{{ selftest_docker }}` (and to `selftest_docker` in a Jinja dictionary) and `ansible_docker_extra_args` set to
  `--host tcp://192.0.2.1:2375`. Molecule needs no interpreter setting; the containers use interpreter discovery.

**Configuration** (`tools/lint/repo_rules/exec_config.py`, `tools/lint/repo_rules/load_config.py`). Every setting of
`config/base.yml` is classified by the test: refused, a plugin selector, a search path (FREES-156) or reviewed.

- Refused in an `ansible.cfg` (any section, any case of the key) and in the `ansible.cfg` and `config_options`
  mappings of `molecule.yml`: `allow_unsafe_lookups`, `become_exe`, `become_flags`, `become_password_file` and
  `connection_password_file` (run when executable), `callbacks_enabled`, `collection_skeleton`, `cowpath` (the
  cowsay executable), `editor`, `enable_plugins` (inventory plugins such as `script`), `executable`,
  `fact_caching_connection` (cached facts can set `discovered_interpreter_python`), `facts_modules`,
  `interpreter_python`, `inventory` (an executable inventory runs), `jinja2_extensions`, `module_args`,
  `module_name`, `pager`, `role_skeleton`, `ssh_agent_executable`, `ssh_config` (netconf, `ProxyCommand`),
  `vars_plugins_enabled`, `vault_identity_list` and `vault_password_file` (scripts); and, from the plugin
  documentation, `ssh_args`, `ssh_common_args`, `ssh_extra_args`, `scp_extra_args`, `sftp_extra_args`,
  `ssh_executable`, `scp_executable`, `sftp_executable`, `pkcs11_provider` and the become plugin keys `executable`
  and `flags`.
- Plugin selectors must name a plugin of ansible-core: `stdout_callback` (`default`, `junit`, `minimal`, `oneline`,
  `tree`), `fact_caching` (`jsonfile`, `memory`), `strategy` (`free`, `host_pinned`, `linear`; not `debug`, which
  evaluates Python typed at its prompt), `become_method` and `transport`. The Molecule scenarios use
  `ansible.builtin.default` and `memory`.
- The environment variables of all of these (`CODE_ENVIRONMENT_VARIABLES`, from `base.yml` and the plugin
  documentation, plus `_ANSIBLE_TEMPLAR_SANDBOX_MODE`, which turns off the Jinja sandbox, and
  `ANSIBLE_DOCKER_EXTRA_ARGS`) are refused wherever FREES-156 refuses the search-path variables, and the
  command-line options that pass arguments or a script (`--ssh-common-args`, `--ssh-extra-args`,
  `--scp-extra-args`, `--sftp-extra-args`, `--vault-id`, `--vault-password-file`, `--vault-pass-file`,
  `--connection-password-file`, `--conn-pass-file`, `--become-password-file`, `--become-pass-file`, from
  `cli/arguments/option_helpers.py`) wherever `--module-path` is refused. `EDITOR` and `PAGER` themselves are
  left alone; only `ansible-vault edit` and `ansible-doc` read them, and neither runs in CI.

**Review items carried over from PR #42.**

- Non-ASCII path components are refused (`non_ascii_findings` in `tools/lint/repo_rules/load_locations.py`). This
  was chosen over `upper().casefold()`: the filesystems fold with their own tables (NTFS with a per-volume upcase
  table that maps the dotless `ı` to `I`, APFS with Unicode case folding and normalisation), so no single Python
  folding equals all of them, and a second folding would only cover the one character the review found. No
  tracked path has a non-ASCII component, and for ASCII names `casefold()` agrees with every filesystem.
- An `--index-modes` listing that cannot be read ends the guard with a clear message and exit status 2 instead of a
  traceback.

**Residuals.** The guard reads the repository, not the run. Every file inside the repository outside `.github/` is
scanned, and every load and render target and template name must be literal and resolve inside it, so what remains
is a file from outside the repository that the run supplies (an inventory, extra variables or a vars file passed on
the command line) and a dictionary key built at run time (`{'ansible_' ~ 'python_interpreter': x}`). Options of
connection, become and shell plugins of other collections are refused only by the name patterns above. Settings
outside the repository (`~/.ansible.cfg`, `ANSIBLE_CONFIG`, the operator's environment) stay the documented
residual of FREES-156. The change closes routes around AGENTS.md rule 1 and needs the independent review that the
issue asks for.

## Amendment 2026-10-26: templated parameters, the run-start check and the evidence entry points (FREES-157)

The residuals that the reviews of PR #40 (FREES-153) and PR #41 (FREES-154) found. Each item tightens a rule; none
adds an exemption, and no lint limit was raised.

- Templated parameters: the second read-back of FREES-153 refuses a fixed forged value only. Ansible templates an
  extra variable, an include parameter and a role parameter again for every task. The reviewer's probe passed the
  plan template `{{ __linux_compliance_remediate_dispatched if __linux_compliance_remediate_dispatched is string else
  <forged plan> }}` to the real remediate role on localhost in check mode, through `-e` and through the `vars` of
  `include_role`. It copied the sentinel during both read-backs and returned a well-shaped plan once the dispatched
  flag was a boolean, so it passed the plan type check, dropped the real crontab rule and published
  `notices=['FORGED-PLAN-USED'] rules=[]` with `changed=0`. No check of values can close this: a lazy template sees
  everything that the assertion sees, including the facts that were just reset.
- Where a name is visible, measured on the pinned ansible-core 2.21.5 inside a role task (FREES-157 probe):

  | Source of `__name` | `query('ansible.builtin.varnames', '^__name$')` | `hostvars[inventory_hostname]` |
  |---|---|---|
  | role parameter, `vars` of a `roles` entry | yes | no |
  | include parameter: `vars` of `include_role`, `import_role` or `include_tasks`, fixed, templated or `omit` | yes | no |
  | block variable or play variable, including the `vars` of `import_playbook` | yes | no |
  | variable of the role's `vars/main.yml` | yes | no |
  | extra variable (`-e`), inventory, `group_vars`, `host_vars` | yes | yes |
  | fact (`set_fact`, `register`, `include_vars`), also from an earlier play | yes | yes |

  `-e hostvars=...` and `-e groups=...` do not replace those magic variables. `-e inventory_hostname=...` and an
  include parameter `inventory_hostname` do replace `inventory_hostname`.
- Parameter check: the generated guard now starts with one assertion item per internal fact, task variable and
  `include_vars` constant of the role: `query('ansible.builtin.varnames', '^<name>$') == [] or '<name>' in
  (hostvars[inventory_hostname] | list)`. A name that the lookup sees and `hostvars` does not was passed as a
  parameter, and it is refused whatever its value, a template or `omit` included. The check runs before the first
  reset, because the reset makes every fact a `hostvars` name. Constants of `vars/main.yml` are role variables, seen
  the same way as a parameter, so they are left out and keep their read-back. The read-backs stay for extra
  variables and as defence in depth. A role parameter of a `roles` entry was already refused by the argument
  validation, which also templates it; the `vars` of a `roles` entry, which ranked below the role's facts, are
  refused now as well.
- Run-start check: the generator also writes `playbooks/run_start.yml` (`tools/roles/run_start.py`), and every
  shipped playbook imports it first. Its one play (on `all:localhost` since the `--limit` item below) refuses the run
  when an inventory host or `localhost` already has, in `hostvars`, any `__linux_compliance_*` name or a role output: every public
  `linux_compliance_*` fact that a role sets (`role_outputs`), among them `linux_compliance_audited`,
  `linux_compliance_discovered`, `linux_compliance_audit_stale_exceptions` and `linux_compliance_baseline`. It also
  refuses `inventory_hostname` and `group_names` as extra variables (see below). As in the FREES-150 Molecule guard it reads only the magic
  variables `groups` and `hostvars` and literals, and it refuses by name, so a template cannot pass it. Two
  exceptions keep legitimate runs working. A fact that a role sets with `cacheable: true`, today only
  `__linux_compliance_verify_baseline_recorded`, survives in a persistent fact cache by design and is checked where
  it is read, so it is exempt. A shipped playbook that imports another passes the play variable
  `linux_compliance_run_start_checked: true` to it, because its own earlier plays have set facts by then; a play
  variable is not in `hostvars`, so the marker skips the check only when it is neither an extra variable nor an
  inventory variable, and the check refuses it in `hostvars` like any other name. Since the `--limit` item below the
  condition is `<marker> is not defined or <every name in hostvars of the inventory hosts and localhost> |
  select('equalto', '<marker>') | list | length > 0`, the same on every host; see the marker item below.
- `linux_compliance_audited` (review of PR #41): the audit role accepted `-e linux_compliance_audited=...` as an
  override of its own output, and the `run_id` check of the evidence role's `collected.yml` relies on that fact. The
  run-start check now refuses it from `-e` and the inventory. In addition, `scan.yml` checks right after it publishes
  the fact that both the resolved value and the value in `hostvars` carry the `run_id` of the scan that just ran, as
  `baseline.yml` does for the baseline, so a fixed override through any route fails before a gate, a collection or a
  comparison uses it.
- Evidence entry points: `tasks_from: collect.yml` skipped the guard and the output directory validation of
  `main.yml`. `collect.yml` is now a block at the end of `main.yml` with the same condition, so the file and the
  entry point no longer exist. The role's task files are `main.yml` and `summary.yml`, which import the guard first,
  `internal_variables.yml`, and `reached.yml` and `collected.yml`, which by design (FREES-154) read internal names
  only through `hostvars[...]` and the `reached.yml` name pattern; a unit test pins this set. The run marker stays a
  run output outside the reset.
- `tools/roles/promote_native_rule.py` also refuses a hard link to `roles/remediate/vars/rules.yml`: it compares
  `st_dev` and `st_ino` of the target with the repository catalogue before it writes.
- Host nonce (review of PR #44): an include parameter `inventory_hostname: <other host>` pointed the parameter check
  at the facts of that host, so a decoy fact of the forged name there let a templated parameter pass. After the
  parameter check the guard now records `__linux_compliance_<role>_host_nonce: "{{ 1000000000000 |
  ansible.builtin.random }}"` and asserts that `hostvars[inventory_hostname]` holds the same nonce. `set_fact` always
  writes to the host that runs the task, so the assertion fails whenever `inventory_hostname` names another host,
  through an include parameter, a role parameter or an extra variable. The nonce is a run output of the guard: it is
  never reset to a sentinel and never read back, its name is in the parameter check, and the generator refuses a
  role variable of that name.
- `group_names` (review of PR #44): an extra variable replaces `group_names` in `vars` and in `hostvars`, and an
  include parameter replaces it in `vars`; the `groups` magic variable cannot be replaced by either. The audit role
  passed `group_names` to `apply_exceptions`, so `-e group_names=[<group>]` widened the hosts an exception scoped to
  that group applied to. `exceptions_apply.yml` now derives the groups of the host from `groups` (every group except
  `all` that lists `inventory_hostname`), and the run-start check compares the `<host> <group>` pairs of
  `hostvars[*].group_names` with those of `groups` and refuses any difference.
- `--limit` (review of PR #44 at 98d95ea): the run-start play targeted `localhost`, which a limit keeps only when it
  names `localhost`, so `playbooks/remediate.yml --limit web01 -e '<plan template>'` skipped the check and published
  the forged plan; the role guards cannot refuse an extra variable, because its name is in `hostvars` and both sides
  of the nonce check read the same value. The play now targets `all:localhost` with `run_once: true` and
  `gather_facts: false`, so it runs once whatever the limit selects. Its only task is an assertion, an action that
  reads `hostvars` and `groups` on the controller and never connects, also for an unreachable host. A limit that
  selects no host ends the run before any play. `make test-role-guards` refuses a forged `-e` with `--limit web01` for
  `remediate.yml`, `audit.yml`, `evidence.yml` and `verify.yml` and with `--limit lost01`, an unreachable host, and
  runs the plain playbooks with `--limit web01`, `lost01` and `localhost` without a connection. The other plays on
  `localhost` stay there, because their results are facts of `localhost` that later plays and roles read, and
  skipping them fails closed:
  - The stale-exceptions play (`audit.yml`, so also `remediate.yml` and `verify.yml`, and `evidence.yml`) only
    reports: no stale warning is printed, the bundles of `evidence.yml` get no `exceptions/stale.json` (the evidence
    role passes an empty mapping), and the report computes the review of every exception from the evaluations itself.
    No gate, waiver or comparison depends on it.
  - The summary play of `evidence.yml`: no collection summary is written, so a report over the bundles has host
    coverage `unknown` and `--require-host-coverage` exits 1; the last play still fails every host whose collection
    failed. `docs/evidence.md` already tells operators to add `localhost` to a limit.
  - The `run_once` tasks of the roles (the exceptions file read and validation, `reached.yml`, the stale and summary
    tasks) run on the first host of their play, which is a selected host whenever the play runs at all.
- The marker under `run_once` (review of PR #44 at c847afa): the skip condition used to be `<marker> is not defined
  or '<marker>' in (hostvars['localhost'] | list)`. On `all:localhost` with `run_once` it is evaluated on the first
  selected host, so an inventory variable `linux_compliance_run_start_checked: true` of that host made the marker
  defined while `localhost` lacked it, and the whole check was skipped, with or without `--limit`. The check is now
  skipped only when the marker is defined and no inventory host and not `localhost` has a `hostvars` name equal to it.
  The only source left is a play variable, which only the importing shipped playbook sets: an extra variable, an
  inventory, `group_vars` or `host_vars` value or a fact of that name on any host puts the name in `hostvars`, the
  check runs and it refuses the marker. The condition reads only `groups`, `hostvars` and literals and is the same on
  every host. The alternative, dropping the skip, would make an imported `audit.yml` refuse the facts of the plays
  before it; a value that the importing playbook passes cannot be told from an inventory value by its content, only
  by where it is defined, which is what the condition checks. `make test-role-guards` runs shipped `remediate.yml`
  and `audit.yml` with the marker as a `host_vars` and as a `group_vars` value of web01, the first selected host,
  with and without `--limit web01`, and requires the refusal.
- Residual, explicit operator options: `--skip-tags always` and `--start-at-task <a later task>` skip the run-start
  check like any task. The check already carries the `always` tag, so `--tags` alone cannot skip it; no other tag
  would survive `--skip-tags always`. With `--skip-tags always` the roles do nothing, and `remediate` and `verify` fail: every task that scans, changes
  or compares is tagged `always`, and the dispatched guards of the `remediate` and `verify` roles (tagged
  `linux_compliance_<role>_guard`) fail the host. `--start-at-task` also skips the internal-variable guards and does
  not fail closed. Both are choices on the command line with the trust of `-e` in a custom playbook, and
  `docs/playbooks.md` tells operators not to use them with the shipped playbooks.
- Two shipped playbooks in one `ansible-playbook` invocation are refused by the run-start check of the second, because
  the first left role outputs and internal facts in `hostvars`. This fails closed and is intended: the shipped
  playbooks that need another one import it with the marker, and facts of a finished playbook must not seed the next.
- Residuals, each needing control of the playbook or the command line:
  - The parameter check cannot tell a parameter from a fact of the same name, so when an earlier entry point of the
    same role already ran on the host in this run (the verify role's `preflight.yml` before `baseline.yml` and
    `main.yml`, the second audit of `playbooks/remediate.yml`, the `stale.yml` play on `localhost`), a templated
    parameter of that name meets only the read-backs.
  - An extra variable is in `hostvars`, so the parameter check passes it. The run-start check refuses it in the
    shipped playbooks; a custom playbook that does not import `playbooks/run_start.yml` keeps the template residual
    of FREES-153 for `-e`.
  - The internal task files of the audit role (`scan.yml`, `gate.yml`, `toggles.yml`, `exceptions_file.yml`,
    `exceptions_apply.yml`, `evaluation.yml`, `defer.yml`) and the remediate family files can still be included
    directly with `tasks_from`, which skips the guard, the same residual as the remediate family files above: such a
    caller can do no more than call the modules itself.

## Amendment 2026-10-30: the `visudo` check of the sudo drop-ins (FREES-175)

The native `sudo` topic ([ADR 0022](0022-native-sudo-drop-ins.md)) writes drop-ins below `/etc/sudoers.d`. sudo
refuses every command when one file of its configuration does not parse, so a drop-in must be checked before it is
moved into place, and the only native way to do so is the `validate` parameter of `ansible.builtin.copy`, which the
FREES-159 amendment refuses because the module runs the command it names.

`tools/lint/repo_rules/exec_modules.py` now keeps a reviewed exception list, `ALLOWED_PARAMETERS`, of entries by file,
module, parameter and exact value. It holds one entry: `validate: /usr/sbin/visudo -cf %s` of `copy` in
`roles/remediate/tasks/sudo_dropin_apply.yml`. Only a plain scalar in the mapping form of the module counts; a quoted
or templated value, a free-form argument, `args`, `module_defaults`, any other value, module or file is refused as
before. The executable is a fixed absolute path, the only argument besides the flags is the temporary file that the
module created, and no variable can change either. `tests/unit/tools/test_check_repo_rules_exec_validate.py` checks
that the list holds exactly this entry, that its file uses it once, and that every other form is refused.
