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
| `resolve_executable(name, search_dirs, owner_uid)` | Searches only `TRUSTED_DIRECTORIES` (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`), never `PATH`. Rejects names with separators or traversal, trusted directories and files that are not owned by `owner_uid` (root, 0, by default) or are writable by group or others, symlinks that resolve outside the trusted directories, non-regular files and non-executable files. A missing file raises `ProcessExecutionError`. It returns the vetted path inside the trusted directory, not the symlink target |
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
- `tools/lint/check_repo_rules.py` applies a deny-by-default rule to Python files under `plugins/` other than
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
  (`EXTRA_IMPORTS` in `tools/lint/check_repo_rules.py`); every other plugin file that imports it fails the guard, which
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
  `KNOWN_SUBMODULE_ATTRIBUTES` in `tools/lint/check_repo_rules.py`), the union over CPython 3.9 to 3.15, not values read from
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
  `tools/lint/check_repo_rules.py`). `xmlsafe.py` holds the same layered defences as the XCCDF results parser (byte
  scan for DOCTYPE and ENTITY, UTF-8 forced, parameter entities off, element and depth bounds, no stored elements) as a
  public API, so that `catalog.py` and later parsers use it without importing private names of `openscap.py`. Every
  other plugin file that imports expat still fails the guard, and a test shows it for several paths. `openscap.py`
  keeps its own copy of the parser for now; moving it onto `xmlsafe.py` is a follow-up.
- The public bounds parameter of `xmlsafe` is named `bounds`, because `limits` stays banned as a call keyword.

## Amendment 2026-10-25: one XML parser (FREES-126)

- Import allow-list for `plugins/`: `xml.parsers.expat` is allowed in exactly one file,
  `plugins/module_utils/compliance/xmlsafe.py` (`EXTRA_IMPORTS` in `tools/lint/check_repo_rules.py`), in the form
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
  `expat`, `RESERVED_ATTRIBUTES` in `tools/lint/check_repo_rules.py`) may be used only in the file that owns the entry,
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
  constants in `tools/lint/check_repo_rules.py`, but they are now generated. `tools/lint/name_set_probe.py` (standard
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
  `main` used them, and no open pull request (#17, #18) adds a use. They are now denied, and `functools` and
  `itertools` are also banned as module-rooted attributes (`typing.functools`). `os.path` was kept although no merged
  plugin uses it: PR #17 (FREES-49, `audit.py`) imports it, the `os`-only-as-`os.path` rule and the file-I/O helper
  rules are built on it, and removing it now would mean a second guard change in that pull request to restore it.
- Test seams: `registry` (the backend registry seam of `audit.Auditor` in PR #17) joins `BANNED_KEYWORDS`. A review of
  every keyword-only parameter in `plugins/` found no other unbanned seam; the remaining keyword-only parameters
  (`accept`, `create`, `default`, `dry_run`, `max_length`, `multiline`, `pattern`, `replace`, `reveal`, `sensitive`,
  `subject`, `write`) are production arguments. `tests/unit/tools/test_check_repo_rules_followups.py` now fails for any
  keyword-only plugin parameter that is neither a banned seam nor on that reviewed list, so a new seam cannot be added
  without a decision.
- `xmlsafe.open_regular` is private (`_open_regular`). Only `RegularFile` (and through it `iter_file_chunks`) calls
  it, so a future plugin cannot open a file in a way that lets a close-time `OSError` escape as a bare `OSError`. The
  existing rules enforce this: an underscore-prefixed attribute of another module and an import of an
  underscore-prefixed name fail the guard, which tests show for five plugin paths.
