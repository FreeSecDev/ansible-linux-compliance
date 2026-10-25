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
| Allow-list | `ALLOWED_EXECUTABLES` holds only `oscap`. Its sub-commands are allow-listed as leading argument sequences: `xccdf eval` and `info`, each followed only by allow-listed options (`--profile`, `--results-arf`, `--results`, `--report`) and positional values, and `--version` alone. Any other sequence is refused, so `xccdf remediate`, `xccdf generate fix`, `oval eval` and a bare `xccdf` never run. The words `remediate` and `--remediate` and the sequence `generate fix` are refused anywhere in the arguments for every executable, because running upstream fix scripts is excluded by ADR 0003. A policy with no command prefixes permits nothing. Adding an executable, sub-command or option requires a security review |
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
  `pathlib`, `re`, `stat`, `types`, `typing`, `unicodedata`, `xml.etree.ElementTree`), `ansible.module_utils` and this
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
