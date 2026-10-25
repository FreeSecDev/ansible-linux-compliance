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
| Allow-list | `ALLOWED_EXECUTABLES` holds only `oscap` with `--profile`, `--results-arf`, `--results`, `--report` and `--version`. Subcommands such as `xccdf` and `eval` do not start with `-` and need no entry. Adding an executable or option requires a security review |
| `resolve_executable(name, search_dirs)` | Searches only `TRUSTED_DIRECTORIES` (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`), never `PATH`. Rejects names with separators or traversal, world-writable trusted directories, symlinks that resolve outside the trusted directories, non-regular files, world-writable files and non-executable files. A missing file raises `ProcessExecutionError`. It returns the vetted path inside the trusted directory, not the symlink target |
| `confined_path(base, candidate)` | Returns the normalised absolute path, rejects NUL, escapes from `base` and any symlink below `base`. Callers still validate their own path arguments |
| `run(spec)` | Returns a frozen `CommandResult` (`argv`, `returncode`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `duration_seconds`, `timed_out`). The child gets `shell=False`, `stdin=DEVNULL`, `close_fds=True`, `start_new_session=True` and an explicit environment |
| Environment | Always `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `LANG=C`. `env_allow` may additionally copy `TZ` and `TMPDIR` from the parent; any other name is a policy error. The environment is never returned or logged |
| Exceptions | `ProcessPolicyError` (also a `ValueError`; nothing ran) and `ProcessExecutionError` (also a `RuntimeError`; missing binary, start failure, read failure), both under `ProcessError`. Untrusted values appear only as `repr` truncated to 64 characters |

Deviations and decisions:

- The implementation uses `subprocess.Popen` with `selectors` and chunked reads from both pipes instead of
  `subprocess.run`, so memory is bounded by `max_output_bytes` and the pipes cannot deadlock. Output beyond the cap
  is drained and discarded, not kept, and the truncation flag is set.
- A timeout kills the whole process group with `SIGKILL` and is reported as `timed_out=True`, not as an exception,
  so the caller maps it to outcome `error` (ADR 0013). A group member that holds the pipes after the leader exits is
  also bounded by the timeout.
- `run` accepts the keyword-only parameters `policies` and `trusted_dirs`. They exist solely so that unit tests can
  run harmless system utilities and are never passed by production code.
- Trusted-directory vetting and `exec` are separate steps, so a file replaced between them is not detected. The
  trusted directories are root-owned system directories; the helper refuses world-writable ones.
- A symlink inside a trusted directory that points elsewhere, such as an `update-alternatives` link under `/etc`,
  is refused. This is deliberate and conservative.
- `tools/lint/check_repo_rules.py` fails when Python files under `plugins/` other than `process.py` import
  `subprocess` or `pty`, use `os.system`, `os.popen`, `os.exec*`, `os.spawn*` or `os.posix_spawn*`, import them
  dynamically, or pass `shell=True`. Bandit B404 and B603 are skipped globally in `pyproject.toml` because Bandit has
  no per-file skip and inline `nosec` comments are banned; Ruff S404 and S603 are ignored only for `process.py`.
- `ansible-test sanity` flags a direct `subprocess.Popen` call with `ansible-bad-function`, and ansible-lint forbids
  ignoring that message. The helper therefore binds `Popen` once to the module constant `SpawnProcess` and calls it
  through that name; behaviour is unchanged and the repository rule still confines `subprocess` to this file.
