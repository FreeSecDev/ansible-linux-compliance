# 0011. Per-rule and per-topic control toggles with cleanup on disable

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** pending (remediation epic)
- **Pull requests:** pending

## Context

The project owner requires that every security rule can be switched on or off through variables, individually or
per topic. For example, it must be possible to disable everything related to auditd. When a control that was
previously enabled and applied is disabled, the collection must clean up what it applied, not merely stop managing it.

Ansible variable precedence replaces dictionaries rather than merging them, so nested toggle dictionaries would be
overwritten wholesale by any inventory layer that sets one key.

## Decision

### Variables

- One topic toggle per control family: `linux_compliance_<family>_enabled`, for example
  `linux_compliance_auditd_enabled`, `linux_compliance_ssh_enabled`, `linux_compliance_sysctl_enabled`.
- One toggle per rule: `linux_compliance_rule_<rule_short_id>_enabled`, for example
  `linux_compliance_rule_sshd_disable_root_login_enabled`. Its default is the value of the rule's family toggle.
- All toggles are flat booleans, so any inventory layer can override a single rule or topic.
- A rule is **effective** when the global `linux_compliance_remediate_enabled` is true, its rule toggle is true, the
  rule belongs to the selected profile, and disruptive families are allow-listed.
- The rule catalogue (`roles/remediate/vars/rules.yml`) lists every implemented rule with its family, ComplianceAsCode
  identifier, disruptive flag and reversibility. Defaults and argument specs are generated from it and checked in CI,
  so no rule can exist without a toggle.

### Apply and revert

Every implemented rule has both an apply path and a revert path. The revert strategy is fixed per rule:

| Strategy | Used when | Revert action |
|---|---|---|
| Owned drop-in | The service supports drop-in directories (`/etc/sysctl.d`, `/etc/audit/rules.d`, `/etc/ssh/sshd_config.d`, `/etc/modprobe.d`, `/etc/security/*.d`) | Remove the collection-owned drop-in file and reload |
| Recorded value | A shared file or setting must be edited in place | Restore the prior value recorded in the state ledger |
| Recorded package or service state | A package is installed or removed, or a service is enabled, disabled or masked | Restore the recorded prior state |
| Irreversible | Partitioning, mount layout or similar | Never reverted automatically; cleanup reports a manual action and links the runbook |

Owned drop-ins are preferred, because cleanup then needs no history and remains correct even if the ledger is lost.

### State ledger

A typed module `freesecdev.linux_compliance.control_state` maintains
`/var/lib/freesecdev/linux_compliance/state.json`. The file is owned by root with mode `0600` and is written atomically.
For each applied rule it records the rule identifier, family, revert strategy, prior values, collection version and the
time it was applied. A rule is cleaned up when it is not effective but the ledger records it as applied. Successful
cleanup removes the ledger entry. If the ledger is missing or a prior value is unknown, cleanup removes owned drop-ins
and reports `cleanup incomplete` for the rest. It never guesses a previous value.

### Cleanup safety

- Cleanup runs in the remediate role and honours check mode and diff mode.
- Cleanup of a disruptive family requires the same allow-list entry as applying it, because reverting SSH, PAM or
  firewall settings can also lock operators out.
- Cleanup is idempotent: a second run with the same toggles reports zero changes.
- Package removal during cleanup happens only when the ledger shows the collection installed the package.

### Audit and reporting

Disabled rules are excluded from the scan through a generated XCCDF tailoring file. They are reported as
`disabled`, a distinct outcome that names the controlling variable. They are never reported as `pass` or silently
dropped. The exceptions report lists disabled rules that have no matching exception record, so governance can require
justification without blocking operators.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Nested toggle dictionaries | Replaced wholesale by Ansible variable precedence; one override silently drops the rest |
| Toggle only; no cleanup | Leaves previously applied hardening behind, contrary to the requirement |
| Infer prior state from distribution defaults | Guessing; wrong on customised hosts |
| Ansible tags for selection | Tags are run-time selection, not persistent configuration, and cannot drive cleanup |

## Benefits

Operators can turn off any rule or topic, and the host returns to its pre-collection state for that control.

## Trade-offs

Every rule needs a tested revert path, roughly doubling the remediation test surface. The ledger is new on-host state.

## Security implications

The ledger reveals which controls are applied, so it is root-only. Disabling a control reduces protection, so disabled
rules are always visible in reports. Cleanup of disruptive families is gated like their application.

## Operational consequences

Molecule gains a toggle-and-cleanup scenario for every family. It applies the family, disables it, asserts the
pre-collection state is restored, and asserts a further run changes nothing. The support matrix records reversibility
per rule.

## Amendment 2026-10-25: state ledger and file-I/O helper (FREES-56)

The ledger is implemented by `plugins/module_utils/compliance/ledger.py` (typed model, strict JSON, transactions),
`plugins/module_utils/compliance/fileio.py` (the single audited file-I/O helper) and the module
`plugins/modules/control_state.py`. Everything is standard-library only and runs on Python 3.9 to 3.14.

### Ledger format

`/var/lib/freesecdev/linux_compliance/state.json` is a JSON document with exactly the keys `schema_version` (integer,
currently `1`) and `entries` (a list sorted by `rule_id`). It is serialised deterministically (sorted keys, two-space
indent, ASCII, trailing newline). Each entry has exactly these keys:

| Key | Contract |
|---|---|
| `rule_id` | Full XCCDF rule identifier, unique in the ledger |
| `family` | Control family, a lower-case slug of at most 64 characters |
| `revert_strategy` | `owned_dropin`, `recorded_value`, `recorded_state` or `irreversible` (the `RevertStrategy` of the findings model) |
| `prior_values` | List of `{name, value, sensitive}` sorted by name, at most 64. `value` is a string of at most 4096 characters or `null` when the setting did not exist. `recorded_value` and `recorded_state` need at least one; `owned_dropin` and `irreversible` take none |
| `collection_version` | `MAJOR.MINOR.PATCH` with an optional pre-release or build suffix |
| `applied_at` | UTC `YYYY-MM-DDTHH:MM:SSZ` |

Reads are strict: at most 4 MiB and 4096 entries; invalid UTF-8, malformed JSON, duplicate keys at any depth, `NaN`,
`Infinity`, excessive nesting, unknown or missing keys, wrong types, a rule listed twice and invalid fields are
`corrupt`; another `schema_version` is `unsupported_schema`. A corrupt ledger is an error and is never reset, repaired
or replaced; the `cleanup incomplete` behaviour of this ADR applies only to a missing ledger. A ledger with a schema
version this collection does not know is not rewritten.

`record` is idempotent: an identical entry (ignoring `applied_at`) is left untouched, so the original time and prior
values survive repeated runs. A differing entry is a `conflict` unless `replace` is set, so the true prior value cannot
be overwritten by accident. Sensitive prior values are stored, because reverting needs them, in the root-only file. They
reach the module through `no_log` options and are redacted (`value: null`, `redacted: true`) from every return value,
diff and error unless `get` or `list` is called with `reveal_sensitive` (the task must then set `no_log`).

### File-I/O helper and guard exemption

The repository guard allows only `os.path` and bans `fcntl`, `errno` and `time` in `plugins/`. Safe state files need
`os.open` with `O_NOFOLLOW`, directory-relative operations, `fsync`, `rename`, `fchmod` and `flock`, so, as for
`process.py` (ADR 0004), exactly one file gets a narrow exemption: `plugins/module_utils/compliance/fileio.py`
(`FILE_IO_HELPER` in `tools/lint/check_repo_rules.py`).

- In that file only, `import os`, `import fcntl`, `import errno` and `import time` are allowed, and each may be used only
  as `module.attribute` with an attribute from `FILE_IO_ATTRIBUTES`: `os` (`O_RDONLY`, `O_WRONLY`, `O_CREAT`, `O_EXCL`,
  `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK`, `O_CLOEXEC`, `open`, `close`, `read`, `write`, `fstat`, `stat`, `fsync`,
  `fchmod`, `mkdir`, `rename`, `unlink`, `urandom`, `supports_dir_fd`), `fcntl` (`flock`, `LOCK_EX`, `LOCK_NB`),
  `errno` (`ELOOP`, `EMLINK`, `ENOTDIR`) and `time` (`monotonic`, `sleep`). Any other attribute, a bare name, an alias
  (`import os as o`) or a `from` import fails.
- Every other rule still applies to that file: process, fork, spawn and exec names, `getattr` with a computed name,
  banned keywords, dict splats and the comment ban. No other file may import these modules; tests show this for several
  paths, and a repository test asserts that only the helper imports `fcntl`.
- The test-only keyword `state_dir` joins `owner_uid` in the banned keywords, so no plugin code can redirect the ledger.
  The module constructs `Ledger()` without arguments; the location, owner and lock timeout are parameters that only
  unit tests pass.
- Unit tests pin the attribute table and the exemption. Bandit, Ruff and `ansible-test sanity` need no suppression.

The helper's contract:

- `open_directory(path, owner_uid, create=...)` walks the path from `/` one component at a time with
  `O_NOFOLLOW | O_DIRECTORY` relative to the parent descriptor, so no component may be a symlink. The final directory
  must be owned by the expected user (root in production) with no group or world bits; missing components are created
  with mode `0700`. An existing directory is never repaired.
- `SafeDirectory` performs every operation relative to the directory descriptor, so replacing the path afterwards
  has no effect. `read` opens with `O_NOFOLLOW | O_NONBLOCK` and then vets the opened descriptor: regular file, owner,
  no group or world bits, one hard link, size within the bound, and a bound on the bytes actually read.
- `write` creates a temporary file in the same directory (`O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`, forced with
  `fchmod`), checks its owner, writes fully, `fsync`s it, renames it over the target and `fsync`s the directory. On any
  failure, including `KeyboardInterrupt`, the temporary file is removed and the old file is intact. A temporary name that
  already exists is an error and is never unlinked.
- `lock` takes an exclusive `flock` on the directory descriptor with a timeout (30 s), serialising concurrent runs
  without an extra lock file. Closing the descriptor releases it. Record and remove hold the lock across read, modify and
  write; reads rely on the atomic rename and do not lock.
- Failures are `SafeFileError` with a stable reason (`unsafe_path`, `symlink`, `not_regular`, `not_directory`,
  `wrong_owner`, `unsafe_mode`, `hardlinked`, `too_large`, `lock_timeout`, `io_error`, `unsupported_platform`), which the
  module returns as `error_type`. Platforms without directory-relative `open`, `mkdir`, `rename`, `stat` and `unlink`
  are refused rather than degraded.
- Check mode never creates or writes anything: it opens the directory without creating it and computes the result.

### Threat model

| Threat | Mitigation |
|---|---|
| Symlink planted at the ledger, the directory or an ancestor | `O_NOFOLLOW` on every component and on the file; a symlink is `symlink`, nothing is followed or replaced |
| Swap between check and use (TOCTOU) | No check by path: the descriptor that was opened is the one that is vetted and used; the directory is held by descriptor; tests swap the file and the directory during the operation |
| Hard link, FIFO or device as ledger | `st_nlink == 1`, regular file only, `O_NONBLOCK` so a FIFO cannot hang the run |
| Ledger written or read by another user | Owner must be root (injectable only in tests), no group or world bits on file and directory |
| Oversized, deeply nested or hostile JSON | 4 MiB bound before and during reading, recursion errors are `corrupt`, strict parser hooks |
| Torn write or crash | Write-to-temporary, `fsync`, atomic `rename`, directory `fsync`; the old ledger is intact after any failure |
| Lost update from concurrent runs | Exclusive `flock` across read-modify-write, with a timeout instead of an unbounded wait |
| Silent reset hiding applied controls | Corruption is an error; the ledger is never recreated automatically |
| Redirecting the ledger through module arguments | The module has no path or owner argument; `state_dir` and `owner_uid` are banned keywords in plugin code |
| Secret leakage | Sensitive values come from `no_log` options and are redacted from results, diffs and errors; the file is root-only |

Residual risks: an attacker who is root, or who can replace `/`, `/var` or `/var/lib`, already controls the host; the
ancestors are checked for symlinks but not for ownership. Network file systems may not honour `flock`; `/var/lib` is
expected to be local. A crash between creating and renaming a temporary file leaves a hidden `.state.json.<hex>.tmp` of
mode `0600` behind; it is harmless and is not read.

### Tooling consequences

- `ansible-test sanity validate-modules` demands a GPLv3 header in every module, while the collection is Apache-2.0.
  The header is not added, because it would misstate the licence of the file. Instead, `tests/sanity/ignore-2.20.txt`
  and `ignore-2.21.txt` gain exactly `plugins/modules/control_state.py validate-modules:missing-gplv3-license`; the
  repository test that pins the ignore files lists both entries, and every new module needs its own reviewed line.
- `validate-modules` also requires imports below `DOCUMENTATION`, `EXAMPLES` and `RETURN`. Ruff `E402` is therefore
  relaxed for `plugins/modules/**` only, and Pylint `wrong-import-position` is disabled (Pylint has no per-file
  setting), both justified in `pyproject.toml`.
- ansible-core has no `py.typed` marker. `typings/ansible/module_utils/` holds minimal stubs for `AnsibleModule` and
  `patch_module_args`, which Pyright reads as its default `stubPath` and mypy through `mypy_path`. The directory is not
  part of the collection.
