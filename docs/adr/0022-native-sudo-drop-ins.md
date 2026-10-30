# 0022. Native sudo remediation through validated drop-ins

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement that every topic toggle remediates for real and reverts
  exactly what the collection changed)
- **Jira:** FREES-175 (native sudo), FREES-173 (a state that already equals the recorded prior state is restored
  without a write)
- **Pull requests:** introduced by the pull request for FREES-175
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md) (amended
  for the `visudo` check), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0021](0021-native-banners-pwquality-and-profile-values.md), [native remediation guide](../native-remediation-guide.md)

## Context

The `sudo` topic (toggle `linux_compliance_sudo_enabled`, disruptive) holds 22 catalogued rules, all `audit_only`
until now. sudo reads `/etc/sudoers` and, through its `@includedir /etc/sudoers.d` (Ubuntu 24.04) or
`#includedir /etc/sudoers.d` (RHEL 9) line, every file of `/etc/sudoers.d` whose name contains no `.` and does not end
in `~`. A syntax error in any of them makes sudo refuse to run at all, so a broken file can lock every administrator
out of root.

The pinned ComplianceAsCode 0.1.82 content was read per rule (`Profile/select`, OVAL objects and states,
`check-export`, `platform`) in `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml`:

| Rule | Selected by | What the OVAL reads and requires |
|---|---|---|
| `sudo_add_use_pty` | Ubuntu CIS (4); RHEL CIS (4), ANSSI (3), CCN advanced and intermediate, PCI DSS | A line `^[\s]*Defaults\b[^!\n]*\buse_pty.*$` in a file matching `^/etc/sudoers(\|\.d/.*)$`; platform `package_sudo` |
| `sudo_custom_logfile` | Ubuntu CIS; RHEL CIS, PCI DSS | Every `Defaults ... logfile=` line in `/etc/sudoers` or `/etc/sudoers.d/*` names the exported `var_sudo_logfile` (`/var/log/sudo.log` in every profile) |
| `sudo_require_reauthentication` | Ubuntu CIS; RHEL CIS, CCN, PCI DSS, STIG | Exactly one line `^[\s]*Defaults[\s]+timestamp_timeout[\s]*=\s*[+]?<number>$` in `/etc/sudoers` or `/etc/sudoers.d/*` (`only_one_exists`) and none with a negative value. The check exports no value; the content's fixes write the profile's `var_sudo_timestamp_timeout` (15 for CIS, 0 for the STIG, the default 5 for CCN and PCI DSS) |
| `sudoers_validate_passwd` | RHEL STIG | Lines `Defaults !targetpw`, `Defaults !rootpw` and `Defaults !runaspw` in `/etc/sudoers` or `/etc/sudoers.d/*`, and no `Defaults targetpw`, `rootpw` or `runaspw` |
| `file_permissions_etc_sudoers`, `file_owner_etc_sudoers`, `file_groupowner_etc_sudoers` | RHEL ANSSI (3) | `/etc/sudoers` at most `0440`, uid 0, gid of root; a missing file or a symbolic link passes |
| `directory_permissions_etc_sudoersd`, `directory_owner_etc_sudoersd`, `directory_groupowner_etc_sudoersd` | RHEL ANSSI (3) | `/etc/sudoers.d` at most `0750`, uid 0, gid of root; a missing directory or a symbolic link passes |
| `sudo_remove_no_authenticate`, `sudo_remove_nopasswd`, `sudo_require_authentication` | Ubuntu CIS and STIG; RHEL CIS, STIG, E8, ISM, CCN, PCI DSS | No uncommented `!authenticate` or `NOPASSWD:` anywhere in `/etc/sudoers` or in any file of `/etc/sudoers.d` |
| `sudo_restrict_privilege_elevation_to_authorized` | Ubuntu and RHEL STIG | No `ALL ALL=(ALL) ALL` or `ALL ALL=(ALL:ALL) ALL` user specification |
| `sudoers_explicit_command_args`, `sudoers_no_command_negation`, `sudoers_no_root_target` | RHEL ANSSI (3) | No user specification without command arguments, with a negated command, or with a runas list that includes root or `ALL` |
| `sudo_add_noexec`, `sudo_add_requiretty` | RHEL ANSSI (3) | A `Defaults ... noexec` or `Defaults ... requiretty` line |
| `sudo_dedicated_group`, `file_permissions_sudo` | RHEL ANSSI enhanced and high | `/usr/bin/sudo` owned by a dedicated group with gid other than 0, and mode `4110` |
| `package_sudo_installed` | Ubuntu CIS; most RHEL profiles | The `sudo` package is installed |

Every check of a `Defaults` setting reads the drop-ins on both platforms, so one method serves both; the
golden test `tests/unit/tools/test_content_golden_native.py` pins it.

## Decision

### 1. Ten rules are native, each with a recorded value and a strict cleanup

**One drop-in per setting rule** (`sudo_add_use_pty`, `sudo_custom_logfile`, `sudo_require_reauthentication`,
`sudoers_validate_passwd`): `/etc/sudoers.d/50-freesecdev-<setting>`, a name without a dot or a trailing `~`, so sudo
reads it. It holds a header that names the rule, one line saying that switching the rule or the topic off removes it,
and the `Defaults` lines of the rule: `Defaults use_pty`, `Defaults logfile=<var_sudo_logfile>`,
`Defaults timestamp_timeout=<var_sudo_timestamp_timeout>` and the three `!targetpw`, `!rootpw`, `!runaspw` lines. It is
written with `ansible.builtin.copy`, mode `0440`, owner and group root, and `validate: /usr/sbin/visudo -cf %s`, so
the module moves it into place only after `visudo` accepted the temporary file. `/etc/sudoers` and every other drop-in
are never written. The strategy is `recorded_value`: before the first write the ledger records `method: dropin`,
`dropin: null` (the file did not exist) and `dropin_sha256` (the SHA-256 of what is written).

**One recorded attribute per attribute rule** (the six `file_*_etc_sudoers` and `directory_*_etc_sudoersd` rules): the
mode is restricted to `current & 0440` (file) or `current & 0750` (directory), so a stricter mode is kept; owner and
group become uid and gid 0. The ledger records `method: attribute`, the prior attribute (`mode`, `owner` or `group`)
and `written`, the value the collection set, with `ansible.builtin.file` and `follow: false`.

The values follow ADR 0021: `var_sudo_logfile` is exported by the check. `var_sudo_timestamp_timeout` is not, because
the check accepts any non-negative timeout; the catalogue entry therefore sets `profile_value_source: fix`, and
`make catalogue` takes the value that the content's own fixes substitute, refusing generation when they do not
(`tools/roles/profile_values.py`). The profile's `refine-value` stays the only source; nothing is chosen by the
collection. Every value is checked against the rule's `value_pattern` (an absolute path, or one to four digits) and
every line against `^Defaults !?[a-z_]{1,32}(={value})?$` before the family changes anything.

### 2. Apply refuses what it cannot make take effect, and changes nothing then

The family reads `/etc/sudoers` and every file of `/etc/sudoers.d` that it does not own, as the content's checks do:
every regular file, hidden ones and names with a `.` or a trailing `~` included, and every symbolic link whose target
is a regular file, read through the link. It joins every line that ends in `\` with the next one, as sudo does, and
keeps every `Defaults` line with the file it came from and whether sudo reads that file: `/etc/sudoers`, and the files
of `/etc/sudoers.d` whose name has no `.` and does not end in `~`. Revised after the review of PR #62: sudo's
`includedir` follows a symbolic link to a regular file, skips a dangling link and skips names with a `.` or a trailing
`~` (checked with `visudo -c`, which lists every file it parses, and `sudo -V`, which prints the effective
`timestamp_timeout`, for sudo 1.9.15p5 on Ubuntu 24.04 and 1.9.17p2 on Rocky Linux 9). Two sets therefore decide:

- **Conflicts are decided over every file the content's check reads.** A `Defaults` line elsewhere that names one of
  the rule's options in any form other than exactly one of the rule's lines is a conflict, in a file that sudo reads
  (it can override the drop-in) and in one that it skips (it fails the content's check). For `timestamp_timeout`,
  whose check requires exactly one line, any second line is a conflict, and so is a single line in a file that sudo
  skips.
- **`compliant` without a drop-in is decided only over the files that sudo reads.** The rule's lines must be set there
  exactly; a line in `hardening.conf`, `site~` or another file that sudo skips never makes a rule compliant, so the
  drop-in is written (or, for `timestamp_timeout`, the rule conflicts).

A rule reports, with a reason and without any change:

| Status | When |
|---|---|
| `notapplicable` | `/etc/sudoers` does not exist (sudo is not installed; the content's `package_sudo` platform), or the attribute rule's path does not exist |
| `not_regular_file`, `not_directory` | `/etc/sudoers` or the drop-in is a symbolic link or not a regular file; `/etc/sudoers.d` is missing, a symbolic link or not a directory. Nothing is written through a link |
| `not_included` | `/etc/sudoers` has no `@includedir` or `#includedir` line for `/etc/sudoers.d`, so sudo would not read the drop-in while the content's check would pass |
| `validator_missing` | `/usr/sbin/visudo` is not a regular file |
| `not_owned` | A file at the drop-in's path does not start with the collection's header |
| `conflicting_setting` | Another file that the content's check reads sets one of the rule's options (any `Defaults` line, after joining continued lines and normalising whitespace, that names it) in a form other than exactly one of the rule's lines, or, for `timestamp_timeout`, the setting appears anywhere else while the drop-in exists, more than once, or only in a file that sudo skips. The collection does not edit files it does not own, and such a line could override the drop-in or fail the content's check |
| `compliant` | The drop-in already holds exactly the content, or, without a drop-in, the files that sudo reads already set exactly the rule's lines (the `Defaults use_pty` of the Ubuntu 24.04 `/etc/sudoers`) and nothing conflicts; nothing is written or recorded |
| `method_changed` | The ledger entry was recorded by another method; clean it up first |
| `invalid_sudoers` | `visudo` refused the drop-in. Nothing is installed, the ledger entry recorded for it is removed again, and the result names the refusal |

### 3. Cleanup restores exactly what was recorded and never overwrites a later change

Before it removes or restores anything, cleanup checks that the state is still what the collection wrote:

| Reason (`cleanup_incomplete`, entry kept, nothing changed) | When |
|---|---|
| `method_changed` | The entry records another method, or none |
| `not_directory`, `not_regular_file` | The directory or the file is a symbolic link or of the wrong type |
| `not_owned` | The drop-in lost the collection's header |
| `invalid_record` | The recorded SHA-256, prior attribute or written attribute is malformed |
| `modified_since_apply` | The drop-in's SHA-256, or the attribute, is no longer what the collection wrote; an administrator's later change survives |
| `target_absent` | The file or directory of an attribute rule is gone |

When the state already equals the recorded prior state, cleanup reports `restored`, removes the ledger entry and
writes nothing (FREES-173): a drop-in that is already gone, or an attribute that already has its prior value. When the
profile value changes while a rule stays on, apply writes the new drop-in and replaces the entry with the same prior
state and the new `dropin_sha256` after the write succeeded.

### 4. Kept `audit_only`, each with its reason

| Rule | Reason |
|---|---|
| `sudo_remove_no_authenticate`, `sudo_remove_nopasswd`, `sudo_require_authentication` | They need other people's `!authenticate` and `NOPASSWD` lines removed from `/etc/sudoers` and from drop-ins the collection does not own. Automation accounts and break-glass administrators rely on them, so the removal can lock them out, and the removed lines cannot be put back exactly once their files change |
| `sudo_restrict_privilege_elevation_to_authorized`, `sudoers_explicit_command_args`, `sudoers_no_command_negation`, `sudoers_no_root_target` | They rewrite or remove user specifications that grant administrators root; which ones may go is a site decision, and removing the wrong one locks administrators out |
| `sudo_add_noexec` | `Defaults noexec` stops every command run through sudo from executing another program, so `sudo -i`, package managers and Ansible's own `become` (`/bin/sh -c` then Python) stop working; the collection could then not even revert it |
| `sudo_add_requiretty` | `Defaults requiretty` refuses sudo without a terminal. Ansible over SSH without pipelining allocates one (`-tt`) and keeps working, but `become` with pipelining, over a connection without a terminal (`docker exec`, `local`) and every other non-interactive automation stops, again including the run that would revert it. The check (`Defaults\b[^!\n]*\brequiretty`) is satisfied by a narrowly scoped `Defaults:<user> requiretty` too, so a remediation that the check rewards but that changes nothing is possible and was rejected; a real one has to be global |
| `sudo_dedicated_group`, `file_permissions_sudo` | They change the group and mode (`4110`) of `/usr/bin/sudo`, a file of the package, so that only members of a dedicated group can run sudo; with the content's default group `root` the rule cannot pass, and every other user loses sudo |
| `package_sudo_installed` | Package state belongs to the package topics; removing sudo again on cleanup would lock out every administrator who uses it |

### 5. The `visudo` check is the only reviewed `validate`

External validators run through the audited process helper (ADR 0004, amendment of FREES-175). The one exception is
`copy`'s `validate` with exactly `/usr/sbin/visudo -cf %s` in `roles/remediate/tasks/sudo_dropin_apply.yml`
(`ALLOWED_PARAMETERS` of `tools/lint/repo_rules/exec_modules.py`), because the check must run on the temporary file
before the atomic rename, so that a drop-in that sudo cannot parse is never in place, not even briefly. A templated,
quoted, block, aliased or merged value, a free-form argument, `args`, `module_defaults`, another value, module or file
is still refused. The path is fixed, so no variable can choose the executable. `copy` runs it through `run_command`,
without the timeout of ADR 0004; that is an accepted residual, because `visudo -cf` parses one small local file.

## Benefits

Every sudo rule that can be remediated without editing what administrators own is now native on both platforms, with
the profile's values and an exact revert; the drop-ins cannot break sudo because `visudo` checks them before they are
moved in place.

## Trade-offs

A host whose `/etc/sudoers` already sets a rule's option in another form (for example `Defaults env_reset,use_pty`)
gets `conflicting_setting` instead of a drop-in; the comparison is by normalised line, after joining continued lines,
not by sudoers grammar. Two refusals are stricter than sudo needs and are accepted: an administrator's later identical
`timestamp_timeout` line next to the drop-in, and a setting in a file that sudo skips but the content's check reads,
are `conflicting_setting`. A partial set of the `!targetpw`, `!rootpw` and `!runaspw` lines elsewhere no longer
conflicts; the drop-in then holds all three. sudo
writes `/var/log/sudo.log` once `logfile` is set; the log is sudo's, not the collection's, and cleanup does not remove
it. The fix-sourced timeout is not compared by the audit, so an operator can lower it by hand without the audit
noticing; cleanup then keeps the change as `modified_since_apply`.

## Security implications

The drop-ins are validated by `visudo`, root-owned, mode `0440` and written without following a link. The collection
never removes a line that grants or restricts privileges, so it cannot lock out an administrator through the sudoers
policy; the strictest settings it writes (`timestamp_timeout=0` for the STIG) only make sudo ask for the password every
time. `/etc/sudoers` lines after its `includedir` and files that it `@include`s outside `/etc/sudoers.d` are read by
sudo but not by the content's checks or the family; a later `Defaults` there can still override a drop-in, which is a
residual of the content's checks as well. `sudo` stays disruptive: it is applied and cleaned up only with `sudo` in
`linux_compliance_remediate_allow_disruptive`.

## Operational consequences

The Molecule images install `sudo` (pinned) so that the lifecycle runs on both platforms. The CIS profiles of the
lifecycle select `sudo_add_use_pty`, `sudo_custom_logfile` and `sudo_require_reauthentication`; the other seven native
rules are applied, made idempotent and cleaned up for real by `shared/tasks/lifecycle_sudo_other_profiles.yml` in the
topic legs. `shared/tasks/lifecycle_sudo_regressions.yml` (rule legs) covers a change of method and a drop-in changed
and one removed by hand, and `shared/tasks/lifecycle_sudo_refusals.yml` (topic legs) a setting of the administrator, a
`visudo` that refuses every file and a symbolic link in place of `/etc/sudoers.d`. On Ubuntu,
`lifecycle_sudo_states.yml` covers `not_included`, `validator_missing`, `not_owned` at apply and at cleanup,
`not_regular_file` for a drop-in path, `invalid_record` and `target_absent`, and `lifecycle_sudo_effective.yml` the
files that sudo skips, continued lines and a linked drop-in. After an apply, a module runs with `become: true`, which
proves that sudo still parses the whole policy and writes the `logfile` that the drop-in set. The containers drop every capability, so the owner and group rules are
proven compliant on the root-owned files and are not changed there.
