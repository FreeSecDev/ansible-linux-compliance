# 0027. Native account lock-out and password reuse, one recorded line per setting

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement that every rule is our own Ansible, can be toggled per topic
  and per rule, really remediates and reverts exactly what the collection changed)
- **Jira:** FREES-186 (native faillock and pwhistory), FREES-111 (PAM and password policy), FREES-173 (a state that
  already equals the recorded prior state is restored without a write), FREES-181 (login and sudo checks in the libvirt
  cycles)
- **Pull requests:** introduced by the pull request for FREES-186
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0011](0011-control-toggles-and-cleanup.md), [ADR 0021](0021-native-banners-pwquality-and-profile-values.md)
  (profile values, the line method of the pwquality main file), [ADR 0022](0022-native-sudo-drop-ins.md) (regression
  groups), [native remediation guide](../native-remediation-guide.md)

## Context

The `faillock` topic (14 rules) and the `pwhistory` topic (7 rules), both disruptive and under the `pam` umbrella, were
`audit_only`. linux-pam reads two configuration files for them: `pam_faillock` reads `/etc/security/faillock.conf`
(`deny`, `unlock_time`, `fail_interval`, `even_deny_root`, `root_unlock_time`, `audit`, `silent`, `dir` and others) and
`pam_pwhistory` reads `/etc/security/pwhistory.conf` (`remember`, `enforce_for_root`, `retry`, `file`). An argument on
the module's line in the PAM stack takes precedence over the file. Both images ship both files with every setting
commented out, and neither image loads either module in its stack: Ubuntu 24.04 ships no pam-auth-update profile for
them, and the Rocky Linux 9 container has no authselect at all.

The pinned ComplianceAsCode 0.1.82 content was read per rule in `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml` (the
selecting profiles, the OVAL objects, states and variables that each definition reaches, `check-export` and
`platform`):

- Every faillock setting rule (`deny`, `unlock_time`, `interval`, `root_unlock_time`,
  `even_deny_root_or_root_unlock_time`, `deny_root`, `audit`, `silent`) has the same form on both platforms: the
  module must be in the stack (preauth and authfail lines around `pam_unix` in `common-auth` and an account line in
  `common-account` on Ubuntu; the same in `system-auth` and `password-auth` on RHEL), and then **either** the setting is
  on the module's line and not in `faillock.conf`, **or** it is in `faillock.conf` and not on the module's line. The
  file is read with `^[\s]*<setting>[\s]*=[\s]*([0-9]+)` (a flag with `^[\s]*<setting>`), the first instance on
  Ubuntu, and compared with the profile's value: `deny` at most the value and at least 1, the times at least the value.
- The RHEL pwhistory rules `accounts_password_pam_pwhistory_remember_password_auth` and `_system_auth` have the same
  form for `remember` in `pwhistory.conf` (`^\s*remember\s*=\s*([0-9]+)`, at least `var_password_pam_remember`) and need
  `pam_pwhistory` in `password-auth` or `system-auth`; `accounts_password_pam_pwhistory_enforce_for_root` reads only
  `^[\s]*enforce_for_root[\s]*$` in `pwhistory.conf`.
- The Ubuntu pwhistory rules (`accounts_password_pam_pwhistory_enabled`, `_enforce_root`, `_remember`, `_use_authtok`)
  read only the `pam_pwhistory` line of `/etc/pam.d/common-password`; none reads `pwhistory.conf`.
- `accounts_passwords_pam_faillock_dir` (RHEL STIG) reads `dir` in `faillock.conf` but exports no value, and
  `account_password_selinux_faillock_dir` requires the SELinux type `faillog_t` on that directory.
- `accounts_passwords_pam_faildelay_delay` (Ubuntu STIG) reads `delay=` on the `pam_faildelay` line of `common-auth`.

No container scan can show these rules pass: Rocky Linux is not RHEL to the RHEL 9 datastream's platform check, so
every RHEL rule is `notapplicable` there, and both contents put the faillock rules below a group with the platform
`system_with_kernel` (`locking_out_password_attempts`), which excludes containers; an Ubuntu container scan reports
`accounts_passwords_pam_faillock_deny` `notapplicable` even with `pam_faillock` in the stack.

## Decision

### 1. One recorded line per setting in the module's own configuration file

Both families write the configuration file in place, as `pwquality` does with its main file (ADR 0021) and as the
login.defs topic of FREES-185 does: `ansible.builtin.lineinfile` replaces the one line of the setting in its place, or
appends it when the setting is absent. The written line is `<setting> = <value>`, or the bare `<setting>` for a flag.
Every native rule is `recorded_value`; before its first write the ledger records `method: line`, `setting_line` (the
line as it was, or `null`), `written_line` and the `mode`, `owner`, `group` and `sha256` of the file. Lines are found
as pam reads them: the setting's name after leading blanks, with or without `=`; commented lines never count and are
never touched. The family files `faillock.yml` and `pwhistory.yml` name their file, module and stack type and share
three helpers, `pam_conf_prepare.yml`, `pam_conf_apply.yml` and `pam_conf_cleanup.yml`, which use only
`ansible.builtin` modules and the ledger module; no external program runs, so ADR 0004 is unchanged.

Values come from the profile (`profile_value` in `content/catalogue.yml`): `var_accounts_passwords_pam_faillock_deny`,
`_unlock_time` (`0`, never, for the STIG profiles), `_fail_interval`, `_root_unlock_time` and `var_password_pam_remember`.
A line counts as compliant only in the strict form that both pam and the check read (one decimal number without a
leading zero or a trailing comment, or the bare flag) and when it satisfies the check's comparison; a stricter value is
kept, also when its line had another form (`deny = 03 # site` under a maximum of 4 becomes `deny = 3`).
`even_deny_root_or_root_unlock_time` writes `root_unlock_time` (the value it exports) and is also compliant with a
strict `even_deny_root` line, the check's other branch.

The two RHEL `remember` rules share one line. The first rule that writes it records the prior state; the second, in
the same run, records the same prior state without writing again. When one of them is switched off, its cleanup
restores the prior line and the other rule, still on, writes it again and keeps the ledger entry; when both are
switched off, the first cleanup restores the line and the second finds the prior state already there (FREES-173).

Apply reports, with a reason and without a change:

| Status | When |
|---|---|
| `notapplicable` | The file does not exist (the PAM package that ships it is not installed); nothing is created |
| `not_regular_file` | The file is a symbolic link or not a regular file; nothing is written through a link |
| `overridden` | A `pam_faillock` (`auth`) or `pam_pwhistory` (`password`) line of `/etc/pam.d/common-auth`, `common-password`, `system-auth` or `password-auth` sets the option (or the alternative flag): pam takes the module's argument over the file and the check then fails with the file's line, so the collection writes nothing and does not edit the stack. Only for rules whose check reads the stack line (`stack_checked`) |
| `duplicate_setting` | The file sets the setting on more than one line; pam takes the last and the Ubuntu check the first |
| `method_changed` | The ledger entry was recorded by another method; clean it up first |
| `compliant` | Exactly one strict line satisfies the check; nothing is written or recorded |

When the profile value changes while a rule stays on, apply writes the new line and records it with the same prior
state.

### 2. Cleanup restores exactly the recorded line and never overwrites a later change

| Result | When |
|---|---|
| `restored`, nothing written | The file already holds the recorded prior state of the setting (no line, or exactly the prior line), for example a line that the collection added and an administrator removed again, or the line of a shared setting that the other rule's cleanup restored (FREES-173); the entry is removed |
| `restored` | The setting is on exactly one line equal to `written_line` and the mode, owner and group are the recorded ones: the prior line is written back in its place, or the line is removed |
| `cleanup_incomplete` (`method_changed`, `target_absent`, `not_regular_file`, `invalid_record`, `modified_since_apply`) | Another method, a missing or linked file, a malformed record, or a change by hand since the apply; nothing is changed and the entry is kept |

With every rule cleaned up the file is byte for byte what it was; a file without a final newline gets one when a line is
appended, and both images end both files in a newline.

### 3. The PAM stack stays with the administrator; the rules that change it stay `audit_only`

The settings take effect only where the stack loads the module. The rules that put the module into the stack were
weighed against the three conditions of FREES-186 (native modules only, an exact revert, a lock-out guard with a login
and sudo check before and after) and are kept `audit_only`:

| Rule | Reason |
|---|---|
| `accounts_passwords_pam_faillock_enabled` (Ubuntu), `account_password_pam_faillock_password_auth`, `account_password_pam_faillock_system_auth` (RHEL) | Enabling `pam_faillock` means `authselect enable-feature with-faillock` on RHEL, a program that needs the audited process helper and an ADR 0004 amendment, and that is not installed in the Rocky Linux container; on Ubuntu it means a pam-auth-update profile of our own and `pam-auth-update`, which regenerates every `common-*` file and refuses or overwrites files changed by hand, so the revert is not exact. A stack that locks accounts out must also be proven with a real login and `sudo` before and after, which needs the libvirt cycles of FREES-181, not yet built. Follow-up: a libvirt-only `pam` stack topic once FREES-181 lands |
| `accounts_password_pam_pwhistory_enabled`, `_enforce_root`, `_remember`, `_use_authtok` (Ubuntu) | The Ubuntu content reads these settings only on the `pam_pwhistory` line of `common-password`, which pam-auth-update generates and which does not load the module; writing `pwhistory.conf` would not satisfy the check, and editing the stack has the same problems as above |
| `accounts_passwords_pam_faildelay_delay` (Ubuntu STIG) | The delay is an argument of `pam_faildelay` on a line of `common-auth`, which pam-auth-update owns |
| `accounts_passwords_pam_faillock_dir` (RHEL STIG) | Its check exports no value, so the catalogue has no profile value for it (the XCCDF value `/var/log/faillock` is only named in the description), and a persistent tally directory needs the `faillog_t` SELinux context of `account_password_selinux_faillock_dir`; under SELinux enforcing, `pam_faillock` cannot write a mislabelled directory and authentication can fail |
| `account_password_selinux_faillock_dir` (RHEL STIG, tag `selinux`) | Setting a file context needs `semanage fcontext` and `restorecon`, which are not `ansible.builtin` modules, and a revert of the policy store |
| `accounts_password_pam_unix_remember` (`pam`, tag `pwhistory`) | It stays in `pam`, whose former toggle and allow-list entry the legacy fixture pins; it reads the same `remember` line of `pwhistory.conf` with another value (`var_password_pam_unix_remember`), and in the PCI DSS profile, the only one that selects both, the pwhistory rules write the same value |
| `accounts_password_pam_unix_no_remember` (`user_accounts`, tag `pwhistory`) | It requires that no `pam_unix` line of the stack carries `remember=`; removing an option from a stack file the collection does not own is not exactly revertable. Both images comply |

No pinned rule reads `retry` in `pwhistory.conf`.

## Benefits

Eight faillock rules and three pwhistory rules are native with the profile's values, a toggle per rule and per topic,
an exact revert and refusals that never claim a change that would not take effect. The golden test
`tests/unit/tools/test_content_golden_pam_conf.py` pins, against the OVAL of both datastreams, that every written line
satisfies the object and the comparison of the check that reads the file (and that the commented line does not), that
the compared value is the catalogue's value, that `stack_checked` is true exactly when the check reads the module line,
that the role's detector (`__linux_compliance_remediate_pam_option_pattern`) finds every module line that the check's
pattern finds, that the role reads every stack file in which a check reads a setting, and that no other catalogued rule
reads either file, so a content update that moves a check fails CI until the families follow.

## Trade-offs

A host that does not load `pam_faillock` or `pam_pwhistory` gets the settings written but not enforced, and its scan
still fails the rules until the stack is enabled; the collection does not claim otherwise, and the stack rules list the
missing piece. A trailing comment on a setting's line is rewritten, because the check does not read it as a strict
value; the cleanup puts the commented line back. `lineinfile` replaces the inode; the content, mode, owner and group
are restored, the inode and the times are not.

## Security implications

Where the stack loads the module, the settings lock an account after failed logins (`deny`), keep it locked
(`unlock_time`, and for the STIG profiles `0`, until an administrator runs `faillock --reset`), lock root as well
(`even_deny_root`, `root_unlock_time`) and reject reused passwords (`remember`, `enforce_for_root`). These can lock
administrators out, so both topics are disruptive: they are applied and cleaned up only with `faillock`, `pwhistory` or
`pam` in `linux_compliance_remediate_allow_disruptive`. Nothing is written through a symbolic link, the PAM stack is
only read, and the prior lines stored in the root-only ledger come from world-readable files.

## Operational consequences

The Molecule lifecycle declares both topics (`extensions/molecule/shared/vars/topics/faillock.yml`,
`pwhistory.yml`). `faillock` runs on both platforms from the as-built file and from a file that an administrator
customised (a looser `deny=10` in place of the commented default and a stricter `unlock_time = 1800`, which stays
`compliant`), and checks the SHA-256 of the whole file after the apply and the exact restore. `pwhistory` runs on Rocky
Linux only (`unselected_platforms: ubuntu`, because no Ubuntu pwhistory rule is native), from the as-built file and
from `remember=5`. The cycles do not scan, because a container scan reports every rule `notapplicable` (see the
context); the SHA-256 of the whole file after the apply and the golden test are the evidence. A real scan of a host
whose stack loads the modules needs the libvirt cycles of FREES-181. Regression groups, each a CI leg:
`faillock` `changes` (a change of method, a stricter value and a removed line by hand, a duplicate line, a zero-padded
value with a comment, a commented default, a symbolic link, a missing file), `stack` (the stack that authselect or a
pam-auth-update profile writes, loaded for the run: both rules apply and add exactly their lines; with
`deny=3` on the module line `deny` is `overridden` and only `unlock_time` is written; the stack files are put
back), `profiles` (the STIG and CIS level 2 rules that the lifecycle profiles do not select, in check mode, applied,
repeated and cleaned up byte for byte), and `pwhistory` `changes` (the shared `remember` line with one rule switched off
and on, a change of method, a change by hand, a line removed by hand and `remember=` on the `pam_pwhistory` line of
`system-auth`).
