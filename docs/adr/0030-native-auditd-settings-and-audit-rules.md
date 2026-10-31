# 0030. Native auditd settings and audit rule drop-ins

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirements that every topic toggle remediates for real and reverts
  exactly what the collection changed, that topics are fine-grained, and that every remediation is the collection's
  own Ansible, never the content's fix code)
- **Jira:** FREES-110
- **Pull requests:** introduced by the first pull request for FREES-110; the remaining audit rule groups follow in
  further pull requests that amend this record
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0021](0021-native-banners-pwquality-and-profile-values.md),
  [native remediation guide](../native-remediation-guide.md)

## Context

The `auditd` family held 206 catalogued rules, all `audit_only`, the largest family of the catalogue. The pinned
ComplianceAsCode 0.1.82 datastreams (`ssg-ubuntu2404-ds.xml`, `ssg-rhel9-ds.xml`) were read rule by rule: profiles,
groups, OVAL definitions, exported values and platforms. Only the checks were read; no fix content of the datastreams
(Ansible, Bash, Kickstart) was executed, imported, generated, copied or parsed, and no rule line or setting below comes
from it.

What the checks read:

- **Audit rules.** Every rule of the group `audit_time_rules` (and of the other rule groups)
  decides first, from `/usr/lib/systemd/system/auditd.service`, whether the host loads its rules with `augenrules`
  (`ExecStartPost=-/sbin/augenrules`, as both Ubuntu 24.04 and RHEL 9 ship it) or with `auditctl`. With `augenrules`
  it reads every file that matches `^/etc/audit/rules\.d/.*\.rules$`; otherwise `/etc/audit/audit.rules`. No check
  reads the rules that the kernel has loaded (`auditctl -l`); that is the runtime effect, which the libvirt scenarios
  prove below.
- **Both system call tables.** A system call rule needs a `-F arch=b32` line on every architecture and a `-F arch=b64`
  line on 64-bit hosts (`audit_rules_time_adjtimex`, `_clock_settime`, `_settimeofday`); `stime` exists only in the
  32-bit table and its check reads only the `b32` line.
- **Two spellings of a file watch.** Ubuntu checks `-w <path> -p wa` (`audit_rules_time_watch_localtime`, and the
  login record watches of the next topic); RHEL 9 checks the system call form with both tables,
  `-a always,exit -F arch=b32 -F path=<path> -F perm=wa` and the `b64` line.
- **auditd.conf.** The 20 settings of the group `configure_auditd_data_retention` that live in
  `/etc/audit/auditd.conf` match `^[ ]*<setting>[ ]+=[ ]+(\S+)[ ]*$` (some with `[ \t]` and a case-insensitive key),
  mostly on the first occurrence, against the profile's value (an alternation such as `halt|single` for the CIS disk
  actions), a fixed value (`SYSLOG|SINGLE|HALT` for the STIG variants) or a minimum (`max_log_file`, `space_left` with
  `%`). `write_logs` also passes when the setting is absent.

What auditd and `auditctl` do, measured on Ubuntu 24.04 (audit 3.1.2) and Rocky Linux 9.8 (audit 3.1.5) virtual
machines:

- `augenrules --load` joins the files of `/etc/audit/rules.d` and runs `auditctl -R`, which stops at the first error
  and leaves every later rule unloaded: a rule held twice (`Rule exists`), a watch below a directory that does not
  exist, or an unknown system call. `augenrules` copies the previous generated file to `/etc/audit/audit.rules.prev`.
- With the rules locked (`-e 2`, `enabled 2`), every change fails until the next boot.
- auditd has no configuration test. On `SIGHUP` it keeps the old configuration when the new one is invalid, but it
  then fails to start at the next boot: `space_left` not larger than `admin_space_left` (percentages are converted
  with the size of the log's file system), incremental flushing with `freq = 0`, an unknown value, or a line without
  spaces around `=` (`Missing equal sign`, after which no further line is read). `email` without a mail transport only
  logs a warning.

## Decision

### 1. Fine-grained topics below the umbrella `auditd`

The rule groups of the catalogue become families with the umbrella `auditd`, so `linux_compliance_auditd_enabled:
false` still switches every audit topic off, while each topic and rule has its own toggle. Family names cannot start
with `audit_` (that is the namespace of the audit role's variables), so they start with `auditd_`. This pull request
adds two, with the drop-in framework that every later audit rule topic reuses:

| Family | Group | Disruptive | Rules |
|---|---|---|---|
| `auditd_conf` | `configure_auditd_data_retention` | yes, pinned in `DISRUPTIVE_FAMILIES` | 20 native, 4 `audit_only` |
| `auditd_rules_time` | `audit_time_rules` | yes, pinned in `DISRUPTIVE_FAMILIES` | 5 native |

`auditd` keeps the other 177 rules as `audit_only` until their topics follow. Every family split from a disruptive
family stays disruptive (ADR 0011), and so are the audit topics: loading a rule topic reloads the whole rule set, and
with the panic failure mode (`-f 2`) more events can stop the host when the backlog overflows; the auditd.conf topic
can halt the host or drop it to single-user mode through its disk actions. The immutable rule (`-e 2`) will be a topic of its own,
disruptive, because it makes every later change of the loaded rules wait for a reboot (section 6).

The split takes the registry past the bound of 64 families that ADR 0011 set for the parsed registry
(`toggles.MAX_FAMILIES`): the remaining audit rule groups add a family each, and other topics are being split the
same way. The bound rises to 256. That leaves room for those splits and still keeps a hostile catalogue from growing
the plan without limit.

### 2. One drop-in per audit rule, with our own lines

Each rule writes `/etc/audit/rules.d/50-freesecdev-<rule>.rules` (mode `0600`, root), with the collection's header and
exactly the rule lines that the check requires. The lines are written by the collection from the check's pattern and
the system call tables, per benchmark (`lines` in `content/catalogue.yml`, keyed by benchmark identifier), in one
spelling: single spaces, `-k <key>`, `auid!=unset`. They are `-w <path> -p wa -k <key>` on Ubuntu and the two system
call lines on RHEL 9 for a watch, `b32` and `b64` lines for a system call, and use the key `time-change`. A rule
whose check exports a value (the lock-out directory of the next topic) substitutes the profile's value
(`profile_value`, `value_pattern`) into its lines. The lines must match the strict form `__linux_compliance_remediate_audit_line_pattern` of the role, which
refuses control lines (`-D`, `-e`, `-f`, `-b`) and anything else. The golden test
`tests/unit/tools/test_content_golden_auditd.py` pins them: for every rule and pinned datastream that selects it, every
test of the check that reads the drop-in must be matched by a line of the drop-in, with the value of every profile, and
the lines must match the role's form. The lines are written for the x86_64 system call tables; on another architecture
a rule is `notapplicable` with that reason.

Before a drop-in is written, the family reads every file that `augenrules` reads with the module `audit_control`
(below) and refuses what would break the rule set or claim a change that does not happen:

- `compliant`, nothing written and nothing recorded, when every line of the rule is already in another file (an
  administrator's file that holds the same rule);
- `duplicate_rule` when only some of the lines are elsewhere, or when they are elsewhere and the drop-in exists too:
  writing or keeping the drop-in would make `auditctl` stop at the repeated rule;
- `watch_target_missing` when the directory of a watched path does not exist, which the kernel refuses;
- `notapplicable` without `/etc/audit/rules.d` (no audit package), `not_directory`, `not_regular_file`, `not_owned`
  (a file at the drop-in's path without the header) and `method_changed`.

### 3. Loading: checked first, verified after, rolled back when it fails

The module `freesecdev.linux_compliance.audit_control` runs the audit tools through the audited process helper in
exact argument forms only (ADR 0004 amendment of FREES-110): `auditctl -s`, `auditctl -l`, `auditctl --signal reload`
and `augenrules --load`. After the drop-ins of a topic changed, and only where `service_facts` reports `auditd.service`
running and the rules are not locked, the family calls it with `action: load`:

1. it reads every file of `/etc/audit/rules.d` again and refuses to load when two places hold the same rule
   (normalised as in section 2), because `auditctl -R` would stop there;
2. it runs `augenrules --load`, exactly what `auditd.service` runs at boot, so the rules loaded now are the rules
   loaded at the next boot;
3. it reads `auditctl -l` and checks that every line of the topic's applied rules is loaded. `auditctl -l` lists a
   rule in the kernel's spelling (`-F key=`, `auid!=-1`, and for a rule without `-S` the system calls that the kernel
   derives from its fields), so the comparison reads both sides in one spelling and ignores the derived system calls.

When the load is refused or fails, the run removes the drop-ins it created and writes back the ones it rewrote, puts
back their ledger entries, loads the rule set again and fails with both messages; a drop-in that a cleanup of the run
removed stays removed, because that is its prior state. `augenrules` leaves `/etc/audit/audit.rules.prev`; the family
puts that file back as it was before the load (its content, mode and owner, or its absence), so a cleanup leaves the
host as it was. With the rules locked, the files change and the result says that they take effect at the next boot;
without a running auditd (the containers), the files change and the rules load when auditd starts. Check mode never
loads.

### 4. auditd.conf: one line per setting, checked together

Each `auditd_conf` rule owns one setting of `/etc/audit/auditd.conf` (`recorded_value`, method `conf_line`). The
value is the profile's (`profile_value`) or the check's fixed value. An alternation is written as its first choice in
the collection's order `syslog`, `email`, `rotate`, `keep_logs`, `hostname`, `fqd`, `numeric`, `single`, `halt`, least
disruptive first: the STIG `SYSLOG|SINGLE|HALT` actions become `syslog`, the CIS `halt|single` disk-full action becomes
`single`. A choice that offers none of these is `unsupported_value`. A minimum keeps a larger value already set.

The line is written as `<setting> = <value>`, replacing the one line that sets it or appended when none does. The rule
is `compliant` when that one line already has the form the check reads and a value it accepts, `duplicate_setting`
when the setting is set more than once (the check reads the first occurrence, auditd keeps the last), and
`prior_too_large` for a line above 1024 characters. Before anything is written, the settings that auditd checks
together are computed as they will be after the run, from the file and auditd's defaults: `space_left` must be larger
than `admin_space_left` (in percent of the log's file system, whose size `audit_control` reads, when one of them is a
percentage), and incremental flushing needs `freq` above 0. When auditd would refuse them, every line of the run is
`invalid_config` and nothing is written. After a change, a running auditd is asked to read the file again
(`auditctl --signal reload`), and the run fails when the same auditd does not run afterwards.

### 5. The ledger and cleanup

The ledger records the method (`rules_file` or `conf_line`). A drop-in records `dropin: null` and its SHA-256; a
setting records `setting`, `prior_line` (the original line, or `null` when the setting was absent) and
`written_line`. Cleanup removes a drop-in only with the recorded SHA-256 and the header, and writes a line back only
while the file holds exactly the line written; otherwise the result is `cleanup_incomplete` with `modified_since_apply`,
`not_owned`, `not_regular_file`, `target_absent`, `invalid_record` or `method_changed`, nothing changes and the entry
is kept. A drop-in that is already gone, or a setting that is already back at its recorded prior line, is `restored`
by removing the entry, without a write (FREES-173).

### 6. Rules kept `audit_only`, and the immutable rule

| Rules | Why |
|---|---|
| The other rule groups of `auditd` (login and lock-out records, privileged commands, DAC and file modification, file deletion, kernel modules, execution of SELinux and ACL tools, session, user and group, sudoers, MAC, network, media export, system administration and SUID, cron, journal, shutdown, and the OSPP policy rules with their per-architecture variants) | Follow in later pull requests of FREES-110 with the drop-in method of this record; `audit_rules_privileged_commands` needs the list of SUID and SGID programs of the host and its check excludes containers |
| `audit_rules_immutable` (`-e 2`) | Follows as a disruptive topic of its own: once loaded, no rule change takes effect until the next boot, so its cleanup can remove the drop-in but cannot unlock the running kernel; the revert is therefore only effective after a reboot, which the topic will say in every result |
| `audit_immutable_login_uids`, `audit_basic_configuration` | Follow with the control lines (`--loginuid-immutable`, `-b`, `-f`), which change the whole rule set's behaviour |
| `auditd_audispd_configure_remote_server` | The remote log server is site-specific; the profile's default `logcollector` is a placeholder |
| `auditd_audispd_syslog_plugin_activated` | Another file, `/etc/audit/plugins.d/syslog.conf`; follows with a plugin method |
| `auditd_audispd_configure_sufficiently_large_partition` | No automated check; the size of the remote storage is an organisational decision |
| `auditd_offload_logs` | Needs a site-specific weekly offload script |
| `grub2_audit_argument`, `grub2_audit_backlog_limit_argument` | Kernel command line; belong to the boot loader method |
| `package_audit_installed`, `package_audit-libs_installed`, `package_audispd-plugins_installed`, `package_audit-audispd-plugins_installed`, `service_auditd_enabled` | Package and service state; follow with the package and service methods |
| The modes and owners of the audit configuration, binaries and logs (`file_permissions_*`, `file_ownership_*`, `directory_*_var_log_audit`) | Attribute rules; follow with the attribute method of the sudo topic, the ownership cases in the libvirt scenarios |

### 7. The lifecycle harness

- A declaration may name `profiles`, the profile per platform with which the topic's cycles, scans and regressions run
  (the default lifecycle profiles, CIS level 1, select no audit rule). The harness discovers that profile at the start
  of the topic and the platform's own profile again at its end; `check_lifecycle_topics.py` refuses a profile that the
  platform's datastream does not have. `auditd_conf` runs with `cis_level2_server` (Ubuntu) and `stig` (Rocky Linux),
  `auditd_rules_time` with `cis_level2_server` and `e8`. The remediate, audit and verify roles refuse profile identifiers
  with a hyphen (`pci-dss`), so that profile cannot be used yet; `auditd_data_retention_space_left`, which only
  `pci-dss` selects, is therefore proven by the golden test and not yet by a lifecycle cycle.
- A new state category, `audit_rules`, records per line whether the kernel has loaded it (`audit_control` `status`).
  Its items name the drivers that can record them, `drivers: [libvirt]`, because the containers cannot read the
  kernel's audit rules; `check_lifecycle_topics.py` refuses such an item without drivers or with Docker.
- The Docker images ship the audit packages (pinned), so the files part runs in the containers, where auditd does not
  run and nothing is loaded. The Ubuntu cloud image lacks auditd, so the libvirt pins gain `auditd` and
  `libauparse0t64` 1:3.1.2-2.1ubuntu0.1 from the signed `noble-updates` index; Rocky Linux ships `audit` running.
- `auditd_rules_time` has a libvirt pre-state in both modes: its cycles load the rules in a real kernel, check every line
  with `auditctl -l` after apply and its absence after cleanup, and compare `/etc/audit/audit.rules` (rewritten by
  `augenrules`) and `audit.rules.prev` with their state before. `auditd_conf` proves its file in Docker; its reload was
  run by hand on the virtual machines of both platforms. A further Docker pre-state of the time topic adds an
  administrator's file that already holds the time zone watch: that rule is `compliant` and writes nothing.
- Regression groups (one Docker leg per platform): `auditd_rules_time` `changes` (method flip, a change by hand
  kept, a drop-in removed by hand `restored` without a write, an administrator's file with the same rule next to the
  drop-in, alone and in part) and `auditd_conf` `changes` (method flip, a change by hand kept, a line
  put back by hand `restored` without a write, a repeated setting, settings that auditd refuses together on Rocky
  Linux, and the rules that only the other profiles of each datastream select, with their values).

## Benefits

- 25 rules remediate for real and revert exactly, with the profile's values, and no rule line or setting comes from
  the content's fix code.
- The rule set is never left half loaded by the collection: duplicates are refused before writing and before loading,
  and a failed load is rolled back.
- The drop-in framework and the harness extensions carry the remaining audit rule groups without new mechanisms.

## Trade-offs

- `augenrules` is a shell script of the audit package; the helper runs it with one fixed argument, as `auditd.service`
  does, rather than reimplementing how it joins the files.
- Two rules that differ only in a spelling the normalisation does not cover (a reordered field list) are not found
  before the load; the load then fails and is rolled back.
- The choice order for alternations is the collection's: it prefers the least disruptive value that the profile
  allows, which an operator who wants `halt` must set by hand.

## Security implications

- `audit_control` runs only the four exact forms; `auditctl` cannot delete, add or lock rules through it, and no
  argument comes from a variable. The executables are resolved in the trusted directories like `oscap`.
- The drop-ins are root-owned `0600`; the lines are checked against a strict form before they are written, so no
  control line can reach the rule set through the catalogue.
- `auditd_conf` is disruptive and needs the allow-list for apply and cleanup; the settings are the profile's.
- The threat model gains the auditd section ([threat model](../security/threat-model.md#auditd-settings-and-audit-rules-on-a-managed-host)).

## Operational consequences

- Enabling the rule topics adds audit events and loads the whole rule set of `/etc/audit/rules.d` again; an
  administrator's file with a broken rule makes the load fail, which the run reports and rolls back.
- With the rules locked, changes take effect at the next boot.
- CI gains 8 Docker cycle legs, 4 regression legs and 4 libvirt legs; FREES-189 (planning only the affected legs) will reduce
  what each pull request runs.
