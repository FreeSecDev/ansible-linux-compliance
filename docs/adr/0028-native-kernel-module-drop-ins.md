# 0028. Native kernel module remediation through modprobe drop-ins

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirements that every topic toggle remediates for real and reverts
  exactly what the collection changed, with the collection's own Ansible only and never the content's fix code)
- **Jira:** FREES-190 (native kernel module topics), FREES-173 (a state that already equals the recorded prior state is
  restored without a write)
- **Pull requests:** introduced by the pull request for FREES-190
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0022](0022-native-sudo-drop-ins.md), [native remediation guide](../native-remediation-guide.md)

## Context

The `kernel_modules` umbrella holds three disruptive topics, all `audit_only` until now: `filesystem_modules` (cramfs,
freevxfs, hfs, hfsplus, jffs2, overlayfs, squashfs, udf and usb-storage; 9 rules), `protocol_modules` (atm, can, dccp,
firewire-core, rds, sctp, tipc; 7) and `wireless_modules` (bluetooth, cfg80211, iwlmvm, iwlwifi, mac80211; 5). The
catalogue has no other usb-storage rule; `grub2_nousb_argument` and `bios_disable_usb_boot` belong to `bootloader`.

The pinned ComplianceAsCode 0.1.82 content was read per rule (`Profile/select`, `platform`, `check-export`, OVAL
definition, tests and objects) in `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml`. Every one of the 21 rules has the
same check on both platforms, with only the module name changing:

- The definition is an `OR` with a single `AND` of two `textfilecontent54_test`s, both `check="all"` with the default
  `check_existence` (`at_least_one_exists`) and no state. So both tests must find at least one matching line.
- One object matches `^\s*install\s+<module>\s+(/bin/false|/bin/true)$`, the other `^blacklist\s+<module>$`, in any
  file matching `^.*\.conf$` of at least one of `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/lib/modprobe.d`,
  `/etc/modules-load.d`, `/run/modules-load.d` and `/usr/lib/modules-load.d`. The two lines may be in different files.
- No check exports a value, so no profile value is involved.
- Nothing in the check reads the running kernel: neither `lsmod` nor `/proc/modules` nor `/sys/module`. A loaded module
  does not fail it, and unloading one does not make it pass.
- The rule of `overlayfs` names the module `overlay`. The Ubuntu 24.04 datastream has no rule for atm, can,
  firewire-core or the five wireless modules; the RHEL 9 datastream has no overlayfs rule.
- Every rule is limited to the `system_with_kernel` platform, which excludes containers: the file system and wireless
  rules carry it themselves, the protocol rules through their group `network-uncommon`.

| Topic | Ubuntu 24.04 profiles | RHEL 9 profiles |
|---|---|---|
| `filesystem_modules` | CIS Level 1 and 2 (cramfs, freevxfs, hfs, hfsplus, jffs2, usb-storage), Level 2 also overlayfs and udf; the STIG usb-storage; no profile squashfs | CIS server and workstation Level 1 (the same six), `cis` and `cis_workstation_l2` also squashfs and udf, CCN squashfs, udf and usb-storage, the STIG cramfs and usb-storage, BSI, HIPAA and PCI DSS usb-storage |
| `protocol_modules` | CIS Level 2 (dccp, rds, sctp, tipc) | `cis` and `cis_workstation_l2` (dccp, rds, sctp, tipc), the STIG (atm, can, firewire-core, sctp, tipc), OSPP and CUI (can, sctp, tipc), PCI DSS (dccp, sctp), BSI (firewire-core) |
| `wireless_modules` | none | BSI (all five), the STIG, OSPP and CUI (bluetooth) |

kmod's `modprobe` reads every `*.conf` and `*.alias` entry, except hidden ones, of `/etc/modprobe.d`,
`/run/modprobe.d`, `/usr/lib/modprobe.d` and `/lib/modprobe.d`, and kmod 31 (Ubuntu 24.04) also of
`/usr/local/lib/modprobe.d`, which kmod 28 (RHEL 9) does not read. An entry in an earlier directory hides the same name
in a later one, whatever it is, except a directory or a symbolic link to a directory: a symbolic link to `/dev/null`, a
dangling link or any other entry that is not a regular file is read as empty, which is how a vendor file is masked.
The remaining files are read in the byte order of their names. A line ending in `\` is joined with the next one and a
line that starts with `#` is a comment. Module names in `install` and `blacklist` treat `-` and `_` as the same, and
the name of an `install` command is a `fnmatch` pattern (`install cram* ...` applies to cramfs). For one module,
`modprobe` runs the first `install` command whose pattern matches it instead of loading the module, and `blacklist` stops loading through an alias (as udev does for hardware), not an explicit `modprobe`. So
`install <module> /bin/false` stops every load through `modprobe`, including the kernel's own requests, and `blacklist`
adds nothing to that but is what the checks also require.

## Decision

### 1. Each rule writes one drop-in with exactly the two lines the check requires

The three topics stay one family each, with the existing per-rule toggles; there is no per-profile value. Each rule
writes `/etc/modprobe.d/freesecdev-<module>.conf` (mode `0644`, owner and group root, written with
`ansible.builtin.copy` and `follow: false`):

```text
# Managed by freesecdev.linux_compliance for xccdf_org.ssgproject.content_rule_kernel_module_<module>_disabled.
# Switching the rule or the <family> topic off removes this file.
install <module> /bin/false
blacklist <module>
```

`/bin/false` is the command the current CIS benchmarks name and makes an explicit `modprobe` fail visibly; the check
accepts `/bin/true` too. The catalogue entry states the module, the drop-in, the install command and whether a
blacklist line is written, and `tests/unit/tools/test_content_golden_kernel_modules.py` checks, for every rule in both
datastreams, the structure of the definition, the directories and file name the objects read, that the drop-in matches
both patterns, that the patterns are exactly the two lines the drop-in writes (so nothing is written that the check
does not require) and that the patterns equal the constants the family uses to recognise a module that is already
disabled. The strategy is `recorded_value`, as for sudo: before the first write the ledger records `method: dropin`,
`dropin: null` (the file did not exist) and `dropin_sha256`.

The three family files `filesystem_modules.yml`, `protocol_modules.yml` and `wireless_modules.yml` each refuse direct
use and include the shared helpers of the umbrella, `kernel_modules_family.yml` (validation and inspection, once per
family run), `kernel_modules_apply.yml` and `kernel_modules_cleanup.yml`, which accept only the three families.

### 2. Another file that already sets the module is respected, never edited

The family finds the files that `modprobe` reads, as `modprobe` orders them, with the directories of the platform's
kmod (`__linux_compliance_remediate_modprobe_read_directories`, per pinned benchmark; another benchmark is refused
before any change). A masking entry takes its name and holds nothing, and a link to a directory is skipped (revised
after the review of PR #76). It does not parse those files itself: kmod reads each of them with its own reader
(revised after the third review of PR #76, see the amendment below), through the module
`freesecdev.linux_compliance.modprobe_config`, which runs `modprobe -c -d /dev -C <file>` for every file and
`modprobe -c -d /dev` once for the whole configuration, and refuses to act when the two disagree. The family matches
the name of each `install` directive that kmod printed as `modprobe` does, with the filter
`freesecdev.linux_compliance.modprobe_pattern`: kmod's `underscores()` first (`-` and `_` alike outside brackets, a
bracket ends at the first `]`, an unterminated `[` or a stray `]` rejected), then glibc's `fnmatch` without flags (`*`,
`?`, `\x` as the literal `x`, brackets that read a `]` right after `[`, `[!` or `[^` as a member, ranges in byte order
and `!` or `^` for negation; a reversed range such as `[z-a]` matches nothing). Only a bracket that holds a character
class, an equivalence class or a collating symbol is taken to match every module, so it can only make the family
refuse:

| Status | When |
|---|---|
| `compliant`, nothing written or recorded | The first `install` command for the module is `/bin/false` or `/bin/true`, a `blacklist` line names it, and files of the checked directories hold both lines in the form the check matches (a site's `/etc/modprobe.d/cramfs.conf`). Or the drop-in already holds exactly the content |
| `overridden`, nothing written | The first `install` command for the module is another command (`install hfs /sbin/modprobe --ignore-install hfs`) in a file read before the drop-in, so the drop-in's line would never run. The collection does not edit that file. An install command in a file read after the drop-in does not matter, because the drop-in's comes first |
| `not_directory` | `/etc/modprobe.d` is missing, a symbolic link or not a directory (kmod creates it) |
| `not_regular_file` | The drop-in path is a symbolic link or another non-regular file |
| `not_owned` | A file at the drop-in path does not start with the collection's header |
| `method_changed` | The ledger entry was recorded by another method |
| `modprobe_missing` | `/etc/modprobe.d` exists but no `modprobe` is found in the trusted directories, so nothing reads it |
| `config_unreadable` | A run of `modprobe -c` failed, timed out or printed too much, or the directives of the files the family found differ from those of the whole configuration, so the family and kmod disagree on what kmod reads |

A disabling `install` line elsewhere without a `blacklist` line, a line spelled with `_` where the check wants `-`
(`usb_storage`), or lines only in a file that `modprobe` does not read (a hidden file, `/etc/modules-load.d`) do not make
a rule compliant: the drop-in is written, and with it the check passes and `modprobe` behaves as required.

### 3. Cleanup removes exactly the drop-in that the collection wrote

| Reason (`cleanup_incomplete`, entry and file kept) | When |
|---|---|
| `method_changed` | The entry records another method, or none |
| `not_directory`, `not_regular_file` | `/etc/modprobe.d` or the drop-in is of the wrong type or a symbolic link |
| `not_owned` | The drop-in lost the collection's header |
| `invalid_record` | The recorded SHA-256 is malformed |
| `modified_since_apply` | The drop-in's SHA-256 is no longer what the collection wrote; an administrator's later change survives |

A drop-in that is already gone is the recorded prior state: the rule is `restored`, its entry dropped and nothing
written (FREES-173).

### 4. No module is unloaded and no initramfs is rebuilt

No pinned check reads the running kernel or the initramfs, so the rules are native without either, and the collection
does neither:

- Unloading a module with `modprobe -r` would need the audited process helper and could cut a running workload off at
  once (an overlay file system under a container runtime, a mounted USB disk, an SCTP association, a Bluetooth
  keyboard); there is no exact revert either, because the collection cannot know which module was loaded with which
  options. A module that is already loaded stays loaded until the next boot or an operator's `modprobe -r`; the drop-in
  stops every later load.
- Rebuilding the initramfs (`update-initramfs -u`, `dracut -f`) is a boot-critical change without an exact revert: the
  rebuilt image cannot be put back byte for byte. Both platforms copy `/etc/modprobe.d` into the initramfs only when it
  is rebuilt, so a module that the initramfs itself loads (rare for these modules; usb-storage on a host that boots from
  USB) can still be loaded early in the boot until the next kernel update rebuilds it. Operators who need that can
  rebuild the initramfs themselves.

No rule of the three topics needs a runtime state, so none stays `audit_only`.

## Benefits

All 21 kernel module rules of both pinned contents are native, with the same drop-in on both platforms, an exact
revert and a refusal whenever a site file would make the drop-in ineffective.

## Trade-offs

An `install` pattern with a character class, an equivalence class or a collating symbol inside a bracket is treated
as matching every module, so such a site file makes every rule that it precedes `overridden` even where it would not
match; no shipped or realistic configuration has one. The family runs `modprobe -c` once per configuration file and
once more, a few milliseconds each. Kernel command-line settings (`modprobe.blacklist=`, `module_blacklist=`) are
neither read nor written. The blacklisted file system modules
(overlay, squashfs, udf) and usb-storage can break container runtimes, snaps, optical media and USB storage, which is
why the topics stay disruptive.

## Security implications

The drop-ins only restrict what `modprobe` loads. They are root-owned, mode `0644` like the rest of `/etc/modprobe.d`,
and never written through a link. The family runs no external program. A site file that re-enables a module is
reported (`overridden`), never changed.

## Operational consequences

The Molecule images install `kmod` (pinned), which ships `/etc/modprobe.d`. The CIS profiles of the lifecycle select
no protocol or wireless module rule, so a topic declaration may now name `profiles`, per platform the profile of that
platform's datastream that its cycles run with (`docs/molecule.md`): `filesystem_modules` runs with
`cis_level2_server` on Ubuntu and `cis` on Rocky Linux, `protocol_modules` with `cis_level2_server` and `stig`, and
`wireless_modules` with `bsi` on Rocky Linux only, because the Ubuntu datastream has no such rule. A golden test checks
that these profiles select exactly the drop-ins that the declarations expect, and
`tests/unit/tools/test_content_golden_lifecycle_profiles.py` that a declared profile selects at least the native rules
of its topic that the platform's own profile selects, and that the cycles of all platforms together run every native
rule of the topic that some pinned profile selects, so a `profiles` entry can never narrow a topic's cycles.
`shared/tasks/lifecycle_kernel_modules_regressions.yml` (group `changes`, both platforms) proves a change of method, a
drop-in changed and one removed by hand, a site file that already disables a module (`compliant`), a site file read
first that lets a module load, before the apply and after it (`overridden`), and a file of the administrator at the
drop-in's path. These cases run there rather than as a pre-state of the cycles, which kept the Rocky Linux rule leg
above 15 minutes. The containers cannot load kernel
modules, so `modprobe` itself is left to the libvirt scenarios (FREES-61), and every rule is `notapplicable` in a
container scan; the drop-ins with their checksums and the golden tests are the evidence there.

## Amendment 2026-10-31: kmod reads the configuration (third review of PR #76)

The third review fuzzed the family's own reading of `install` lines with 27,931 names against the real `modprobe -n -v`
of both pinned kmods and found 114 names that kmod applies and the family did not, each giving a false `applied`:
kmod's line reader (`freadline_wrapped()`) removes every backslash before it parses a line (`\x` is `x`, `\\` is `\`,
and only an odd number of backslashes at the end continues the line), so `install \*cramfs`, `ins\tall cramfs` and a
line ending in `\\` meant something else to kmod than to a reader of the text; and `cr[]a[a]mfs` is one bracket to
`fnmatch`, where the filter had rejected it.

Decision: kmod, the platform's own reader and not content of the scanner, is the source of truth for what a file says.

- The new module `freesecdev.linux_compliance.modprobe_config` runs `modprobe -c` through the audited process helper
  (ADR 0004, amendment of FREES-190): once per file with `-C <file>`, so that every directive is known with its file and
  its place in kmod's order, and once without, for the whole configuration. `-d /dev` points kmod at a root without
  `lib/modules`, so it dumps no module index. kmod prints the directives as it keeps them: backslashes resolved,
  continued lines joined, comments and rejected lines dropped and `-` turned into `_` in module names. Directives from
  the kernel command line, which kmod adds to every run, are read once with `-C /dev/null` and removed from the front
  of each run. Checked against both pinned kmods: `install \*cramfs` prints as `install *cramfs`, `ins\tall cramfs` as
  `install cramfs`, and the two lines after one ending in `\\` as two directives.
- The family fails closed: when the concatenation of the files' directives is not exactly the whole configuration
  (a file it missed, one that kmod skips, a failed or truncated run), every rule is `config_unreadable` and nothing is
  written; without `modprobe` every rule is `modprobe_missing`.
- `modprobe -c` keeps no file names, so the file-level part stays: which entries take a name, in which order, and
  which of them are the collection's drop-ins. Within one file the order of kmod's output is the order of the file.
- The matching of a name against a module stays a translation of `fnmatch`, because `modprobe -n -v` finds an
  `install` directive by pattern only for a module that the running kernel's module tree has, which a container and
  many hosts do not. The filter now models glibc's bracket reading exactly. `tests/fixtures/kmod/install-names.tsv`
  holds kmod's verdicts for 5,781 rows of the fuzzing corpus (every match, every row on which the round-2 or the
  current filter differs from kmod, and 800 others), produced from the real `modprobe -c` and `modprobe -n -v` of
  both pinned images, which agree on every row; `tests/unit/plugins/filter/test_modprobe_pattern.py` requires the
  filter to match every name that kmod matches, and to differ otherwise only by matching every module for a class
  inside a bracket (1,729 rows, 0 narrower divergences).
- The regression group adds an escaped wildcard, a backslash inside the directive, a line ending in `\\` followed by
  a re-enabling line, and `cr[]a[a]mfs`, each before the collection's drop-ins and each expected `overridden`.
