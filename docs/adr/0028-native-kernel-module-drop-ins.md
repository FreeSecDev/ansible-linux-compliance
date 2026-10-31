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

kmod's `modprobe` reads every `*.conf` and `*.alias` file, except hidden ones, of `/etc/modprobe.d`, `/run/modprobe.d`,
`/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` and `/lib/modprobe.d`; a file name in an earlier directory hides the
same name in a later one, and the remaining files are read in the byte order of their names. A line ending in `\` is
joined with the next one and a line that starts with `#` is a comment. Module names in `install` and `blacklist` treat
`-` and `_` as the same. For one module, `modprobe` runs the first `install` command it read instead of loading the
module, and `blacklist` stops loading through an alias (as udev does for hardware), not an explicit `modprobe`. So
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

The family reads every file that `modprobe` reads, as `modprobe` orders them, besides the collection's drop-ins, and
keeps every `install` and `blacklist` command:

| Status | When |
|---|---|
| `compliant`, nothing written or recorded | The first `install` command for the module is `/bin/false` or `/bin/true`, a `blacklist` line names it, and files of the checked directories hold both lines in the form the check matches (a site's `/etc/modprobe.d/cramfs.conf`). Or the drop-in already holds exactly the content |
| `overridden`, nothing written | The first `install` command for the module is another command (`install hfs /sbin/modprobe --ignore-install hfs`) in a file read before the drop-in, so the drop-in's line would never run. The collection does not edit that file. An install command in a file read after the drop-in does not matter, because the drop-in's comes first |
| `not_directory` | `/etc/modprobe.d` is missing, a symbolic link or not a directory (kmod creates it) |
| `not_regular_file` | The drop-in path is a symbolic link or another non-regular file |
| `not_owned` | A file at the drop-in path does not start with the collection's header |
| `method_changed` | The ledger entry was recorded by another method |

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

The `install` comparison is by module name with `-` and `_` treated alike, not by `modprobe`'s `fnmatch` wildcards: a
site file with `install * ...` is not recognised as overriding. A same-named file in `/run/modprobe.d` or
`/usr/lib/modprobe.d` is assumed to be hidden by the collection's drop-in even before it exists. Kernel command-line
settings (`modprobe.blacklist=`, `module_blacklist=`) are neither read nor written. The blacklisted file system modules
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
that these profiles select exactly the drop-ins that the declarations expect.
`shared/tasks/lifecycle_kernel_modules_regressions.yml` (group `changes`, both platforms) proves a change of method, a
drop-in changed and one removed by hand, a site file that already disables a module (`compliant`), a site file read
first that lets a module load, before the apply and after it (`overridden`), and a file of the administrator at the
drop-in's path. These cases run there rather than as a pre-state of the cycles, which kept the Rocky Linux rule leg
above 15 minutes. The containers cannot load kernel
modules, so `modprobe` itself is left to the libvirt scenarios (FREES-61), and every rule is `notapplicable` in a
container scan; the drop-ins with their checksums and the golden tests are the evidence there.
