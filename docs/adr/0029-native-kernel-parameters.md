# 0029. Native kernel parameters through sysctl drop-ins and the running kernel

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement that every topic toggle remediates for real and reverts
  exactly what the collection changed, with the collection's own Ansible and never the content's fixes)
- **Jira:** FREES-107
- **Pull requests:** introduced by the pull request for FREES-107
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0009](0009-molecule-layout-and-drivers.md), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0021](0021-native-banners-pwquality-and-profile-values.md),
  [ADR 0023](0023-native-ssh-server-configuration.md), [native remediation guide](../native-remediation-guide.md)

## Context

Three families of the catalogue hold the kernel parameter rules, all `audit_only` until now: `sysctl` (31 rules, not
disruptive: kernel hardening that does not change routing), `ipv4_parameters` (26) and `ipv6_parameters` (19), both
disruptive and grouped by the umbrella `network`.

The pinned ComplianceAsCode 0.1.82 datastreams were read rule by rule (profiles, OVAL definitions, exported values,
platforms) for `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml`. Every kernel parameter rule of both uses the same
check:

- A **static** half: `textfilecontent54` objects over `/etc/sysctl.conf` (Ubuntu also `/etc/ufw/sysctl.conf`,
  through the file path pattern `/etc(/ufw){0,1}/sysctl.conf$`) and every `*.conf` of `/etc/sysctl.d`,
  `/run/sysctl.d` and `/usr/local/lib/sysctl.d` (the "files not managed by packages"), with the pattern
  `^[\s]*<key>[\s]*=[\s]*(.*\S)[\s]*$`, in which the dots of the key are regular expression wildcards, and
  `check="all"`: every occurrence in any of these files must have an accepted value, and at least one must exist. Only
  when none of them sets the key, every occurrence in `/usr/lib/sysctl.d/*.conf` (the package files) must be accepted
  and one must exist.
- A **runtime** half: a `sysctl_test` of the running value.
- The accepted values come from the profile through an exported XCCDF value (38 rules, for example
  `sysctl_net_ipv4_conf_all_rp_filter_value`) or are fixed in the check: one value (`kernel.dmesg_restrict` 1), a set
  (`kernel.kptr_restrict` 1 or 2; `kernel.yama.ptrace_scope` 1 on RHEL 9 and 1, 2 or 3 on Ubuntu), a pattern
  (`net.ipv4.ip_local_port_range` `32768\s*65535`) or the empty string (`kernel.core_pattern` of the OSPP and CUI
  profiles, whose static pattern is `^[[:blank:]]*kernel.core_pattern[[:blank:]]*=[[:blank:]]*(.*)$`).
  `sysctl_kernel_unprivileged_bpf_disabled_accept_default` also passes when no file sets the key and the package
  files do not contradict it (`pkg_not_wrong`).
- The IPv6 rules pass as well when IPv6 is disabled (`sysctl_kernel_ipv6_disable`). The kernel rules and the IPv6
  rules are limited to `system_with_kernel`, which excludes containers; the IPv4 rules have no platform.

`systemd-sysctl` at boot and `sysctl --system` read the `*.conf` files of `/etc/sysctl.d`, `/run/sysctl.d`,
`/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d` and `/lib/sysctl.d`, a name in an earlier directory hiding the same
name in a later one, in lexical order of the file names, and the last assignment of a key wins.
`/etc/sysctl.conf` is read through the link `99-sysctl.conf` and, by `sysctl --system`, once more at the end; ufw
applies `/etc/ufw/sysctl.conf` when it starts. Ubuntu's procps ships `/etc/sysctl.d/10-*.conf`, among them
`10-network-security.conf` with `net.ipv4.conf.all.rp_filter=2` and `default.rp_filter=2`, which the CIS value 1
contradicts; Ubuntu also ships `/usr/lib/sysctl.d/99-protect-links.conf`. RHEL 9 ships only package files
(`10-default-yama-scope.conf` sets `kernel.yama.ptrace_scope = 0`, `50-redhat.conf` sets
`net.ipv4.conf.default.rp_filter = 1`). The Rocky Linux container has no `/etc/sysctl.d` at all.

In the Molecule containers `/proc/sys` is mounted read-only, and most kernel parameters are those of the host.

## Decision

### 1. One drop-in per rule, applied after every file of the distributions

Each native rule writes `/etc/sysctl.d/999-freesecdev-<rule>.conf` (the rule's short identifier with dashes), mode
`0644`, owner and group root, with a header that names the rule and exactly one line `<key> = <value>`. The name
sorts after every name that the distributions ship, the `99-` files included (`99-sysctl.conf`,
`99-protect-links.conf`, `99-cloudimg-ipv6.conf`), so the drop-in's value is the one the kernel gets at boot, and an
administrator's file that sorts later, such as `zz-site.conf`, still wins and is reported (section 3). Both contents
read `/etc/sysctl.d`, so the audit sees the value. `tests/unit/tools/test_content_golden_sysctl.py` checks, against
the OVAL of both datastreams and for every native rule: that the definition is the static and the runtime half (and
the IPv6 alternative), the key of the runtime object, the files and directories of the static objects (which are the
role constants `__linux_compliance_remediate_sysctl_checked` per benchmark), the line pattern (the constants
`__linux_compliance_remediate_sysctl_line_pattern` and `_empty_line_pattern`), the existence checks, that the
accepted values are exactly the check's states (or its exported value), that the written value is one of them, that
the drop-in's own line is captured by the pattern with that value, and that every drop-in sorts after the vendor
names. A content update that moves a check fails CI until the catalogue follows.

Values come from the profile (`profile_value`, ADR 0021) for the 38 rules whose checks export a value, and from the
check itself for the others, as fixed parameters (`value`, `accepted` per benchmark, `accepted_pattern`,
`empty_value`, `absent_accepted`) that the golden test compares with the OVAL states. Where a check accepts several
values, the catalogue writes the one that changes least and stays reversible: `kernel.kptr_restrict` 1,
`kernel.yama.ptrace_scope` 1, `kernel.unprivileged_bpf_disabled` 2 for the `accept_default` rule (1 could not be
reverted, section 7). No value is taken from the content's fixes (`profile_value_source: fix` is not used). A rule
without a usable value for the verified profile and content stops the family before anything changes.

### 2. What the family checks before it writes

The family reads every file that the content's check reads and every file that the boot order reads, follows the
links to regular files that both read (`99-sysctl.conf`), and decides per rule, mirroring the check: the OVAL pattern
on the whole text of each file (as the scanner applies it), the boot order of section 1 for what takes effect. With
nothing changed and a reason, it refuses:

| Status | When |
|---|---|
| `overridden` | a file applied after the drop-in sets another value: an administrator's later file in a directory that the check reads (the check fails as well), `/etc/sysctl.conf`, or a package file in `/usr/lib/sysctl.d` or `/lib/sysctl.d` that sorts later (the check ignores it, but it wins at boot); a glob line (`net.ipv4.conf.*.rp_filter`) counts for every key it names |
| `conflicting_setting` | a file that the check reads and that is applied before the drop-in sets another value, so the drop-in would win at boot but the check, which reads every occurrence, would still fail; also a hidden `.*.conf`, which the check reads and the boot order skips |
| `duplicate_setting`, `prior_too_large` | a vendor file sets the key more than once, or its conflicting line is longer than 1024 characters (section 2a) |
| `runtime_unavailable` | the running value must change (section 4) but `/proc/sys` cannot be written, as in an unprivileged container |
| `notapplicable` | with the running values on, the kernel has no such parameter (for example IPv6 disabled at boot) |
| `not_directory`, `not_regular_file`, `not_owned` | `/etc/sysctl.d` is not a directory (a symbolic link included), the drop-in path is not a regular file, or a file at that path does not carry the collection's header |
| `method_changed` | the ledger entry was recorded by another method |

A rule is `compliant`, with nothing written, when its drop-in already holds exactly what the collection writes and
the running value is accepted, or when there is no drop-in and the check would already pass (the static half over
the other files, the last assignment of the boot order accepted, the running value accepted): for example
`kernel.yama.ptrace_scope` on Ubuntu, which `10-ptrace.conf` sets to 1, and `net.ipv4.conf.default.rp_filter` on
RHEL 9, which only the package file `50-redhat.conf` sets.

### 2a. A conflicting line in a vendor file is set to the compliant value

The pattern of ADR 0023, section 1a: a conflicting line in one of the files that Ubuntu's packages ship with settings
that the checks read (`__linux_compliance_remediate_sysctl_vendor_files`: procps's `10-kernel-hardening.conf`,
`10-magic-sysrq.conf`, `10-network-security.conf`, `10-ptrace.conf` and `10-zeropage.conf` in `/etc/sysctl.d`, and
ufw's `/etc/ufw/sysctl.conf`, which the Ubuntu checks read and which sets `log_martians=0` and `tcp_syncookies=0`) is
changed in place, when the file sets the key exactly once: the value part of the line becomes the rule's value, so
`net.ipv4.conf.all.rp_filter=2` becomes `net.ipv4.conf.all.rp_filter=1` and ufw's `net/ipv4/tcp_syncookies=0` becomes
`net/ipv4/tcp_syncookies=1`. The rule's ledger entry records the original line (`vendor_line:<path>`) and
the line written (`vendor_written:<path>`) before the change, once per file; `ansible.builtin.lineinfile` with
`backrefs: true` replaces exactly that line and never appends one, and every backslash of the line it writes is
doubled with the constant `__linux_compliance_remediate_backslash`. Cleanup writes the original line back when the file
still holds the written line, leaves a file alone that already holds the original line, and refuses
`modified_since_apply` otherwise. `/etc/sysctl.conf` ships with every line commented out on both distributions, so an
active line there is an administrator's and is refused (`overridden`), never edited, as is every other file.

### 3. The running kernel

Persistent configuration takes effect at the next boot; the check also reads the running value. The new role input
`linux_compliance_remediate_sysctl_runtime` (default `true`) decides whether the family sets it:

- With `true`, a rule whose running value the check rejects sets it to the rule's value, after the drop-in is
  written, and its ledger entry records the running value before (`runtime_prior`) and the value written
  (`runtime_written`). A rule whose running value is accepted already leaves it alone and records nothing about it. A
  later run that finds the running value changed again (by an administrator, or a reboot after the drop-in was
  removed by hand) sets it again and keeps the first record.
- With `false`, only the persistent value is written and the running kernel is neither read nor changed; the rule
  reports `applied` with a message that the kernel takes the value at the next boot. The Molecule containers use
  this, because their `/proc/sys` is read-only.

The running value is set by the new module `freesecdev.linux_compliance.sysctl_runtime` with its helper
`plugins/module_utils/compliance/sysctl.py`. No program runs: the module writes the value to the parameter's own file
below `/proc/sys`, as `sysctl -w` does, and reads it back; when the kernel keeps another value, it writes the value
before back and fails. A parameter name is two to eight dot-separated components of a fixed alphabet; the helper
refuses a path reached through a symbolic link, a file that is not regular and a file on another file system than
`/proc/sys`, so a name cannot reach outside it. A procfs file cannot be written atomically through a temporary file;
one `write` to the open file is how the kernel takes a parameter. Its test root is the keyword-only seam `proc_root`,
which only this helper may define (the repository guard's `SEAM_OWNERS`). `ansible.posix.sysctl` was not used: the
collection has no dependencies, and that module always edits a configuration file of its own choice and runs the
`sysctl` program to set and reload values. Like every module of the collection, `sysctl_runtime` carries no GPLv3
header, so `tests/sanity/ignore-2.20.txt` and `ignore-2.21.txt` gain exactly
`plugins/modules/sysctl_runtime.py validate-modules:missing-gplv3-license` (ADR 0011).

Writing `net.ipv4.ip_forward`, `net.ipv4.conf.all.forwarding` or `net.ipv6.conf.all.forwarding` also sets the
forwarding flag of `default` and of every interface. Before such a rule sets it, its ledger entry records the flag of
every interface as well (`companion:<parameter>`), and cleanup sets the global value back first and then every
interface's flag that still exists, each read just before it is set, so a router whose interfaces forwarded
differently gets exactly its prior flags back. A change of IPv4 forwarding also sets
`net.ipv4.conf.all.accept_redirects` to its opposite (the kernel's `inet_forward_change`), so that parameter is
recorded as a companion too (`__linux_compliance_remediate_sysctl_side_effects`): apply sets it back to its value
before right after forwarding, cleanup sets the recorded value again after the forwarding flags, unless a rule that
stays applied manages it, and the forwarding rules are set and restored before every other rule of the family. The
running kernel regressions prove this on the virtual machines.

### 4. The ledger and cleanup

Every rule is `recorded_value` and records, before the drop-in is written: `method` (`dropin`), `dropin` (`null`),
`dropin_sha256`, `written_line`, the vendor lines of section 2a and the running values of section 3. Cleanup first sets
the recorded running value back, then writes back the vendor lines, removes the drop-in and forgets the entry. It
refuses, with nothing changed and the entry kept, always with a reason:

| Reason | When |
|---|---|
| `method_changed` | the entry records another method, or none |
| `not_directory`, `not_regular_file`, `not_owned` | as for apply |
| `invalid_record` | the recorded SHA-256 is missing or malformed, a running value is recorded without the value written (or the reverse), an interface flag is recorded without the running value, or a recorded vendor line is not one of a vendor file |
| `target_absent` | a vendor file whose line the collection changed no longer exists, or the kernel no longer has the parameter whose running value the entry records |
| `modified_since_apply` | the drop-in carries the header but its content is no longer what the collection wrote, a vendor file no longer holds the written line, or the running value is neither the value written nor the recorded value before: an administrator's change is never overwritten |

When the current state already equals the recorded prior state (the drop-in removed by hand, the running value
already back at the recorded value, the vendor line already the original), the rule is `restored`, its entry is
dropped and nothing is written there (FREES-173).

Where `/etc/sysctl.d` does not exist, as in the Rocky Linux container, the first drop-in creates it with mode `0755` and
the marker `.freesecdev-created` (no `.conf`, so neither the check nor the boot order reads it); the directory is
removed with the marker once nothing else is in it.

### 5. Disruptive rules

`sysctl` holds kernel hardening that does not cut a host off and is not disruptive. `ipv4_parameters` and
`ipv6_parameters` stay disruptive (umbrella `network`) and are applied and cleaned up only with the family or
`network` in `linux_compliance_remediate_allow_disruptive`, the existing mechanism:

| Rules | What they can break |
|---|---|
| `sysctl_net_ipv4_ip_forward`, `sysctl_net_ipv4_conf_all_forwarding`, `sysctl_net_ipv6_conf_all_forwarding` | every router, VPN gateway, container or virtual machine host that forwards packets (Docker, Kubernetes, libvirt NAT) |
| `sysctl_net_ipv4_conf_*_rp_filter` | asymmetric routing and multi-homed hosts (strict reverse-path filtering drops replies that arrive on another interface) |
| `sysctl_net_ipv4_conf_*_accept_redirects`, `_secure_redirects`, `_send_redirects`, `_accept_source_route`, `_shared_media`, `sysctl_net_ipv6_conf_*_accept_redirects`, `_accept_source_route` | networks that rely on ICMP redirects or source routing |
| `sysctl_net_ipv4_conf_all_arp_filter`, `_arp_ignore`, `_drop_gratuitous_arp`, `_accept_local`, `_route_localnet` | hosts with several addresses on one subnet, high-availability addresses that move by gratuitous ARP, and DNAT to loopback (`route_localnet`) |
| `sysctl_net_ipv6_conf_*_accept_ra`, `_accept_ra_defrtr`, `_accept_ra_pinfo`, `_accept_ra_rtr_pref`, `_autoconf`, `_router_solicitations`, `_max_addresses` | IPv6 hosts that get their address, prefix or default route from router advertisements |
| `sysctl_net_ipv4_ip_local_port_range`, `sysctl_net_ipv4_tcp_rfc1337`, `sysctl_net_ipv4_tcp_syncookies`, `sysctl_net_ipv4_icmp_*`, `_log_martians` | services that use fixed ports in the new ephemeral range; otherwise little |

No rule of these families disables IPv6; a host with IPv6 disabled passes the IPv6 checks as it is. Each rule can be
switched off on its own with its rule toggle, for example `ip_forward` on a container host.

### 6. Topics

The three families are the topics: kernel hardening (`sysctl`) apart from the network (`ipv4_parameters`,
`ipv6_parameters`), each with its toggle, the umbrella toggle `linux_compliance_network_enabled` over the two network
topics and a toggle per rule. A finer split, for example forwarding apart from the other IPv4 rules, would add a family
whose lifecycle needs its own CI legs on both drivers; the rule toggles already let an operator keep forwarding while
the rest of the topic applies.

### 7. Rules kept `audit_only`

65 of the 76 rules are native: 20 of `sysctl` and all of `ipv4_parameters` and `ipv6_parameters`. 11 stay
`audit_only`:

| Rules | Reason |
|---|---|
| `sysctl_kernel_kexec_load_disabled`, `sysctl_kernel_modules_disabled`, `sysctl_kernel_unprivileged_bpf_disabled` | The running value cannot be set back until the next boot (1 is one-way for each), so switching the rule off could not revert it; `modules_disabled` also stops every later module load. The `accept_default` variant of the BPF rule, which accepts 2, is native |
| `sysctl_kernel_pid_max` | 65536 instead of RHEL 9's 4194304 can stop workloads that run more than 65536 tasks or threads; it needs a disruptive topic of its own |
| `sysctl_user_max_user_namespaces`, `sysctl_user_max_user_namespaces_no_remediation` | 0 stops rootless containers, browser sandboxes and services that use `PrivateUsers=`; the content itself does not remediate the STIG variant |
| `sysctl_kernel_exec_shield` | Not a kernel parameter on RHEL 9: the check reads the boot loader's command line for `noexec`, which belongs to the `bootloader` topic |
| `coredump_disable_backtraces`, `coredump_disable_storage`, `service_systemd-coredump_disabled`, `disable_users_coredumps` | Not kernel parameters: `systemd-coredump` configuration (`/etc/systemd/coredump.conf.d`), the `systemd-coredump.socket` unit and PAM limits (`/etc/security/limits.d`); they need methods of their own and are a follow-up |

### 8. The lifecycle harness

The three topics run the toggle lifecycle on both drivers, by the per-pre-state driver rule of FREES-61:

- The `as built` pre-state runs in the Docker scenarios with the running values off: it proves the drop-ins, the
  vendor line on Ubuntu, the directory with its marker on Rocky Linux, the ledger, check mode, idempotence and the
  exact cleanup, and the whole-instance comparison shows that no running value changed.
- The `as built, with the running kernel` pre-state requires libvirt and runs on the virtual machines with the
  running values on: the declared kernel parameters must have the rule's value after apply and their value before
  after cleanup, the whole-instance comparison covers every readable parameter below `/proc/sys`, and on Ubuntu the
  real scan must report every rule `pass` after apply.
- Regression groups (`ipv4_parameters`): `changes`, a Docker leg on both platforms
  (`shared/tasks/lifecycle_sysctl_regressions.yml`): an administrator's file that sorts later (`overridden`) and one
  that sorts earlier (`conflicting_setting`), a ledger entry of another method (`method_changed` on apply and cleanup),
  a drop-in and, on Ubuntu, a vendor line changed by hand (`modified_since_apply`), a drop-in removed by hand
  (`restored` without a write), a file without the header at a drop-in path (`not_owned`), the running values on in a
  container (`runtime_unavailable` with nothing written) and, on Rocky Linux, a symbolic link in place of the missing
  `/etc/sysctl.d` (`not_directory`). `runtime`, a libvirt leg on both platforms
  (`shared/tasks/lifecycle_sysctl_runtime_regressions.yml`): forwarding switched on as on a router with one interface
  left out, which apply records and cleanup restores flag by flag; a running value changed by hand after apply, which
  the next apply sets again; and a running value changed by hand to a third value, which cleanup refuses
  (`modified_since_apply`) until it is the value written again.
- A regression group may now name the drivers it `requires` (default Docker); `make lint-lifecycle` checks the drivers
  and that a libvirt group's topic runs a libvirt cycle, and `make molecule-matrix` plans its legs with that driver.
- The lifecycle passes `linux_compliance_remediate_sysctl_runtime` as `true` on the virtual machines and `false` in
  the containers (`lifecycle_sysctl_runtime`), which a regression may override.

## Benefits

65 kernel parameter rules remediate for real on both platforms, with the profile's values, persistently and in the
running kernel, and switch off exactly, including the running values and the interface flags that forwarding changes.
Nothing runs a program, and nothing reloads all of `sysctl.d`, which would apply unrelated files as well.

## Trade-offs

One file per rule in `/etc/sysctl.d` instead of one shared file; the per-rule file is what lets a rule toggle revert
without history. The `999-` prefix lets the collection's value win over the distributions' at boot, which is the
point, and an administrator who wants the last word uses a later name and gets `overridden`. Six Ubuntu vendor
files can be edited in place; a package update that replaces one shows up as `modified_since_apply` or
`target_absent` at cleanup and needs a review. A conflicting setting in an administrator's file is reported, never
fixed. The running value is set only for the rules that need it, so a host where a value was changed by hand after the
drop-in was written is corrected on the next run, not reverted to the administrator's value.

## Security implications

The running kernel is changed only for rules that the operator switched on and, for the network topics, allow-listed.
The module writes only below `/proc/sys`, refuses links and other file systems, validates names and values, and reads
every value back. `ip_forward`, reverse-path filtering, redirects and router advertisements can cut a host off; the
allow-list is the operator's acknowledgement, and the per-rule toggles let them keep forwarding on a container host.
Three rules whose running value cannot be reverted stay `audit_only` rather than being applied one-way.

## Operational consequences

The topics add Docker legs (two modes on two platforms each, plus the `changes` regression group) and libvirt legs
(two modes on two platforms each, plus the `runtime` regression group). The drop-ins of a host can be listed with
`ls /etc/sysctl.d/999-freesecdev-*`, and `sysctl --system` or a reboot applies them as the kernel will.
