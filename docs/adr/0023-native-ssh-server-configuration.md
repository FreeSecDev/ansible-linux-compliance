# 0023. Native SSH server configuration through validated drop-ins

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement that every topic toggle remediates for real and reverts
  exactly what the collection changed)
- **Jira:** FREES-109
- **Pull requests:** introduced by the pull request for FREES-109
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0021](0021-native-banners-pwquality-and-profile-values.md),
  [native remediation guide](../native-remediation-guide.md)

## Context

The `ssh` topic holds 63 catalogued rules, all `audit_only` until now. It is disruptive: a wrong sshd setting can
lock out every remote operator, and a configuration that sshd refuses stops the daemon at its next start or reload.

The pinned ComplianceAsCode 0.1.82 datastreams were read rule by rule (profiles, OVAL definitions, exported values,
platforms) for both `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml`:

- Every sshd keyword rule that a pinned profile selects, on both platforms, checks `/etc/ssh/sshd_config` and every
  `/etc/ssh/sshd_config.d/*.conf` (`textfilecontent54` objects with `filepath` and with `path` plus
  `filename` `.*\.conf$`), with `check="all"`: every occurrence of the keyword in any of these files must comply, and
  at least one must exist. The keyword is matched case-insensitively.
- The numeric rules compare with the profile's value: `ClientAliveInterval` at most `sshd_idle_timeout_value` (300
  in the CIS profiles, 600 in STIG, 900 in CCN and PCI DSS), `ClientAliveCountMax` equal to `var_sshd_set_keepalive`
  (3 in the Ubuntu CIS profiles, 1 elsewhere), `LoginGraceTime`, `MaxAuthTries`, `MaxSessions` and the three numbers of
  `MaxStartups` against their values; `KexAlgorithms` and `MACs` of the Ubuntu CIS profiles must be subsets of
  `sshd_strong_kex` and `sshd_strong_macs`. The STIG cipher, MAC and key exchange rules of Ubuntu compare with a fixed
  ordered list, and `sshd_use_strong_ciphers` with a pattern of allowed ciphers; the other rules check one fixed value
  (`PermitRootLogin no`, `Banner /etc/issue.net` and so on).
- sshd uses the first value it obtains for most keywords, and both distributions include
  `/etc/ssh/sshd_config.d/*.conf` near the top of `sshd_config`, before any other setting: drop-ins are read first,
  in lexical order, and the rest of the main file after them. Rocky Linux 9 ships
  `/etc/ssh/sshd_config.d/50-redhat.conf`, which includes the crypto policy back end
  `/etc/crypto-policies/back-ends/opensshserver.config` (Ciphers, MACs, KexAlgorithms and the other algorithm lists)
  and sets `GSSAPIAuthentication yes`, `X11Forwarding yes` and `UsePAM yes`. Ubuntu's `sshd_config` sets
  `UsePAM yes` and `X11Forwarding yes` after the include.
- `sshd_rekey_limit` (RHEL 9) requires `RekeyLimit` in `sshd_config` itself and no `RekeyLimit` in any drop-in
  (`check_existence="none_exist"`), and its value combines two profile values.
- The STIG and CIS rules about ownership and modes of the configuration and the host keys, the package and service
  rules, the client rules (`/etc/ssh/ssh_config`), `sshd_include_crypto_policy` and `sshd_use_directory_configuration`
  are not keyword settings of the server.

## Decision

### 1. One validated drop-in per rule, read before every other file

Each native rule writes one drop-in, `/etc/ssh/sshd_config.d/00-freesecdev-<rule>.conf`, mode `0600`, owner and group
root, with a header that names the rule and exactly one line `<Keyword> <value>`. The name sorts before every drop-in of
the distributions (`50-redhat.conf`, `50-cloud-init.conf`) and after `00-complianceascode-hardening.conf`, so sshd reads
it first and its value takes effect. Both pinned contents read the drop-ins, so the audit sees the value.
`tests/unit/tools/test_content_golden_ssh.py` checks against the OVAL of both datastreams that the
check of every native rule reads `sshd_config` and the rule's own drop-in path with `check="all"`, that each fixed
value satisfies the check's state and that each numeric rule reads the exported value it is given, that no pinned
profile selects two native rules for one keyword, and that `sshd_rekey_limit` refuses every drop-in. A content update
that moves a check fails CI until the catalogue follows. The method is therefore the same on both platforms; the
ledger still records it (section 4), so a later content version that needs another method cannot clean up an entry
by the wrong one.

Values come from the profile (`profile_value`, ADR 0021) for the numeric and the Ubuntu CIS algorithm rules, and from
the check itself for the others, as fixed parameters that the golden test compares with the OVAL state. A rule without
a usable value, or two planned rules for the same keyword, stop the family before anything changes.

A drop-in only takes effect where nothing earlier sets the same keyword. Before it writes, the family reads
`sshd_config` and every `*.conf` drop-in and refuses, with nothing changed:

| Status | When |
|---|---|
| `overridden` | `sshd_config` sets the keyword or includes another file before its drop-in `Include`, or a drop-in that sorts before the rule's own sets it, includes other files or cannot be read; or a later line that the content's check reads sets another value and the collection cannot change it (section 1a); the reason names the files |
| `duplicate_setting`, `prior_too_large` | a vendor file sets the keyword more than once, or its conflicting line is longer than 1024 characters (section 1a) |
| `not_included` | `sshd_config` has no `Include` of `/etc/ssh/sshd_config.d/*.conf` before its first `Match` block, so a drop-in would not apply globally |
| `crypto_policy` | `Ciphers`, `MACs` or `KexAlgorithms` on RHEL 9, where the system-wide crypto policy governs them (section 5) |
| `invalid_config` | `sshd -t` refuses the configuration with the settings to write (section 2) |
| `not_directory`, `not_regular_file`, `not_owned` | the drop-in directory is not a directory (a symbolic link included), the drop-in path is not a regular file, or a file at that path does not carry the collection's header |
| `notapplicable` | `sshd_config` or the `sshd` executable is missing: openssh-server is not installed |
| `method_changed` | the ledger entry was recorded by another method |

### 1a. A conflicting later line in a vendor file is set to the compliant value

sshd ignores a later line for the same keyword, but the content's check reads every occurrence: Ubuntu's
`sshd_config` sets `X11Forwarding yes` after its `Include`, and RHEL's `50-redhat.conf` sets `X11Forwarding yes` and
`GSSAPIAuthentication yes`. With the drop-in alone, `sshd_disable_x11_forwarding` (Ubuntu STIG; RHEL ISM, PCI DSS and
STIG) and `sshd_disable_gssapi_auth` (RHEL CIS, CUI, Essential Eight, HIPAA, ISM, OSPP and STIG) would be written but
still fail the audit. A later line whose value equals the rule's value is compliant and left alone.

A conflicting later line is changed in place when it is in a vendor file, the two files that the packages ship and that
sshd reads after the drop-ins (`__linux_compliance_remediate_sshd_vendor_files`: `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.d/50-redhat.conf`), outside any `Match` block, and set exactly once in that file. This is the
`recorded_value` method that `pwquality` uses for the package-owned `/etc/security/pwquality.conf` on Ubuntu, and
ComplianceAsCode's own fix removes the keyword from these files too. Before the change, the rule's ledger entry records
for each such file the exact original line (`vendor_line:<path>`), the line written (`vendor_written:<path>`, the same
`<Keyword> <value>` as the drop-in); a file is recorded once, by the first run that changes it.
`ansible.builtin.lineinfile` then replaces that one line, keeping the file's mode and owner. It runs with `backrefs:
true` for the edit, the cleanup and the rollback, so a line that no longer matches is left alone and nothing is ever
appended at the end of the file, where it could land inside a `Match` block.
Otherwise the rule is refused with nothing changed: `overridden` for a later line in an administrator's drop-in (for
example `LoginGraceTime 120` in a `60-site.conf`, which the collection never edits) or inside a `Match` block of a vendor
file, `duplicate_setting` when a vendor file sets the keyword more than once, and `prior_too_large` for a line over
1024 characters. A rule is reported `applied` only when the drop-in and the changed vendor lines leave no occurrence
that the check would refuse.

### 2. Every change is validated with `sshd -t` before it is written

The file modules' `validate` parameter is refused by the repository guard (ADR 0004, FREES-159), and a drop-in on its
own is not the configuration that sshd loads. The new module `freesecdev.linux_compliance.sshd_validate` runs
`sshd -t -f /etc/ssh/sshd_config` through the audited process helper, with every setting to write as
`-o <Keyword>=<value>`. sshd processes command-line options first and keeps the first value, so the test validates the
whole effective configuration, the main file and every drop-in it includes, exactly as it will be with the new drop-ins
read first. The helper's allow-list gains `sshd` with only that form (an amendment of ADR 0004): the prefix
`-t -f /etc/ssh/sshd_config` and the option `-o`; `-T`, `-D`, `-d`, `-h`, `-E`, `-C`, another configuration file and
every other option are refused, and the module accepts only the keywords of the native rules and one-word values.
sshd in test mode reads the configuration and the host keys and exits; it starts no daemon. The keyword list and the
one-word value pattern are part of the helper's policy, not only of the module: `-o` must be its own argument followed by
exactly one `<Keyword>=<value>` with a keyword of the native rules, so `-o=...`, `Include`, `HostKey`,
`AuthorizedKeysCommand`, values with spaces and positional arguments are refused by the helper itself. Only an sshd
that is not found in the trusted directories is reported `available: false` (the rule is then `notapplicable`); an sshd
that the helper refuses or that cannot be started fails the module. Like the other modules
of the collection, `sshd_validate` carries no GPLv3 header, so `tests/sanity/ignore-2.20.txt` and `ignore-2.21.txt`
gain exactly `plugins/modules/sshd_validate.py validate-modules:missing-gplv3-license` (ADR 0011).

All drop-ins of a run are validated in one call before the first is written. When sshd refuses (a later drop-in with an
unknown keyword, a value that this sshd does not support, a missing host key), every rule to write is
`invalid_config` with sshd's message as the reason, and nothing is installed. Check mode runs the same read-only test,
so it reports `invalid_config` too.

### 3. sshd is reloaded once, only where it runs, after a second validation

After the family changed what sshd reads (a drop-in written or removed, a vendor line changed or written back), it
validates the whole configuration again with `sshd -t`. sshd can refuse it when a run only cleans up, which validates
nothing before it removes drop-ins, while another file is invalid, or after a concurrent change. The family then rolls
back what this run created: it writes back the vendor lines it changed, removes the drop-ins it created and forgets
the ledger entries it recorded. A drop-in rewritten for a changed value keeps its new content, and what the cleanup
removed or wrote back stays as it is, with its entries forgotten, because that is the prior state. The family then
fails without reloading, so a running sshd keeps its configuration. When sshd is not installed in a trusted directory
(`available: false`), for example after openssh-server was removed with its configuration kept, the family reports
that it could not validate, and it neither rolls back, fails nor reloads, so a cleanup on such a host succeeds.
Otherwise it reads the
services with `service_facts` and reloads `ssh.service` (Ubuntu) or `sshd.service` (RHEL) only when it is running. A
reload keeps every open session, including the controller's; only new sessions use the new configuration. Where no
service manager runs, as in the Molecule containers, nothing is reloaded. On Ubuntu 24.04 `ssh.socket` has
`Accept=no`: the first connection starts `ssh.service`, which keeps running and is then reloaded like any running
service, and its own `ExecReload` runs `sshd -t` once more; before the first connection there is no sshd to reload, and
the service starts with the new configuration. In check mode nothing is validated a second time or reloaded.

When the run applies `PermitRootLogin no` or `prohibit-password` while the play itself reaches the host over SSH as
root, the family prints a `WARNING`: the open session continues, but the next run must connect as another user with
`become`. The disruptive allow-list remains the operator's acknowledgement of the lockout risk.

This is a task at the end of the family rather than a role handler. A handler of the role would run at the end of the
play, after the dispatcher's completeness check and possibly after other roles, outside the family's second
validation, and the role's guard tooling treats the task files as its only code; the task gives the same "only once,
only when changed" behaviour and keeps the validation next to the reload.

### 4. The ledger and cleanup

Every rule is `recorded_value` and records, before its drop-in is written: `method` (`dropin`), `dropin` (`null`, the
drop-in did not exist), `dropin_sha256` (the SHA-256 of what was written) and `written_line`, plus the vendor lines of
section 1a. Cleanup removes the drop-in only when its content still has the recorded SHA-256, and writes each original
vendor line back only when the file still sets the keyword on exactly one line equal to the recorded written line. It
refuses with nothing changed and the entry kept, always with a reason:

| Reason | When |
|---|---|
| `method_changed` | the entry records another method, or none |
| `not_directory` | the drop-in directory is not a directory |
| `not_regular_file` | the drop-in path is a symbolic link or another non-regular file |
| `not_owned` | the file at the drop-in path has another content and does not carry the collection's header |
| `invalid_record` | the recorded SHA-256 is missing or malformed, or a recorded vendor line is not a line of the keyword |
| `target_absent` | a vendor file whose line the collection changed no longer exists |
| `modified_since_apply` | the drop-in carries the header but its content is no longer what the collection wrote, or a vendor file no longer sets the keyword on exactly the line written; an administrator's change is never overwritten |

When the drop-in no longer exists at cleanup, the current state already equals the recorded prior state, so the rule
is reported `restored`, its entry is dropped and nothing is written (the pattern of FREES-173; for a drop-in the prior
state is its absence, so there is no setting line to compare). The same holds for a vendor line: when the file sets the
keyword on one line that equals the recorded original once keywords are compared without case and runs of spaces or
`=` are read as one separator, the line is left as it is. When a profile value changes while a rule stays on,
apply writes the new value and replaces the entry with the same prior state and the new `dropin_sha256` and
`written_line`.

Where the drop-in directory does not exist but the main file includes it, the first drop-in creates it with mode
`0700` and the empty marker `.freesecdev-created` (sshd reads only `*.conf`); the directory and the marker are removed
once nothing else is left in it, and a directory without the marker is never removed (guide, section 2). Both
distributions ship the directory, so only the regressions exercise this branch.

### 5. Rules kept `audit_only`

34 of the 63 rules are native. Of those, `sshd_use_strong_ciphers`, `sshd_use_strong_kex`, `sshd_use_strong_macs` and
the three ordered STIG rules for `Ciphers`, `KexAlgorithms` and `MACs` are refused as `crypto_policy` on RHEL 9, where
`50-redhat.conf` includes the crypto policy back end and the `crypto_policy` topic owns those settings; no pinned RHEL 9
profile selects them, and on Ubuntu, which has no crypto policies, they are written. The other 29 rules stay
`audit_only`:

| Rules | Reason |
|---|---|
| `file_permissions_sshd_config`, `file_owner_sshd_config`, `file_groupowner_sshd_config`, `file_permissions_sshd_drop_in_config`, `file_owner_sshd_drop_in_config`, `file_groupowner_sshd_drop_in_config`, `directory_permissions_sshd_config_d`, `directory_owner_sshd_config_d`, `directory_groupowner_sshd_config_d`, `file_permissions_sshd_private_key`, `file_permissions_sshd_pub_key`, `file_ownership_sshd_private_key`, `file_ownership_sshd_pub_key`, `file_groupownership_sshd_private_key`, `file_groupownership_sshd_pub_key` | Modes and ownership of files that the packages and other tools own; they follow the per-attribute pattern of `banners` and are a follow-up (FREES-177). The containers drop every capability, so ownership changes need the libvirt scenarios (FREES-61). The collection's own drop-ins already have mode `0600` and owner root |
| `sshd_limit_user_access` | Needs `AllowUsers`, `AllowGroups`, `DenyUsers` or `DenyGroups` with site-specific names; any default would lock out every other user |
| `sshd_rekey_limit` | Its check requires the setting in `sshd_config` itself and refuses it in every drop-in, and its value combines two profile values (`var_rekey_limit_size`, `var_rekey_limit_time`) that the catalogue cannot carry yet; a main-file method is a follow-up |
| `sshd_use_directory_configuration` | Requires moving every `Match` block out of `sshd_config`, a structural rewrite of a file that the collection does not own |
| `sshd_include_crypto_policy` | The `Include` of the crypto policy back end in `50-redhat.conf`, which belongs to the `crypto_policy` topic |
| `sshd_allow_only_protocol2` | Its platform is OpenSSH 7.0 or older (`package_openssh-server_le_7_0`); both platforms ship 9.x, where the keyword no longer exists |
| `file_sshd_50_redhat_exists` | Restores a file that the openssh-server package ships |
| `package_openssh-server_installed`, `package_openssh-clients_installed`, `service_sshd_enabled` | Package and service state; the containers have no service manager |
| `firewalld_sshd_port_enabled` | Firewall state, topic `firewalld` |
| `ssh_client_rekey_limit`, `ssh_client_use_approved_ciphers_ordered_stig`, `ssh_use_approved_macs_ordered_stig` | Client configuration in `/etc/ssh/ssh_config`, not the server; a follow-up |
| `ssh_keys_passphrase_protected` | Users' private keys, which only their owners can protect |

The sshd `Banner` keyword is the server's own setting and is native; the banner files themselves stay with the
`banners` topic and are never written by `ssh`.

### 6. The lifecycle harness grows again

The Molecule images install openssh-server (pinned), with host keys on Rocky Linux and `/run/sshd` on Ubuntu, so that
`sshd -t` can run; no sshd runs in the containers. The lifecycle declaration of `ssh` declares every drop-in with its
SHA-256 per platform, the vendor files `sshd_config` and `50-redhat.conf` with their checksums as built (no rule of the
lifecycle profiles changes them, which the declaration proves) and two pre-states, both with real scans: the as-built
state, and a customised one with a site drop-in read after the collection's, which sets `LoginGraceTime` and
`ClientAliveInterval`, and an earlier one that sets `MaxAuthTries` first. In the customised state those three rules are
`overridden`, nothing is written for them, and the scan must report them `fail`, which the harness now checks for
every overridden rule of a pre-state with scans. The customised pre-state runs with the rule toggle only
(`modes: [rule]`), because the overridden statuses do not depend on the toggle and a second cycle of it would push the
`topic` leg past its time budget. Four harness extensions, each checked by `tools/roles/check_lifecycle_topics.py`:

- a pre-state file may give `content`: the harness writes it as root before the cycle and removes it afterwards, which
  is how the customised pre-state adds the two site drop-ins;
- a pre-state may list rules `unchanged` with the status `overridden`, and may replace expectations of `applied`
  (`applied` inside the pre-state), so that the overridden rule's drop-in is expected absent;
- an `applied` expectation may name the same path once per platform, for a drop-in whose value differs per profile;
- a pre-state may list the toggle `modes` in which its cycles run, and `audit` may list the platforms on which its
  cycles scan. Every driver of a topic must still run a pre-state in each mode, and a leg counts its topic as proven
  only after a cycle of its own mode ran, so no toggle drops out of the proof.

`shared/tasks/lifecycle_ssh_regressions.yml` runs in the `topic` leg of `ssh`: a drop-in that sshd refuses makes every
rule `invalid_config` with nothing installed; an entry of another method is refused on apply and on cleanup; a change
by hand is kept as `modified_since_apply`; a drop-in removed by hand is restored without a write; and, on Ubuntu, where
the directory is empty as built, a missing directory is created with the marker and removed again, and a symbolic link
in its place makes every rule `not_directory` with nothing written through it.
`shared/tasks/lifecycle_ssh_vendor_regressions.yml` also runs in the `topic` leg, which runs one cycle against the
two of the `rule` leg, so that the legs stay of similar length: it adds `sshd_disable_x11_forwarding` (and on RHEL `sshd_disable_gssapi_auth`) to the profile, applies them and
checks that every occurrence that the check reads now has the compliant value, that a second apply is compliant, and
that cleanup writes the vendor file back byte for byte; that a change by hand to the changed line is kept as
`modified_since_apply` and, once restored by hand with other spacing, left alone while the rule is reported
`restored`; and that a conflicting line inside a `Match` block is refused as `overridden` and not edited.
`shared/tasks/lifecycle_ssh_rollback_regressions.yml` runs in the `rule` leg: a cleanup with an administrator's
drop-in that sshd refuses fails at the final `sshd -t`, before the reload, with the cleanup kept, and a cleanup with
the sshd binary removed succeeds.

## Benefits

34 rules of the most selected topic remediate for real with the profile's values, on both platforms, and switch off
exactly. No change reaches sshd without `sshd -t` accepting the whole effective configuration first, and nothing
restarts sshd.

## Trade-offs

One small file per rule in `sshd_config.d` instead of one shared file; the per-rule file is what makes per-rule toggles revert without
history. The `sshd` executable joins the allow-list of the process helper. Two vendor files are edited in place, so a
package update that replaces them shows up as `modified_since_apply` or `target_absent` at cleanup and needs a review. A
later setting in an administrator's drop-in is reported `overridden`, not fixed.

## Security implications

The topic is disruptive and needs `ssh` in `linux_compliance_remediate_allow_disruptive` for apply and cleanup.
`PermitRootLogin no`, `MaxAuthTries` and the algorithm lists can lock out operators who rely on root logins, many keys
or old clients; the allow-list is the operator's acknowledgement. `sshd -t` runs as root with a fixed argument form and a
timeout, never as a shell, and validation failures are reported with sshd's bounded message. The threat model
(`docs/security/threat-model.md`) lists the binary, its limits and the lockout containment. Drop-ins are written
with mode `0600`, which the CIS and STIG drop-in permission rules require.

## Operational consequences

The Ubuntu and Rocky Linux Molecule images grow by openssh-server. The `ssh` `rule` leg runs two cycles and the
rollback regressions, and the `topic` leg one cycle and the other two sets of regressions, all narrowed to two rules
(four with the vendor rules), so that each leg stays within the time budget of the merge queue. The larger images add about 45 seconds to every image build on
Rocky Linux, which took the standard `molecule-docker` scenarios past their 8-minute limit, so that limit is now 13
minutes, one and a half times their longest run as `docs/molecule.md` sets out.
