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
it first and its value takes effect. Both pinned contents read the drop-ins, so the audit sees the value; the main
file is never edited. `tests/unit/tools/test_content_golden_ssh.py` checks against the OVAL of both datastreams that the
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
| `overridden` | `sshd_config` sets the keyword before its `Include`, or a drop-in that sorts before the rule's own sets it, includes other files or cannot be read; the reason names the files |
| `not_included` | `sshd_config` has no `Include` of `/etc/ssh/sshd_config.d/*.conf` before its first `Match` block, so a drop-in would not apply globally |
| `crypto_policy` | `Ciphers`, `MACs` or `KexAlgorithms` on RHEL 9, where the system-wide crypto policy governs them (section 5) |
| `invalid_config` | `sshd -t` refuses the configuration with the settings to write (section 2) |
| `not_directory`, `not_regular_file`, `not_owned` | the drop-in directory is not a directory (a symbolic link included), the drop-in path is not a regular file, or a file at that path does not carry the collection's header |
| `notapplicable` | `sshd_config` or the `sshd` executable is missing: openssh-server is not installed |
| `method_changed` | the ledger entry was recorded by another method |

A later setting of the same keyword (Ubuntu's `X11Forwarding yes`, `GSSAPIAuthentication yes` in `50-redhat.conf`)
does not stop the rule, because sshd ignores it; the result message names it. The content's check reads every
occurrence, so such a rule is applied but still fails the audit until the later line is changed. The collection does
not edit files that it does not own; this gap is recorded here and named in every result it affects.

### 2. Every change is validated with `sshd -t` before it is written

The file modules' `validate` parameter is refused by the repository guard (ADR 0004, FREES-159), and a drop-in on its
own is not the configuration that sshd loads. The new module `freesecdev.linux_compliance.sshd_validate` runs
`sshd -t -f /etc/ssh/sshd_config` through the audited process helper, with every setting to write as
`-o <Keyword>=<value>`. sshd processes command-line options first and keeps the first value, so the test validates the
whole effective configuration, the main file and every drop-in it includes, exactly as it will be with the new drop-ins
read first. The helper's allow-list gains `sshd` with only that form (an amendment of ADR 0004): the prefix
`-t -f /etc/ssh/sshd_config` and the option `-o`; `-T`, `-D`, `-d`, `-h`, `-E`, `-C`, another configuration file and
every other option are refused, and the module accepts only the keywords of the native rules and one-word values.
sshd in test mode reads the configuration and the host keys and exits; it starts no daemon.

All drop-ins of a run are validated in one call before the first is written. When sshd refuses (a later drop-in with an
unknown keyword, a value that this sshd does not support, a missing host key), every rule to write is
`invalid_config` with sshd's message as the reason, and nothing is installed. Check mode runs the same read-only test,
so it reports `invalid_config` too.

### 3. sshd is reloaded once, only where it runs, after a second validation

After the family changed what sshd reads, it reads the services with `service_facts` and, only when `ssh.service`
(Ubuntu) or `sshd.service` (RHEL) is running, validates the whole configuration again and reloads the service. A reload
keeps every open session, including the controller's; only new sessions use the new configuration. When the second
validation fails, the family fails without reloading, so a running sshd keeps its configuration. Where no service
manager runs, as in the Molecule containers, or sshd is socket-activated (Ubuntu's `ssh.socket`, which starts a fresh
sshd for each connection), nothing is reloaded. In check mode nothing is reloaded.

This is a task at the end of the family rather than a role handler. A handler of the role would run at the end of the
play, after the dispatcher's completeness check and possibly after other roles, outside the family's second
validation, and the role's guard tooling treats the task files as its only code; the task gives the same "only once,
only when changed" behaviour and keeps the validation next to the reload.

### 4. The ledger and cleanup

Every rule is `recorded_value` and records, before its drop-in is written: `method` (`dropin`), `dropin` (`null`, the
drop-in did not exist), `dropin_sha256` (the SHA-256 of what was written) and `written_line`. Cleanup removes the
drop-in only when its content still has the recorded SHA-256, and refuses with nothing changed and the entry kept,
always with a reason:

| Reason | When |
|---|---|
| `method_changed` | the entry records another method, or none |
| `not_directory` | the drop-in directory is not a directory |
| `not_regular_file` | the drop-in path is a symbolic link or another non-regular file |
| `not_owned` | the file at the drop-in path has another content and does not carry the collection's header |
| `invalid_record` | the recorded SHA-256 is missing or malformed |
| `modified_since_apply` | the drop-in carries the header but its content is no longer what the collection wrote; an administrator's change is never removed |

When the drop-in no longer exists at cleanup, the current state already equals the recorded prior state, so the rule
is reported `restored`, its entry is dropped and nothing is written (the pattern of FREES-173; for a drop-in the prior
state is its absence, so there is no setting line to compare). When a profile value changes while a rule stays on,
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
| `file_permissions_sshd_config`, `file_owner_sshd_config`, `file_groupowner_sshd_config`, `file_permissions_sshd_drop_in_config`, `file_owner_sshd_drop_in_config`, `file_groupowner_sshd_drop_in_config`, `directory_permissions_sshd_config_d`, `directory_owner_sshd_config_d`, `directory_groupowner_sshd_config_d`, `file_permissions_sshd_private_key`, `file_permissions_sshd_pub_key`, `file_ownership_sshd_private_key`, `file_ownership_sshd_pub_key`, `file_groupownership_sshd_private_key`, `file_groupownership_sshd_pub_key` | Modes and ownership of files that the packages and other tools own; they follow the per-attribute pattern of `banners` and are a follow-up. The containers drop every capability, so ownership changes need the libvirt scenarios (FREES-61). The collection's own drop-ins already have mode `0600` and owner root |
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
SHA-256 per platform and two pre-states, the as-built state and a customised one with a site drop-in read after the
collection's and an earlier one that sets `MaxAuthTries` first. Three harness extensions, each checked by
`tools/roles/check_lifecycle_topics.py`:

- a pre-state file may give `content`: the harness writes it as root before the cycle and removes it afterwards, which
  is how the customised pre-state adds the two site drop-ins;
- a pre-state may list rules `unchanged` with the status `overridden`, and may replace expectations of `applied`
  (`applied` inside the pre-state), so that the overridden rule's drop-in is expected absent;
- an `applied` expectation may name the same path once per platform, for a drop-in whose value differs per profile.

`shared/tasks/lifecycle_ssh_regressions.yml` runs in the `topic` leg of `ssh`: a drop-in that sshd refuses makes every
rule `invalid_config` with nothing installed; an entry of another method is refused on apply and on cleanup; a change
by hand is kept as `modified_since_apply`; a drop-in removed by hand is restored without a write; and, on Ubuntu, where
the directory is empty as built, a missing directory is created with the marker and removed again, and a symbolic link
in its place makes every rule `not_directory` with nothing written through it.

## Benefits

34 rules of the most selected topic remediate for real with the profile's values, on both platforms, and switch off
exactly. No change reaches sshd without `sshd -t` accepting the whole effective configuration first, and nothing
restarts sshd.

## Trade-offs

One small file per rule in `sshd_config.d` instead of one shared file; the per-rule file is what makes per-rule toggles revert without
history. The `sshd` executable joins the allow-list of the process helper. A later setting of a keyword in a file that
the collection does not own still fails the audit (section 1).

## Security implications

The topic is disruptive and needs `ssh` in `linux_compliance_remediate_allow_disruptive` for apply and cleanup.
`PermitRootLogin no`, `MaxAuthTries` and the algorithm lists can lock out operators who rely on root logins, many keys
or old clients; the allow-list is the operator's acknowledgement. `sshd -t` runs as root with a fixed argument form and a
timeout, never as a shell, and validation failures are reported with sshd's bounded message. Drop-ins are written
with mode `0600`, which the CIS and STIG drop-in permission rules require.

## Operational consequences

The Ubuntu and Rocky Linux Molecule images grow by openssh-server. Each `ssh` lifecycle leg runs two cycles, and the
`topic` leg the regressions as well, narrowed to two rules so that the leg stays within the time budget of the merge
queue.
