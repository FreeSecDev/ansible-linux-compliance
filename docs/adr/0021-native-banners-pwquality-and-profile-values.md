# 0021. Native banners and password quality, with profile values from the pinned content

- **Status:** proposed
- **Date:** 2026-10-27
- **Deciders:** lead architect; project owner (requirement that every topic toggle remediates for real and reverts
  exactly what the collection changed)
- **Jira:** FREES-53 (native remediations, step 3), FREES-57 (cleanup per family)
- **Pull requests:** introduced by the pull request for FREES-53 that makes `banners` and `pwquality` native
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0013](0013-normalized-findings-model.md), [ADR 0015](0015-content-acquisition-and-pinning.md),
  [native remediation guide](../native-remediation-guide.md)

## Context

Until now one rule had a native remediation, `file_permissions_crontab`; the other 1202 catalogued rules were
`audit_only`. The first topics to become native are `banners` (login banners and the message of the day) and
`pwquality` (password quality, under the `pam` umbrella). They set the pattern for every later topic.

Two questions have to be answered before any value is written:

- **Which value.** Many rules compare the host with a tailorable XCCDF `Value` whose option the profile chooses with a
  `refine-value`: `var_password_pam_minlen` is 14 in the CIS profiles, 12 in OSPP and CCN and 15 in the STIG and ANSSI
  profiles; `login_banner_text` is a regular expression of the DoD notice in the STIG profiles and of a generic notice
  in the CCN profiles. A remediation that writes its own value can satisfy one profile and fail another.
- **How to revert exactly.** The project owner requires that switching a topic from on to off reverts exactly what the
  collection changed: a file that was absent is removed, a file that was present gets back its content, mode, owner and
  group. Several rules share one file (the banner text, mode, owner and group of `/etc/issue` are four rules), and
  every rule has its own toggle.

The pinned ComplianceAsCode 0.1.82 content was read to decide what each rule expects (rule descriptions and OVAL
checks of `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml`):

- The banner text rules `banner_etc_issue_cis`, `banner_etc_issue_net_cis` and `banner_etc_motd_cis` (CIS profiles of
  both platforms) require `/etc/issue` and `/etc/issue.net` to be non-empty and none of the three files to contain the
  getty escapes `\v`, `\r`, `\m`, `\s` or the operating system name (`ubuntu2404`, `Ubuntu 24.04`, `rhel9`,
  `Red Hat Enterprise Linux 9`). They export no value; the description names the value `cis_banner_text`, whose
  default is "Authorized users only. All activity may be monitored and reported." `banner_etc_issue`,
  `banner_etc_issue_net` and `banner_etc_motd` (STIG and CCN profiles) require the whole file, read as one string, to
  match the regular expression of `login_banner_text`, `remote_login_banner_text` or `motd_banner_text`. A missing
  `/etc/motd` passes both motd checks.
- The mode, owner and group rules of the three files require at most `0644` (no set-id, sticky, execute or group and
  world write bits), uid 0 and gid 0, and pass when the file is missing or a symbolic link.
- `libpwquality` reads `<cfgfile>.d/*.conf` in lexical order and then the main file, so the main file
  `/etc/security/pwquality.conf` overrides every drop-in and a later drop-in overrides an earlier one (upstream
  `src/settings.c`; the directory is read since release 1.3.0; Ubuntu 24.04 ships 1.4.5 and Rocky Linux 9 1.4.4). The
  Rocky Linux 9 package ships `/etc/security/pwquality.conf.d`; the Debian and Ubuntu packages do not create it, and the
  Ubuntu 24.04 base image has no libpwquality at all.
- The RHEL 9 checks of the pwquality settings read `/etc/security/pwquality.conf` and every
  `/etc/security/pwquality.conf.d/*.conf` and require every occurrence to satisfy the profile value. The Ubuntu 24.04
  checks read only `/etc/security/pwquality.conf`. Every pwquality check also requires `pam_pwquality.so` in
  `/etc/pam.d/system-auth` (RHEL) or `/etc/pam.d/common-password` (Ubuntu), and every pwquality and banner text rule
  carries the `system_with_kernel` platform, so a container audit reports them `notapplicable`.

## Decision

### 1. Profile values are read from the pinned datastream at generation time

A native rule of `content/catalogue.yml` that depends on a value names it in `profile_value` (the short identifier,
for example `var_password_pam_minlen`). `tools/roles/generate_catalogue.py` reads, with `tools/roles/profile_values.py`,
every `Value` with its options, the `refine-value` of every profile and the `check-export` of every rule from each
pinned datastream, after verifying its SHA-256 and while hashing it a second time, through the bounded parser of
`xmlsafe`. It writes into the rule's parameters `value_id` and `profile_values`: per datastream (`datastream`,
`content_sha256`), the sorted profiles that share one value and the value, split into chunks that the catalogue renders
within its line length. A profile without a `refine-value` gets the value's default. Generation fails when a selecting
datastream does not define the value, when the rule's checks there do not export it, when a profile refines it to an
option that does not exist, and when the value has no default. `make test-content-golden` regenerates the catalogue
from the pinned content in CI, so the values cannot drift from it.

At run time the family file takes the entry whose `content_sha256` equals `linux_compliance_discovered.content_sha256`
and whose profiles contain `linux_compliance_remediate_profile`. Both come from the `discover` role, which verified the
digest and the profile. A rule planned for apply without such an entry fails the family before it changes anything, so
other content versions and other profiles are never served a guessed or substituted value.

Rejected alternatives:

| Alternative | Reason rejected |
|---|---|
| Role defaults per setting, validated against the profile at run time | The defaults would repeat the content for 25 profiles and still need the profile's values to be validated, so the content would be read anyway; a default that suits one profile silently fails another |
| Reading the values from the datastream on the managed host | Needs a new parse of untrusted-until-verified content in the `discover` module on every host; the catalogue already holds the content-derived data, is reviewed in the pull request and is checked against the pinned content in CI |
| One value per setting for all profiles (the strictest) | Not what the profile requires: a stricter `difok` or `minlen` than CIS is a different baseline, and `dictcheck` and `enforcing` have no "stricter" |

This refines the FREES-53 amendment of ADR 0011, which wrote only identifiers of the BSD-3-Clause content: the values
that native rules need are now copied as written. They are short numbers, and for the banner rules the regular
expressions of the notices, which include the text of the DoD notice. The content is attributed in `NOTICE`; no other
benchmark prose is copied.

### 2. The banner text is an operator variable with the content's default

`linux_compliance_remediate_banner_text` (remediate role, default "Authorized users only. All activity may be
monitored and reported.", the default of `cis_banner_text`) is written, with one trailing newline, to every banner
file whose text rule is applied. Before the family changes anything, the text must be non-empty, at most 4096
characters, free of backslashes and of control characters other than newline and tab, free of the operating system
names of the CIS checks (the `forbidden_pattern` parameter of the CIS rules), and, when the profile gives the rule a
value, match that regular expression as the OVAL check does (the whole text as one string). The STIG profiles therefore
need the DoD notice; the default text fails them closed with a message that names the value. Deriving the DoD text from
its regular expression was rejected: it would make the collection publish a government notice on any host that selects
a STIG profile without the operator choosing to.

### 3. Banners: one recorded value per attribute

Every banner rule is `recorded_value` and records only the attribute it changes, before it changes it:
`content_base64` (the base64 of the prior content, or `null` when the file did not exist; files over 3072 bytes are
refused as `prior_too_large`, so the record fits the ledger's 4096 characters), `mode`, `owner` (uid) or `group` (gid).
Cleanup restores exactly that attribute and nothing else, so switching off only the mode rule leaves the banner text,
and switching off the text rule of a file that did not exist removes the file. A missing file is created by the text
rule with mode `0644`, owner and group root, as ComplianceAsCode's own fix does; the mode, owner and group rules then
find it compliant, and in check mode they predict that from the file the text rule would create. A symbolic link or
other non-regular file is never changed (`not_regular_file`). A file that disappeared or changed type before cleanup
keeps its ledger entry and reports `cleanup_incomplete`, as for `file_permissions` (ADR 0011, FREES-52 amendment).
The content is rewritten with `ansible.builtin.copy`, which replaces the inode; the content hash, mode, owner and
group are restored, the inode and mtime are not.

### 4. Password quality: one owned drop-in per rule

Every pwquality rule is `owned_dropin`: it writes `/etc/security/pwquality.conf.d/50-freesecdev-<setting>.conf` with
a header that names the rule and one setting with the profile value (`enforce_for_root` is a flag without value). The
main file is never touched. Cleanup removes the drop-in when it carries the header; a file at that path without the
header is never overwritten or removed (`not_owned`). When the directory does not exist (Ubuntu) the first drop-in
creates it with mode `0755` and an empty marker file `.freesecdev-created`, which libpwquality ignores because it
reads only `*.conf`; after the family's cleanup and apply the directory and the marker are removed when nothing else is
left in it, so an absent directory is absent again. A directory that existed is never removed. The rule reports
`notapplicable` when `/etc/security/pwquality.conf` does not exist, because libpwquality is not installed, and
`overridden` without changing anything when the main file or a drop-in that libpwquality reads later sets the same
setting, because the drop-in would not be in force and the result would claim a remediation that did not happen.

Kept `audit_only`, each with its reason:

| Rule | Reason |
|---|---|
| `accounts_password_pam_pwquality_enabled`, `accounts_password_pam_pwquality_password_auth`, `accounts_password_pam_pwquality_system_auth` | They put `pam_pwquality.so` into the PAM stack, which belongs to the `pam` topic |
| `accounts_password_pam_retry` | Its check reads `retry=` from the `pam_pwquality` arguments of the PAM stack first, and otherwise only the main file, never a drop-in; the PAM stack belongs to `pam` |
| `package_pam_pwquality_installed` | Installing the package is package state, and on Ubuntu its post-installation script runs `pam-auth-update`, which changes the PAM stack |
| `banner_etc_profiled_ssh_confirm` (banners) | It installs a login script that asks SSH users for confirmation; its value is a regular expression of the whole script, and it changes the behaviour of interactive SSH sessions |
| `dconf_gnome_banner_enabled`, `dconf_gnome_login_banner_text` (banners) | They need GDM, which neither the containers nor server profiles have (`package_gdm` platform); on RHEL the dconf database must be compiled with `dconf update`, a command; they belong with the `desktop` topic and need the libvirt scenarios |

Known gap: on Ubuntu 24.04 the pinned content reads only `/etc/security/pwquality.conf`, so a host audit reports the
pwquality rules as failing although the drop-ins are in force. Writing the main file on Ubuntu only would make the
audit pass, but edits a file that the package owns and that the operator may manage; the decision is recorded as a
follow-up for the lead (FREES-53 comment) rather than taken silently here.

`pwquality` stays disruptive under the `pam` umbrella: its rules can reject every password change, including root's
(`enforce_for_root`). It is applied and cleaned up only with `pwquality` or `pam` in
`linux_compliance_remediate_allow_disruptive`.

### 5. The toggle lifecycle harness grows with the topics

The FREES-60 harness proved one rule whose every pre-state was non-compliant and whose file kept its inode. Three
extensions, each checked by `tools/roles/check_lifecycle_topics.py` and self-checks of the harness:

- `state.files[].rewritten: true` declares a file whose content the topic rewrites; its inode and mtime are not
  compared after cleanup (the declared state and the whole-instance comparison), while its existence, type, content
  hash, mode, owner and group still are.
- `pre_states[].unchanged` lists rules that the pre-state already satisfies (`compliant`) or that do not apply
  (`notapplicable`), optionally per platform. They must report that status and change nothing, are not recorded, plan
  `none` when switched off and report no cleanup; every other rule must still be `applied` and changed, and at least
  one rule of a pre-state must change something.
- Each remediate run of a topic narrows `linux_compliance_discovered.rule_ids` to the rules of that topic and restores
  it afterwards, and fails if a rule outside the topic was applied or cleaned up, so topics cannot interfere and a
  cleanup can be compared exactly.

`converge` and `verify` keep proving the reference rule alone; their plays switch off every other native topic and
check that the list of those topics matches the catalogue.

## Benefits

Every banner and pwquality rule that can be remediated natively and safely is now remediated, with the value of the
selected profile and an exact revert per rule. The profile values are reviewed data in the catalogue, checked against
the pinned content in CI. The patterns (per-attribute records, owned drop-ins, a marker for a created directory,
generated profile values) are reusable by the next topics, as the [guide](../native-remediation-guide.md) describes.

## Trade-offs

The catalogue grows by about 750 lines, most of them the chunked regular expressions of the banner values. A new
content version can change values; the golden check then fails until the catalogue is regenerated and reviewed, which
is intended. Rewritten files get a new inode. Operators of STIG profiles must set the banner text.

## Security implications

Password quality settings can lock users out of password changes; they stay behind the allow-list for apply and
cleanup. Banner text is validated before anything changes and cannot inject getty escapes. The prior content of a
banner file is stored in the root-only ledger; banner files are public, so it is not marked sensitive. The marker file
proves only that the collection created the directory; removing it by hand makes the collection keep the directory.

## Operational consequences

`make catalogue` reads the values (a second bounded parse per datastream). The Ubuntu Molecule image installs
`libpam-pwquality` (pinned) so that the pwquality lifecycle runs on both platforms. The harness runs four banner
cycles and two pwquality cycles per platform in addition to the four of `file_permissions`. The containers drop every
capability, so root cannot change ownership there: the owner and group rules are proven compliant on the as-built
root-owned files, and their change and restore are not exercised in a container; the customised banner pre-state
changes the mode only. Changing and restoring ownership needs the libvirt scenarios (FREES-61).
