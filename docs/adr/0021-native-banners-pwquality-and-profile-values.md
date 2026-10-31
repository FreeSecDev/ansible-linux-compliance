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
rule with mode `0644`, owner and group root, the most that the OVAL checks of its mode, owner and group rules accept
(amended by [ADR 0025](0025-own-ansible-remediation-only.md): the content's fix is not a reference); those rules then
find it compliant, and in check mode they predict that from the file the text rule would create. A symbolic link or
other non-regular file is never changed (`not_regular_file`). A file that disappeared or changed type before cleanup
keeps its ledger entry and reports `cleanup_incomplete`, as for `file_permissions` (ADR 0011, FREES-52 amendment).
The content is rewritten with `ansible.builtin.copy`, which replaces the inode; the content hash, mode, owner and
group are restored, the inode and mtime are not.

### 4. Password quality: written where the content of each platform checks

Decided by the lead after review: the remediation follows what the pinned content checks on each platform, so that
the audit agrees with the remediation. The OVAL of the pinned 0.1.82 datastreams, read per rule, says:

- **RHEL 9:** every native pwquality check reads `^/etc/security/pwquality\.conf(\.d/[^/]+\.conf)?$`, the main file
  and every drop-in (13 rules; `accounts_password_pam_enforcing` has no RHEL definition).
- **Ubuntu 24.04:** every native pwquality check reads only `^/etc/security/pwquality.conf$` (12 rules).

Each pwquality rule names the benchmarks whose content checks only the main file in `main_file_benchmarks` (today
`xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04`), and the family chooses the method from the benchmark that the
`discover` role verified. `tests/unit/tools/test_content_golden_native.py` checks every rule against the OVAL objects
of both pinned datastreams, so a content update that moves a check fails CI until the parameter follows. Every
pwquality rule is `recorded_value`.

- **Main file (Ubuntu).** `ansible.builtin.lineinfile` writes one line per setting into
  `/etc/security/pwquality.conf` (`minlen = 14`, or `enforce_for_root`): it replaces the one active line of the
  setting, or appends the line when there is none. Before the change the ledger records the exact prior state of the
  setting and of the file: `setting_line` (the active line as it was, or `null` when the setting was absent), `mode`,
  `owner`, `group` and `sha256` of the file, with the `method` and the `written_line`. The collection never changes the
  file's mode or ownership (`lineinfile` keeps them), so cleanup requires them to be unchanged rather than setting
  them. Cleanup writes the recorded line back in place, or removes the setting when it was absent; with every rule
  cleaned up the file
  is byte for byte the original, which the toggle lifecycle checks by SHA-256. No drop-in directory is created. A
  setting that is active on more than one line is not touched (`duplicate_setting`), because libpwquality would take
  the last one and the content's check requires every one to comply. Nothing overrides the main file, which
  libpwquality reads last.
- **Drop-ins (RHEL).** One drop-in per rule, `/etc/security/pwquality.conf.d/50-freesecdev-<setting>.conf`, with a
  header that names the rule; the main file is not touched. The ledger records that the drop-in did not exist
  (`dropin: null`); cleanup removes it when it carries the header, and a file at that path without the header is never
  overwritten or removed (`not_owned`). A rule is `overridden`, without any change, when the main file or a drop-in
  that libpwquality reads later sets the same setting. Where the directory does not exist, the first drop-in creates
  it with mode `0755` and an empty marker `.freesecdev-created`, which libpwquality ignores because it reads only
  `*.conf`, and the directory and the marker are removed when nothing else is left in it. The Rocky Linux 9 package
  ships the directory, so the Molecule lifecycle does not exercise this branch; the first version of this change did
  exercise it on Ubuntu.

On both platforms a rule is `notapplicable` when `/etc/security/pwquality.conf` does not exist, because libpwquality
is not installed, as in the content.

Refinements after the security review of PR #56 (findings B1, N1 and N2):

- **The method belongs to the ledger entry.** Every entry records `method` (`main_file` or `dropin`) next to what it
  wrote: `written_line` for the main file, `dropin_sha256` (the SHA-256 of the drop-in written) for a drop-in. The
  benchmark only selects the method for new work. When an entry was recorded by the other method, which happens when a
  content update moves a check to the other file, apply reports `method_changed` and writes nothing, and cleanup
  reports `cleanup_incomplete` with the reason `method_changed`, keeps the entry and changes nothing. An entry without
  a recorded method counts as the other method. Without this, a main-file entry cleaned up through the drop-in path
  was forgotten and reported `restored` while the line stayed in place.
- **Cleanup never overwrites a later change.** Before it restores anything, cleanup checks that the state is still
  what the collection wrote: with the main file, the setting is active on exactly one line equal to `written_line`, and
  the mode, owner and group of the file are the recorded ones; with a drop-in, its content has the recorded SHA-256.
  Otherwise the result is `cleanup_incomplete` with the reason `modified_since_apply`, the file is left alone and the
  entry is kept, so an administrator's later change survives and the rule is reported as not reverted. When the
  profile value changes while a rule stays applied, apply writes the new value and replaces the entry with the same
  prior state and the new `written_line` or `dropin_sha256`, so the check keeps matching.
- **No symbolic links are followed.** A `pwquality.conf.d` that exists but is not a directory, a symbolic link
  included, makes every drop-in rule `not_directory` (apply) or `cleanup_incomplete` (`not_directory`) without any
  change; a drop-in that is a symbolic link is `not_regular_file`; and the directory and the marker are removed only
  when the directory is a real directory and the marker a regular file. A file at a drop-in's path without the
  collection's header is `not_owned` whether or not a ledger entry exists.

Kept `audit_only`, each with its reason:

| Rule | Reason |
|---|---|
| `accounts_password_pam_pwquality_enabled`, `accounts_password_pam_pwquality_password_auth`, `accounts_password_pam_pwquality_system_auth` | They put `pam_pwquality.so` into the PAM stack, which belongs to the `pam` topic |
| `accounts_password_pam_retry` | Its check reads `retry=` from the `pam_pwquality` arguments of the PAM stack first, and otherwise only the main file, never a drop-in; the PAM stack belongs to `pam` |
| `package_pam_pwquality_installed` | Installing the package is package state, and on Ubuntu its post-installation script runs `pam-auth-update`, which changes the PAM stack |
| `banner_etc_profiled_ssh_confirm` (banners) | It installs a login script that asks SSH users for confirmation; its value is a regular expression of the whole script, and it changes the behaviour of interactive SSH sessions |
| `dconf_gnome_banner_enabled`, `dconf_gnome_login_banner_text` (banners) | They need GDM, which neither the containers nor server profiles have (`package_gdm` platform); on RHEL the dconf database must be compiled with `dconf update`, a command; they belong with the `desktop` topic and need the libvirt scenarios |

Upstream gap, kept documented: the Ubuntu 24.04 checks of the pinned content ignore
`/etc/security/pwquality.conf.d`, although libpwquality 1.4.5 reads it (since 1.3.0). A drop-in therefore takes effect
on Ubuntu but is not seen by the audit; settings that an operator keeps in drop-ins are invisible to the Ubuntu audit.
This is a ComplianceAsCode limitation to report upstream; the collection does not depend on it, because on Ubuntu it
writes the main file.

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
the pinned content in CI. The patterns (per-attribute records, one line per setting in a shared file, drop-ins per rule, a marker for a created directory,
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
`libpam-pwquality` (pinned) so that the pwquality lifecycle runs on both platforms: through the main file on
Ubuntu and through drop-ins on Rocky Linux. The harness runs four banner
cycles and two pwquality cycles per platform in addition to the four of `file_permissions`. The containers drop every
capability, so root cannot change ownership there: the owner and group rules are proven compliant on the as-built
root-owned files, and their change and restore are not exercised in a container; the customised banner pre-state
changes the mode only. Changing and restoring ownership needs the libvirt scenarios (FREES-61).

## Amendment of 2026-10-31: password quality as libpwquality reads it (FREES-200)

**Context.** The `pwquality` family found settings with regular expressions of its own (`^[ \t]*minlen[ \t]*=`,
case-sensitive, `=` required) and wrote and restored the main file with `ansible.builtin.lineinfile`. Reviews of the
other families found such parsers diverging from the real reader. libpwquality cannot print the configuration it
uses, so a verdict table was produced with the real library of both Molecule images (libpwquality 1.4.5-3build1 on
Ubuntu 24.04, 1.4.4-8.el9 on Rocky Linux 9), through `ctypes` calls of `pwquality_read_config`,
`pwquality_set_option` and `pwquality_get_int_value`. It confirms what `src/settings.c` and `src/pam_pwquality.c`
of those releases do:

- Every directory entry whose name holds `.conf` only at its end is read, dot files included (`.x.conf`) and
  `a.conf.conf` not, in `strcmp` order, and then the main file; a symbolic link is followed, a directory and a link
  to nothing add nothing.
- The first line that the library cannot read stops the whole configuration, and what was read until then stays:
  an unknown name, a value that `strtol` does not read completely (`14x`, `= 14` after `=`, `minlen =`, a lone CR
  inside the value), a NUL byte that is not the first byte of its line, and a line of 1023 bytes or more, comment or
  not, including a last line of exactly 1023 bytes without a line break. A bad drop-in therefore means the main file
  is never read. `pam_pwquality` logs the error and goes on.
- `#` starts a comment anywhere; space, tab, CR, VT, FF and LF are white space around the name and the value; the
  name ends at the first white space or `=` (`minlen 14` and `minlen=14` are read); names are compared without case
  (`MINLEN = 8` is read); the last occurrence wins; `minlen` below 6 is read as 6, `minclass` above 4 as 4, and
  `enforce_for_root = 0` sets the flag.
- The arguments of `pam_pwquality` in every PAM stack override the files (`minlen=8`, `MINLEN=8`,
  `enforce_for_root`), and an argument that the library refuses changes nothing.

The table holds 228 cases, every file state that a decision of the family leaves (1323 states, read identically in
both images) and the 1824 decisions of four rules (`minlen`, `minclass`, `retry`, `enforce_for_root`) with both
methods. Measured against it, the family on main reported a rule `compliant` or `applied` while the library held a
looser value for: a looser second line in another case or without `=` (`MINLEN = 6`, `minlen 6`), a looser later
drop-in written in upper case, a malformed or over-long line before the setting, a bad or over-long drop-in read
before the main file, a dot file drop-in that stops the reading, a later drop-in that is a symbolic link, a
`pam_pwquality` argument, and a `minlen` line without a value, after which the appended line was never read; and it
rewrote a CRLF file or one with a lone CR other than byte for byte.

**Decision.**

- `plugins/module_utils/compliance/pwquality.py` reproduces the reader on the bytes of the files, and the filters
  `pwquality_decide` and `pwquality_restore` decide and restore every rule with it. A rule is `compliant` or `applied`
  only when the library, reading the files as they are or as they will be after the write, takes the profile's value
  from the line or the drop-in that the rule writes. Otherwise nothing is written and the rule is `unreadable_file`
  (the reading stops before the rule's value, a drop-in that libpwquality reads is a symbolic link or not a regular
  file, or the main file is not UTF-8 text or holds a NUL), `overridden` (a later file sets another value, with the
  file and line in the reason), `duplicate_setting` (two lines of the main file set the setting, in any case and
  spacing) or `unreadable_value` (the setting's line holds a control character other than a tab or a CR, which the
  ledger cannot record).
- Every PAM file below `/etc/pam.d` and `/usr/lib/pam.d`, read through symbolic links, is searched: on every line that
  names `pam_pwquality` and is not a comment line, with continued lines joined, every word that names the setting and
  does not set exactly the profile's value makes the rule `overridden`, with the file and the argument in the reason.
  This finds more than PAM passes to the module and never less; `retry=3` on the lines that both images ship
  overrides only a `retry` rule whose value is not 3.
- The family reads every entry of the drop-in directory, dot files included, and the main file is written and
  restored with `ansible.builtin.copy` of the whole text read, with the setting's line replaced in place, appended or
  removed with its line break, and the file's mode; CRs everywhere stay as they were. `lineinfile` is no longer used.
- `tools/lint/pwquality_readers.sh <Ubuntu image> <Rocky image>` regenerates
  `tests/fixtures/pwquality_readers/verdicts.json` from `cases.json`: the decisions are computed on the controller,
  and `tools/lint/pwquality_readers_probe.py` reads every state in throwaway containers of both Molecule images with
  `--network none` and read-only mounts. `tests/unit/tools/test_pwquality_verdicts.py`
  checks that the reader of the collection reads every state as the library did, that every decision is the one in
  the table, and that no `compliant` or `applied` decision leaves a value that the library does not hold.
- A regression group `readers` (`shared/tasks/lifecycle_pwquality_readers_regressions.yml`, a Docker leg per
  platform) applies `minlen` and `enforce_for_root` over a main file with CRLF line ends, a lone CR in a comment and
  `minlen = 8` (rewritten in place on Ubuntu, `overridden` by the main file on Rocky Linux), cleans up byte for byte,
  and refuses both rules, with nothing written, under a PAM file that passes `minlen=8` and a drop-in read first with
  `minlen == 14`, which stops libpwquality.
