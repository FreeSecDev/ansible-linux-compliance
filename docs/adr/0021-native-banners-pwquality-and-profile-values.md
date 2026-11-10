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

The table holds 273 cases, every file state that a decision of the family leaves (1795 states, read identically in
both images) and the 2730 decisions of five rules (`minlen`, `minclass`, `retry`, `enforce_for_root`, `enforcing`)
with both methods. Measured against it, the family on main reported a rule `compliant` or `applied` while the library held a
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

**Review of PR #89, round 1.**

- *A linked drop-in directory is refused with both methods (F2).* libpwquality follows a symbolic link at
  `/etc/security/pwquality.conf.d` with `scandir`; a bad drop-in there stops the reading before the main file. The
  main file method, used on Ubuntu, now refuses with `not_directory` as the drop-in method does; the table has cases
  with a linked directory, which the probe installs as a link to a real directory.
- *`enforcing = 0` refuses every other rule, and `local_users_only` is reported (F7).* With `enforcing` at 0 in the
  files or a `pam_pwquality` argument, libpwquality only warns, so a rule is `overridden` with that reason instead of
  `applied`. With `local_users_only` set, an applied or compliant rule says in its message that it applies to local
  users only; the shipped Rocky Linux stack sets it, so refusing would refuse every rule there.
- *A PAM line that includes a file by absolute path refuses the rule (F8)*, because Linux-PAM opens that file
  wherever it is and the collection reads only `/etc/pam.d` and `/usr/lib/pam.d`.
- *Every write re-checks the file (F3), and a cleanup is `restored` only after a SHA-256 match (F5).* Right before the
  main file is recorded and written, and right before it is written back, its SHA-256 must be that of the text read;
  otherwise the rule is `modified_since_read` with nothing written. After it is written back, its SHA-256 must be
  that of the text written, or the entry is kept with `write_mismatch`. The recorded `sha256` of the file before the
  rule changed it is compared with the restored text: the message says when the file is byte for byte as recorded,
  and that only the line is back when other lines changed since, for example by rules that are still applied.

**Review of PR #89, round 2.**

- *Every form of `enforcing = 0` in PAM refuses the other rules (N2).* A `pam_pwquality` argument is read as
  `pwquality_set_option` reads it, with `strtol`, so `enforcing=00`, `enforcing=+00`, `enforcing=-00` and
  `enforcing=000` are 0 as `enforcing=0` is, and every other rule is `overridden`.
- *A PAM include of any path with a `/` refuses the rule (N4).* Linux-PAM opens a relative path below `/etc/pam.d`, so
  `include ../security/x` opens a file outside the PAM files that the collection reads, as an absolute path does;
  only a bare name in the PAM directory is accepted.
- *The file name filter of the drop-ins ends with `\Z` (N7)*, so a name that ends in a line break, which libpwquality
  does not read, is not taken for a `.conf` file.
- *A cleanup that ends in `write_mismatch` says that the main file was written back (N6)*, instead of saying that
  nothing was changed.

## Amendment of 2026-11-10: the vendor PAM directory (FREES-211)

**Context.** The amendment of FREES-200 decided that every PAM file below `/etc/pam.d` and `/usr/lib/pam.d` is
searched for `pam_pwquality` arguments, and its reviews explained the include refusals with "the collection reads
only `/etc/pam.d` and `/usr/lib/pam.d`" (F8) and "Linux-PAM opens a relative path below `/etc/pam.d`" (N4).
[ADR 0027](0027-native-faillock-pwhistory.md) records that libpam also opens a service from the vendor directory
`/usr/share/pam.d`, and the `faillock` and `pwhistory` families read it. A `pam_pwquality minlen=8` line in a service
file that only `/usr/share/pam.d` holds was therefore not read: the family could report `minlen` `compliant` or
`applied` while libpwquality, called through that service, used 8.

The source of `libpam/pam_handlers.c` in both Molecule images, fetched the way `make pam-reader-verdicts` fetches it
(linux-pam 1.5.1-28.el9 and 1.5.3-5ubuntu5.7), and the strings of the installed `libpam.so.0` show:

- `_pam_open_config_file` opens a service name and every `include` and `substack` target the same way, and on Ubuntu,
  whose libpam also accepts `@include` (Rocky Linux's refuses the line), every `@include` target too:
  an absolute path as given, and any other name in the first of `/etc/pam.d/<name>`, `/usr/lib/pam.d/<name>` and,
  only when libpam is built with a vendor directory, `/usr/share/pam.d/<name>` that it can open. A relative target is
  looked up in each directory in turn, not only below `/etc/pam.d`.
- Rocky Linux 9 builds pam with `--enable-vendordir=/usr/share` and ships an empty `/usr/share/pam.d`. The Ubuntu
  24.04 package is built without a vendor directory: its `libpam.so.0` names only `/etc/pam.d` and `/usr/lib/pam.d`,
  and the image has no `/usr/share/pam.d`.

**Decision.**

- The family reads the shared list `__linux_compliance_remediate_pam_directories` of ADR 0027 (`/etc/pam.d`,
  `/usr/lib/pam.d`, `/usr/share/pam.d`), and `__linux_compliance_remediate_pwquality_pam_directories` is removed.
  Every regular file of every directory that exists is read and the files are searched together: no file is left
  out because a file of the same name comes first in libpam's order. An argument in a file that libpam does not
  open, such as a vendor file behind a file of the same name in `/etc/pam.d`, or any vendor file on Ubuntu, also
  refuses the rule, so the added directory can only add refusals.
- **Known gap, not closed here.** A PAM file that is a symbolic link, and a PAM directory that is one, are not read:
  `ansible.builtin.find` with `file_type: file` keeps only regular files, whatever `follow` says. The decision of
  FREES-200 above says the files are read through symbolic links; that is not what the role does. On a host where
  authselect makes `/etc/pam.d/system-auth` a link, an argument there is missed and the rule can be reported
  `compliant` or `applied`. FREES-213 records the fail-open and its fix, for this family and for the faillock and
  pwhistory families of ADR 0027.
- An include of a target with a `/` still refuses every rule; the reason is the lookup above: `../security/x` and
  `site/x` open a file outside the three directories or below one of them, which the collection does not read. A bare
  name is looked up in the three directories, and every file of them is read.
- The regression group `readers` adds a service file that only `/usr/share/pam.d` holds, with
  `pam_pwquality.so minlen=8 enforcing=0`, on both platforms (the directory is created for the test on Ubuntu and
  removed again): `minlen` is `overridden` by the argument and `enforce_for_root` by `enforcing=0`, with nothing
  written. The test declares `/usr/share/pam.d` as rewritten, so that the whole-instance comparison leaves out the
  times of that directory and of `/usr/share`, which the test changes for good.

## Amendment of 2026-11-10: PAM files and directories that are symbolic links (FREES-213)

**Context.** The amendment of FREES-211 recorded as a known gap that a PAM file that is a symbolic link, and a PAM
directory that is one, are not read, and gave the `find` as the cause of both. The causes, checked with ansible-core
2.21.5, are two different ones:

- `ansible.builtin.find` with `file_type: file` calls `os.lstat` on each entry and keeps only regular files;
  `follow: true` changes only how directories are walked. A service file that is a link, such as the
  `/etc/pam.d/system-auth` and `password-auth` that authselect links into `/etc/authselect` on RHEL 9, was never read.
- `find` does read a directory that is a link when it is given as a path. The pwquality family dropped such a PAM
  directory earlier: its stat "Inspect the PAM directories, the vendor directory included" did not follow links, so
  `isdir` was false and the directory was not listed. The faillock and pwhistory families already stat the
  directories with `follow: true` ([ADR 0027](0027-native-faillock-pwhistory.md)), so they read a linked directory;
  their gap was only the linked files.

A `pam_pwquality minlen=8` or `enforcing=0` in a linked file, or in a file of a linked directory, was missed, and the
rule could be reported `compliant` or `applied` while libpwquality, called by `pam_pwquality`, used the looser value.

libpam opens a service name and every `include` and `substack` target with `fopen(path, "r")` in
`_pam_open_config_file` of `libpam/pam_handlers.c` (linux-pam 1.5.1 and 1.5.3), which follows links. A name that
`fopen` cannot open, such as a link to nothing, a link to itself or a link through a regular file, is looked up in the
next directory. A directory opens, and libpam reads no line from it: every read of a directory fails with `EISDIR`,
whichever reader the version has (the `getline` one of 1.5.1 on Rocky Linux, the fixed-buffer one of 1.5.3 on Ubuntu),
and libpam treats the directory as an empty file. It still takes that entry for the name: it does not look for the name
in a lower directory, so a service named like the directory falls back to `other`, and an include of it adds nothing.
This was observed with the real libpam of both Molecule images (a service `t3` that is a directory in `/etc/pam.d`
next to a file `t3` in the lower directory runs `other`; a self-link and a link through `/etc/hostname` fall through
to the lower file), and a read of a directory returns `EISDIR` in both.

**Decision.**

- The PAM directories are inspected with `follow: true`, so a linked `/etc/pam.d`, `/usr/lib/pam.d` or
  `/usr/share/pam.d` is listed and read under its own path.
- Every entry is listed with `find` `file_type: any` and `follow: false`; every entry that is a link is inspected with
  `ansible.builtin.stat` and `follow: true`; the filter `pam_service_files`
  (`plugins/module_utils/compliance/pam_files.py`) sorts the entries:
  - a regular file, or a link that resolves to one, is read with `ansible.builtin.slurp`, which follows the link,
    under its name in the PAM directory, the name that libpam opens and that a reason names;
  - a directory, or a link to one, is left out, because libpam reads no line from it. A regular file of the same name
    in a lower PAM directory is still read, although libpam stops at the directory and never opens it; it can only
    add a refusal, never hide an argument, and a reason may then name that file;
  - a link to nothing, a link to anything else (a FIFO, a device, a socket), a link that `stat` cannot follow (a loop,
    a path through something that is not a directory, or any other error of `stat`), an entry that is none of a
    regular file, a directory and a link, and a PAM directory or an entry that `find` could not inspect refuse every
    rule of the family as `overridden`, with the entry and what it is in the reason. libpam would skip a link to
    nothing or a loop, but the collection cannot tell what such an entry would read when it resolves, so it refuses
    instead of guessing; this is the status that an include the collection does not read already gives.
- Nothing is read through an entry that is not a regular file once followed, so a link to `/dev/zero` or to a FIFO is
  never opened. The family puts no size limit on a PAM file; a link to a large regular file is read as a large
  regular file is. `ansible.builtin.stat` returns `exists: false` only for `FileNotFoundError` and fails on any other
  error, such as `ELOOP` or `ENOTDIR`, so the stat of the links runs with `failed_when: false`; a result without
  `stat` is passed to the filter as an empty mapping and the link is the unreadable kind `unfollowed_link`, never read
  and never dropped. The stat of the PAM directories runs the same way: a PAM directory that `stat` cannot inspect,
  such as a link to itself, is the unreadable kind `uninspected_directory` and refuses every rule, instead of
  stopping the run. A PAM directory that does not exist, or is not a directory, is left out, as libpam leaves it out.
- The union of FREES-211 stays: every file read from every directory is searched together. A target read under two
  names, through a link and under its own name, is searched twice, which repeats a refusal but cannot change it.
- The regression group `readers` adds, on both platforms: a service file `/etc/pam.d/freesecdev-readers-linked` that
  is a relative link into `/etc/security`, as authselect lays out `system-auth`, with
  `pam_pwquality.so minlen=8 enforcing=0` (both rules `overridden`, the reason naming the link); the vendor directory
  made a link to a directory that holds such a file (both rules `overridden`, the reason naming the file below
  `/usr/share/pam.d`), with the empty vendor directory of Rocky Linux put back afterwards; and a link to nothing next
  to a link to `/dev/null` and a link to itself (both rules `overridden`, the reason naming all three); and the vendor
  directory made a link to itself (both rules `overridden`, the reason naming `/usr/share/pam.d`). Nothing is written
  in any of them.
- The known gap of the FREES-211 amendment is closed.

**Open points, for FREES-212.**

- `pam_unread_includes` checks each physical line on its own. libpam joins a line that ends in a backslash with the
  next one, so `password include \` followed by ` ../security/x` opens `/etc/security/x`, which the collection does not
  read, and the rule is not refused for it. The function's docstring states this.
- When none of `/etc/pam.d`, `/usr/lib/pam.d` and `/usr/share/pam.d` is a directory, libpam reads `/etc/pam.conf`
  instead (observed on both Molecule images). The role does not read that file, so a `pam_pwquality` argument there is
  missed on such a host and the rule is not refused. Both images ship `/usr/lib/pam.d/systemd-user`, so the case
  needs a host whose PAM directories are all gone.

## Amendment of 2026-11-10: PAM text read as libpam reads it, links below /proc, and /etc/pam.conf (FREES-212)

**Context.** Since FREES-200 the family parsed PAM text itself (`pam_arguments`, `pam_enforcing_off` and
`pam_unread_includes` in `plugins/module_utils/compliance/pwquality.py`), while the `faillock` and `pwhistory`
families read it with the reader of `plugins/filter/pam_conf.py`, which is checked against libpam's own line assembly
([ADR 0027](0027-native-faillock-pwhistory.md)). The own parser differed from libpam, fail-open, in these ways, each
reproduced with the real libpam of both Molecule images (linux-pam 1.5.1-28.el9 on Rocky Linux 9, 1.5.3-5ubuntu5.7 on
Ubuntu 24.04) during the review of FREES-213 and again by the probe below:

- It joined a line that ends with a backslash with the next one before it checked for `#`, so a live
  `pam_pwquality minlen=1 enforcing=0` line after `# comment \` was skipped; libpam ends a whole-line comment there
  and runs the line (both images).
- It read a comment line of 1023 bytes or more as one comment; the fixed-buffer reader of Ubuntu's libpam reads 1023
  bytes, skips them as a comment and runs the rest of the line (Ubuntu).
- It ignored NUL bytes, and found `@include` and `<type> include|substack` only on one physical line and only in lower
  case: libpam also takes `@INCLUDE` and `-@include` (Ubuntu, whose libpam compares `@include` with `strcasecmp`
  after it drops one leading `-`) and an include whose control or target is on a continued line (both).
- A PAM entry that links to `/proc/self/environ` was read in the module's process; libpam reads the environment of
  the process that calls it, which can hold a `pam_pwquality` line (both).
- When none of the PAM directories is a directory, libpam reads `/etc/pam.conf` instead, which the role did not read.
  `_pam_init_handlers` of `libpam/pam_handlers.c` tests `stat(path) == 0 && S_ISDIR` on `/etc/pam.d`,
  `/usr/lib/pam.d` and, only where libpam is built with a vendor directory (Rocky Linux 9), `/usr/share/pam.d`;
  `stat` follows links, so a linked directory counts and a looping one does not. Neither image is built with
  `--enable-read-both-confs`: with the directories present, a service without a file falls back to `other`, never
  to `/etc/pam.conf` (observed on both images with `pam_echo`).

The amendment of FREES-213 listed the continued include and the `/etc/pam.conf` fallback as its open points.

**Decision.**

- The line assembly, the token split, the module and include lines and `effective_stack` move unchanged from the
  filter `pam_conf.py` to `plugins/module_utils/compliance/pam_reader.py`; `pam_conf_decision` imports them and
  behaves byte for byte as before (its tests and the existing rows of the verdict table pass unchanged).
- `pwquality.read_pam` reads every PAM file the role passes with `pam_reader`, in both assembly variants, and returns
  the arguments of every line whose module path names `pam_pwquality` (any type), the includes of a target with a
  `/` and the problems. Every rule is `overridden` with the reason, before anything else is decided, when a file has a
  NUL byte or a line of 1023 bytes or more (`pam_reader.unassembled`, the test that `effective_stack` already makes),
  when the lines of a file that load `pam_pwquality` or include a file differ between the two variants (a continued
  line with a blank or comment line inside it: the collection cannot tell which reader the host's libpam has), or
  when an `include`, `substack` or `@include` of any form that libpam accepts on either image names a path with a
  `/`. `overridden` is the status that an include the collection does not read already gave, so no status is added.
  The `pam_pwquality` arguments, `enforcing=0` and `local_users_only` come from the same lines.
- `@include` is read as an include on both platforms, in any case and with a leading `-`. Ubuntu's libpam takes it;
  Rocky Linux's refuses the line as an illegal type and installs it as a handler that fails in the `auth` stack.
  Reading it as an include on Rocky Linux too can only add a refusal.
- The fallback to `/etc/pam.conf` is refused, not read, for all three PAM families: reading it properly needs its own
  format (the service name first on every line, `other` lines, includes resolved from it), which is not small. The
  filter `pam_service_files` returns `/etc/pam.conf` as the unreadable kind `pam_conf_fallback` whenever neither
  `/etc/pam.d` nor `/usr/lib/pam.d` is a directory by its followed `stat`. That holds whenever either libpam reads the
  file; on Rocky Linux with only `/usr/share/pam.d` left it refuses although libpam reads the vendor directory, which
  is an over-refusal on a host that has lost both of its PAM directories.
- A link in a PAM directory that resolves to a regular file, and a PAM directory itself, is resolved with
  `ansible.builtin.stat` and `follow: false`, whose `lnk_source` is the path `os.path.realpath` gives; one that
  resolves below `/proc`, `/sys` or `/dev` is the unreadable kind `virtual_file`, with that path in the reason, and
  nothing below such a directory is read. The resolution is the fifth argument of `pam_service_files`, required, and a
  link or a directory missing from it, or whose `stat` failed, is unreadable too. A parent of a PAM directory that is
  a link (`/usr` itself, for example) is not resolved.
- The `msg` of a `stat` that failed on a link or a PAM directory is passed to the filter and named in the reason
  (`unfollowed_link` and `uninspected_directory`, for example `Too many levels of symbolic links`), and the docstring
  of `unreadable_refusal` names every kind.
- The slurp of the PAM files runs with `no_log`, as the faillock and pwhistory families do, because a link can point
  anywhere.
- Evidence: `make pam-reader-verdicts` now also installs 29 layouts of PAM files (`LIBPAM_CASES` of
  `tools/pam/reader_corpus.py`) in throwaway containers of both images, with `pam_pwquality.so` replaced by a module
  that records the arguments that libpam passes to it (`tools/pam/oracle/fake_pwquality.c`), runs `pam_chauthtok` of
  the real libpam (`tools/pam/oracle/probe_libpam.c`) and records the calls under `libpam_cases` of
  `tests/fixtures/pam_conf/reader_verdicts.json` (schema 3). The generator ran without AppArmor changes. What libpam
  passed (U Ubuntu, R Rocky Linux):

  | Case | libpam passes `minlen=1`/`enforcing=0` | Decision |
  |---|---|---|
  | live line after `# comment \` | U, R | `overridden` by the arguments |
  | comment line of 1023 bytes, then the line | U only (R: nothing) | `overridden`, long line |
  | comment line of 1022 bytes, then `minlen=14` | neither | `compliant` |
  | NUL after `minlen=14` on the line | neither (both cut the line at the NUL) | `overridden`, NUL |
  | `@INCLUDE`, `-@include`, `@include \` + target | U only (R: illegal line) | `overridden`, include |
  | `password include \` + `../security/x`, `password \` + `include x`, `PASSWORD SUBSTACK x`, `-password include x` | U, R | `overridden`, include |
  | continued line with a blank or comment line inside | U only | `overridden`, assembled differently |
  | continued line at the end of the file | neither (`pam_start` fails with `PAM_ABORT` on both) | `overridden` by the arguments |
  | `[minlen=1]`, `[default=die]pam_pwquality.so`, `PASSWORD`, `-password`, `minlen=1\r` | U, R | `overridden` by the arguments |
  | link to `/proc/self/environ` with a `pam_pwquality` line in the environment | U, R | `overridden`, below `/proc` |
  | no PAM directory, the line in `/etc/pam.conf`; `/etc/pam.d` a regular file | U, R | `overridden`, `/etc/pam.conf` |
  | only `/usr/share/pam.d` left | U (`/etc/pam.conf`), R reads the vendor file | `overridden`, `/etc/pam.conf` |
  | directories present, the line in `/etc/pam.conf` | neither | `compliant` |

  `tests/unit/tools/test_pam_libpam_verdicts.py` rebuilds, for every case and image, what the role passes to
  `pwquality_decide` and requires the decision above, that no decision is `compliant` or `applied` while libpam
  passes a looser argument on either image, that every argument libpam passes is one the family reads whenever it
  reads the files, and that `pam_reader` assembles the service file as libpam does wherever the family relies on it.
- The regression group `readers` adds, on both platforms: a live `pam_pwquality.so minlen=8 enforcing=0` line after a
  comment line that ends with a backslash (both rules `overridden` by the arguments); `password include \` with
  `../security/freesecdev-readers-included` on the next line (both rules `overridden`, the include named); a comment
  line of exactly 1023 bytes followed by that line (both rules `overridden`, the long line named; fail-open on Ubuntu
  only, refused on both); and a service file that links to `/proc/self/environ` (both rules `overridden`, the
  resolved path named). The cases of FREES-213 with a link to itself and a looping vendor directory now also check
  the `stat` message in the reason.

**The open points of the FREES-213 amendment are closed:** an include whose target or control is on a continued
line is read as libpam reads it and refused, and the `/etc/pam.conf` fallback is refused.
