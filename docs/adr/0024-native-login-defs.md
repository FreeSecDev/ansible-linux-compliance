# 0024. Native login.defs remediation, one recorded line per setting

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement that every rule can be toggled per topic and per rule,
  really remediates, and reverts exactly what the collection changed)
- **Jira:** FREES-185 (native login_defs), FREES-173 (a state that already equals the recorded prior state is
  restored without a write), FREES-194 and FREES-198 (the readers of a line byte for byte)
- **Pull requests:** introduced by the pull request for FREES-185; amended by the pull request for FREES-198
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0021](0021-native-banners-pwquality-and-profile-values.md) (the `recorded_value` line method of the pwquality
  main file), [ADR 0022](0022-native-sudo-drop-ins.md) (regression groups, FREES-173),
  [native remediation guide](../native-remediation-guide.md)

## Context

Every rule of the pinned profiles whose OVAL reads `/etc/login.defs` was `audit_only` and spread over four families:
`password_aging` (`PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`, `PASS_WARN_AGE`), `umask` (`UMASK`),
`user_sessions` (`CREATE_HOME`, `FAIL_DELAY`) and `pam` (`ENCRYPT_METHOD`). The project owner asked for one
`login_defs` topic that remediates these settings for real and reverts each one exactly.

The pinned ComplianceAsCode 0.1.82 content was read per rule (`Profile/select`, the OVAL objects, states and
variables reached from each definition, `check-export`, `platform`) in `ssg-ubuntu2404-ds.xml` and `ssg-rhel9-ds.xml`.
Every selected rule whose definition reaches an object that reads `/etc/login.defs`:

| Rule | Selected by | Object pattern in `/etc/login.defs` and state |
|---|---|---|
| `accounts_maximum_age_login_defs` | Ubuntu CIS (4), STIG; RHEL CIS (4), CCN (3), ISM, PCI DSS, STIG (2) | `^[\s]*(?i)(PASS_MAX_DAYS[\s]+\d+)`, the value captured case-sensitively by `PASS_MAX_DAYS\s+(\d+)`, every value `less than or equal` `var_accounts_maximum_age_login_defs` (365 for CIS, 60 for the STIG, 45 for CCN, 90 for PCI DSS) |
| `accounts_minimum_age_login_defs` | Ubuntu CIS level 2 (2), STIG; RHEL CIS level 2 (2), CCN (3), ISM, STIG (2) | `^[\s]*(?i)(PASS_MIN_DAYS[\s]+\d+)`, `greater than or equal` `var_accounts_minimum_age_login_defs` (1, or 2 for CCN) |
| `accounts_password_warn_age_login_defs` | Ubuntu CIS (4); RHEL CIS (4), CCN (3), ISM, PCI DSS | `^[\s]*(?i)(PASS_WARN_AGE[\s]+\d+)[\s]*(?:#.*)?$`, `greater than or equal` `var_accounts_password_warn_age_login_defs` (7, or 10 for CCN) |
| `accounts_password_minlen_login_defs` | RHEL ANSSI (4), CCN (3) | `^[\s]*(?i)(PASS_MIN_LEN[\s]+\d+)`, `greater than or equal` `var_accounts_password_minlen_login_defs` (15 for ANSSI, 12 for CCN) |
| `accounts_umask_etc_login_defs` | Ubuntu CIS (4), STIG; RHEL ANSSI enhanced and high, CCN advanced, CIS (4), STIG (2) | `^[\s]*UMASK[\s]+([^#\s]*)` (case-sensitive), its first three digits as an octal number, `bitwise and` with `var_accounts_user_umask` (027 for CIS and CCN, 077 for the STIG and ANSSI): every bit that the profile requires is set; platform `system_with_kernel` |
| `accounts_logon_fail_delay` | RHEL STIG (2) | `^[\s]*(?i)FAIL_DELAY(?-i)[\s]+([^#\s]*)`, `greater than or equal` `var_accounts_fail_delay` (4) |
| `accounts_have_homedir_login_defs` | RHEL STIG (2) | `^[\s]*(?i)CREATE_HOME(?-i)[\s]+yes[\s]*(?:#.*)?$`, and no `CREATE_HOME` in `/etc/login.defs.d/*.defs` (or `yes` there); no exported value |
| `set_password_hashing_algorithm_logindefs` | Ubuntu CIS (4), STIG; RHEL CIS (4), CCN (3), PCI DSS, STIG (2) | `^[\s]*(?i)(ENCRYPT_METHOD[\s]+\w+)[\s]*(?:#.*)?$`, `pattern match` `var_password_hashing_algorithm` (`SHA512\|YESCRYPT` for the Ubuntu CIS profiles) |
| `no_shelllogin_for_systemaccounts` | Ubuntu CIS (4); RHEL CCN (2), CIS (4), ISM, PCI DSS, STIG (2) | Reads `UID_MIN`, `SYS_UID_MIN` and `SYS_UID_MAX` only to tell system accounts apart; the check is about the shells in `/etc/passwd` |

`set_password_hashing_min_rounds_logindefs` (`SHA_CRYPT_MIN_ROUNDS`, `SHA_CRYPT_MAX_ROUNDS`) has a definition in the RHEL
9 datastream but no pinned profile selects it, so it is not catalogued. No pinned profile selects a rule about
`USERGROUPS_ENAB` or `HOME_MODE`. shadow-utils (`lib/getdef.c`) takes the name of a line case-sensitively, the first
word after it as the value, ignores lines whose first non-blank character is `#`, trims trailing white space and
keeps the last line of a name. It parses numbers with base 0 (`strtol`) and requires the whole value to be the
number, so a value followed by a comment (`PASS_MAX_DAYS 30 # site`) or a zero-padded decimal (`090`, `08`) does not
parse and shadow-utils falls back to its default, and `010` reads as 8. `pam_umask` (Ubuntu's `common-session`)
takes the first `UMASK` line, its name in any case, and reads the first word as octal, ignoring a trailing comment.
Neither image ships `/etc/login.defs.d`, and neither pinned shadow-utils reads it: `useradd` and `chage` do not link
libeconf on Ubuntu 24.04 (4.13) or Rocky Linux 9 (4.9), and a `PASS_MAX_DAYS 5` there left new accounts at 99999 in
the review of the pull request. Only the `CREATE_HOME` check reads it. `login` and `su` on Rocky Linux 9 are
util-linux, which reads `FAIL_DELAY` through libeconf and its drop-ins; the
[amendment of 2026-10-31](#amendment-of-2026-10-31-every-reader-of-a-line-byte-for-byte-frees-198) models that reader
and the bytes that every reader treats differently.

## Decision

### 1. A `login_defs` family under the `accounts` umbrella, with tags that keep the former toggles

`login_defs` is a new disruptive family of the registry under the `accounts` umbrella (`DISRUPTIVE_FAMILIES` grows
by one, the registry to 56 families). Rule prefixes ending in `_login_` or `_fail_` assign it the seven rules of
`password_aging`, `umask` and `user_sessions` above; they find exactly these rules in the pinned content. All three
former families sit under `accounts` as well, so `linux_compliance_accounts_enabled`, its allow-list entry and the
legacy fixture of ADR 0011 keep their rules. Three subsystem tags keep the post-split toggles working:
`password_aging` tags the four `PASS_*` rules, `umask` tags `accounts_umask_etc_login_defs` and `user_sessions` tags
`accounts_have_homedir_login_defs` and `accounts_logon_fail_delay`, so `linux_compliance_password_aging_enabled:
false` still switches off `PASS_MAX_DAYS`. A `login_defs` tag (patterns `login_defs`, `logindefs`) tags
`set_password_hashing_algorithm_logindefs` of `pam`, so `linux_compliance_login_defs_enabled: false` reaches every
login.defs rule. Because the tag's umbrella is `accounts`, `linux_compliance_accounts_enabled: false` now also switches
off that rule: the legacy fixture lists it under `added_by_tags`, the ninth rule that a tag adds to a former toggle
(still eight former toggles widen). The disruptive flag and the allow-list stay with the family, as ADR 0011 decides
for tags: allowing `login_defs` or `accounts` allows the seven native rules.

### 2. One recorded line per setting in `/etc/login.defs`

login.defs has no drop-in directory that the pinned shadow-utils builds or the content's checks read for these
settings, so the family edits the shared file in place, as `pwquality` does with its main file on Ubuntu
(ADR 0021): the one line of the setting is replaced in its place, or the line is appended when the setting is
absent, and every other byte of the file is kept (see the amendment for how it is written). The written line is
`<NAME> <value>` (`FAIL_DELAY  <value>`, with two spaces, for libeconf). Every rule is `recorded_value`; before its first write
the ledger records `method: line`, `setting_line` (the line as it was, or `null`), `written_line`, and the `mode`,
`owner`, `group` and `sha256` of the file. Lines are found case-insensitively and with leading blanks, as the
content's objects match them (`(?i)`), so `pass_max_days 99999` is the line of `PASS_MAX_DAYS` and is replaced and
later restored as written. Commented lines are never counted or touched.

The value comes from the profile (`profile_value`, ADR 0021). A line counts as compliant only when it has the strict
form that shadow-utils, `pam_umask` and the check all read the same way (the name in upper case, a decimal number
without a leading zero (`0` or `[1-9][0-9]{0,5}`), or a zero and two octal digits for the umask, and no trailing
comment) and satisfies the check's comparison; then nothing is written and a stricter value is kept
(`PASS_MAX_DAYS 30` under a maximum of 365, `UMASK 077` under 027). Any other line is rewritten from the forms of its
first word that the family reads: for a number an unsigned decimal of up to six digits, a zero and up to six octal
digits, or `0x` and up to four hexadecimal digits; for the umask `0`, a zero and up to two octal digits, two zeros and
two octal digits, or a single octal digit (values without the owner's bits, which shadow-utils and `pam_umask` read
alike). For a maximum the written value is the smallest of the profile's value and every such reading, for a minimum
the largest (`PASS_MAX_DAYS 30 # site` becomes `PASS_MAX_DAYS 30`, `PASS_MAX_DAYS 0365` becomes `245`,
`PASS_WARN_AGE 010` becomes `10`), and the umask written is the union of the bits that the profile requires and the
bits of the reading (`UMASK 077 # site` and `UMASK 0077` become `077`). The profile's value is written as it is when
the first word is empty, negative (`-1`, no limit), not a number that shadow-utils parses (`9x`), or a decimal of
seven digits or more under a maximum: in each case it is stricter than what is in effect. A first word in any other
form that shadow-utils or `pam_umask` may read (quoted, signed, longer, or a umask in another base or length, such as
`"30"`, `+30`, `1234567` under a minimum, `0x10000`, `00077`, `"077"` or `0x3f`) is refused as `unreadable_value`
without a write, because the family cannot tell that the profile's value is not looser. A number line with a quote whose
first word has no reading is classified by the value that shadow-utils' `getdef` reads: it skips every blank and
quote after the name and takes the characters up to the next quote, and the family keeps that value up to a blank or
`#`. When that value is a number in any base, with an optional `+` (`PASS_MAX_DAYS " 30"`, `""30`, `30"x` or
`"0x1e"`, which shadow-utils reads as 30), the rule is `unreadable_value`; when it is empty, negative or not a number
(`PASS_MAX_DAYS ""`, `"-1"`, `" -1"`, `"9x"`, `9x # "q"`, `-1 # "x"`), the profile's value is written, as for the
unquoted forms. A carriage return, a vertical tab or a form feed before or after the value is a blank, a NUL in the
line and a line of 1023 bytes or more refuse, and `FAIL_DELAY` follows libeconf as well (see the amendment).
`CREATE_HOME` has no exported value; its rule carries the value `yes`, which the check's pattern requires, and the
parameter `reads_dropins`, because its check also reads `/etc/login.defs.d`.

Apply reports, with a reason and without a change:

| Status | When |
|---|---|
| `notapplicable` | `/etc/login.defs` does not exist (shadow-utils is not installed; the content's `package_shadow-utils` platform) |
| `not_regular_file` | `/etc/login.defs` is a symbolic link or not a regular file; nothing is written through a link |
| `not_directory` | Only for a rule whose drop-ins are read (`reads_dropins` for `CREATE_HOME`, whose check reads them, and `libeconf` for `FAIL_DELAY`): `/etc/login.defs.d` exists but is a symbolic link or not a directory, so its drop-ins cannot be read |
| `long_line` | A line of `/etc/login.defs` is 1023 bytes or longer: shadow-utils reads it in pieces, and a piece can set any setting (amendment) |
| `overridden` | Only for those two rules: a drop-in `/etc/login.defs.d/*.defs` (a regular file, or a link to one) mentions the name anywhere, and the check or libeconf reads it whatever the main file says, so the collection does not claim a change that would not take effect and does not edit a file it does not own. For the other five rules a drop-in is ignored, as by their checks and the pinned shadow-utils |
| `unreadable_file` | Only for `FAIL_DELAY`: libeconf would not read the configuration as one, because a line of login.defs or of a drop-in starts a section (`[`) or a drop-in is a link to no regular file (amendment) |
| `duplicate_setting` | The name is set on more than one line, in any case, also counting for `UMASK` and `FAIL_DELAY` the forms that `pam_modutil_search_key` and libeconf read (amendment): `pam_umask` and libeconf take the first line, shadow-utils the last, and the check requires every one to comply, so no single rewrite is right |
| `unreadable_value` | The one line of the setting has a value in a form that shadow-utils, libeconf or `pam_umask` may read but the family does not (see above and the amendment), a NUL, or the only line that sets the name is in a form that only another reader reads; the reason names the line |
| `method_changed` | The ledger entry was recorded by another method, or none; clean it up first |
| `compliant` | Exactly one line, in the strict form, satisfies the check; nothing is written or recorded |

When the profile value changes while a rule stays on, apply writes the new line and replaces the entry with the same
prior state and the new `written_line` after the write.

### 3. Cleanup restores exactly the recorded line and never overwrites a later change

| Result | When |
|---|---|
| `restored`, nothing written | The file already holds the recorded prior state of the setting (no line when `setting_line` is `null`, exactly that line otherwise), for example a line that the collection added and an administrator removed again (FREES-173); the entry is removed |
| `restored` | The setting is set on exactly one line equal to `written_line` and the mode, owner and group of the file are the recorded ones: the recorded line is written back in its place, or the line is removed when the setting was absent |
| `cleanup_incomplete` (`method_changed`, `target_absent`, `not_regular_file`, `invalid_record`, `modified_since_apply`) | The entry records another method, the file is gone or a link, the record is malformed (a prior or written line that spans lines or does not set the name, a malformed mode or owner), or the setting was changed or removed by hand since; nothing is changed and the entry is kept |

With every rule cleaned up the file is byte for byte what it was, also when it has Windows line endings or does not end
in a newline (amendment).

### 4. Kept `audit_only`, each with its reason

| Rule | Reason |
|---|---|
| `set_password_hashing_algorithm_logindefs` | It stays in `pam`, whose former toggle and allow-list entry the legacy fixture pins (moving it would change what `linux_compliance_pam_enabled` and `allow_disruptive: [pam]` cover), and its value is a choice: the CIS profiles accept `SHA512\|YESCRYPT`, and the algorithm must agree with the `pam_unix` hashing of the PAM stack (`set_password_hashing_algorithm_systemauth`, `..._passwordauth`), which the `pam` topic owns. Both pinned images already comply (`SHA512` in the Ubuntu 24.04 and Rocky Linux 9 images). The `login_defs` tag switches it off with the topic |
| `no_shelllogin_for_systemaccounts` (`root_access`) | It reads login.defs only for the system UID range; it changes the shells of accounts in `/etc/passwd`, which can stop services that run a shell, and it is not a login.defs setting |
| `accounts_password_set_max_life_existing`, `accounts_password_set_min_life_existing`, `accounts_password_set_warn_age_existing` and the other existing-account rules of `password_aging` | They change fields of every account in `/etc/shadow`. That file holds the password hashes, so its content cannot be recorded in the ledger; an exact revert would need every prior field of every account and breaks as soon as an account is added or changes its password; and setting a maximum age on existing operators and service accounts can expire their passwords at once. Root in the Docker containers cannot even read `/etc/shadow` on Rocky Linux |
| `set_password_hashing_min_rounds_logindefs` | No pinned profile selects it |

## Benefits

Seven login.defs rules are native on both platforms with the profile's values, a toggle per rule and per topic, and
an exact revert; the topic toggle also reaches the hashing rule that stays with `pam`. The golden test
`tests/unit/tools/test_content_golden_login_defs.py` pins, against the OVAL of both datastreams, the object pattern,
the comparison and the exported value of every native rule, and the set of rules whose checks read login.defs, so a
content update that moves a check fails CI until the family follows.

## Trade-offs

The family refuses rather than merges: a duplicate line, a drop-in that sets `CREATE_HOME`, or a symbolic link leave
the rule unremediated with a reason. A trailing comment or a zero-padded number on a setting's line is rewritten,
because shadow-utils does not read the value as written then; the value written is never looser than any reading of
the line, and the cleanup puts the line back as it was. Each write replaces the inode of login.defs; its content,
mode, owner and group are restored, the inode and the times are not.

## Security implications

The settings take effect for passwords that shadow-utils sets and accounts it creates, and on Ubuntu `pam_umask` takes
the session umask from `UMASK`; a stricter umask changes the modes of new files, and a maximum password age expires
passwords that are older than it once they are next changed (`/etc/shadow` is never changed). `login_defs` is
disruptive: it is applied and cleaned up only with `login_defs` or `accounts` in
`linux_compliance_remediate_allow_disruptive`. Nothing is written through a symbolic link, and the prior lines stored in
the root-only ledger are from a world-readable file.

## Operational consequences

The Molecule lifecycle (`extensions/molecule/shared/vars/topics/login_defs.yml`) runs both toggle modes on both
platforms from the as-built file and from a file that an administrator customised (a looser maximum age with extra
blanks, a warning age in lower case and a stricter umask, set with the new pre-state key `lines`), and checks that the
cleanup restores those lines and not a default. Six regression groups run in legs of their own
(`regressions-changes`, `regressions-refusals`, `regressions-values`, `regressions-profiles`, `regressions-bytes`, and
`regressions-readers` on Rocky Linux): `lifecycle_login_defs_regressions.yml` covers a change of method, a
stricter value set by hand (`modified_since_apply`, then `restored` once the written line is put back), a removed line
that existed before (`modified_since_apply`) and a line that the collection added and an administrator removed again
(`restored` without a write), and checks the exact SHA-256 after the apply; `lifecycle_login_defs_refusals.yml` covers
duplicate lines in either case, a commented default, a lower-case name with a four-digit umask, a stricter maximum
age and a stricter umask with a trailing comment (both kept), a drop-in and
a symbolic link for the drop-in directory (both ignored by these rules), a symbolic link for login.defs and a missing
login.defs; `lifecycle_login_defs_values.yml` covers zero-padded numbers (`090`, `010`, `0365`), the forms refused as
`unreadable_value` and those that take the profile's value (`-1`, an empty value, `9x`, seven digits under a maximum,
`0x1e`, `0`); `lifecycle_login_defs_bytes.yml` covers the bytes of the amendment (Windows line endings on a customised
and on the as-built file, a vertical tab and a form feed before, after and inside the number, a NUL, and lines of more
than 1023 bytes); `lifecycle_login_defs_other_profiles.yml` applies, repeats and cleans up the rules that the CIS level
1 profiles of the lifecycle do not select, with the STIG profiles of both platforms and the RHEL 9 ANSSI enhanced
profile, and refuses `CREATE_HOME` next to a drop-in that sets it (`overridden`) and next to a linked drop-in directory
(`not_directory`); `lifecycle_login_defs_readers.yml` runs on Rocky Linux the libeconf forms of `FAIL_DELAY` and
`CREATE_HOME` of the amendment, each on a login.defs of its own that the cleanup restores byte for byte.

## Amendment of 2026-10-31: every reader of a line, byte for byte (FREES-198)

The review of FREES-194 read the sources of the readers (shadow-utils 4.9 and 4.13 `def_load` and `getdef_num`,
libeconf 0.4.1 `read_file`, util-linux 2.37.4 `login-utils/logindefs.c`, Linux-PAM 1.5.1 `pam_modutil_search_key`),
ran them in the Molecule images, and found forms that the family read differently, most of them already on `main`.
This amendment replaces the refusal of FREES-194, which refused every number line with a carriage return, vertical
tab or form feed, and so never remediated a login.defs with Windows line endings.

- **Blanks.** shadow-utils trims every trailing `isspace` character (space, tab, `\r`, `\v`, `\f`) of a line, ends the
  name at a space or a tab, and `strtol` skips the same characters before the number. The family now does the same:
  after the space or tab that ends the name it skips `[ \t\r\v\f]`, its first word ends at one of them or at `#`,
  and the strict form allows them at the end of the line. So `PASS_MAX_DAYS 30` with a Windows line ending is
  `compliant`, the as-built `PASS_MAX_DAYS 99999\r` is rewritten to the profile's 365 (and restored with its `\r`),
  `PASS_MAX_DAYS 30\v` is `compliant`, and `CREATE_HOME yes\r` is `compliant`. One of these characters inside the
  value (`30\v5`, `3\r0`, or before a comment), which shadow-utils does not parse, is still `unreadable_value` for the
  number and umask rules. A line that would be rewritten and holds a control character other than a tab or a carriage
  return (`PASS_MAX_DAYS \v30`, which shadow-utils reads as 30) is `unreadable_value` as well: the state ledger
  records no such character (ADR 0011), so the prior line could not be restored exactly.
- **NUL.** shadow-utils, libeconf and `pam_modutil_search_key` stop reading a line at a NUL byte, so
  `PASS_MAX_DAYS 30\0junk` reads as 30. A line of the setting with a NUL is `unreadable_value`, for every rule.
- **Long lines.** shadow-utils reads with `fgets` into 1024 bytes, so it reads a line of 1024 bytes or more in pieces
  of 1023, and a piece can set a setting that the family does not see (`#`, 1022 bytes, then `PASS_MAX_DAYS 30`) or a
  value it reads differently (`PASS_MAX_DAYS`, blanks, then `30junk` across the boundary, read as 30). Rather than
  model the pieces, every rule refuses as `long_line` when any line of the file is 1023 bytes or longer, counted in
  bytes (from the base64 of the line, so a multibyte character counts as its bytes). libeconf reads 8191 bytes at a
  time and `pam_modutil_search_key` whole lines, so the limit covers them too.
- **libeconf and `FAIL_DELAY`.** On Rocky Linux 9 `login` and `su` are util-linux 2.37.4 linked with libeconf, which
  reads `FAIL_DELAY`, the only setting of the catalogue that util-linux reads, with `econf_readDirs(…, "/etc", "login",
  "defs", "= \t", "#")`: `/etc/login.defs`, then the drop-ins `/etc/login.defs.d/*.defs`, which override it. It cuts a
  line at a NUL and at the first `#`, ends the name at any `isspace` character or `=`, takes the first line of a name
  (case-sensitively), skips a `=` before the value, strips a pair of quotes, and reads the number with `strtoull` in
  base 10 (`030` is 30, `0x1e` is 0, `30junk` is 30, `-1` is 2^64-1, which `login` truncates to an unsigned int). A line
  that has no space, tab or `=` after the one that ends its name, such as `FAIL_DELAY 4`, is glued to the value of an
  entry on the line before it, so the stock file's last line `HMAC_CRYPTO_ALGO SHA512` swallowed an appended
  `FAIL_DELAY 4`. A line that starts a section (`[…]`) moves every later name into that section, and a drop-in that
  cannot be read makes libeconf read nothing. The rule carries the catalogue parameter `libeconf: true`, which the
  golden test pins to `FAIL_DELAY`, and the family then:
  - writes `FAIL_DELAY  <value>` with two spaces, which libeconf always reads as an entry of its own, and counts a line
    as compliant only when libeconf cannot glue it (a second space, tab or `=` after the one that ends the name), so a
    compliant-looking `FAIL_DELAY 30` after another setting is rewritten as `FAIL_DELAY  30`;
  - adds libeconf's reading to the readings of the line, so the value written under the minimum is never below what
    libeconf read: `FAIL_DELAY = 30`, `=30`, `= "30"`, `30junk`, `030` become `FAIL_DELAY  30`;
  - refuses as `unreadable_value` a value that libeconf reads as negative or as seven digits or more, and a line in a
    form that libeconf reads but the family does not write (`FAIL_DELAY=30`, `\vFAIL_DELAY 30`, `FAIL_DELAY\v30`),
    or as `duplicate_setting` when another line sets the name;
  - refuses as `overridden` a drop-in that mentions `FAIL_DELAY` anywhere, and as `not_directory` a linked drop-in
    directory, as for `CREATE_HOME`;
  - refuses as `unreadable_file` a section line in login.defs or a drop-in, and a drop-in that is a link to no regular
    file.
  `su` also reads `/etc/default/su`, which can set `FAIL_DELAY` for `su` alone; the rule's check and the STIG requirement
  concern the login prompt, so that file is out of scope. `pam_faildelay` without `delay=` reads `FAIL_DELAY` with
  `pam_modutil_search_key`, whose forms the next item refuses as well.
- **`pam_modutil_search_key`.** `pam_umask` (and `pam_faildelay`) read the first line whose name, in any case, follows
  any `isspace` characters and ends at a space, tab or `=`, so `\vUMASK 000` and `UMASK=000` set the session umask
  although shadow-utils ignores them. For `UMASK` and `FAIL_DELAY` such a line counts as a line of the setting: a
  second one is `duplicate_setting`, an only one `unreadable_value`.
- **Drop-ins.** For `CREATE_HOME` and `FAIL_DELAY` a drop-in overrides when it mentions the name anywhere: libeconf
  reads `CREATE_HOME=no` and `\vCREATE_HOME no`, which the former line pattern missed, and a comment that mentions the
  name refuses too, on the safe side.
- **Writes.** `ansible.builtin.lineinfile` reads with Python's universal newlines and writes every `\r\n` and lone
  `\r` back as `\n`, so a write rewrote every line of a file with Windows line endings and the cleanup could not
  restore it. The family now writes the whole file with `ansible.builtin.copy` from the text it read and recorded:
  the line of the setting is replaced in place, or the line is appended (after an added newline, and then without a
  trailing one, when the file does not end in a newline), and every other byte is kept. The cleanup removes exactly
  the written line with the newline that the apply added, or puts the recorded line back in its place, so a file with
  Windows line endings or without a final newline is restored byte for byte.

The decision tasks of `login_defs_apply.yml`, copied word for word into a localhost probe, were run on 312 crafted
files (the cases of the reviews of #70, #80 and #82 and 66 new ones), and each decision was checked against byte-level
emulations of the four readers written from their sources, which agree with `useradd` and `chage` on both images and
with libeconf through `ctypes` on Rocky Linux 9: every written value takes effect for every reader of the setting and
is never looser than what any of them read before, and every `compliant` holds for every reader. The same check
found 24 looser or ineffective decisions in the logic before this amendment.
