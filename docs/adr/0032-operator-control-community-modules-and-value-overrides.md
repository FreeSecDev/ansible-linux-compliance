# 0032. Operator control: community modules, and value overrides reported as deviations

- **Status:** proposed
- **Date:** 2026-11-09
- **Deciders:** project owner (requirement of 2026-11-09: remediate only with native Ansible modules, community
  modules or this collection's own modules, never with a scanner's remediation; users who run the code must be able
  to adjust its behaviour; a value looser than the profile is applied and reported as a deviation); lead architect
- **Jira:** FREES-203
- **Pull requests:** introduced by the pull request for FREES-203 that records this decision; accepted through the
  pull request of its first implementation
- **Related:** [ADR 0003](0003-native-module-remediation.md) and [ADR 0025](0025-own-ansible-remediation-only.md)
  (both widened once this ADR is accepted), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0011](0011-control-toggles-and-cleanup.md), [ADR 0013](0013-normalized-findings-model.md),
  [ADR 0016](0016-report-schema-and-summary-semantics.md), [ADR 0017](0017-offline-html-dashboard.md),
  [ADR 0021](0021-native-banners-pwquality-and-profile-values.md), [ADR 0024](0024-native-login-defs.md)

## Context

ADR 0025 made every remediation our own Ansible and banned the scanner's remediation. The `own_remediation` rule
group enforces that ban. Two parts of the owner's requirement are not met yet.

### Modules

ADR 0025 §1 allows only `ansible.builtin` modules and this collection's typed modules. The owner also allows modules
of community collections. Today nothing enforces the narrower rule either:

- `tools/lint/repo_rules/ansible_tasks.py` is a deny list (`shell`, `command`, `raw`, `script`, `expect` and others);
- `galaxy.yml` declares no dependencies;
- the pinning of collection dependencies (FREES-160) is not implemented.

### Values

A user can turn remediation on or off per umbrella, topic and rule (ADR 0011). The value a rule writes comes only from
the selected profile's XCCDF `Value`. The catalogue names it in `profile_value` (the short id, verified as exported
by the check) or in `profile_value_id` (the full id, for checks that export nothing, today only
`sudo_require_reauthentication`). The one exception is the banner text: `linux_compliance_remediate_banner_text`
already lets the user choose it (ADR 0021). The banner profile values are regular expressions to match, not values to
write.

A user who wants `minlen = 16` where the profile asks for 14 has no supported way to say so.

### What the catalogue knows today

Only the `login_defs` rules carry a `comparison` against the profile value: `at_least`, `at_most`, `umask`, and
`equal` for one rule without a value. The pwquality, ssh and sudo rules have none. Their comparison is implicit in
each family's task file. Every `profile_value` in the catalogue is used by exactly one rule today.

Some checks also do not test the value:

- the check of `sudo_require_reauthentication` accepts any non-negative timeout (ADR 0025 §3);
- the `login_defs` family keeps a host value that is already stricter than the profile (ADR 0024).

So a looser value does not always make the scan fail, and the value written is not always the target value.

## Decision

### 1. Which modules remediation may use (widens ADR 0025 §1 and ADR 0003 once accepted)

A task file of `roles/remediate` may use:

- `ansible.builtin` modules;
- this collection's own modules and action plugins (ADR 0003);
- modules of a community collection, but only when all of the following hold:
  - the collection is named in `galaxy.yml` `dependencies` and in the requirements files at an exact version;
  - the module's fully qualified name is on the allow list of a new repository rule;
  - a security review of the module, done in the pull request that adds it to the allow list, records:
    - that it supports check mode and reports `changed` truthfully;
    - how it reads and writes the files it manages: whole-file writes or not, CR and NUL handling, symlinks;
    - **every external process it runs.** A module that runs a process is allowed only when that process call meets
      AGENTS.md rule 2 and ADR 0004: an explicit argument list, a resolved absolute path, validated inputs and a
      timeout. Most `run_command` users have no timeout and are therefore refused. `ansible.posix.sysctl`, for
      example, runs `sysctl` with no timeout and is refused; the kernel parameters use our own drop-in design
      (ADR 0029).

`community.general.pam_limits` is an example of a module that may qualify: it edits a file in Python and runs no
process.

**Enforcement**, introduced with the first implementation:

- a new rule in `tools/lint/repo_rules` fails when a module in `roles/remediate` is not `ansible.builtin.*`, not
  `freesecdev.linux_compliance.*` and not on the allow list. The allow list starts empty. From then on, modules such as
  `community.general.make` or `ansible.posix.at` are refused because they are not listed, not because of a deny entry;
- the dependency pinning check of FREES-160 is in place before the first community module is listed.

**Unchanged:**

- `ansible.builtin.shell`, `command`, `raw` and `script` and their aliases stay banned (AGENTS.md rule 1);
- everything ADR 0025 bans stays banned, whichever module would carry it;
- a family that uses a community module is held to the rule that the reader is the oracle, like every other family.

AGENTS.md rule 1 is worded to match: missing functionality becomes a typed Python module, action plugin,
`module_utils` code or an allow-listed community module.

### 2. Value overrides

A new role variable, `linux_compliance_remediate_value_overrides`, maps the short id of an XCCDF `Value` to the value
the user wants as the target. For example:

```yaml
linux_compliance_remediate_value_overrides:
  var_password_pam_minlen: 16
```

- **The key** is the catalogue's `profile_value`, or for a `profile_value_id` rule the id without the
  `xccdf_org.ssgproject.content_value_` prefix. Keying by value rather than by rule follows how profiles tailor. If a
  value is ever used by more than one rule, which is not the case today, one override applies to all of them.
- **The banner values are excluded.** The banner text is chosen with `linux_compliance_remediate_banner_text`, as
  today.
- **Refused before any change:**
  - a key that is not a value of a native rule in the catalogue;
  - a key for a value whose family has no comparison function yet (see §3);
  - a value that does not pass the family's own validator for that setting. That is the same validator that guards
    profile values: type, characters the reader accepts, and bounds the reader honours.

  A typo is therefore never silently ignored, and an override never writes a line the reader reads differently.
- **Keys the current profile or toggles do not select** are not refused. One inventory can serve several profiles.
  They are listed in the role's results as `unused_overrides`.
- **The target is replaced, not the family's logic.** The override takes the place of the profile value as the
  family's target, and everything else stays the same. For example, `login_defs` still keeps a host value that is
  stricter than the target.
- **Ledger.** It records `value_source` (`profile` or `override`), the profile value and the target. Cleanup, and a
  target that changes while the rule stays on, work as they do today (ADR 0011, ADR 0021).

### 3. Classification: judged on the value in force after the run

Each family gets a comparison function per setting, in `module_utils` and unit-tested, that knows its reader's
special values (for example `0` meaning "never" for a faillock time, or `-1` for a pwquality credit). The
`login_defs` comparisons move into these functions. A family's values become overridable only once its functions
exist.

After the decision, the role compares **the value in force after the run** (written, or kept because it was already
stricter) with **the profile value**:

- **It meets the profile:** the usual statuses (`applied`, `compliant`, …), with `value_source: override` in the
  result.
- **It is looser:** the new status `deviation`, with the reason `operator_override`, the profile value and the value
  in force. `changed` reports as usual. Check mode plans and reports `deviation` the same way. A rule is never
  `applied` or `compliant` when its value in force is looser than the profile.

### 4. Findings and report

- The remediation result carries `deviation: {value_id, profile_value, effective_value}`.
- The finding of the rule in the next scan gets the flag `operator_deviation`, with that object. The flag is allowed
  on the outcomes `pass`, `fail` and `waived`. **The scanner's outcome is never changed:** a check that does not test
  the value may still say `pass`.
- **Report (ADR 0016).** A finding with `operator_deviation` is never counted as a pass. The summary gets a new count,
  `deviation`, and those findings are taken out of `pass`. A `fail` with the flag stays in `fail` and is counted in
  `deviation` as well. The dashboard (ADR 0017) lists every flagged finding in its own section.
- **A deviation is not a waiver.** Only an active exception record turns `fail` into `waived` (ADR 0013). A waived
  finding keeps the flag and stays visible as a deviation.
- The verify and evidence roles carry the flag through.

### 5. Model and schema changes

All of these come with tests, in the first implementation.

- **`RemediationStatus`** gains `deviation`. The remediation result gains `value_source`, `profile_value`,
  `effective_value` and `deviation`.
- **`ResultFlag`** gains `operator_deviation`, and `_FLAG_OUTCOMES` allows it on `pass`, `fail` and `waived`. The
  finding gains an optional `deviation` object.
- **Report summary:** gains the `deviation` count.
- **Schema versions:** the findings schema moves from `1.2` to `1.3` (ADR 0013 §Serialization), and the report schema
  takes its next minor version. The ledger entries get the new fields under a new ledger version, and older entries
  still read as `value_source: profile`.

### 6. Status of ADR 0003 and ADR 0025

Both are implemented on `main`: the native families since FREES-53, and ADR 0025 since FREES-188. They are accepted
now, as an exception to the index rule ("accepted through the pull request that introduces their first
implementation"), because that implementation has already merged. Their widening in §1 applies once this ADR is
accepted.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Overrides keyed by rule | Profiles tailor values, not rules; a key per rule would let two rules for one value disagree once values are shared |
| Override values through an XCCDF tailoring of the audited profile | The audit would then measure the user's value, and a looser value would scan as `pass` with nothing to flag it |
| Refuse a looser override | Rejected by the owner: the user decides; the collection's job is to make the decision visible |
| Report a looser override as `waived` | A waiver needs an accountable exception record with an expiry (ADR 0013); an override variable is neither |
| Change the scanner's outcome to `fail` for a deviation that scans `pass` | Falsifies the scan result; the report counts it as a deviation instead |
| Accept overrides for every family at once, comparing by equality | A stricter override of pwquality, ssh or sudo would be misreported as a deviation |
| Any community module, unpinned or without the process review | Widens the supply chain, lets a module's own parsing replace the reader, and can run processes outside ADR 0004 |
| Keep `ansible.builtin` and own modules only | Against the owner's requirement, and it forces a typed module where a reviewed community module would do |

## Benefits

- Users can tune every native value without editing generated files. The tuning is validated, recorded in the ledger
  and reverted like any other change.
- A weakened host never looks compliant:
  - remediation reports it as `deviation`;
  - the finding carries the flag `operator_deviation`;
  - the report counts and lists it separately, even when the scan itself passes.
- Community modules become available without losing ADR 0025's guarantees or ADR 0004's process rules.

## Trade-offs

- Each family needs comparison functions that know its reader's special values before its values can be overridden.
  pwquality, ssh and sudo get them in the implementation; until then, overrides for their values are refused.
- One more status, one more flag and one more report count, each a schema change with a version bump and tests.
- Every community module costs a security review, and the allow list has to be maintained.

## Security implications

An override can weaken a host by design. These limit the risk:

- it is an explicit role variable, reviewable in the user's inventory;
- it goes through the same validators as profile values, so it cannot inject a line or a value that the reader parses
  differently;
- it is judged on the value in force and reported at every layer, never as compliant, and never as a pass in the
  report, even where the scanner's check does not test the value.

Community modules add third-party code that runs as root. They are limited by the exact pins, the allow list, the
review of every process they run, and the rule that the reader is the oracle. The `own_remediation` guard and the
process helper's refusals stay in force.

## Operational consequences

- `docs/remediation-variables.md` and the remediate role's argument spec document
  `linux_compliance_remediate_value_overrides`, with the value keys each native rule accepts and their comparison.
- The model, report and ledger changes of §5.
- The repository rule and the dependency pinning of §1, before the first community module.
- Each native family gets lifecycle regressions once its comparison functions exist:
  - a stricter override is `applied`, then `compliant`, and is reverted byte for byte;
  - a looser override is `deviation`, and its finding carries `operator_deviation`;
  - a host value that is already stricter is kept, and its status is decided on that value;
  - an unknown key, a key of a family without a comparison, and an invalid value are refused before any change;
  - check mode reports the same statuses.
- Forward-looking: the faillock bounds (at most 604800 for the times) and its values come from FREES-186 (#78). They
  join the override set when that family's comparison functions are in place.

## Amendment of 2026-11-10: the comparison functions and the catalogue key (FREES-203)

The comparison functions of §3 are `plugins/module_utils/compliance/values.py`. Each is a named comparator in
`COMPARATORS` with three operations: `validate` turns an operator's value (a YAML integer that is not a boolean, or a
string) into its canonical text or refuses it; `meets` says whether a canonical value is at least as strict as the
profile's, reflexively and transitively; `stricter` picks the stricter of two values, which for a umask is the union
of their bits. `judge(name, profile, effective)` and `stricter_of(name, target, readings)` apply them by name;
`stricter_of` is the `login_defs` merge that keeps a stricter host value, ported from the Jinja of
`login_defs_decide.yml`.

A rule of the catalogue is overridable only when it names its comparator in a new key, `value_comparison`, next to
`profile_value` or `profile_value_id`. `make catalogue` copies the name into the rule's parameters, and refuses it
without a profile value, for a banner rule, for an unknown name and when a profile value is not a canonical value of
the comparator. So the "family without a comparison" of §2 is decided per rule, from data, and a family is wired for
overrides by editing only its own catalogue entries and task files.

The first comparators cover the integer families: `login_defs` (`at_least`, `at_most`, `umask`), pwquality
(`at_least`, `minlen`, `minclass`, `credit`, `max_or_off`, `flag`, `retry`), `pwhistory_remember` and faillock
(`deny`, `interval`, `unlock_time`, the last also for `root_unlock_time`). Their bounds are those of the family
validators and of what the readers read as written:

- a umask is three octal digits given as a string; a YAML integer is refused, because YAML 1.1 reads `027` as 23;
- integers are decimal without a sign, leading zero or `-0`, so `016` is never read as octal by one reader and as
  decimal by another;
- `minlen` starts at libpwquality's floor of 6 and `minclass` ends at its 4 classes, because the library reads other
  values as those;
- `maxrepeat`, `maxclassrepeat` and `maxsequence` treat 0 (off) as the loosest value, and `retry` starts at 1;
- `deny = 0` (never lock) is judged the loosest value but refused as an override, as the faillock family refuses a
  maximum of 0; `unlock_time = 0` (never unlock) is the strictest and is accepted; the faillock times end at 604800
  and `deny` at 65535, which pam_faillock stores in 16 bits.

No catalogue entry names a comparator yet, so nothing is overridable and behaviour is unchanged.
`plugins/filter/pam_conf.py` keeps its own decision until the faillock and pwhistory family is wired; the unit tests
pin the faillock and pwhistory comparators to that filter's decisions over a table of values, and the `login_defs`
comparators to the family's Jinja.
