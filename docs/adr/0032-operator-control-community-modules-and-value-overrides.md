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
  (both amended and accepted here), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0013](0013-normalized-findings-model.md), [ADR 0016](0016-report-schema-and-summary-semantics.md),
  [ADR 0017](0017-offline-html-dashboard.md), [ADR 0021](0021-native-banners-pwquality-and-profile-values.md)

## Context

ADR 0025 made every remediation our own Ansible and banned the scanner's remediation, and the `own_remediation` rule
group enforces it. Two parts of the owner's requirement are not met yet:

- **Modules.** ADR 0025 §1 allows only `ansible.builtin` modules and this collection's typed modules. The owner also
  allows modules of community collections. Some families would be simpler and better tested with one, for example
  `community.general.pam_limits` or `ansible.posix.sysctl`, than with a new typed module of our own.
- **Values.** A user can turn remediation on or off per umbrella, topic and rule (ADR 0011). The value a rule writes
  comes only from the selected profile's XCCDF `Value` (ADR 0021, ADR 0025 §3). A user who wants `minlen = 16` where
  the profile asks for 14, or a shorter `unlock_time` for one fleet, has no supported way to say so. Editing
  `content/catalogue.yml` or the generated `rules.yml` breaks the golden tests and the provenance of the values.

The catalogue already gives every native rule with a value its `comparison` against the profile value: `equal`,
`at_least`, `at_most` or `umask`. Whether a value meets the profile can therefore be decided without the scanner.

## Decision

### 1. Which modules remediation may use (amends ADR 0025 §1 and ADR 0003)

A task file of `roles/remediate` may use:

- `ansible.builtin` modules;
- this collection's own modules and action plugins (ADR 0003);
- modules of a community collection that is named in `galaxy.yml` `dependencies` and in the requirements files at an
  exact version (FREES-160), and whose module is on the reviewed allow list of the `ansible_tasks` repository rule
  group. Adding a module to the list is a pull request with a security review. That review records:
  - that the module supports check mode and reports `changed` truthfully;
  - how the module reads and writes the files it manages (whole-file writes or not, CR and NUL handling, symlinks);
  - that it runs no shell and no scanner content.

Unchanged:

- `ansible.builtin.shell`, `command`, `raw` and `script` and their aliases stay banned (AGENTS.md rule 1). So does any
  community module whose purpose is to run a command or a script, such as `community.general.make` or
  `ansible.posix.at`.
- Everything ADR 0025 bans stays banned, whichever module would carry it: the scanner's remediation, its `fix`
  elements, generated playbooks and scripts.
- A family that uses a community module is held to the same rule as every other family: the real reader decides
  ("the reader is the oracle"). The module's own idea of the file never counts as evidence.

### 2. Value overrides

A new role variable `linux_compliance_remediate_value_overrides` maps the short identifier of an XCCDF `Value` to the
value the user wants written, for example:

```yaml
linux_compliance_remediate_value_overrides:
  var_password_pam_minlen: 16
  var_accounts_passwords_pam_faillock_unlock_time: 900
```

- The key is the `Value`, not the rule. Several rules share one value (the profile tailors values, not rules), and
  one override applies to all of them.
- Before any change, the role refuses a run when:
  - a key is not the `value_id` of a native rule in the catalogue;
  - a value does not pass the family's own validator for that setting, the same one that guards profile values:
    type, characters the reader accepts, and bounds the reader honours (for example at most 604800 for the
    faillock times).

  A typo can therefore never be silently ignored, and an override can never write a line that the reader reads
  differently.
- The effective value of a rule is the override when one is given, and the profile value otherwise. The ledger
  records `value_source` (`profile` or `override`), the profile value and the written value. Cleanup, and a value
  that changes while the rule stays on, work as for profile values (ADR 0011, ADR 0021).

### 3. Classification: stricter or equal is normal, looser is a deviation

The role compares the override with the profile value using the rule's `comparison`:

| `comparison` | The override meets the profile when |
|---|---|
| `at_least` | it is greater than or equal to the profile value |
| `at_most` | it is less than or equal to the profile value |
| `umask` | it masks at least the bits the profile value masks |
| `equal`, and any rule without a `comparison` | it is equal to the profile value |

Special values that the readers treat apart, such as `0` meaning "never" for `unlock_time`, are compared the way the
reader treats them, in the family's comparison function.

- **Meets the profile:** the rule gets its usual statuses (`applied`, `compliant`, …), with `value_source: override`
  in its result.
- **Looser than the profile:** the role still writes the override (owner decision of 2026-11-09). The rule's status
  is the new `deviation`, with the reason `operator_override`, the profile value and the written value, and
  `changed` as usual. It is never `applied` or `compliant`.

### 4. Findings and report

- The audit always evaluates the selected profile, so a looser override still fails the scan. The finding keeps
  outcome `fail`. It gets the flag `operator_deviation`, with the value identifier, the profile value and the
  written value, taken from the remediation result.
- A deviation is not a waiver. ADR 0013's rule that only an active exception record turns `fail` into `waived` is
  unchanged. A user who wants a deviation waived files an exception with an expiry, as for any other failure.
- The report (ADR 0016) counts deviations separately within the failures, and the dashboard (ADR 0017) lists them in
  their own section. The summary semantics are unchanged: a deviation is a failure.
- The verify and evidence roles carry the flag through, so a deviation is visible in every artefact that shows the
  rule.

### 5. Status of ADR 0003 and ADR 0025

Both are implemented on `main` (the native families since FREES-53, and FREES-188 for ADR 0025). They are accepted
with this amendment.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Overrides keyed by rule | Several rules share one `Value`; per-rule keys would let two rules for one setting disagree and write conflicting lines |
| Override values through an XCCDF tailoring of the audited profile | The audit would then measure the user's value, and a looser value would scan as `pass`, hiding the deviation from every report |
| Refuse a looser override | Rejected by the owner: the user decides; the collection's job is to make the decision visible |
| Report a looser override as `waived` | A waiver needs an accountable exception record with an expiry (ADR 0013); an override variable is neither |
| Any community module, unpinned | Widens the supply chain and lets a module's own parsing replace the reader; pinning, an allow list and a review keep both visible |
| Keep `ansible.builtin` and own modules only | Against the owner's requirement, and it forces a typed module where a reviewed community module would do |

## Benefits

- Users can tune every native value without editing generated files, and the tuning is validated, recorded in the
  ledger and reverted like any other change.
- A weakened host can never look compliant: a looser value is `deviation` in remediation, `fail` with
  `operator_deviation` in the findings, and its own section in the report.
- Community modules become available without losing the guarantees of ADR 0025.

## Trade-offs

- Each family needs a comparison function that knows its reader's special values, and a validator that the
  overrides share with the profile values.
- The allow list of community modules needs a security review per module, and their parsing has to be checked
  against the reader like our own.
- One more status (`deviation`) in the remediation results and one more flag in the findings model, both schema
  changes with tests.

## Security implications

An override can weaken a host by design. Three things limit the risk:

- It is an explicit role variable, so it is reviewable in the user's inventory.
- It goes through the same validators as profile values, so it cannot inject a line or a value the reader parses
  differently.
- It is reported at every layer (status, finding flag, report section) and never as compliant.

Community modules add third-party code that runs as root. The modules are pinned to exact versions, held to a
reviewed allow list, and kept under the "reader is the oracle" tests. The `own_remediation` guard and the process
helper's refusals stay in force.

## Operational consequences

- `docs/remediation-variables.md` and the remediate role's argument spec document
  `linux_compliance_remediate_value_overrides`, with the value identifiers each native rule uses.
- The schema of the remediation results, the findings model and the report gain `deviation`, `value_source` and
  `operator_deviation`, with tests.
- The `ansible_tasks` repository rule group gains the reviewed allow list of community modules; it starts empty.
- Each native family gets lifecycle regressions:
  - a stricter override is `applied`, then `compliant`, and is reverted byte for byte;
  - a looser override is `deviation` and the scan fails with `operator_deviation`;
  - an unknown key and an invalid value are refused before any change.
