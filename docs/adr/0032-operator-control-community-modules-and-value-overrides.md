# 0032. Operator control: community modules, and value overrides reported as deviations

- **Status:** accepted
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

## Acceptance 2026-11-10 (FREES-203)

This ADR is accepted through the pull request that implements the enforcement of §1, its first implementation. ADR
0003 and ADR 0025 are widened from now on, and AGENTS.md rule 1 reads: missing functionality becomes a typed Python
module, action plugin or `module_utils` code, or, **in a task file of `roles/remediate`**, a module of a community
collection on the allow list of §1.

What is in force with the acceptance:

- `tools/lint/repo_rules/remediate_modules.py`, run by `make lint-repo` for every YAML file below `roles/remediate/`
  whose document is a task list. A task key that is not a task keyword of ansible-core (the field attributes of
  `Task`, `Block` and `Handler`, plus the `with_` loops) names the module, and so do the first word of an `action` or
  `local_action` string and the `module` key of their mapping form. That name must be an `ansible.builtin` module of
  `BUILTIN_MODULES`, a `freesecdev.linux_compliance` module or a module on `ALLOWED_COMMUNITY_MODULES`. A short name,
  an `ansible.legacy` name and a templated name are refused, because Ansible may resolve them to any module.
- A fully qualified name does not fix the code that runs: a routing entry sends the name to another plugin before
  Ansible looks for a file. ansible-core's `config/ansible_builtin_runtime.yml` redirects more than 3700
  `ansible.builtin` module names to other collections (`ansible.builtin.make` to `community.general.make`,
  `ansible.builtin.at` to `ansible.posix.at`, `ansible.builtin.sysctl` to `ansible.posix.sysctl`,
  `ansible.builtin.pam_limits` to `community.general.pam_limits`) and removes others (`include`). So
  `BUILTIN_MODULES` lists the module files of the pinned ansible-core that its routing neither redirects nor removes,
  and a unit test keeps it equal to the installed ansible-core; every other `ansible.builtin` name is refused. A
  `freesecdev.linux_compliance` name needs its file in `plugins/modules` or `plugins/action` and no `redirect` or
  `tombstone` in `meta/runtime.yml`; a `meta/runtime.yml` that cannot be read refuses all of them.
- The role runs no tasks that the rule does not read. `include_role`, `import_role` and a dependency in
  `roles/remediate/meta/main.yml` are refused. `include_tasks` and `import_tasks` are accepted only as task keys whose
  target is `{{ role_path }}/tasks/` followed by a literal relative path, because Ansible looks for any other relative
  target in the playbook's directory too.
- Every file from which Ansible can load the role's tasks, handlers or metadata is one the rule reads. ansible-core
  2.21.6 (`Role._load_role_yaml`) loads the `tasks`, `handlers` and `meta` entry point `main` as `main.yml`,
  `main.yaml`, `main.json` or `main` without a suffix, and `tasks_from` and `handlers_from` of a caller load any file
  below `tasks/` or `handlers/` by its exact name, whatever its suffix. `DataLoader` reads each file as JSON before YAML
  and decrypts a vaulted file. So `tools/lint/repo_rules/remediate_files.py` requires of every file below
  `roles/remediate/tasks/`, `handlers/` and `meta/`, at any depth and case-folded, that it ends in `.yml` or `.yaml` and
  is YAML that PyYAML reads (JSON indented with tabs is not), and that each document is empty or a sequence of tasks
  (`tasks/`, `handlers/`) or a mapping (`meta/`), so a vaulted document is refused too. The role has no `handlers/`
  directory today; a handler file added later is read like any task file, whichever name or `listen` topic notifies it.
  `vars/` and `defaults/` hold variables only. A unit test loads each refused form through `_load_role_yaml` of the
  installed ansible-core to show that Ansible reads it, and keeps the directories and the `_from` options equal to
  ansible-core's.
- `ALLOWED_COMMUNITY_MODULES` is empty. `community.general.make` and `ansible.posix.at` are refused because they are
  not listed.
- An allow-listed module is refused unless its collection is pinned at one exact version (see H below).
- A unit test keeps the keyword list equal to the field attributes of the installed ansible-core, so a new keyword
  fails the test instead of being read as a module name.

Molecule scenarios, test playbooks and the other roles are outside the allow list; the banned modules apply to them as
before. One limit is documented rather than enforced: `ansible.builtin.service`, which the `ssh` family uses to reload
sshd, runs the module that the host's service manager fact names (its `use` parameter is refused, ADR 0004). On the
supported platforms that is `systemd`, a module of ansible-core; on a host with another service manager it can be a
community module, if that collection is installed on the controller. The value overrides of §2 to §5 are not
implemented yet: until their pull requests merge, `linux_compliance_remediate_value_overrides` does not exist, and
nothing in this section changes what the remediate role writes.

## Corrections to the context (2026-11-10)

`main` moved after the context above was written:

1. **Two more families carry a catalogue `comparison`.** Next to `login_defs`, the `faillock` and `pwhistory` rules
   (FREES-186, ADR 0027) have `comparison: at_least`, `at_most` or `present` in `content/catalogue.yml`. Their
   decision, including the faillock special values (`0` or `never` for the unlock times, at most 604800 seconds), is
   `satisfies` in `plugins/filter/pam_conf.py`, not yet in `module_utils`.
2. **One XCCDF value is shared by two rules.** `var_password_pam_remember` is the `profile_value` of both
   `accounts_password_pam_pwhistory_remember_password_auth` and `accounts_password_pam_pwhistory_remember_system_auth`.
   The case of §2, "one override applies to all of them", is real, and its implementation needs a test for it.
3. **Families with profile values.** Counted from the value rules of `roles/remediate/vars/rules.yml`: `login_defs` 6,
   `pwquality` 13, `pwhistory` 2 (one value), `faillock` 4, `ssh` 8, `sudo` 2, `ipv4_parameters` 19,
   `ipv6_parameters` 19 and `auditd_conf` 13. The 3 values of `banners` stay excluded (§2).

## Decisions of the implementation (2026-11-10)

These answer the questions that the decision above leaves open. Each one is implemented, with tests, by the pull
request of FREES-203 that owns that part.

- **A. Source of a deviation for the audit.** A deviation register in the ledger document on the host (`state.json`,
  ledger schema 2), a top-level `deviations` list separate from the revert entries: a deviation where nothing was
  written still needs a record, and no revert entry may exist for a change that was never made. The audit does not
  judge the value again: the remediation judges it with the family's reader, and the scanner judges the check. A
  missing ledger means no deviations. A corrupt or unsafe ledger makes `compliance_scan` fail before it scans, with
  the error type `deviation_source_invalid` (fail closed, as remediation already refuses a corrupt ledger). A stale
  record over-reports, which is the safe direction, until the next enabled remediation run corrects it.
- **B. Findings schema version.** The version follows the content: `1.3` when a finding carries
  `operator_deviation`, else `1.2` when a finding carries `control`, else `1.1` when the run is off-platform, else
  `1.0`. A `1.3` document has `control` and `deviation` (object or null) on every finding, `off_platform` as in `1.2`,
  and at least one deviation. Any other form is refused, so each document has one canonical form.
- **C. Flags and outcomes.** `_FLAG_OUTCOMES` maps a flag to a set of outcomes: `fixed` to `pass`, `informational`
  and `notselected` to `notchecked`, `operator_deviation` to `pass`, `fail` and `waived`. The flag is set exactly when
  the finding's `deviation` is set.
- **D. A deviated rule that scans `error`, `notchecked`, `notapplicable` or `disabled`** gets no flag, because the
  model does not allow it there. None of these outcomes counts as a pass (ADR 0016). The audit result lists such rules
  in `deviations.unflagged` with rule id and outcome, and the remediation result keeps the deviation. ADR 0013 and
  `docs/audit.md` record this when it is implemented.
- **E. Values without an order.** `exact` (sudo `logfile`, auditd `action_mail_acct`, every kernel parameter): any
  difference is a deviation. `choice_set` (the auditd actions): the override is one keyword the reader accepts, and it
  meets the profile when it is in the profile's `a|b|c` set. `algorithm_subset` (sshd `KexAlgorithms`, `MACs`): it
  meets the profile when it is a subset of the profile's list, order ignored, and the `+`, `-` and `^` modifiers are
  refused. Flags such as pwquality `dictcheck` and `enforcing` are ordered `0 < 1`. `MaxStartups` is compared per
  component (`start` and `full` at most, `rate` at least), unless the golden test of its check shows otherwise.
- **F. AGENTS.md rule 1** is worded as in the acceptance above.
- **G. ADR 0029.** The kernel parameter design that §1 refers to is implemented on `main` (FREES-107). Its row in
  `docs/adr/README.md` still says `proposed`; correcting that belongs to FREES-107, not to this ADR.
- **H. The requirements files of §1** are `galaxy.yml` `dependencies`, `extensions/molecule/requirements.yml` and
  `extensions/molecule/collections.pins` (with the SHA-256 and size of the artifact). An allow-listed module's
  collection must be named once in each, at the same `<major>.<minor>.<patch>` version; the repository rule of §1
  checks that they agree. FREES-160 adds the lock for installs and the Renovate policy on top, and remains a condition
  for listing the first community module.
- **I. Families that need comparison functions** before their values can be overridden: `pwquality`, `ssh`, `sudo`
  and `auditd_conf`, and also `faillock`, `pwhistory`, `ipv4_parameters` and `ipv6_parameters`, whose comparisons are
  in family code today (correction 1) or nowhere. `login_defs` moves into the same functions.
- **J. Judged statuses.** `applied`, `compliant` and `notapplicable` are judged; a looser value turns `applied` or
  `compliant` into `deviation`. The refusal statuses (`overridden`, `duplicate_setting`, `unreadable_*`,
  `not_regular_file`, `modified_*`, `method_changed`) are not judged and keep an earlier register record. A successful
  cleanup, or a plan action of `none`, removes the record.
- **K. `unused_overrides`** is a list of `{value_id, reason}` with the reasons `not_in_profile`, `disabled_by_toggle`,
  `disruptive_not_allowed`, `remediation_disabled` and `no_profile_value_for_content`. Keys are validated even when
  `linux_compliance_remediate_enabled` is false, so a typo fails early.
- **L. An override equal to the profile value** has `value_source: override`: it is the operator's input, and it is
  judged as meeting the profile.
- **M. Override value types.** A YAML integer (not a boolean) or a string, turned into canonical text by the
  comparison function. A YAML integer for a umask is refused, because YAML 1.1 reads `027` as octal 23; it must be a
  quoted string. Lists are refused; algorithm lists are comma-separated strings.
- **N. A selected rule without a profile value for the content** still fails closed. An override does not stand in for
  the missing profile value, because the classification needs it.
- **O. Audit gate.** The audit `summary` gains a `deviation` count next to the outcome counts; `pass` stays the raw
  outcome count there. The gate record gains `deviation`, and `linux_compliance_audit_fail_on_deviation` (default
  `false`, like `linux_compliance_audit_fail_on_noncompliant`) lets CI fail on deviations.
- **P. Report counting.** The summary gains `deviation` (every flagged rule) and `deviation_by_outcome` (`pass`,
  `fail`, `waived`). A flagged pass leaves `counts.pass` but stays in `evaluated`, so the percentage drops and
  `all_evaluated_passed` cannot be reached. Invariant: the sum of `counts` plus `deviation_by_outcome.pass` equals
  `rules`. A rule rolled up from several scans is flagged when any of them is.
- **Q. STIG checklist export.** A flagged `pass` exports as `Open`, with the deviation in `FINDING_DETAILS`: a
  checklist status is a reviewer's verdict, and a weakened host never looks compliant.
- **R. Which values are overridable.** A per-rule catalogue key `value_comparison: <name>` next to `profile_value`,
  generated into `parameters.value_comparison`, names an entry of `values.COMPARATORS` in `module_utils`. A family
  becomes overridable by changing only its catalogue entries and family files.
- **S. Register writes when a run aborts.** The register record is written before the family writes, in the order the
  ledger already uses, and only for rules whose deviation state changes. One final step in `tasks/main.yml` removes
  the records of rules that were cleaned up or planned `none`.

## Correction 2026-11-10: builtins that choose their module at run time (FREES-203)

This corrects the acceptance section above, which stays as written.

- **Not every name of `BUILTIN_MODULES` runs ansible-core's code.** Three of them are action plugins that choose while
  the play runs which module they execute (`_execute_module` with a name that is not a literal):
  `ansible.builtin.gather_facts` runs the fact modules that its `network_os` argument, `ansible_network_os` or
  `ansible_facts_modules` names (`cisco.ios.ios` runs `cisco.ios.ios_facts`), `ansible.builtin.package` runs the
  module that `ansible_package_use` or the `pkg_mgr` fact names, and `ansible.builtin.service` the one that the
  `service_mgr` fact names. A task of the role can set each of them, a variable by a `set_fact` key that is templated
  and so got past the literal-name rules of ADR 0004, and a fact by a cacheable `set_fact`. With ansible-core 2.21.6
  such a task file ran a module of an arbitrary installed collection, and the rule reported nothing. These three are
  now refused in `roles/remediate` (`DISPATCHING_MODULES` of `tools/lint/repo_rules/remediate_modules.py`); they stay
  on `BUILTIN_MODULES`, so that list remains equal to the module files of ansible-core. `ansible.builtin.dnf` chooses
  its backend at run time too, but only among `VALID_BACKENDS` of ansible-core, which name its `dnf` and `dnf5`
  modules or no module at all (`yum`), so it is accepted as `BOUNDED_DISPATCHING_MODULES`. A unit test parses every
  action plugin of the installed ansible-core and fails when one runs a module whose name is not a literal and it is
  on neither list. The first bullet of the acceptance therefore reads: the name must be an `ansible.builtin` module
  of `BUILTIN_MODULES` other than `DISPATCHING_MODULES`, a `freesecdev.linux_compliance` module or a module on
  `ALLOWED_COMMUNITY_MODULES`.
- **The documented limit is withdrawn.** The paragraph that starts "One limit is documented rather than enforced"
  described `ansible.builtin.service` as safe on the supported platforms and its module as chosen by the host's service
  manager. That was too narrow: the role's own tasks could choose the module, and `package` and `gather_facts` had the
  same property. The role no longer uses `ansible.builtin.service`. The `ssh` family reloads sshd with
  `ansible.builtin.systemd_service`, a module without an action plugin, and only where `service_facts` reports
  `ssh.service` or `sshd.service` running with `source: systemd`; elsewhere nothing is reloaded, as before where no
  service manager runs. No limit of §1 remains documented instead of enforced.
- **JSON load markers.** `DataLoader` reads a task file as JSON before YAML, and `AnsibleJSONDecoder` replaces any
  mapping that holds `__ansible_unsafe`, `__ansible_vault` or `__ansible_type` with the value it decodes. In an
  `action` or `local_action`, or in its `module` key, `{"__ansible_unsafe": "zz.evil.pwn"}` is therefore a module name
  to Ansible and a mapping to the rule. Only the unrelated rule that every YAML file starts with `---` kept such a
  file out. The module rule now refuses an `action` or `local_action` that is neither a string nor a mapping whose
  every `module` key is a string, and `tools/lint/repo_rules/remediate_files.py` refuses any key that starts with
  `__ansible_` in the role's `tasks/`, `handlers/` and `meta/` files; a unit test keeps the markers of ansible-core's
  JSON loader under that prefix.
- **Names learned at run time, outside §1.** The templated `set_fact` key above is one case of a wider gap of the
  rules of ADR 0004 (FREES-159), which refuse execution-altering variables and module parameters by their literal
  names: the same key sets `ansible_python_interpreter`, `ansible_connection` or `ansible_become_method`, a template
  given as `args`, as a free-form argument or as a `module_defaults` entry becomes the module's arguments (with
  ansible-core 2.21.6, `ansible.builtin.copy: "{{ d }}"` ran the `validate` command of `d`), and a literal
  `loop_var: ansible_python_interpreter` sets the interpreter for each loop item.
  `tools/lint/repo_rules/runtime_names.py` refuses these forms in every task list of the repository. A templated
  `set_fact` key is accepted only below `extensions/molecule/`, where the lifecycle harness switches the catalogue
  toggles of a family by name in throwaway instances; the roles, playbooks and test playbooks have none.

## Boundary of the module rule (2026-11-10)

Decision of the project lead, 2026-11-10, for FREES-203. This section corrects the sections above, which stay as
written, wherever they claim more than what follows.

The rule of §1 guards against mistakes and unreviewed additions. It is not a sandbox against a contributor who
deliberately builds a bypass in several steps. That threat is handled by the independent review of every pull request
([ADR 0033](0033-review-policy-independent-verdict-without-required-approval.md)), by CI and by the other rules of the
repository.

**What the rule guarantees.** Every module that a task, handler or metadata file of `roles/remediate` names is one of
these: an `ansible.builtin` module of `BUILTIN_MODULES` that is not in `DISPATCHING_MODULES`, a module or action plugin
of this collection, or a module on `ALLOWED_COMMUNITY_MODULES` whose collection is pinned. A module is named as a task
key, as the module of `action` or `local_action`, or as the `module` key of their mapping form. A module of this
collection must have its file in `plugins/modules` or `plugins/action`, and `meta/runtime.yml` may have no routing
entry for it other than `deprecation`. Every file below `roles/remediate/tasks/`, `handlers/` and `meta/` is a file the
rule reads.

**What it refuses in addition**, so that the guarantee does not depend on how Ansible resolves a name:

- `ansible.builtin` names that ansible-core redirects or removes, and short, `ansible.legacy` and templated names;
- `ansible.builtin.gather_facts`, `package` and `service`, whose action plugins choose at run time which module they
  run;
- an `action` or `local_action` whose module is not a plain string, and any key that starts with `__ansible_` in the
  role's task, handler and metadata files;
- below `tasks/`, `handlers/` and `meta/` of the role, a file without a `.yml` or `.yaml` suffix, a file PyYAML cannot
  read, and a document that is not a task list (`meta/`: a mapping);
- `include_role`, `import_role` and role dependencies, and `include_tasks` or `import_tasks` with a target other than
  `{{ role_path }}/tasks/` followed by a literal path;
- in `meta/runtime.yml`, a `plugin_routing` entry for `modules` or `action` with a key other than `redirect`,
  `tombstone` and `deprecation` (for example `action_plugin`), a `module_utils` entry with a key other than
  `deprecation` (for example `redirect`), a routing section or entry that is not a mapping, and any
  `import_redirection` (`tools/lint/repo_rules/remediate_routing.py`). The file has none of these today;
- repository-wide, wherever variables or facts are set: `ansible_network_os` and `network_os`, next to
  `ansible_facts_modules`, `ansible_package_use`, `pkg_mgr` and `service_mgr` (`BACKEND_VARIABLES` of
  `tools/lint/repo_rules/exec_variables.py`, ADR 0004). These variables and facts choose the module that
  `gather_facts`, `package` and `service` run, also for a play's own fact gathering after the role has run;
- the keywords `delegate_to`, `delegate_facts`, `local_action` and `connection` on any task or block of
  `roles/remediate`. Only these keyword forms are refused; the other ways in which a task reaches the controller or
  another host are listed below. The role used none of the four keywords when this was added;
- repository-wide, names that Ansible learns only at run time (`tools/lint/repo_rules/runtime_names.py`).

**What it does not defend against.** These are left to the independent review of every pull request under ADR 0033:

- Jinja filter, test and lookup plugins of other collections in templates and expressions of the role. They are code
  on the controller, not modules, and the rule does not read them.
- Files planted by tasks of the role, for example a module that a task writes into one of Ansible's module paths,
  which ansible-core's own action plugins then load as an `ansible.legacy` module. Such a file can be planted on the
  controller through any of the forms in the next item, not only on a controller that is also a managed host. The rule
  has no check on `roles/remediate/files/` or `templates/`.
- Ways other than the four keywords in which a task of the role runs on the controller or on another host, or writes
  there: connection and host variables such as `ansible_connection` (for example `local`) and `ansible_host` set as
  `vars` of a task, block or the role; `delegate_to`, `connection` and the other keywords inside `apply` of an
  `include_tasks`, which is not a task and which the rule does not read; and `ansible.builtin.fetch`, an accepted
  `ansible.builtin` module whose `dest` is on the controller by design. Today the role sets none of these variables,
  has no such key in `apply` and does not use `fetch`.
- Plugin routing outside the forms it checks: `plugin_routing` of other plugin types (filters, tests, lookups and the
  rest), and routing or plugin paths that the operator's configuration sets.
- Settings of the play, inventory or configuration that run the role and that are outside `roles/remediate`, other
  than those the rules of ADR 0004 refuse in this repository.
- A contributor who edits the rule, its lists or its tests. The drift tests compare the lists with the installed
  ansible-core only in the forms they read: the dispatch test finds `_execute_module` calls whose module name is not a
  literal, and not a module chosen through routing or through variables that a play-level task reads.

**Corrections of earlier sentences.**

- "The role runs no tasks that the rule does not read" (acceptance) means: every task and handler file of the role is
  a file the rule reads. It does not mean that only reviewed code runs during remediation. The limits above remain.
- "No limit of §1 remains documented instead of enforced" (correction of 2026-11-10) is withdrawn. The limits above are
  documented and left to review.
- "`meta/runtime.yml` neither redirects nor removes" a module of this collection (acceptance) now reads: it has no
  routing entry for the module other than `deprecation`, and it holds no routing that the rule does not read.
- The `ssh` family's reload through `ansible.builtin.systemd_service` (correction of 2026-11-10) stays. On the supported
  platforms (ADR 0010: Ubuntu 24.04 and RHEL 9-compatible hosts, both with systemd) `ansible.builtin.service` ran the
  same `systemd` module of ansible-core (`systemd.py` and `systemd_service.py` are one file), and `service_facts` names
  a unit `ssh.service` or `sshd.service` only with `source: systemd`, so the change is behaviour-neutral there. The
  Molecule `ssh` lifecycle legs ran and passed on both Docker images, in `rule` and in `topic` mode. Their containers
  run no systemd, so the reload was skipped there, as it was before the change.

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

- a umask is a zero and two octal digits given as a string (`027`), the strict form of ADR 0024 that every reader
  of `UMASK` reads alike; a YAML integer is refused, because YAML 1.1 reads `027` as 23, and so is a umask with the
  owner's bits such as `177`, because shadow-utils reads it with base 0 as the decimal 177 (octal 261, which leaves
  the read and write bits of others unmasked) while `pam_umask` reads it as octal 177; such a value is neither
  accepted nor judged;
- integers are decimal without a sign, leading zero or `-0`, so `016` is never read as octal by one reader and as
  decimal by another;
- `minlen` starts at libpwquality's floor of 6 and `minclass` ends at its 4 classes, because the library reads other
  values as those;
- `maxrepeat`, `maxclassrepeat` and `maxsequence` treat 0 (off) as the loosest value, and `retry` starts at 1;
- `deny = 0` (never lock) is judged the loosest value but refused as an override, as the faillock family refuses a
  maximum of 0; `unlock_time = 0` (never unlock) is the strictest and is accepted; the faillock times end at 604800
  and `deny` at 65535, which pam_faillock stores in 16 bits;
- `login_defs_at_most` has no loosest value, so a host value of `PASS_MAX_DAYS -1` (no expiry) cannot be judged
  and `judge` raises, which fails closed; whether it is judged as a deviation instead is decided, against the OVAL
  check, when the `login_defs` family is wired for overrides.

No catalogue entry names a comparator yet, so nothing is overridable and behaviour is unchanged.
`plugins/filter/pam_conf.py` keeps its own decision until the faillock and pwhistory family is wired; the unit tests
pin the faillock and pwhistory comparators to that filter's decisions over a table of values, and the `login_defs`
comparators to the family's Jinja.

## Amendment of 2026-11-11: the variable and its validation (FREES-203)

`linux_compliance_remediate_value_overrides` exists from this pull request on, with the default `{}`, as a role
default and an argument specification option of type `dict`. The sentence of the acceptance section that it "does not
exist" until the pull requests of §2 to §5 merge is therefore outdated; the rest of that sentence holds: nothing that
the role writes changes yet.

The filter `freesecdev.linux_compliance.value_overrides` checks the variable in `tasks/main.yml` right after the plan's
own error check and before the dispatch, so a refused override stops the role before any family reads or changes the
host, also when remediation is disabled (decision K). It refuses, all at once: a key that is not the `value_id` of a
native rule (a full `xccdf_org.ssgproject.content_value_` identifier is refused with its short form in the message), a
value of the `banners` family, naming `linux_compliance_remediate_banner_text`, a value whose rules name no
`value_comparison` or different ones, and a value that the comparator's `validate` refuses, which covers decision M.
Since no catalogue rule names a comparator yet, every key is refused today.

For every rule that the plan applies and that has a value, the filter resolves `value_id`, `value_source`,
`profile_value`, `target` and `comparison` into the internal fact `__linux_compliance_remediate_values`, with the
lookup that the family files make in Jinja; no family reads it yet. An override of a rule without a profile value
for the content is not used (decision N): `value_source` stays `profile` and `target` stays `none`, so the family
still fails closed. A key that no applied rule uses is listed in `unused_overrides` of `linux_compliance_remediated`
and in the notices. For a value that several rules share, decision K's reason is that of the first of its rules by
rule identifier, and the key counts as used when any of its rules applies it.
