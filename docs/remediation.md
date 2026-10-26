# Remediation

Scope: the `freesecdev.linux_compliance.remediate` role, its safety model, its variables, the rule catalogue and the
contract that every control family task file implements. Audience: operators, playbook authors, family authors and
reviewers. Jira: FREES-52, FREES-55 (generated toggles). Decisions: [ADR 0003](adr/0003-native-module-remediation.md) (native modules only),
[ADR 0011](adr/0011-control-toggles-and-cleanup.md) (toggles, cleanup and the state ledger, with the amendment of
FREES-52).

Remediation changes managed hosts. It never runs ComplianceAsCode playbooks, Bash fixes or `oscap --remediate`; every
change is made by a native Ansible module or by a module of this collection. A remediated rule is not a claim of
compliance: only a later audit shows whether the rule now passes, and a host scan is never a certification.

## Status

The dispatcher, the safety model and one reference family are implemented. The catalogue holds exactly one rule,
`xccdf_org.ssgproject.content_rule_file_permissions_crontab` (family `file_permissions`). The toggles of every family
and rule are generated from the catalogue (FREES-55) and honoured by the audit role too. The control families of
FREES-53 and the cleanup paths of the other families (FREES-57) follow. The
reference rule was exercised for real only in a disposable Ubuntu 24.04 container (see [Testing](#testing)); no
Molecule scenario exists yet.

## Safety model

| Control | Default | Effect |
|---|---|---|
| `linux_compliance_remediate_enabled` | `false` | Without it the role neither reads the state ledger nor changes anything. It only reports every rule as `skip` with the reason `remediation_disabled`. It gates cleanup as well, so disabling a rule while remediation is off changes nothing until the next enabled run. |
| `linux_compliance_remediate_allow_disruptive` | `[]` | Rules of a disruptive family are applied and cleaned up only when the family is named here. Otherwise they are `skip` with the reason `disruptive_not_allowed`, and a notice names them. A rule that the ledger records as applied and that would no longer be applied (toggled off or no longer in the profile) keeps its ledger entry and is reported with `pending_cleanup: true` until the family is allow-listed. |
| Profile check | the discovered profile | With the opt-in, the role requires `linux_compliance_discovered` from the `discover` role for the same profile and applies only rules that the verified profile selects. It never substitutes another profile. |
| Fail closed | always | Unknown rule or family toggles, toggles that are not booleans, allow-list entries that are not disruptive families, an invalid catalogue and a ledger entry whose family contradicts the catalogue stop the role before anything changes. |
| Check mode | `--check` | Every task runs in check mode: nothing is written, not even the ledger, and the role reports what would change. |
| No silent skips | always | Every task runs with the tag `always`, so `--tags` and `--skip-tags <family>` cannot skip work. After the dispatch the role fails unless every rule planned for `apply` or `cleanup` has exactly one result (filter `remediation_unaccounted`). `--skip-tags always` fails the role through a guard task tagged `linux_compliance_remediate_guard`. |
| Family files refuse direct use | always | Every family file and helper first asserts the opt-in and checks its family and rule against the dispatcher's own plan (`__linux_compliance_remediate_plan`), so `include_role` with `tasks_from` cannot change the host without the opt-in and a matching plan. |

The opt-in must be a JSON boolean on the command line: `-e '{"linux_compliance_remediate_enabled": true}'`.
`-e linux_compliance_remediate_enabled=true` passes a string and fails the input validation.

## Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_remediate_enabled` | `bool` | `false` | Global opt-in. |
| `linux_compliance_remediate_allow_disruptive` | `list` of `str` | `[]` | Disruptive families that may be applied and cleaned up. The argument specification accepts only the disruptive families of the registry. |
| `linux_compliance_remediate_profile` | `str` | `cis_level1_server` | Profile short identifier; must equal the profile the `discover` role verified. |
| `linux_compliance_<family>_enabled` | `bool` | `true` | Topic toggle of a registered family, for example `linux_compliance_auditd_enabled: false` turns off every auditd rule. |
| `linux_compliance_rule_<rule_short_id>_enabled` | `bool` | `"{{ linux_compliance_<family>_enabled }}"` | Toggle of one catalogued rule, for example `linux_compliance_rule_file_permissions_crontab_enabled`. |

The topic and rule toggles are flat booleans, so any inventory layer can set one of them. Their defaults and argument
specifications are generated from the catalogue; every toggle is listed in the
[remediation variable reference](remediation-variables.md).

### Generated toggles

`tools/roles/generate_toggles.py` (`make toggles`) derives from `roles/remediate/vars/rules.yml`:

- in `defaults/main.yml` of the `remediate` and the `audit` role, `linux_compliance_<family>_enabled: true` for every
  registered family, in registry order, then
  `linux_compliance_rule_<rule_short_id>_enabled: "{{ linux_compliance_<family>_enabled }}"` for every catalogued rule,
  sorted by rule identifier;
- in the `main` entry point of `meta/argument_specs.yml` of both roles, an option of type `bool` with a description
  for each. A topic toggle has `default: true`. A rule toggle has no `default` in the argument specification, because
  the role argument validation would check the template string of its default against the type `bool`; its
  description names the family toggle it defaults to;
- the reference page [remediation-variables.md](remediation-variables.md).

Every other variable and option of those files is kept, in its order, and toggles that the catalogue no longer
contains are removed. Both YAML files are written in one canonical style that is checked to load back to the same data.
`make lint-toggles` (part of `make lint`, CI job `lint`) regenerates all five files in memory and fails with a diff when
any of them differs from the files in the repository, so no rule can be catalogued without its toggle and no toggle can
outlive its rule. `tools/roles/check_role_specs.py` (`make lint-ansible`) checks the toggles on its own as well: in the
`remediate` and `audit` roles, the set of toggle names, every default (value and type) and every argument
specification must equal what the generator produces for the catalogue, so an uncatalogued toggle, a near-namespace
name such as `linux_compliance_remediatex_enabled` or a rule default that points at the opt-in or at another family is
a finding. Toggles in any other role fail its role-prefix rule.

When a topic toggle is `false` but no catalogued rule of its family is in the profile (in the catalogue, when remediation
is disabled), the notices of the role contain a `WARNING:` that the toggle currently changes nothing; the audit role
prints the same warning ([variable reference](remediation-variables.md#what-a-topic-toggle-covers)).

A rule toggle default is a template. Ansible resolves it to the boolean of the family toggle when the role reads it,
and the filter checks that resolved value: a family toggle passed as the string `"false"` makes both the family toggle
and every rule toggle that follows it fail the role as non-boolean.

### Effective state of a rule

For every catalogued rule the filter `freesecdev.linux_compliance.remediation_plan` resolves:

1. The **toggle state**: the rule toggle when it is set, else the family toggle when it is set, else on. The variable
   that switched a rule off is reported as `disabled_by`: the family toggle whenever the family toggle is off, and the
   rule toggle otherwise. Because the generated default of a rule toggle is its family toggle, the role cannot tell a
   rule toggle that follows a disabled family from one that is also set to `false`; both name the family toggle. A
   rule toggle set to `true` wins over a disabled family toggle. The resolution lives in
   `plugins/module_utils/compliance/toggles.py`, which the audit role uses as well, so a rule that is switched off is
   reported as `disabled` by the audit with the same controlling variable
   ([disabled rules in the audit](audit.md#disabled-rules-adr-0011)).
2. The **action**, in this order:

| Condition | Action | Reason |
|---|---|---|
| `linux_compliance_remediate_enabled` is false | `skip` | `remediation_disabled` |
| The family is disruptive and not allow-listed | `skip` | `disruptive_not_allowed` |
| Toggle on and the discovered profile selects the rule | `apply` | `enabled` |
| Otherwise, and the ledger has no entry for the rule | `none` | `disabled_by_toggle` or `not_in_profile` |
| Otherwise, and the rule is irreversible | `manual` | as above; a notice links the runbook and the ledger entry is kept |
| Otherwise | `cleanup` | as above |

So disabling a rule or a whole topic that was applied before cleans it up, and switching to a profile that no longer
selects an applied rule cleans that rule up too.

### Toggle names and reserved names

The role finds every variable that matches `^linux_compliance_.+_enabled$` (`ansible.builtin.varnames`). Only the
declared role variable `linux_compliance_remediate_enabled` is ignored. Every other name must be the toggle of a
catalogued rule (`linux_compliance_rule_*`) or of a registered family, or the role fails. A name in the namespace of a
role of the collection (`linux_compliance_<role>_enabled` or `linux_compliance_<role>_*_enabled` for `audit`,
`discover`, `evidence`, `remediate` and `verify`) that is not a declared variable fails too, so the likely typo
`linux_compliance_audit_enabled` for the auditd topic is caught. Family names must therefore not equal or start with a
role name followed by `_`, and must not be `rule` or start with `rule_`. `auditd` is a valid family name; `audit_rules`
would not be.

## Disruptive families

The family registry is in `roles/remediate/vars/rules.yml`. Its order is the dispatch order: non-disruptive families
first, so that a failure in a disruptive family leaves the harmless changes applied, then the families in order of
growing lock-out risk, with the bootloader last because it takes effect only on the next boot.

| Order | Family | Disruptive | Why |
|---|---|---|---|
| 1 | `file_permissions` | no | Tightens modes and owners of system files; no service is restarted |
| 2 | `sysctl` | no | Kernel hardening parameters that do not change routing or forwarding (those belong to `network`) |
| 3 | `auditd` | yes | Audit settings can halt the host or drop it to single-user mode when the audit log fills, and immutable rules need a reboot to change |
| 4 | `services` | yes | Disabling or masking services can stop workloads the host exists for |
| 5 | `network` | yes | Forwarding, redirects and IPv6 settings can cut routers, container hosts and VPN gateways off |
| 6 | `firewall` | yes | A default-deny policy can cut every remote session |
| 7 | `ssh` | yes | sshd settings can lock out every remote operator |
| 8 | `pam` | yes | Lock-out, password quality and module order can lock out every user, including root |
| 9 | `sudo` | yes | Can remove administrative access |
| 10 | `crypto_policy` | yes | Can break TLS and SSH with older peers |
| 11 | `mounts` | yes | Mount options can break running software; partitioning is irreversible |
| 12 | `bootloader` | yes | A wrong boot configuration can leave the host unbootable |

Cleanup of a disruptive family is gated exactly like applying it, because reverting SSH, PAM or firewall settings can
also lock operators out. Every rule of a disruptive family is disruptive; the catalogue rejects a rule whose flag
differs from its family. The disruptive families of this table are also pinned in the filter
(`DISRUPTIVE_FAMILIES`), so a registry passed in through `-e`, `set_fact` or role parameters that marks one of them
non-disruptive fails the role instead of bypassing the allow-list.

## Rule catalogue

`roles/remediate/vars/rules.yml` holds `__linux_compliance_remediate_families` (the registry above) and
`__linux_compliance_remediate_rules`. Each rule has exactly these keys; the filter rejects anything else.

| Key | Contract |
|---|---|
| `rule_id` | Full ComplianceAsCode XCCDF rule identifier, unique |
| `family` | A registered family; it names the task file `roles/remediate/tasks/<family>.yml` |
| `disruptive` | Equals the flag of the family |
| `reversible` | `false` exactly for the `irreversible` strategy |
| `revert_strategy` | `owned_dropin`, `recorded_value`, `recorded_state` or `irreversible` (ADR 0011) |
| `toggle` | `linux_compliance_rule_<rule_short_id>_enabled` |
| `runbook` | A `docs/` path or `https://` link for an irreversible rule, `null` for every other rule |
| `parameters` | A mapping that only the family task file interprets |

A rule enters the catalogue only when the pinned content shows that it exists. The reference rule is selected by the
Ubuntu 24.04 profiles `cis_level1_server`, `cis_level1_workstation`, `cis_level2_server` and `cis_level2_workstation`
and by the RHEL 9 profiles `bsi`, `cis`, `cis_server_l1`, `cis_workstation_l1`, `cis_workstation_l2` and `pci-dss` of
the pinned content `v0.1.82`, checked with `catalog.read_benchmarks` on the fetched datastreams. The role does not
trust this list: it applies a rule only when `linux_compliance_discovered.rule_ids` contains it.

## Dispatch

`tasks/main.yml` only dispatches; every task in it is tagged `always`, except the two guard tasks tagged only
`linux_compliance_remediate_guard`.

0. Refuse internal variables supplied from outside the role: `tasks/internal_variables.yml`, generated by
   `make role-guards`, resets every internal fact to a sentinel and asserts that every internal fact, task variable
   and constant reads back as set by the role. A role parameter, an include parameter or an extra variable named
   `__linux_compliance_remediate_*`, or a catalogue set by the play, stops the role before anything is read or
   changed.
1. Arm the guard (guard tag): set `__linux_compliance_remediate_dispatched` to `false`.
2. Validate the inputs (the argument specification runs first).
3. Load the catalogue and the registry with `ansible.builtin.include_vars`.
4. Find the toggle variables.
5. With the opt-in only: check `linux_compliance_discovered` (same profile, at least one rule) and read the ledger with
   `control_state` `list`.
6. Resolve the plan with `remediation_plan` and stop on any error.
7. Include `tasks/dispatch.yml`, which holds one static include of the literal `{{ role_path }}/tasks/<family>.yml`
   for every catalogued family, in registry order, each run only for the plan entry of its family and with the tag
   `always` applied to it. No variable chooses the file. The dispatch is generated from the registry by
   `make role-guards`, which fails for a catalogued family without a task file; planned work of a family without a
   dispatch entry fails step 9.
8. Publish the fact `linux_compliance_remediated` and print the notices (skipped disruptive rules, manual actions,
   orphaned ledger entries, incomplete cleanups).
9. Fail unless every rule planned for `apply` or `cleanup` has exactly one result, and no other result exists
   (`remediation_unaccounted`).
10. Mark the dispatch as complete; the final guard task (guard tag) fails the role when it was not.

Toggles, not tags, select rules. Every task of the role and of its family files is tagged `always` and nothing else,
so `--tags` and `--skip-tags <family>` change nothing, and a task skipped any other way fails step 9.
`--skip-tags always` skips every always-tagged task; the two guard tasks still run, and the role fails with a message
that nothing was remediated or cleaned up. Combining `--tags <tag>` with `--skip-tags always` skips the guard as well,
so the role does nothing and that run must not be read as success.

## Family file contract

A family file `roles/remediate/tasks/<family>.yml` receives `__linux_compliance_remediate_family` with `name`,
`disruptive`, `cleanup` (rules to clean up) and `apply` (rules to apply), each rule being its catalogue entry plus
`action`, `reason`, `disabled_by` and `ledger_entry` (the ledger entry as `control_state` returns it, or `null`). It
must:

1. **Clean up first, then apply.** Loop over `cleanup`, then over `apply`; per-rule logic may live in helper files
   named `<family>_<purpose>.yml`.
2. **Use native modules only.** No `shell`, `command`, `raw`, `script`, `expect` or anything that executes code
   indirectly; the repository guard enforces the module ban. Missing functionality becomes a typed module or filter of
   this collection.
3. **Record before changing.** For `recorded_value` and `recorded_state`, call `control_state` `record` with the prior
   values before the first change, and only when the change is needed and `ledger_entry` is `null`. Never re-record an
   existing entry: the first recorded value is the true prior state. For `owned_dropin`, record an entry without prior
   values, so the dispatcher knows the rule was applied.
4. **Clean up from the ledger, never by guessing.** Restore the recorded prior value or remove the owned drop-in, then
   call `control_state` `remove`. If a prior value is missing or cannot be applied, keep the ledger entry and report
   `cleanup_incomplete`. `ledger_entry` comes from `control_state` `list`, which redacts sensitive prior values; a
   family that stores one (through `sensitive_prior_values`) reads it back with `control_state` `get` and
   `reveal_sensitive: true` in a task with `no_log: true`.
5. **Honour check mode.** Never set `check_mode: false`, never skip a task in check mode to hide a change, and never
   use `changed_when: false` or `ignore_errors` to hide a change or a failure. `control_state` writes nothing in check
   mode.
6. **Honour diff mode.** Change files with modules that produce a diff; `control_state` shows the ledger entry before
   and after.
7. **Be idempotent.** A second run with the same toggles reports zero changes, after apply and after cleanup.
8. **Report exactly one result per planned rule** by appending to `__linux_compliance_remediate_results` a mapping
   with `rule_id`, `family`, `action` (`apply` or `cleanup`), `status`, `reason` (`null` or why the cleanup is
   incomplete), `changed` and `message`. The dispatcher fails when a planned rule has no result or more than one.
9. **Stay narrow.** One family per file; no rule logic in `tasks/main.yml`.
10. **Tag every task `always` and nothing else.** A family tag would let `--skip-tags <family>` skip planned work.
11. **Refuse direct use.** The entry file and every helper start with one `ansible.builtin.assert`:
    - `linux_compliance_remediate_enabled` is `true` and `__linux_compliance_remediate_plan.enabled` is `true`;
    - in the entry file, `__linux_compliance_remediate_family` equals the entry for the family in
      `__linux_compliance_remediate_plan.families`;
    - in a helper, `__linux_compliance_remediate_rule` is one of the rules in that entry's `apply` or `cleanup` list.

    The family context and the rule only select work; the dispatcher's own plan authorises it. This is defence in
    depth against `include_role` with `tasks_from`. The real decisions (opt-in, allow-list, toggles, profile) are made
    by the dispatcher before the file is included. A playbook author who sets every private fact by hand can still
    pass these checks, but cannot do so without the opt-in.
12. **Include helpers from the role.** Use `file: "{{ role_path }}/tasks/<family>_<purpose>.yml"`, never a bare file
    name, so a missing helper fails instead of resolving against the playbook directory.

### Reference family: `file_permissions`

`file_permissions_crontab` restricts `/etc/crontab` to at most `0600`, as the ComplianceAsCode fix does
(`chmod u-xs,g-xwrs,o-xwrt`): the filter `freesecdev.linux_compliance.restricted_mode` computes `current & 0600`, so a
stricter mode such as `0400` is kept and only the excess bits are removed. Its strategy is `recorded_value`.

| Step | Module | Behaviour |
|---|---|---|
| Inspect | `ansible.builtin.stat` with `follow: false` | A missing file is `notapplicable`; a symbolic link or other non-regular file is `not_regular_file`; neither is changed |
| Record | `freesecdev.linux_compliance.control_state` `record` | Prior mode (for example `0644`), only when the mode must change and no entry exists |
| Apply | `ansible.builtin.file` with `follow: false` | Sets the restricted mode; status `applied`, or `compliant` when nothing had to change |
| Clean up | `ansible.builtin.file`, then `control_state` `remove` | Restores the recorded mode, which must be exactly four octal digits, and then removes the entry (`restored`). Otherwise nothing is changed, the entry is kept and the result is `cleanup_incomplete` with the reason `target_absent` (the file is missing), `not_regular_file` (a symbolic link or other non-regular file) or `invalid_record` (no usable recorded mode). The cleanup is retried on every run until it succeeds; a file that is removed for good leaves its entry behind until an operator removes it with `control_state` `remove` |

## Results

The role publishes `linux_compliance_remediated`:

| Key | Content |
|---|---|
| `enabled`, `check_mode`, `profile`, `allow_disruptive` | The run settings |
| `summary` | Number of rules per action (`apply`, `cleanup`, `manual`, `none`, `skip`) |
| `rules` | Every rule with `rule_id`, `family`, `action`, `reason`, `disabled_by`, `pending_cleanup` and `runbook` |
| `results` | Exactly one result per rule planned for `apply` or `cleanup`, from the family files, with `rule_id`, `family`, `action`, `status`, `reason`, `changed` and `message` |
| `disabled_rules` | Rules switched off by a toggle (`rule_id`, `disabled_by`), restricted to the profile when remediation is enabled. The audit role computes the same list itself from the same toggles, so it does not depend on this fact |
| `orphaned` | Ledger entries for rules that the catalogue no longer contains; nothing is done to them |
| `notices` | Operator messages |

### A lost ledger cannot be detected

`control_state` `list` returns the same empty list for a ledger that never existed and for one that was deleted, and
the role cannot tell them apart. If `/var/lib/freesecdev/linux_compliance/state.json` is lost, every applied
`recorded_value` or `recorded_state` rule that is then disabled plans as `none`: nothing is restored and no notice is
printed, because the prior state is unknown and the role never guesses it. The hardening stays in place, which errs
on the side of security, but the host no longer returns to its pre-collection state for those rules. Back up the
ledger with the host's configuration, and restore it before disabling rules after a rebuild. Owned drop-ins
(`owned_dropin`) do not depend on the ledger for cleanup once their families exist (FREES-57).

## Running

Through the playbook, which audits first and runs the `verify` role afterwards ([playbooks](playbooks.md)):

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.remediate \
  -e linux_compliance_target_hosts=web01 \
  -e linux_compliance_discover_content_path=/opt/freesecdev/content/ssg-ubuntu2404-ds.xml \
  -e linux_compliance_discover_content_sha256=<sha256 from content/manifest.yml> \
  -e '{"linux_compliance_remediate_enabled": true, "linux_compliance_rule_file_permissions_crontab_enabled": true}' \
  --check --diff
```

Drop `--check` to apply. To revert the rule, run again with
`"linux_compliance_rule_file_permissions_crontab_enabled": false` (or `"linux_compliance_file_permissions_enabled":
false` for the whole topic) and the opt-in.

## Security considerations

| Concern | Handling |
|---|---|
| Unintended host changes | The opt-in gates every read and write; the default inventory leaves remediation off |
| Operator lock-out | Disruptive families need the allow-list for apply and cleanup alike |
| Typos silently disabling or keeping a control | Unknown and non-boolean toggles and unknown allow-list entries fail closed |
| Remediating rules the content does not select | Only rules in the digest-verified profile of the `discover` role are applied |
| Path injection into `include_tasks` | Family names come only from the registry and match `[a-z][a-z0-9_]{0,63}` |
| Symbolic links at a target | `stat` and `file` use `follow: false`; a non-regular target is neither changed nor restored |
| Lost or tampered prior state | The root-only ledger of `control_state` (ADR 0011); a restored mode must match `^[0-7]{4}$`, otherwise the entry is kept and the cleanup is reported incomplete |
| Ledger entries the catalogue no longer knows | Reported as orphaned, never cleaned up by guesswork |

Residual risk: between `stat` and `file` a root-level attacker could replace the target; anyone who can write to `/etc`
already controls the host. A remediated rule is not proof that the control passes; only the next audit is.

## Testing

| Test | What it proves | Where it runs |
|---|---|---|
| `tests/unit/plugins/filter/` | Effective-state resolution and validation (`remediation_plan`), result accounting (`remediation_unaccounted`) and `restricted_mode`, 100% line and branch coverage | `make test-coverage`, `ansible-test units` |
| `tests/unit/roles/test_remediate_catalogue.py` | The catalogue is valid, the allow-list choices equal the disruptive families, every family with rules has a task file, the recorded collection version equals `galaxy.yml` | `make test-coverage` |
| `tests/unit/roles/test_remediate_tasks.py` | Every task in `roles/remediate/tasks/*.yml`, including tasks in blocks, is tagged exactly `[always]`; the only exceptions are the two guard tasks of `main.yml`. Every include applies exactly `always` and loads a file below `{{ role_path }}/tasks/`. The completeness check asserts the `remediation_unaccounted` result of the plan and runs before the dispatch is marked complete | `make test-coverage` |
| `tests/unit/tools/test_check_role_specs.py` | The guard tag is accepted only, and alone, on a top-level `assert`, `fail` or the `__linux_compliance_<role>_dispatched: false` `set_fact` of the role's `tasks/main.yml`. It is refused on other modules, a `set_fact` with other keys, includes, imports, blocks, conditions, loops, nested tasks, `apply`, other task files and another role's name | `make test-coverage` |
| `tests/playbooks/remediate-check-mode.yml` | Against localhost, in check mode and without `become`. Nothing happens without the opt-in: the ledger read and the profile check are skipped. The reference rule is planned and the host is unchanged. Invalid toggles, allow-list entries, a profile mismatch and an empty profile fail. A disruptive family is skipped without the allow-list. The `file_permissions` helpers, called with synthetic planned rules against `tests/playbooks/fixtures/remediate/` (a regular file and a symbolic link): the prior mode is recorded only without a ledger entry, a symbolic link or an absent target is never changed, invalid recorded modes (`abc`, `06440`, a trailing newline, no mode) and absent or non-regular targets keep the entry as `cleanup_incomplete`, and the family file and helpers refuse to run without the opt-in or for a rule the dispatcher did not plan. Every play refuses to run without `--check`. The target runs it twice, the second time with `--skip-tags file_permissions` | `make test-remediate-check`, CI job `test` |
| `tests/unit/plugins/module_utils/compliance/test_toggles.py`, `tests/unit/plugins/filter/test_audit_disabled_rules.py` | Toggle resolution: a rule toggle overriding its family in both directions, a family switched off, the controlling variable, non-boolean values (including an unresolved template string), unknown and reserved toggle names, and that `remediation_plan` and `audit_disabled_rules` agree on the disabled rules for the same toggles, also with the generated defaults templated in | `make test-coverage` |
| `tests/unit/tools/test_generate_toggles.py` | The generated defaults, argument specifications and reference equal the files in the repository; drift is reported with a diff and nothing is written in `--check` mode; stale toggles are removed; a new rule gets its toggle; an invalid catalogue fails; the YAML renderer round-trips and refuses what it cannot render within 120 characters. 100% line and branch coverage | `make test-coverage`, `make lint-toggles` |
| `tests/playbooks/remediate-check-mode.yml`, toggle plays | In check mode, with the generated defaults: a single rule switched off and a whole topic switched off are not applied, name the rule toggle or the topic toggle as `disabled_by`, and the audit role's `toggles.yml` resolves the same disabled rules; a rule switched back on inside a disabled topic is applied and disabled in neither role; the audit fails before any scan on `linux_compliance_audit_enabled`, a string toggle and a catalogued rule in `linux_compliance_audit_disabled_rules`, and keeps explicit entries for uncatalogued rules | `make test-remediate-check`, CI job `test` |
| `tests/unit/roles/test_audit_tasks.py` | The audit scan task passes exactly the toggle result (`__linux_compliance_audit_toggles.disabled_rules`), and `toggles.yml` runs after the discover check and before the scan and fails closed | `make test-coverage` |
| `tests/playbooks/audit-toggles-oscap.yml` | The `discover` and `audit` roles, with `become` and a real `oscap`, on the pinned Ubuntu 24.04 `cis_level1_server` content with `linux_compliance_file_permissions_enabled: false`: `file_permissions_crontab` is the only `disabled` finding and names the topic toggle | `make test-oscap-integration`, CI job `oscap-integration` |
| `tests/playbooks/remediate-skip-always.yml` | With `--check --skip-tags always`, the role fails through its guard instead of silently doing nothing | `make test-remediate-check`, CI job `test` |

`make test-remediate-check` reads the ledger directory as the calling user; on a host where
`/var/lib/freesecdev/linux_compliance` already exists and is root-only it fails instead of reading it.

For FREES-52 the role was also run for real, with the opt-in, in a disposable Ubuntu 24.04 container
(`ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`, no network): apply (`0644` to `0600`,
ledger entry with prior `0644`), a second run with zero changes, cleanup by rule toggle and by family toggle (back to
`0644`, entry removed), a further run with zero changes, the rule toggle overriding a disabled family, no cleanup while
remediation is off, a stricter `0400` kept, and `4755` restricted to `0600` and restored to `4755`. It was repeated
after the review of FREES-52 with these additional cases:

- cleanup with `--skip-tags file_permissions` still ran;
- disabling the rule while `/etc/crontab` was absent kept the ledger entry and reported `cleanup_incomplete`
  (`target_absent`);
- after the file was put back, the retried cleanup restored the recorded mode;
- `--skip-tags always` failed the role;
- `linux_compliance_audit_enabled` was refused.

These runs are evidence from the pull request, not a repeatable CI test.

The tests were checked by mutation. Each of these changes to the role makes `make test-remediate-check` or the
role unit tests fail, at the assertion meant for it:

- reading the ledger without the opt-in;
- re-recording over an existing ledger entry;
- restoring without the strict mode check, and without only its length part;
- accepting an empty discovered profile;
- a family tag on the cleanup include, or on the apply include;
- replacing the completeness assertion with `true`;
- a helper without the opt-in check;
- a helper or entry file that trusts the caller's family context instead of the plan;
- forgetting the entry of an absent target;
- including a family file without `role_path`;
- disabling the `--skip-tags always` guard.

A play in `remediate-check-mode.yml` also catalogues a rule of the registered `sysctl` family, which has no task file
yet, and checks that the run stops at the dispatch.

The Molecule scenario (nothing changes without the opt-in, disruptive families skipped without the allow-list, the
reference rule applied, idempotent and cleaned up on disable, check mode changing nothing) waits for the Docker Molecule
framework of FREES-59 and is tracked as a FREES-60 follow-up. The Molecule assertions of FREES-55 (a single rule and a
whole topic switched off after being applied are cleaned up, and the following audit reports them as `disabled` with
the controlling variable) belong to the same follow-up, because the Docker Molecule framework (pull request #14) has not
been merged. Until then the toggles are proven by the unit tests and the check-mode playbook above, which do not apply
a rule for real or run a scan.

## Related decisions and issues

- [ADR 0003](adr/0003-native-module-remediation.md), [ADR 0011](adr/0011-control-toggles-and-cleanup.md)
- FREES-52 (this page), FREES-53 (first families), FREES-55 (generated toggles,
  [variable reference](remediation-variables.md)), FREES-57 (cleanup per family),
  FREES-54 (verify), FREES-59 and FREES-60 (Molecule)
