# Remediation

Scope: the `freesecdev.linux_compliance.remediate` role, its safety model, its variables, the rule catalogue and the
contract that every control family task file implements. Audience: operators, playbook authors, family authors and
reviewers. Jira: FREES-52, FREES-55 (generated toggles), FREES-53 (full catalogue and native topics), FREES-57
(cleanup per family). Decisions: [ADR 0003](adr/0003-native-module-remediation.md) (native modules only),
[ADR 0011](adr/0011-control-toggles-and-cleanup.md) (toggles, cleanup and the state ledger, with the amendments of
FREES-52, FREES-55 and FREES-53), [ADR 0021](adr/0021-native-banners-pwquality-and-profile-values.md) (profile values,
banners and password quality), [ADR 0022](adr/0022-native-sudo-drop-ins.md) (sudo, FREES-175),
[ADR 0023](adr/0023-native-ssh-server-configuration.md) (SSH server, FREES-109),
[ADR 0024](adr/0024-native-login-defs.md) (login.defs, FREES-185),
[ADR 0025](adr/0025-own-ansible-remediation-only.md) (our own Ansible only, FREES-188). How to make a further
topic native is in the
[native remediation guide](native-remediation-guide.md).

Remediation changes managed hosts. Every change is made by this project's own Ansible: a native Ansible module or a
module of this collection ([ADR 0025](adr/0025-own-ansible-remediation-only.md)). The collection never runs, reads,
generates or ships ComplianceAsCode or OpenSCAP remediation: no generated playbooks or Bash fixes, no `fix` elements of
the datastream, no `oscap --remediate` or `generate fix`, and no script that the scanner provides. The scanner content
is used only to audit and, in golden tests, as the reference that pins what our own remediation writes. Values come
from the profile's XCCDF values through our own pinned mappings in `content/catalogue.yml`. A rule without a native
remediation is scan-only: remediation reports it as `not_implemented` and no other tool remediates it. `make lint-repo`
enforces this on every tracked file. A remediated rule is not a claim of compliance: only a later audit shows whether
the rule now passes, and a host scan is never a certification.

## Status

The dispatcher, the safety model and six native families are implemented. The catalogue holds every rule that a
pinned profile selects, 1203 rules in 56 families (FREES-53), generated from the digest-verified content and listed in
the [control family reference](control-families.md). 81 rules have a native remediation: the reference rule
`xccdf_org.ssgproject.content_rule_file_permissions_crontab` (family `file_permissions`), 15 rules of `banners`, 14
of `pwquality`, 34 of `ssh`, 7 of `login_defs` and 10 of `sudo` ([native families](#native-families)); every other rule has the strategy `audit_only`: it can be
switched off per rule and per topic, the audit excludes it and reports it as `disabled`, and remediation reports it as
`not_implemented` and never changes anything for it. The native remediations land topic by topic on top of this
catalogue, following the [native remediation guide](native-remediation-guide.md). Every native topic is exercised for
real in the Docker Molecule scenarios on Ubuntu 24.04 and Rocky Linux 9 through its toggle lifecycle (see
[Testing](#testing)).

## Safety model

| Control | Default | Effect |
|---|---|---|
| `linux_compliance_remediate_enabled` | `false` | Without it the role neither reads the state ledger nor changes anything. It only reports every rule as `skip` with the reason `remediation_disabled`. It gates cleanup as well, so disabling a rule while remediation is off changes nothing until the next enabled run. |
| `linux_compliance_remediate_allow_disruptive` | `[]` | Rules of a disruptive family are applied and cleaned up only when the family or its umbrella is named here; an umbrella allows every disruptive family it groups. Otherwise they are `skip` with the reason `disruptive_not_allowed`, and a notice names them. A rule that the ledger records as applied and that would no longer be applied (toggled off or no longer in the profile) keeps its ledger entry and is reported with `pending_cleanup: true` until the family is allow-listed. |
| Profile check | the discovered profile | With the opt-in, the role requires `linux_compliance_discovered` from the `discover` role for the same profile and applies only rules that the verified profile selects. It never substitutes another profile. |
| Fail closed | always | Unknown rule or family toggles, toggles that are not booleans, allow-list entries that are neither a disruptive family nor an umbrella of one, an invalid catalogue and a ledger entry whose family contradicts the catalogue stop the role before anything changes. A ledger entry may record a former family name of its rule when `__linux_compliance_remediate_family_aliases` maps that name to the current family (FREES-165), so moving a native rule to another family keeps the entries of upgraded hosts cleanable. |
| Check mode | `--check` | Every task runs in check mode: nothing is written, not even the ledger, and the role reports what would change. |
| No silent skips | always | Every task runs with the tag `always`, so `--tags` and `--skip-tags <family>` cannot skip work. After the dispatch the role fails unless every rule planned for `apply` or `cleanup` has exactly one result (filter `remediation_unaccounted`). `--skip-tags always` fails the role through a guard task tagged `linux_compliance_remediate_guard`. |
| Family files refuse direct use | always | Every family file and helper first asserts the opt-in and checks its family and rule against the dispatcher's own plan (`__linux_compliance_remediate_plan`), so `include_role` with `tasks_from` cannot change the host without the opt-in and a matching plan. |

The opt-in must be a JSON boolean on the command line: `-e '{"linux_compliance_remediate_enabled": true}'`.
`-e linux_compliance_remediate_enabled=true` passes a string and fails the input validation.

## Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_remediate_enabled` | `bool` | `false` | Global opt-in. |
| `linux_compliance_remediate_allow_disruptive` | `list` of `str` | `[]` | Disruptive families that may be applied and cleaned up. The argument specification accepts only the disruptive families of the registry and the umbrellas that group one, such as `services`. |
| `linux_compliance_remediate_profile` | `str` | `cis_level1_server` | Profile short identifier; must equal the profile the `discover` role verified. |
| `linux_compliance_remediate_banner_text` | `str` | the default of the XCCDF value `cis_banner_text`: `Authorized users only. All activity may be monitored and reported.` | Text of `/etc/issue`, `/etc/issue.net` and `/etc/motd` for the banner text rules; validated against the profile before anything changes ([banners](#banners)). |
| `linux_compliance_<family>_enabled` | `bool` | `true` | Topic toggle of a registered family, for example `linux_compliance_auditd_enabled: false` turns off every auditd rule. |
| `linux_compliance_<umbrella>_enabled` | `bool` | `true` | Umbrella toggle of the families an umbrella groups, for example `linux_compliance_services_enabled: false` turns off `sssd`, `time_sync`, `mail` and every other service family; a family toggle only narrows it. `pam` is both a family and the umbrella of `pwquality`, `pwhistory` and `faillock`, so `allow_disruptive: [pam]` allows all four; there is no entry for the `pam` family alone. |
| `linux_compliance_rule_<rule_short_id>_enabled` | `bool` | not set: follows `linux_compliance_<family>_enabled` | Toggle of one catalogued rule, for example `linux_compliance_rule_file_permissions_crontab_enabled`. Not declared as a role default (ADR 0011, amendment of FREES-53). |

The topic and rule toggles are flat booleans, so any inventory layer can set one of them. The topic toggle defaults
and argument specifications are generated from the catalogue; every topic and rule toggle is listed in the
[remediation variable reference](remediation-variables.md).

### Generated toggles

`tools/roles/generate_toggles.py` (`make toggles`) derives from `roles/remediate/vars/rules.yml`:

- in `defaults/main.yml` of the `remediate` and the `audit` role, `linux_compliance_<family>_enabled: true` for every
  registered family and every umbrella, in registry order;
- in the `main` entry point of `meta/argument_specs.yml` of both roles, an option of type `bool` with `default: true`
  and a short description for each topic and umbrella toggle, and the `choices` of
  `linux_compliance_remediate_allow_disruptive` (the disruptive families of the registry and the umbrellas that group
  one);
- the reference page [remediation-variables.md](remediation-variables.md), with every topic toggle and every rule
  toggle, per family.

Rule toggles are not declared in either role (ADR 0011, amendment of FREES-53). With more than a thousand catalogued
rules, declaring each as a default and an argument specification option made every role run several seconds slower
per host; the measurements are in the ADR. A rule toggle that is not set follows its family toggle in the shared
resolution code, exactly as a declared default would, and a rule toggle that is set is validated by the role before
anything changes. Because rule toggles are not argument specification options, set them as inventory, play, task or
`include_role` `vars`, or with `-e`, never as role parameters: the role argument validation rejects an undeclared
role parameter. Topic toggles are declared and also work as role parameters.

Every other variable and option of those files is kept, in its order, and toggles that the catalogue no longer
contains are removed. Both YAML files are written in one canonical style that is checked to load back to the same data.
`make lint-toggles` (part of `make lint`, CI job `lint`) regenerates all five files in memory and fails with a diff when
any of them differs from the files in the repository, so no family can be registered without its toggle and no toggle
can outlive its family. `tools/roles/check_role_specs.py` (`make lint-ansible`) checks the toggles on its own as well:
in the `remediate` and `audit` roles, the set of topic toggle names, every default (value and type) and every argument
specification must equal what the generator produces for the catalogue, so an uncatalogued toggle, a near-namespace
name such as `linux_compliance_remediatex_enabled` or a declared rule toggle is a finding. Toggles in any other role
fail its role-prefix rule.

The catalogue itself is generated by `make catalogue` from the pinned content (see [Rule catalogue](#rule-catalogue)),
which then runs `make toggles`.

When a topic or umbrella toggle is `false` but no catalogued rule of the families it governs is in the profile (in the
catalogue, when remediation is disabled), the notices of the role contain a `WARNING:` that the toggle changes nothing; the audit role prints the
same warning ([variable reference](remediation-variables.md#what-the-catalogue-covers)). With the full catalogue this
happens only for a family that has no rule in the profile at all, such as `auditd` with the Ubuntu 24.04
`cis_level1_server` profile.

A rule toggle copied into the inventory as `"{{ linux_compliance_<family>_enabled }}"` is resolved by Ansible to the
boolean of the family toggle before the filter checks it: a family toggle passed as the string `"false"` makes both the
family toggle and every rule toggle that follows it in this way fail the role as non-boolean.

### Effective state of a rule

For every catalogued rule the filter `freesecdev.linux_compliance.remediation_plan` resolves:

1. The **toggle state**: the rule toggle when it is set; otherwise on only when the umbrella toggle of the family (if
   the family belongs to an umbrella), the family toggle, and the toggle of every subsystem tag of the rule and of the
   tag's umbrella are all on, a toggle that is not set counting as on. A family toggle therefore only narrows its
   umbrella: `linux_compliance_services_enabled: false` switches `sssd` off even with
   `linux_compliance_sssd_enabled: true`. A subsystem tag (FREES-165) only adds a way to switch a rule off:
   `linux_compliance_sssd_enabled: false` also switches off the permissions of `/var/log/sssd`, which belong to
   `file_permissions` and are tagged `sssd`, and a tag toggle that is `true` never switches a rule on
   ([control family reference](control-families.md#subsystem-tags)). The variable that switched a rule off is reported
   as `disabled_by`: the first toggle that is off in the order umbrella of the family, family, then each tag in
   alphabetical order after its umbrella, and the rule toggle otherwise. Because a rule toggle copied from its family
   default cannot be told apart from one set to `false`, both name the family toggle. A rule toggle set to `true` wins
   over every disabled family, umbrella or tag toggle
   ([variable reference](remediation-variables.md#umbrellas)). The disruptive allow-list stays a property of the
   family: a tag never puts a rule behind the allow-list or takes it out. The resolution lives in
   `plugins/module_utils/compliance/toggles.py`, which the audit role uses as well, so a rule that is switched off is
   reported as `disabled` by the audit with the same controlling variable
   ([disabled rules in the audit](audit.md#disabled-rules-adr-0011)).
2. The **action**, in this order:

| Condition | Action | Reason |
|---|---|---|
| `linux_compliance_remediate_enabled` is false | `skip` | `remediation_disabled` |
| The rule has no native remediation (`audit_only`), toggle on and the profile selects it | `not_implemented` | `audit_only`; one result with the status `not_implemented` and no change |
| The rule is `audit_only` and the ledger records it (written by an older collection version) | `manual` | `audit_only`; a notice asks for a manual review, nothing is changed |
| The rule is `audit_only` otherwise | `none` | `disabled_by_toggle` or `not_in_profile` |
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

The family registry is in `roles/remediate/vars/rules.yml`, generated from `content/catalogue.yml`. Its order is the
dispatch order: non-disruptive families first, so that a failure in a disruptive family leaves the harmless changes
applied, then the families in order of growing lock-out risk, with the bootloader last because it takes effect only on
the next boot. The [control family reference](control-families.md) lists all 21 families with the reason for each
disruptive flag and their rules per profile.

| Disruptive | Families |
|---|---|
| no | `file_permissions`, `sysctl`, `logging`, `banners`, `integrity`, `kernel_build_config` |
| yes | `auditd`, `services`, `packages`, `desktop`, `network`, `kernel_modules`, `firewall`, `ssh`, `pam`, `accounts`, `sudo`, `mandatory_access_control`, `crypto_policy`, `mounts`, `bootloader` |

Cleanup of a disruptive family is gated exactly like applying it, because reverting SSH, PAM or firewall settings can
also lock operators out. Every rule of a disruptive family is disruptive; the catalogue rejects a rule whose flag
differs from its family. The disruptive families are also pinned in the filter (`DISRUPTIVE_FAMILIES`), so a registry
passed in through `-e`, `set_fact` or role parameters that marks one of them non-disruptive fails the role instead of
bypassing the allow-list. `accounts`, `kernel_modules`, `mandatory_access_control`, `packages` and `desktop` joined the
pinned set with FREES-53 (reasons in [ADR 0011](adr/0011-control-toggles-and-cleanup.md)).

## Rule catalogue

`roles/remediate/vars/rules.yml` is generated by `make catalogue` (`tools/roles/generate_catalogue.py`) from the
digest-verified datastreams of `content/manifest.yml` and the family mapping `content/catalogue.yml`; do not edit it by
hand. The CI job `test-suites` regenerates it from the pinned content (`make test-content-golden`) and fails on any
difference. It holds five keys:

- `__linux_compliance_remediate_families`: the registry above, each family with `name` and `disruptive`;
- `__linux_compliance_remediate_rules`: the rules with a native remediation, from `native_rules` of
  `content/catalogue.yml`, each with exactly the keys below;
- `__linux_compliance_remediate_audit_only`: every family, in registry order, mapped to the sorted full identifiers of
  its rules without a native remediation. The filters expand each into an entry of the same shape with the strategy
  `audit_only`;
- `__linux_compliance_remediate_tags`: every subsystem tag that tags a rule, a family name, mapped to the sorted full
  identifiers of the rules of other families that it tags, derived from `subsystem_tags` of `content/catalogue.yml`
  (FREES-165, [control family reference](control-families.md#subsystem-tags));
- `__linux_compliance_remediate_family_aliases`: former family names that the state ledger may record, mapped to the
  families their rules belong to now, from `ledger_family_aliases` of `content/catalogue.yml`. It is empty: no native
  rule has moved. When one moves, add its former family here so that upgraded hosts keep their cleanup.

| Key | Contract |
|---|---|
| `rule_id` | Full ComplianceAsCode XCCDF rule identifier, unique across both lists |
| `family` | A registered family; for a native rule it names the task file `roles/remediate/tasks/<family>.yml` |
| `disruptive` | Equals the flag of the family |
| `reversible` | `false` exactly for the `irreversible` strategy; `true` for `audit_only`, which never applies anything |
| `revert_strategy` | `owned_dropin`, `recorded_value`, `recorded_state` or `irreversible` (ADR 0011), or `audit_only` for an expanded rule without a native remediation |
| `toggle` | `linux_compliance_rule_<rule_short_id>_enabled`, with the short identifier in lower case and every other character than a letter, digit or `_` replaced by `_` |
| `runbook` | A `docs/` path or `https://` link for an irreversible rule, `null` for every other rule |
| `parameters` | A mapping that only the family task file interprets; empty for `audit_only` |

The catalogue covers all 25 pinned profiles; how each rule gets its family is described in the
[control family reference](control-families.md#how-a-rule-gets-its-family). The role does not trust the catalogue for
profile membership: it applies a rule only when `linux_compliance_discovered.rule_ids` contains it. To give a rule a
native remediation, add it to `native_rules` of `content/catalogue.yml` with its strategy and parameters, write the
family file, and run `make catalogue`.

## Dispatch

`tasks/main.yml` only dispatches; every task in it is tagged `always`, except the three guard tasks tagged only
`linux_compliance_remediate_guard`.

0. Refuse internal variables supplied from outside the role: `tasks/internal_variables.yml`, generated by
   `make role-guards`, first refuses every internal name passed as a role, include, block or play parameter by its
   name, whatever its value, so a templated plan cannot imitate the sentinels (FREES-157), then resets every internal
   fact to a sentinel and asserts that every internal fact, task variable
   and constant reads back as set by the role, then repeats the reset and the read-back with a second sentinel, so a
   value forged as the sentinel string fails too (FREES-153). A role parameter, an include parameter or an extra
   variable named `__linux_compliance_remediate_*`, or a catalogue set by the play, stops the role before anything
   is read or changed. The toggle names, the plan, the results and the dispatched flag are also type-checked in the
   task right after the role sets them.
1. Arm the guard (guard tag): set `__linux_compliance_remediate_dispatched` to `false` and check that it is.
2. Validate the inputs (the argument specification runs first).
3. Load the catalogue and the registry with `ansible.builtin.include_vars`.
4. Find the toggle variables.
5. With the opt-in only: check `linux_compliance_discovered` (same profile, at least one rule) and read the ledger with
   `control_state` `list`.
6. Resolve the plan with `remediation_plan` and stop on any error.
7. Start the results with one `not_implemented` result per `audit_only` rule that would be applied. Include
   `tasks/dispatch.yml`, which holds one static include of the literal `{{ role_path }}/tasks/<family>.yml` for every
   family that has at least one rule with a native remediation, in registry order, each run only for the plan entry
   of its family and with the tag `always` applied to it. No variable chooses the file. A family whose rules are all
   `audit_only` gets no include, because the plan never gives it work. The dispatch is generated from the catalogue by
   `make role-guards` (with `generate_toggles.native_families`), which fails for a dispatched family without a task
   file; planned work of a family without a dispatch entry fails step 9.
8. Publish the fact `linux_compliance_remediated` and print the notices (skipped disruptive rules, manual actions,
   the number of `not_implemented` rules, orphaned ledger entries, incomplete cleanups).
9. Fail unless every rule planned for `apply`, `cleanup` or `not_implemented` has exactly one result, and no other
   result exists (`remediation_unaccounted`).
10. Mark the dispatch as complete; the final guard task (guard tag) fails the role when it was not.

Toggles, not tags, select rules. Every task of the role and of its family files is tagged `always` and nothing else,
so `--tags` and `--skip-tags <family>` change nothing, and a task skipped any other way fails step 9.
`--skip-tags always` skips every always-tagged task; the three guard tasks still run, and the role fails with a message
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

`file_permissions_crontab` restricts `/etc/crontab` to at most `0600`, the most that its OVAL check accepts (no
set-ID, sticky or owner-execute bit and no group or other bit): the filter `freesecdev.linux_compliance.restricted_mode` computes `current & 0600`, so a
stricter mode such as `0400` is kept and only the excess bits are removed. Its strategy is `recorded_value`.

| Step | Module | Behaviour |
|---|---|---|
| Inspect | `ansible.builtin.stat` with `follow: false` | A missing file is `notapplicable`; a symbolic link or other non-regular file is `not_regular_file`; neither is changed |
| Record | `freesecdev.linux_compliance.control_state` `record` | Prior mode (for example `0644`), only when the mode must change and no entry exists |
| Apply | `ansible.builtin.file` with `follow: false` | Sets the restricted mode; status `applied`, or `compliant` when nothing had to change |
| Clean up | `ansible.builtin.file`, then `control_state` `remove` | Restores the recorded mode, which must be exactly four octal digits, and then removes the entry (`restored`). Otherwise nothing is changed, the entry is kept and the result is `cleanup_incomplete` with the reason `target_absent` (the file is missing), `not_regular_file` (a symbolic link or other non-regular file) or `invalid_record` (no usable recorded mode). The cleanup is retried on every run until it succeeds; a file that is removed for good leaves its entry behind until an operator removes it with `control_state` `remove` |

## Native families

Besides the reference family, these topics are native
([ADR 0021](adr/0021-native-banners-pwquality-and-profile-values.md), [ADR 0022](adr/0022-native-sudo-drop-ins.md),
[ADR 0023](adr/0023-native-ssh-server-configuration.md), [ADR 0024](adr/0024-native-login-defs.md),
[ADR 0027](adr/0027-native-faillock-pwhistory.md)).
Their rules use the profile's own values, which `make catalogue` reads from the pinned datastreams into the rule
parameters (`value_id`, `profile_values`); a rule whose content and profile the catalogue holds no value for fails the
family before anything changes. A rule whose check exports its value names it with `profile_value` in
`content/catalogue.yml`. A rule whose check accepts a range and exports nothing pins the full XCCDF `Value` identifier
with `profile_value_id`. The value is still the profile's own `refine-value` or the `Value`'s default, and a golden
test pins it per profile (`sudo_require_reauthentication`: 15 for CIS, 0 for the STIG, 5 for CCN and PCI DSS). The
content's `fix` elements are never read ([ADR 0025](adr/0025-own-ansible-remediation-only.md)).

### Banners

| Rules | What is applied | Strategy and cleanup |
|---|---|---|
| `banner_etc_issue_cis`, `banner_etc_issue_net_cis`, `banner_etc_motd_cis` (CIS profiles) and `banner_etc_issue`, `banner_etc_issue_net`, `banner_etc_motd` (STIG and CCN profiles) | `/etc/issue`, `/etc/issue.net` or `/etc/motd` gets exactly `linux_compliance_remediate_banner_text` and a newline; a missing file is created with mode `0644`, owner and group root | `recorded_value` of `content_base64` (the prior content, or `null` when the file did not exist); cleanup writes the prior content back, keeping the current mode and owner, or removes a file that did not exist |
| `file_permissions_etc_issue`, `_issue_net`, `_motd` | Mode at most `0644`; a stricter mode is kept | `recorded_value` of `mode` |
| `file_owner_etc_issue`, `_issue_net`, `_motd` | Owner uid 0 | `recorded_value` of `owner` (the uid) |
| `file_groupowner_etc_issue`, `_issue_net`, `_motd` | Group gid 0 | `recorded_value` of `group` (the gid) |

Before anything changes, the banner text must be non-empty, at most 4096 characters, without a backslash (the getty
escapes `\s`, `\r`, `\m`, `\v` that the CIS checks forbid) or control characters other than newline and tab, without
the operating system names of the CIS checks, and must match the profile's value of the rule, read as one string as
the OVAL check does. The STIG profiles require the DoD notice, so with them the text must be set; the default fails
closed with a message that names the XCCDF value. A symbolic link or non-regular file is never changed
(`not_regular_file`), a file over 3072 bytes is not rewritten (`prior_too_large`, the record would not fit the
ledger), and a missing file is `notapplicable` for the mode, owner and group rules unless the text rule of the same run
creates it, which check mode predicts. Kept `audit_only`: `banner_etc_profiled_ssh_confirm` (an SSH login script that
asks for confirmation) and `dconf_gnome_banner_enabled`, `dconf_gnome_login_banner_text` (GDM, which needs a desktop and
`dconf update`).

### Password quality

`pwquality` is disruptive (umbrella `pam`), so it is applied and cleaned up only with `pwquality` or `pam` in
`linux_compliance_remediate_allow_disruptive`.

Each rule writes where the pinned content of the platform checks the setting
([ADR 0021](adr/0021-native-banners-pwquality-and-profile-values.md)): the Ubuntu 24.04 checks read only
`/etc/security/pwquality.conf`, the RHEL 9 checks also every `/etc/security/pwquality.conf.d/*.conf`. The parameter
`main_file_benchmarks` of each rule names the benchmarks of the first kind, and the family picks the method from the
benchmark that the `discover` role verified.

| Rules | Method | What is applied | Record and cleanup |
|---|---|---|---|
| `accounts_password_pam_dcredit`, `_dictcheck`, `_difok`, `_enforcing`, `_lcredit`, `_maxclassrepeat`, `_maxrepeat`, `_maxsequence`, `_minclass`, `_minlen`, `_ocredit`, `_ucredit`, `_pwquality_retry`, `_enforce_root` | main file (Ubuntu 24.04) | One line per setting in `/etc/security/pwquality.conf` with the profile's value (`enforce_for_root` without value), written with `lineinfile`: the one active line of the setting is replaced, or the line is appended | `recorded_value` of `method` (`main_file`), `setting_line` (the prior active line, or `null` when absent), `written_line` and the file's `mode`, `owner`, `group` and `sha256`; cleanup checks that the setting is still the line written and that the mode and ownership are unchanged, then writes the line back or removes the setting, so the file is byte for byte the original once every rule is cleaned up |
| the same rules | drop-ins (RHEL 9) | `/etc/security/pwquality.conf.d/50-freesecdev-<setting>.conf` with a header that names the rule; the main file is not touched | `recorded_value` of `method` (`dropin`), `dropin` (`null`: it did not exist) and `dropin_sha256`; cleanup removes the drop-in when it carries the header and still has that SHA-256 |

Every ledger entry records its `method` and what was written (`written_line`, or `dropin_sha256` for a drop-in). The
statuses that refuse to act, with nothing changed and the entry kept:

| Status (apply) or reason (cleanup) | When |
|---|---|
| `method_changed` | The entry was recorded by the other method, for example after a content update moved the check; apply writes nothing, cleanup is `cleanup_incomplete` |
| `modified_since_apply` (cleanup) | The setting is no longer exactly the line the collection wrote, the main file's mode or ownership changed, or the drop-in's content no longer has the recorded SHA-256; an administrator's later change is never overwritten |
| `not_directory` | `pwquality.conf.d` exists but is not a directory, for example a symbolic link; nothing is written through it |
| `not_regular_file` | The main file or a drop-in is a symbolic link or another non-regular file |
| `not_owned` | A file at the drop-in's path does not carry the collection's header, with or without a ledger entry |

When the profile value changes while a rule stays on, apply writes the new value and replaces the entry with the same
prior state and the new `written_line` or `dropin_sha256`.

With the main file, a setting that is active on more than one line is `duplicate_setting` and not touched. With
drop-ins, libpwquality reads them in lexical order and the main file last, so a rule is `overridden`, with nothing
changed and the overriding file named, when the main file or a later drop-in sets the same setting; a file at the
drop-in's path without the header is `not_owned` and never touched; and where the directory does not exist, the
first drop-in creates it with mode `0755` and an empty marker `.freesecdev-created`, removed with the directory once
nothing else is in it. Without `/etc/security/pwquality.conf` libpwquality is not installed and every rule is
`notapplicable`, as in the content. Kept `audit_only`: the rules that put `pam_pwquality.so` into the PAM stack
(`accounts_password_pam_pwquality_enabled`, `_password_auth`, `_system_auth`, topic `pam`),
`accounts_password_pam_retry` (its check reads the PAM arguments first and never the drop-ins) and
`package_pam_pwquality_installed` (package state, and on Ubuntu the package changes the PAM stack). That the Ubuntu
checks ignore the drop-in directory, which libpwquality reads, is an upstream gap recorded in ADR 0021.

### SSH server

`ssh` is disruptive, so it is applied and cleaned up only with `ssh` in `linux_compliance_remediate_allow_disruptive`
([ADR 0023](adr/0023-native-ssh-server-configuration.md)). Both pinned contents check `/etc/ssh/sshd_config` and every
`/etc/ssh/sshd_config.d/*.conf` and require every occurrence of the keyword to comply, and sshd uses the first value it
reads, with the drop-ins read before the rest of the main file; `tests/unit/tools/test_content_golden_ssh.py` checks
this against the OVAL of both datastreams.

| Rules | What is applied | Record and cleanup |
|---|---|---|
| `disable_host_auth`, `sshd_disable_compression`, `_empty_passwords`, `_forwarding`, `_gssapi_auth`, `_kerb_auth`, `_rhosts`, `_root_login`, `_root_password_login`, `_tcp_forwarding`, `_user_known_hosts`, `_x11_forwarding`, `sshd_do_not_permit_user_env`, `sshd_enable_pam`, `_pubkey_auth`, `_strictmodes`, `_warning_banner`, `_warning_banner_net`, `sshd_print_last_log`, `sshd_set_loglevel_info`, `_loglevel_verbose`, `sshd_x11_use_localhost`, `sshd_use_strong_ciphers` and the ordered STIG `Ciphers`, `KexAlgorithms` and `MACs` rules | `/etc/ssh/sshd_config.d/00-freesecdev-<rule>.conf`, mode `0600`, owner and group root, with a header that names the rule and the one line `<Keyword> <value>` that the check requires | `recorded_value` of `method` (`dropin`), `dropin` (`null`: it did not exist), `dropin_sha256` and `written_line`, and for each vendor line changed (below) `vendor_line:<path>`, `vendor_written:<path>` and `vendor_number:<path>`; cleanup removes the drop-in when it carries the header and still has that SHA-256, and writes each original vendor line back |
| `sshd_set_idle_timeout`, `_keepalive`, `_login_grace_time`, `_max_auth_tries`, `_max_sessions`, `_maxstartups`, `sshd_use_strong_kex`, `_macs` | The same, with the profile's value (`sshd_idle_timeout_value`, `var_sshd_set_keepalive`, `var_sshd_set_login_grace_time`, `sshd_max_auth_tries_value`, `var_sshd_max_sessions`, `var_sshd_set_maxstartups`, `sshd_strong_kex`, `sshd_strong_macs`) | As above |

Before anything is written, the module `freesecdev.linux_compliance.sshd_validate` runs
`sshd -t -f /etc/ssh/sshd_config` with every setting to write as `-o <Keyword>=<value>`. sshd reads command-line
options first and keeps the first value, so this tests the whole effective configuration as it will be; when sshd
refuses it, every rule to write is `invalid_config` with sshd's message and nothing is installed. After a change, a
second `sshd -t` checks the whole configuration; when it refuses, the run rolls back the drop-ins, vendor lines and
ledger entries that it created and fails (what a cleanup removed or wrote back stays, because that is the prior state).
When sshd is not installed, the second check and the reload are skipped, so a cleanup on such a host succeeds.
Otherwise sshd is reloaded once, only when `service_facts` reports
`ssh.service` or `sshd.service` running; a reload keeps open sessions. Where no service manager runs, as in the Molecule
containers, nothing is reloaded, and check mode never reloads. A run that applies `PermitRootLogin no` or
`prohibit-password` while it reaches the host over SSH as root prints a warning.

The content's check reads every occurrence of the keyword, so a later line with another value would still fail it,
although sshd uses the drop-in's value. A later line with the same value is left alone. A conflicting later line in a
vendor file (`/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/50-redhat.conf`; for example Ubuntu's `X11Forwarding yes`
and RHEL's `X11Forwarding yes` and `GSSAPIAuthentication yes`) is set to the rule's value in place with `lineinfile`,
outside any `Match` block and only where the file sets the keyword once; the original line is recorded first and
written back on cleanup while the file still has the line written. Every other conflicting later line, in an
administrator's drop-in or inside a `Match` block, makes the rule `overridden`: nothing is written, because the rule
could not pass.

The statuses that refuse to act, with nothing changed and the ledger entry kept, each with a reason:

| Status (apply) or reason (cleanup) | When |
|---|---|
| `overridden` (apply) | `sshd_config` sets the keyword or includes another file before its drop-in `Include`, or a drop-in that sorts earlier sets it, includes other files or cannot be read, or a later line that the collection does not change sets another value |
| `duplicate_setting` (apply) | A vendor file sets the keyword more than once |
| `prior_too_large` (apply) | The conflicting vendor line is longer than 1024 characters |
| `not_included` (apply) | `sshd_config` does not include `/etc/ssh/sshd_config.d/*.conf` before its first `Match` block |
| `crypto_policy` (apply) | `Ciphers`, `MACs` or `KexAlgorithms` on RHEL 9, where the crypto policy governs them |
| `invalid_config` (apply) | `sshd -t` refuses the configuration with the settings to write |
| `method_changed` | The ledger entry was recorded by another method |
| `not_directory` | `sshd_config.d` exists but is not a directory, for example a symbolic link |
| `not_regular_file` | The drop-in path, or `sshd_config` itself, is a symbolic link or another non-regular file |
| `not_owned` | A file at the drop-in path does not carry the collection's header |
| `invalid_record` (cleanup) | The recorded SHA-256 is missing or malformed, or a recorded vendor line is not a line of the keyword |
| `target_absent` (cleanup) | A vendor file whose line the collection changed no longer exists |
| `modified_since_apply` (cleanup) | The drop-in's content is no longer what the collection wrote, or a vendor file no longer sets the keyword on exactly the line written; an administrator's change is never overwritten |

A drop-in that no longer exists at cleanup is the recorded prior state: the rule is `restored`, its entry dropped and
nothing written (FREES-173); so is a vendor line that already equals its recorded original, compared without case
and with runs of spaces or `=` read as one separator. Where `sshd_config.d` does not exist, the first drop-in creates it with mode `0700` and the
marker `.freesecdev-created`, removed with the directory once nothing else is in it. The sshd `Banner` keyword is native; the banner files belong to `banners`. Kept `audit_only`, with
the reasons in ADR 0023: the modes and ownership of the configuration, the drop-ins and the host keys,
`sshd_limit_user_access` (site-specific user lists), `sshd_rekey_limit` (its check refuses every drop-in and it needs
two values), `sshd_use_directory_configuration`, `sshd_include_crypto_policy`, `sshd_allow_only_protocol2` (OpenSSH 7.0
or older only), `file_sshd_50_redhat_exists`, the package, service and firewall rules, the client rules and
`ssh_keys_passphrase_protected`.

### Sudo

`sudo` is disruptive, so it is applied and cleaned up only with `sudo` in `linux_compliance_remediate_allow_disruptive`.
The checks of both pinned datastreams read `/etc/sudoers` and every file of `/etc/sudoers.d`, so every setting rule
writes one drop-in on both platforms ([ADR 0022](adr/0022-native-sudo-drop-ins.md),
`tests/unit/tools/test_content_golden_native.py` checks it against the OVAL of both datastreams).

| Rules | What is applied | Record and cleanup |
|---|---|---|
| `sudo_add_use_pty`, `sudo_custom_logfile`, `sudo_require_reauthentication`, `sudoers_validate_passwd` | `/etc/sudoers.d/50-freesecdev-<setting>` with a header that names the rule and `Defaults use_pty`, `Defaults logfile=<var_sudo_logfile>`, `Defaults timestamp_timeout=<var_sudo_timestamp_timeout>` (pinned with `profile_value_id`) or the three `Defaults !targetpw`, `!rootpw`, `!runaspw` lines; mode `0440`, owner and group root, written with `copy` and `validate: /usr/sbin/visudo -cf %s`. `/etc/sudoers` and other drop-ins are never written | `recorded_value` of `method` (`dropin`), `dropin` (`null`: it did not exist) and `dropin_sha256`; cleanup removes the drop-in when it carries the header and still has that SHA-256 |
| `file_permissions_etc_sudoers`, `file_owner_etc_sudoers`, `file_groupowner_etc_sudoers` | `/etc/sudoers` at most `0440` (a stricter mode is kept), uid 0, gid 0 | `recorded_value` of `method` (`attribute`), the prior `mode`, `owner` or `group` and `written`; cleanup restores the prior attribute when the current one is still `written` |
| `directory_permissions_etc_sudoersd`, `directory_owner_etc_sudoersd`, `directory_groupowner_etc_sudoersd` | `/etc/sudoers.d` at most `0750`, uid 0, gid 0 | as above |

The statuses that refuse to act, each with a reason, nothing changed and the ledger entry kept:

| Status (apply) or reason (cleanup) | When |
|---|---|
| `notapplicable` (apply) | `/etc/sudoers` does not exist (sudo is not installed), or the path of an attribute rule does not exist |
| `not_regular_file`, `not_directory` | `/etc/sudoers`, the drop-in or the path of an attribute rule is a symbolic link or of the wrong type, or `/etc/sudoers.d` is missing or not a directory; nothing is written through a link |
| `not_included` (apply) | `/etc/sudoers` has no `@includedir` or `#includedir` line for `/etc/sudoers.d`, so sudo would not read the drop-in |
| `validator_missing` (apply) | `/usr/sbin/visudo` is not a regular file |
| `invalid_sudoers` (apply) | `visudo` refused the drop-in; nothing is installed and the entry recorded for it is removed |
| `conflicting_setting` (apply) | Another file of `/etc/sudoers` or `/etc/sudoers.d` sets one of the rule's options in another form, or `timestamp_timeout` more than once; the collection does not edit files it does not own |
| `not_owned` | A file at the drop-in's path does not carry the collection's header |
| `method_changed` | The ledger entry records another method, or none |
| `modified_since_apply` (cleanup) | The drop-in's content or the attribute is no longer what the collection wrote; an administrator's later change is never overwritten |
| `invalid_record`, `target_absent` (cleanup) | The record is malformed, or the path of an attribute rule is gone |

The family reads every file that the content's checks read, including names that sudo skips (a `.` or a trailing
`~`) and symbolic links to regular files, which sudo follows, and joins lines continued with `\`. Conflicts are
decided over all of them; `compliant` without a drop-in only over the files that sudo reads. A rule whose setting
those files already hold exactly (the `Defaults use_pty` of the Ubuntu 24.04 `/etc/sudoers`) is `compliant` and
writes nothing; a setting only in `hardening.conf` or `site~` never is. When the state already equals the recorded prior state at cleanup (the drop-in was
removed by hand, the attribute already has its prior value), the rule is `restored`, its entry is removed and nothing
is written (FREES-173). Kept `audit_only`, with the reasons in ADR 0022: the rules that remove other people's
`!authenticate`, `NOPASSWD` or user specifications (`sudo_remove_no_authenticate`, `sudo_remove_nopasswd`,
`sudo_require_authentication`, `sudo_restrict_privilege_elevation_to_authorized`, `sudoers_explicit_command_args`,
`sudoers_no_command_negation`, `sudoers_no_root_target`), `sudo_add_noexec` and `sudo_add_requiretty` (they break
`become` and so the run that would revert them), `sudo_dedicated_group` and `file_permissions_sudo` (they limit who may
run `/usr/bin/sudo`) and `package_sudo_installed` (package state).

### Account defaults in login.defs

`login_defs` is disruptive (umbrella `accounts`), so it is applied and cleaned up only with `login_defs` or `accounts`
in `linux_compliance_remediate_allow_disruptive`. Every check of the pinned content reads the setting from
`/etc/login.defs` alone on both platforms, so the family edits one line per setting there
([ADR 0024](adr/0024-native-login-defs.md); `tests/unit/tools/test_content_golden_login_defs.py` pins each check's
pattern, comparison and value against the OVAL of both datastreams). The tags `password_aging`, `umask` and
`user_sessions` keep the toggles of the families that held these rules before, and the tag `login_defs` lets the topic
toggle also switch off `set_password_hashing_algorithm_logindefs`, which stays in `pam`.

| Rules | What is applied | Record and cleanup |
|---|---|---|
| `accounts_maximum_age_login_defs` (`PASS_MAX_DAYS`, at most the value), `accounts_minimum_age_login_defs` (`PASS_MIN_DAYS`), `accounts_password_warn_age_login_defs` (`PASS_WARN_AGE`), `accounts_password_minlen_login_defs` (`PASS_MIN_LEN`), `accounts_logon_fail_delay` (`FAIL_DELAY`, each at least the value) | `<NAME> <value>` with the profile's value, written with `lineinfile` in place of the one line of the setting (found in any case), or appended when the setting is absent; a stricter value in the strict form is kept | `recorded_value` of `method` (`line`), `setting_line` (the prior line, or `null`), `written_line` and the file's `mode`, `owner`, `group` and `sha256`; cleanup writes the prior line back in its place, or removes the line when the setting was absent |
| `accounts_umask_etc_login_defs` (`UMASK`) | Three octal digits with every bit that the profile requires; the bits of the current value are kept (`UMASK 0077` becomes `077` under 027) | as above |
| `accounts_have_homedir_login_defs` (`CREATE_HOME`) | `CREATE_HOME yes` | as above |

The statuses that refuse to act, each with a reason, nothing changed and the ledger entry kept:

| Status (apply) or reason (cleanup) | When |
|---|---|
| `notapplicable` (apply) | `/etc/login.defs` does not exist (shadow-utils is not installed) |
| `not_regular_file` | `/etc/login.defs` is a symbolic link or not a regular file; nothing is written through a link |
| `overridden`, `not_directory` (apply) | Only `CREATE_HOME`, whose check also reads `/etc/login.defs.d`: a drop-in there sets the name, or the directory is a symbolic link or not a directory. The other rules ignore the directory, as their checks and the pinned shadow-utils do |
| `duplicate_setting` (apply) | The name is set on more than one line, in any case (`pam_umask` reads the first, shadow-utils the last) |
| `unreadable_value` (apply) | The value is in a form that shadow-utils or `pam_umask` may read but the family cannot compare (quoted, signed, longer, another base, such as `"30"`, `+30`, `00077` or `0x3f`, or a number line with a carriage return, vertical tab or form feed), so a written value could be looser; the reason names the line |
| `method_changed` | The ledger entry records another method, or none |
| `modified_since_apply` (cleanup) | The setting is not exactly the line the collection wrote any more (changed or removed by hand), or the file's mode or ownership changed; an administrator's later change is never overwritten |
| `invalid_record`, `target_absent` (cleanup) | The record is malformed, or `/etc/login.defs` is gone |

A line counts as compliant only in the form that both shadow-utils and the check read: the name in upper case, one
decimal value without a leading zero and no trailing comment (shadow-utils parses with base 0, so it does not read
`PASS_MAX_DAYS 30 # site` or `090` and reads `010` as 8). Any other line is rewritten, never looser than any
reading of its first word (`PASS_MAX_DAYS 30 # site` becomes `PASS_MAX_DAYS 30`, `UMASK 077 # site` becomes `UMASK 077`). Commented lines are
never touched. When the file already holds the recorded prior state at cleanup (an added line removed again by hand),
the rule is `restored`, its entry is removed and nothing is written (FREES-173). Kept `audit_only`, with the reasons in
ADR 0024: `set_password_hashing_algorithm_logindefs` (`pam`: its CIS value accepts two algorithms and must agree with
the `pam_unix` hashing of the PAM stack), `no_shelllogin_for_systemaccounts` (it changes shells in `/etc/passwd`) and
the rules of `password_aging` that change existing accounts in `/etc/shadow` (password hashes that cannot be recorded,
no exact revert, and immediate expiry of existing passwords).

### Account lock-out and password reuse

`faillock` and `pwhistory` are disruptive (umbrella `pam`), so they are applied and cleaned up only with `faillock`,
`pwhistory` or `pam` in `linux_compliance_remediate_allow_disruptive`
([ADR 0027](adr/0027-native-faillock-pwhistory.md)). Each rule writes one line into the file that the PAM module reads
and that the content's check reads on that platform; `tests/unit/tools/test_content_golden_pam_conf.py` checks this
against the OVAL of both datastreams. The PAM stack is only read, never edited. The filter
`freesecdev.linux_compliance.pam_conf_decision` decides each rule the way `pam_faillock`, `pam_pwhistory` and libpam
read the file and every file of `/etc/pam.d`, and `tests/unit/plugins/filter/test_pam_conf_oracle.py` checks it against
what the real readers of both images read (`make pam-reader-verdicts`).

| Rules | What is applied | Record and cleanup |
|---|---|---|
| `accounts_passwords_pam_faillock_deny`, `_unlock_time`, `_interval`, `_root_unlock_time` | `deny = <n>`, `unlock_time = <n>`, `fail_interval = <n>` or `root_unlock_time = <n>` in `/etc/security/faillock.conf`, with the profile's value (`var_accounts_passwords_pam_faillock_deny`, `_unlock_time`, `_fail_interval`, `_root_unlock_time`); a stricter value already set is kept, a time above 604800 (which `pam_faillock` ignores) is replaced, and a required `unlock_time` of `0` (never) is met only by `0` | `recorded_value` of `method` (`line`), `setting_line` (the prior line, or `null`), `written_line` and the file's `mode`, `owner`, `group` and `sha256`; cleanup writes the prior line back in its place or removes the line, while the setting is still the line written |
| `accounts_passwords_pam_faillock_deny_root`, `_even_deny_root_or_root_unlock_time`, `_audit`, `_silent` | The flag `even_deny_root` (both root rules share the line, because `root_unlock_time` alone does not lock root), `audit` or `silent` in `faillock.conf` | As above |
| `accounts_password_pam_pwhistory_remember_password_auth`, `_remember_system_auth` (RHEL 9) | `remember = <var_password_pam_remember>` in `/etc/security/pwhistory.conf`; both rules share the line | As above; the first rule writes the line and records the prior state, the second records the same prior state |
| `accounts_password_pam_pwhistory_enforce_for_root` (RHEL 9) | The flag `enforce_for_root` in `pwhistory.conf` | As above |

The statuses that refuse to act, with nothing changed and the entry kept, each with a reason: `notapplicable` (the file
does not exist), `not_regular_file` (a symbolic link or not a regular file), `unsupported_value` (the profile requires a
time above 604800 seconds, which `pam_faillock` ignores), `overridden` (a `pam_faillock` or `pam_pwhistory` line of any
file of `/etc/pam.d`, in any case and across continued lines, carries `conf=` or sets the option, which pam takes over
the file), `unreadable_file` (a NUL byte or a line of 1023 characters or more, on which `pam_faillock` fails),
`hidden_setting` (pam reads a line of the setting that the collection would not edit: a vertical tab, form feed or
carriage return around the key, or the key in another case for `pam_pwhistory`), `duplicate_setting` (the setting is on
more than one line), `stricter_setting` (`unlock_time` or `root_unlock_time` is `0`, never, while the profile requires
seconds; the line is kept), `method_changed`, and at cleanup `modified_since_apply`, `invalid_record`, `target_absent` and `not_regular_file`. A
setting that is already as before at cleanup, such as a line removed by hand or the shared `remember` line that the
other rule restored, is `restored` without a write (FREES-173). The settings take effect only where the stack loads
`pam_faillock` or `pam_pwhistory`, and the content's checks pass only then; the Molecule regressions load such a stack
for one run, and a container scan reports the rules `notapplicable` (their group is limited to
`system_with_kernel`). Kept `audit_only`, with the reasons in ADR 0027: the rules
that put the modules into the stack (`accounts_passwords_pam_faillock_enabled`, `account_password_pam_faillock_password_auth`,
`account_password_pam_faillock_system_auth`; authselect and pam-auth-update are not exactly revertable and need the
lock-out guard of FREES-181), the Ubuntu pwhistory rules (their checks read only the `common-password` line),
`accounts_passwords_pam_faildelay_delay`, `accounts_passwords_pam_faillock_dir` and
`account_password_selinux_faillock_dir` (a tally directory with the `faillog_t` SELinux context), and the `pam_unix`
`remember` rules of `pam` and `user_accounts`.

## Results

The role publishes `linux_compliance_remediated`:

| Key | Content |
|---|---|
| `enabled`, `check_mode`, `profile`, `allow_disruptive` | The run settings |
| `summary` | Number of rules per action (`apply`, `cleanup`, `manual`, `none`, `not_implemented`, `skip`) |
| `rules` | Every rule with `rule_id`, `family`, `action`, `reason`, `disabled_by`, `pending_cleanup` and `runbook` |
| `results` | Exactly one result per rule planned for `apply` or `cleanup`, from the family files, and per rule planned as `not_implemented`, from the dispatcher (status `not_implemented`, reason `audit_only`, `changed: false`), each with `rule_id`, `family`, `action`, `status`, `reason`, `changed` and `message`. A `not_implemented` result never means that anything was remediated |
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
| `tests/unit/roles/test_remediate_tasks.py` | Every task in `roles/remediate/tasks/*.yml`, including tasks in blocks, is tagged exactly `[always]`; the only exceptions are the three guard tasks of `main.yml`. Every include applies exactly `always` and loads a file below `{{ role_path }}/tasks/`. The completeness check asserts the `remediation_unaccounted` result of the plan and runs before the dispatch is marked complete | `make test-coverage` |
| `tests/unit/tools/test_check_role_specs.py` | The guard tag is accepted only, and alone, on a top-level `assert`, `fail` or the `__linux_compliance_<role>_dispatched: false` `set_fact` of the role's `tasks/main.yml`. It is refused on other modules, a `set_fact` with other keys, includes, imports, blocks, conditions, loops, nested tasks, `apply`, other task files and another role's name | `make test-coverage` |
| `tests/playbooks/remediate-check-mode.yml` | Against localhost, in check mode and without `become`. Nothing happens without the opt-in: the ledger read and the profile check are skipped. The reference rule is planned and the host is unchanged. Invalid toggles, allow-list entries, a profile mismatch and an empty profile fail. The `file_permissions` helpers, called with synthetic planned rules against `tests/playbooks/fixtures/remediate/` (a regular file and a symbolic link): the prior mode is recorded only without a ledger entry, a symbolic link or an absent target is never changed, invalid recorded modes (`abc`, `06440`, a trailing newline, no mode) and absent or non-regular targets keep the entry as `cleanup_incomplete`, and the family file and helpers refuse to run without the opt-in or for a rule the dispatcher did not plan. Every play refuses to run without `--check`. The target runs it twice, the second time with `--skip-tags file_permissions` | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/playbooks/remediate-disruptive.yml` | The real remediate role in check mode against a copy of the collection in which `audit_rules_immutable` is a native `auditd` rule (`tools/roles/promote_native_rule.py`). With the default toggles and allow-list the rule is `skip` with `disruptive_not_allowed`, one notice names it and no family is dispatched; with `auditd` on the allow-list it is planned for `apply` and the role fails closed at the completeness check because the copy has no `auditd` task file. Refuses to run without `--check` (FREES-153) | `make test-remediate-disruptive`, run by `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/plugins/module_utils/compliance/test_toggles.py`, `tests/unit/plugins/filter/test_audit_disabled_rules.py` | Toggle resolution: a rule toggle overriding its family in both directions, a family switched off, the controlling variable, non-boolean values (including an unresolved template string), unknown and reserved toggle names, and that `remediation_plan` and `audit_disabled_rules` agree on the disabled rules for the same toggles, also with the generated defaults templated in | `make test-coverage` |
| `tests/unit/tools/test_generate_toggles.py` | The generated defaults, argument specifications and reference equal the files in the repository; drift is reported with a diff and nothing is written in `--check` mode; stale toggles are removed; a new rule gets its toggle; an invalid catalogue fails; the YAML renderer round-trips and refuses what it cannot render within 120 characters. 100% line and branch coverage | `make test-coverage`, `make lint-toggles` |
| `tests/playbooks/remediate-check-mode.yml`, toggle plays | In check mode, with the generated defaults: a single rule switched off and a whole topic switched off are not applied, name the rule toggle or the topic toggle as `disabled_by`, and the audit role's `toggles.yml` resolves the same disabled rules; a rule switched back on inside a disabled topic is applied and disabled in neither role; the audit fails before any scan on `linux_compliance_audit_enabled`, a string toggle and a catalogued rule in `linux_compliance_audit_disabled_rules`, and keeps explicit entries for uncatalogued rules | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/roles/test_audit_tasks.py` | The audit scan task passes exactly the toggle result (`__linux_compliance_audit_toggles.disabled_rules`), and `toggles.yml` runs after the discover check and before the scan and fails closed | `make test-coverage` |
| `tests/playbooks/audit-toggles-oscap.yml` | The `discover` and `audit` roles, with `become` and a real `oscap`, on the pinned Ubuntu 24.04 `cis_level2_server` content with `linux_compliance_auditd_enabled: false` and `linux_compliance_rule_file_permissions_crontab_enabled: false`: every auditd rule of the catalogue that the profile selects comes back `disabled` and names the topic toggle, the crontab rule names its rule toggle, and the number of `disabled` findings equals the catalogue count plus one | `make test-oscap-integration`, CI job `oscap-integration` |
| `tests/unit/tools/test_generate_catalogue.py` | The catalogue generator against synthetic datastreams: each rule gets exactly one family by topic group, rule prefix and fallback group; a rule below two topic groups, a rule that nothing decides, two datastreams that disagree, a group mapped twice, overlapping prefixes, unused mapping entries and a native rule outside every profile fail; the compact rendering expands back to the full entries; the repository mapping covers the required topics and its disruptive families are the pinned ones. 100% line and branch coverage | `make test-coverage` |
| `tests/unit/tools/test_content_golden.py` | With the fetched pinned content, the generated catalogue and `docs/control-families.md` equal the files in the repository and every rule of every pinned profile is catalogued; `make test-content-golden` also runs `generate_catalogue --check` | `make test-content-golden`, CI job `test-suites` |
| `tests/playbooks/remediate-check-mode.yml`, full-catalogue plays | With every catalogued rule in the profile: `linux_compliance_auditd_enabled: false` switches off every auditd rule in both roles with the topic toggle as `disabled_by` and no warning; with the opt-in and `auditd` allow-listed, every `audit_only` rule gets exactly one `not_implemented` result with `changed: false`, only the reference rule is dispatched, and one notice counts them | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/plugins/module_utils/compliance/test_toggle_umbrellas.py`, `tests/unit/plugins/filter/test_remediation_plan_umbrellas.py` | Umbrella precedence: an umbrella toggle that is `false` switches off every family it groups and a family toggle cannot switch one back on, a family toggle narrows its umbrella, a rule toggle wins over both, `disabled_by` names the most general toggle that is off, a family that heads an umbrella (`pam`) switches off its own and its families' rules, an allow-listed umbrella allows every disruptive family it groups, invalid and nested umbrellas fail, and the empty-topic warning covers umbrellas | `make test-coverage`, CI job `test` |
| `tests/unit/roles/test_topic_toggles.py` | On the real catalogue: every umbrella groups the subsystems it was split into, `auditd`, `ssh`, `sudo` and `pam` stay topics, every topic and umbrella toggle switches off exactly its rules and the rules tagged with its families in both filters, and for every toggle of the 21 families before the split (recorded in `tests/fixtures/catalog/legacy-families.yml`) its families hold exactly its former rules, it switches off exactly those plus the rules that tags add (pinned in the fixture and listed in the control family reference), keeps its disruptive flag and its allow-list entry, and is a declared default of both roles | `make test-coverage`, CI job `test` |
| `tests/unit/tools/test_content_golden.py`, topic toggles | With the pinned content, every topic and umbrella toggle switches off exactly its rules and its tagged rules in each of the 25 pinned profiles and warns exactly when it excludes nothing, and each reviewed example follows its subsystem toggle in every profile that selects it while the audit watches on MAC policy do not | `make test-content-golden`, CI job `test-suites` |
| `tests/playbooks/remediate-check-mode.yml`, umbrella play | With every catalogued rule in the profile: `linux_compliance_services_enabled: false` with `linux_compliance_sssd_enabled: true` switches off the 119 rules of the services umbrella and the 36 rules tagged with its families in both roles and names the umbrella; with the umbrella on, `linux_compliance_sssd_enabled: false` switches off exactly the sssd rules and the three sssd log file rules; `cron` and `time_sync` off switch off the native crontab rule, the cron.deny and at.deny ownership and the chrony key files but not the cron audit rules or the AIDE cron job; `smartcard`, `apparmor`, `selinux` and `pwhistory` off switch off `sssd_enable_smartcards`, the GNOME lock on smart card removal and both pam_unix `remember` rules, and leave the audit watches on MAC policy on | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/plugins/module_utils/compliance/test_toggle_tags.py`, `tests/unit/plugins/filter/test_remediation_plan_tags.py` | Subsystem tags (FREES-165) on synthetic catalogues: the tags of every rule are validated (registered family, catalogued rule of another family, sorted), a rule is off when any tag or tag umbrella is off, `disabled_by` follows the precedence, a tag toggle that is `true` never switches a rule on, a rule toggle still wins, a tag does not change the allow-list, the empty-topic warning counts tagged rules, and a ledger entry under a former family name is accepted only through `family_aliases` | `make test-coverage` |
| `tests/unit/roles/test_subsystem_tags.py` | On the real catalogue: each reviewed example (sssd log files, chrony keys, cron.deny, at.deny and the native crontab rule, `sssd_enable_smartcards`, the GNOME lock on smart card removal, pam_unix `remember`) follows its subsystem toggle in both filters, the audit watches on MAC policy stay with `auditd`, the precedence of `disabled_by`, tags never switch a rule on, and the native crontab rule is cleaned up with `cron` off, also from a ledger entry under a former family name | `make test-coverage` |
| `tests/unit/tools/test_generate_catalogue_tags.py` | The tag derivation against synthetic datastreams: rule patterns and groups, exclusions, the drift check for untagged families, unused entries and stale exclusions, the rendering into the catalogue and the reference, and every invalid source | `make test-coverage` |
| `tests/playbooks/remediate-skip-always.yml` | With `--check --skip-tags always`, the role fails through its guard instead of silently doing nothing | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/playbooks/remediate-native-check.yml` | Against localhost in check mode: with the Ubuntu 24.04 CIS profile and `pwquality` allow-listed, every banner and password quality rule gets exactly one result, `changed` exactly when it is `applied`, and the banner and pwquality files are unchanged; a banner text with a getty escape, an operating system name, an empty text, the default text under the STIG profile and a content without catalogued values fail at the text check, and the short DoD notice passes it; a pwquality rule without a profile value fails before any change; every banner and pwquality file and helper refuses to run without the opt-in | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/tools/test_content_golden_ssh.py` | With the pinned content: the check of every native ssh rule on both platforms reads `sshd_config` and the rule's own drop-in with `check="all"`, each fixed value satisfies the check's state and each profile value is exported by the check, no pinned profile selects two native ssh rules for one keyword, the crypto rules carry the RHEL 9 refusal, every drop-in sorts before the distributions' drop-ins, and `sshd_rekey_limit` refuses every drop-in | `make test-content-golden`, CI job `test-suites` |
| `tests/unit/plugins/modules/test_sshd_validate.py`, `test_process.py` | The `sshd_validate` module passes only the keywords of the native rules and one-word values as `-o` options of `sshd -t -f /etc/ssh/sshd_config`, reports a refusal with sshd's bounded message, a timeout and a missing executable, and changes nothing in check mode; the process policy refuses every other sshd command line. 100% line and branch coverage | `make test-coverage` |
| `tests/playbooks/remediate-native-check.yml`, ssh plays | Against localhost in check mode with the Ubuntu 24.04 CIS rules of `ssh` allow-listed: every rule gets exactly one result, `changed` exactly when it is `applied`, every refusal has a reason and `/etc/ssh` is unchanged (as a user that cannot read a drop-in, the run must stop at the read); a rule without its profile value fails before any change; `ssh.yml` refuses to run without the opt-in | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/tools/test_profile_values.py` | The profile value reader against synthetic datastreams: values, defaults, refinements and exports, that the `fix` elements of the content are never kept, digest and safety refusals, oversized values, chunking, grouping per profile, pinned `profile_value_id` values, and every error of the generator integration, including the removed `profile_value_source`. Without content: no catalogue entry sets `profile_value_source`, and the generated `timestamp_timeout` keeps 15 for CIS, 0 for the STIG and 5 for CCN and PCI DSS. 100% line and branch coverage | `make test-coverage` |
| `tests/unit/tools/test_check_repo_rules_own_remediation.py` | The repository guard of ADR 0025 with mutation cases: Python outside `tests/unit/` that names the XCCDF `fix` element in a string or bytes constant, as a path, namespace, wildcard, suffix test, markup or regular expression (including the removed fix reader and the ElementTree and lxml forms), files that are ComplianceAsCode or OpenSCAP remediation content, invocations of the scanner's remediation (also across line continuations, and `usg fix`) and of scripts it provides in makefiles, workflows, tasks, scripts, Jinja templates, container files and Python, the exact pinned exceptions, that adding a path form to a pinned file is refused, and that only the pinned constants name the element in the repository | `make test-coverage`, `make lint-repo` |
| `tests/unit/tools/test_content_golden_native.py`, sudo | With the pinned content: every sudo drop-in is read by every check of its rule on both platforms, satisfies the check's pattern and state for every profile value (and matches none of its `none_exist` patterns), every attribute rule restricts the path and the mode bits that the OVAL checks, and the pinned `xccdf_org.ssgproject.content_value_var_sudo_timestamp_timeout` exists in both datastreams, is not exported by the check, and gives every selecting profile its value (15 for CIS, 0 for the STIG, 5 for CCN and PCI DSS) | `make test-content-golden`, CI job `test-suites` |
| `tests/unit/tools/test_content_golden_pam_conf.py` | With the pinned content: every line that a native faillock or pwhistory rule writes satisfies the object and the comparison of every check that reads `faillock.conf` or `pwhistory.conf` on both platforms, the commented line does not, the compared value is the catalogue's, `stack_checked` is true exactly when the check reads the module line of the PAM stack and the filter's stack detector finds every module line that the check finds, every stack file of a check is a file of `/etc/pam.d`, which the role reads whole, no other catalogued rule reads either file, and the Ubuntu pwhistory rules read only `common-password` | `make test-content-golden`, CI job `test-suites` |
| `tests/unit/plugins/filter/test_pam_conf_oracle.py`, `test_pam_conf.py`, `tests/unit/tools/test_pam_reader_corpus.py` | Against `tests/fixtures/pam_conf/reader_verdicts.json`, which `make pam-reader-verdicts` builds from the readers of the pam source packages that the Molecule images install: the filter reads all 1506 cases (CR, VT, FF and NUL, case, duplicates, long lines, continued and bracketed module lines, `conf=`, a fuzz corpus and the file after each change) exactly as both readers do, the module lines yield the arguments that libpam passes, and no decision is `compliant` or `applied` while a real reader reads the file looser than the profile requires; the reviewed refusals; the table is exactly what the generator assembles. 100% line and branch coverage | `make test-coverage`, CI job `test-suites` |
| `tests/playbooks/remediate-pam-conf-check.yml` | Against localhost in check mode with the Ubuntu 24.04 STIG and the RHEL 9 CIS workstation level 2 rules of `faillock` and `pwhistory` allow-listed: every rule gets exactly one result, `changed` exactly when it is `applied`, every refusal has a reason and both files are unchanged; a rule without its profile value fails before any change; the family files and the three `pam_conf_*` helpers refuse to run without the opt-in | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/playbooks/remediate-native-check.yml`, sudo | A sudo rule without a profile value fails before any sudoers file is read, and every sudo family file and helper refuses to run without the opt-in. The sudo rules are not run against localhost, because `/etc/sudoers` is readable only by root | `make test-remediate-check`, CI job `test-playbooks` |
| `tests/unit/tools/test_content_golden_login_defs.py` | With the pinned content: every native login_defs rule reads only `/etc/login.defs` (and, for `CREATE_HOME`, `/etc/login.defs.d/*.defs`) with the pinned object pattern, its comparison is the operation of the check's state and its value the external variable of the check, on both platforms; and every selected rule whose check reads `/etc/login.defs` is native or one of the two documented `audit_only` rules | `make test-content-golden`, CI job `test-suites` |
| `tests/playbooks/remediate-login-defs-check.yml` | Against localhost in check mode: with the Ubuntu 24.04 CIS level 2, RHEL 9 STIG and RHEL 9 ANSSI enhanced profiles every login_defs rule gets exactly one result, `changed` exactly when it is `applied`, a reason for every refusal, and `/etc/login.defs` is unchanged; a rule without a profile value fails before login.defs is read; the family file and helpers refuse to run without the opt-in; a ledger entry of another method or without one, a written line of another setting, a prior line over two lines and a malformed mode are refused and kept | `make test-remediate-check`, CI job `test-playbooks` |

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

The Docker Molecule scenarios ([Molecule guide](molecule.md)) run the role for real in disposable containers. `converge`
and `verify` show that nothing changes without the opt-in, that the reference rule is applied, idempotent and cleaned up
on disable, and that check mode changes nothing. The toggle lifecycle step (FREES-60,
[toggle lifecycle](molecule.md#toggle-lifecycle-of-every-native-topic)) does so for every topic with a native rule: it
switches the topic on and off with its topic toggle and with its rule toggles, from the as-built state and from every
declared pre-state, checks check mode, idempotence and the ledger, asserts that the declared files, packages, services,
kernel parameters, users and groups are restored exactly, and asserts that the following audit reports the rules as
`disabled` with the controlling variable. `make lint-lifecycle` fails when a topic with a native rule has no lifecycle
declaration. The skip of a disruptive family without the allow-list is still shown only in check mode
(`make test-remediate-disruptive`); with `pwquality` the lifecycle now also runs a disruptive topic with its
allow-list entry, and `make test-remediate-disruptive` checks that its rules are skipped without it.

## Related decisions and issues

- [ADR 0003](adr/0003-native-module-remediation.md), [ADR 0011](adr/0011-control-toggles-and-cleanup.md)
- FREES-52 (this page), FREES-53 (first families), FREES-55 (generated toggles,
  [variable reference](remediation-variables.md)), FREES-57 (cleanup per family),
  FREES-54 (verify), FREES-59 and FREES-60 (Molecule)
