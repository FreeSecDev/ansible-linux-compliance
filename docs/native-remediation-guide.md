# Native remediation guide

Scope: how to give a topic of the rule catalogue a native remediation, from reading the content to the toggle
lifecycle in Molecule. Audience: family authors and reviewers. Jira: FREES-53 (native remediations), FREES-57
(cleanup per family). Decisions: [ADR 0003](adr/0003-native-module-remediation.md) (native modules only),
[ADR 0011](adr/0011-control-toggles-and-cleanup.md) (toggles, cleanup, ledger),
[ADR 0021](adr/0021-native-banners-pwquality-and-profile-values.md) (profile values, banners, password quality),
[ADR 0023](adr/0023-native-ssh-server-configuration.md) (SSH server).
The contract of a family file is in [remediation.md](remediation.md#family-file-contract); this guide is the
procedure. `file_permissions`, `banners`, `pwquality`, `ssh` and `sudo`
([ADR 0022](adr/0022-native-sudo-drop-ins.md)) are the worked examples.

## 1. Read what the content expects

Never infer a rule from its name. Fetch the pinned content (`make content`) and read, for every rule of the topic in
both pinned datastreams of `content/manifest.yml`:

- which profiles select it (`Profile/select`), so you know which platforms and profiles the lifecycle will run;
- its description and its OVAL definition: the files, the patterns, `check` (`all`, `at least one`),
  `check_existence` (does a missing file pass?), the filters (are symbolic links excluded?) and the states;
- the `check-export` of its checks: a rule that exports a `Value` must use the profile's value (step 3);
- its `platform` elements: `system_with_kernel` and `machine` exclude containers, `package_<name>` makes the rule
  not applicable without the package.

Write the setting where the content's check reads it on each platform, so the audit agrees with the remediation;
when the platforms differ, choose the method per benchmark and pin it with a golden test against the OVAL (as
`pwquality` does with `main_file_benchmarks`). Decide per rule whether it can be implemented natively and safely: with `ansible.builtin` modules only (`copy`,
`template`, `lineinfile`, `file`, `stat`, `slurp`, `find`; never `shell`, `command`, `raw` or `script`), without
changing what another topic owns (the PAM stack belongs to `pam`, packages to the package topics), and with an exact
revert. A rule that fails any of these stays `audit_only`; write the reason into the ADR of the topic and the
[remediation guide](remediation.md#native-families).

## 2. Choose the revert strategy per rule

| Strategy | Use when | What the ledger records | Cleanup |
|---|---|---|---|
| `owned_dropin` | The service reads a drop-in directory (`pwquality.conf.d`, `sysctl.d`, `sshd_config.d`, `modprobe.d`) | An entry without prior values | Remove the drop-in, only when it carries the collection's header |
| `recorded_value` | A shared file or one of its attributes must be changed in place | Only the attribute the rule changes: the content (base64, `null` when absent), the mode, the uid or the gid | Restore exactly that attribute |
| `recorded_state` | A package or a service changes state | The prior state | Restore it |
| `irreversible` | Partitioning and similar | Nothing to restore; a runbook | Never automatic |

Rules that share a file record different attributes, so each rule restores only what it changed (the four rules of
`/etc/issue` record `content_base64`, `mode`, `owner` and `group`). Prefer one drop-in per rule over one shared file:
a per-rule file needs no merge and its cleanup needs no history. Record a value only when the rule must change
something and the rule has no ledger entry yet; never re-record, because the first record is the true prior state.

When a rule needs a directory that may not exist (Ubuntu ships no `pwquality.conf.d`), create it together with an
empty marker file that the service ignores (`.freesecdev-created`), and after the family's cleanup and apply remove the
marker and the directory when nothing else is left in it. A directory without the marker is never removed.

## 3. Use the profile's values

When a rule's check exports a `Value`, add `profile_value: <short value id>` to its entry in `native_rules` of
`content/catalogue.yml` and run `make catalogue`. The generator writes `value_id` and `profile_values` (per datastream
and content SHA-256, the profiles that share a value and the value as chunks) into the rule's parameters and fails when
the checks do not export the value or a profile cannot take it. In the family file, select the entry with
`linux_compliance_discovered.content_sha256` and `linux_compliance_remediate_profile`, join the chunks, and refuse the
family before any change when no entry matches or the value has the wrong form:

```yaml
found: >-
  {{ rule.parameters.profile_values | default([])
     | selectattr('content_sha256', 'equalto', linux_compliance_discovered.content_sha256)
     | selectattr('profiles', 'contains', linux_compliance_remediate_profile)
     | map(attribute='value') | map('join', '') | list }}
```

Never hard-code a value that a profile refines, and never fall back to another profile's value. A value that the
operator chooses (the banner text) is a role variable with the content's default, validated against the profile's
value before anything changes (ADR 0021).

## 4. Write the family file and its helpers

Add the rules to `native_rules` with their strategy and the parameters your family file interprets, run
`make catalogue` (it also runs `make toggles` and `make role-guards`, which adds the static dispatch include and the
internal-variable guards of the new facts), and write `roles/remediate/tasks/<family>.yml` plus helpers named
`<family>_<purpose>.yml`. Follow the [family file contract](remediation.md#family-file-contract); the points that
reviews catch most often:

- Every file starts with the `assert` that refuses direct use, every task is tagged `always` and nothing else, and
  helpers are included as `{{ role_path }}/tasks/<file>.yml`.
- Validate inputs and profile values for all rules of the family before the cleanup and apply loops, so a refused rule
  stops the family before it changes anything.
- Inspect with `stat` and `follow: false`; never change a symbolic link or another non-regular file; use the results
  `notapplicable`, `not_regular_file`, `compliant`, `applied`, and for cleanup `restored` or `cleanup_incomplete` with
  a reason, plus topic-specific refusals (`overridden`, `not_owned`, `prior_too_large`) that never claim a change.
- Check mode must report every planned change and change nothing. When a later task depends on something an earlier
  rule would create (a directory, a file), predict it from a fact instead of failing or reporting nothing; skip a
  module in check mode only when it cannot run without the prediction and another task already reports the change.
- Report exactly one result per planned rule, with `changed` true exactly when the rule changed or would change
  something.
- Record what was written (the line, or the drop-in's SHA-256) and the `method`; cleanup refuses `method_changed` and
  `modified_since_apply` without a change, and a state that already equals the recorded prior state (a drop-in removed
  by hand, an attribute already back at its prior value) is `restored` by removing the ledger entry, without a write
  (FREES-173). Every refusal carries a non-null `reason`.
- When a syntax error in the file breaks the service (sudoers), write it only through the module's `validate` with the
  service's own checker. The repository guard refuses `validate` except for reviewed entries of `ALLOWED_PARAMETERS`
  in `tools/lint/repo_rules/exec_modules.py` (ADR 0004, amendment of FREES-175); add one only with an ADR, and catch
  the refusal so that the rule reports it and nothing is installed (`sudo_dropin_apply.yml`).
- Jinja under ansible-core 2.21 does not unescape `'\n'` inside a template, so use the constant
  `__linux_compliance_remediate_newline` of `vars/main.yml` for a newline in generated content.
- The `validate` parameter of the file modules is refused by the repository guard (ADR 0004). When a service must
  accept a configuration before it is written, validate it with a module of this collection that runs the service's
  own test through the audited process helper, as `sshd_validate` does for `ssh` (ADR 0023), and validate the
  effective configuration rather than the new file alone.
- Restart or reload a service only where it runs (`service_facts`), once per run, after a final validation, and prefer
  a reload that keeps open sessions; check mode never reloads.

## 5. Declare the lifecycle

Add `extensions/molecule/shared/vars/topics/<family>.yml` ([Molecule guide](molecule.md#declaring-a-topic)):

- `state` lists every file, directory, marker, package, user and group the topic can touch, with `platforms` where they
  differ, and `rewritten: true` for a file whose content the topic rewrites;
- `applied` gives real expectations, ideally the SHA-256 of the exact content, the mode, owner, group, uid and gid,
  because a container audit often reports `notapplicable`;
- `pre_states` include a customised state that shows that cleanup restores the recorded value and not a default, and
  list under `unchanged` the rules that a pre-state already satisfies (`compliant`), that do not apply
  (`notapplicable`) or that an earlier setting overrides (`overridden`); a pre-state may add files with `content`
  (written before the cycle and removed after it) and replace `applied` expectations, for example the absent drop-in
  of an overridden rule;
- `audit.applied_outcomes` adds `notapplicable` with the reason when the content's platform excludes containers;
- regressions that the cycles cannot show (a change of method, a change by hand, a refusal) go into task files of
  `shared/tasks`, included by the static dispatch `shared/tasks/lifecycle_regressions.yml`, and are declared as named
  groups under `regressions`; each group gets its own CI leg, so the cycle legs stay short;
- a disruptive topic needs `disruptive: true` and a `containment` note that says what it can break and why the harness
  still reaches the container.

`make lint-lifecycle` refuses a native topic without a declaration and a malformed declaration. If converge or verify
should not see the new topic, add it to `molecule_other_native_topics` in `shared/vars/target.yml` and to the play
variables of `converge.yml` and `verify.yml`; their first task fails until both agree with the catalogue.

## 6. Test

- Unit tests: the generated catalogue, the parameters and strategies of the new rules
  (`tests/unit/roles/test_remediate_catalogue.py`), and 100% coverage of any Python you add.
- Check-mode plays on the controller (`make test-remediate-check`): the family files refuse direct use, invalid inputs
  and missing profile values fail before any change, and a run with the rules in the profile reports one result per
  rule and changes nothing (`tests/playbooks/remediate-native-check.yml`).
- `make test-molecule-docker`: the toggle lifecycle applies and cleans up the topic from every pre-state on Ubuntu
  24.04 and Rocky Linux 9 and compares the whole instance. Never run remediation on a workstation; only in these
  containers. Add `MOLECULE_DOCKER_SCENARIOS=docker-ubuntu-lifecycle MOLECULE_LIFECYCLE_TOPIC=<topic>
  MOLECULE_LIFECYCLE_MODE=rule` (and `topic`) to run only the new topic; CI gives the topic its own legs without a
  workflow change ([Molecule](molecule.md#ci-legs)).
- Regenerate with the make targets and run `make lint`, `make lint-role-guards`, `make lint-lifecycle` and `make ci`.

## 7. Document

Update the ADR of the topic (or add one) with the rules made native, the rules kept `audit_only` and why, and any gap
between the content's check and what the service reads; update [remediation.md](remediation.md#native-families), the
role README and add a changelog fragment.

## Worked examples

| Topic | Rules | Strategy | Notes |
|---|---|---|---|
| `file_permissions` | `file_permissions_crontab` | `recorded_value` (mode) | Keeps a stricter mode (`current & 0600`) |
| `banners` | text of `/etc/issue`, `/etc/issue.net`, `/etc/motd` (CIS and STIG/CCN rules), their mode, owner and group | `recorded_value` per attribute | Text from `linux_compliance_remediate_banner_text`, validated against the profile's value; a missing file is created `0644 root:root` and removed again on cleanup |
| `pwquality` | `dcredit`, `dictcheck`, `difok`, `enforce_for_root`, `enforcing`, `lcredit`, `maxclassrepeat`, `maxrepeat`, `maxsequence`, `minclass`, `minlen`, `ocredit`, `retry` (STIG rule), `ucredit` | `recorded_value`: one line per setting in the main file where the content checks only it (Ubuntu), one drop-in per rule where it checks the drop-ins (RHEL) | Values from the profile; the method per platform follows the content's OVAL (`main_file_benchmarks`, checked by a golden test); `duplicate_setting` and `overridden` refuse to claim a change that would not take effect |
| `ssh` | 34 sshd keyword rules (`PermitRootLogin`, `MaxAuthTries`, `ClientAliveInterval`, `Ciphers`, `Banner` and the others) | `recorded_value`: one drop-in per rule, `00-freesecdev-<rule>.conf`, which sshd reads before every other file, and the one conflicting later line of a vendor file (`sshd_config`, `50-redhat.conf`) set to the rule's value in place | Both contents read the drop-ins and every later line (golden test); fixed values from the check, numeric and algorithm values from the profile; a conflicting later line in an administrator's drop-in or a `Match` block is `overridden`; every change validated with `sshd -t` through the `sshd_validate` module before it is written (`invalid_config`), `overridden` for an earlier setting, `not_included` without the `Include`, `crypto_policy` on RHEL; sshd reloaded only where it runs; 29 rules `audit_only` with the reasons in ADR 0023 |
| `sudo` | `use_pty`, `logfile`, `timestamp_timeout`, `!targetpw`/`!rootpw`/`!runaspw` (STIG); mode, owner and group of `/etc/sudoers` and `/etc/sudoers.d` (ANSSI) | `recorded_value`: one drop-in per rule below `/etc/sudoers.d` with its SHA-256, or the prior attribute and the one written | Every write is checked by `visudo` through `copy` `validate` (the one reviewed exception of the repository guard); `timestamp_timeout` comes from the content's fix (`profile_value_source: fix`); `conflicting_setting`, `not_included` and `invalid_sudoers` refuse to claim a change that would not take effect; rules that remove other people's `NOPASSWD`, `!authenticate` or user specifications stay `audit_only` |
| `filesystem_modules`, `protocol_modules`, `wireless_modules` | 21 `kernel_module_<module>_disabled` rules, usb-storage included | `recorded_value`: one drop-in per rule, `/etc/modprobe.d/freesecdev-<module>.conf`, with the `install <module> /bin/false` and `blacklist <module>` lines that both contents require ([ADR 0028](adr/0028-native-kernel-module-drop-ins.md)) | Three families share the umbrella's helpers (`kernel_modules_*.yml`); the family reads every file that `modprobe` reads in its order, so a site file that already disables the module is `compliant` and one read first that lets it load is `overridden`; no module is unloaded and no initramfs rebuilt; the lifecycle runs them with the profiles that select them (`profiles` in the declaration) |
