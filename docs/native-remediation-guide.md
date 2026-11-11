# Native remediation guide

Scope: how to give a topic of the rule catalogue a native remediation, from reading the content to the toggle
lifecycle in Molecule. Audience: family authors and reviewers. Jira: FREES-53 (native remediations), FREES-57
(cleanup per family). Decisions: [ADR 0003](adr/0003-native-module-remediation.md) (native modules only),
[ADR 0011](adr/0011-control-toggles-and-cleanup.md) (toggles, cleanup, ledger),
[ADR 0021](adr/0021-native-banners-pwquality-and-profile-values.md) (profile values, banners, password quality),
[ADR 0023](adr/0023-native-ssh-server-configuration.md) (SSH server),
[ADR 0025](adr/0025-own-ansible-remediation-only.md) (our own Ansible only),
[ADR 0032](adr/0032-operator-control-community-modules-and-value-overrides.md) (allow-listed community modules),
[ADR 0027](adr/0027-native-faillock-pwhistory.md) (account lock-out and password reuse),
[ADR 0029](adr/0029-native-kernel-parameters.md) (kernel parameters) and
[ADR 0030](adr/0030-native-auditd-settings-and-audit-rules.md) (auditd settings and audit rules).
The contract of a family file is in [remediation.md](remediation.md#family-file-contract); this guide is the
procedure. `file_permissions`, `banners`, `pwquality`, `ssh`, `sudo`
([ADR 0022](adr/0022-native-sudo-drop-ins.md)), `login_defs` ([ADR 0024](adr/0024-native-login-defs.md)),
`faillock`, `pwhistory` and the kernel parameter topics `sysctl`, `ipv4_parameters` and `ipv6_parameters` are the
worked examples.

## The rule: our own Ansible, never theirs

Every remediation is Ansible that you write in `roles/remediate`. Do not run, import, copy, translate or parse the
remediation of ComplianceAsCode or OpenSCAP: not their generated playbooks or Bash fixes, not the `fix` elements of the
datastream, not `oscap --remediate` or `generate fix`, and not any script that the scanner provides. Read the OVAL
check to learn what the audit expects, and pin your method against it in a golden test. The OVAL is a reference and
an audit, never a source of remediation code. Take values only from the profile's XCCDF values through
`profile_value` or `profile_value_id` (step 3). A rule that you cannot implement natively and safely stays
`audit_only`: it is scanned, reported as `not_implemented` and never remediated by another tool. `make lint-repo`
refuses Python that reads `fix` elements, committed upstream remediation content and invocations of the scanner's
remediation ([ADR 0025](adr/0025-own-ansible-remediation-only.md)).

### Which modules a family may use

A task of `roles/remediate` names its module by the fully qualified name, and that module is one of these
([ADR 0032](adr/0032-operator-control-community-modules-and-value-overrides.md) §1):

- an `ansible.builtin` module of `BUILTIN_MODULES`, never `shell`, `command`, `raw` or `script` (AGENTS.md rule 1).
  The list holds the module files of the pinned ansible-core that its `plugin_routing` neither redirects nor removes,
  and a unit test keeps it equal to the installed ansible-core. ansible-core sends thousands of `ansible.builtin`
  names to other collections: `ansible.builtin.make` runs `community.general.make`, `ansible.builtin.at` runs
  `ansible.posix.at` and `ansible.builtin.sysctl` runs `ansible.posix.sysctl`, so these names are refused like the
  modules they reach;
- except `ansible.builtin.gather_facts`, `ansible.builtin.package` and `ansible.builtin.service`
  (`DISPATCHING_MODULES`): their action plugins choose the module they run while the play runs, from an argument
  (`network_os`), a variable (`ansible_network_os`, `ansible_facts_modules`, `ansible_package_use`) or a fact
  (`pkg_mgr`, `service_mgr`) that a task can set, so they could run any installed module. Reload or restart a unit
  with `ansible.builtin.systemd_service`. `ansible.builtin.dnf` also picks its backend at run time, but only among
  the dnf modules of ansible-core, and stays allowed; a unit test fails when ansible-core gains another action plugin
  that runs a module whose name is not a literal;
- a module or action plugin of this collection, `freesecdev.linux_compliance.*`, whose file is in `plugins/modules` or
  `plugins/action` and for which `meta/runtime.yml` has no routing entry other than `deprecation`. `make lint-repo`
  also refuses, in `meta/runtime.yml`, any routing of `modules` or `action` other than `redirect`, `tombstone` and
  `deprecation` (such as `action_plugin`), any routing of `module_utils` other than `deprecation`, and any
  `import_redirection`;
- a module of a community collection that is on `ALLOWED_COMMUNITY_MODULES` in
  `tools/lint/repo_rules/remediate_modules.py`. **The list is empty today.**

`make lint-repo` refuses every other module in every YAML task file below `roles/remediate`, including a short name
(`copy:`), an `ansible.legacy` name and a templated name, in a task key as well as in `action` and `local_action`,
and an `action` or `local_action` whose module is not a plain string (in a JSON file ansible-core reads
`{"__ansible_unsafe": "zz.evil.pwn"}` there as the module name). A
module of a community collection, such as `community.general.make` or `ansible.posix.at`, is refused because it is not
listed. To list one, the same pull request:

- records the security review of ADR 0032 §1: check mode and a truthful `changed`, how the module reads and writes the
  files it manages (whole-file writes, CR and NUL handling, symbolic links), and every external process it runs. A
  process call must meet AGENTS.md rule 2 and [ADR 0004](adr/0004-audited-process-execution.md), with a timeout among
  other things; `ansible.posix.sysctl` runs `sysctl` with no timeout and is refused, which is why the kernel parameters
  use their own drop-ins ([ADR 0029](adr/0029-native-kernel-parameters.md));
- pins the collection at one exact version (`<major>.<minor>.<patch>`) in `galaxy.yml` `dependencies`,
  `extensions/molecule/requirements.yml` and `extensions/molecule/collections.pins` (`make molecule-collections-lock`);
  the rule refuses an allow-listed module whose collection is missing from one of them or pinned at different
  versions.

The family keeps the reader as the oracle, whichever module writes the file. Molecule scenarios, test playbooks and
the other roles are not in scope of the allow list; the banned modules apply to them as everywhere.

Ansible loads a role's `tasks`, `handlers` and `meta` entry point `main` also as `main.json` or `main` without a
suffix, and `tasks_from` or `handlers_from` loads any file below `tasks/` or `handlers/` by its exact name. It reads
each file as JSON first and decrypts a vaulted file. So every file below `roles/remediate/tasks/`, `handlers/` and
`meta/` must end in `.yml` or `.yaml`, must be YAML that PyYAML reads, and must hold only task lists (`tasks/`,
`handlers/`) or a mapping (`meta/`), with no key that starts with `__ansible_` (ansible-core's JSON loader decodes
such a mapping into another value); `make lint-repo` refuses anything else there, so every task and handler file of
the role is one the rule reads.

A task or block of `roles/remediate` may not use the keywords `delegate_to`, `delegate_facts`, `local_action` or
`connection`. Only these keyword forms are refused; the other ways to reach the controller or another host are listed
in "What the module rule does not cover" below. `ansible_network_os` and
`network_os` are refused wherever the repository sets variables or facts, like `ansible_facts_modules`,
`ansible_package_use`, `pkg_mgr` and `service_mgr`, because they choose the module that a play's fact gathering runs
after the role.

The allow list governs modules, so the role does not run tasks it does not own: `include_role`, `import_role` and a
dependency in `roles/remediate/meta/main.yml` are refused, and `include_tasks` and `import_tasks` are task keys whose
target is `{{ role_path }}/tasks/` followed by a literal path. Ansible looks for any other relative target in the
playbook's directory as well, and the rule never reads that file.

Names that Ansible learns only while the play runs get past every rule that reads literal keys, so `make lint-repo`
refuses them in every task list of the repository: a templated `set_fact` key (accepted only below
`extensions/molecule/`, whose lifecycle harness switches toggles by name), `args`, a `module_defaults` entry or the
mapping form of `action` that is not a mapping with literal keys, a free-form argument string with a template (other
than an include target), and a `loop_var`, `index_var`, `register` or `include_vars`/`vars_prompt` `name` that is
templated or names a variable that changes what Ansible executes, such as `ansible_python_interpreter`.

#### What the module rule does not cover

The rule guards against mistakes and unreviewed additions. It is not a sandbox against a contributor who deliberately
builds a bypass in several steps ([ADR 0032](adr/0032-operator-control-community-modules-and-value-overrides.md),
boundary of 2026-11-10). It does not read Jinja filter, test and lookup plugins of other collections, files that tasks
of the role plant (`files/`, `templates/`, a module written into one of Ansible's module paths), routing of other
plugin types, settings of the play, inventory or configuration outside the role, or a change to the rule and its tests.
Nor does it refuse the ways other than the four keywords in which a task reaches the controller or another host:
connection and host variables (`ansible_connection`, `ansible_host`) set as `vars`, `delegate_to` and the other
keywords inside `apply` of an include, and `ansible.builtin.fetch`, whose destination is on the controller.
The independent review of every pull request covers those
([ADR 0033](adr/0033-review-policy-independent-verdict-without-required-approval.md)). A reviewer of a change to
`roles/remediate`, `meta/runtime.yml` or the rule looks for such bypasses.

## 1. Read what the content expects

Never infer a rule from its name. Fetch the pinned content (`make content`) and read, for every rule of the topic in
both pinned datastreams of `content/manifest.yml`:

- which profiles select it (`Profile/select`), so you know which platforms and profiles the lifecycle will run;
- its description and its OVAL definition (never its `fix` elements): the files, the patterns, `check` (`all`, `at least one`),
  `check_existence` (does a missing file pass?), the filters (are symbolic links excluded?) and the states;
- the `check-export` of its checks: a rule that exports a `Value` must use the profile's value (step 3);
- its `platform` elements: `system_with_kernel` and `machine` exclude containers, `package_<name>` makes the rule
  not applicable without the package.

Write the setting where the content's check reads it on each platform, so the audit agrees with the remediation;
when the platforms differ, choose the method per benchmark and pin it with a golden test against the OVAL (as
`pwquality` does with `main_file_benchmarks`). Decide per rule whether it can be implemented natively and safely: with the modules of
[Which modules a family may use](#which-modules-a-family-may-use) (for example `ansible.builtin.copy`, `template`,
`lineinfile`, `file`, `stat`, `slurp` and `find`; never `shell`, `command`, `raw` or `script`), without
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

When the check accepts a range and exports nothing (the `timestamp_timeout` check accepts any non-negative number),
pin the full identifier of the `Value` that the profile refines instead:
`profile_value_id: xccdf_org.ssgproject.content_value_var_sudo_timestamp_timeout`. The generator then resolves it from
each selecting profile's `refine-value` and the `Value`'s default and selectors, and fails when a pinned datastream
does not define it. Add a golden test that pins the identifier and the value of every profile that selects the rule
(`test_the_pinned_sudo_timeout_value_gives_every_selecting_profile_its_value`). Never take a value from the content's
`fix` elements; `profile_value_source` no longer exists (ADR 0025).

A rule with a profile value becomes overridable by the operator (ADR 0032) once it names its comparison:
`value_comparison: <name>` next to `profile_value` or `profile_value_id`, where the name is an entry of
`COMPARATORS` in `plugins/module_utils/compliance/values.py`. A comparator validates an operator's value (only the
values the family's own validator accepts and the reader reads as written), says whether a value is at least as strict
as the profile's (`meets`, which knows the reader's special values such as `deny = 0` or `unlock_time = 0`), reads a
profile's value (`read_profile`, which for an auditd choice takes a set such as `syslog|single|halt` while an override
is one keyword) and picks the stricter of two values. The generator copies the name into the rule's parameters and
fails for a rule without a profile value, for a banner rule, for an unknown name and when a profile value is not a
canonical value of the comparator. Comparators exist for every family with profile values except `banners`: the
integer families, the sshd numbers, `MaxStartups` and algorithm lists, the sudo timeout and log file, the kernel
parameters and each auditd setting. Add a comparator to `values.py` with a table test in
`tests/unit/plugins/module_utils/compliance/test_values.py` that pins it to the family's reader before any rule names
it (for a text family, what the reader prints or reads back for each form of the value); no rule names one until its
family is wired for overrides.

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
- Choose a short internal variable prefix for the family and its helpers, `__linux_compliance_remediate_<xx>_`, that
  no other family and no constant of `vars/` uses (`ld`, `kp`, `sc` and the others are taken); `make lint-repo`
  refuses a prefix that another family's task files use, a second prefix in one family and a prefix of a constant
  (FREES-208).
- Validate inputs and profile values for all rules of the family before the cleanup and apply loops, so a refused rule
  stops the family before it changes anything.
- Inspect with `stat` and `follow: false`; never change a symbolic link or another non-regular file; use the results
  `notapplicable`, `not_regular_file`, `compliant`, `applied`, and for cleanup `restored` or `cleanup_incomplete` with
  a reason, plus topic-specific refusals (`overridden`, `not_owned`, `prior_too_large`) that never claim a change.
- Read the files that a program reads the way it opens them. `ansible.builtin.find` with `file_type: file` keeps only
  regular files, whatever `follow` says, so a file that the program opens through a symbolic link is missed. List with
  `file_type: any`, stat every link with `follow: true`, and read a link that resolves to a regular file through the
  link; refuse the rule on a link that resolves to nothing, to a special file or that `stat` cannot follow (run that
  stat with `failed_when: false`, because it fails on a loop, and treat a result without `stat` as unreadable), and on
  an entry that `find` lists in `skipped_paths`, and never read through one. A
  directory to list is inspected with `follow: true` when the program follows a linked directory, again with
  `failed_when: false`, refusing on a directory that `stat` cannot inspect. Pass the error message of a failed `stat`
  into the reason. Resolve every link and every linked directory with a `stat` and `follow: false` (its `lnk_source`
  is the resolved path, its `lnk_target` the target as the link holds it) and refuse on one that resolves below
  `/proc`, `/sys` or `/dev`, or whose target names such a path: such a file, like `/proc/self/environ` or
  `/proc/self/cwd/x`, reads differently in the module's process than in the program's, and `lnk_source` is computed
  in the module's process. Read a link only when its target, made absolute, is `lnk_source` itself, and refuse a link
  reached through a further link, whose hops the module does not see. Know the program's fallback
  when its directories are missing (libpam reads `/etc/pam.conf` when neither `/etc/pam.d` nor `/usr/lib/pam.d` is a
  directory) and refuse when it would apply, unless the family reads the fallback too. The PAM families do this with
  the filter `pam_service_files` (FREES-213, FREES-212).
- Parse a format once. When several families read the same files, they share one reader in `module_utils` that is
  checked against the real program, instead of each family parsing the text itself: the `pwquality` family once read
  PAM lines with a parser of its own that missed a live line after `# comment \`, a split long line and include forms
  that libpam accepts, while `pam_conf` read them right (FREES-212). Where the pinned platforms read a file
  differently, read it both ways and refuse when the readings disagree on anything that the rule depends on.
- Identify what the program loads by the file it loads, not by its name. libpam runs `pam_pwquality.so` reached
  through a link or a copy under any name, so the `pwquality` family resolves every module path as libpam does and
  compares the file with `pam_pwquality.so` by SHA-256, refusing when it cannot tell (FREES-212). State what a family
  does not decide: the `pwquality` family decides the values that the module would use, not whether the stack runs
  it.
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
- Decide as the program that reads the file does (FREES-200). Where it prints its effective configuration
  (`sshd -T`), read that through the audited process helper, as `ssh` does; where it cannot, reproduce its reader and
  check it against a verdict table that the real program produced in the Molecule images, as `pwquality` does
  (`tools/lint/pwquality_readers.sh`). Report `applied` or `compliant` only when the reader takes the required value
  from what the rule wrote; refuse with a reason otherwise.
- Do not edit a shared file with `lineinfile` or `replace`: ansible-core 2.21 reads with universal newlines, drops the
  CR before an LF on other lines and splits at a lone CR. Write the whole file with `copy` from the exact text that
  `slurp` read, with only the rule's line replaced, and the file's mode.
- Jinja under ansible-core 2.21 does not unescape `'\n'` inside a template, so use the constant
  `__linux_compliance_remediate_newline` of `vars/main.yml` for a newline in generated content.
- The `validate` parameter of the file modules is refused by the repository guard (ADR 0004). When a service must
  accept a configuration before it is written, validate it with a module of this collection that runs the service's
  own test through the audited process helper, as `sshd_validate` does for `ssh` (ADR 0023), and validate the
  effective configuration rather than the new file alone.
- Restart or reload a service only where systemd runs it (`service_facts` reports it `running` with `source:
  systemd`), with `ansible.builtin.systemd_service`, once per run, after a final validation, and prefer a reload that
  keeps open sessions; check mode never reloads. `ansible.builtin.service` is refused in `roles/remediate`.

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
  groups under `regressions`; each group gets its own CI leg, so the cycle legs stay short; a group that needs what
  only a virtual machine has (a running value changed by hand) names `requires: [libvirt]`;
- what a container cannot prove (a running kernel parameter, an ownership change) goes into a pre-state that
  `requires: [libvirt]`, next to the container pre-state that proves the files (the kernel parameter topics);
- a disruptive topic needs `disruptive: true` and a `containment` note that says what it can break and why the harness
  still reaches the container.

`make lint-lifecycle` refuses a native topic without a declaration and a malformed declaration. Converge and verify
switch the new topic off by themselves: `shared/tasks/other_topics_off.yml` derives the native topics other than the
reference topic from the catalogue at run time (FREES-195), so a topic pull request does not edit `converge.yml`,
`verify.yml`, their libvirt counterparts or `shared/vars/target.yml`. Keep the topic's changes to its own files, as
[adding a topic](molecule.md#adding-a-topic-without-touching-shared-files) lists them, so that CI plans only the
topic's own lifecycle legs.

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
| `pwquality` | `dcredit`, `dictcheck`, `difok`, `enforce_for_root`, `enforcing`, `lcredit`, `maxclassrepeat`, `maxrepeat`, `maxsequence`, `minclass`, `minlen`, `ocredit`, `retry` (STIG rule), `ucredit` | `recorded_value`: one line per setting in the main file where the content checks only it (Ubuntu), one drop-in per rule where it checks the drop-ins (RHEL) | Values from the profile; the method per platform follows the content's OVAL (`main_file_benchmarks`, checked by a golden test); every rule is decided as libpwquality reads the files and the `pam_pwquality` arguments in every regular file of the three PAM directories (`/etc/pam.d`, `/usr/lib/pam.d`, `/usr/share/pam.d`, FREES-211) and every symbolic link there that resolves to one, read through the link (FREES-213), override them, a link to nothing, to a special file or that `stat` cannot follow, and a PAM directory or entry that `find` or `stat` could not inspect, refusing the rule, checked against a verdict table of the real library (FREES-200); the PAM lines are read with the shared reader `pam_reader` in both libpam line assembly variants, and a NUL, a line of 1023 bytes or more, lines that the variants assemble differently, an include of a path in any form, a link below `/proc`, `/sys` or `/dev` and the `/etc/pam.conf` fallback refuse the rule, checked against the real libpam (FREES-212); `duplicate_setting`, `overridden`, `unreadable_file` and `unreadable_value` refuse to claim a change that would not take effect |
| `ssh` | 34 sshd keyword rules (`PermitRootLogin`, `MaxAuthTries`, `ClientAliveInterval`, `Ciphers`, `Banner` and the others) | `recorded_value`: one drop-in per rule, `00-freesecdev-<rule>.conf`, which sshd reads before every other file, and the one conflicting later line of a vendor file (`sshd_config`, `50-redhat.conf`) set to the rule's value in place | Both contents read the drop-ins and every later line (golden test); fixed values from the check, numeric and algorithm values from the profile; a conflicting later line in an administrator's drop-in or a `Match` block is `overridden`; every change validated with `sshd -T` through the `sshd_validate` module before it is written (`invalid_config`), and a drop-in counted as applied or compliant only when `sshd -T` prints its value (FREES-200), `overridden` for an earlier setting, `not_included` without the `Include`, `crypto_policy` on RHEL; sshd reloaded only where it runs; 29 rules `audit_only` with the reasons in ADR 0023 |
| `auditd_rules_time` | the five time change rules (`adjtimex`, `clock_settime`, `settimeofday`, `stime`, the `/etc/localtime` watch) | `recorded_value`: one drop-in per rule, `/etc/audit/rules.d/50-freesecdev-<rule>.rules`, with the collection's own lines per benchmark (`lines` keyed by benchmark identifier) | The shared helper `auditd_rules_dropins.yml` is the framework of every audit rule topic: a strict line form, `compliant` when another file already holds every line, `duplicate_rule` when only part, `watch_target_missing`; the set is checked for repeated rules, loaded with `augenrules --load` through `audit_control` only where auditd runs, verified with `auditctl -l` and rolled back when it fails; a declaration may choose the lifecycle profile (`profiles`) and declare loaded rules for libvirt (`audit_rules` with `drivers`) |
| `auditd_conf` | 20 settings of `/etc/audit/auditd.conf` | `recorded_value` of the prior line and the line written | Values from the profile or the check; an alternation is written least disruptive first; `duplicate_setting`, and `invalid_config` when auditd would refuse `space_left` and `admin_space_left` or `flush` and `freq` together; a running auditd reloads with `auditctl --signal reload` |
| `sudo` | `use_pty`, `logfile`, `timestamp_timeout`, `!targetpw`/`!rootpw`/`!runaspw` (STIG); mode, owner and group of `/etc/sudoers` and `/etc/sudoers.d` (ANSSI) | `recorded_value`: one drop-in per rule below `/etc/sudoers.d` with its SHA-256, or the prior attribute and the one written | Every write is checked by `visudo` through `copy` `validate` (the one reviewed exception of the repository guard); `timestamp_timeout` comes from the profile through the pinned `profile_value_id`; `conflicting_setting`, `not_included` and `invalid_sudoers` refuse to claim a change that would not take effect; rules that remove other people's `NOPASSWD`, `!authenticate` or user specifications stay `audit_only` |
| `login_defs` | `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`, `PASS_MIN_LEN`, `UMASK`, `FAIL_DELAY`, `CREATE_HOME` in `/etc/login.defs` | `recorded_value`: one line per setting, the prior line (or `null`) and the line written | A new family whose rules came from three others, which keep their toggles as subsystem tags; the strict form that both the check and shadow-utils read decides `compliant`, a stricter value is kept, and `duplicate_setting`, `overridden` (a libeconf drop-in) and symbolic links refuse; a pre-state sets an administrator's `lines` |
| `faillock`, `pwhistory` | `deny`, `unlock_time`, `fail_interval`, `root_unlock_time`, `even_deny_root`, `audit`, `silent` in `/etc/security/faillock.conf`; `remember`, `enforce_for_root` in `/etc/security/pwhistory.conf` | `recorded_value`: one line per setting in place or appended, the exact new text written with `copy` after a SHA-256 re-check, the prior line and the file's SHA-256 before the first write recorded | Two families share the helpers `pam_conf_*.yml`; values from the profile and a stricter value kept; two rules that share one line (`remember`) record the same prior state; the decision is the filter `pam_conf_decision`, which reads the file and the service files of the three PAM directories as linux-pam does (a symbolic link through the link; a link to nothing, to a special file or that `stat` cannot follow, and a PAM directory or entry that `find` or `stat` could not inspect, `unreadable_stack`, FREES-213; a link below `/proc`, `/sys` or `/dev` and the `/etc/pam.conf` fallback too, FREES-212), and the cleanup text the filter `pam_conf_restore`, whose last restore of a file must give back the recorded SHA-256 and is pinned to the real readers by a verdict table (`make pam-reader-verdicts`); a module argument or `conf=` on any PAM service file makes the rule `overridden` (`stack_checked`, pinned by a golden test against the OVAL); the stack is only read, and the rules that enable the modules in it stay `audit_only` until FREES-181 (ADR 0027) |
| `filesystem_modules`, `protocol_modules`, `wireless_modules` | 21 `kernel_module_<module>_disabled` rules, usb-storage included | `recorded_value`: one drop-in per rule, `/etc/modprobe.d/freesecdev-<module>.conf`, with the `install <module> /bin/false` and `blacklist <module>` lines that both contents require ([ADR 0028](adr/0028-native-kernel-module-drop-ins.md)) | Three families share the umbrella's helpers (`kernel_modules_*.yml`); the family reads every file that `modprobe` reads in its order, so a site file that already disables the module is `compliant` and one read first that lets it load is `overridden`; no module is unloaded and no initramfs rebuilt; the lifecycle runs them with the profiles that select them (`profiles` in the declaration) |
| `sysctl`, `ipv4_parameters`, `ipv6_parameters` | 65 kernel parameter rules (`kernel.dmesg_restrict`, `fs.protected_*`, `net.ipv4.conf.*.rp_filter`, `net.ipv4.ip_forward`, `net.ipv6.conf.*.accept_ra` and the others) | `recorded_value`: one drop-in per rule, `/etc/sysctl.d/999-freesecdev-<rule>.conf`, sorting after the distributions' files; the running value through the collection's `sysctl_runtime` module where the check needs it, with the value before (and every interface's forwarding flag) recorded; on Ubuntu the one conflicting line of a procps vendor file set in place | One helper for three topics; both contents read every `sysctl.conf` and `sysctl.d` file and the running value (golden test); values from the profile or the check, never from a fix; `overridden` and `conflicting_setting` for an administrator's file after or before the drop-in; `modified_since_read` when a vendor file changed between the read and the write (its SHA-256 is read again before the first write); `runtime_unavailable` where `/proc/sys` is read-only, and `linux_compliance_remediate_sysctl_runtime: false` for files only, as in the containers; the running half is proven in the libvirt cycles and a libvirt regression group; 11 rules `audit_only` with the reasons in ADR 0029 |
