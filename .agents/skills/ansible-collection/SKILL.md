---
name: ansible-collection
description: Authoring and maintaining the freesecdev.linux_compliance Ansible collection layout, roles (discover, audit, remediate, verify, evidence), orchestration playbooks, galaxy metadata and changelog fragments. Use when adding or changing roles, tasks, argument specs, defaults, playbooks, remediation task files per control family, ansible-lint or ansible-test sanity configuration, or collection metadata. Enforces the shell/command ban, FQCN, safe defaults and native-module-only remediation.
license: Apache-2.0
metadata:
  owner: ansible-lead
  version: "1.0.0"
---

# Ansible collection

Keeps roles and playbooks small, idempotent, check-mode safe and free of shell execution.
Remediation is opt-in, narrow per control family and implemented only with native modules.

## When to use

- Adding or changing any role under `roles/` (`discover`, `audit`, `remediate`, `verify`, `evidence`) or any playbook under `playbooks/`.
- Adding a remediation control or a new control family file under `roles/remediate/tasks/`.
- Changing `galaxy.yml`, `meta/runtime.yml`, `meta/argument_specs.yml`, ansible-lint or ansible-test sanity configuration.
- Adding a changelog fragment for a user-visible collection change.
- Writing Molecule or test playbooks that call collection roles (the same bans apply).

## Inputs

- Jira issue key, acceptance criteria and the ADRs that govern the interface being changed.
- The component layout in the `architecture` skill reference `component-map.md` and current role argument specs.
- ComplianceAsCode rule IDs for any control being implemented, with the family it belongs to.
- The ansible-core and Python versions pinned in `galaxy.yml`, `meta/runtime.yml` and the toolbox lock files.

## Outputs

- Role, playbook and metadata changes with `meta/argument_specs.yml` kept in sync with `defaults/main.yml`.
- Remediation task files `roles/remediate/tasks/<family>.yml`, one narrow family per file.
- A fragment in `changelogs/fragments/` for each user-visible change.
- Passing `make lint-ansible` and `make test-sanity` output.

## Conventions

- Every YAML file starts with `---`. No inline comments; explain through names, argument specs and `docs/`.
- Use fully qualified collection names for every module, role, filter and lookup.
- Never use `ansible.builtin.shell`, `ansible.builtin.command`, `ansible.builtin.raw`, `ansible.builtin.script` or aliases, including in Molecule and test playbooks. Do not disguise shell with `ansible.builtin.expect`, `ansible.builtin.template` plus execution, or similar. Missing functionality becomes a module or `module_utils` code (see `ansible-modules`).
- Every role has `meta/argument_specs.yml`. Role variables are prefixed `linux_compliance_<role>_`; internal facts are prefixed `__linux_compliance_<role>_`.
- Safe defaults: `linux_compliance_remediate_enabled: false`. Disruptive controls (SSH, PAM, sudo, firewall, network, bootloader, mounts, crypto policy) run only when named in an explicit allow-list such as `linux_compliance_remediate_allow_disruptive: []`.
- Every rule is toggleable ([ADR 0011](../../../docs/adr/0011-control-toggles-and-cleanup.md)): flat booleans `linux_compliance_<family>_enabled` per topic and `linux_compliance_rule_<rule_short_id>_enabled` per rule, defaulting to the family toggle. Never use nested toggle dictionaries.
- Every rule has an apply path and a revert path. Disabling a rule that the state ledger records as applied triggers cleanup back to the recorded prior state. Prefer collection-owned drop-in files so cleanup is a file removal.
- New rules are added to the rule catalogue `roles/remediate/vars/rules.yml` with family, rule ID, disruptive flag and revert strategy; defaults and argument specs are generated from it.
- `roles/remediate/tasks/main.yml` only dispatches: validate inputs, then include the family files. Logic lives in family files.
- Each family file implements controls keyed by stable ComplianceAsCode rule ID, only with native modules. ComplianceAsCode generated playbooks use shell and command and must never be imported or copied. See [references/remediation-families.md](references/remediation-families.md).
- Honour check mode and diff mode: native modules with `check_mode` support, no tasks that are skipped in check mode to hide changes.
- Scope `become` at task or block level, never play-wide for discovery and audit.
- Use handlers for service reloads and restarts, named with the role prefix.
- Set `no_log: true` on tasks handling secrets, tokens or credentials hashes.
- Defaults in `defaults/main.yml`, constants in `vars/main.yml`, templates in `templates/`, static files in `files/`.
- Lint profile is `production`. Suppressions need a justification in the lint config or ADR; see [references/lint-and-metadata.md](references/lint-and-metadata.md).
- Changelogs use antsibull-changelog fragments with one fragment per Jira issue.

## Quality gates

- `make lint-ansible` passes with the ansible-lint `production` profile and no unjustified suppression.
- `make test-sanity` (ansible-test sanity) passes for the supported ansible-core versions.
- A grep-based guard finds no banned module names or aliases anywhere in the repository.
- `galaxy.yml` and `meta/runtime.yml` (`requires_ansible`) are consistent with tested versions.
- Molecule converge is idempotent and honours check and diff mode (see `molecule-testing`).
- Every new variable appears in `defaults/main.yml`, `meta/argument_specs.yml` and `docs/`.

## Common failures

- Reaching for `command` to call `oscap`, `sysctl`, `systemctl` or `grubby` instead of a module.
- Importing ComplianceAsCode generated remediation playbooks, which embed shell.
- Putting control logic in `tasks/main.yml` until it becomes a monolith.
- Enabling a disruptive control because the family is selected, without the allow-list entry.
- Implementing apply without revert, or treating "stopped managing it" as cleanup.
- Guessing a prior value during cleanup instead of using the ledger, or reverting a disruptive family without its allow-list entry.
- Using `changed_when: false` or `ignore_errors` to hide non-idempotence or failures.
- Variables without the role prefix, undocumented defaults, or argument specs that drift from defaults.
- Short module names (`copy`, `lineinfile`) instead of FQCN.
- Remediation running in audit playbooks, or audit tasks changing host state.

## Security requirements

- Audit and discover roles never change a managed host; remediation requires `linux_compliance_remediate_enabled: true`.
- Disruptive changes require the allow-list and must keep a recovery path (validated config, `validate:` parameters, backups).
- File modes and ownership are explicit; sensitive files are never world-readable.
- Secrets are never logged, templated into reports or stored in defaults.
- Never lower the safe defaults to make a test pass.

## Documentation requirements

- Document each role variable, family and rule ID covered in `docs/`; never claim rules that are not implemented.
- Update the support matrix when remediation availability changes (see `compliance-frameworks`).
- Add an ADR for changes to role interfaces, variable naming or the family layout.
- Add or update a changelog fragment in the same pull request.

## Completion criteria

- Lint, sanity, banned-module guard and Molecule scenarios pass in CI, not only locally.
- Argument specs, defaults and docs agree; the changelog fragment exists.
- New remediation controls have a rule ID, a catalogue entry, a toggle, a revert path, a family file, a negative test, a check-mode test and a toggle-off cleanup test proving the prior state is restored idempotently.
- Jira issue records the pull request, CI links and any suppression justifications.

## Interaction with other skills

- Follows interface decisions from the `architecture` skill and requests an ADR when interfaces change.
- Delegates Python modules and `module_utils` to the `ansible-modules` skill.
- Takes rule IDs, profiles and classification from the `compliance-frameworks` skill.
- Relies on the `molecule-testing` skill for converge, idempotence and check-mode proof.
- Hands workflow wiring to the `github-actions` skill and release steps to the `release-engineering` skill.
- Escalates privilege and disruptive-control changes to the `security-review` skill.
