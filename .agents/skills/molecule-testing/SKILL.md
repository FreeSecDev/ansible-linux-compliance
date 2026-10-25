---
name: molecule-testing
description: Designing and running Molecule scenarios for the freesecdev.linux_compliance collection under extensions/molecule, using Docker and libvirt. Use when adding or changing scenarios, create/destroy/prepare/verify playbooks, golden image consumption, idempotence and check-mode tests, negative tests, or expected-findings assertions. Enforces the shell/command ban, digest-pinned images, isolated libvirt networks and a guard that never touches the developer host.
license: Apache-2.0
metadata:
  owner: test-lead
  version: "1.0.0"
---

# Molecule testing

Proves that roles and modules behave on real operating systems, never on the developer host.
A scenario that did not run is not evidence.

## When to use

- Adding, changing or debugging a scenario under `extensions/molecule/<scenario>/`.
- Writing create, destroy, prepare, converge or verify playbooks.
- Adding negative, check-mode, diff-mode, idempotence or baseline-regression tests.
- Consuming golden images from `extensions/packer/images.lock.json`.
- Producing testing status evidence for `docs/support-matrix.yml`.

## Inputs

- Jira issue key and the roles or modules under test.
- The image manifest `extensions/packer/images.lock.json` and the container digests pinned in the scenario configuration.
- Expected findings fixtures per OS and profile.
- The Molecule, community.docker and community.libvirt versions pinned in the toolbox lock files.

## Outputs

- Scenario directories with `molecule.yml`, `create.yml`, `prepare.yml`, `converge.yml`, `verify.yml`, `destroy.yml`.
- Expected-findings files and adversarial inputs for verify steps.
- CI and local run logs linked from the Jira issue.

## Conventions

- Scenarios use flat names under `extensions/molecule/`: `docker-ubuntu`, `docker-rhel-compatible`, `libvirt-ubuntu-bare`, `libvirt-rhel-bare`, `libvirt-negative`, `libvirt-idempotency`, `libvirt-ubuntu-golden`, `libvirt-rhel-golden`, `libvirt-baseline-regression`, `libvirt-remediation`. The final layout is confirmed by ADR; follow the ADR if it differs.
- Playbooks obey the shell and command ban. Use `community.docker`, `community.libvirt`, native modules or project modules; missing capability becomes a module, never `command`.
- Container images are pinned by digest. Privileged containers only when required and documented in the scenario; tests meaningless in containers (bootloader, mounts, kernel parameters, systemd-dependent services) are marked and run in libvirt.
- Golden images come from the shared manifest with SHA-256, verified before boot. See [references/scenario-matrix.md](references/scenario-matrix.md).
- libvirt scenarios use an isolated NAT network, unique per-run names (domain, volumes, network), and guaranteed teardown on failure.
- A guard task fails the run if any target resolves to `localhost`, `127.0.0.1` or uses `connection: local`, so the developer host is never modified.
- Sequence: create, prepare, converge, idempotence, verify, compliance scan, expected-findings assertions, destroy.
- Idempotence requires zero unexpected changes; volatile scanner output, timestamps and report paths are normalized or excluded explicitly, never by blanket `changed_when: false`.
- Cover check mode, diff mode, negative cases, invalid profile, unavailable scanner and an audit-only run asserting no host change.
- Expected findings are explicit fixtures; a scenario fails on both missing and unexpected findings.

## Quality gates

- Each scenario passes the full sequence in CI, with logs retained.
- The banned-module guard finds nothing in `extensions/`.
- Idempotence step reports zero unexpected changes; volatility handling is documented in the scenario.
- Negative scenarios fail for the expected reason, asserted by message or error type.
- Teardown runs after a forced failure in a test of the destroy path.
- Support matrix testing status is updated only from runs that executed.

## Common failures

- Using `command` for `virsh`, `docker exec` or `oscap` in a helper playbook.
- Tags such as `latest` for images, or a golden image used without checksum verification.
- Shared domain or network names that collide between concurrent runs.
- Teardown skipped when converge fails, leaving VMs and networks behind.
- Silencing idempotence failures with `changed_when: false` on real changes.
- Running container scenarios for controls that need a real kernel or bootloader.
- Claiming success from a scenario that was skipped or only linted.

## Security requirements

- No credentials or private keys in scenario files; generate ephemeral keys per run and delete them at teardown.
- Libvirt networks are isolated; no bridging to the host network or exposure of services.
- Test VMs never receive production secrets or real compliance content that is restricted.
- Containers drop capabilities by default; any exception is documented and reviewed.

## Documentation requirements

- Document how to run each scenario locally and in CI, prerequisites and expected runtime in `docs/`.
- Document volatility handling and expected-findings fixtures.
- Update ADRs when scenario layout or naming changes.

## Completion criteria

- All relevant scenarios executed and passed, with links recorded in Jira.
- No leftover VMs, networks, volumes or containers after the run.
- Negative, check-mode, diff-mode and audit-only assertions are present for changed behaviour.
- Matrix testing status reflects exactly what ran.

## Interaction with other skills

- Exercises roles written under the `ansible-collection` skill and modules from the `ansible-modules` skill.
- Consumes golden images produced under the `packer-images` skill.
- Gets expected findings and support matrix rules from the `compliance-frameworks` skill.
- Runs in workflows defined by the `github-actions` skill.
- Isolation and host-safety changes go to the `security-review` skill.
