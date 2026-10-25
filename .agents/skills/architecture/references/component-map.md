# Component map

Status: initial design, pending ADR acceptance. Update this file when components change.

## Repositories

| Repository | Responsibility | Consumes | Produces |
|---|---|---|---|
| `FreeSecDev/ansible-linux-compliance` | Collection, Molecule, Packer templates, reporting, docs | Runner image by digest | Collection tarball, golden images, reports |
| `FreeSecDev/linux-compliance-runner` | CI toolbox OCI image built in AWS | Alpine base by digest | Signed image, SBOM, provenance |

## Collection components

| Component | Location | Runs on | Responsibility |
|---|---|---|---|
| Findings model | `plugins/module_utils/compliance/model.py` | host and controller | Typed outcomes, rules, findings, provenance |
| Content catalog | `plugins/module_utils/compliance/catalog.py` | host | Locate, verify digests and describe SCAP content |
| Scanner protocol | `plugins/module_utils/compliance/scanner.py` | host | Backend-neutral audit interface |
| OpenSCAP backend | `plugins/module_utils/compliance/openscap.py` | host | Validated `oscap` execution, result parsing |
| Discovery modules | `plugins/modules/benchmark_info.py`, `profile_info.py` | host | List content, profiles and rules |
| Audit module | `plugins/modules/compliance_scan.py` | host | Run a backend, return normalized findings |
| Exceptions | `plugins/module_utils/compliance/exceptions.py`, `plugins/filter/` | controller | Validate and apply waivers |
| Roles | `roles/discover`, `roles/audit`, `roles/remediate`, `roles/verify`, `roles/evidence` | host | User-facing workflows |
| Remediation families | `roles/remediate/tasks/<family>.yml` | host | Native-module controls keyed by stable rule IDs |
| Playbooks | `playbooks/` | controller | Orchestration only |
| Reporting | `tools/reporting/` | controller and CI | Parse, normalize, aggregate, render HTML |
| Molecule | `extensions/molecule/` | CI and developer | Docker and libvirt scenarios |
| Packer | `extensions/packer/` | AWS build host | Data-driven golden images using the collection |

## Trust boundaries

1. Controller to managed host: Ansible transport, `become` scoped per task.
2. Managed host to controller: scan results and evidence are untrusted input.
3. Pull request to CI: fork code is untrusted and receives no credentials.
4. CI to AWS: OIDC with repository and ref pinned trust policies.
5. AWS build host to artifact storage: least-privilege, encrypted, lifecycle-managed.
6. Report to viewer: static HTML with all data escaped and no network access.
