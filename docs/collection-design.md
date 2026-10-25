# Collection design

The repository root is the collection root of `freesecdev.linux_compliance`. This page describes the skeleton and how
its tooling works. The component responsibilities are in the
[component map](../.agents/skills/architecture/references/component-map.md); the findings model is recorded in
[ADR 0013](adr/0013-normalized-findings-model.md).

Jira: FREES-39 (skeleton, metadata), FREES-26 (findings model), FREES-69 (ansible-lint hook), FREES-40 (role skeletons), FREES-41 (playbooks).

## Layout

| Path | Purpose |
|---|---|
| `galaxy.yml` | Namespace `freesecdev`, name `linux_compliance`, Apache-2.0, repository links, tags and `build_ignore` |
| `meta/runtime.yml` | `requires_ansible: ">=2.20.0"` |
| `plugins/module_utils/compliance/` | Shared target-side code; currently `model.py`, the findings model |
| `plugins/{modules,action,filter,lookup}/` | Created together with the first plugin of each kind; Git cannot track empty directories and Galaxy does not need placeholders |
| `changelogs/` | antsibull-changelog `config.yaml`, `changelog.yaml` and `fragments/`; one fragment per Jira issue |
| `tests/unit/plugins/` | Unit tests that run under pytest and `ansible-test units` |
| `roles/` | The `discover`, `audit`, `remediate`, `verify` and `evidence` role skeletons (FREES-40) |
| `playbooks/` | Orchestration playbooks `audit.yml`, `remediate.yml` and `verify.yml` |
| `.ansible-lint` | ansible-lint `production` profile |

Everything else (`tools/`, `.agents/`, `.github/`, the Python tooling files, `docs/planning`, `docs/research`) supports
development and is listed in `build_ignore`, so it is not part of the tarball.

## Roles and playbooks

The roles are skeletons. Each one validates its inputs and then fails with a message that names the issue that
tracks its implementation, so a playbook can never report success for work that does not exist yet. They use only
`ansible.builtin.assert` and `ansible.builtin.fail`. The platforms in each `meta/main.yml` are intended targets
([ADR 0010](adr/0010-initial-os-and-benchmark-scope.md)); none is tested.

| Role | Changes the host | Tracked in | Variables (default) |
|---|---|---|---|
| `discover` | Never | FREES-43 | `linux_compliance_discover_profile` (`cis_level1_server`) |
| `audit` | Never | FREES-49 | `linux_compliance_audit_profile` (`cis_level1_server`), `linux_compliance_audit_fail_on_noncompliant` (`false`) |
| `remediate` | Only with explicit opt-in | FREES-52 | `linux_compliance_remediate_enabled` (`false`), `linux_compliance_remediate_allow_disruptive` (`[]`), `linux_compliance_remediate_profile` (`cis_level1_server`) |
| `verify` | Never | FREES-54 | `linux_compliance_verify_profile` (`cis_level1_server`), `linux_compliance_verify_fail_on_regression` (`true`) |
| `evidence` | Never; writes on the controller only | FREES-51 | `linux_compliance_evidence_output_dir` (`evidence`), `linux_compliance_evidence_include_host_facts` (`false`) |

Per-rule and per-family toggles do not exist yet; they are generated from the rule catalogue by FREES-55
([ADR 0011](adr/0011-control-toggles-and-cleanup.md)). The variables of each role are documented in its
`README.md` and in `meta/argument_specs.yml`.
`tools/roles/check_role_specs.py` (part of `make lint-ansible`) fails when a role's `defaults/main.yml` and
`meta/argument_specs.yml` disagree in names, types or values, when an option lacks a description or default, or when
a variable lacks the `linux_compliance_<role>_` prefix.

The playbooks `playbooks/audit.yml`, `playbooks/remediate.yml` and `playbooks/verify.yml` only reference roles by
FQCN, for example `freesecdev.linux_compliance.audit`. The target comes from the variable
`linux_compliance_target_hosts`, which defaults to the group `linux_compliance` so that no play ever targets `all` by accident (usage in
[playbooks](playbooks.md)). `become` is scoped to the role entry and is never set for the whole play; the
`discover` role runs without it.

## Supported versions

`requires_ansible` is `>=2.20.0`. The ansible-core support matrix lists 2.20 with managed-node Python 3.9 to 3.14, so
code in `plugins/modules` and `plugins/module_utils` must run on Python 3.9 and use only the standard library
([ADR 0013](adr/0013-normalized-findings-model.md)). The developer environment pins ansible-core 2.21.5, the latest
release that is at least seven days old, which is used by `ansible-lint`, `ansible-test` and `ansible-galaxy`.

## The temporary collection tree

`ansible-test` only runs inside a path of the form `ansible_collections/<namespace>/<name>`, and the repository is not
laid out that way. The repository is not restructured. Two generated trees under `build/` (ignored by Git) bridge the
gap:

- `make collection-tree` copies the collection files tracked by Git into
  `build/collection/ansible_collections/freesecdev/linux_compliance`, initializes a throwaway Git repository there so
  that `ansible-test` can enumerate the files, and excludes `tests/output`. It is a copy, not a symlink, because
  `ansible-test` resolves its working directory and rejects symlinks that leave the tree. Only collection content is
  copied, so developer tooling is never sanity-tested as collection code.
- `make collection-link` creates `build/collections/ansible_collections/freesecdev/linux_compliance/plugins`, a
  symlink to `plugins/`. pytest, mypy, Pyright and Pylint put `build/collections` on their search path so that tests
  import `ansible_collections.freesecdev.linux_compliance.plugins...`, the same name `ansible-test` uses. Coverage
  resolves the symlink, so measured files are the real ones.

The link directory also links `roles/`, so ansible-lint can resolve the role references in the playbooks. `make lint-ansible` and the ansible-lint hook set
`ANSIBLE_COLLECTIONS_PATH` to `build/collections` for that one invocation only; the repository has no `ansible.cfg`,
which would override users' own Ansible configuration, and `ansible.cfg` is listed in `build_ignore`.
`make install` creates the links; the targets that need them depend on it.

## Targets

| Target | What it does |
|---|---|
| `lint-ansible` | `ansible-lint` with the `production` profile, then `antsibull-changelog lint` |
| `test-unit`, `test-coverage` | pytest including the plugin tests; coverage requires 100% for `tools/` and `plugins/` |
| `test-sanity` | `ansible-test sanity --local` on the temporary tree, no Docker |
| `test-ansible-units` | `ansible-test units --venv` on Python 3.9, 3.12 and 3.14, no Docker |
| `package` | `ansible-galaxy collection build` repacked with a canonical `FILES.json`, into `dist/`, with `dist/SHA256SUMS` |
| `package-check` | Builds twice from differently ordered trees and compares the SHA-256 values |

`ansible-test sanity` runs with `--local` rather than `--venv`. Sanity tests install their own pinned requirements in
isolated virtual environments either way, and `--local` avoids a second delegation virtual environment inside the
tree, which adds minutes and files that the `symlinks` and `pylint` tests then inspect. The interpreters that
`compile` and `import` need (3.9, 3.10, 3.11, 3.13, 3.14) are installed with `uv python install`, so those tests run
on every managed-node Python version instead of being skipped. Units use `--venv` because each interpreter needs its
own pytest.

`package` builds from the temporary tree, so `build_ignore` is applied to a tree that already holds only collection
content. Two things in the `ansible-galaxy` output depend on the machine: it stamps the build time into the archive,
and it writes the `FILES.json` entries in `os.listdir` order, which differs between filesystems. The target therefore
unpacks the result, sorts the `FILES.json` entries by name, recomputes the `FILES.json` checksum in `MANIFEST.json`,
asserts that the order is sorted, and repacks with sorted members, owner 0, a zero modification time and a gzip header
without name or time. `make package-check`, which CI runs, builds twice from trees created in opposite file order and
fails unless the two SHA-256 values are identical. The remaining assumption is the same `tar`, `gzip` and `jq`
behaviour; byte-identical output across different machines was checked by comparing a local build with the CI build of
the same commit (see the pull request that introduced it).

## Adding plugins

1. Put target-side logic in `plugins/module_utils/compliance/<area>.py`, standard library only and Python 3.9 compatible.
2. Add the module in `plugins/modules/`, with complete `DOCUMENTATION`, `EXAMPLES` and `RETURN`.
3. Mirror the tests under `tests/unit/plugins/`, keeping 100% line and branch coverage of `plugins/`.
4. Add a changelog fragment in `changelogs/fragments/`.
5. Run `make ci`.
