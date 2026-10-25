# Collection design

The repository root is the collection root of `freesecdev.linux_compliance`. This page describes the skeleton and how
its tooling works. The component responsibilities are in the
[component map](../.agents/skills/architecture/references/component-map.md); the findings model is recorded in
[ADR 0013](adr/0013-normalized-findings-model.md).

Jira: FREES-39 (skeleton, metadata), FREES-26 (findings model), FREES-69 (ansible-lint hook).

## Layout

| Path | Purpose |
|---|---|
| `galaxy.yml` | Namespace `freesecdev`, name `linux_compliance`, Apache-2.0, repository links, tags and `build_ignore` |
| `meta/runtime.yml` | `requires_ansible: ">=2.20.0"` |
| `plugins/module_utils/compliance/` | Shared target-side code; currently `model.py`, the findings model |
| `plugins/{modules,action,filter,lookup}/` | Created together with the first plugin of each kind; Git cannot track empty directories and Galaxy does not need placeholders |
| `changelogs/` | antsibull-changelog `config.yaml`, `changelog.yaml` and `fragments/`; one fragment per Jira issue |
| `tests/unit/plugins/` | Unit tests that run under pytest and `ansible-test units` |
| `roles/` | Not created yet; the roles belong to FREES-40 |
| `.ansible-lint` | ansible-lint `production` profile |

Everything else (`tools/`, `.agents/`, `.github/`, the Python tooling files, `docs/planning`, `docs/research`) supports
development and is listed in `build_ignore`, so it is not part of the tarball.

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

`make install` creates the link; the targets that need it depend on it.

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
