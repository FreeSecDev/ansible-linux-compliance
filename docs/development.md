# Development guide

The `Makefile` is the single entry point for developers and CI. `make ci` runs every implemented,
credential-free stage locally and is what the pull request workflow runs, split into jobs.

Jira: FREES-68 (Makefile), FREES-69 (pre-commit), FREES-70 (Python tooling),
FREES-71 (pull request workflow), FREES-91 (skill validator tests), FREES-39 (collection skeleton and
ansible tooling), FREES-26 (findings model), FREES-69 (ansible-lint hook), FREES-40 (role skeletons),
FREES-30, FREES-31, FREES-33, FREES-34 (AWS bootstrap, OpenTofu, Checkov), FREES-127 (per-checkout Ansible home),
FREES-59 (Docker Molecule scenarios).

## Bootstrap

Requirements: `git`, GNU `make`, [`jq`](https://jqlang.org/) (used by `make package`) and
[`uv`](https://docs.astral.sh/uv/). Python 3.12 is selected by
`.python-version` and installed by `uv` when missing.

```text
make bootstrap
make help
```

`make bootstrap` runs `uv sync --frozen` (exact versions from `uv.lock`), installs the `pre-commit` and
`pre-push` git hooks and prints tool versions. A missing `uv` produces an error with install instructions. `make bootstrap` also checks that
`jq` is on `PATH` and fails with an install hint when it is missing, because `make package` cannot run without it.
`make bootstrap` also requires OpenTofu `1.13.2` on `PATH`; install the pinned, checksum-verified release with
`tools/iac/install-tofu.sh`. Packer checks join with FREES-64.

## Per-checkout Ansible home

Every checkout, including each git worktree, has its own Ansible home, so parallel checkouts never share installed
collections, caches or temporary files, and a stale copy of this collection under `~/.ansible/collections` can no
longer shadow the working tree (FREES-127). The `Makefile` sets and exports these variables for every recipe:

| Variable | Default | Used by |
|---|---|---|
| `ANSIBLE_HOME` | `build/ansible-home` | ansible-core (`ansible-playbook`, `ansible-galaxy`) and ansible-lint, which otherwise use `~/.ansible` for temporary files, the Galaxy cache, the lint mocks and the collections path that ansible-lint puts first |
| `ANSIBLE_COLLECTIONS_PATH` | `build/collections` | Collection lookup: the links that `make collection-link` creates, never `~/.ansible/collections` |
| `ANSIBLE_TEST_HOME` | `build/ansible-test-home` | `HOME` of `ansible-test` only, because it keeps its sanity virtual environments under a fixed `~/.ansible/test/venv` |

The defaults are absolute paths below the checkout. A value from the environment or the command line wins, for
example `make lint-ansible ANSIBLE_HOME=/var/tmp/ansible-home`. `make collection-link` and `make collection-tree`
create the directories through `ansible-home`, so every target that runs Ansible tooling has them: `lint-ansible`,
`test-sanity`, `test-ansible-units`, `package`, `package-check`, `test-audit-exceptions`, `test-evidence`,
`test-remediate-check`, `test-role-guards`, and
the Molecule targets once they are implemented. The ansible-lint pre-commit hook runs `make lint-ansible`, so it uses
the same paths and needs no manual `ANSIBLE_HOME`. `make clean` removes `build/`, and with it the default Ansible home
and the `ansible-test` home; it never removes a directory given as an override.

`make ci` writes nothing below `~/.ansible`. This was checked with an empty temporary `HOME`, and with a temporary
`HOME` whose `~/.ansible/collections` held an old copy of this collection, in two worktrees running `make ci` at the
same time. Molecule and other tools added later must keep that property: use the exported variables instead of
overriding them.

## Makefile targets

| Target | Status | What it does |
|---|---|---|
| `help` | implemented | Prints this target list |
| `bootstrap` | implemented | `install` plus tool version check |
| `install` | implemented | `uv sync --frozen`, installs both git hook types |
| `format` | implemented | `ruff check --fix` and `ruff format` |
| `lint` | implemented | `uv lock --check`, `lint-repo`, `lint-skills`, `lint-python`, `lint-yaml`, `lint-actions`, `lint-containerfile`, `lint-ansible`, `lint-toggles`, `lint-role-guards`, `lint-lifecycle` |
| `lint-ansible` | implemented | `molecule-dependencies`, then `ansible-lint` with the `production` profile, `tools/roles/check_role_specs.py`, then `antsibull-changelog lint` |
| `lint-toggles` | implemented | `tools/roles/generate_toggles.py --check`: fails with a diff when the generated toggle defaults, argument specs or `docs/remediation-variables.md` differ from the rule catalogue ([remediation guide](remediation.md#generated-toggles)) |
| `toggles` | implemented | Regenerates the topic toggle defaults, the topic toggle argument specs and the allow-list choices of the `remediate` and `audit` roles and `docs/remediation-variables.md` from `roles/remediate/vars/rules.yml` |
| `lint-role-guards` | implemented | `tools/roles/generate_role_guards.py --check`: fails with a diff when `roles/remediate/tasks/dispatch.yml` or a `tasks/internal_variables.yml` of the audit, evidence, remediate or verify role differs from what the family registry and the role files give, or a role with internal variables is not guarded (FREES-137, FREES-153) |
| `lint-lifecycle` | implemented | `tools/roles/check_lifecycle_topics.py`: fails when a topic with a native rule in the catalogue has no Molecule toggle lifecycle declaration in `extensions/molecule/shared/vars/topics/`, when a declaration names a topic without a native rule, or when a declaration does not follow the format ([Molecule](molecule.md#toggle-lifecycle-of-every-native-topic), FREES-60) |
| `molecule-matrix` | implemented | `tools/roles/molecule_matrix.py`: prints the CI legs of `MOLECULE_MATRIX_DRIVER` (`docker` or `libvirt`) as JSON, one per platform, native topic with a cycle of that driver and toggle mode; for libvirt also the base leg of each platform and the self-test ([libvirt](molecule-libvirt.md#ci)) |
| `role-guards` | implemented | Regenerates the static family dispatch of the remediate role, with one include per family that has a native rule, and the internal-variable guards of the audit, evidence, remediate and verify roles |
| `content` | implemented | `tools/content/fetch_content.py --output-dir build/content`: fetches the pinned release archive and extracts the verified datastreams |
| `catalogue` | implemented | `tools/roles/generate_catalogue.py`, then `toggles` and `role-guards`: regenerates `roles/remediate/vars/rules.yml` and `docs/control-families.md` from the datastreams in `build/content` and the family mapping `content/catalogue.yml` (run `make content` first) |
| `lint-python` | implemented | Ruff lint, Ruff format check, Pylint (`tools`, `tests`, `plugins`) |
| `lint-yaml` | implemented | `yamllint --strict` |
| `lint-actions` | implemented | actionlint |
| `lint-repo` | implemented | `tools/lint/check_repo_rules.py` on every tracked and new file, including symbolic links and files without a suffix; it refuses compiled module files (`.so`, `.pyd`, `.pyc`, `.pyo`, `.fwork`, any case) and code outside `plugins/` in a location from which Ansible loads code (FREES-156) |
| `lint-skills` | implemented | `tools/skills/validate_skills.py` |
| `security` | implemented | Bandit (`tools`, `plugins`), Checkov on `infra/`, gitleaks history scan, zizmor (pedantic persona) |
| `aws-bootstrap` | implemented | Renders and runs the one-time interactive AWS account bootstrap ([docs/aws/bootstrap.md](aws/bootstrap.md)); never run by CI |
| `typecheck` | implemented | mypy strict, Pyright strict |
| `test` | implemented | Alias for `test-unit` |
| `test-unit` | implemented | `pytest tests/unit`, including the collection plugin tests |
| `test-coverage` | implemented | Unit tests with branch coverage, 95% overall, 100% on `tools/` and on `plugins/` |
| `test-name-sets` | implemented | `NAME_SET_PYTHON=<version>`: probes that interpreter with `python -I -S` and checks the guard name sets against it (subset, and equality with the recorded snapshot of the same release); run by the `name-sets` CI matrix |
| `name-sets` | implemented | Probes Python 3.9 to 3.15 (`uv python find`) and regenerates `tools/lint/name_sets.json` and the name-set constants of the guard |
| `test-sanity` | implemented | `ansible-test sanity --local` on the temporary collection tree, no Docker; installs Python 3.9 to 3.14 with `uv python install` |
| `test-ansible-units` | implemented | `ansible-test units --venv` on Python 3.9, 3.12 and 3.14, no Docker |
| `molecule-dependencies` | implemented | Installs the collections of `extensions/molecule/collections.pins` into `build/collections` with `ansible-galaxy --offline`, from files whose SHA-256 and size match the pins; outside GitHub Actions it runs `molecule-collections-fetch` first ([Molecule](molecule.md#galaxy-collections)) |
| `molecule-collections-fetch` | implemented | Downloads the pinned collection artifacts from Galaxy with bounded retries into `build/molecule-collections`, checks each one and reuses verified files; the only target that contacts Galaxy |
| `molecule-collections-lock` | implemented | Writes `extensions/molecule/collections.pins` from Galaxy's metadata for the exact versions of `extensions/molecule/requirements.yml`; run it after Renovate raises a version |
| `molecule-images-build` | implemented | Builds or reuses each Docker instance image with bounded, timed attempts, verifies it against its inputs label and the pinned base layers, saves it to `build/molecule-images` and records its image ID (the CI job `molecule-images`) |
| `molecule-images-plan` | implemented | Prints `<image>=<tag>` for each Docker instance image, for `$GITHUB_OUTPUT` |
| `molecule-images-ids` | implemented | Prints the verified `<image>=<image ID>` pairs that the Docker legs check |
| `molecule-content` | implemented | Fetches and verifies the pinned `ubuntu2404` and `rhel9` datastreams into `build/content` for the Molecule scenarios |
| `test-molecule-docker` | implemented | `molecule-dependencies`, `molecule-content`, the instance images of the selected scenarios (built or reused locally; in GitHub Actions only loaded from `build/molecule-images` and checked against `MOLECULE_IMAGE_IDS`), then `molecule test` for `docker-ubuntu`, `docker-rhel-compatible` and their toggle lifecycle scenarios `docker-ubuntu-lifecycle` and `docker-rhel-compatible-lifecycle` (stops at the first failure), then `test-molecule-docker-selftest` unless `MOLECULE_DOCKER_SELFTEST=false`. The lifecycle runs every native topic in both toggle modes unless `MOLECULE_LIFECYCLE_TOPIC` and `MOLECULE_LIFECYCLE_MODE` select one; needs a running Docker daemon, see [Molecule](molecule.md) |
| `molecule-matrix` | implemented | `tools/roles/molecule_matrix.py`: prints the CI matrix of the toggle lifecycle legs as one line of JSON, one leg per Molecule platform, native topic and toggle mode ([Molecule](molecule.md#ci-legs)) |
| `test-molecule-docker-selftest` | implemented | Real guard bypass attempts and the label-based destroy fallback against containers of the `docker-selftest` scenario, see [Molecule](molecule.md#self-test-against-real-containers) |
| `package` | implemented | `ansible-galaxy collection build` repacked with a canonical `FILES.json`, into `dist/`, plus `dist/SHA256SUMS` |
| `package-check` | implemented | Builds twice from differently ordered trees and fails unless the SHA-256 values match |
| `collection-tree` | implemented | Copies the collection files into `build/collection/ansible_collections/freesecdev/linux_compliance` |
| `collection-link` | implemented | Links `plugins/` and `roles/` into `build/collections` for pytest, the type checkers, ansible-lint and `test-remediate-check` |
| `ansible-home` | implemented | Creates `ANSIBLE_HOME` and `ANSIBLE_TEST_HOME` ([per-checkout Ansible home](#per-checkout-ansible-home)); a prerequisite of `collection-link` and `collection-tree` |
| `test-remediate-check` | implemented | Runs `tests/playbooks/remediate-check-mode.yml` against localhost with `--check --diff` and again with `--skip-tags file_permissions`, then `tests/playbooks/remediate-skip-always.yml` with `--skip-tags always`, all without `become`; the toggle plays also run the audit role's toggle resolution ([remediation guide](remediation.md#testing)). Runs `test-remediate-disruptive` first |
| `test-remediate-disruptive` | implemented | Copies the collection into `build/test-remediate-disruptive`, promotes the `ssh` rule `sshd_disable_root_login` to a native rule there with `tools/roles/promote_native_rule.py`, and runs `tests/playbooks/remediate-disruptive.yml` against the copy in check mode: the rule is skipped as `disruptive_not_allowed` without the allow-list and planned for apply, failing closed, with it (FREES-153) |
| `docs` | implemented | markdownlint-cli2 and the relative link checker |
| `clean` | implemented | Removes caches, coverage output and `build/`, including the per-checkout Ansible home |
| `test-role-guards` | implemented | Runs `tests/playbooks/internal-variables-include.yml`, `internal-variables-extra.yml` (four times: a forged plan and a forged family, and both forged as the sentinel string, as extra variables) and `internal-variables-role-param.yml` (per host) against localhost with `--check`, and fails unless every forged internal role variable is refused before the remediate role reads the ledger |
| `ci` | implemented | `lint lint-iac typecheck test-coverage test-browser test-audit-exceptions test-evidence test-remediate-check` (with `test-remediate-disruptive`) `test-role-guards test-verify security docs test-sanity test-ansible-units package-check` |
| `test-evidence` | implemented | Runs the evidence role against local inventory hosts with synthetic audit results and fixture files: bundle content, provenance, permissions, planted secrets, carried target facts and SCE output, a refused second collection, and fail-closed checksum, path, host-symlink and exceptions-file mismatches; reports on the bundles with `--exceptions-file`, refuses them without it or with another file, and rejects a tampered copy; then runs the plays of `playbooks/evidence.yml` with the gate on and checks that failing and incomplete hosts are collected, missing hosts are named and the play still fails; and checks that no variable route (`-e`, `group_vars`, `host_vars`, include or role import parameters) defers the audit gate ([evidence bundles](evidence.md#tests)) |
| `test-audit-exceptions` | implemented | Runs the audit role's exceptions path (`evaluate.yml` and `stale.yml` entry points) against two local inventory hosts with synthetic scan runs, without `oscap`, with the per-checkout `ANSIBLE_HOME`; checks the stale report under `--limit`; then requires that an invalid file, per-host files under `serial` and the `free` strategy fail the play. The `free` case runs `AUDIT_EXCEPTIONS_FREE_RUNS` times (default 10), and each time every host must have been refused or must have applied exactly the validated SHA-256 (FREES-143, [audit guide](audit.md#tests)) |
| `test-verify` | implemented | Runs the verify role (`baseline.yml` and `main`) on the local inventory host `web01` with synthetic baseline and later audits, without `oscap`, with the per-checkout `ANSIBLE_HOME`; requires the printed regression and applicability warnings, then that baselines not recorded by `baseline.yml` (extra, play, host and inventory variables, a pre-set marker, none at all) are refused and that `--skip-tags always` fails the role ([verify guide](verify.md#tests)) |
| `test-browser` | implemented | Dashboard browser and accessibility tests in the pinned headless Chromium with axe-core; fetches both into `build/browser-test` first (`browser-test-deps`), see the [dashboard guide](dashboard.md) |
| `lint-containerfile` | implemented | hadolint 2.15.1 (pinned by SHA-256, fetched into `build/tools` by `tools/lint/fetch-hadolint.sh`) on `extensions/ci/scc/Containerfile` with `--failure-threshold info`; part of `make lint` |
| `scc-expiry-check` | implemented | Fails from seven days before `SCC_EXPIRES` (`tools/scc/check-expiry.sh`); a prerequisite of `scc-image`, so an expiring SCC is never built or run ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md#7-version-updates-manual-pin-bump)) |
| `scc-fetch` | implemented | Downloads the pinned SCC bundle from the DISA host into `build/scc/download` (or reuses a copy whose SHA-256 matches), cross-checks the published checksum file, extracts only the pinned Debian package and stages it in `build/scc/context` ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md)) |
| `scc-image` | implemented | `scc-expiry-check`, `lint-containerfile` and `scc-fetch`, then `docker build --network none` of the CI-only SCC image as `SCC_IMAGE` (default `localhost/freesecdev-scc:local`; only `localhost/` tags are accepted). The image is never pushed |
| `scc-smoke` | implemented | `scc-image`, then runs `cscc --version` in the image with no network, no capabilities, `no-new-privileges` and a read-only root file system, and requires the pinned version. Needs Docker; not part of `make ci` |
| `scc-release-watch` | implemented | Runs `tools/scc/release_watch.py`: fetches only NIWC Atlantic's `scc_release.xml`, parses it with the hardened XML reader, compares its version with `SCC_VERSION` and reports the expiry phase of `SCC_EXPIRES` (warning from 21 days before, hard stop from seven). Never downloads SCC. Exits 1 inside the hard stop and 2 when the record or the API cannot be used. Only with `SCC_RELEASE_WATCH_ISSUES=true` (the scheduled workflow) does it open or reopen one GitHub issue per finding, labelled `scc-release` or `scc-expiry`; it needs `GH_TOKEN` and `GITHUB_REPOSITORY` then ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-30-release-watch-and-expiry-fallback-frees-176)) |
| `scc-own-expiry-check` | implemented | Runs `tools/scc/own_expiry.py` on `SCC_EXPIRY_LOG` (`build/scc/expiry/application-debug-log.txt`), the application debug log that the real scan of `make scc-integration` exports, with `--run-date` set to the scan's UTC start from `SCC_EXPIRY_START` (read by the test driver from the log's name). Fails when either file is missing, when the log mentions the software's expiry more than once or not at all, or when the start day plus SCC's own "Software expires in N days" is earlier than `SCC_EXPIRES`; one day early passes with a warning only for a scan started at or after 12:00 UTC. Run after `scc-integration` in the `scc-smoke` job ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md#7-version-updates-manual-pin-bump)) |
| `scc-image-clean` | implemented | Removes `SCC_IMAGE` from the local image store. On a shared Docker daemon, build with a unique tag (`make scc-smoke SCC_IMAGE=localhost/freesecdev-scc:<name>`) and remove it afterwards |
| `lint-iac` | implemented | `tofu fmt -check -recursive infra/`, `tofu init -backend=false` and `tofu validate` per root module, shellcheck of the rendered bootstrap script; needs `tofu` on `PATH`, runs in the `iac` CI job and in `make ci`, not in `make lint` |
| `aws-bootstrap-render` | implemented | Renders `infra/bootstrap/bootstrap.sh.tmpl` to the gitignored `infra/bootstrap/bootstrap.local.sh` |
| `lint-packer` | pending FREES-64 | Packer validation |
| `test-integration` | pending FREES-60 | Integration tests |
| `test-idempotency` | pending FREES-60 | Idempotency checks |
| `test-compliance` | pending FREES-62 | Compliance scan scenarios |
| `test-molecule-libvirt` | implemented | `molecule-dependencies`, `molecule-content`, `molecule-libvirt-images`, `molecule-libvirt-preflight`, then `molecule test` for the base scenarios `libvirt-ubuntu` and `libvirt-rhel-compatible` and the lifecycle scenarios `libvirt-ubuntu-lifecycle` and `libvirt-rhel-compatible-lifecycle` in KVM virtual machines (stops at the first failure; `MOLECULE_LIFECYCLE_TOPIC` and `MOLECULE_LIFECYCLE_MODE` select one topic and mode), then `test-molecule-libvirt-selftest` unless `MOLECULE_LIBVIRT_SELFTEST=false`; needs `/dev/kvm` and `qemu:///system`, see [libvirt](molecule-libvirt.md) |
| `test-molecule-libvirt-selftest` | implemented | Real guard bypass attempts, decoys, strangers and the destroy fallback against libvirt objects of the `libvirt-selftest` scenario, see [libvirt](molecule-libvirt.md#self-test-against-real-libvirt-objects) |
| `molecule-libvirt-images` | implemented | `tools/molecule/fetch-cloud-images.sh`: fetches the cloud images and packages of `MOLECULE_LIBVIRT_PLATFORMS` into `build/molecule-libvirt/cache`, checks every SHA-256 and the vendors' signed checksum files |
| `molecule-libvirt-preflight` | implemented | Fails unless `/dev/kvm` exists and `qemu:///system` is reachable |
| `test-molecule-golden` | pending FREES-63 | Golden image scenarios |
| `packer-validate` | pending FREES-64 | Packer template validation |
| `packer-build` | pending FREES-64 | Packer image build |
| `image-build` | pending FREES-36 | Stub: the runner image is built by the runner repository's `image-build` workflow on GitHub-hosted runners, not here |
| `report` | implemented | Normalized JSON and the HTML dashboard (`REPORT_SCOPE`, `REPORT_ARGS`, `REPORT_OUTPUT`, `REPORT_HTML`), see [reporting data model](reporting-data-model.md) and the [dashboard guide](dashboard.md) |
| `report-serve` | implemented | Serves `build/report/` on 127.0.0.1 only (`REPORT_PORT`, default 8765); refuses a `REPORT_HTML` outside it |
| `release-check` | pending FREES-84 | Release readiness |

Pending targets print `not implemented yet: <target> (tracked in FREES-<key>)` to standard error and exit
with status 2. They never succeed silently and are not part of `lint`, `test` or `ci`.

## Pre-commit stages

Configuration: `.pre-commit-config.yaml`. Install the hooks with `make install`.

| Stage | Hooks |
|---|---|
| `pre-commit` (fast) | trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, check-merge-conflict, check-added-large-files, detect-private-key, gitleaks (staged), ruff check, ruff format, yamllint, ansible-lint, markdownlint-cli2, shellcheck, tofu fmt, tofu validate, Checkov, repository source rules, skill validator, markdown relative links |
| `pre-push` | mypy, pyright, pylint, bandit, pytest |
| `manual` (CI only) | gitleaks history scan, actionlint, zizmor |

Run a stage by hand:

```text
uv run pre-commit run --all-files
uv run pre-commit run --all-files --hook-stage pre-push
uv run pre-commit run --all-files --hook-stage manual
```

`pre-commit run` only sees files known to git; `git add` new files first.

The ansible-lint hook (FREES-69) runs `make lint-ansible` whenever a collection file changes: ansible-lint on the whole
project with the `production` profile, the role argument spec check and the changelog lint, with the
[per-checkout Ansible home](#per-checkout-ansible-home) (FREES-127). The `tofu-fmt`, `tofu-validate` (system `tofu`) and `checkov` (`uv run --frozen`) hooks run when files
under `infra/` change (FREES-69). Packer hooks (FREES-64) are pending the issue that introduces their sources. They are
intentionally absent rather than faked.

The mypy, pyright, pylint and pytest hooks need the `build/collections` link that `make install` creates; pytest
stops with the hint "run 'make install'" when it is missing.

Pin ownership rule: every Python tool hook (ruff, yamllint, ansible-lint, mypy, pyright, pylint, bandit, pytest,
shellcheck, actionlint, zizmor) is a `repo: local` hook that runs `uv run --frozen <tool>`, so its version lives only in
`pyproject.toml` and `uv.lock` and is updated by Dependabot. Only hook repositories that are not tools declared in
`pyproject.toml` (pre-commit-hooks, gitleaks, markdownlint-cli2) are remote hooks. pre-commit-hooks is a Python
package, but its version is the hook revision, owned by Renovate rather than by the project environment. They are
pinned by full commit SHA with a `# vX.Y.Z` annotation and updated by Renovate. `additional_dependencies` is never used. The annotation on `rev:` is the second permitted
YAML comment form (ADR 0005, amendment 2026-10-25).

## Running each check manually

| Check | Command |
|---|---|
| Ruff lint and format | `uv run ruff check .` and `uv run ruff format --check .` |
| Pylint | `uv run pylint tools tests plugins` |
| mypy | `uv run mypy` |
| Pyright | `uv run pyright` |
| Bandit | `make security` runs Bandit on everything except the process helper, then on the helper with only B404 and B603 skipped |
| Tests with coverage | `uv run pytest tests/unit --cov --cov-report=term-missing` |
| yamllint | `uv run yamllint --strict .` |
| ansible-lint | `make lint-ansible`; a bare `uv run ansible-lint` uses `~/.ansible` and can resolve a stale installed copy of this collection |
| Changelog fragments | `uv run antsibull-changelog lint` |
| Collection sanity | `make test-sanity` |
| actionlint | `uv run actionlint` |
| zizmor | `uv run zizmor --persona pedantic .github/workflows` |
| Repository rules | `uv run python tools/lint/check_repo_rules.py <files>` |
| Skills | `uv run python tools/skills/validate_skills.py` |
| Markdown links | `uv run python tools/docs/check_links.py <files>` |

zizmor runs offline unless a `GH_TOKEN` is present. CI exports the workflow token for the `security` job
so that online audits (impostor commits, version annotation mismatch, known vulnerable actions) run too.
The pedantic persona is used because it is the strictest signal and the workflow count is small; the
current workflows produce no findings under it.

## Comment and annotation rules

No inline code comments are allowed in Python, YAML, Makefile, TOML or shell. Use names, docstrings,
module documentation and `docs/` instead. `tools/lint/check_repo_rules.py` enforces the rules below on
YAML and Python files (ADR 0005). It is the command-line entry point of the package `tools/lint/repo_rules/`,
which holds one module per rule group; the name sets and allow-lists live in `tools/lint/repo_rules/names.py`
(ADR 0004, FREES-141):

- Every YAML file starts with `---` followed by a newline.
- YAML files contain no `#` comments, except a trailing version annotation of exactly `# vX.Y.Z` on a pinned line:
  - `uses: owner/repo@<40-hex>` in workflows,
  - `rev: <40-hex>` in `.pre-commit-config.yaml`.
- `#` inside quoted scalars, block scalars and URLs is content, not a comment.
- Python files contain no comments, except a shebang on the first line. This includes `# noqa` and
  `# type: ignore`; suppressions are configured in `pyproject.toml` instead.
- Python files under `plugins/` are checked deny-by-default (ADR 0004): only allow-listed standard library modules,
  `ansible.module_utils` and this collection may be imported, `os` is usable only as `os.path`, `exec`, `eval`,
  `compile` and `__import__` are banned, process, fork and `run_command` attributes are banned, `shell=True` and
  `use_unsafe_shell` and the test-seam keywords (`owner_uid`, `state_dir`, `lock_timeout`, `policies`, `trusted_dirs`,
  `runner`, `clock`, `limits` and, since FREES-129, `registry`) are banned, `subprocess`,
  `pty`, `posix`, `os` and `sys` are banned as imported names or attributes, `vars`, `globals`, `locals`, `__dict__`
  and `get_type_hints` are banned, and `getattr` needs a literal permitted name. Since FREES-125 the attribute names
  `builtins`, `operator`, `eval`, `exec`, `compile`, `attrgetter`, `methodcaller`, `_evaluate` and
  `evaluate_forward_ref` are banned (use `re.fullmatch(PATTERN, text)` with a string constant instead of
  `re.compile`), a module-level `__getattr__` is banned, `__kwdefaults__`, `__defaults__`, `__code__`, `__closure__`
  and `__globals__` are banned, assigning to an attribute or item of a name bound by an import (and `setattr` or
  `delattr` on it) is banned, and an underscore-prefixed attribute may only be read, called or assigned through
  `self` or `cls` inside a class body, so `openscap._expat`, `backend._runner = ...` and imports of
  underscore-prefixed names fail. Dunders are denied by default: only reading `__name__` is allowed (FREES-129 removed
  the unused `__qualname__`, `__doc__` and `__module__`), plus the single form `object.__setattr__(self, "<literal>", value)`
  directly in `__post_init__`;
  dunder methods that your own classes define stay allowed. Frame and code attributes (`currentframe`, `f_builtins`,
  `co_code`, `CodeType`, `FunctionType` and the like) are banned, `types` may only provide `MappingProxyType`, and
  attribute names that equal a standard library module or a module of this collection are banned when the chain starts
  at a module name (`dataclasses.inspect`, `enum.sys`, `scanner.process`), while `{}.copy()`, `obj.time` and
  `other.scanner` stay allowed; `bltns`, `_bltin` and `stdlib_re` are banned everywhere. Only
  `super().__init__(...)` and `super().__post_init__()` may call a dunder on `super()`, and `super` and `object` must
  never be rebound. A submodule reached by attribute (`os.path`, `json.decoder`) is a module value too and may only be
  the base of an attribute access, so import `from xml.parsers import expat` rather than storing `xml.parsers.expat`.
  A name bound to a module
  may only be used as `name.attribute`, never assigned, passed, returned or stored, and `self` or `cls` count as such only
  when they are the never rebound first parameter of a method. Object-level private writes through `C.f(obj)` are an
  accepted residual risk (ADR 0004).
  The guard is static analysis, not a sandbox. Only
  `plugins/module_utils/compliance/process.py` is exempt. Extend the allow-list in `tools/lint/repo_rules/names.py`
  with a justification when a new module is genuinely needed. Since FREES-129 the import allow-list holds only modules
  that plugins use: `collections` (bare), `functools` and `itertools` were removed, `collections.abc` stays. A new
  keyword-only parameter of plugin code must be classified in `tests/unit/tools/test_check_repo_rules_followups.py`
  as a test seam (and then added to `BANNED_KEYWORDS`) or as a production keyword. Since FREES-137 every test seam is
  keyword-only: a parameter named like a banned keyword that a positional argument can fill (positional,
  positional-only, `*args` or `**kwargs`) fails the guard and the classification test, so `audit.plan(job, 1000)` or
  `process.resolve_executable("oscap", ("/tmp",), 1000)` cannot bypass the keyword ban (the latter's directories
  parameter is now the banned `trusted_dirs`). Only the files in `SEAM_OWNERS` of the guard (`audit.py`, `catalog.py`,
  `fileio.py`, `ledger.py`, `openscap.py`; `process.py` is exempt from the guard) may define a seam, and they may pass a seam on
  only unchanged, as `owner_uid=owner_uid` from the keyword-only parameter of the enclosing function or as
  `owner_uid=self._owner_uid` in a class whose `__init__` takes the keyword-only seam; `self._<seam>` may only be
  assigned to `self` in `__init__` and never through `setattr`, `delattr` or `object.__setattr__`. Every other banned
  keyword in a call still fails. `_<seam>` for every banned keyword is reserved: any other file may not read, set,
  delete or `getattr` it on any object (so a subclass of `audit.Auditor` or a method called on one cannot change its
  `_owner_uid`), and no file may bind it in a class body. Files are opened through
  `xmlsafe.RegularFile`; the open helper behind it is private (`_open_regular`), so no other plugin file can call it.
  The standard library name sets of the guard (`STDLIB_MODULE_NAMES`, `KNOWN_SUBMODULE_ATTRIBUTES`) are generated:
  `make name-sets` runs `tools/lint/name_set_probe.py` in a clean interpreter of every version from 3.9 to 3.15,
  records the result per version in `tools/lint/name_sets.json` and writes the union into the guard
  (`tools/lint/generate_name_sets.py`). Run it after changing the import allow-list or when a Python release adds
  names; the `name-sets` CI job fails until then.
- Since FREES-156 the guard knows every location from which Ansible loads code (ADR 0004). The collection's code
  lives in `plugins/` at the repository root, as Python source, and nowhere else:
  - A file in a `library`, `module_utils`, `doc_fragments`, `*_plugins`, `collections`, `ansible_collections` or
    `plugins` directory anywhere else in the repository (a role, a playbook directory, a Molecule scenario, a test
    playbook directory, the repository root) is refused, and Python there also gets the deny-by-default rules. The unit
    tests and type stubs that mirror the collection layout (`tests/unit/plugins`, `typings/ansible/module_utils`) are
    not load locations; `tests/unit/` and `typings/` may hold only Python source and stubs.
  - Every file under `plugins/` must end in `.py`, a file in `plugins/modules` must import `ansible.module_utils` or
    the collection's `module_utils` and contain no control byte, so Ansible always runs it as a new-style Python
    module, and a Python file may only have a Python shebang.
  - A symbolic link is refused unless it is `.claude/skills` or the remediation test fixture, and an executable file is
    refused outside `tools/**/*.sh`.
  - `ansible.cfg` may not set a module, plugin, role, collection, home or playbook-directory path; a file in a directory
    that such a setting names is refused as well. The `ANSIBLE_*` environment variables for those paths and
    `ANSIBLE_CONFIG` are refused as YAML keys, in workflow and `molecule.yml` values, in makefiles and in shell scripts,
    and so are `--module-path` and `-M`; only the `Makefile` may set `ANSIBLE_HOME` and `ANSIBLE_COLLECTIONS_PATH`,
    which point below `build/`. `molecule.yml` may not set the `ansible.cfg` path settings either. Environment files
    (`.env`, `.envrc`), `.ini`, `.toml` and `.cfg` files are scanned for the same variables, and an ansible-navigator
    settings file may point `ansible.config.path` only at a file named `ansible.cfg`.
  - Names are compared case-folded, because a macOS or Windows controller finds `Library/` as `library/`, and a
    symbolic link or executable bit recorded only in the Git index is refused too: `make lint-repo` passes
    `git ls-files -s -z` to the guard with `--index-modes`; a listing that cannot be read is a guard error with
    exit status 2. A path component that is not ASCII is refused, because filesystems fold such names with their
    own tables (FREES-159).
- Since FREES-159 the guard refuses the other ways to run a command without the banned modules (ADR 0004 lists
  each name and its source in ansible-core 2.21.5):
  - `expect` and `cron` as tasks and actions, and the module parameters that name a command, an executable or its
    options (`validate`, `dpkg_options`, `extra_opts`, `ssh_opts`, the `reboot` commands, `fact_path`, the `use` of
    `package` and `service`, and others).
  - The `pipe` and `lines` lookups in every form (`lookup`, `query`, `q`, `with_<name>`, bare, `ansible.builtin.`,
    `ansible.legacy.`) in any templated YAML value, bare conditional and template file; a lookup with a computed or
    indirect name; any lookup that ansible-core does not ship; a computed `include`, `import`, `extends` or `from`
    name; and the `#jinja2:` header and delimiter options, which would hide a template from the check. Every
    tracked file outside `.github/` is read as a template whatever its suffix; only a real binary (magic bytes and
    a matching suffix) is skipped, a NUL byte elsewhere is refused, and `.json` and extensionless vars files are
    also read as YAML. `vars_files`, `include_vars` and `template` targets must be literal paths inside the
    repository, vars files must be YAML or JSON, and `include_vars` may not set `extensions`.
  - Variables and keywords that set an interpreter, an executable, arguments or flags (`ansible_*_interpreter`,
    `ansible_ssh_*_args`, `ansible_become_exe`, `ansible_shell_executable` and the others), wherever the repository
    sets them, a connection, become or shell plugin outside ansible-core, and `PATH` and the loader and interpreter
    environment variables as YAML keys. The reviewed exceptions of the test plays and the Molecule guard cases are
    keyed by file and exact value (`ALLOWED_SETTINGS` in `tools/lint/repo_rules/exec_variables.py`).
  - Configuration settings, environment variables and command-line options that run code or choose what runs, in
    `ansible.cfg`, `molecule.yml` and every place where FREES-156 refuses a search path.
- YAML files contain no `shell`, `command`, `raw`, `script`, `win_shell` or `win_command` task keys,
  including the `ansible.builtin.`, `ansible.legacy.`, `ansible.windows.` and `community.windows.` forms and the `action` / `local_action` spellings.
  The scan covers `extensions/` and `tests/` as well. Since FREES-128 the check knows where Ansible reads a module name:
  - A document whose root is a sequence is a playbook or a task file, wherever it lives (role `tasks/` and `handlers/`
    files, Molecule playbooks, files that `include_tasks`, `import_tasks` or `import_playbook` load). Every mapping in
    it is treated as both a play and a task, and the task lists `tasks`, `pre_tasks`, `post_tasks`, `handlers`,
    `block`, `rescue` and `always` are followed to any depth, through aliases and YAML merge keys (`<<`).
  - Only the keys of a play or task are checked, plus the value of `action` and `local_action`: the first word of the
    string form and of every `module` key of the mapping form (`module: shell echo hi` names `shell`). A templated
    module name there (`action: "{{ name }}"`) is denied, because it cannot be checked statically.
  - Module parameters and keyword data are not checked, so `community.docker.docker_container: {command: ...}`, play
    and task `vars`, `set_fact` data, `loop` items, `environment` and `module_defaults` may contain the banned words.
  - The file that `include_tasks`, `import_tasks` or `import_playbook` loads, and `tasks_from` and `handlers_from` of
    `include_role` and `import_role`, must end in `.yml` or `.yaml`, because Ansible would also load a `.json` or
    suffix-less file that the check never scans. A repository test keeps every file below a `tasks` or `handlers`
    directory a YAML file, which covers the default `main` entry point of a role.
  - Since FREES-137 these targets must also be relative paths without a `..` component and must not be templated or
    start with `/` or `~`, because such a target could load an unscanned file from outside the repository. The one
    templated form is `{{ role_path }}/tasks/` followed by a literal relative path
    (`{{ role_path }}/tasks/file_permissions_apply.yml`); no variable may choose the file, because a role parameter,
    an include parameter or an extra variable outranks every fact a role sets. The remediate role therefore
    dispatches with one static include per catalogued family in `roles/remediate/tasks/dispatch.yml`, which
    `make role-guards` generates from the family registry and `make lint-role-guards` checks for drift. A test
    playbook that chose a helper by template now uses one static include per helper with `when`.
  - Every entry point of the audit, evidence, remediate and verify roles starts with the generated
    `tasks/internal_variables.yml`, which refuses an internal `__linux_compliance_<role>_*` variable supplied from
    outside the role (a role parameter, an include parameter, an extra variable, or a play `set_fact` of a constant
    the role loads). It first refuses, by name and whatever the value, every internal name that the `varnames`
    lookup sees but `hostvars` does not, which is a role, include, block or play parameter, so a template that
    imitates the sentinels cannot pass (FREES-157). It then reads every fact and task variable back with two
    different sentinels, so a fixed value forged as the sentinel string is refused too, and the key facts are
    type-checked right after the role sets them (FREES-153). The generator also writes `playbooks/run_start.yml`,
    which every shipped playbook imports first: it refuses an internal `__linux_compliance_*` name or a role output
    such as `linux_compliance_audited` that is already in `hostvars` when the run starts, from `-e`, the inventory or
    a fact cache (ADR 0004, FREES-157). Regenerate it with `make role-guards` after adding an internal variable; the generator fails on a
    variable it cannot classify and on a role with internal variables that is not in `GUARDED_ROLES`.
    `make test-role-guards` checks the refusals in check mode.
  - A run output (`RUN_OUTPUTS` in `tools/roles/generate_role_guards.py`) is an internal fact that a role sets for a
    later play of the same run. Today that is only the evidence role's collection marker
    `__linux_compliance_evidence_run_bundle` (FREES-154). The guard neither resets nor reads it back: a reset to the
    sentinel string at the start of the evidence role would leave a host whose collection then failed with a
    defined marker. The marker is type-checked where it is set, read only as a mapping of the audited run, and refused
    at the start of the run by `reached.yml` ([evidence bundles](evidence.md#the-collection-marker)). The generator
    fails if a run output is not a fact that the role sets. The evidence entry points `reached.yml` and
    `collected.yml` do not import the guard: `collected.yml` uses no internal variable but the run output, which it
    reads through `hostvars`, so no parameter can stand in for it, and `reached.yml` runs before the role sets
    anything and refuses every `__linux_compliance_evidence_*` variable of every host itself.
  - Seam owners store their seam attributes directly in `__init__`, never from a function nested in it, and no
    compiled module file (`.so`, `.pyd`, `.pyc`, `.pyo`, `.fwork`) may be tracked (FREES-153).
  - A repository test fails when a symlink below the repository points outside it or is a symlinked directory other
    than `.claude/skills`, because the guard does not scan through a symlinked directory.
  - Role names of `include_role` and `import_role` (mapping and free-form `name=`) and of the `roles` of a play
    (`- name`, `- role: name` or `- name: name`) must be plain or fully qualified names: a templated name or a path
    such as `/srv/roles/x` or `../x` is denied. A free-form role include may not be templated at all.
  - A templated task key (`"{{ m }}": cmd`) is denied as defence in depth; `ansible-playbook --syntax-check`
    rejects it too. Templated keys inside module parameters and `vars` are data and stay allowed.
  - A document with any other root (a mapping such as `molecule.yml`, a vars file or a workflow) can never be loaded as
    plays or tasks; it stays checked deny-by-default for banned keys and `action` values at any depth. A `redirect` to a
    banned module (`plugin_routing` in `meta/runtime.yml`) is denied there too, because it would make another name an
    alias of that module.

Every lint ignore lives in `pyproject.toml` with its reason in `[tool.freesecdev.lint-justifications]` or
`[tool.freesecdev.pylint-justifications]`.

Configuration relaxations, each with its reason:

- `.markdownlint-cli2.yaml` disables MD013 (line length) because prose and tables in the research notes and
  skills are written one paragraph per line, and MD060 (table column style) because it demands padded
  pipes that the existing tables, which are maintained by hand, do not use. All other default rules are on.
- `.yamllint.yaml` sets `comments-indentation`, `braces` and `octal-values` as ansible-lint requires, because
  ansible-lint warns about and disables its fix mode for an incompatible yamllint configuration. Comments are
  banned in YAML anyway, and `build/` and `dist/` are generated and ignored.
- `.ansible-lint` runs offline and lists `supported_ansible_also` 2.20 and 2.21, because the ansible-lint release in use
  still lists 2.15 to 2.19 as the supported `requires_ansible` versions while the ansible-core matrix lists 2.20 and
  2.21. This extends a version list; it does not suppress a rule.
- `.yamllint.yaml` exempts `docs/planning/` from the line length rule only, because the Jira plan stores each
  acceptance criterion on one line (up to about 300 characters) and the file is consumed by tooling.

## Pull request workflow

`.github/workflows/ci.yml` runs on `pull_request` to `main`, `push` to `main` and `merge_group`.

| Job | Make target |
|---|---|
| `lint` | `make lint` |
| `typecheck` | `make typecheck` |
| `test` | `make test-coverage`, `make test-audit-exceptions`, `make test-content-golden`, `make test-browser` |
| `test-playbooks` | `make test-evidence`, `make test-remediate-check`, `make test-role-guards`, `make test-verify` |
| `name-sets` | matrix over the pinned Python releases 3.9.25, 3.10.21, 3.11.16, 3.12.14, 3.13.15 and 3.14.6: `uv python install`, then `make test-name-sets` |
| `security` | `make security` |
| `collection` | `make test-sanity test-ansible-units package-check` |
| `iac` | `tools/iac/install-tofu.sh`, then `make lint-iac` |
| `molecule-docker` | `make test-molecule-docker MOLECULE_DOCKER_SELFTEST=false` for `docker-ubuntu` and `docker-rhel-compatible`, and `make test-molecule-docker-selftest` for `docker-selftest`, one matrix entry each |
| `molecule-plan` | `make -s molecule-matrix`: one leg per Molecule platform, native topic and toggle mode, derived from the catalogue, as the job output `matrix` |
| `molecule-lifecycle` | `make test-molecule-docker MOLECULE_DOCKER_SELFTEST=false` with the `docker-<platform>-lifecycle` scenario, `MOLECULE_LIFECYCLE_TOPIC` and `MOLECULE_LIFECYCLE_MODE` of each leg of `molecule-plan` ([Molecule](molecule.md#ci-legs)) |
| `scc-changes` | the base revision's `tools/scc/needs-smoke.sh`, read with `git show` and run with `bash`: `scc=false` only for a pull request or merge group whose diff touches no SCC path (renames count as a deletion and an addition); `true` for push, schedule and dispatch, and fails closed to `true`. A change to the filter takes effect only after it merges. Also the base revision's `tools/scc/expiry-state.sh` on the base and head `scc.pins`: `expiry=expired` only for a pull request or merge group in which both pins name the same SCC release and both are past their hard stop, otherwise `expiry=current` |
| `scc-smoke` | runs unless `scc-changes` output `scc=false` or `expiry=expired`; restores the verified SCC download from the Actions cache (key: SHA-256 of `extensions/ci/scc/scc.pins`; skipped for a pull request from a fork), then `make scc-smoke`, `make scc-integration` and `make scc-own-expiry-check`; `contents: read` only, the image and the exported debug log stay on the runner |
| `ci-gate` | none; fails unless every needed job succeeded |

`ci-gate` needs every job above, runs with `if: always()` and is the only check that branch protection should require. It accepts a skipped `scc-smoke` only for a `pull_request` or `merge_group` whose `scc-changes` output is exactly `scc=false` or exactly `expiry=expired`, and it compares the event name and the outputs exactly, not as substrings; on `push` to `main` and the daily `schedule` the smoke test always runs. A skip for `expiry=expired` is named in the warning annotation "SCC not built or run": once the pinned SCC is past its hard stop and no newer pin exists, pull requests and merge groups keep flowing, SCC is neither built nor run, and `main` stays red until the pin is bumped ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-30-release-watch-and-expiry-fallback-frees-176)). Job names
are stable, so the required check name `ci-gate` does not change. Runs for pull requests cancel superseded
runs; runs on `main` and merge groups are never cancelled. `docs` is part of `make ci` locally and is
added as a job together with the documentation pipeline (FREES-80).

`.github/workflows/scc-release-watch.yml` runs the job `scc-release-watch` daily at 05:43 UTC and on manual dispatch,
on `main` only: `make scc-release-watch SCC_RELEASE_WATCH_ISSUES=true` with `GH_TOKEN` set to the job token. It is the
only job in the repository with `issues: write` (next to `contents: read`), it never runs for a pull request or merge
group, and it is not part of `ci-gate`. It keeps one issue labelled `scc-release` while NIWC's release record names a
version other than the pin, and one labelled `scc-expiry` from 21 days before `SCC_EXPIRES`. It fails from the hard
stop until the pin is bumped, and whenever the release record or the GitHub API cannot be used. Run
`make scc-release-watch` locally to see the same comparison without touching any issue.

The toolbox runner image is built by the `linux-compliance-runner` repository's `image-build` workflow on
GitHub-hosted runners (FREES-36) and published as `ghcr.io/freesecdev/linux-compliance-runner`, signed with cosign
and attested. No image has been published yet. This repository consumes it by digest only:
`ghcr.io/freesecdev/linux-compliance-runner@sha256:<digest>`, never a tag.
`tests/unit/tools/test_runner_image_pin.py` reads every tracked file except Markdown and fails on any other reference
to the image, including its unverified `candidate-` tags, and on any reference to an ECR staging image. It reads
literal text only, so a name assembled from variables is left to review. Before adopting a new digest, verify its
signature and attestations as described in the runner repository's `docs/image-build.md`. Jobs still run on
`ubuntu-24.04` with a pinned `uv`; moving them into the image is follow-up work.

## Dependency pins

- Python tools, including `ansible-core`, `ansible-lint` and `antsibull-changelog`, are pinned to exact versions in
  `pyproject.toml` and locked in `uv.lock`. Update with `uv lock --upgrade-package <name>` and commit both files.
- The release-age policy (at least seven days) applies to direct and transitive version updates through the
  Dependabot cooldown and review; the lock is not filtered by age, because a security fix is exempt from the policy
  ([dependency management](dependency-management.md)).
- Molecule and `requests` are pinned to exact versions in `pyproject.toml` and `uv.lock` like the other Python tools.
  The `community.docker` collection is pinned in `extensions/molecule/requirements.yml` (Renovate owns Galaxy
  collections), with the SHA-256 of every artifact in `extensions/molecule/collections.pins`; after a Renovate update
  run `make molecule-collections-lock` and commit both files. The container image digests live in `extensions/molecule/shared/vars/versions.yml`. The
  distribution packages of the instance images are pinned to exact versions in the Dockerfiles under
  `extensions/molecule/shared/images/` and updated by hand.
- GitHub Actions are pinned to full commit SHAs with a `# vX.Y.Z` annotation.
- The `uv` version used in CI is pinned in `.github/workflows/ci.yml`.
- OpenTofu `1.13.2` (a security release, exempt from the seven-day rule) is pinned in `infra/account/versions.tf` and
  `tools/iac/install-tofu.sh` with SHA-256 checksums; the AWS provider `6.69.1` is pinned in `versions.tf` and
  `infra/account/.terraform.lock.hcl` (`linux_amd64` and `linux_arm64`); Checkov is pinned in `pyproject.toml`.
