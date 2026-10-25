# Development guide

The `Makefile` is the single entry point for developers and CI. `make ci` runs every implemented,
credential-free stage locally and is what the pull request workflow runs, split into jobs.

Jira: FREES-68 (Makefile), FREES-69 (pre-commit), FREES-70 (Python tooling),
FREES-71 (pull request workflow), FREES-91 (skill validator tests), FREES-39 (collection skeleton and
ansible tooling), FREES-26 (findings model), FREES-69 (ansible-lint hook), FREES-40 (role skeletons).

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
OpenTofu and Packer checks join `make bootstrap` with FREES-30 and FREES-64.

## Makefile targets

| Target | Status | What it does |
|---|---|---|
| `help` | implemented | Prints this target list |
| `bootstrap` | implemented | `install` plus tool version check |
| `install` | implemented | `uv sync --frozen`, installs both git hook types |
| `format` | implemented | `ruff check --fix` and `ruff format` |
| `lint` | implemented | `lint-repo`, `lint-skills`, `lint-python`, `lint-yaml`, `lint-actions`, `lint-ansible` |
| `lint-ansible` | implemented | `ansible-lint` with the `production` profile, `tools/roles/check_role_specs.py`, then `antsibull-changelog lint` |
| `lint-python` | implemented | Ruff lint, Ruff format check, Pylint (`tools`, `tests`, `plugins`) |
| `lint-yaml` | implemented | `yamllint --strict` |
| `lint-actions` | implemented | actionlint |
| `lint-repo` | implemented | `tools/lint/check_repo_rules.py` on tracked and new YAML and Python files |
| `lint-skills` | implemented | `tools/skills/validate_skills.py` |
| `security` | implemented | Bandit (`tools`, `plugins`), gitleaks history scan, zizmor (pedantic persona) |
| `typecheck` | implemented | mypy strict, Pyright strict |
| `test` | implemented | Alias for `test-unit` |
| `test-unit` | implemented | `pytest tests/unit`, including the collection plugin tests |
| `test-coverage` | implemented | Unit tests with branch coverage, 95% overall, 100% on `tools/` and on `plugins/` |
| `test-sanity` | implemented | `ansible-test sanity --local` on the temporary collection tree, no Docker; installs Python 3.9 to 3.14 with `uv python install` |
| `test-ansible-units` | implemented | `ansible-test units --venv` on Python 3.9, 3.12 and 3.14, no Docker |
| `package` | implemented | `ansible-galaxy collection build` repacked with a canonical `FILES.json`, into `dist/`, plus `dist/SHA256SUMS` |
| `package-check` | implemented | Builds twice from differently ordered trees and fails unless the SHA-256 values match |
| `collection-tree` | implemented | Copies the collection files into `build/collection/ansible_collections/freesecdev/linux_compliance` |
| `collection-link` | implemented | Links `plugins/` into `build/collections` for pytest and the type checkers |
| `docs` | implemented | markdownlint-cli2 and the relative link checker |
| `clean` | implemented | Removes caches and coverage output |
| `ci` | implemented | `lint typecheck test-coverage security docs test-sanity test-ansible-units package-check` |
| `lint-iac` | pending FREES-30 | OpenTofu validation and Checkov |
| `lint-packer` | pending FREES-64 | Packer validation |
| `test-integration` | pending FREES-60 | Integration tests |
| `test-idempotency` | pending FREES-60 | Idempotency checks |
| `test-compliance` | pending FREES-62 | Compliance scan scenarios |
| `test-molecule-docker` | pending FREES-59 | Docker Molecule scenarios |
| `test-molecule-libvirt` | pending FREES-61 | libvirt Molecule scenarios |
| `test-molecule-golden` | pending FREES-63 | Golden image scenarios |
| `packer-validate` | pending FREES-64 | Packer template validation |
| `packer-build` | pending FREES-64 | Packer image build |
| `aws-bootstrap` | pending FREES-33 | AWS bootstrap |
| `image-build` | pending FREES-36 | Runner image build on AWS |
| `report` | pending FREES-77 | HTML report generation |
| `report-serve` | pending FREES-77 | Local report server |
| `release-check` | pending FREES-84 | Release readiness |

Pending targets print `not implemented yet: <target> (tracked in FREES-<key>)` to standard error and exit
with status 2. They never succeed silently and are not part of `lint`, `test` or `ci`.

## Pre-commit stages

Configuration: `.pre-commit-config.yaml`. Install the hooks with `make install`.

| Stage | Hooks |
|---|---|
| `pre-commit` (fast) | trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, check-merge-conflict, check-added-large-files, detect-private-key, gitleaks (staged), ruff check, ruff format, yamllint, ansible-lint, markdownlint-cli2, shellcheck, repository source rules, skill validator, markdown relative links |
| `pre-push` | mypy, pyright, pylint, bandit, pytest |
| `manual` (CI only) | gitleaks history scan, actionlint, zizmor |

Run a stage by hand:

```text
uv run pre-commit run --all-files
uv run pre-commit run --all-files --hook-stage pre-push
uv run pre-commit run --all-files --hook-stage manual
```

`pre-commit run` only sees files known to git; `git add` new files first.

The ansible-lint hook (FREES-69) runs the whole project with the `production` profile whenever a collection
file changes. Hooks for OpenTofu and Checkov (FREES-30, FREES-31) and Packer (FREES-64) are pending the issues
that introduce their sources. They are intentionally absent rather than faked.

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
| ansible-lint | `uv run ansible-lint` |
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
YAML and Python files (ADR 0005):

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
  `use_unsafe_shell` are banned, and `getattr` needs a literal permitted name. Only
  `plugins/module_utils/compliance/process.py` is exempt. Extend the allow-list in `tools/lint/check_repo_rules.py`
  with a justification when a new module is genuinely needed.
- YAML files contain no `shell`, `command`, `raw`, `script`, `win_shell` or `win_command` task keys,
  including the `ansible.builtin.`, `ansible.legacy.`, `ansible.windows.` and `community.windows.` forms and the `action` / `local_action` spellings.
  The scan covers `extensions/` and `tests/` as well.

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
| `test` | `make test-coverage` |
| `security` | `make security` |
| `collection` | `make test-sanity test-ansible-units package-check` |
| `ci-gate` | none; fails unless every needed job succeeded |

`ci-gate` needs every job above, runs with `if: always()` and is the only check that branch protection should require. Job names
are stable, so the required check name `ci-gate` does not change. Runs for pull requests cancel superseded
runs; runs on `main` and merge groups are never cancelled. `docs` is part of `make ci` locally and is
added as a job together with the documentation pipeline (FREES-80).

The toolbox runner image lives in the `linux-compliance-runner` repository and does not exist yet. Jobs
currently run on `ubuntu-24.04` with a pinned `uv`. Moving the jobs into the image, consumed by digest, is
follow-up work tracked with the runner image issue (FREES-35); it is not simulated here.

## Dependency pins

- Python tools, including `ansible-core`, `ansible-lint` and `antsibull-changelog`, are pinned to exact versions in
  `pyproject.toml` and locked in `uv.lock`. Update with `uv lock --upgrade-package <name>` and commit both files.
- The release-age policy (at least seven days) applies to direct and transitive version updates through the
  Dependabot cooldown and review; the lock is not filtered by age, because a security fix is exempt from the policy
  ([dependency management](dependency-management.md)).
- GitHub Actions are pinned to full commit SHAs with a `# vX.Y.Z` annotation.
- The `uv` version used in CI is pinned in `.github/workflows/ci.yml`.
