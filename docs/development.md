# Development guide

The `Makefile` is the single entry point for developers and CI. `make ci` runs every implemented,
credential-free stage locally and is what the pull request workflow runs, split into jobs.

Jira: FREES-68 (Makefile), FREES-69 (pre-commit), FREES-70 (Python tooling),
FREES-71 (pull request workflow), FREES-91 (skill validator tests).

## Bootstrap

Requirements: `git`, GNU `make` and [`uv`](https://docs.astral.sh/uv/). Python 3.12 is selected by
`.python-version` and installed by `uv` when missing.

```text
make bootstrap
make help
```

`make bootstrap` runs `uv sync --frozen` (exact versions from `uv.lock`), installs the `pre-commit` and
`pre-push` git hooks and prints tool versions. A missing `uv` produces an error with install instructions.
OpenTofu and Packer checks join `make bootstrap` with FREES-30 and FREES-64.

## Makefile targets

| Target | Status | What it does |
|---|---|---|
| `help` | implemented | Prints this target list |
| `bootstrap` | implemented | `install` plus tool version check |
| `install` | implemented | `uv sync --frozen`, installs both git hook types |
| `format` | implemented | `ruff check --fix` and `ruff format` |
| `lint` | implemented | `lint-repo`, `lint-skills`, `lint-python`, `lint-yaml`, `lint-actions` |
| `lint-python` | implemented | Ruff lint, Ruff format check, Pylint |
| `lint-yaml` | implemented | `yamllint --strict` |
| `lint-actions` | implemented | actionlint |
| `lint-repo` | implemented | `tools/lint/check_repo_rules.py` on tracked and new YAML and Python files |
| `lint-skills` | implemented | `tools/skills/validate_skills.py` |
| `security` | implemented | Bandit, gitleaks history scan, zizmor (pedantic persona) |
| `typecheck` | implemented | mypy strict, Pyright strict |
| `test` | implemented | Alias for `test-unit` |
| `test-unit` | implemented | `pytest tests/unit` |
| `test-coverage` | implemented | Unit tests with branch coverage, 95% overall, 100% on `tools/` |
| `docs` | implemented | markdownlint-cli2 and the relative link checker |
| `clean` | implemented | Removes caches and coverage output |
| `ci` | implemented | `lint typecheck test-coverage security docs` |
| `lint-ansible` | pending FREES-39 | Collection skeleton and ansible-lint |
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
| `package` | pending FREES-39 | Collection artifact build |
| `release-check` | pending FREES-84 | Release readiness |

Pending targets print `not implemented yet: <target> (tracked in FREES-<key>)` to standard error and exit
with status 2. They never succeed silently and are not part of `lint`, `test` or `ci`.

## Pre-commit stages

Configuration: `.pre-commit-config.yaml`. Install the hooks with `make install`.

| Stage | Hooks |
|---|---|
| `pre-commit` (fast) | trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, check-merge-conflict, check-added-large-files, detect-private-key, gitleaks (staged), ruff check, ruff format, yamllint, markdownlint-cli2, shellcheck, repository source rules, skill validator, markdown relative links |
| `pre-push` | mypy, pyright, pylint, bandit, pytest |
| `manual` (CI only) | gitleaks history scan, actionlint, zizmor |

Run a stage by hand:

```text
uv run pre-commit run --all-files
uv run pre-commit run --all-files --hook-stage pre-push
uv run pre-commit run --all-files --hook-stage manual
```

`pre-commit run` only sees files known to git; `git add` new files first.

Hooks for ansible-lint (FREES-39), OpenTofu and Checkov (FREES-30, FREES-31) and Packer (FREES-64) are pending
the issues that introduce their sources. They are intentionally absent rather than faked.

Third-party hook repositories are pinned by full commit SHA with a `# vX.Y.Z` annotation. Hooks without a
suitable annotated tag (shellcheck-py publishes four-part versions) run from the locked `uv` environment.

## Running each check manually

| Check | Command |
|---|---|
| Ruff lint and format | `uv run ruff check .` and `uv run ruff format --check .` |
| Pylint | `uv run pylint tools tests` |
| mypy | `uv run mypy` |
| Pyright | `uv run pyright` |
| Bandit | `uv run bandit -c pyproject.toml -r tools` |
| Tests with coverage | `uv run pytest tests/unit --cov --cov-report=term-missing` |
| yamllint | `uv run yamllint --strict .` |
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
- YAML files contain no `shell`, `command`, `raw`, `script`, `win_shell` or `win_command` task keys,
  including `ansible.builtin.` and `ansible.legacy.` forms and the `action` / `local_action` spellings.
  The scan covers `extensions/` and `tests/` as well.

Every lint ignore lives in `pyproject.toml` with its reason in `[tool.freesecdev.lint-justifications]` or
`[tool.freesecdev.pylint-justifications]`.

Configuration relaxations adopted to accept existing content without rewriting it in this change:

- `.markdownlint-cli2.yaml` disables MD013 (line length), MD032, MD033, MD034 (bare URLs in research notes),
  MD037, MD040, MD041 and MD060 (table style). Re-enable them as documents are cleaned up.
- `.yamllint.yaml` exempts `docs/planning/` from the line length rule because the plan stores long
  acceptance criteria on single lines.

## Pull request workflow

`.github/workflows/ci.yml` runs on `pull_request` to `main`, `push` to `main` and `merge_group`.

| Job | Make target |
|---|---|
| `lint` | `make lint` |
| `typecheck` | `make typecheck` |
| `test` | `make test-coverage` |
| `security` | `make security` |
| `ci-gate` | none; fails unless every needed job succeeded |

`ci-gate` runs with `if: always()` and is the only check that branch protection should require. Job names
are stable, so the required check name `ci-gate` does not change. Runs for pull requests cancel superseded
runs; runs on `main` and merge groups are never cancelled. `docs` is part of `make ci` locally and is
added as a job together with the documentation pipeline (FREES-80).

The toolbox runner image lives in the `linux-compliance-runner` repository and does not exist yet. Jobs
currently run on `ubuntu-24.04` with a pinned `uv`. Moving the jobs into the image, consumed by digest, is
follow-up work tracked with the runner image issue (FREES-35); it is not simulated here.

## Dependency pins

- Python tools are pinned to exact versions in `pyproject.toml` and locked in `uv.lock`. Update with
  `uv lock --upgrade-package <name>` and commit both files.
- GitHub Actions are pinned to full commit SHAs with a `# vX.Y.Z` annotation.
- The `uv` version used in CI is pinned in `.github/workflows/ci.yml`.
