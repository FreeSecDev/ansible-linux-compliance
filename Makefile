SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

UV := $(shell command -v uv 2>/dev/null)
RUN := uv run --frozen
TRACKED := git ls-files -z --cached --others --exclude-standard
ZIZMOR_PERSONA := pedantic

NOT_IMPLEMENTED = @printf 'not implemented yet: %s (tracked in %s)\n' '$(1)' '$(2)' >&2; exit 2

define HELP_TEXT
Usage: make <target>

Setup
  help                  Show this help
  bootstrap             Install tooling and git hooks, then verify the environment
  install               Sync the locked Python environment and install pre-commit and pre-push hooks

Formatting and linting
  format                Apply Ruff fixes and formatting
  lint                  Run every implemented linter (repo, skills, python, yaml, actions)
  lint-python           Ruff lint, Ruff format check and Pylint
  lint-yaml             yamllint in strict mode
  lint-actions          actionlint for GitHub workflows
  lint-repo             Repository source rules (document start, comments, banned modules)
  lint-skills           Validate agent skills under .agents/skills
  lint-ansible          [pending FREES-39] ansible-lint
  lint-iac              [pending FREES-30] OpenTofu validation and Checkov
  lint-packer           [pending FREES-64] Packer validation

Security and types
  security              Bandit, gitleaks history scan and zizmor
  typecheck             mypy strict and Pyright strict

Tests
  test                  Alias for test-unit
  test-unit             Unit tests
  test-coverage         Unit tests with branch coverage thresholds
  test-integration      [pending FREES-60] Integration tests
  test-molecule-docker  [pending FREES-59] Molecule Docker scenarios
  test-molecule-libvirt [pending FREES-61] Molecule libvirt scenarios
  test-molecule-golden  [pending FREES-63] Molecule golden image scenarios
  test-idempotency      [pending FREES-60] Idempotency checks
  test-compliance       [pending FREES-62] Compliance scan scenarios

Images and AWS
  packer-validate       [pending FREES-64] Validate Packer templates
  packer-build          [pending FREES-64] Build images with Packer
  aws-bootstrap         [pending FREES-33] Bootstrap AWS prerequisites
  image-build           [pending FREES-36] Build the runner image on AWS

Reporting, docs and release
  report                [pending FREES-77] Generate the HTML report
  report-serve          [pending FREES-77] Serve the HTML report locally
  docs                  markdownlint and relative link check
  package               [pending FREES-39] Build the collection artifact
  release-check         [pending FREES-84] Verify release readiness

Housekeeping
  clean                 Remove caches and generated files
  ci                    Run the credential-free CI stages locally
endef
export HELP_TEXT

.PHONY: help bootstrap install format lint lint-ansible lint-python lint-yaml lint-actions \
	lint-iac lint-packer lint-repo lint-skills security typecheck test test-unit \
	test-integration test-coverage test-molecule-docker test-molecule-libvirt \
	test-molecule-golden test-idempotency test-compliance packer-validate packer-build \
	aws-bootstrap image-build report report-serve docs package release-check clean ci \
	require-uv

help:
	@printf '%s\n' "$$HELP_TEXT"

require-uv:
	@if [ -z "$(UV)" ]; then \
		printf 'error: uv is required but was not found on PATH\n' >&2; \
		printf 'install it from https://docs.astral.sh/uv/getting-started/installation/\n' >&2; \
		exit 1; \
	fi

install: require-uv
	uv sync --frozen
	$(RUN) pre-commit install

bootstrap: install
	@command -v git >/dev/null || { printf 'error: git is required\n' >&2; exit 1; }
	$(RUN) python --version
	$(RUN) pre-commit --version

format: require-uv
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

lint: lint-repo lint-skills lint-python lint-yaml lint-actions

lint-python: require-uv
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) pylint tools tests

lint-yaml: require-uv
	$(RUN) yamllint --strict .

lint-actions: require-uv
	$(RUN) actionlint

lint-repo: require-uv
	$(TRACKED) -- '*.yml' '*.yaml' '*.py' | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py

lint-skills: require-uv
	$(RUN) python tools/skills/validate_skills.py

lint-ansible:
	$(call NOT_IMPLEMENTED,lint-ansible,FREES-39)

lint-iac:
	$(call NOT_IMPLEMENTED,lint-iac,FREES-30)

lint-packer:
	$(call NOT_IMPLEMENTED,lint-packer,FREES-64)

security: require-uv
	$(RUN) bandit -c pyproject.toml -r tools -q
	$(RUN) pre-commit run gitleaks-history --hook-stage manual --all-files
	$(RUN) zizmor --persona $(ZIZMOR_PERSONA) .github/workflows

typecheck: require-uv
	$(RUN) mypy
	$(RUN) pyright

test: test-unit

test-unit: require-uv
	$(RUN) pytest tests/unit

test-coverage: require-uv
	$(RUN) pytest tests/unit --cov --cov-report=term-missing --cov-report=xml
	$(RUN) coverage report --include='tools/*' --fail-under=100

test-integration:
	$(call NOT_IMPLEMENTED,test-integration,FREES-60)

test-molecule-docker:
	$(call NOT_IMPLEMENTED,test-molecule-docker,FREES-59)

test-molecule-libvirt:
	$(call NOT_IMPLEMENTED,test-molecule-libvirt,FREES-61)

test-molecule-golden:
	$(call NOT_IMPLEMENTED,test-molecule-golden,FREES-63)

test-idempotency:
	$(call NOT_IMPLEMENTED,test-idempotency,FREES-60)

test-compliance:
	$(call NOT_IMPLEMENTED,test-compliance,FREES-62)

packer-validate:
	$(call NOT_IMPLEMENTED,packer-validate,FREES-64)

packer-build:
	$(call NOT_IMPLEMENTED,packer-build,FREES-64)

aws-bootstrap:
	$(call NOT_IMPLEMENTED,aws-bootstrap,FREES-33)

image-build:
	$(call NOT_IMPLEMENTED,image-build,FREES-36)

report:
	$(call NOT_IMPLEMENTED,report,FREES-77)

report-serve:
	$(call NOT_IMPLEMENTED,report-serve,FREES-77)

docs: require-uv
	$(RUN) pre-commit run markdownlint-cli2 --all-files
	$(TRACKED) -- '*.md' | xargs -0 -r $(RUN) python tools/docs/check_links.py

package:
	$(call NOT_IMPLEMENTED,package,FREES-39)

release-check:
	$(call NOT_IMPLEMENTED,release-check,FREES-84)

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} +

ci: lint typecheck test-coverage security docs
