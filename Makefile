SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

UV := $(shell command -v uv 2>/dev/null)
RUN := uv run --frozen
TRACKED := git ls-files -z --cached --others --exclude-standard
ZIZMOR_PERSONA := pedantic
COLLECTION_PATH := ansible_collections/freesecdev/linux_compliance
COLLECTION_TREE := build/collection/$(COLLECTION_PATH)
COLLECTION_LINK := build/collections/$(COLLECTION_PATH)
COLLECTION_SOURCES := galaxy.yml README.md LICENSE NOTICE meta plugins roles playbooks changelogs docs \
	tests/unit/plugins tests/sanity tests/integration extensions
TREE_SORT := sort -z
MANAGED_NODE_PYTHONS := 3.9 3.10 3.11 3.13 3.14
UNIT_PYTHONS := 3.9 3.12 3.14
ANSIBLE_TEST := PATH="$$(uv python dir --bin):$$PATH" uv run --frozen --project '$(CURDIR)' ansible-test

NOT_IMPLEMENTED = @printf 'not implemented yet: %s (tracked in %s)\n' '$(1)' '$(2)' >&2; exit 2

define HELP_TEXT
Usage: make <target>

Setup
  help                  Show this help
  bootstrap             Install tooling and git hooks, then verify the environment
  install               Sync the locked Python environment and install pre-commit and pre-push hooks

Formatting and linting
  format                Apply Ruff fixes and formatting
  lint                  Run every implemented linter (repo, skills, python, yaml, actions, ansible)
  lint-python           Ruff lint, Ruff format check and Pylint
  lint-yaml             yamllint in strict mode
  lint-actions          actionlint for GitHub workflows
  lint-repo             Repository source rules (document start, comments, banned modules)
  lint-skills           Validate agent skills under .agents/skills
  lint-ansible          ansible-lint (production profile) and antsibull-changelog lint
  lint-iac              [pending FREES-30] OpenTofu validation and Checkov
  lint-packer           [pending FREES-64] Packer validation

Security and types
  security              Bandit, gitleaks history scan and zizmor
  typecheck             mypy strict and Pyright strict

Tests
  test                  Alias for test-unit
  test-unit             Unit tests, including the collection plugin tests
  test-sanity           ansible-test sanity on a temporary collection tree, no Docker
  test-ansible-units    ansible-test units on the temporary collection tree, no Docker
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
  package               Build the collection tarball into dist/ with a canonical FILES.json
  package-check         Build the tarball twice from differently ordered trees and compare SHA-256
  release-check         [pending FREES-84] Verify release readiness

Housekeeping
  collection-tree       Assemble the temporary collection tree under build/collection
  collection-link       Link plugins/ into build/collections for pytest and type checkers
  clean                 Remove caches and generated files
  ci                    Run the credential-free CI stages locally
endef
export HELP_TEXT

.PHONY: help bootstrap install format lint lint-ansible lint-python lint-yaml lint-actions \
	lint-iac lint-packer lint-repo lint-skills security typecheck test test-unit test-sanity \
	test-ansible-units package-check collection-tree collection-link sanity-pythons \
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

install: require-uv collection-link
	uv sync --frozen
	$(RUN) pre-commit install

bootstrap: install
	@command -v git >/dev/null || { printf 'error: git is required\n' >&2; exit 1; }
	$(RUN) python --version
	$(RUN) pre-commit --version

format: require-uv
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

lint: lint-repo lint-skills lint-python lint-yaml lint-actions lint-ansible

lint-python: require-uv collection-link
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) pylint tools tests plugins

lint-yaml: require-uv
	$(RUN) yamllint --strict .

lint-actions: require-uv
	$(RUN) actionlint

lint-repo: require-uv
	$(TRACKED) -- '*.yml' '*.yaml' '*.py' | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py

lint-skills: require-uv
	$(RUN) python tools/skills/validate_skills.py

lint-ansible: require-uv
	$(RUN) ansible-lint
	$(RUN) antsibull-changelog lint

lint-iac:
	$(call NOT_IMPLEMENTED,lint-iac,FREES-30)

lint-packer:
	$(call NOT_IMPLEMENTED,lint-packer,FREES-64)

security: require-uv
	$(RUN) bandit -c pyproject.toml -r tools plugins -q
	$(RUN) pre-commit run gitleaks-history --hook-stage manual --all-files
	$(RUN) zizmor --persona $(ZIZMOR_PERSONA) .github/workflows

typecheck: require-uv collection-link
	$(RUN) mypy
	$(RUN) pyright

test: test-unit

test-unit: require-uv collection-link
	$(RUN) pytest tests/unit

test-coverage: require-uv collection-link
	$(RUN) pytest tests/unit --cov --cov-report=term-missing --cov-report=xml
	$(RUN) coverage report --include='tools/*' --fail-under=100
	$(RUN) coverage report --include='plugins/*' --fail-under=100

sanity-pythons: require-uv
	uv python install $(MANAGED_NODE_PYTHONS)

test-sanity: require-uv collection-tree sanity-pythons
	cd $(COLLECTION_TREE) && $(ANSIBLE_TEST) sanity --local

test-ansible-units: require-uv collection-tree sanity-pythons
	cd $(COLLECTION_TREE) && for version in $(UNIT_PYTHONS); do $(ANSIBLE_TEST) units --venv --python $$version; done

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

package: require-uv collection-tree
	rm -rf dist build/package
	mkdir -p dist build/package/raw build/package/content
	cd $(COLLECTION_TREE) && uv run --frozen --project '$(CURDIR)' ansible-galaxy collection build --force --output-path '$(CURDIR)/build/package/raw'
	archive="$$(basename build/package/raw/*.tar.gz)" && \
		tar -xzpf "build/package/raw/$$archive" -C build/package/content && \
		(cd build/package/content && jq --indent 1 '.files |= sort_by(.name)' FILES.json > FILES.json.new && mv FILES.json.new FILES.json && \
			sum="$$(sha256sum FILES.json | cut -d' ' -f1)" && \
			jq --indent 1 --arg sum "$$sum" '.file_manifest_file.chksum_sha256 = $$sum' MANIFEST.json > MANIFEST.json.new && mv MANIFEST.json.new MANIFEST.json && \
			chmod 0644 FILES.json MANIFEST.json && \
			jq -e '(.files | map(.name)) as $$names | $$names == ($$names | sort)' FILES.json > /dev/null) && \
		(cd build/package/content && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort > ../members.txt) && \
		(cd build/package/content && tar --no-recursion --owner=0 --group=0 --numeric-owner --mtime='@0' -cf - -T ../members.txt | gzip -n -9 > "$(CURDIR)/dist/$$archive")
	cd dist && sha256sum -- *.tar.gz | tee SHA256SUMS

package-check: require-uv
	$(MAKE) package
	cp dist/SHA256SUMS build/package-first.sums
	$(MAKE) package TREE_SORT='sort -z -r'
	diff build/package-first.sums dist/SHA256SUMS

collection-link:
	mkdir -p $(COLLECTION_LINK)
	ln -sfn ../../../../../plugins $(COLLECTION_LINK)/plugins

collection-tree:
	rm -rf build/collection
	mkdir -p $(COLLECTION_TREE)
	git ls-files -z --cached --others --exclude-standard -- $(COLLECTION_SOURCES) | $(TREE_SORT) | tar --null -T - -cf - | tar -xf - -C $(COLLECTION_TREE)
	git -C $(COLLECTION_TREE) init --quiet
	printf 'tests/output/\n' > $(COLLECTION_TREE)/.git/info/exclude
	git -C $(COLLECTION_TREE) add --all

release-check:
	$(call NOT_IMPLEMENTED,release-check,FREES-84)

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage coverage.xml htmlcov build dist
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} +

ci: lint typecheck test-coverage security docs test-sanity test-ansible-units package-check
