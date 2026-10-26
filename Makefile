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
ANSIBLE_HOME ?= $(CURDIR)/build/ansible-home
ANSIBLE_COLLECTIONS_PATH ?= $(CURDIR)/build/collections
ANSIBLE_TEST_HOME ?= $(CURDIR)/build/ansible-test-home
export ANSIBLE_HOME ANSIBLE_COLLECTIONS_PATH
MOLECULE_DOCKER_SCENARIOS := docker-ubuntu docker-rhel-compatible
MOLECULE_DOCKER_SELFTEST ?= true
MOLECULE_SELFTEST_DIR := $(CURDIR)/build/molecule-selftest
MOLECULE_SELFTEST = MOLECULE_SCENARIO_NAME=docker-selftest $(RUN) ansible-playbook \
	-e molecule_instance_config='$(MOLECULE_SELFTEST_DIR)/instance_config.yml' -e molecule_no_log=false \
	-e molecule_selftest_dir='$(MOLECULE_SELFTEST_DIR)' -e @extensions/molecule/selftest/vars/platforms.yml
MOLECULE_SELFTEST_REFUSED := docker_host extra_args privileged local localhost loopback unknown mounted unmasked seccomp
COLLECTION_SOURCES := galaxy.yml README.md LICENSE NOTICE meta plugins roles playbooks changelogs docs \
	tests/unit/plugins tests/fixtures tests/sanity tests/integration extensions
TREE_SORT := sort -z
AWS_ACCOUNT_ID := 910736812072
AWS_REGION := eu-west-1
GITHUB_REPOSITORY := FreeSecDev/ansible-linux-compliance
STATE_BUCKET := freesecdev-tfstate-$(AWS_ACCOUNT_ID)-$(AWS_REGION)
IAC_ROOT_MODULES := infra/account
BOOTSTRAP_TEMPLATE := infra/bootstrap/bootstrap.sh.tmpl
BOOTSTRAP_SCRIPT := infra/bootstrap/bootstrap.local.sh
BOOTSTRAP_RENDER_SED := -e 's|@@AWS_ACCOUNT_ID@@|$(AWS_ACCOUNT_ID)|g' -e 's|@@AWS_REGION@@|$(AWS_REGION)|g' \
	-e 's|@@STATE_BUCKET@@|$(STATE_BUCKET)|g' -e 's|@@GITHUB_REPOSITORY@@|$(GITHUB_REPOSITORY)|g'
MANAGED_NODE_PYTHONS := 3.9 3.10 3.11 3.13 3.14
UNIT_PYTHONS := 3.9 3.12 3.14
BROWSER_TEST_DIR := build/browser-test
NAME_SET_PYTHONS := 3.9 3.10 3.11 3.12 3.13 3.14 3.15
NAME_SET_PYTHON ?=
NAME_SET_DIRECTORY := build/name-sets
AUDIT_EXCEPTIONS_DIR := build/test-audit-exceptions
AUDIT_EXCEPTIONS_INVENTORY := tests/playbooks/inventory/audit-exceptions.yml
AUDIT_EXCEPTIONS_FREE_RUNS ?= 10
AUDIT_EXCEPTIONS_FORBIDDEN :=Apply the exceptions file to the scan run|AUDIT-EXCEPTIONS-NOT-REACHED
AUDIT_EXCEPTIONS_PLAYBOOK := ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -e audit_exceptions_dir='$(CURDIR)/$(AUDIT_EXCEPTIONS_DIR)'
EVIDENCE_DIR := build/test-evidence
EVIDENCE_PLAYBOOK := ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -e evidence_test_dir='$(CURDIR)/$(EVIDENCE_DIR)'
EVIDENCE_REPORT := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.reporting
EVIDENCE_EXCEPTIONS := $(EVIDENCE_DIR)/exceptions/exceptions-valid.yml
EVIDENCE_BUNDLES := --evidence-bundle '$(EVIDENCE_DIR)/bundles/web01/synthetic-web01' \
	--evidence-bundle '$(EVIDENCE_DIR)/bundles/db01/synthetic-db01'
EVIDENCE_GATE_BUNDLES := --evidence-bundle '$(EVIDENCE_DIR)/bundles-gate/web01/gate-web01' \
	--evidence-bundle '$(EVIDENCE_DIR)/bundles-gate/db01/gate-db01' \
	--exceptions-file '$(EVIDENCE_DIR)/exceptions-gate/exceptions-valid.yml'
EVIDENCE_REPORT_CHECK := .sections.compliance.status == "available" and .sections.exceptions.status == "available" \
	and ([.sections.compliance.items[].format] | unique) == ["exceptions_evaluation"] \
	and ([.sections.compliance.groups[].summary.counts.waived] | add) == 2 \
	and .sections.exceptions.summary.by_status.stale == 1 and .sections.exceptions.summary.by_status.in_effect == 2 \
	and .sections.exceptions.exceptions_file.verified \
	and (.sections.exceptions.exceptions_file.path | endswith("/exceptions/exceptions-valid.yml")) \
	and (.overview.error | length) == 0
EVIDENCE_GATE_CHECK := .sections.compliance.status == "available" \
	and ([.sections.compliance.items[].format] | sort) == ["exceptions_evaluation", "scan_run"] \
	and ([.sections.compliance.groups[].summary.run_status] | sort) == ["completed", "failed"] \
	and ([.sections.compliance.groups[].host.hostname] | sort) == ["db01", "web01"]
EVIDENCE_TAMPERED_CHECK := .sections.compliance.status == "error" \
	and (.sections.compliance.gaps[0].reason | test("checksum mismatch for raw/scan/results.xml"))

EVIDENCE_ROUTES_PLAYBOOK := $(EVIDENCE_PLAYBOOK) tests/playbooks/audit-gate-routes.yml
EVIDENCE_FORGED_DEFERRAL := {"linux_compliance_audit_defer_gate": true, "__linux_compliance_audit_gate_deferred": true}

define evidence_gate_route
status=0; $(EVIDENCE_ROUTES_PLAYBOOK) $(2) > '$(EVIDENCE_DIR)/route-$(1).log' 2>&1 || status=$$?; \
	cat '$(EVIDENCE_DIR)/route-$(1).log'; \
	test "$$status" -eq 2 || { printf 'error: gate route %s gave exit status %s, not 2\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -q 'The audit reported 2 failed and 1 errored rule(s)' '$(EVIDENCE_DIR)/route-$(1).log' && \
	grep -q 'The scan did not complete (run_status failed)' '$(EVIDENCE_DIR)/route-$(1).log' || \
	{ printf 'error: gate route %s did not gate both hosts\n' '$(1)' >&2; exit 1; }; \
	if grep -q 'GATE-ROUTE-PASSED' '$(EVIDENCE_DIR)/route-$(1).log'; then \
		printf 'error: gate route %s let a host pass\n' '$(1)' >&2; exit 1; fi
endef

define evidence_expect_status
status=0; $(2) > '$(EVIDENCE_DIR)/$(1).log' 2>&1 || status=$$?; cat '$(EVIDENCE_DIR)/$(1).log'; \
	test "$$status" -eq $(3) || { printf 'error: %s gave exit status %s, not %s\n' '$(1)' "$$status" '$(3)' >&2; exit 1; }; \
	grep -q -- '$(4)' '$(EVIDENCE_DIR)/$(1).log' || { printf 'error: %s: the expected message is missing\n' '$(1)' >&2; exit 1; }
endef

ANSIBLE_TEST := PATH="$$(uv python dir --bin):$$PATH" uv run --frozen --project '$(CURDIR)' env HOME='$(ANSIBLE_TEST_HOME)' ansible-test

space := $(subst ,, )
DOCKER ?= docker
SCC_PINS := extensions/ci/scc/scc.pins
include $(SCC_PINS)
SCC_IMAGE ?= localhost/freesecdev-scc:local
SCC_CONTAINERFILE := extensions/ci/scc/Containerfile
SCC_DOWNLOAD_DIR := build/scc/download
SCC_CONTEXT_DIR := build/scc/context
SCC_FETCH_ENV := SCC_VERSION='$(SCC_VERSION)' SCC_BUNDLE='$(SCC_BUNDLE)' SCC_BUNDLE_URL='$(SCC_BUNDLE_URL)' \
	SCC_BUNDLE_SIZE='$(SCC_BUNDLE_SIZE)' SCC_BUNDLE_SHA256='$(SCC_BUNDLE_SHA256)' SCC_CHECKSUMS_URL='$(SCC_CHECKSUMS_URL)' \
	SCC_DEB_MEMBER='$(SCC_DEB_MEMBER)' SCC_DEB_SHA256='$(SCC_DEB_SHA256)' SCC_CSCC_SHA256='$(SCC_CSCC_SHA256)'
HADOLINT := build/tools/hadolint
SHELL_SCRIPTS := build/bootstrap.rendered.sh tools/iac/install-tofu.sh tools/browser/fetch-test-deps.sh \
	tools/lint/fetch-hadolint.sh tools/scc/fetch-scc.sh tools/scc/smoke-test.sh tools/scc/check-expiry.sh \
	tools/scc/needs-smoke.sh

PYLINT_BASE_IGNORES := ^\.venv/|^\.agents/|^\.claude/|^build/|^dist/
PYLINT_GUARD := tools/lint/check_repo_rules.py
PYLINT_GUARD_MAX_LINES := 1700
PYLINT_MODULE_DIRECTORIES := plugins/modules
PYLINT_MODULE_IGNORES := $(subst $(space),|,$(patsubst %,^%/,$(PYLINT_MODULE_DIRECTORIES)))

define audit_exceptions_expect_failure
status=0; $(AUDIT_EXCEPTIONS_PLAYBOOK) $(2) > '$(AUDIT_EXCEPTIONS_DIR)/$(1).log' 2>&1 || status=$$?; \
	cat '$(AUDIT_EXCEPTIONS_DIR)/$(1).log'; \
	test "$$status" -eq 2 || { printf 'error: %s did not fail the play (status %s)\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -q '$(3)' '$(AUDIT_EXCEPTIONS_DIR)/$(1).log' || { printf 'error: %s: the expected message is missing\n' '$(1)' >&2; exit 1; }; \
	if grep -qE '$(4)' '$(AUDIT_EXCEPTIONS_DIR)/$(1).log'; then printf 'error: %s: forbidden output found\n' '$(1)' >&2; exit 1; fi
endef

NOT_IMPLEMENTED = @printf 'not implemented yet: %s (tracked in %s)\n' '$(1)' '$(2)' >&2; exit 2

define HELP_TEXT
Usage: make <target>

Setup
  help                  Show this help
  bootstrap             Install tooling and git hooks, then verify the environment (git, jq)
  install               Sync the locked Python environment and install pre-commit and pre-push hooks

Formatting and linting
  format                Apply Ruff fixes and formatting
  lint                  Run every implemented linter (lock, repo, skills, python, yaml, actions, ansible, toggles, Containerfile)
  lint-python           Ruff lint, Ruff format check and Pylint
  lint-pylint           Pylint in two passes: wrong-import-position on, and off for plugins/modules only
  lint-yaml             yamllint in strict mode
  lint-actions          actionlint for GitHub workflows
  lint-containerfile    hadolint (pinned binary, fetched into build/tools) on the CI-only SCC Containerfile
  lint-repo             Repository source rules (document start, comments, banned modules)
  name-sets             Probe Python 3.9 to 3.15 and regenerate the guard name sets
  lint-skills           Validate agent skills under .agents/skills
  lint-ansible          ansible-lint (production profile), role argument spec check and antsibull-changelog lint
  lint-toggles          Fail when the generated toggles, their argument specs or their reference drift from the catalogue
  toggles               Regenerate the toggle defaults, argument specs and docs/remediation-variables.md
  lint-role-guards      Fail when the generated family dispatch or internal-variable guards drift from the roles
  role-guards           Regenerate the family dispatch and the internal-variable guards of the roles
  content               Fetch and verify the pinned SCAP content into build/content
  catalogue             Regenerate the rule catalogue and docs/control-families.md from build/content, then the toggles and role guards
  lint-iac              tofu fmt check, tofu validate per root module and shellcheck of the rendered bootstrap script
  lint-packer           [pending FREES-64] Packer validation

Security and types
  security              Bandit, Checkov, gitleaks history scan and zizmor
  typecheck             mypy strict and Pyright strict

Tests
  test                  Alias for test-unit
  test-unit             Unit tests, including the collection plugin tests
  test-sanity           ansible-test sanity on a temporary collection tree, no Docker
  test-ansible-units    ansible-test units on the temporary collection tree, no Docker
  test-coverage         Unit tests with branch coverage thresholds
  test-content-golden   Fetch the pinned content, compare the catalog with the recorded rule lists and check the catalogue for drift
  test-oscap-integration Fetch the pinned Ubuntu 24.04 content and scan the host with a real oscap, also through the audit role
  test-browser          Dashboard browser and accessibility tests in the pinned headless Chromium
  browser-test-deps     Fetch and verify the pinned headless Chromium and axe-core into build/
  test-name-sets        Check the guard name sets on one interpreter (NAME_SET_PYTHON=3.9.25)
  test-audit-exceptions Run the audit role's exceptions path on localhost with synthetic scan runs, without oscap
  test-evidence         Collect evidence bundles of synthetic audit results on localhost and report on them
  test-remediate-check  Run the remediate role and the audit toggle resolution against localhost in check mode, without become
  test-role-guards      Check in check mode that forged internal role variables are refused before any change
  test-verify           Run the verify role on localhost with synthetic baseline and later audits, without oscap
  test-integration      [pending FREES-60] Integration tests
  test-molecule-docker  Molecule Docker scenarios and their self-test (requires a running Docker daemon)
  test-molecule-docker-selftest Guard bypass attempts and the destroy fallback against real containers
  test-molecule-libvirt [pending FREES-61] Molecule libvirt scenarios
  test-molecule-golden  [pending FREES-63] Molecule golden image scenarios
  test-idempotency      [pending FREES-60] Idempotency checks
  test-compliance       [pending FREES-62] Compliance scan scenarios

Images and AWS
  packer-validate       [pending FREES-64] Validate Packer templates
  packer-build          [pending FREES-64] Build images with Packer
  aws-bootstrap-render  Render the gitignored bootstrap script from its template
  aws-bootstrap         Render and run the one-time interactive AWS account bootstrap
  image-build           [pending FREES-36] Build the runner image on AWS
  scc-expiry-check      Fail from seven days before SCC_EXPIRES, so an expiring SCC is never built or run
  scc-fetch             Download the pinned SCC bundle from DISA, verify it and stage its Debian package in build/scc
  scc-image             Build the CI-only SCC image locally as SCC_IMAGE (a localhost/ tag); it is never pushed
  scc-smoke             Build the SCC image and check that cscc starts and reports the pinned version
  scc-image-clean       Remove the local SCC_IMAGE

Reporting, docs and release
  report                Write the normalized report JSON and the HTML dashboard from REPORT_ARGS
  report-serve          Serve build/report on 127.0.0.1 only (REPORT_PORT, default 8765)
  docs                  markdownlint and relative link check
  package               Build the collection tarball into dist/ with a canonical FILES.json
  package-check         Build the tarball twice from differently ordered trees and compare SHA-256
  release-check         [pending FREES-84] Verify release readiness

Housekeeping
  collection-tree       Assemble the temporary collection tree under build/collection
  collection-link       Link plugins/ and roles/ into build/collections for pytest, type checkers and ansible-lint
  ansible-home          Create the per-checkout ANSIBLE_HOME and ansible-test HOME under build/
  clean                 Remove caches and generated files
  ci                    Run the credential-free CI stages locally (needs tofu on PATH)
endef
export HELP_TEXT

.PHONY: help bootstrap install format lint lint-ansible lint-toggles toggles lint-role-guards role-guards content catalogue lint-python lint-yaml lint-actions \
	lint-containerfile scc-expiry-check scc-fetch scc-image scc-smoke scc-image-clean lint-iac lock-check tofu-validate aws-bootstrap-render lint-packer lint-repo lint-skills security typecheck test test-unit test-sanity test-audit-exceptions test-evidence test-remediate-check test-role-guards test-verify \
	test-ansible-units package-check collection-tree collection-link sanity-pythons name-sets test-name-sets \
	test-integration test-coverage test-content-golden test-oscap-integration test-browser browser-test-deps molecule-dependencies molecule-content test-molecule-docker test-molecule-docker-selftest test-molecule-libvirt \
	test-molecule-golden test-idempotency test-compliance packer-validate packer-build \
	aws-bootstrap image-build report report-serve docs package release-check clean ci \
	require-uv ansible-home

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
	@command -v tofu >/dev/null || { printf 'error: tofu is required but was not found on PATH\n' >&2; printf 'install the pinned version with tools/iac/install-tofu.sh\n' >&2; exit 1; }
	@command -v jq >/dev/null || { printf 'error: jq is required by make package but was not found on PATH\n' >&2; printf 'install it with your package manager, for example: sudo apt-get install jq\n' >&2; exit 1; }
	$(RUN) python --version
	$(RUN) pre-commit --version

format: require-uv
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

lint: lock-check lint-repo lint-skills lint-python lint-yaml lint-actions lint-containerfile lint-ansible lint-toggles lint-role-guards

GENERATE_TOGGLES := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.generate_toggles
GENERATE_CATALOGUE := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.generate_catalogue

toggles: require-uv collection-link
	$(GENERATE_TOGGLES)

content: require-uv
	$(RUN) python tools/content/fetch_content.py --output-dir build/content

catalogue: require-uv collection-link
	$(GENERATE_CATALOGUE)
	$(GENERATE_TOGGLES)
	$(GENERATE_ROLE_GUARDS)

lint-toggles: require-uv collection-link
	$(GENERATE_TOGGLES) --check

GENERATE_ROLE_GUARDS := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.generate_role_guards

role-guards: require-uv collection-link
	$(GENERATE_ROLE_GUARDS)

lint-role-guards: require-uv collection-link
	$(GENERATE_ROLE_GUARDS) --check

lock-check: require-uv
	uv lock --check

lint-python: require-uv collection-link lint-pylint
	$(RUN) ruff check .
	$(RUN) ruff format --check .

lint-pylint: require-uv collection-link
	$(RUN) pylint --ignore-paths='$(PYLINT_BASE_IGNORES)|$(PYLINT_MODULE_IGNORES)' --ignore=$(notdir $(PYLINT_GUARD)) tools tests plugins
	$(RUN) pylint --disable=wrong-import-position $(PYLINT_MODULE_DIRECTORIES)
	$(RUN) pylint --max-module-lines=$(PYLINT_GUARD_MAX_LINES) $(PYLINT_GUARD)

lint-yaml: require-uv
	$(RUN) yamllint --strict .

lint-actions: require-uv
	$(RUN) actionlint

lint-containerfile:
	tools/lint/fetch-hadolint.sh '$(HADOLINT)'
	'$(HADOLINT)' --failure-threshold info $(SCC_CONTAINERFILE)

lint-repo: require-uv
	@if git ls-files | grep -E '(^|/)__pycache__/|\.py[cod]$$'; then printf 'error: compiled Python files are tracked\n' >&2; exit 1; fi
	$(TRACKED) -- '*.yml' '*.yaml' '*.py' | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py

lint-skills: require-uv
	$(RUN) python tools/skills/validate_skills.py

lint-ansible: require-uv collection-link molecule-dependencies
	$(RUN) ansible-lint
	PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.check_role_specs roles
	$(RUN) antsibull-changelog lint

lint-iac: require-uv
	@command -v tofu >/dev/null || { printf 'error: tofu is required; run tools/iac/install-tofu.sh\n' >&2; exit 1; }
	tofu fmt -check -recursive infra/
	$(MAKE) --no-print-directory tofu-validate
	mkdir -p build
	sed $(BOOTSTRAP_RENDER_SED) $(BOOTSTRAP_TEMPLATE) > build/bootstrap.rendered.sh
	$(RUN) shellcheck $(SHELL_SCRIPTS)

tofu-validate:
	@for module in $(IAC_ROOT_MODULES); do \
		tofu -chdir="$$module" init -backend=false -input=false -lockfile=readonly && \
		tofu -chdir="$$module" validate; \
	done

lint-packer:
	$(call NOT_IMPLEMENTED,lint-packer,FREES-64)

security: require-uv
	$(RUN) bandit -c pyproject.toml -r tools plugins -q -x plugins/module_utils/compliance/process.py
	$(RUN) bandit -c pyproject.toml -q -s B404,B603 plugins/module_utils/compliance/process.py
	$(RUN) pre-commit run gitleaks-history --hook-stage manual --all-files
	$(RUN) checkov --config-file .checkov.yaml
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

test-content-golden: require-uv collection-link content
	FREESECDEV_REQUIRE_CONTENT=1 $(RUN) pytest tests/unit/tools/test_content_golden.py --no-cov
	$(GENERATE_CATALOGUE) --check

test-oscap-integration: require-uv collection-link
	$(RUN) python tools/content/fetch_content.py --output-dir build/content --datastream ubuntu2404
	$(RUN) pytest tests/system --no-cov -v -s -p no:cacheprovider
	$(RUN) ansible-playbook -i localhost, tests/playbooks/audit-toggles-oscap.yml

browser-test-deps:
	tools/browser/fetch-test-deps.sh '$(BROWSER_TEST_DIR)'

test-browser: require-uv collection-link browser-test-deps
	FREESECDEV_BROWSER_TEST_DIR='$(CURDIR)/$(BROWSER_TEST_DIR)' $(RUN) pytest tests/browser --no-cov

name-sets: require-uv
	rm -rf $(NAME_SET_DIRECTORY)
	mkdir -p $(NAME_SET_DIRECTORY)
	modules="$$($(RUN) python -m tools.lint.generate_name_sets --modules)"; \
	for version in $(NAME_SET_PYTHONS); do \
		interpreter="$$(uv python find --no-project "$$version")"; \
		"$$interpreter" -I -S tools/lint/name_set_probe.py $$modules > "$(NAME_SET_DIRECTORY)/$$version.json"; \
	done
	$(RUN) python -m tools.lint.generate_name_sets $(NAME_SET_DIRECTORY)/*.json

test-name-sets: require-uv collection-link
	@test -n '$(NAME_SET_PYTHON)' || { printf 'error: set NAME_SET_PYTHON to an installed Python version, for example 3.9.25\n' >&2; exit 2; }
	FREESECDEV_NAME_SET_PYTHON="$$(uv python find --no-project '$(NAME_SET_PYTHON)')" $(RUN) pytest tests/unit/tools/test_name_sets.py --no-cov

test-audit-exceptions: require-uv collection-link
	rm -rf '$(AUDIT_EXCEPTIONS_DIR)'
	mkdir -p '$(AUDIT_EXCEPTIONS_DIR)'
	$(AUDIT_EXCEPTIONS_PLAYBOOK) -i $(AUDIT_EXCEPTIONS_INVENTORY) tests/playbooks/audit-exceptions.yml
	$(AUDIT_EXCEPTIONS_PLAYBOOK) -i $(AUDIT_EXCEPTIONS_INVENTORY) --limit db01,localhost tests/playbooks/audit-exceptions-limit.yml \
		| tee '$(AUDIT_EXCEPTIONS_DIR)/limit.log'
	grep -q 'unmatched on 1 of 2 target hosts; not covered: web01' '$(AUDIT_EXCEPTIONS_DIR)/limit.log'
	if grep -q 'review and remove' '$(AUDIT_EXCEPTIONS_DIR)/limit.log'; then printf 'error: a limited run advised removal\n' >&2; exit 1; fi
	$(call audit_exceptions_expect_failure,invalid,-i $(AUDIT_EXCEPTIONS_INVENTORY) tests/playbooks/audit-exceptions-invalid.yml,missing keys: risk,$(AUDIT_EXCEPTIONS_FORBIDDEN))
	$(call audit_exceptions_expect_failure,serial,-i tests/playbooks/inventory/audit-exceptions-split.yml tests/playbooks/audit-exceptions-serial.yml,also across serial,$(AUDIT_EXCEPTIONS_FORBIDDEN))
	for run in $$(seq 1 $(AUDIT_EXCEPTIONS_FREE_RUNS)); do \
		$(call audit_exceptions_expect_failure,free,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e audit_exceptions_free_run=$$run tests/playbooks/audit-exceptions-free.yml,does not support the free strategy,AUDIT-EXCEPTIONS-NOT-REACHED); \
		$(AUDIT_EXCEPTIONS_PLAYBOOK) -i $(AUDIT_EXCEPTIONS_INVENTORY) -e audit_exceptions_free_run=$$run tests/playbooks/audit-exceptions-free-check.yml; \
	done

test-evidence: require-uv collection-link
	rm -rf '$(EVIDENCE_DIR)'
	mkdir -p '$(EVIDENCE_DIR)'
	$(EVIDENCE_PLAYBOOK) -i $(AUDIT_EXCEPTIONS_INVENTORY) -e audit_exceptions_dir='$(CURDIR)/$(EVIDENCE_DIR)/exceptions' \
		tests/playbooks/evidence.yml | tee '$(EVIDENCE_DIR)/playbook.log'
	if grep -q 'FREESECDEV-PLANTED' '$(EVIDENCE_DIR)/playbook.log'; then printf 'error: a planted secret was printed\n' >&2; exit 1; fi
	$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/report.json' $(EVIDENCE_BUNDLES) \
		--exceptions-file '$(EVIDENCE_EXCEPTIONS)'
	jq -e '$(EVIDENCE_REPORT_CHECK)' '$(EVIDENCE_DIR)/report.json' > /dev/null
	$(call evidence_expect_status,unreviewed,$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/unreviewed.json' $(EVIDENCE_BUNDLES),2,requires --exceptions-file)
	$(call evidence_expect_status,foreign,$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/foreign.json' $(EVIDENCE_BUNDLES) --exceptions-file '$(EVIDENCE_DIR)/exceptions-changed.yml',2,not byte-identical to --exceptions-file)
	test ! -e '$(EVIDENCE_DIR)/unreviewed.json' && test ! -e '$(EVIDENCE_DIR)/foreign.json'
	cp -a '$(EVIDENCE_DIR)/bundles/web01/synthetic-web01' '$(EVIDENCE_DIR)/tampered'
	printf ' ' >> '$(EVIDENCE_DIR)/tampered/raw/scan/results.xml'
	$(call evidence_expect_status,tampered,$(EVIDENCE_REPORT) --scope single_host --output '$(EVIDENCE_DIR)/tampered.json' --evidence-bundle '$(EVIDENCE_DIR)/tampered' --exceptions-file '$(EVIDENCE_EXCEPTIONS)',1,report written)
	jq -e '$(EVIDENCE_TAMPERED_CHECK)' '$(EVIDENCE_DIR)/tampered.json' > /dev/null
	status=0; $(EVIDENCE_PLAYBOOK) -i tests/playbooks/inventory/evidence-gate.yml \
		-e audit_exceptions_dir='$(CURDIR)/$(EVIDENCE_DIR)/exceptions-gate' tests/playbooks/evidence-gate.yml \
		> '$(EVIDENCE_DIR)/gate.log' 2>&1 || status=$$?; cat '$(EVIDENCE_DIR)/gate.log'; \
		test "$$status" -ne 0 || { printf 'error: the gated play did not fail\n' >&2; exit 1; }
	grep -q 'WARNING: no evidence bundle for 2 of 4 target host(s): app01, lost01' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'The audit reported 2 failed and 1 errored rule(s)' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'The scan did not complete (run_status failed)' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'EVIDENCE-GATE-PASSED app01' '$(EVIDENCE_DIR)/gate.log'
	if grep -qE 'EVIDENCE-GATE-PASSED (web01|db01)' '$(EVIDENCE_DIR)/gate.log'; then printf 'error: a gated host passed\n' >&2; exit 1; fi
	grep -qE '^web01 +: .*failed=1' '$(EVIDENCE_DIR)/gate.log'
	grep -qE '^db01 +: .*failed=1' '$(EVIDENCE_DIR)/gate.log'
	grep -qE '^lost01 +: .*unreachable=1' '$(EVIDENCE_DIR)/gate.log'
	$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/gate.json' $(EVIDENCE_GATE_BUNDLES)
	$(call evidence_gate_route,baseline,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=baseline)
	$(call evidence_gate_route,extra,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=baseline -e '$(EVIDENCE_FORGED_DEFERRAL)')
	$(call evidence_gate_route,group_vars,-i tests/playbooks/inventory/gate-routes-group -e gate_route=baseline)
	$(call evidence_gate_route,host_vars,-i tests/playbooks/inventory/gate-routes-host -e gate_route=baseline)
	$(call evidence_gate_route,include,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=include)
	$(call evidence_gate_route,import,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=import)
	jq -e '$(EVIDENCE_GATE_CHECK)' '$(EVIDENCE_DIR)/gate.json' > /dev/null

REMEDIATE_CHECK = $(RUN) ansible-playbook -i localhost, --check

test-remediate-check: require-uv collection-link
	$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-check-mode.yml
	$(REMEDIATE_CHECK) --skip-tags file_permissions tests/playbooks/remediate-check-mode.yml
	$(REMEDIATE_CHECK) --skip-tags always tests/playbooks/remediate-skip-always.yml

ROLE_GUARDS_DIR := build/test-role-guards
ROLE_GUARDS_FORGED_PLAN := {"__linux_compliance_remediate_plan": {"enabled": true, "errors": [], \
	"families": [{"name": "../../../../tmp/forged", "disruptive": false, "apply": [], "cleanup": []}]}}
ROLE_GUARDS_FORGED_FAMILY := {"__linux_compliance_remediate_family": {"name": "../../../../tmp/forged"}}

ROLE_GUARDS_REFUSALS := is set from outside the role|Validation of arguments failed

define role_guards_expect_refusal
status=0; ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -i forged_plan,forged_family,forged_vars, --limit $(1) --check \
		tests/playbooks/internal-variables-role-param.yml > '$(ROLE_GUARDS_DIR)/$(1).log' 2>&1 || status=$$?; \
	cat '$(ROLE_GUARDS_DIR)/$(1).log'; \
	test "$$status" -eq 2 || { printf 'error: %s did not fail the play (status %s)\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -qE '$(ROLE_GUARDS_REFUSALS)' '$(ROLE_GUARDS_DIR)/$(1).log' || { printf 'error: %s was not refused\n' '$(1)' >&2; exit 1; }; \
	if grep -q 'Remediate | Read the state ledger' '$(ROLE_GUARDS_DIR)/$(1).log'; then \
		printf 'error: the role went on after %s\n' '$(1)' >&2; exit 1; fi
endef

test-role-guards: require-uv collection-link
	rm -rf '$(ROLE_GUARDS_DIR)'
	mkdir -p '$(ROLE_GUARDS_DIR)'
	$(REMEDIATE_CHECK) tests/playbooks/internal-variables-include.yml
	$(REMEDIATE_CHECK) -e '$(ROLE_GUARDS_FORGED_PLAN)' -e internal_forged_variable=__linux_compliance_remediate_plan \
		tests/playbooks/internal-variables-extra.yml
	$(REMEDIATE_CHECK) -e '$(ROLE_GUARDS_FORGED_FAMILY)' -e internal_forged_variable=__linux_compliance_remediate_family \
		tests/playbooks/internal-variables-extra.yml
	$(call role_guards_expect_refusal,forged_plan)
	$(call role_guards_expect_refusal,forged_family)
	ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -i forged_plan,forged_family,forged_vars, --limit forged_vars --check \
		tests/playbooks/internal-variables-role-param.yml > '$(ROLE_GUARDS_DIR)/forged_vars.log' 2>&1 || \
		{ cat '$(ROLE_GUARDS_DIR)/forged_vars.log'; exit 1; }
	if grep -q 'tmp/forged' '$(ROLE_GUARDS_DIR)/forged_vars.log'; then \
		printf 'error: role variables of a roles entry replaced the plan\n' >&2; exit 1; fi

VERIFY_DIR := build/test-verify
VERIFY_PLAYBOOK := ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -i $(AUDIT_EXCEPTIONS_INVENTORY) \
	-e audit_exceptions_dir='$(CURDIR)/$(VERIFY_DIR)'

test-verify: require-uv collection-link
	rm -rf '$(VERIFY_DIR)'
	mkdir -p '$(VERIFY_DIR)'
	$(VERIFY_PLAYBOOK) tests/playbooks/verify.yml | tee '$(VERIFY_DIR)/verify.log'
	grep -q 'WARNING: REGRESSION on web01: 1 rule(s) passed in the baseline and no longer pass' '$(VERIFY_DIR)/verify.log'
	grep -q 'WARNING: NEW FAILURE on web01: 1 rule(s) were not applicable or missing in the baseline and fail now' '$(VERIFY_DIR)/verify.log'
	grep -q 'passed in the baseline and are not applicable now' '$(VERIFY_DIR)/verify.log'
	$(VERIFY_PLAYBOOK) -i tests/playbooks/inventory/verify-forged.yml tests/playbooks/verify-forged.yml | tee -a '$(VERIFY_DIR)/verify.log'
	$(VERIFY_PLAYBOOK) -e '{"linux_compliance_baseline": {"run_id": "stale-baseline"}}' \
		-e verify_expected_task='Check that the baseline is the audit that just ran' tests/playbooks/verify-baseline-override.yml
	$(VERIFY_PLAYBOOK) -e '{"ansible_facts": {"__linux_compliance_verify_baseline_recorded": {"run_id": "verify-baseline"}}}' \
		-e verify_expected_task='Check that no baseline marker is set' tests/playbooks/verify-baseline-override.yml
	$(VERIFY_PLAYBOOK) tests/playbooks/verify-preflight.yml | tee -a '$(VERIFY_DIR)/verify.log'
	$(VERIFY_PLAYBOOK) --skip-tags always tests/playbooks/verify-skip-always.yml
	if grep -qE 'VERIFY-[A-Z-]+-NOT-(FAILED|REFUSED)' '$(VERIFY_DIR)/verify.log'; then printf 'error: a verify check was not enforced\n' >&2; exit 1; fi

sanity-pythons: require-uv
	uv python install $(MANAGED_NODE_PYTHONS)

test-sanity: require-uv collection-tree sanity-pythons
	cd $(COLLECTION_TREE) && $(ANSIBLE_TEST) sanity --local

test-ansible-units: require-uv collection-tree sanity-pythons
	cd $(COLLECTION_TREE) && for version in $(UNIT_PYTHONS); do $(ANSIBLE_TEST) units --venv --python $$version; done

test-integration:
	$(call NOT_IMPLEMENTED,test-integration,FREES-60)

molecule-dependencies: require-uv collection-link
	$(RUN) ansible-galaxy collection install -r extensions/molecule/requirements.yml -p '$(ANSIBLE_COLLECTIONS_PATH)'

molecule-content: require-uv
	$(RUN) python tools/content/fetch_content.py --output-dir build/content --datastream ubuntu2404 --datastream rhel9

test-molecule-docker: require-uv molecule-dependencies molecule-content
	@docker info >/dev/null 2>&1 || { printf 'error: a running Docker daemon is required\n' >&2; exit 1; }
	for scenario in $(MOLECULE_DOCKER_SCENARIOS); do \
		$(RUN) molecule test -s "$$scenario" || exit 1; \
	done
	if [ '$(MOLECULE_DOCKER_SELFTEST)' = true ]; then $(MAKE) --no-print-directory test-molecule-docker-selftest; fi

test-molecule-docker-selftest: require-uv molecule-dependencies
	@docker info >/dev/null 2>&1 || { printf 'error: a running Docker daemon is required\n' >&2; exit 1; }
	rm -rf '$(MOLECULE_SELFTEST_DIR)'
	mkdir -p '$(MOLECULE_SELFTEST_DIR)/host-directory'
	status=0; \
	$(MOLECULE_SELFTEST) extensions/molecule/shared/create.yml || status=1; \
	if [ $$status -eq 0 ]; then $(MOLECULE_SELFTEST) extensions/molecule/shared/create.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then $(MOLECULE_SELFTEST) extensions/molecule/selftest/assert_created.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then $(MOLECULE_SELFTEST) extensions/molecule/selftest/bypass.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then \
		$(MOLECULE_SELFTEST) -i '$(MOLECULE_SELFTEST_DIR)/good.yml' extensions/molecule/shared/guard.yml \
			> '$(MOLECULE_SELFTEST_DIR)/good.log' 2>&1 || { cat '$(MOLECULE_SELFTEST_DIR)/good.log'; status=1; }; \
	fi; \
	for case in $(MOLECULE_SELFTEST_REFUSED); do \
		[ $$status -eq 0 ] || break; \
		config='$(MOLECULE_SELFTEST_DIR)/instance_config.yml'; \
		if [ -f "$(MOLECULE_SELFTEST_DIR)/instance_config_$$case.yml" ]; then config="$(MOLECULE_SELFTEST_DIR)/instance_config_$$case.yml"; fi; \
		if $(MOLECULE_SELFTEST) -e "molecule_instance_config=$$config" -i "$(MOLECULE_SELFTEST_DIR)/$$case.yml" \
			extensions/molecule/shared/guard.yml > "$(MOLECULE_SELFTEST_DIR)/$$case.log" 2>&1; then \
			printf 'error: the guard accepted the bypass attempt %s\n' "$$case" >&2; status=1; \
		elif ! grep -q 'Refusing to run' "$(MOLECULE_SELFTEST_DIR)/$$case.log"; then \
			cat "$(MOLECULE_SELFTEST_DIR)/$$case.log"; \
			printf 'error: the bypass attempt %s failed for another reason than the guard\n' "$$case" >&2; status=1; \
		elif [ -f "$(MOLECULE_SELFTEST_DIR)/instance_config_$$case.yml" ] \
			&& ! grep -q 'is not isolated' "$(MOLECULE_SELFTEST_DIR)/$$case.log"; then \
			cat "$(MOLECULE_SELFTEST_DIR)/$$case.log"; \
			printf 'error: the decoy %s was not refused by the isolation check\n' "$$case" >&2; status=1; \
		else printf 'guard refused the bypass attempt %s\n' "$$case"; fi; \
	done; \
	printf '[]\n' > '$(MOLECULE_SELFTEST_DIR)/instance_config.yml'; \
	$(MOLECULE_SELFTEST) extensions/molecule/shared/destroy.yml || status=1; \
	$(MOLECULE_SELFTEST) extensions/molecule/selftest/assert_destroyed.yml || status=1; \
	if [ $$status -eq 0 ]; then $(MOLECULE_SELFTEST) extensions/molecule/shared/create.yml || status=1; fi; \
	rm -f '$(MOLECULE_SELFTEST_DIR)/instance_config.yml'; \
	$(MOLECULE_SELFTEST) extensions/molecule/shared/destroy.yml || status=1; \
	$(MOLECULE_SELFTEST) extensions/molecule/selftest/assert_destroyed.yml || status=1; \
	exit $$status

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

aws-bootstrap-render:
	@printf '%s' '$(AWS_ACCOUNT_ID)' | grep -Eq '^[0-9]{12}$$' || { printf 'error: AWS_ACCOUNT_ID must be 12 digits\n' >&2; exit 1; }
	@printf '%s' '$(AWS_REGION)' | grep -Eq '^(eu-west-[123]|eu-central-1|eu-north-1)$$' || { printf 'error: AWS_REGION is not allow-listed\n' >&2; exit 1; }
	@printf '%s' '$(STATE_BUCKET)' | grep -Eq '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$$' || { printf 'error: STATE_BUCKET is not a valid S3 bucket name\n' >&2; exit 1; }
	@printf '%s' '$(GITHUB_REPOSITORY)' | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$$' || { printf 'error: GITHUB_REPOSITORY must be owner/name\n' >&2; exit 1; }
	@mkdir -p $(dir $(BOOTSTRAP_SCRIPT))
	sed $(BOOTSTRAP_RENDER_SED) $(BOOTSTRAP_TEMPLATE) > $(BOOTSTRAP_SCRIPT)
	chmod 0700 $(BOOTSTRAP_SCRIPT)

aws-bootstrap: aws-bootstrap-render
	bash $(BOOTSTRAP_SCRIPT)

image-build:
	$(call NOT_IMPLEMENTED,image-build,FREES-36)

scc-expiry-check:
	tools/scc/check-expiry.sh '$(SCC_EXPIRES)'

scc-fetch:
	$(SCC_FETCH_ENV) tools/scc/fetch-scc.sh '$(SCC_DOWNLOAD_DIR)' '$(SCC_CONTEXT_DIR)'

scc-image: scc-expiry-check lint-containerfile scc-fetch
	@printf '%s' '$(SCC_IMAGE)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: SCC_IMAGE must be a localhost/ tag\n' >&2; exit 2; }
	$(DOCKER) build --network none --file $(SCC_CONTAINERFILE) --tag '$(SCC_IMAGE)' \
		--build-arg SCC_VERSION='$(SCC_VERSION)' --build-arg SCC_DEB_SHA256='$(SCC_DEB_SHA256)' \
		--build-arg SCC_CSCC_SHA256='$(SCC_CSCC_SHA256)' '$(SCC_CONTEXT_DIR)'

scc-smoke: scc-image
	tools/scc/smoke-test.sh '$(SCC_IMAGE)' '$(SCC_VERSION)'

scc-image-clean:
	@printf '%s' '$(SCC_IMAGE)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: SCC_IMAGE must be a localhost/ tag\n' >&2; exit 2; }
	$(DOCKER) image rm --force '$(SCC_IMAGE)'

REPORT_SCOPE ?=
REPORT_ARGS ?=
REPORT_OUTPUT ?= build/report/report.json
REPORT_HTML ?= build/report/report.html
REPORT_PORT ?= 8765
REPORT_SERVE_DIR := build/report

report: require-uv collection-link
	@test -n '$(REPORT_SCOPE)' || { printf 'error: set REPORT_SCOPE to single_host, multi_host, benchmark or fleet\n' >&2; exit 2; }
	PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.reporting --scope '$(REPORT_SCOPE)' --output '$(REPORT_OUTPUT)' --html '$(REPORT_HTML)' $(REPORT_ARGS)

report-serve: require-uv
	@printf '%s' '$(REPORT_PORT)' | grep -Eq '^[1-9][0-9]{3,4}$$' && [ '$(REPORT_PORT)' -le 65535 ] || { printf 'error: REPORT_PORT must be a port from 1000 to 65535\n' >&2; exit 2; }
	@served="$$(realpath -m -- '$(REPORT_SERVE_DIR)')" && [ "$$served" = "$$(realpath -m -- .)/$(REPORT_SERVE_DIR)" ] && [ "$$(realpath -m -- '$(dir $(REPORT_HTML))')" = "$$served" ] || { printf 'error: report-serve serves only %s; REPORT_HTML must be a file directly inside it\n' '$(REPORT_SERVE_DIR)' >&2; exit 2; }
	@test -f '$(REPORT_HTML)' || { printf 'error: %s does not exist; run make report first\n' '$(REPORT_HTML)' >&2; exit 2; }
	@printf 'serving %s on http://127.0.0.1:%s/ (loopback only, stop with Ctrl+C)\n' '$(REPORT_SERVE_DIR)' '$(REPORT_PORT)'
	$(RUN) python -m http.server --bind 127.0.0.1 --directory '$(REPORT_SERVE_DIR)' '$(REPORT_PORT)'

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

ansible-home:
	mkdir -p '$(ANSIBLE_HOME)' '$(ANSIBLE_TEST_HOME)'

collection-link: ansible-home
	mkdir -p $(COLLECTION_LINK)
	ln -sfn ../../../../../plugins $(COLLECTION_LINK)/plugins
	ln -sfn ../../../../../roles $(COLLECTION_LINK)/roles

collection-tree: ansible-home
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

ci: lint lint-iac typecheck test-coverage test-browser test-audit-exceptions test-evidence test-remediate-check test-role-guards test-verify security docs test-sanity test-ansible-units package-check
