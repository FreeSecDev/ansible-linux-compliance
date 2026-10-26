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
AUDIT_EXCEPTIONS_FORBIDDEN := Apply the exceptions file to the scan run|AUDIT-EXCEPTIONS-NOT-REACHED
AUDIT_EXCEPTIONS_PLAYBOOK := ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -e audit_exceptions_dir='$(CURDIR)/$(AUDIT_EXCEPTIONS_DIR)'
ANSIBLE_TEST := PATH="$$(uv python dir --bin):$$PATH" uv run --frozen --project '$(CURDIR)' env HOME='$(ANSIBLE_TEST_HOME)' ansible-test

space := $(subst ,, )
PYLINT_BASE_IGNORES := ^\.venv/|^\.agents/|^\.claude/|^build/|^dist/
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
  lint                  Run every implemented linter (lock, repo, skills, python, yaml, actions, ansible, toggles)
  lint-python           Ruff lint, Ruff format check and Pylint
  lint-pylint           Pylint in two passes: wrong-import-position on, and off for plugins/modules only
  lint-yaml             yamllint in strict mode
  lint-actions          actionlint for GitHub workflows
  lint-repo             Repository source rules (document start, comments, banned modules)
  name-sets             Probe Python 3.9 to 3.15 and regenerate the guard name sets
  lint-skills           Validate agent skills under .agents/skills
  lint-ansible          ansible-lint (production profile), role argument spec check and antsibull-changelog lint
  lint-toggles          Fail when the generated toggles, their argument specs or their reference drift from the catalogue
  toggles               Regenerate the toggle defaults, argument specs and docs/remediation-variables.md
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
  test-content-golden   Fetch the pinned content and compare the catalog with the recorded rule lists
  test-oscap-integration Fetch the pinned Ubuntu 24.04 content and scan the host with a real oscap
  test-browser          Dashboard browser and accessibility tests in the pinned headless Chromium
  browser-test-deps     Fetch and verify the pinned headless Chromium and axe-core into build/
  test-name-sets        Check the guard name sets on one interpreter (NAME_SET_PYTHON=3.9.25)
  test-audit-exceptions Run the audit role's exceptions path on localhost with synthetic scan runs, without oscap
  test-remediate-check  Run the remediate role and the audit toggle resolution against localhost in check mode, without become
  test-verify           Run the verify role on localhost with synthetic baseline and later audits, without oscap
  test-integration      [pending FREES-60] Integration tests
  test-molecule-docker  [pending FREES-59] Molecule Docker scenarios
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

.PHONY: help bootstrap install format lint lint-ansible lint-toggles toggles lint-python lint-yaml lint-actions \
	lint-iac lock-check tofu-validate aws-bootstrap-render lint-packer lint-repo lint-skills security typecheck test test-unit test-sanity test-audit-exceptions test-remediate-check test-verify \
	test-ansible-units package-check collection-tree collection-link sanity-pythons name-sets test-name-sets \
	test-integration test-coverage test-content-golden test-oscap-integration test-browser browser-test-deps test-molecule-docker test-molecule-libvirt \
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

lint: lock-check lint-repo lint-skills lint-python lint-yaml lint-actions lint-ansible lint-toggles

GENERATE_TOGGLES := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.generate_toggles

toggles: require-uv collection-link
	$(GENERATE_TOGGLES)

lint-toggles: require-uv collection-link
	$(GENERATE_TOGGLES) --check

lock-check: require-uv
	uv lock --check

lint-python: require-uv collection-link lint-pylint
	$(RUN) ruff check .
	$(RUN) ruff format --check .

lint-pylint: require-uv collection-link
	$(RUN) pylint --ignore-paths='$(PYLINT_BASE_IGNORES)|$(PYLINT_MODULE_IGNORES)' tools tests plugins
	$(RUN) pylint --disable=wrong-import-position $(PYLINT_MODULE_DIRECTORIES)

lint-yaml: require-uv
	$(RUN) yamllint --strict .

lint-actions: require-uv
	$(RUN) actionlint

lint-repo: require-uv
	@if git ls-files | grep -E '(^|/)__pycache__/|\.py[cod]$$'; then printf 'error: compiled Python files are tracked\n' >&2; exit 1; fi
	$(TRACKED) -- '*.yml' '*.yaml' '*.py' | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py

lint-skills: require-uv
	$(RUN) python tools/skills/validate_skills.py

lint-ansible: require-uv collection-link
	$(RUN) ansible-lint
	$(RUN) python tools/roles/check_role_specs.py roles
	$(RUN) antsibull-changelog lint

lint-iac: require-uv
	@command -v tofu >/dev/null || { printf 'error: tofu is required; run tools/iac/install-tofu.sh\n' >&2; exit 1; }
	tofu fmt -check -recursive infra/
	$(MAKE) --no-print-directory tofu-validate
	mkdir -p build
	sed $(BOOTSTRAP_RENDER_SED) $(BOOTSTRAP_TEMPLATE) > build/bootstrap.rendered.sh
	$(RUN) shellcheck build/bootstrap.rendered.sh tools/iac/install-tofu.sh tools/browser/fetch-test-deps.sh

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

test-content-golden: require-uv collection-link
	$(RUN) python tools/content/fetch_content.py --output-dir build/content
	FREESECDEV_REQUIRE_CONTENT=1 $(RUN) pytest tests/unit/tools/test_content_golden.py --no-cov

test-oscap-integration: require-uv collection-link
	$(RUN) python tools/content/fetch_content.py --output-dir build/content --datastream ubuntu2404
	$(RUN) pytest tests/system --no-cov -v -s -p no:cacheprovider

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
	$(call audit_exceptions_expect_failure,free,-i $(AUDIT_EXCEPTIONS_INVENTORY) tests/playbooks/audit-exceptions-free.yml,does not support the free strategy,AUDIT-EXCEPTIONS-NOT-REACHED)

REMEDIATE_CHECK = $(RUN) ansible-playbook -i localhost, --check

test-remediate-check: require-uv collection-link
	$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-check-mode.yml
	$(REMEDIATE_CHECK) --skip-tags file_permissions tests/playbooks/remediate-check-mode.yml
	$(REMEDIATE_CHECK) --skip-tags always tests/playbooks/remediate-skip-always.yml

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

ci: lint lint-iac typecheck test-coverage test-browser test-audit-exceptions test-remediate-check test-verify security docs test-sanity test-ansible-units package-check
