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
MOLECULE_SELFTEST_CONFIG := $(MOLECULE_SELFTEST_DIR)/instance_config.yml
MOLECULE_SELFTEST_PLAYBOOK = MOLECULE_SCENARIO_NAME=docker-selftest $(RUN) ansible-playbook -e molecule_no_log=false \
	-e molecule_selftest_dir='$(MOLECULE_SELFTEST_DIR)' -e @extensions/molecule/selftest/vars/platforms.yml
MOLECULE_SELFTEST = MOLECULE_INSTANCE_CONFIG='$(MOLECULE_SELFTEST_CONFIG)' $(MOLECULE_SELFTEST_PLAYBOOK) \
	-e molecule_instance_config='$(MOLECULE_SELFTEST_CONFIG)'
MOLECULE_SELFTEST_REFUSED := docker_host extra_args privileged local localhost loopback unknown mounted unmasked seccomp
RUN_LIBVIRT := uv run --frozen --group libvirt
MOLECULE_LIBVIRT_SCENARIOS := libvirt-ubuntu libvirt-rhel-compatible
MOLECULE_LIBVIRT_PLATFORMS ?= ubuntu rhel_compatible
MOLECULE_LIBVIRT_SELFTEST ?= true
MOLECULE_LIBVIRT_PINS := extensions/molecule/shared/images/cloud-images.pins
MOLECULE_LIBVIRT_CACHE := $(CURDIR)/build/molecule-libvirt/cache
MOLECULE_LIBVIRT_SELFTEST_DIR := $(CURDIR)/build/molecule-libvirt-selftest
MOLECULE_LIBVIRT_SELFTEST_CONFIG := $(MOLECULE_LIBVIRT_SELFTEST_DIR)/instance_config.yml
MOLECULE_LIBVIRT_SELFTEST_PLAYBOOK = MOLECULE_SCENARIO_NAME=libvirt-selftest \
	MOLECULE_EPHEMERAL_DIRECTORY='$(MOLECULE_LIBVIRT_SELFTEST_DIR)/ephemeral' $(RUN_LIBVIRT) ansible-playbook \
	-e molecule_no_log=false -e molecule_selftest_dir='$(MOLECULE_LIBVIRT_SELFTEST_DIR)' \
	-e @extensions/molecule/selftest/vars/libvirt_platforms.yml
MOLECULE_LIBVIRT_SELFTEST_RUN = MOLECULE_INSTANCE_CONFIG='$(MOLECULE_LIBVIRT_SELFTEST_CONFIG)' \
	$(MOLECULE_LIBVIRT_SELFTEST_PLAYBOOK) -e molecule_instance_config='$(MOLECULE_LIBVIRT_SELFTEST_CONFIG)'
MOLECULE_LIBVIRT_SELFTEST_REFUSED := local localhost loopback unknown proxy jump port user key password hostkey become \
	shared bridged channel
MOLECULE_LIBVIRT_SELFTEST_ENVIRONMENTS := ANSIBLE_HOST_KEY_CHECKING=False
COLLECTION_SOURCES := galaxy.yml README.md LICENSE NOTICE meta plugins roles playbooks changelogs docs \
	tests/unit/plugins tests/fixtures tests/sanity tests/integration extensions content/stig-mapping.json
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
EVIDENCE_GATE_BUNDLES := --evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-all/web01/gate-web01' \
	--evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-all/db01/gate-db01' \
	--exceptions-file '$(EVIDENCE_DIR)/exceptions-gate/exceptions-valid.yml'
EVIDENCE_GATE_COLLECTION = --evidence-collection "$$(cat '$(EVIDENCE_DIR)/collection-gate-$(1).path')"
EVIDENCE_LIMITED_BUNDLES := --evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-every_host_fails/web01/gate-web01' \
	--exceptions-file '$(EVIDENCE_DIR)/exceptions-gate-limited/exceptions-valid.yml'
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
	and ([.sections.compliance.groups[].host.hostname] | sort) == ["db01", "web01"] \
	and .sections.compliance.host_coverage.status == "unknown" and .schema_version == "2.3" \
	and .overview.off_platform == 0 and .sections.compliance.off_platform == []
EVIDENCE_MISSING_CHECK := .sections.compliance.status == "partial" and .sections.compliance.summary == null \
	and .sections.compliance.groups == [] and .sections.compliance.aggregates == [] \
	and .sections.exceptions.status == "partial" \
	and .sections.compliance.host_coverage.status == "incomplete" \
	and .sections.compliance.host_coverage.summary.missing == 2 \
	and ([.sections.compliance.host_coverage.hosts[] | select(.in_report | not) | [.host, .status]]) \
		== [["app01", "no_evidence_written"], ["lost01", "unreachable"]] \
	and ([.sections.compliance.gaps[].reason] | sort) == [ \
		"target host app01 has no evidence bundle: its audit wrote no evidence (check mode or no scan)", \
		"target host lost01 has no evidence bundle: it was unreachable (it did not complete fact gathering)"]
EVIDENCE_LIMITED_CHECK := .sections.compliance.status == "partial" and .sections.compliance.summary == null \
	and .sections.compliance.host_coverage.status == "incomplete" \
	and ([.sections.compliance.host_coverage.hosts[] | [.host, .status, .in_report]]) == [ \
		["app01", "limited_out", false], ["db01", "limited_out", false], \
		["lost01", "unreachable", false], ["web01", "collected", true]]
EVIDENCE_UNLISTED_CHECK := .sections.compliance.status == "error" \
	and ([.sections.compliance.gaps[].reason] | any(test("does not list run gate-web01 of web01"))) \
	and .sections.compliance.host_coverage.status == "incomplete"
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

EVIDENCE_GATE_RUN = $(EVIDENCE_PLAYBOOK) -i tests/playbooks/inventory/evidence-gate.yml -e evidence_gate_case=$(1) \
	-e audit_exceptions_dir='$(CURDIR)/$(EVIDENCE_DIR)/exceptions-gate-$(1)' $(2) tests/playbooks/evidence-gate.yml
EVIDENCE_ZERO_SHA256 := 0000000000000000000000000000000000000000000000000000000000000000
EVIDENCE_PLANTED_FACT = {"directory": "$(CURDIR)/$(EVIDENCE_DIR)/bundles-gate-$(1)/web01/gate-web01", \
	"run_id": "gate-web01", "manifest_sha256": "$(EVIDENCE_ZERO_SHA256)", "files": [], "excluded": [], \
	"exceptions_applied": true}
EVIDENCE_PLANTED_EXTRA := {"linux_compliance_evidence_bundle": $(call EVIDENCE_PLANTED_FACT,planted_extra)}
EVIDENCE_FORGED_MARKER := {"__linux_compliance_evidence_run_bundle": $(call EVIDENCE_PLANTED_FACT,marker_extra)}
EVIDENCE_COMPLETE_CHECK := .sections.compliance.status == "available" and .sections.compliance.summary != null \
	and .sections.compliance.host_coverage.status == "complete" \
	and .sections.compliance.host_coverage.summary.in_report == 2 and .sections.compliance.host_coverage.summary.missing == 0
EVIDENCE_PLANTED_CHECK := .sections.compliance.status == "partial" and .sections.compliance.summary == null \
	and .sections.compliance.host_coverage.status == "incomplete" \
	and ([.sections.compliance.host_coverage.hosts[] | [.host, .status, .in_report]]) == [ \
		["app01", "no_evidence_written", false], ["db01", "collected", true], \
		["lost01", "unreachable", false], ["web01", "collection_failed", false]]

define evidence_planted_route
mkdir -m 0700 '$(EVIDENCE_DIR)/bundles-gate-$(1)'
mkdir -m 0755 '$(EVIDENCE_DIR)/bundles-gate-$(1)/web01'
status=0; $(call EVIDENCE_GATE_RUN,$(1),$(2)) > '$(EVIDENCE_DIR)/gate-$(1).log' 2>&1 || status=$$?; \
	cat '$(EVIDENCE_DIR)/gate-$(1).log'; \
	test "$$status" -ne 0 || { printf 'error: planted route %s gave exit status %s\n' '$(1)' "$$status" >&2; exit 1; }
grep -q 'must be a directory with mode 0700 that is not a symbolic link' '$(EVIDENCE_DIR)/gate-$(1).log'
grep -q 'Evidence | Refuse internal variables supplied from outside the role' '$(EVIDENCE_DIR)/gate-$(1).log'
grep -q 'Collection failed: web01. A report over the collected bundles' '$(EVIDENCE_DIR)/gate-$(1).log'
grep -q 'wrote evidence on the host, but no evidence bundle was collected in this run' '$(EVIDENCE_DIR)/gate-$(1).log'
grep -qE '^web01 +: .*failed=1' '$(EVIDENCE_DIR)/gate-$(1).log'
grep -qE '^db01 +: .*failed=1' '$(EVIDENCE_DIR)/gate-$(1).log'
grep -q 'EVIDENCE-GATE-PASSED app01' '$(EVIDENCE_DIR)/gate-$(1).log'
if grep -qE 'EVIDENCE-GATE-PASSED (web01|db01)' '$(EVIDENCE_DIR)/gate-$(1).log'; then \
	printf 'error: planted route %s let a host pass\n' '$(1)' >&2; exit 1; fi
test ! -e '$(EVIDENCE_DIR)/bundles-gate-$(1)/web01/gate-web01'
$(call evidence_expect_status,report-$(1),$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/$(1).json' \
	--evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-$(1)/db01/gate-db01' $(call EVIDENCE_GATE_COLLECTION,$(1)) --require-host-coverage,1,the host coverage is incomplete)
jq -e '$(EVIDENCE_PLANTED_CHECK)' '$(EVIDENCE_DIR)/$(1).json' > /dev/null
endef

define evidence_marker_route
status=0; $(call EVIDENCE_GATE_RUN,$(1),$(2)) > '$(EVIDENCE_DIR)/gate-$(1).log' 2>&1 || status=$$?; \
	cat '$(EVIDENCE_DIR)/gate-$(1).log'; \
	test "$$status" -ne 0 || { printf 'error: marker route %s gave exit status %s\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -q 'Refusing to run: internal variables of the evidence role' '$(EVIDENCE_DIR)/gate-$(1).log' || \
	{ printf 'error: marker route %s was not refused at the start of the audit play\n' '$(1)' >&2; exit 1; }; \
	if grep -q 'Evidence | Collect the bundle on the controller' '$(EVIDENCE_DIR)/gate-$(1).log'; then \
		printf 'error: marker route %s went on to collect\n' '$(1)' >&2; exit 1; fi; \
	test ! -e '$(EVIDENCE_DIR)/bundles-gate-$(1)' && test ! -e '$(EVIDENCE_DIR)/collection-gate-$(1).path' || \
	{ printf 'error: marker route %s wrote a bundle or a summary\n' '$(1)' >&2; exit 1; }
endef

ANSIBLE_TEST := PATH="$$(uv python dir --bin):$$PATH" uv run --frozen --project '$(CURDIR)' env HOME='$(ANSIBLE_TEST_HOME)' ansible-test

space := $(subst ,, )
DOCKER ?= docker
SCC_PINS := extensions/ci/scc/scc.pins
include $(SCC_PINS)
SCC_IMAGE ?= localhost/freesecdev-scc:local
SCC_IMAGE_UBUNTU2604 ?= $(SCC_IMAGE)-ubuntu2604
SCC_CONTAINERFILE := extensions/ci/scc/Containerfile
SCC_CONTAINERFILE_UBUNTU2604 := extensions/ci/scc/Containerfile.ubuntu2604
SCC_DOWNLOAD_DIR := build/scc/download
SCC_CONTEXT_DIR := build/scc/context
OSCAP_IMAGE ?= localhost/freesecdev-oscap:local
OSCAP_CONTAINERFILE := extensions/ci/oscap/Containerfile
OPENSCAP_SCANNER_VERSION := 1.3.9+dfsg-1.1ubuntu2
GENERATE_STIG_MAPPING := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.content.generate_stig_mapping
SCC_FETCH_ENV := SCC_VERSION='$(SCC_VERSION)' SCC_BUNDLE='$(SCC_BUNDLE)' SCC_BUNDLE_URL='$(SCC_BUNDLE_URL)' \
	SCC_BUNDLE_SIZE='$(SCC_BUNDLE_SIZE)' SCC_BUNDLE_SHA256='$(SCC_BUNDLE_SHA256)' SCC_CHECKSUMS_URL='$(SCC_CHECKSUMS_URL)' \
	SCC_DEB_MEMBER='$(SCC_DEB_MEMBER)' SCC_DEB_SHA256='$(SCC_DEB_SHA256)' SCC_CSCC_SHA256='$(SCC_CSCC_SHA256)'
HADOLINT := build/tools/hadolint
SHELL_SCRIPTS := build/bootstrap.rendered.sh tools/iac/install-tofu.sh tools/browser/fetch-test-deps.sh \
	tools/lint/fetch-hadolint.sh tools/scc/fetch-scc.sh tools/scc/smoke-test.sh tools/scc/check-expiry.sh \
	tools/scc/needs-smoke.sh

INDEX_MODES := build/lint-repo-index-modes
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
  lint                  Run every implemented linter (lock, repo, skills, python, yaml, actions, ansible, toggles, Containerfile)
  lint-python           Ruff lint, Ruff format check and Pylint
  lint-pylint           Pylint in two passes: wrong-import-position on, and off for plugins/modules only
  lint-yaml             yamllint in strict mode
  lint-actions          actionlint for GitHub workflows
  lint-containerfile    hadolint (pinned binary, fetched into build/tools) on the CI-only SCC and OpenSCAP Containerfiles
  lint-repo             Repository source rules (document start, comments, banned modules)
  name-sets             Probe Python 3.9 to 3.15 and regenerate the guard name sets
  lint-skills           Validate agent skills under .agents/skills
  lint-ansible          ansible-lint (production profile), role argument spec check and antsibull-changelog lint
  lint-toggles          Fail when the generated toggles, their argument specs or their reference drift from the catalogue
  toggles               Regenerate the toggle defaults, argument specs and docs/remediation-variables.md
  lint-role-guards      Fail when the generated family dispatch or internal-variable guards drift from the roles
  role-guards           Regenerate the family dispatch and the internal-variable guards of the roles
  lint-lifecycle        Fail when a native topic has no valid Molecule toggle lifecycle declaration
  content               Fetch and verify the pinned SCAP content into build/content
  catalogue             Regenerate the rule catalogue and docs/control-families.md from build/content, then the toggles and role guards
  stig-mapping          Regenerate content/stig-mapping.json, the STIG ID to ComplianceAsCode rule mapping, from build/content
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
  test-content-golden   Fetch the pinned content, compare the catalog with the recorded rule lists and check the catalogue and STIG mapping for drift
  test-oscap-integration Fetch the pinned Ubuntu 24.04 content and scan the host with a real oscap, also through the audit role
  test-browser          Dashboard browser and accessibility tests in the pinned headless Chromium
  browser-test-deps     Fetch and verify the pinned headless Chromium and axe-core into build/
  test-name-sets        Check the guard name sets on one interpreter (NAME_SET_PYTHON=3.9.25)
  test-audit-exceptions Run the audit role's exceptions path on localhost with synthetic scan runs, without oscap
  test-evidence         Collect evidence bundles of synthetic audit results on localhost and report on them
  test-remediate-check  Run the remediate role and the audit toggle resolution against localhost in check mode, without become
  test-remediate-disruptive  Check in check mode that a disruptive rule is skipped without the allow-list (run by test-remediate-check)
  test-role-guards      Check in check mode that forged internal variables and role outputs are refused before any change
  test-verify           Run the verify role on localhost with synthetic baseline and later audits, without oscap
  test-integration      [pending FREES-60] Integration tests
  test-molecule-docker  Molecule Docker scenarios and their self-test (requires a running Docker daemon)
  test-molecule-docker-selftest Guard bypass attempts and the destroy fallback against real containers
  test-molecule-libvirt Molecule libvirt scenarios on KVM virtual machines and their self-test (requires KVM and libvirt)
  test-molecule-libvirt-selftest Guard bypass attempts, decoys, strangers and the destroy fallback against real libvirt objects
  molecule-libvirt-images Fetch the pinned cloud images and packages and check the vendors' signed checksum files
  test-molecule-golden  [pending FREES-63] Molecule golden image scenarios
  test-idempotency      [pending FREES-60] Idempotency checks
  test-compliance       [pending FREES-62] Compliance scan scenarios

Images and AWS
  packer-validate       [pending FREES-64] Validate Packer templates
  packer-build          [pending FREES-64] Build images with Packer
  aws-bootstrap-render  Render the gitignored bootstrap script from its template
  aws-bootstrap         Render and run the one-time interactive AWS account bootstrap
  image-build           [pending FREES-36] The runner image is built by the runner repository's workflow
  scc-expiry-check      Fail from seven days before SCC_EXPIRES, so an expiring SCC is never built or run
  scc-fetch             Download the pinned SCC bundle from DISA, verify it and stage its Debian package in build/scc
  scc-image             Build the CI-only SCC image locally as SCC_IMAGE (a localhost/ tag); it is never pushed
  scc-smoke             Build the SCC image and check that cscc starts and reports the pinned version
  scc-image-ubuntu2604  Build SCC_IMAGE_UBUNTU2604, the same SCC on an Ubuntu 26.04 base, locally; never pushed
  oscap-image           Build OSCAP_IMAGE, the CI-only OpenSCAP image on the SCC image's base, locally; never pushed
  scc-integration       Run real SCC scans through compliance_scan, the egress test, the 26.04 case and the OpenSCAP STIG checklist export
  scc-image-clean       Remove the local SCC_IMAGE, SCC_IMAGE_UBUNTU2604 and OSCAP_IMAGE

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

.PHONY: help bootstrap install format lint lint-ansible lint-toggles toggles lint-role-guards role-guards lint-lifecycle content catalogue stig-mapping lint-python lint-yaml lint-actions \
	lint-containerfile oscap-image scc-expiry-check scc-fetch scc-image scc-image-ubuntu2604 scc-smoke scc-integration scc-image-clean lint-iac lock-check tofu-validate aws-bootstrap-render lint-packer lint-repo lint-skills security typecheck test test-unit test-sanity test-audit-exceptions test-evidence test-remediate-check test-remediate-disruptive test-role-guards test-verify \
	test-ansible-units package-check collection-tree collection-link sanity-pythons name-sets test-name-sets \
	test-integration test-coverage test-content-golden test-oscap-integration test-browser browser-test-deps molecule-dependencies molecule-content test-molecule-docker test-molecule-docker-selftest test-molecule-libvirt \
	test-molecule-libvirt-selftest molecule-libvirt-images molecule-libvirt-preflight \
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

lint: lock-check lint-repo lint-skills lint-python lint-yaml lint-actions lint-containerfile lint-ansible lint-toggles lint-role-guards lint-lifecycle

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

stig-mapping: require-uv collection-link
	$(GENERATE_STIG_MAPPING)

lint-toggles: require-uv collection-link
	$(GENERATE_TOGGLES) --check

GENERATE_ROLE_GUARDS := PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.generate_role_guards

role-guards: require-uv collection-link
	$(GENERATE_ROLE_GUARDS)

lint-role-guards: require-uv collection-link
	$(GENERATE_ROLE_GUARDS) --check

lint-lifecycle: require-uv collection-link
	PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.check_lifecycle_topics

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

lint-containerfile:
	tools/lint/fetch-hadolint.sh '$(HADOLINT)'
	'$(HADOLINT)' --failure-threshold info $(SCC_CONTAINERFILE) $(SCC_CONTAINERFILE_UBUNTU2604) $(OSCAP_CONTAINERFILE)

lint-repo: require-uv
	@if git ls-files | grep -E '(^|/)__pycache__/|\.py[cod]$$'; then printf 'error: compiled Python files are tracked\n' >&2; exit 1; fi
	mkdir -p build
	git ls-files -s -z > $(INDEX_MODES)
	$(TRACKED) | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py --index-modes $(INDEX_MODES)

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
	$(GENERATE_STIG_MAPPING) --check

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
	$(AUDIT_EXCEPTIONS_PLAYBOOK) -i $(AUDIT_EXCEPTIONS_INVENTORY) -e '{"group_names": ["web"]}' \
		tests/playbooks/audit-exceptions-group-names.yml
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
	status=0; $(EVIDENCE_PLAYBOOK) -i tests/playbooks/inventory/evidence-gate.yml -e evidence_gate_case=all \
		-e audit_exceptions_dir='$(CURDIR)/$(EVIDENCE_DIR)/exceptions-gate' tests/playbooks/evidence-gate.yml \
		> '$(EVIDENCE_DIR)/gate.log' 2>&1 || status=$$?; cat '$(EVIDENCE_DIR)/gate.log'; \
		test "$$status" -ne 0 || { printf 'error: the gated play did not fail\n' >&2; exit 1; }
	grep -q 'WARNING: no evidence bundle for 2 of 4 target host(s): app01, lost01. Unreachable (did not complete fact gathering): lost01.' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'WARNING: the result gates of web01 are deferred' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'The audit reported 2 failed and 1 errored rule(s)' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'The scan did not complete (run_status failed)' '$(EVIDENCE_DIR)/gate.log'
	grep -q 'EVIDENCE-GATE-PASSED app01' '$(EVIDENCE_DIR)/gate.log'
	if grep -qE 'EVIDENCE-GATE-PASSED (web01|db01)' '$(EVIDENCE_DIR)/gate.log'; then printf 'error: a gated host passed\n' >&2; exit 1; fi
	grep -qE '^web01 +: .*failed=1' '$(EVIDENCE_DIR)/gate.log'
	grep -qE '^db01 +: .*failed=1' '$(EVIDENCE_DIR)/gate.log'
	grep -qE '^lost01 +: .*unreachable=1' '$(EVIDENCE_DIR)/gate.log'
	$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/gate.json' $(EVIDENCE_GATE_BUNDLES)
	$(call evidence_expect_status,unknown-required,$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/unknown-required.json' $(EVIDENCE_GATE_BUNDLES) --require-host-coverage,1,the host coverage is unknown)
	jq -e '.sections.compliance.status == "available" and .sections.compliance.host_coverage.status == "unknown"' '$(EVIDENCE_DIR)/unknown-required.json' > /dev/null
	$(call evidence_expect_status,missing,$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/missing.json' --html '$(EVIDENCE_DIR)/missing.html' $(EVIDENCE_GATE_BUNDLES) $(call EVIDENCE_GATE_COLLECTION,all) --require-host-coverage,1,the host coverage is incomplete)
	jq -e '$(EVIDENCE_MISSING_CHECK)' '$(EVIDENCE_DIR)/missing.json' > /dev/null
	grep -q 'lost01' '$(EVIDENCE_DIR)/missing.html'
	status=0; $(EVIDENCE_PLAYBOOK) -i tests/playbooks/inventory/evidence-gate.yml -e evidence_gate_case=every_host_fails \
		--limit web01,lost01,localhost -e audit_exceptions_dir='$(CURDIR)/$(EVIDENCE_DIR)/exceptions-gate-limited' \
		tests/playbooks/evidence-gate.yml > '$(EVIDENCE_DIR)/gate-limited.log' 2>&1 || status=$$?; \
		cat '$(EVIDENCE_DIR)/gate-limited.log'; \
		test "$$status" -ne 0 || { printf 'error: the play where every host fails did not fail\n' >&2; exit 1; }
	grep -q 'WARNING: no evidence bundle for 3 of 4 target host(s): app01, db01, lost01. Unreachable (did not complete fact gathering): lost01. Limited out: app01, db01.' '$(EVIDENCE_DIR)/gate-limited.log'
	grep -q 'The audit reported 2 failed and 1 errored rule(s)' '$(EVIDENCE_DIR)/gate-limited.log'
	grep -qE '^web01 +: .*failed=1' '$(EVIDENCE_DIR)/gate-limited.log'
	grep -qE '^lost01 +: .*unreachable=1' '$(EVIDENCE_DIR)/gate-limited.log'
	if grep -q 'EVIDENCE-GATE-PASSED' '$(EVIDENCE_DIR)/gate-limited.log'; then printf 'error: a gated host passed\n' >&2; exit 1; fi
	$(call evidence_expect_status,limited,$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/limited.json' $(EVIDENCE_LIMITED_BUNDLES) $(call EVIDENCE_GATE_COLLECTION,every_host_fails) --require-host-coverage,1,the host coverage is incomplete)
	jq -e '$(EVIDENCE_LIMITED_CHECK)' '$(EVIDENCE_DIR)/limited.json' > /dev/null
	$(call evidence_expect_status,unlisted,$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/unlisted.json' --evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-all/web01/gate-web01' --exceptions-file '$(EVIDENCE_DIR)/exceptions-gate/exceptions-valid.yml' $(call EVIDENCE_GATE_COLLECTION,every_host_fails) --require-host-coverage,1,report written)
	jq -e '$(EVIDENCE_UNLISTED_CHECK)' '$(EVIDENCE_DIR)/unlisted.json' > /dev/null
	status=0; $(call EVIDENCE_GATE_RUN,complete,-e evidence_gate_hosts=web01:db01) > '$(EVIDENCE_DIR)/gate-complete.log' 2>&1 || status=$$?; \
		cat '$(EVIDENCE_DIR)/gate-complete.log'; \
		test "$$status" -ne 0 || { printf 'error: the gated play of the complete run did not fail\n' >&2; exit 1; }
	grep -q 'Collected an evidence bundle for every one of the 2 target host(s).' '$(EVIDENCE_DIR)/gate-complete.log'
	$(EVIDENCE_REPORT) --scope multi_host --output '$(EVIDENCE_DIR)/complete.json' --html '$(EVIDENCE_DIR)/complete.html' \
		--evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-complete/web01/gate-web01' \
		--evidence-bundle '$(EVIDENCE_DIR)/bundles-gate-complete/db01/gate-db01' \
		--exceptions-file '$(EVIDENCE_DIR)/exceptions-gate-complete/exceptions-valid.yml' \
		$(call EVIDENCE_GATE_COLLECTION,complete) --require-host-coverage
	jq -e '$(EVIDENCE_COMPLETE_CHECK)' '$(EVIDENCE_DIR)/complete.json' > /dev/null
	$(call evidence_planted_route,planted_inventory,-i tests/playbooks/inventory/evidence-planted.yml)
	$(call evidence_planted_route,planted_extra,-e '$(EVIDENCE_PLANTED_EXTRA)')
	$(call evidence_marker_route,marker_extra,-e '$(EVIDENCE_FORGED_MARKER)')
	$(call evidence_marker_route,marker_inventory,-i tests/playbooks/inventory/evidence-marker.yml)
	$(call evidence_gate_route,baseline,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=baseline)
	$(call evidence_gate_route,extra,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=baseline -e '$(EVIDENCE_FORGED_DEFERRAL)')
	$(call evidence_gate_route,group_vars,-i tests/playbooks/inventory/gate-routes-group -e gate_route=baseline)
	$(call evidence_gate_route,host_vars,-i tests/playbooks/inventory/gate-routes-host -e gate_route=baseline)
	$(call evidence_gate_route,include,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=include)
	$(call evidence_gate_route,import,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e gate_route=import)
	jq -e '$(EVIDENCE_GATE_CHECK)' '$(EVIDENCE_DIR)/gate.json' > /dev/null

REMEDIATE_CHECK = $(RUN) ansible-playbook -i localhost, --check

REMEDIATE_DISRUPTIVE_DIR := build/test-remediate-disruptive
REMEDIATE_DISRUPTIVE_TREE := $(REMEDIATE_DISRUPTIVE_DIR)/collections/$(COLLECTION_PATH)
REMEDIATE_DISRUPTIVE_RULE := xccdf_org.ssgproject.content_rule_sshd_disable_root_login
REMEDIATE_DISRUPTIVE_FAMILY := ssh

test-remediate-disruptive: ANSIBLE_COLLECTIONS_PATH = $(CURDIR)/$(REMEDIATE_DISRUPTIVE_DIR)/collections
test-remediate-disruptive: require-uv collection-link
	rm -rf '$(REMEDIATE_DISRUPTIVE_DIR)'
	mkdir -p '$(REMEDIATE_DISRUPTIVE_TREE)'
	cp -R roles '$(REMEDIATE_DISRUPTIVE_TREE)/roles'
	ln -s '$(CURDIR)/plugins' '$(REMEDIATE_DISRUPTIVE_TREE)/plugins'
	PYTHONPATH='$(CURDIR)/build/collections' $(RUN) python -m tools.roles.promote_native_rule \
		--catalogue '$(REMEDIATE_DISRUPTIVE_TREE)/roles/remediate/vars/rules.yml' --rule '$(REMEDIATE_DISRUPTIVE_RULE)'
	$(REMEDIATE_CHECK) -e disruptive_rule='$(REMEDIATE_DISRUPTIVE_RULE)' -e disruptive_family='$(REMEDIATE_DISRUPTIVE_FAMILY)' \
		tests/playbooks/remediate-disruptive.yml

test-remediate-check: require-uv collection-link test-remediate-disruptive
	$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-check-mode.yml
	$(REMEDIATE_CHECK) --skip-tags file_permissions tests/playbooks/remediate-check-mode.yml
	$(REMEDIATE_CHECK) --skip-tags always tests/playbooks/remediate-skip-always.yml

ROLE_GUARDS_DIR := build/test-role-guards
ROLE_GUARDS_FORGED_PLAN := {"__linux_compliance_remediate_plan": {"enabled": true, "errors": [], \
	"families": [{"name": "../../../../tmp/forged", "disruptive": false, "apply": [], "cleanup": []}]}}
ROLE_GUARDS_FORGED_FAMILY := {"__linux_compliance_remediate_family": {"name": "../../../../tmp/forged"}}
ROLE_GUARDS_SENTINEL_PLAN := {"__linux_compliance_remediate_plan": "__linux_compliance_unset__"}
ROLE_GUARDS_SENTINEL_FAMILY := {"__linux_compliance_remediate_family": "__linux_compliance_unset__"}

ROLE_GUARDS_REFUSALS := is set from outside the role|Validation of arguments failed
ROLE_GUARDS_PARAMETERS := Refuse internal variables supplied from outside the role as parameters
ROLE_GUARDS_HOSTS := forged_plan,forged_family,forged_vars,forged_template,

define role_guards_expect_refusal
status=0; ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -i $(ROLE_GUARDS_HOSTS) --limit $(1) --check \
		tests/playbooks/internal-variables-role-param.yml > '$(ROLE_GUARDS_DIR)/$(1).log' 2>&1 || status=$$?; \
	cat '$(ROLE_GUARDS_DIR)/$(1).log'; \
	test "$$status" -eq 2 || { printf 'error: %s did not fail the play (status %s)\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -qE '$(2)' '$(ROLE_GUARDS_DIR)/$(1).log' || { printf 'error: %s was not refused\n' '$(1)' >&2; exit 1; }; \
	if grep -qE 'Remediate \| Read the state ledger|tmp/forged|FORGED-PLAN-USED|PROBE-COMPLETED' \
		'$(ROLE_GUARDS_DIR)/$(1).log'; then printf 'error: the role went on after %s\n' '$(1)' >&2; exit 1; fi
endef

RUN_START_PLAYBOOK := ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook -i localhost, --check \
	-e linux_compliance_target_hosts=freesecdev_no_target_host
RUN_START_REFUSAL := Refusing to run: internal variables or role outputs of the freesecdev.linux_compliance roles
RUN_START_AUDITED := {"linux_compliance_audited": {"run_id": "forged", "run_status": "completed", "evidence_written": true}}

define run_start_expect_refusal
status=0; $(RUN_START_PLAYBOOK) $(3) playbooks/$(2).yml > '$(ROLE_GUARDS_DIR)/run-start-$(1).log' 2>&1 || status=$$?; \
	cat '$(ROLE_GUARDS_DIR)/run-start-$(1).log'; \
	test "$$status" -eq 2 || { printf 'error: run start %s gave exit status %s, not 2\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -qF '$(RUN_START_REFUSAL) ($(4))' '$(ROLE_GUARDS_DIR)/run-start-$(1).log' || \
		{ printf 'error: run start %s was not refused by the first play\n' '$(1)' >&2; exit 1; }; \
	test "$$(grep -c '^PLAY \[' '$(ROLE_GUARDS_DIR)/run-start-$(1).log')" -eq 1 || \
		{ printf 'error: run start %s went on after the first play\n' '$(1)' >&2; exit 1; }
endef

RUN_START_LIMIT := -i tests/playbooks/inventory/run-start-limit.yml --limit

define run_start_limit_plain
$(RUN_START_PLAYBOOK) $(RUN_START_LIMIT) $(2) playbooks/$(1).yml > '$(ROLE_GUARDS_DIR)/run-start-limit-$(1)-$(2).log' 2>&1 || \
	{ cat '$(ROLE_GUARDS_DIR)/run-start-limit-$(1)-$(2).log'; printf 'error: %s refused a plain run limited to %s\n' '$(1)' '$(2)' >&2; exit 1; }
grep -qE '^ok: \[$(2)\]' '$(ROLE_GUARDS_DIR)/run-start-limit-$(1)-$(2).log' || \
	{ printf 'error: the run-start check of %s did not run with --limit %s\n' '$(1)' '$(2)' >&2; exit 1; }
if grep -qE 'UNREACHABLE|unreachable=[1-9]' '$(ROLE_GUARDS_DIR)/run-start-limit-$(1)-$(2).log'; then \
	printf 'error: the run-start check of %s connected to a host with --limit %s\n' '$(1)' '$(2)' >&2; exit 1; fi
endef

RUN_START_MARKER_PLAYBOOK := ANSIBLE_NOCOLOR=1 $(RUN) ansible-playbook --check \
	-e linux_compliance_target_hosts=freesecdev_no_target_host -e @tests/playbooks/vars/run-start-templated-plan.yml

define run_start_marker_refusal
status=0; $(RUN_START_MARKER_PLAYBOOK) -i tests/playbooks/inventory/run-start-marker-$(2) $(4) playbooks/$(3).yml \
		> '$(ROLE_GUARDS_DIR)/run-start-marker-$(1).log' 2>&1 || status=$$?; \
	cat '$(ROLE_GUARDS_DIR)/run-start-marker-$(1).log'; \
	test "$$status" -eq 2 || { printf 'error: marker case %s gave exit status %s, not 2\n' '$(1)' "$$status" >&2; exit 1; }; \
	grep -qF '$(RUN_START_REFUSAL) (__linux_compliance_remediate_plan, linux_compliance_run_start_checked)' \
		'$(ROLE_GUARDS_DIR)/run-start-marker-$(1).log' || \
		{ printf 'error: marker case %s was not refused by the first play\n' '$(1)' >&2; exit 1; }; \
	test "$$(grep -c '^PLAY \[' '$(ROLE_GUARDS_DIR)/run-start-marker-$(1).log')" -eq 1 || \
		{ printf 'error: marker case %s went on after the first play\n' '$(1)' >&2; exit 1; }
endef

define run_start_expect_success
$(RUN_START_PLAYBOOK) playbooks/$(1).yml > '$(ROLE_GUARDS_DIR)/run-start-plain-$(1).log' 2>&1 || \
	{ cat '$(ROLE_GUARDS_DIR)/run-start-plain-$(1).log'; printf 'error: %s refused a plain run\n' '$(1)' >&2; exit 1; }
endef

test-role-guards: require-uv collection-link
	rm -rf '$(ROLE_GUARDS_DIR)'
	mkdir -p '$(ROLE_GUARDS_DIR)'
	$(REMEDIATE_CHECK) tests/playbooks/internal-variables-include.yml
	$(REMEDIATE_CHECK) -e '$(ROLE_GUARDS_FORGED_PLAN)' -e internal_forged_variable=__linux_compliance_remediate_plan \
		tests/playbooks/internal-variables-extra.yml
	$(REMEDIATE_CHECK) -e '$(ROLE_GUARDS_FORGED_FAMILY)' -e internal_forged_variable=__linux_compliance_remediate_family \
		tests/playbooks/internal-variables-extra.yml
	$(REMEDIATE_CHECK) -e '$(ROLE_GUARDS_SENTINEL_PLAN)' -e internal_forged_variable=__linux_compliance_remediate_plan \
		tests/playbooks/internal-variables-extra.yml
	$(REMEDIATE_CHECK) -e '$(ROLE_GUARDS_SENTINEL_FAMILY)' -e internal_forged_variable=__linux_compliance_remediate_family \
		tests/playbooks/internal-variables-extra.yml
	$(REMEDIATE_CHECK) tests/playbooks/internal-variables-templated.yml
	$(call role_guards_expect_refusal,forged_plan,$(ROLE_GUARDS_REFUSALS))
	$(call role_guards_expect_refusal,forged_family,$(ROLE_GUARDS_REFUSALS))
	$(call role_guards_expect_refusal,forged_vars,$(ROLE_GUARDS_PARAMETERS))
	$(call role_guards_expect_refusal,forged_template,$(ROLE_GUARDS_REFUSALS))
	$(call run_start_expect_success,audit)
	$(call run_start_expect_success,remediate)
	$(call run_start_expect_success,verify)
	$(call run_start_expect_refusal,templated_plan,remediate,-e @tests/playbooks/vars/run-start-templated-plan.yml,__linux_compliance_remediate_plan)
	$(call run_start_expect_refusal,audited_audit,audit,-e '$(RUN_START_AUDITED)',linux_compliance_audited)
	$(call run_start_expect_refusal,audited_evidence,evidence,-e '$(RUN_START_AUDITED)',linux_compliance_audited)
	$(call run_start_expect_refusal,audited_inventory,evidence,-i tests/playbooks/inventory/run-start-planted.yml,linux_compliance_audited)
	$(call run_start_expect_refusal,comparison,verify,-e '{"__linux_compliance_verify_comparison": {}}',__linux_compliance_verify_comparison)
	$(call run_start_expect_refusal,marker,remediate,-e linux_compliance_run_start_checked=true,linux_compliance_run_start_checked)
	$(call run_start_expect_refusal,inventory_hostname,evidence,-e inventory_hostname=freesecdev_forged,none)
	$(call run_start_expect_refusal,group_names,audit,-e '{"group_names": ["web"]}',none)
	$(call run_start_expect_refusal,group_names_grouped,audit,-i $(AUDIT_EXCEPTIONS_INVENTORY) -e '{"group_names": ["web"]}',none)
	$(REMEDIATE_CHECK) -i $(AUDIT_EXCEPTIONS_INVENTORY) tests/playbooks/internal-variables-hostname.yml
	$(call run_start_expect_refusal,limit_plan,remediate,$(RUN_START_LIMIT) web01 -e @tests/playbooks/vars/run-start-templated-plan.yml,__linux_compliance_remediate_plan)
	$(call run_start_expect_refusal,limit_audited,audit,$(RUN_START_LIMIT) web01 -e '$(RUN_START_AUDITED)',linux_compliance_audited)
	$(call run_start_expect_refusal,limit_unreachable,remediate,$(RUN_START_LIMIT) lost01 -e @tests/playbooks/vars/run-start-templated-plan.yml,__linux_compliance_remediate_plan)
	$(call run_start_expect_refusal,limit_evidence,evidence,$(RUN_START_LIMIT) web01 -e '$(RUN_START_AUDITED)',linux_compliance_audited)
	$(call run_start_expect_refusal,limit_verify,verify,$(RUN_START_LIMIT) web01 -e '{"__linux_compliance_verify_comparison": {}}',__linux_compliance_verify_comparison)
	$(call run_start_limit_plain,remediate,web01)
	$(call run_start_limit_plain,remediate,lost01)
	$(call run_start_limit_plain,audit,localhost)
	$(call run_start_marker_refusal,host-remediate,host,remediate,)
	$(call run_start_marker_refusal,host-remediate-limit,host,remediate,--limit web01)
	$(call run_start_marker_refusal,host-audit,host,audit,)
	$(call run_start_marker_refusal,host-audit-limit,host,audit,--limit web01)
	$(call run_start_marker_refusal,group-remediate,group,remediate,)
	$(call run_start_marker_refusal,group-remediate-limit,group,remediate,--limit web01)
	$(call run_start_marker_refusal,group-audit,group,audit,)
	$(call run_start_marker_refusal,group-audit-limit,group,audit,--limit web01)
	status=0; $(RUN_START_PLAYBOOK) playbooks/audit.yml playbooks/audit.yml > '$(ROLE_GUARDS_DIR)/run-start-twice.log' 2>&1 \
		|| status=$$?; cat '$(ROLE_GUARDS_DIR)/run-start-twice.log'; \
		test "$$status" -eq 2 || { printf 'error: two shipped playbooks in one invocation gave status %s\n' "$$status" >&2; exit 1; }; \
		grep -qF '$(RUN_START_REFUSAL) (__linux_compliance_audit_' '$(ROLE_GUARDS_DIR)/run-start-twice.log' || \
		{ printf 'error: the second shipped playbook was not refused by its run-start check\n' >&2; exit 1; }

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
		if MOLECULE_INSTANCE_CONFIG="$$config" $(MOLECULE_SELFTEST_PLAYBOOK) -e "molecule_instance_config=$$config" \
			-i "$(MOLECULE_SELFTEST_DIR)/$$case.yml" extensions/molecule/shared/guard.yml \
			> "$(MOLECULE_SELFTEST_DIR)/$$case.log" 2>&1; then \
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
	extra='$(MOLECULE_SELFTEST_DIR)/extra-vars'; \
	if [ $$status -eq 0 ] && [ ! -s "$$extra/cases" ]; then \
		printf 'error: bypass.yml listed no extra-variable bypass attempts\n' >&2; status=1; \
	fi; \
	for case in $$(cat "$$extra/cases" 2>/dev/null); do \
		[ $$status -eq 0 ] || break; \
		if MOLECULE_INSTANCE_CONFIG="$$extra/$$case/instance_config.yml" $(MOLECULE_SELFTEST_PLAYBOOK) \
			-e "molecule_instance_config=$$extra/$$case/instance_config.yml" -e "@$$extra/$$case/vars.yml" \
			-i "$$extra/$$case/inventory.yml" extensions/molecule/shared/guard.yml > "$$extra/$$case/guard.log" 2>&1; then \
			printf 'error: the guard accepted the extra variable %s\n' "$$case" >&2; status=1; \
		elif ! grep -q 'Refusing to run: a variable that the guard relies on was supplied from outside' \
			"$$extra/$$case/guard.log"; then \
			cat "$$extra/$$case/guard.log"; \
			printf 'error: the extra variable %s was not refused as supplied from outside the guard\n' "$$case" >&2; \
			status=1; \
		else printf 'guard refused the extra variable %s\n' "$$case"; fi; \
	done; \
	printf '[]\n' > '$(MOLECULE_SELFTEST_DIR)/instance_config.yml'; \
	$(MOLECULE_SELFTEST) extensions/molecule/shared/destroy.yml || status=1; \
	$(MOLECULE_SELFTEST) extensions/molecule/selftest/assert_destroyed.yml || status=1; \
	if [ $$status -eq 0 ]; then $(MOLECULE_SELFTEST) extensions/molecule/shared/create.yml || status=1; fi; \
	rm -f '$(MOLECULE_SELFTEST_DIR)/instance_config.yml'; \
	$(MOLECULE_SELFTEST) extensions/molecule/shared/destroy.yml || status=1; \
	$(MOLECULE_SELFTEST) extensions/molecule/selftest/assert_destroyed.yml || status=1; \
	exit $$status

molecule-libvirt-images:
	tools/molecule/fetch-cloud-images.sh '$(MOLECULE_LIBVIRT_PINS)' '$(MOLECULE_LIBVIRT_CACHE)' $(MOLECULE_LIBVIRT_PLATFORMS)

molecule-libvirt-preflight: require-uv
	@test -c /dev/kvm || { printf 'error: /dev/kvm is missing; the libvirt scenarios need KVM (docs/molecule-libvirt.md)\n' >&2; exit 1; }
	@$(RUN_LIBVIRT) python -I -c 'import libvirt; libvirt.open("qemu:///system").close()' \
		|| { printf 'error: qemu:///system is not reachable; see docs/molecule-libvirt.md\n' >&2; exit 1; }

test-molecule-libvirt: require-uv molecule-dependencies molecule-content molecule-libvirt-images molecule-libvirt-preflight
	@printf '%s\n' $(MOLECULE_LIBVIRT_SCENARIOS) | grep -Eqx 'libvirt-[a-z0-9-]+' || { printf 'error: MOLECULE_LIBVIRT_SCENARIOS must name libvirt scenarios\n' >&2; exit 2; }
	for scenario in $(MOLECULE_LIBVIRT_SCENARIOS); do \
		$(RUN_LIBVIRT) molecule test -s "$$scenario" || exit 1; \
	done
	if [ '$(MOLECULE_LIBVIRT_SELFTEST)' = true ]; then $(MAKE) --no-print-directory test-molecule-libvirt-selftest MOLECULE_LIBVIRT_PLATFORMS=ubuntu; fi

test-molecule-libvirt-selftest: require-uv molecule-dependencies molecule-libvirt-images molecule-libvirt-preflight
	rm -rf '$(MOLECULE_LIBVIRT_SELFTEST_DIR)'
	mkdir -p '$(MOLECULE_LIBVIRT_SELFTEST_DIR)/host-directory' '$(MOLECULE_LIBVIRT_SELFTEST_DIR)/ephemeral'
	status=0; dir='$(MOLECULE_LIBVIRT_SELFTEST_DIR)'; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/shared/create_libvirt.yml || status=1; \
	if [ $$status -eq 0 ]; then $(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/shared/create_libvirt.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then $(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/selftest/libvirt_assert_created.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then $(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/selftest/libvirt_bypass.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then $(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/selftest/libvirt_strangers.yml || status=1; fi; \
	if [ $$status -eq 0 ]; then \
		$(MOLECULE_LIBVIRT_SELFTEST_RUN) -i "$$dir/good.yml" extensions/molecule/shared/guard.yml \
			> "$$dir/good.log" 2>&1 || { cat "$$dir/good.log"; status=1; }; \
	fi; \
	for case in $(MOLECULE_LIBVIRT_SELFTEST_REFUSED); do \
		[ $$status -eq 0 ] || break; \
		config="$$dir/instance_config.yml"; \
		if [ -f "$$dir/instance_config_$$case.yml" ]; then config="$$dir/instance_config_$$case.yml"; fi; \
		if MOLECULE_INSTANCE_CONFIG="$$config" $(MOLECULE_LIBVIRT_SELFTEST_PLAYBOOK) -e "molecule_instance_config=$$config" \
			-i "$$dir/$$case.yml" extensions/molecule/shared/guard.yml > "$$dir/$$case.log" 2>&1; then \
			printf 'error: the guard accepted the bypass attempt %s\n' "$$case" >&2; status=1; \
		elif ! grep -q 'Refusing to run' "$$dir/$$case.log"; then \
			cat "$$dir/$$case.log"; \
			printf 'error: the bypass attempt %s failed for another reason than the guard\n' "$$case" >&2; status=1; \
		elif [ -f "$$dir/instance_config_$$case.yml" ] && ! grep -q 'is not isolated' "$$dir/$$case.log"; then \
			cat "$$dir/$$case.log"; \
			printf 'error: the decoy %s was not refused by the isolation check\n' "$$case" >&2; status=1; \
		else printf 'guard refused the bypass attempt %s\n' "$$case"; fi; \
	done; \
	for setting in $(MOLECULE_LIBVIRT_SELFTEST_ENVIRONMENTS); do \
		[ $$status -eq 0 ] || break; \
		name="$${setting%%=*}"; \
		if env "$$setting" $(MOLECULE_LIBVIRT_SELFTEST_RUN) -i "$$dir/good.yml" extensions/molecule/shared/guard.yml \
			> "$$dir/environment-$$name.log" 2>&1; then \
			printf 'error: the guard accepted the environment setting %s\n' "$$name" >&2; status=1; \
		elif ! grep -q 'is not isolated' "$$dir/environment-$$name.log"; then \
			cat "$$dir/environment-$$name.log"; \
			printf 'error: the environment setting %s was not refused by the isolation check\n' "$$name" >&2; status=1; \
		else printf 'guard refused the environment setting %s\n' "$$name"; fi; \
	done; \
	extra="$$dir/extra-vars"; \
	if [ $$status -eq 0 ] && [ ! -s "$$extra/cases" ]; then \
		printf 'error: libvirt_bypass.yml listed no extra-variable bypass attempts\n' >&2; status=1; \
	fi; \
	for case in $$(cat "$$extra/cases" 2>/dev/null); do \
		[ $$status -eq 0 ] || break; \
		if MOLECULE_INSTANCE_CONFIG="$$extra/$$case/instance_config.yml" $(MOLECULE_LIBVIRT_SELFTEST_PLAYBOOK) \
			-e "molecule_instance_config=$$extra/$$case/instance_config.yml" -e "@$$extra/$$case/vars.yml" \
			-i "$$extra/$$case/inventory.yml" extensions/molecule/shared/guard.yml > "$$extra/$$case/guard.log" 2>&1; then \
			printf 'error: the guard accepted the extra variable %s\n' "$$case" >&2; status=1; \
		elif ! grep -q 'Refusing to run: a variable that the guard relies on was supplied from outside' \
			"$$extra/$$case/guard.log"; then \
			cat "$$extra/$$case/guard.log"; \
			printf 'error: the extra variable %s was not refused as supplied from outside the guard\n' "$$case" >&2; \
			status=1; \
		else printf 'guard refused the extra variable %s\n' "$$case"; fi; \
	done; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/shared/destroy_libvirt.yml || status=1; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) -e selftest_expect_orphan=true extensions/molecule/selftest/libvirt_assert_destroyed.yml || status=1; \
	printf '[]\n' > '$(MOLECULE_LIBVIRT_SELFTEST_CONFIG)'; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/shared/destroy_libvirt.yml || status=1; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/selftest/libvirt_assert_destroyed.yml || status=1; \
	rm -f '$(MOLECULE_LIBVIRT_SELFTEST_CONFIG)'; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/shared/destroy_libvirt.yml || status=1; \
	$(MOLECULE_LIBVIRT_SELFTEST_RUN) extensions/molecule/selftest/libvirt_cleanup.yml || status=1; \
	exit $$status

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

scc-image-ubuntu2604: scc-image
	@printf '%s' '$(SCC_IMAGE_UBUNTU2604)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: SCC_IMAGE_UBUNTU2604 must be a localhost/ tag\n' >&2; exit 2; }
	$(DOCKER) build --network none --file $(SCC_CONTAINERFILE_UBUNTU2604) --tag '$(SCC_IMAGE_UBUNTU2604)' \
		--build-arg SCC_VERSION='$(SCC_VERSION)' --build-arg SCC_DEB_SHA256='$(SCC_DEB_SHA256)' \
		--build-arg SCC_CSCC_SHA256='$(SCC_CSCC_SHA256)' '$(SCC_CONTEXT_DIR)'

scc-smoke: scc-image
	tools/scc/smoke-test.sh '$(SCC_IMAGE)' '$(SCC_VERSION)'

oscap-image: lint-containerfile
	@printf '%s' '$(OSCAP_IMAGE)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: OSCAP_IMAGE must be a localhost/ tag\n' >&2; exit 2; }
	$(DOCKER) build --file $(OSCAP_CONTAINERFILE) --tag '$(OSCAP_IMAGE)' \
		--build-arg OPENSCAP_SCANNER_VERSION='$(OPENSCAP_SCANNER_VERSION)' $(dir $(OSCAP_CONTAINERFILE))

scc-integration: scc-image scc-image-ubuntu2604 oscap-image require-uv collection-link
	uv python install
	$(RUN) python tools/content/fetch_content.py --output-dir build/content --datastream ubuntu2404
	FREESECDEV_SCC_IMAGE='$(SCC_IMAGE)' FREESECDEV_SCC_IMAGE_UBUNTU2604='$(SCC_IMAGE_UBUNTU2604)' FREESECDEV_REQUIRE_SCC=1 \
		FREESECDEV_OSCAP_IMAGE='$(OSCAP_IMAGE)' $(RUN) pytest tests/system/scc --no-cov -v -s -p no:cacheprovider

scc-image-clean:
	@printf '%s' '$(SCC_IMAGE)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: SCC_IMAGE must be a localhost/ tag\n' >&2; exit 2; }
	@printf '%s' '$(SCC_IMAGE_UBUNTU2604)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: SCC_IMAGE_UBUNTU2604 must be a localhost/ tag\n' >&2; exit 2; }
	@printf '%s' '$(OSCAP_IMAGE)' | grep -Eq '^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$$' || { printf 'error: OSCAP_IMAGE must be a localhost/ tag\n' >&2; exit 2; }
	$(DOCKER) image rm --force '$(SCC_IMAGE)' '$(SCC_IMAGE_UBUNTU2604)' '$(OSCAP_IMAGE)'

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
