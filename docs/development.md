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
| `lint` | implemented | `uv lock --check`, `lint-repo`, `lint-skills`, `lint-python`, `lint-yaml`, `lint-actions`, `lint-containerfile`, `lint-ansible`, `lint-toggles`, `lint-role-guards` |
| `lint-ansible` | implemented | `molecule-dependencies`, then `ansible-lint` with the `production` profile, `tools/roles/check_role_specs.py`, then `antsibull-changelog lint` |
| `lint-toggles` | implemented | `tools/roles/generate_toggles.py --check`: fails with a diff when the generated toggle defaults, argument specs or `docs/remediation-variables.md` differ from the rule catalogue ([remediation guide](remediation.md#generated-toggles)) |
| `toggles` | implemented | Regenerates the topic toggle defaults, the topic toggle argument specs and the allow-list choices of the `remediate` and `audit` roles and `docs/remediation-variables.md` from `roles/remediate/vars/rules.yml` |
| `lint-role-guards` | implemented | `tools/roles/generate_role_guards.py --check`: fails with a diff when `roles/remediate/tasks/dispatch.yml` or a `tasks/internal_variables.yml` of the audit, remediate or verify role differs from what the family registry and the role files give (FREES-137) |
| `role-guards` | implemented | Regenerates the static family dispatch of the remediate role, with one include per family that has a native rule, and the internal-variable guards of the audit, remediate and verify roles |
| `content` | implemented | `tools/content/fetch_content.py --output-dir build/content`: fetches the pinned release archive and extracts the verified datastreams |
| `catalogue` | implemented | `tools/roles/generate_catalogue.py`, then `toggles` and `role-guards`: regenerates `roles/remediate/vars/rules.yml` and `docs/control-families.md` from the datastreams in `build/content` and the family mapping `content/catalogue.yml` (run `make content` first) |
| `lint-python` | implemented | Ruff lint, Ruff format check, Pylint (`tools`, `tests`, `plugins`) |
| `lint-yaml` | implemented | `yamllint --strict` |
| `lint-actions` | implemented | actionlint |
| `lint-repo` | implemented | `tools/lint/check_repo_rules.py` on tracked and new YAML and Python files |
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
| `molecule-dependencies` | implemented | Installs the pinned `extensions/molecule/requirements.yml` collections into `build/collections` |
| `molecule-content` | implemented | Fetches and verifies the pinned `ubuntu2404` and `rhel9` datastreams into `build/content` for the Molecule scenarios |
| `test-molecule-docker` | implemented | `molecule-dependencies`, `molecule-content`, then `molecule test` for `docker-ubuntu` and `docker-rhel-compatible` (stops at the first failure), then `test-molecule-docker-selftest` unless `MOLECULE_DOCKER_SELFTEST=false`; needs a running Docker daemon, see [Molecule](molecule.md) |
| `test-molecule-docker-selftest` | implemented | Real guard bypass attempts and the label-based destroy fallback against containers of the `docker-selftest` scenario, see [Molecule](molecule.md#self-test-against-real-containers) |
| `package` | implemented | `ansible-galaxy collection build` repacked with a canonical `FILES.json`, into `dist/`, plus `dist/SHA256SUMS` |
| `package-check` | implemented | Builds twice from differently ordered trees and fails unless the SHA-256 values match |
| `collection-tree` | implemented | Copies the collection files into `build/collection/ansible_collections/freesecdev/linux_compliance` |
| `collection-link` | implemented | Links `plugins/` and `roles/` into `build/collections` for pytest, the type checkers, ansible-lint and `test-remediate-check` |
| `ansible-home` | implemented | Creates `ANSIBLE_HOME` and `ANSIBLE_TEST_HOME` ([per-checkout Ansible home](#per-checkout-ansible-home)); a prerequisite of `collection-link` and `collection-tree` |
| `test-remediate-check` | implemented | Runs `tests/playbooks/remediate-check-mode.yml` against localhost with `--check --diff` and again with `--skip-tags file_permissions`, then `tests/playbooks/remediate-skip-always.yml` with `--skip-tags always`, all without `become`; the toggle plays also run the audit role's toggle resolution ([remediation guide](remediation.md#testing)) |
| `docs` | implemented | markdownlint-cli2 and the relative link checker |
| `clean` | implemented | Removes caches, coverage output and `build/`, including the per-checkout Ansible home |
| `test-role-guards` | implemented | Runs `tests/playbooks/internal-variables-include.yml`, `internal-variables-extra.yml` (twice, with a forged plan and a forged family as extra variables) and `internal-variables-role-param.yml` (per host) against localhost with `--check`, and fails unless every forged internal role variable is refused before the remediate role reads the ledger |
| `ci` | implemented | `lint lint-iac typecheck test-coverage test-browser test-audit-exceptions test-evidence test-remediate-check test-role-guards test-verify security docs test-sanity test-ansible-units package-check` |
| `test-evidence` | implemented | Runs the evidence role against local inventory hosts with synthetic audit results and fixture files: bundle content, provenance, permissions, planted secrets, carried target facts and SCE output, a refused second collection, and fail-closed checksum, path, host-symlink and exceptions-file mismatches; reports on the bundles with `--exceptions-file`, refuses them without it or with another file, and rejects a tampered copy; then runs the plays of `playbooks/evidence.yml` with the gate on and checks that failing and incomplete hosts are collected, missing hosts are named and the play still fails; and checks that no variable route (`-e`, `group_vars`, `host_vars`, include or role import parameters) defers the audit gate ([evidence bundles](evidence.md#tests)) |
| `test-audit-exceptions` | implemented | Runs the audit role's exceptions path (`evaluate.yml` and `stale.yml` entry points) against two local inventory hosts with synthetic scan runs, without `oscap`, with the per-checkout `ANSIBLE_HOME`; checks the stale report under `--limit`; then requires that an invalid file, per-host files under `serial` and the `free` strategy fail the play. The `free` case runs `AUDIT_EXCEPTIONS_FREE_RUNS` times (default 10), and each time every host must have been refused or must have applied exactly the validated SHA-256 (FREES-143, [audit guide](audit.md#tests)) |
| `test-verify` | implemented | Runs the verify role (`baseline.yml` and `main`) on the local inventory host `web01` with synthetic baseline and later audits, without `oscap`, with the per-checkout `ANSIBLE_HOME`; requires the printed regression and applicability warnings, then that baselines not recorded by `baseline.yml` (extra, play, host and inventory variables, a pre-set marker, none at all) are refused and that `--skip-tags always` fails the role ([verify guide](verify.md#tests)) |
| `test-browser` | implemented | Dashboard browser and accessibility tests in the pinned headless Chromium with axe-core; fetches both into `build/browser-test` first (`browser-test-deps`), see the [dashboard guide](dashboard.md) |
| `lint-containerfile` | implemented | hadolint 2.15.1 (pinned by SHA-256, fetched into `build/tools` by `tools/lint/fetch-hadolint.sh`) on `extensions/ci/scc/Containerfile` with `--failure-threshold info`; part of `make lint` |
| `scc-expiry-check` | implemented | Fails from seven days before `SCC_EXPIRES` (`tools/scc/check-expiry.sh`); a prerequisite of `scc-image`, so an expiring SCC is never built or run ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md#7-version-updates-manual-pin-bump)) |
| `scc-fetch` | implemented | Downloads the pinned SCC bundle from the DISA host into `build/scc/download` (or reuses a copy whose SHA-256 matches), cross-checks the published checksum file, extracts only the pinned Debian package and stages it in `build/scc/context` ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md)) |
| `scc-image` | implemented | `scc-expiry-check`, `lint-containerfile` and `scc-fetch`, then `docker build --network none` of the CI-only SCC image as `SCC_IMAGE` (default `localhost/freesecdev-scc:local`; only `localhost/` tags are accepted). The image is never pushed |
| `scc-smoke` | implemented | `scc-image`, then runs `cscc --version` in the image with no network, no capabilities, `no-new-privileges` and a read-only root file system, and requires the pinned version. Needs Docker; not part of `make ci` |
| `scc-image-clean` | implemented | Removes `SCC_IMAGE` from the local image store. On a shared Docker daemon, build with a unique tag (`make scc-smoke SCC_IMAGE=localhost/freesecdev-scc:<name>`) and remove it afterwards |
| `lint-iac` | implemented | `tofu fmt -check -recursive infra/`, `tofu init -backend=false` and `tofu validate` per root module, shellcheck of the rendered bootstrap script; needs `tofu` on `PATH`, runs in the `iac` CI job and in `make ci`, not in `make lint` |
| `aws-bootstrap-render` | implemented | Renders `infra/bootstrap/bootstrap.sh.tmpl` to the gitignored `infra/bootstrap/bootstrap.local.sh` |
| `lint-packer` | pending FREES-64 | Packer validation |
| `test-integration` | pending FREES-60 | Integration tests |
| `test-idempotency` | pending FREES-60 | Idempotency checks |
| `test-compliance` | pending FREES-62 | Compliance scan scenarios |
| `test-molecule-libvirt` | pending FREES-61 | libvirt Molecule scenarios |
| `test-molecule-golden` | pending FREES-63 | Golden image scenarios |
| `packer-validate` | pending FREES-64 | Packer template validation |
| `packer-build` | pending FREES-64 | Packer image build |
| `image-build` | pending FREES-36 | Runner image build on AWS |
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
  - Every entry point of the audit, remediate and verify roles starts with the generated
    `tasks/internal_variables.yml`, which refuses an internal `__linux_compliance_<role>_*` variable supplied from
    outside the role (a role parameter, an include parameter, an extra variable, or a play `set_fact` of a constant
    the role loads). Regenerate it with `make role-guards` after adding an internal variable; the generator fails on a
    variable it cannot classify. `make test-role-guards` checks the refusals in check mode.
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
| `test` | `make test-coverage`, `make test-audit-exceptions`, `make test-evidence`, `make test-remediate-check`, `make test-role-guards`, `make test-verify`, `make test-content-golden`, `make test-browser` |
| `name-sets` | matrix over the pinned Python releases 3.9.25, 3.10.21, 3.11.16, 3.12.14, 3.13.15 and 3.14.6: `uv python install`, then `make test-name-sets` |
| `security` | `make security` |
| `collection` | `make test-sanity test-ansible-units package-check` |
| `iac` | `tools/iac/install-tofu.sh`, then `make lint-iac` |
| `molecule-docker` | `make test-molecule-docker MOLECULE_DOCKER_SELFTEST=false` for `docker-ubuntu` and `docker-rhel-compatible`, and `make test-molecule-docker-selftest` for `docker-selftest`, one matrix entry each |
| `scc-changes` | `tools/scc/needs-smoke.sh`: `scc=false` only for a pull request or merge group whose diff touches no SCC path; `true` for push, schedule and dispatch, and fails closed to `true` |
| `scc-smoke` | runs unless `scc-changes` output `scc=false`; restores the verified SCC download from the Actions cache (key: SHA-256 of `extensions/ci/scc/scc.pins`), then `make scc-smoke`; `contents: read` only, the image stays on the runner |
| `ci-gate` | none; fails unless every needed job succeeded |

`ci-gate` needs every job above, runs with `if: always()` and is the only check that branch protection should require. It accepts a skipped `scc-smoke` only for a `pull_request` or `merge_group` whose `scc-changes` output is `scc=false`; on `push` to `main` and the daily `schedule` the smoke test always runs. Job names
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
- Molecule and `requests` are pinned to exact versions in `pyproject.toml` and `uv.lock` like the other Python tools.
  The `community.docker` collection is pinned in `extensions/molecule/requirements.yml` (Renovate owns Galaxy
  collections) and the container image digests live in `extensions/molecule/shared/vars/versions.yml`. The
  distribution packages of the instance images are pinned to exact versions in the Dockerfiles under
  `extensions/molecule/shared/images/` and updated by hand.
- GitHub Actions are pinned to full commit SHAs with a `# vX.Y.Z` annotation.
- The `uv` version used in CI is pinned in `.github/workflows/ci.yml`.
- OpenTofu `1.13.2` (a security release, exempt from the seven-day rule) is pinned in `infra/account/versions.tf` and
  `tools/iac/install-tofu.sh` with SHA-256 checksums; the AWS provider `6.69.1` is pinned in `versions.tf` and
  `infra/account/.terraform.lock.hcl` (`linux_amd64` and `linux_arm64`); Checkov is pinned in `pyproject.toml`.
