---
name: ansible-modules
description: Writing typed Python Ansible modules, action plugins and module_utils for the freesecdev.linux_compliance collection. Use when adding or changing code in plugins/modules, plugins/module_utils/compliance, plugins/action or plugins/filter, executing external binaries such as oscap, parsing XML scanner output on managed hosts, or writing files on managed hosts. Enforces stdlib-only target code, a single audited process helper, safe parsing and path handling.
license: Apache-2.0
metadata:
  owner: ansible-lead
  version: "1.0.0"
---

# Ansible modules

Target-side Python is small, standard-library only and defensive. It is the only place
where external processes run, and only through one audited helper.

## When to use

- Adding or changing modules in `plugins/modules/` or shared code in `plugins/module_utils/compliance/`.
- Adding controller-side logic as an action plugin or filter.
- Running any external executable from Python, including `oscap`.
- Parsing XCCDF, ARF, OVAL or other XML on a managed host.
- Writing, replacing or deleting files on a managed host from Python.

## Inputs

- Jira issue key, acceptance criteria and ADRs for the interface being changed.
- The findings model and scanner protocol in `plugins/module_utils/compliance/`.
- The ansible-core version pinned in `galaxy.yml` and the managed-host Python versions it supports.
- Adversarial fixtures under `tests/fixtures/adversarial/`.

## Outputs

- Module and `module_utils` code with complete DOCUMENTATION, EXAMPLES and RETURN.
- Unit tests run by `ansible-test units` and pytest, plus new adversarial fixtures.
- A changelog fragment and updated docs for any argument or return value change.

## Conventions

- Target-side code (modules and `module_utils`) uses only the Python standard library and Ansible public APIs, and supports every managed-host Python version supported by the pinned ansible-core. Third-party imports belong to controller code only.
- DOCUMENTATION, EXAMPLES and RETURN are complete, with typed options, choices, defaults and `version_added`. See [references/module-template.md](references/module-template.md).
- Set `supports_check_mode=True` wherever a check is meaningful; audit modules never change the host.
- Failures use `module.fail_json` with structured fields (`msg`, `error_type`, `rule_id` or `path` where relevant), never bare tracebacks.
- Resolve binaries with `module.get_bin_path(name, required=True)`.
- All external process execution goes through `plugins/module_utils/compliance/process.py`, which runs an argument list with `shell=False`, a timeout, an explicit minimal environment and bounded output (ADR 0004). No other file imports `subprocess` or calls `os.system`, `os.popen` or `pty`. Commands are argument lists, never strings.
- Arguments are validated by allow-list or regex before use; reject values starting with `-` where a path or ID is expected. See [references/safe-io.md](references/safe-io.md).
- Parse XML on hosts with the standard library only: reject DOCTYPE and entity declarations before parsing and bound the file size first.
- Confine paths to a base directory, resolve and compare real paths, reject symlinks for writes, write atomically (temporary file, fsync, rename) with an explicit mode.
- Scanner failure, timeout, malformed output or missing content yields outcome `error`, never `pass` or `fail`.
- Action plugins hold only controller-side logic (inventory-wide aggregation, exception handling); they never run host work.
- Private Ansible internals (`_`-prefixed APIs) are forbidden unless isolated behind one adapter, tested and justified by an ADR.
- No inline comments; docstrings are allowed and expected. Typing rules are in `python-quality`.

## Quality gates

- `make test-unit` and `ansible-test units` pass; `make test-sanity` validates the documentation blocks.
- `make typecheck`, `make lint-python` and `make security` pass without new suppressions.
- The repository rule is deny-by-default for `plugins/` outside `process.py`: allow-listed imports only, `os` only as `os.path`, no `exec`, `eval`, `compile`, `__import__`, `getattr` with a computed name, `run_command`, `use_unsafe_shell` or `shell=True`. Ask for an allow-list extension instead of working around it.
- Security decision logic (path confinement, argument validation, XML rejection, outcome mapping) has 100% branch coverage.
- Every module has a negative test for bad arguments and a check-mode test.

## Common failures

- Importing `lxml`, `yaml` or `requests` in target-side code.
- Calling `subprocess` directly "just once", or building a command with an f-string.
- Using `shutil.which` or relying on `PATH` instead of `get_bin_path`.
- Parsing with `xml.etree` without rejecting DOCTYPE, or reading unbounded files.
- Following symlinks on write, or checking a path and then using a different one.
- Mapping scanner exit codes loosely so a crash becomes `pass`.
- Documentation that disagrees with `argument_spec`.
- Environment inherited wholesale into child processes.

## Security requirements

- Treat scanner output, content files, ARF results and module arguments as untrusted.
- Minimal explicit environment for child processes; no secrets in arguments, environment or logs.
- Timeouts on every external call; bounded stdout and stderr capture.
- File writes are atomic, mode-explicit and confined; temporary files are not world-readable.
- Modules that need privilege rely on task-level `become` and do not escalate themselves.

## Documentation requirements

- Module documentation is the user reference; mirror new behaviour in `docs/`.
- Record an ADR for interface, return-schema, protocol or process-helper changes.
- Add a changelog fragment; update the threat model for new entry points.

## Completion criteria

- Unit, sanity, typing, lint and security checks pass in CI.
- Adversarial fixtures exist for each new parser or path-handling code path.
- Documentation, examples and return values match behaviour.
- Jira issue records the pull request, CI links and test evidence.

## Interaction with other skills

- Interfaces and boundaries come from the `architecture` skill.
- Roles that call these modules are governed by the `ansible-collection` skill.
- Classification and rule ID semantics come from the `compliance-frameworks` skill.
- Typing, coverage and static analysis rules come from the `python-quality` skill.
- Process execution, parsing and file writes always go through the `security-review` skill.
- Integration behaviour is proven by the `molecule-testing` skill.
