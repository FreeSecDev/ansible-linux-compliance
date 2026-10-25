# Testing and coverage

## Targets

- `make test-unit`: pytest unit tests, fast, no network.
- `make test-coverage`: pytest with branch coverage and the thresholds below.

## Thresholds

- At least 95% line and branch coverage overall.
- 100% line and branch coverage for security decision logic: input validation, path confinement, XML rejection, outcome classification, exception application, HTML escaping.

## Rules

- Tests assert behaviour: outputs, raised error types, side effects. A test that only executes code is not acceptable.
- Cover failure paths: timeouts, malformed input, oversized input, permission errors.
- Use parametrization for tables such as result mapping.
- Use `tmp_path` and fixtures; no shared mutable state, no real network, no real hosts.
- Hostile fixtures live in `tests/fixtures/adversarial/`.

## Exclusions

Allowed only for code that cannot run under test (for example a `__main__` guard or a typing-only branch). Each exclusion is listed in `pyproject.toml` with a reason; reviewers reject unexplained ones.

## Evidence

Attach the coverage summary for changed files to the pull request and link the CI run in Jira.
