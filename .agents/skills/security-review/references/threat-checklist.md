# Security review checklist

Mark each item `satisfied`, `not applicable` or `violated` in the review comment.

## Process execution

- [ ] No `ansible.builtin.shell`, `command`, `raw`, `script` or aliases are introduced.
- [ ] External binaries run with an argument list, `shell=False` and an absolute, validated path.
- [ ] Every argument derived from user input is validated against an allow-list or strict pattern.
- [ ] A timeout is enforced and expiry is reported as an execution error.
- [ ] The child environment is explicit and does not inherit secrets.
- [ ] Non-zero exit codes are mapped deliberately; scanner "findings present" codes are distinguished from failures.

## Input handling

- [ ] XML is parsed with entity expansion, DTD loading and network access disabled.
- [ ] Input size and element counts are bounded before full parsing.
- [ ] Paths are resolved and confined to an expected base directory; `..` and absolute escapes are rejected.
- [ ] Symlinks are not followed when writing, or are explicitly rejected.
- [ ] Malformed, truncated and empty inputs produce a structured error, never a pass.
- [ ] Unknown enumeration values are rejected rather than coerced.

## Host modification

- [ ] Audit mode performs no writes; check mode is honoured.
- [ ] File writes are atomic, preserve or set explicit owner, group, mode and SELinux context.
- [ ] Changes that can lock out access (SSH, PAM, sudo, firewall, network, bootloader, mounts) require explicit opt-in variables.
- [ ] Recovery guidance exists for every disruptive control.
- [ ] `become` is scoped to the tasks that need it.

## Secrets and data exposure

- [ ] Sensitive module arguments use `no_log` and are marked in the argument spec.
- [ ] Logs, reports, artifacts and job summaries contain no credentials or tokens.
- [ ] Report HTML escapes all report-derived strings and embeds no executable content from input.

## CI/CD and supply chain

- [ ] Third-party actions are pinned to full commit SHAs and were reviewed.
- [ ] Job `permissions` are minimal and declared per job.
- [ ] No `pull_request_target` or `workflow_run` executes untrusted code with secrets or write tokens.
- [ ] Untrusted input is passed to scripts through environment variables, never interpolated into `run:`.
- [ ] Caches written by untrusted runs cannot be restored by privileged runs.
- [ ] Release jobs verify tag, commit approval, required checks and artifact digests.

## AWS

- [ ] OIDC trust pins issuer, audience, organization, repository and ref or environment.
- [ ] Roles grant only the actions and resources needed; no `*` actions on `*` resources.
- [ ] Session duration is the minimum practical.
- [ ] Buckets block public access, enforce TLS and encryption, and have lifecycle rules.
- [ ] Temporary compute is tagged and is terminated on failure paths.

## Result integrity

- [ ] Scanner execution failures are reported as `error`, never as `fail` or `pass`.
- [ ] Waivers apply only while valid and unexpired, and waived findings stay visible.
- [ ] No rule coverage is claimed that the bundled or supplied content does not contain.
