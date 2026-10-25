---
name: security-review
description: Threat modelling and adversarial review of security-critical changes in the FreeSecDev compliance platform. Use for any change touching privilege escalation, external process execution, parsing of scanner or benchmark content, file system writes on managed hosts, IAM or OIDC trust, CI permissions, secrets, release signing, or compliance result classification. Produces a written review verdict with findings and required fixes.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Security review

Independent, adversarial review of changes whose failure would compromise a managed host,
the CI/CD supply chain, AWS accounts, or the correctness of compliance results.
The reviewer must not be the author of the change.

## When to use

Invoke this skill when a change does any of the following:

- Executes an external binary from a module, action plugin or tool.
- Parses untrusted or semi-trusted input: XCCDF, ARF, OVAL, DataStreams, JUnit, JSON reports, user-supplied benchmark content, exception files.
- Writes, moves, deletes or changes permissions of files on a managed host.
- Uses `become`, changes PAM, SSH, sudo, firewall, bootloader, kernel or authentication settings.
- Changes IAM policies, OIDC trust policies, CodeBuild roles, bucket policies or KMS keys.
- Changes GitHub Actions triggers, permissions, caches, artifacts, environments or release workflows.
- Changes how results are classified as pass, fail, error, waived, not applicable or not checked.
- Changes image signing, SBOM generation, provenance or release verification.
- Adds a dependency, GitHub Action, container base image or Packer plugin.

## Inputs

- Jira issue key and the pull request URL or local branch name.
- The diff under review and the ADRs it claims to implement.
- The current threat model in `docs/security/threat-model.md`.
- CI results for the branch, including security scanners.

## Outputs

- A review comment on the pull request using the template in [references/review-template.md](references/review-template.md).
- A verdict: `approve`, `approve-with-follow-ups` or `request-changes`.
- Jira follow-up issues for every accepted residual risk, linked to the original issue.
- Threat model updates when the change introduces a new trust boundary, asset or entry point.

## Conventions

- Review against the checklist in [references/threat-checklist.md](references/threat-checklist.md); record each applicable item as satisfied, not applicable or violated.
- State every finding as: affected file and line, attacker capability assumed, concrete failure scenario, impact, required fix.
- Severity uses `critical`, `high`, `medium`, `low`. A `critical` or `high` finding always means `request-changes`.
- Prefer exploit-shaped evidence: a failing test, a crafted input file or a reproducible command sequence.
- Distinguish defects from hardening suggestions; suggestions never block a merge on their own.
- Assume CI pull requests from forks are hostile, report files are attacker-controlled, and managed hosts may already be compromised.

## Quality gates

- Every applicable checklist item is evaluated and recorded.
- Every `critical` and `high` finding has a regression test in the same pull request before approval.
- Bandit, Ruff security rules, zizmor and secret scanning pass without new suppressions.
- New suppressions carry a justification referencing the finding and the reviewer.
- Security-relevant decision logic has 100% line and branch coverage.

## Common failures

- Reviewing only the happy path and not malformed, oversized, symlinked or concurrent inputs.
- Accepting `shell=True`, string-built command lines or binaries resolved from `PATH` without pinning.
- Treating a scanner crash or parser error as `pass` or `not applicable` instead of `error`.
- Allowing `pull_request_target`, `workflow_run` or shared caches to expose privileged tokens to untrusted code.
- Trusting the `sub` claim of an OIDC token without pinning repository, ref or environment.
- Approving secrets in logs, `no_log` omissions, or report HTML that renders untrusted strings unescaped.
- Confusing "the remediation ran" with "the control is now satisfied".

## Security requirements

- The reviewer never runs untrusted pull request code with credentials available.
- The reviewer never copies secrets, tokens or host evidence containing sensitive data into Jira, PR comments or logs.
- Proof-of-concept inputs are committed only as inert test fixtures under `tests/fixtures/adversarial/`.
- Residual risk is accepted only by the lead architect and recorded in Jira and the threat model.

## Documentation requirements

- Update `docs/security/threat-model.md` for new assets, trust boundaries or entry points.
- Record an ADR when the review changes an architectural security decision.
- Link the review comment from the Jira issue with a short summary of the verdict and findings.

## Completion criteria

- A verdict is posted on the pull request.
- All blocking findings are fixed and re-verified, or the change is rejected.
- Follow-up issues exist for every non-blocking finding that was accepted.
- The Jira issue records the review outcome, reviewer and pull request link.

## Interaction with other skills

- Invoked by the `code-review` skill whenever a change matches the trigger list above.
- Consumes threat model context maintained with the `architecture` skill.
- Escalates IAM and OIDC questions to the `aws-infrastructure` skill and workflow questions to the `github-actions` skill.
- Hands parser and classification test requirements to the `python-quality` and `reporting-dashboard` skills.
- Records outcomes through the `jira-management` skill.
