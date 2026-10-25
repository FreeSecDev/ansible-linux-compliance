---
name: compliance-frameworks
description: Compliance content, benchmarks, profiles, rule mappings, licensing and the support matrix for the FreeSecDev platform. Use when selecting or pinning OpenSCAP or ComplianceAsCode content, classifying controls, mapping rules to CIS, STIG, NIST, PCI DSS or ANSSI references, handling user-supplied benchmark content, mapping XCCDF results to outcomes, or updating docs/support-matrix.yml. Prevents licence violations, invented coverage and false compliance claims.
license: Apache-2.0
metadata:
  owner: compliance-lead
  version: "1.0.0"
---

# Compliance frameworks

Defines what the platform may scan, remediate and claim, and how content is licensed,
pinned and mapped. Coverage is only what is implemented and tested.

## When to use

- Adding, updating or pinning SCAP content or a supported OS, version or profile.
- Classifying a control or adding a rule to audit or remediation.
- Mapping rules to frameworks or changing result outcome mapping.
- Accepting user-supplied benchmark content or writing its acquisition documentation.
- Updating `docs/support-matrix.yml` or any statement about coverage or compliance.

## Inputs

- Jira issue key and the ADRs on scanner protocol and content handling.
- Upstream ComplianceAsCode / SCAP Security Guide release notes and licence files.
- The content manifest and current `docs/support-matrix.yml`.
- Test evidence (Molecule runs, CI links) for any testing status being recorded.

## Outputs

- Updated content manifest entries with version and SHA-256 per datastream.
- Updated `docs/support-matrix.yml`, validated against its schema.
- Rule classification and mapping data with provenance.
- Licensing and provenance notes in `docs/`.

## Conventions

- Engines: OpenSCAP with ComplianceAsCode / SCAP Security Guide content (BSD-3-Clause). Other backends may be added later only through the scanner protocol.
- Classify every control as exactly one of: directly auditable, automatable remediation, evidence-only, manual or organizational, unsupported. See [references/classification-and-mapping.md](references/classification-and-mapping.md).
- Never redistribute CIS benchmark documents, CIS-CAT content or other restricted material. SSG's own CIS-aligned profiles may be used, with provenance stating they are ComplianceAsCode implementations and not CIS-certified content.
- User-supplied content is supported with documented acquisition steps; the repository never bundles it.
- The content manifest pins version and SHA-256 per datastream; the digest is verified before every use.
- Never silently substitute an unavailable profile or benchmark; fail with a clear error. Never invent coverage.
- Rule IDs are full XCCDF IDs: `xccdf_org.ssgproject.content_rule_<id>`. Short IDs are display-only.
- Cross-framework mappings (CIS, STIG ID and SRG, NIST 800-53, 800-171, PCI DSS, ANSSI) come from ComplianceAsCode reference metadata and carry provenance (source, content version, digest).
- One remediation may satisfy many frameworks; deduplicate by rule ID so each rule is scanned, remediated and counted once.
- Mapping frameworks (NIST, PCI DSS, ISO 27001, NIS2, BSI) are evidence mappings only.
- Result outcomes: `pass`, `fail`, `notapplicable`, `notchecked`, `error`, `waived`, `disabled`. `disabled` means an operator toggle excluded the rule ([ADR 0011](../../../docs/adr/0011-control-toggles-and-cleanup.md)) and is never counted as passing. XCCDF `informational`, `notselected`, `fixed` and `unknown` are mapped explicitly, never defaulted; see the mapping table in the reference.
- `docs/support-matrix.yml` is machine-readable with OS, version, architecture, benchmark versions, profiles, scanner availability, remediation availability, testing status and restrictions.

## Quality gates

- Manifest verification test fails on a digest mismatch or a missing entry.
- Support matrix schema validation passes; testing status values correspond to executed runs with CI or Jira links.
- Outcome mapping tests cover every XCCDF result value with 100% branch coverage.
- A test fails if a profile is requested that the matrix marks unavailable and the code falls back to another.
- Licence scan finds no restricted benchmark files in the repository or artifacts.

## Common failures

- Committing a CIS PDF, CIS-CAT bundle or a benchmark spreadsheet.
- Calling SSG profiles "CIS certified" or omitting provenance.
- Marking testing status `tested` for a platform that only built, or from a past run.
- Counting the same rule once per framework and inflating coverage.
- Mapping `notselected` or `unknown` to `pass`.
- Using short rule IDs as keys, which collide across content versions.
- Updating content without updating the manifest digest, or trusting a digest from the same download.

## Security requirements

- Datastreams are untrusted until the SHA-256 matches the manifest; user content is additionally parsed defensively.
- Provenance (source URL, version, digest, retrieval date) is recorded for every content item.
- No credentials or licensed content in logs, reports or issues.
- A scanner failure is `error`, never `pass` or `fail`.

## Documentation requirements

- Document supported platforms, profiles and limits in `docs/` from the support matrix.
- Document acquisition steps for user-supplied content and its licence implications.
- State in reports that scans provide evidence, not certification; never claim ISO 27001, PCI DSS, NIST or NIS2 compliance from host scans.
- Record an ADR when adding a backend, changing outcome mapping or changing manifest format.

## Completion criteria

- Manifest, support matrix and docs agree and validate.
- Every claimed rule has a classification, a full ID and mapping provenance.
- Testing status is backed by executed tests linked from the pull request.
- Jira issue records licence review and evidence links.

## Interaction with other skills

- Interfaces and backend protocol decisions belong to the `architecture` skill.
- Parsing and scanner code is implemented under the `ansible-modules` skill.
- Remediation task files that implement rule IDs are written under the `ansible-collection` skill.
- Testing status is produced by the `molecule-testing` skill.
- Presentation of outcomes and mappings is owned by the `reporting-dashboard` skill.
- Licence and provenance concerns are reviewed by the `security-review` skill.
- Upstream content updates follow the `dependency-management` skill.
