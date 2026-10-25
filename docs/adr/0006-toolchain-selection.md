# 0006. Toolchain selection for infrastructure and supply-chain security

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending
- **Pull requests:** pending
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

The platform must be free to use, pin every tool and avoid tools with recent unresolved supply-chain risk.
Terraform and Packer are under the BUSL licence. Trivy and its GitHub Actions were compromised on 2026-03-19.

## Decision

- Infrastructure as code: OpenTofu, pinned per repository.
- Image builds: Packer with the official amazon, qemu and ansible plugins. BUSL permits this internal build use; no OSI-licensed alternative of equivalent maturity exists.
- SBOM: Syft (SPDX and CycloneDX). Vulnerability scanning: Grype. IaC scanning: Checkov.
- Signing and attestation: cosign keyless signing from GitHub Actions OIDC plus GitHub artifact attestations.
- Workflow security: actionlint and zizmor. Secret scanning: gitleaks plus GitHub push protection.
- Trivy is not used. Reconsider only through a new ADR after its release integrity is re-established.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Terraform | BUSL licence; OpenTofu is the open-source fork with compatible syntax |
| Trivy for image, IaC and secret scanning | 2026 supply-chain compromise of binaries and actions |
| tfsec | Merged into Trivy and no longer maintained separately |

## Benefits

Open-source tooling with active maintenance and verifiable releases.

## Trade-offs

More tools to pin than a single all-in-one scanner. Packer remains BUSL.

## Security implications

Removes a tool with a known recent compromise from the trust base. All tools are installed by pinned version and checksum.

## Operational consequences

Developers need OpenTofu installed locally; `make bootstrap` checks for it.
