# 0007. Container registry, build location and signing

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending
- **Pull requests:** pending
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

The runner image must be built in AWS, not locally or on GitHub-hosted runners, and published to a free public
registry with signatures, SBOM and provenance. GHCR is free for public images and accepts `GITHUB_TOKEN` pushes.
CodeBuild can push to Amazon ECR with IAM but has no native GitHub token without a long-lived secret.

## Decision

CodeBuild builds the image with rootless Buildah and pushes it to a private ECR staging repository using its
IAM role. The GitHub Actions workflow that triggered the build then scans the staged digest, generates the SBOM, and
copies the image by digest to GHCR (`ghcr.io/freesecdev/linux-compliance-runner`). It signs it with cosign keyless and
attaches provenance attestations. GHCR is the canonical public registry; consumers reference it by digest only.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Push to GHCR from CodeBuild | Requires a long-lived GitHub token in AWS |
| Amazon ECR Public as canonical | Viable; GHCR integrates attestations and repository visibility more simply |
| Build on GitHub-hosted runners | Violates the AWS build requirement |

## Benefits

No long-lived credentials anywhere; the bytes built in AWS are the bytes signed and published.

## Trade-offs

Provenance is issued by the GitHub workflow, which records the CodeBuild build ID and staged digest as build parameters.

## Security implications

The copy step verifies the digest unchanged between ECR and GHCR. Publishing requires the protected `release` environment.

## Operational consequences

ECR staging images expire through a lifecycle policy after 14 days.

Implemented in FREES-36. The resources and roles are in `infra/account` (see [ADR 0014](0014-aws-account-bootstrap.md),
"Runner image build"). The pipeline is in the runner repository: its `image-build.yml` workflow, `docs/image-build.md`
and ADR 0002. That ADR records why the CodeBuild container is privileged: rootless Buildah needs user namespaces.
