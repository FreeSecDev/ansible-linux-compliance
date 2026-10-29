# 0007. Container registry, build location and signing

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-36
- **Pull requests:** pending; amended 2026-10-27 (build location)
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

> **Amended 2026-10-27:** the runner image is built on GitHub-hosted runners, not in AWS CodeBuild. See
> [Amendment of 2026-10-27](#amendment-of-2026-10-27). The registry, signing and digest-only consumption decisions
> below are unchanged; the CodeBuild, ECR staging and copy steps are withdrawn.

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
| Build on GitHub-hosted runners | Superseded on 2026-10-27: this is now the decision (see the amendment). The "AWS build requirement" came only from the original brief and had no technical reason |

## Benefits

No long-lived credentials anywhere; the bytes built in AWS are the bytes signed and published.

## Trade-offs

Provenance is issued by the GitHub workflow, which records the CodeBuild build ID and staged digest as build parameters.

## Security implications

The copy step verifies the digest unchanged between ECR and GHCR. Publishing requires the protected `release` environment.

## Operational consequences

ECR staging images expire through a lifecycle policy after 14 days.

## Amendment of 2026-10-27

The product owner decided on 2026-10-27 to build the CI runner image on GitHub-hosted runners and to use AWS only
for VM golden images (Packer, [ADR 0008](0008-qcow2-builds-nested-virtualization.md)). The CodeBuild design was
merged in the runner repository (linux-compliance-runner pull request 8) but its AWS resources were never created:
pull request 51 here was closed unmerged.

### Decision

- The runner repository's `image-build` workflow builds the image with rootless Buildah from a digest-pinned
  `quay.io/buildah/stable` image on an `ubuntu-24.04` GitHub-hosted runner, from `main` only, in the `release`
  environment.
- The build runs in a job whose token is `contents: read` only, with no package or OIDC token, and hands the image
  on as an archive whose hash and image config digest it records. A separate `push` job, on another VM, checks the
  archive against that record and pushes it to `ghcr.io/freesecdev/linux-compliance-runner` by digest. The smoke
  tests also run in a job without a package token.
- Every later step names `name@sha256:<digest>`: the Grype gate, the SPDX and CycloneDX SBOMs, the cosign keyless
  signature, the build provenance and SBOM attestations, and the workflow's own verification of all of them. The
  release tag `<commit>-<run>-<attempt>` is added last, to the verified digest, and is never moved or reused.
- The only credential is the per-job `GITHUB_TOKEN`. No AWS role, credential or resource is used.
- CodeBuild, the ECR staging repository, the build role and the copy from ECR to GHCR are withdrawn. The "Push to
  GHCR from CodeBuild" and "Build on GitHub-hosted runners" rows of the alternatives table are superseded.
- GHCR stays canonical, and consumers still reference the image by digest only.
  `tests/unit/tools/test_runner_image_pin.py` fails on any other reference to it in a tracked file other than
  Markdown, which it skips because documentation shows tags and placeholders.

### Why

- This ADR required AWS only because the original brief said so; it gave no technical reason.
- [ADR 0012](0012-github-native-releases-and-packages.md) recorded a weakness of the CodeBuild path: its build
  steps were not covered by cryptographic provenance. Built inside the workflow, `actions/attest-build-provenance`
  covers the real build steps.
- GitHub-hosted runners are single-use VMs, as CodeBuild environments were, and the build runs with no write
  credential on its VM, as the CodeBuild build did: the push happens in a separate job on another VM. With that
  split, the isolation of the build is equivalent. GitHub was already in the trust chain, because it triggered the
  build and published the image.
- The CodeBuild path needed a privileged build container, a build role, 26 `StartBuild` Deny statements and an
  inline gate buildspec. All of that disappears.

### Consequences

- The `release` environment does not restrict `packages: write`: any workflow on any branch of the runner
  repository can declare it and write to the package. Consumers are protected by the digest pin and by verifying
  the signature and attestations bound to `image-build.yml@refs/heads/main`, as
  [ADR 0012](0012-github-native-releases-and-packages.md) records.
- Residual risk: the build trusts GitHub-hosted runners and their images. It is recorded in the runner
  repository's [ADR 0002](https://github.com/FreeSecDev/linux-compliance-runner/tree/main/docs/adr).
- The trade-off above (provenance issued by a workflow that did not run the build) and the ECR lifecycle policy no
  longer apply. The benefit becomes: the bytes built in the workflow are the bytes signed and published.
- The pipeline is described in the runner repository's [`docs/image-build.md`](https://github.com/FreeSecDev/linux-compliance-runner/blob/main/docs/image-build.md).
