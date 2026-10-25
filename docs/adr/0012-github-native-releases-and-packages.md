# 0012. GitHub-native releases, packages and supply-chain features

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** FREES-118 (release features), FREES-119 (GHCR artifacts), FREES-120 (code scanning), FREES-121 (report image), FREES-122 (Pages)
- **Pull requests:** [ansible-linux-compliance#1](https://github.com/FreeSecDev/ansible-linux-compliance/pull/1)
- **Related:** [0006](0006-toolchain-selection.md), [0007](0007-registry-build-and-signing.md), [0008](0008-qcow2-builds-nested-virtualization.md)

## Context

The project owner requires that the project use everything GitHub offers for releases, packages and related
features. The FreeSecDev organisation is on the Team plan, and both repositories are public. On 2026-10-25 the
following were confirmed available through the API: immutable releases, CodeQL code scanning, GitHub Pages,
deployment environments, dependency-graph SBOM export, Discussions, artifact attestations and GHCR.

GitHub Packages has no native registry for Ansible collections or Python packages. GHCR stores arbitrary OCI artifacts.

## Decision

### Releases

- Releases are cut from protected `main`, never by pushing a tag. A release starts when a reviewed pull request that
  changes the `galaxy.yml` version (or the runner's version file) is squash-merged.
  - The release workflow runs on `push` to `main`, so its definition always comes from protected, reviewed `main`.
    A tag-triggered workflow would run the workflow file from the tagged commit, and an edited file there could skip
    every check.
  - The workflow validates the release, then creates the annotated `vX.Y.Z` tag and the release itself. Tags are
    therefore validated version tags created by the trusted workflow, not inputs to it.
  - Pre-releases use `vX.Y.Z-alpha.N` and `vX.Y.Z-rc.N` and are marked as pre-releases.
- **Immutable releases** are enabled on both repositories, so published release assets and their tags cannot be changed.
- Release notes combine GitHub generated notes, categorised by `.github/release.yml` labels, with the
  antsibull-changelog fragment output.
- Release assets: the collection tarball, `SHA256SUMS`, SPDX and CycloneDX SBOMs, and the OpenSCAP content manifest.
  In the runner repository, the image digest, SBOM and scan report.
- **Artifact attestations** (build provenance and SBOM) are created for every release asset and image, and can be verified
  with `gh attestation verify`. What an attestation proves depends on where the artifact was built:
  - The collection tarball and the content mirror are built inside the GitHub release workflow. Their provenance
    identifies that workflow, its commit and its run.
  - The runner and report images are built in AWS CodeBuild and promoted by digest, as decided in
    [ADR 0007](0007-registry-build-and-signing.md). Their provenance is issued by the GitHub workflow that triggered,
    scanned, copied and signed the image. It records the CodeBuild build ID and the staged ECR digest as build
    parameters, but it does not cryptographically prove which steps CodeBuild executed. Trust in the CodeBuild step
    rests on its IAM role scoping and on the build specification being version-controlled in the runner repository.
- A **tag ruleset** on `refs/tags/v*` blocks tag deletion and updates. It does not yet restrict tag creation:
  GitHub rejects the built-in GitHub Actions app as a bypass actor on repository rulesets, so restricting creation
  needs a dedicated org-owned release App. That App is tracked in FREES-124.
- A **`release` deployment environment** accepts deployments from `main` only. Administrator bypass is disabled. It
  holds the publishing secrets. The AWS release role's OIDC trust must be pinned to this environment when it is built (FREES-31).
- The environment has no human required reviewers: the project owner decided on 2026-10-25 not to be asked for
  approvals. The gate is automated instead. Before anything is published, the release workflow, running from `main`,
  verifies all of the following and fails otherwise:
  - the commit was merged from a pull request approved by the `freesecdev-review` App;
  - every required check passed on that commit;
  - the version is new, follows SemVer and has a changelog entry;
  - no `vX.Y.Z` tag or release exists yet, so a hand-pushed tag makes the release fail instead of being reused;
  - the artifacts rebuild reproducibly.

  See residual risks below.
- Each release posts an announcement to the **Discussions** Announcements category.
- **Milestones** mirror planned versions; Jira fix versions are kept in step for the same version names.

### Packages on GHCR

| Package | Type | Purpose |
|---|---|---|
| `ghcr.io/freesecdev/linux-compliance-runner` | OCI image | CI toolbox ([ADR 0007](0007-registry-build-and-signing.md)) |
| `ghcr.io/freesecdev/linux-compliance-report` | OCI image | Run the report generator without a local Python setup; a variant built from the runner repository's shared build definition |
| `ghcr.io/freesecdev/linux-compliance-collection` | OCI artifact | Digest-pinned, signed collection tarball for offline and disconnected installation |
| `ghcr.io/freesecdev/linux-compliance-content` | OCI artifact | Mirror of pinned ComplianceAsCode datastreams with licence and provenance, for offline hosts |

Every package is signed with cosign, attested, linked to its source repository, and consumed by digest.
Ansible Galaxy remains the primary installation channel for the collection; the GitHub Release and the GHCR artifact
carry byte-identical tarballs. Golden qcow2 images stay in S3 as decided in [ADR 0008](0008-qcow2-builds-nested-virtualization.md),
because of their size.

### Repository features

- **CodeQL** uses advanced setup through a pinned, version-controlled workflow for Python and GitHub Actions, rather than
  default setup, so the configuration is reviewed in pull requests.
- **Code scanning** also ingests SARIF from zizmor, Checkov, Grype and ansible-lint, so findings appear in the Security tab.
- **GitHub Pages** publishes the documentation and approved public sample reports from a pinned Actions deployment.
- The **dependency graph SBOM** is exported for each release and compared with the Syft SBOM.
- A **merge queue** is enabled once the required `ci-gate` check exists.
- **Discussions** are enabled for questions and release announcements.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Galaxy only | Ignores the owner requirement; no signed, digest-pinned offline channel |
| CodeQL default setup | Configuration lives outside Git and cannot be reviewed or pinned |
| qcow2 images on GHCR | Multi-gigabyte artifacts; S3 is already the authoritative store |
| Release Drafter or similar actions | GitHub generated notes provide the same function natively |

## Benefits

Users can verify every artifact with GitHub-native tooling, install offline from signed OCI artifacts, and find all
security findings in one place.

## Trade-offs

More publishing paths to maintain. Immutable releases mean a bad release must be fixed by a new version, never by editing.

## Security implications

### Benefits to integrity

- Immutable releases and the tag ruleset stop published assets and release tags from being replaced or moved.
- Attestations link each artifact to the GitHub workflow run that built or promoted it, within the limits stated above.

### New permissions and how they are contained

| Permission | Needed by | Containment |
|---|---|---|
| `contents: write` | Creating the release | Release job only, `v*` tags only, inside the `release` environment |
| `packages: write` | Pushing to GHCR | Publish jobs only, inside the `release` environment |
| `id-token: write` | cosign keyless signing, attestations, AWS OIDC, Pages | Granted per job, never at workflow level |
| `attestations: write` | Attestations | Publish jobs only |
| `security-events: write` | SARIF upload | Scan jobs on `main` and same-repository pull requests only |
| `pages: write` | Pages deployment | Deploy job on `main` only |
| `discussions: write` | Release announcement | Release job only |

- Workflows declare `permissions: {}` at the top level and grant permissions per job.
- No workflow uses `pull_request_target`, and fork pull requests never receive write tokens or secrets.
- Pages publishes only documentation and sample reports generated from synthetic fixtures. It never publishes real host
  evidence, account identifiers or secrets.
- Mirroring ComplianceAsCode content is limited to BSD-3-Clause material with its notice preserved. Restricted
  benchmark content is never published.

### Residual risks

| Risk | Mitigation now | Owner | Follow-up |
|---|---|---|---|
| No human approves a release before publication, by owner decision | Automated gates in the release workflow, which always runs from protected `main` (approved pull request, required checks, new SemVer version with changelog, reproducibility); main-only release environment; immutable releases; attestations | Project owner | FREES-84 |
| Anyone with write access can create a `v*` tag and run workflows from their own commits with the repository token. They cannot use the `release` environment, so they get no publishing secrets and no AWS release role | Write access is the real containment: today the owner is the only collaborator and the organisation default permission is read. Releases are never triggered by tags. The tag ruleset blocks deletion and update | Project owner | FREES-124 |
| CodeBuild steps are not covered by cryptographic provenance | Version-controlled build specification, least-privilege CodeBuild role, digest comparison before promotion | Lead architect | FREES-36 |

## Operational consequences

The release workflow must complete every publishing step before the release is made public, because immutable releases
cannot be edited afterwards. Release runbooks cover failed partial publishes.
