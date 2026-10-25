# 0012. GitHub-native releases, packages and supply-chain features

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** pending (release epic)
- **Pull requests:** pending
- **Related:** [0006](0006-toolchain-selection.md), [0007](0007-registry-build-and-signing.md)

## Context

The project owner requires that the project use everything GitHub offers for releases, packages and related
features. The FreeSecDev organisation is on the Team plan, and both repositories are public. On 2026-10-25 the
following were confirmed available through the API: immutable releases, CodeQL code scanning, GitHub Pages,
deployment environments, dependency-graph SBOM export, Discussions, artifact attestations and GHCR.

GitHub Packages has no native registry for Ansible collections or Python packages. GHCR stores arbitrary OCI artifacts.

## Decision

### Releases

- Releases are created only by the release workflow, from annotated `vX.Y.Z` tags. Pre-releases use
  `vX.Y.Z-alpha.N` and `vX.Y.Z-rc.N` and are marked as pre-releases.
- **Immutable releases** are enabled on both repositories, so published release assets and their tags cannot be changed.
- Release notes combine GitHub generated notes, categorised by `.github/release.yml` labels, with the
  antsibull-changelog fragment output.
- Release assets: the collection tarball, `SHA256SUMS`, SPDX and CycloneDX SBOMs, and the OpenSCAP content manifest.
  In the runner repository, the image digest, SBOM and scan report.
- **Artifact attestations** (build provenance and SBOM) are created for every release asset and image, and can be verified
  with `gh attestation verify`.
- A **tag ruleset** on `refs/tags/v*` blocks tag deletion and updates.
- A **`release` deployment environment** restricted to `v*` tags gates publishing, with the project owner as required reviewer.
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

Immutable releases and tag rulesets stop artifacts being replaced after publication. Attestations bind each artifact to
the workflow that built it. The release environment adds a human approval before publishing.

## Operational consequences

The release workflow must complete every publishing step before the release is made public, because immutable releases
cannot be edited afterwards. Release runbooks cover failed partial publishes.
