---
name: release-engineering
description: Versioning, changelog, packaging and publishing for the freesecdev.linux_compliance Ansible collection and the linux-compliance-runner image. Use when preparing a release, adding changelog fragments, bumping galaxy.yml, building the collection tarball, creating release tags, or changing the release workflow, checksums, SBOM, provenance or Ansible Galaxy publishing. Enforces tag-only, verified, reproducible releases.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Release engineering

Releases are rare, verified and reproducible. A release is never a side effect of a merge.

## When to use

- Adding a user-visible change that needs a changelog fragment.
- Preparing or publishing a release of the collection, including the version-bump pull request that triggers it.
- Releasing or consuming a new runner image version.
- Changing `make package`, `make release-check` or the release workflow.

## Inputs

- Merged pull requests since the previous release and their changelog fragments.
- `galaxy.yml` version and the planned tag `vX.Y.Z`.
- Required check results, security scan results and ADRs affecting the release.

## Outputs

- Changelog fragments in `changelogs/fragments/`, built with antsibull-changelog at release time.
- A release pull request that bumps `galaxy.yml` and the changelog.
- An annotated tag `vX.Y.Z` on a commit on `main`.
- Collection tarball, SHA-256 checksums, SBOM and provenance attestation on GitHub Releases, and the collection on Ansible Galaxy.
- Steps and checks per [references/release-checklist.md](references/release-checklist.md).

## Conventions

- Semantic Versioning: breaking changes to module arguments, role variables, report schema or exception format are major; additive changes are minor; fixes are patch.
- Every user-visible change adds a changelog fragment reviewed in its pull request.
- Releases start only when a reviewed pull request that bumps the `galaxy.yml` version (or the runner version file) is merged to `main`. The release workflow runs from `main`, validates the release, then creates the annotated `vX.Y.Z` tag and the release. Never trigger a release by pushing a tag, and never release an arbitrary commit without a version bump.
- Use every GitHub-native release feature in [ADR 0012](../../../docs/adr/0012-github-native-releases-and-packages.md). Releases are immutable, so complete every publishing step before making a release public. Attest every asset and image so `gh attestation verify` succeeds. Generate notes from `.github/release.yml` categories, announce in Discussions, and publish the collection and content mirror as signed OCI artifacts on GHCR alongside Galaxy.
- The release workflow, running on `push` to `main`, verifies before publishing: the merge commit came from a pull request approved by `freesecdev-review`; all required checks passed; the version is new SemVer with a changelog; no `vX.Y.Z` tag or release exists yet (otherwise it fails); the artifacts rebuild reproducibly (`SOURCE_DATE_EPOCH` set from the merge commit, deterministic tarball); security scans passed. It then creates the tag on the merge commit and the release.
- It publishes the tarball, checksums, SBOM and provenance attestation to GitHub Releases and the collection to Ansible Galaxy.
- The Galaxy API key is stored only as a secret of the `release` environment, which accepts deployments from `main` only. Galaxy offers no OIDC publishing, so this key is the one long-lived credential and is rotated on schedule.
- Runner images are released from the runner repository with immutable version tags and consumed here by digest only.
- `make package` builds the tarball locally; `make release-check` runs every verification except publishing.
- Never release when a mandatory check fails; fix forward with a new version rather than moving a tag.

## Quality gates

- `make release-check` passes locally and in CI.
- Two independent builds of the tarball produce identical SHA-256 sums.
- Tag version, `galaxy.yml` version and changelog heading agree.
- Security scans, `ansible-test sanity` and the full test matrix passed for the merge commit.
- Checksums and attestation verify against the published files.

## Common failures

- Pushing a `vX.Y.Z` tag by hand or triggering a release from a tag; a pre-existing tag makes the release workflow fail by design.
- A lightweight tag instead of an annotated one.
- Non-reproducible tarballs from timestamps, file ordering or ownership.
- Publishing to Galaxy from a workflow without the protected environment.
- Re-pointing or deleting a published tag.
- Consuming a runner image by mutable tag.
- Releasing with a skipped or flaky required check marked as acceptable.

## Security requirements

- The Galaxy key never appears in logs, artifacts or the repository; the release environment accepts `main` only, and the workflow passes its automated gates before the key is used.
- Release workflow permissions are least privilege; attestation uses OIDC to GitHub, not stored keys.
- No release artifact is built from untrusted pull request code.
- Changes to the release workflow or signing require the `security-review` skill.

## Documentation requirements

- Update `docs/release.md` with any process change and link the ADR.
- The GitHub Release notes come from the changelog, with checksum verification instructions.
- Record the release outcome on the Jira release issue.

## Completion criteria

- The tag, GitHub Release and Galaxy version exist and match.
- Checksums, SBOM and attestation are attached and verified.
- Reproducibility was demonstrated and recorded.
- The Jira issue links the tag, workflow run and release page.

## Interaction with other skills

- Release workflows are implemented with `github-actions`; image release policy is shared with `container-security`.
- Dependency and vulnerability state is supplied by `dependency-management`.
- Pull requests carrying fragments are accepted through `code-review`, and the release workflow is reviewed by `security-review`.
- Release documentation is written with `documentation` and tracked in `jira-management`.
- Interface changes that drive major versions are decided with `architecture`.
