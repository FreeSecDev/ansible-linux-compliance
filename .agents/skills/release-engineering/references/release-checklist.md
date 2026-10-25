# Release checklist

Mark each item only after it actually ran. Do not paste secrets.

## Before tagging

- [ ] All changes since the last release have changelog fragments in `changelogs/fragments/`.
- [ ] Version chosen by SemVer; major bump has an accepted ADR.
- [ ] Release pull request bumps `galaxy.yml` and the generated changelog; approved by an independent reviewer; squash merged.
- [ ] `make release-check` passes on `main` at the merge commit.
- [ ] Required checks and security scans are green on that commit.
- [ ] Runner image reference in use is a digest of an immutable version tag.

## Tagging

- [ ] Annotated tag `vX.Y.Z` created on the merge commit on `main`.
- [ ] Tag version equals `galaxy.yml` version.

## Release workflow verification

- [ ] Tag commit is on `main` and came from an approved pull request.
- [ ] All required checks passed for the tag commit.
- [ ] Tarball rebuilt twice with `SOURCE_DATE_EPOCH`; SHA-256 sums identical.
- [ ] Security scans passed.
- [ ] Publishing job waited for approval from the `release` environment reviewers.

## Published artifacts

- [ ] GitHub Release has tarball, SHA-256 checksums, SBOM and provenance attestation.
- [ ] Ansible Galaxy shows the same version; downloaded tarball checksum matches.
- [ ] Attestation verifies for the tarball.

## After release

- [ ] Jira release issue transitioned with tag, run and release links.
- [ ] `docs/release.md` and support matrix reflect only verified facts.
- [ ] Galaxy key rotation date checked.
