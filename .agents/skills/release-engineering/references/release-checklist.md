# Release checklist

Mark each item only after it actually ran. Do not paste secrets. Releases are cut from protected `main` by the release
workflow; nobody pushes `v*` tags by hand ([ADR 0012](../../../../docs/adr/0012-github-native-releases-and-packages.md)).

## Release pull request

- [ ] All changes since the last release have changelog fragments in `changelogs/fragments/`.
- [ ] Version chosen by SemVer; a major bump has an accepted ADR.
- [ ] The pull request bumps `galaxy.yml` (or the runner version file) and the generated changelog.
- [ ] Approved by `freesecdev-review` after the last push; squash merged into `main`.
- [ ] Runner image reference in use is a digest of an immutable version.

## Release workflow gates (on push to `main`)

- [ ] Merge commit came from a pull request approved by `freesecdev-review`.
- [ ] All required checks and security scans passed on the merge commit.
- [ ] Version is new SemVer with a changelog entry, and no `vX.Y.Z` tag or release exists yet.
- [ ] Tarball rebuilt twice with `SOURCE_DATE_EPOCH` from the merge commit; SHA-256 sums identical.
- [ ] Workflow created the annotated `vX.Y.Z` tag on the merge commit and the release.

## Published artifacts

- [ ] GitHub Release has tarball, SHA-256 checksums, SBOM and provenance attestation.
- [ ] Ansible Galaxy shows the same version; downloaded tarball checksum matches.
- [ ] Attestation verifies for the tarball.

## After release

- [ ] Jira release issue transitioned with tag, run and release links.
- [ ] `docs/release.md` and support matrix reflect only verified facts.
- [ ] Galaxy key rotation date checked.
