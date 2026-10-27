# Image hardening checklist

## Build definition

- [ ] File is named `Containerfile`.
- [ ] Base image pinned by digest.
- [ ] Multi-stage; final stage has no compilers or package caches.
- [ ] `apk add` pins versions; no `apk upgrade`.
- [ ] Python installs use `--require-hashes` with the locked requirements file.
- [ ] Variants share the same definition.

## Runtime posture

- [ ] Non-root user with fixed UID and GID.
- [ ] No SSH daemon; no setuid or setgid files (verify with a filesystem scan).
- [ ] Explicit permissions on copied files and directories.
- [ ] Works with read-only rootfs, `--cap-drop=ALL` and `--security-opt=no-new-privileges`.
- [ ] Writable paths limited to mounted tmpfs or volumes.
- [ ] OCI labels set.

## Supply chain

- [ ] Built by rootless Buildah in the `image-build` workflow on a GitHub-hosted runner.
- [ ] hadolint clean.
- [ ] SBOM in SPDX and CycloneDX stored with the release.
- [ ] Vulnerability scan clean of fixable critical and high findings.
- [ ] cosign signature and provenance attestation verified against the digest.

## Smoke test

- [ ] Run read-only, non-root, no capabilities.
- [ ] Execute `--version` for every bundled tool and compare with the manifest.
- [ ] Fail on any missing or mismatching tool.
