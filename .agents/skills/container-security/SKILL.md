---
name: container-security
description: Secure container image engineering for the FreeSecDev CI toolbox image built in the linux-compliance-runner repository. Use when writing or changing a Containerfile, image variants, SBOM, vulnerability scanning, signing, provenance, smoke tests, or how the collection repository consumes the image by digest. Produces hardened, signed, scanned and smoke-tested images.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Container security

The runner repository builds a toolbox image used by CI. It is a toolbox, not a persistent
self-hosted runner agent. The collection repository consumes it by digest only.

## When to use

- Creating or changing a `Containerfile`, its variants or its build scripts.
- Changing package, Python dependency or tool installation in the image.
- Changing SBOM generation, vulnerability scanning, signing or provenance.
- Changing smoke tests or the release gate.
- Changing how any repository references the image.

## Inputs

- The Jira issue and ADRs, including the scanner decision.
- The Containerfile, the hash-locked Python requirements file and the tool manifest.
- The runner repository's `image-build` workflow, `Makefile` and digest-pinned Buildah builder image.

## Outputs

- A `Containerfile` (never a Dockerfile) with purpose-specific variants sharing one build definition.
- SBOMs in SPDX and CycloneDX formats, scan reports, a cosign signature and a provenance attestation.
- The image digest, published for the main repository to consume.
- Review checklist in [references/image-hardening-checklist.md](references/image-hardening-checklist.md) completed.

## Conventions

- Base image is Alpine, pinned by digest and updated by Renovate.
- Use multi-stage builds. `apk add` pins package versions; never run an unbounded `apk upgrade`.
- Python dependencies install from a hash-locked requirements file with `--require-hashes`.
- Run as a non-root user with a fixed UID and GID such as 10001. No SSH daemon, no setuid or setgid binaries, explicit file permissions, no credentials in any layer.
- Add OCI labels for source, revision, version and licence.
- The image works with a read-only root filesystem, `--cap-drop=ALL` and `--security-opt=no-new-privileges`.
- Release images are built with rootless Buildah by the runner repository's `image-build` workflow on GitHub-hosted
  runners, from `main` only; a local or self-hosted build is never published.
- Variants are build arguments or targets of one definition; do not fork the Containerfile.
- Lint with hadolint, which works on Containerfiles.
- Generate SBOMs with Syft in SPDX and CycloneDX.
- Scan with Grype and/or Trivy as decided by the ADR. Release is blocked on fixable critical or high findings.
- Sign with cosign and attach a provenance attestation to the digest.
- The collection repository references the image by digest and never duplicates its build logic.

## Quality gates

- hadolint passes without undocumented ignores.
- Smoke tests run the image read-only, as non-root, with all capabilities dropped, and execute each bundled tool's `--version`.
- Scan shows no fixable critical or high findings, or a documented, expiring exception exists.
- Signature and attestation verify against the pushed digest.
- Tool versions in the image match the versions pinned in the tool manifest.

## Common failures

- Using a tag instead of a digest for the base image or for consumers.
- `apk add` without versions, or `apk upgrade`, making builds irreproducible.
- Installing Python packages without hashes or with `--no-deps` gaps.
- Leaving package caches, build tools or tokens in the final stage.
- Tests that pass only because the container runs as root or with writable rootfs.
- Signing a tag rather than the digest.
- Duplicating tool installation in the collection repository.

## Security requirements

- No secrets in build arguments, layers, labels or logs; the only credential is the per-job `GITHUB_TOKEN`, which
  never enters the build container.
- The final stage contains only runtime tools needed by CI.
- Scan, signing and attestation steps run in the same workflow against the pushed digest; signing is keyless
  through GitHub OIDC; no long-lived keys and no AWS credential.
- Vulnerability exceptions use the expiring format from the `dependency-management` skill.
- Image and pipeline changes are reviewed by `security-review`.

## Documentation requirements

- Update runner repository docs with the tool list, variants, verification commands and consumption by digest.
- Record ADRs for scanner choice, base image changes and new tools.
- Document how to verify the signature and read the SBOM.

## Completion criteria

- The image was built by the `image-build` workflow, scanned, signed, attested and smoke-tested; digest and run
  links are on the Jira issue.
- The main repository references the new digest through a reviewed pull request.
- No step is reported successful unless it actually ran.

## Interaction with other skills

- Runs on GitHub-hosted runners with workflows from the `github-actions` skill; AWS is not involved.
- Base image and package updates flow through the `dependency-management` skill.
- Signing and publishing procedures align with `release-engineering`.
- Reviewed by `security-review`; design choices go through `architecture`.
- Tool lists feed the `python-quality` and `documentation` skills.
