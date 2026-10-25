---
name: packer-images
description: Packer HCL2 templates and golden image builds for the FreeSecDev Linux compliance platform. Use when adding or changing image variants, Packer plugins, the variant definition file, the images lock manifest, image provenance outputs, or the AWS build flow that produces AMIs and portable qcow2 images hardened with the collection's own playbooks. Produces validated templates, build outputs with provenance and a pinned lock manifest.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Packer images

Golden images are built from one data-driven template and hardened by the collection itself.
They exist so Molecule golden scenarios and users can test against reproducible, scanned hosts.

## When to use

- Adding, removing or changing an image variant or its base image selection.
- Changing `required_plugins`, builders, provisioners or post-processors under `extensions/packer/`.
- Changing the build orchestration (CodeBuild for AMIs, ephemeral KVM host for qcow2).
- Changing `extensions/packer/images.lock.json` or how Molecule consumes it.
- Changing image outputs, manifests, scan steps or provenance.

## Inputs

- The Jira issue and the ADR that accepted the image strategy.
- The variant definition file and the template in `extensions/packer/`.
- The collection version and the profile plus benchmark version to apply, from `compliance-frameworks` content.
- Infrastructure outputs (roles, buckets, subnets) from the `infra/` OpenTofu stack.

## Outputs

- One HCL2 template plus a variant definition file; no per-variant template copies.
- Build artifacts: AMI IDs, qcow2 files, SHA-256 digests, the Packer manifest, distro metadata, Packer and plugin versions, collection version, profile and benchmark version, scan results and provenance.
- Artifacts stored in the encrypted S3 artifact bucket with versioning.
- An updated `extensions/packer/images.lock.json` with pinned hashes, via pull request.
- Checklist in [references/build-checklist.md](references/build-checklist.md) completed for new variants.

## Conventions

- Templates are HCL2 under `extensions/packer/`; `required_plugins` lists exact versions for the official HashiCorp `amazon`, `qemu` and `ansible` plugins, taken from the versions pinned in the plugin lock and research notes.
- Variants are data: `base-ubuntu`, `cis-l1-ubuntu`, `cis-l2-ubuntu`, `stig-ubuntu`, `base-rhel-compatible`, `cis-l1-rhel-compatible`, `stig-rhel-compatible`. A new variant is a new entry in the definition file, never a copied template.
- Hardening runs through the `ansible` provisioner using this collection's playbooks and roles. There is no second hardening implementation in shell, user-data or Packer inline provisioners.
- Authoritative builds run only in AWS region `eu-west-1`. AMIs are built with `amazon-ebs`, orchestrated by CodeBuild.
- Portable qcow2 images use the `qemu` builder on an ephemeral KVM-capable EC2 build host. Never assume CodeBuild exposes `/dev/kvm`.
- Expensive builds are opt-in through `workflow_dispatch` or selective triggers; pull request CI never builds images.
- Golden images are referenced only through `extensions/packer/images.lock.json`, which Molecule golden scenarios read; scenarios never hardcode AMI IDs or image paths.
- Build instances are tagged with the mandatory tags and a max-lifetime value.
- Tool versions are the ones pinned in the repository version files; never restate them in prose.

## Quality gates

- `packer fmt -check` and `packer validate` (per variant) pass in CI without AWS credentials.
- `packer init` resolves only the pinned plugin versions.
- Every produced image has a recorded post-build scan result; failed scans do not update the lock manifest.
- The lock manifest validates against its schema and every entry has a SHA-256 or AMI ID plus the provenance reference.
- Orchestration and lock-manifest logic is covered by the repository's normal test suite.

## Common failures

- Copying the template for one profile instead of adding a variant entry.
- Re-implementing hardening in a provisioner script rather than running the collection.
- Floating plugin versions or unpinned base AMI filters that change between builds.
- Assuming nested virtualization on CodeBuild and failing late.
- Leaving a builder instance or key pair running after a failed or cancelled build.
- Treating "provisioner succeeded" as "image is compliant" without a post-build scan.
- Publishing an image whose lock entry lacks scan results or collection version.

## Security requirements

- Builders are terminated on every failure path: Packer cleanup, instance-initiated shutdown behaviour set to terminate, a max-lifetime tag and the reaper from the `aws-infrastructure` skill.
- Build credentials come from OIDC-assumed image-build roles; no keys in templates, variable files or images.
- Remove SSH host keys, machine IDs, shell history, build users and temporary credentials before capture.
- Artifacts are stored in encrypted, versioned S3 with block public access; AMIs are private and encrypted.
- Images are never claimed compliant beyond what the recorded scan shows; benchmark content is not redistributed (see `compliance-frameworks`).

## Documentation requirements

- Update `docs/` image pages for new variants, the lock manifest format and consumption by Molecule.
- Record an ADR for builder strategy changes, new image sources or plugin changes.
- Document build cost estimates per variant and how to trigger a build.

## Completion criteria

- Template, variant file and lock manifest validate in CI.
- A real build in `eu-west-1` ran for any variant claimed as working, with its outputs and scan result recorded; otherwise the Jira issue states it was not run.
- Builder cleanup was verified, not assumed.
- Jira issue records build run links, artifact hashes and residual risks.

## Interaction with other skills

- Receives bucket, role and builder infrastructure from the `aws-infrastructure` skill.
- Runs the playbooks owned by the `ansible-collection` skill and content selection from the `compliance-frameworks` skill.
- Feeds golden scenarios in the `molecule-testing` skill through the lock manifest.
- Workflow wiring and opt-in triggers belong to the `github-actions` skill.
- Plugin updates flow through the `dependency-management` skill; trust-boundary changes go to `security-review`.
- Design changes need an ADR via the `architecture` skill; outcomes are logged through `jira-management`.
