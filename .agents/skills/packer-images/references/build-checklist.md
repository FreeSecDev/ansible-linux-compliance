# Image build checklist

## New variant

- [ ] Entry added to the variant definition file; no template copied.
- [ ] Base image selection filter is pinned by owner and exact name pattern.
- [ ] Profile and benchmark version resolve to content available to the collection.
- [ ] `packer fmt -check` and `packer validate` pass for the variant.
- [ ] Molecule golden scenario added or updated to read the lock manifest.

## AMI build (CodeBuild, eu-west-1)

- [ ] Triggered by `workflow_dispatch` or an explicit selective rule.
- [ ] Image-build role assumed through OIDC; session at most one hour.
- [ ] Builder and AMI carry project, repo, owner, cost-center and ttl tags.
- [ ] AMI is encrypted and private; snapshot tags match.
- [ ] Post-build scan executed and stored.

## qcow2 build (ephemeral KVM host)

- [ ] Host launched with instance-initiated shutdown set to terminate and a max-lifetime tag.
- [ ] `/dev/kvm` presence checked before the qemu build starts.
- [ ] SHA-256 computed after the build and recorded in the manifest.
- [ ] Host terminated on success and on failure; termination verified.

## Lock manifest entry

- [ ] Image ID or SHA-256, distro metadata, Packer and plugin versions.
- [ ] Collection version, profile and benchmark version.
- [ ] Scan result reference and provenance reference.
- [ ] Artifact location in the encrypted S3 bucket.
