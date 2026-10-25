# 0008. Portable qcow2 image builds on ephemeral nested-virtualization EC2

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending
- **Pull requests:** pending
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

Developers need portable qcow2 golden images for libvirt. CodeBuild containers are not documented to expose
`/dev/kvm`. The Packer amazon plugin and EC2 now support nested virtualization on current non-metal instance families.

## Decision

A CodeBuild job launches an ephemeral EC2 build host with nested virtualization enabled (C8i family by default)
from a pinned AMI, with instance-initiated shutdown set to terminate and a maximum lifetime tag. The host runs Packer's
qemu builder against checksum-verified official cloud images and provisions with this collection. It uploads qcow2,
SHA-256 and the manifest to encrypted S3, then terminates. A scheduled reaper terminates any builder past its lifetime.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| qemu inside CodeBuild | KVM availability unverified; software emulation is too slow |
| Export AMIs to raw and convert | Export constraints and boot differences between Xen/Nitro and libvirt |
| Bare-metal instances | Much higher hourly cost for no benefit over nested virtualization |

## Benefits

Real KVM acceleration at standard instance pricing, fully ephemeral.

## Trade-offs

Nested virtualization performance is lower than bare metal; builds are opt-in and run on demand.

## Security implications

Builders have no inbound access, use instance roles scoped to one artifact prefix, and are always terminated.

## Operational consequences

Expected cost is a few US dollars per full variant matrix build. Exact figures go in `docs/aws/costs.md` once measured.
