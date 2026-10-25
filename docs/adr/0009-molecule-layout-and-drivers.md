# 0009. Molecule layout and drivers

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending
- **Pull requests:** pending
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

Molecule documents `extensions/molecule/` with ansible-native configuration for collections. molecule-plugins
has no maintained libvirt driver. Driver playbooks must obey the shell and command module ban.

## Decision

Scenarios live in `extensions/molecule/<scenario>/` with flat names such as `docker-ubuntu` and
`libvirt-ubuntu-bare`. Create and destroy playbooks are shared per platform type and use only
`community.docker` and `community.libvirt` modules plus this collection's modules. Every scenario runs converge,
idempotence, verify and compliance assertions, and libvirt scenarios run a localhost guard first.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| molecule-plugins docker driver | Adds a plugin dependency for behaviour our playbooks provide |
| Vagrant with vagrant-libvirt | Extra non-Python toolchain and box management |
| Nested directories such as `docker/ubuntu` | Molecule scenario discovery uses one directory level |

## Benefits

Current upstream conventions, fewer dependencies, uniform scenario behaviour.

## Trade-offs

The project maintains its own create and destroy playbooks.

## Security implications

Explicit lifecycle playbooks make cleanup and host isolation reviewable.

## Operational consequences

libvirt scenarios need a KVM-capable host; CI runs them opt-in or where KVM is available.
