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

## Amendment 2026-10-30: libvirt scenarios (FREES-61)

The libvirt scenarios are `libvirt-ubuntu` and `libvirt-rhel-compatible` ([libvirt guide](../molecule-libvirt.md)). They
run the shared playbooks of the Docker scenarios, so the toggle lifecycle of ADR 0011 runs unchanged in a real virtual
machine. The `-bare`, `-golden` and other names of the original list remain for the scenarios of FREES-62 and FREES-63,
which build on these. These refinements apply.

- **Driver and modules.** Molecule's default driver in managed mode with the project's own
  `shared/create_libvirt.yml` and `shared/destroy_libvirt.yml`, as for Docker. The playbooks use only
  `community.libvirt` 2.4.0 (`virt`, `virt_net`, `virt_pool`, `virt_volume`, including `create_cidata_cdrom` for the
  cloud-init seed) and `community.crypto` 3.5.0 (`openssh_keypair` with the `cryptography` backend, for the ephemeral
  client and host keys), both pinned exactly in `extensions/molecule/requirements.yml`. No task runs `virt-install`,
  `qemu-img` or `virsh`: libvirt creates, resizes and deletes the volumes itself. The modules need `libvirt-python`
  12.8.0, `lxml` 6.1.3 and `pycdlib` 1.22.0 on the controller. They form the separate `uv` dependency group `libvirt`,
  installed only by the libvirt targets, because `libvirt-python` builds from source against `libvirt-dev` and every
  other job would need that toolchain otherwise.
- **`qemu:///system` with a network per run.** `qemu:///session` would need user-mode networking, which reaches the
  host's LAN and, with passt, the host's loopback. Each run defines its own network without `<forward>`, DHCP or DNS,
  and gives the virtual machine a static address through cloud-init, so the virtual machine has no route beyond its
  subnet. The network, the pool and the domain carry the run's name; the domain and the network carry its labels as
  libvirt metadata, and the domain carries a random marker as its SMBIOS serial.
- **No package mirror.** Instead of NAT, which would route to the host's LAN, the scanner and its missing libraries are
  pinned packages that the controller copies into the virtual machine.
- **Verified images.** Images and packages are pinned by SHA-256 in `shared/images/cloud-images.pins`.
  `tools/molecule/fetch-cloud-images.sh` checks the vendor's signature on its checksum file with a committed key of the
  pinned fingerprint and requires the signed file to list the pinned digest. It is a shell script, like the SCC fetch
  script, because tools and plugins stay free of `subprocess` outside the audited process helper.
- **Guard.** The localhost guard of FREES-59 and FREES-150 decides the driver from the scenario name and checks a
  libvirt target in three groups: its inventory settings, the domain, network and pool definitions read from the
  controller, and its SMBIOS identity, boot id and machine id over the connection. SSH runs with a per-run
  `known_hosts` and `StrictHostKeyChecking=yes`. Simulated cases run in every scenario's `verify`, and
  `make test-molecule-libvirt-selftest` tests decoys, extra variables, strangers and the destroy fallback against real
  libvirt objects.
- **A video adapter.** The Rocky Linux 9 cloud image does not boot without one, so every domain has a VGA adapter. It
  has no graphical console (`<graphics>` is refused), so it opens no channel to the host.
- **CI.** The `molecule-libvirt` job runs every libvirt scenario and the self-test on GitHub-hosted `ubuntu-24.04`
  runners with KVM, installs QEMU and libvirt in exact versions from a fixed Ubuntu archive snapshot, and is part of
  `ci-gate`. Without `/dev/kvm` it fails instead of emulating.
