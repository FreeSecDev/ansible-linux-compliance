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
run only what a container cannot prove: the shared `prepare` and toggle lifecycle (with the cycles that require
libvirt, ADR 0011), and their own `converge_libvirt.yml` and `verify_libvirt.yml`, which show the reference rule moving
from `fail` to `pass` in a real scan, one idempotence pass and the cleanup. The `-bare`, `-golden` and other names of
the original list remain for the scenarios of FREES-62 and FREES-63, which build on these. These refinements apply.

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
  controller, and its SMBIOS identity, boot id and machine id over the connection. The domain check is an
  allow-list: only the elements that the template defines or libvirt adds, sources in the run's pool, network or a
  pseudo terminal, dynamic security labels with relabelling (AppArmor ones on an AppArmor host), the pinned emulator and
  `/dev/urandom` as the only entropy source; everything else is refused. SSH runs with a per-run
  `known_hosts` and `StrictHostKeyChecking=yes`. Simulated cases run in every scenario's `verify`, and
  `make test-molecule-libvirt-selftest` tests decoys, extra variables, strangers and the destroy fallback against real
  libvirt objects.
- **File disks.** The disks are files in the run's pool directory (`type='file'`), because `virt-aa-helper`, which writes
  the AppArmor profile of a domain on Ubuntu, does not resolve pool volumes.
- **A video adapter.** The Rocky Linux 9 cloud image does not boot without one, so every domain has a VGA adapter. It
  has no graphical console (`<graphics>` is refused), so it opens no channel to the host.
- **Base and lifecycle scenarios.** As for Docker after FREES-53, each platform has a base scenario
  (`libvirt-<platform>`: converge, idempotence, verify) and a lifecycle scenario (`libvirt-<platform>-lifecycle`:
  `side_effect`).
- **CI.** The `molecule-libvirt` job runs the legs that `make molecule-matrix MOLECULE_MATRIX_DRIVER=libvirt` plans in
  the `molecule-plan` job: the base scenario of each platform, one lifecycle leg per topic with a cycle that requires
  libvirt, platform and toggle mode, and the self-test. It runs on GitHub-hosted `ubuntu-24.04` runners with KVM,
  installs QEMU and libvirt in exact versions from a fixed Ubuntu archive snapshot, and is part of `ci-gate`. Without
  `/dev/kvm` it fails instead of emulating. Each leg must finish well within the 30-minute check timeout of the merge
  queue; the first version, which ran every cycle on the machines, took 65 minutes, so the machines now run only what
  containers cannot prove.

## Amendment 2026-10-30: cached host packages and task timings (FREES-180)

On slow runs the snapshot answered at 128 to 239 kB/s, and installing QEMU and libvirt took 6.4 minutes instead of
0.9, close to the leg's timeout. These refinements apply ([libvirt guide](../molecule-libvirt.md#host-packages-of-the-ci-runner)).

- **Pinned files, not a resolver run.** `tools/molecule/libvirt-host.pins` names the snapshot, the required versions
  and every `.deb` that the runner lacks for them, each with its pool path, SHA-256 and size from the snapshot's
  signed index. The snapshot pin stays: the files are downloaded from its pool.
- **Verify, then cache, then install.** CI restores the files with `actions/cache/restore` under a key of the pins
  file, `tools/molecule/libvirt-host-packages.sh fetch` checks each one and downloads only what is missing or wrong,
  `actions/cache/save` stores them on a miss, and `install` checks them again and installs them with `apt-get`
  configured with no package source, so that `apt` can neither download nor install a file that was not verified. A
  corrupt or stale cache entry therefore costs only a download. A crafted one is not stopped by these checks, because
  `actions/cache` restores with `tar -P` and can rewrite the checker before it runs; the boundary is write access to
  the cache scope (amended by FREES-182, T-MOLECULE-1 and T-LIBVIRT-1 in the
  [threat model](../security/threat-model.md)). As for the cloud images, a pull request from a fork neither restores
  nor saves it.
- **Timings from the job log.** A timing callback such as `ansible.posix.profile_tasks` is code that Ansible loads,
  and the repository rules refuse `callbacks_enabled` and `ANSIBLE_CALLBACKS_ENABLED` (ADR 0004). The per-task times
  come instead from the timestamps that GitHub Actions puts on every log line: `make molecule-task-timings` reads a
  job log and prints the slowest tasks, so the runs need no change.

## Amendment 2026-10-30: instance images and collections prepared once per run (FREES-182, FREES-184)

Every Docker leg built both instance images in `create`, and every Molecule leg and `lint` installed the collections
from Galaxy, about 35 times per run. Two flakes took pull requests out of the merge queue, whose check timeout is 30
minutes: building the Rocky Linux image took 532 to 540 seconds on a slow package mirror instead of about 24, and
Galaxy answered HTTP 500, cut downloads short, failed TLS or left its cache incomplete. These refinements apply
([Molecule guide](../molecule.md#images-and-collections-built-once-per-run)).

- **One job per input.** `molecule-images` builds the instance images and `molecule-collections` fetches the
  collections, each once per run, with `contents: read` only. The Docker legs need both, the libvirt legs and `lint`
  need `molecule-collections`, and `ci-gate` needs both. The jobs run before the legs start, so they add no
  concurrent jobs at the peak of a run.
- **Images: verify, never rebuild in a leg.** `make molecule-images-build` restores each image's archive from an
  `actions/cache` entry keyed by its tag, which already hashes every build input, and reuses it only when the image
  carries the label `org.freesecdev.molecule.inputs=<tag>` on exactly the layers of the pinned base, which it pulls by
  digest. Otherwise it builds, with each pull and build attempt bounded by `timeout` and retried up to three times.
  The job passes the image IDs as an output and the archives as a run artifact. A leg loads the archive and refuses an
  image whose ID is not the recorded one; it never pulls or builds, because `MOLECULE_OFFLINE` is `true` in GitHub
  Actions. `create.yml` builds nothing: it requires the record of verified images with its own tag and the recorded
  ID. The tag scheme is unchanged. Images are never pushed, and they keep the digest-pinned bases.
- **Collections: pinned by SHA-256, installed offline.** Galaxy publishes no signatures for the pinned collections.
  `extensions/molecule/collections.pins` records the SHA-256 and size of each artifact, including the dependency
  `community.library_inventory_filtering_v1`, which `requirements.yml` now pins as well. `make
  molecule-collections-fetch` downloads only what a cached file does not match, with bounded `curl` retries, and every
  install checks every file again and runs `ansible-galaxy collection install --offline` on verified copies, with an
  unresolvable Galaxy server. No step after the fetch contacts Galaxy.
- **Trust in caches.** As for the libvirt host packages, a pull request from a fork neither restores nor saves these
  caches. Every collection file is checked against its pin, and a restored image against its inputs label and the
  pinned base layers. These checks catch a corrupt or stale entry. They are no boundary against whoever can write an
  entry in a restored scope: `actions/cache` restores with `tar -xf … -P`, so a crafted entry can rewrite any file
  the runner user can write, the checking scripts included, before they run. The boundary is write access to the
  `main` cache scope, which any code running in a workflow run on `main` has (T-MOLECULE-1 in the
  [threat model](../security/threat-model.md)). The image cache, unlike the others, has no content pin, because
  builds are not reproducible. It stays, because a hit keeps a slow mirror out of the run, under two limits: its key
  carries the ISO week of the run (`make -s molecule-images-plan` prints `week=<YYYY-Www>`), so a planted entry is
  restored at most until the week ends and every image is rebuilt at least once a week; and a scheduled run never
  saves an entry (`actions/cache/save` runs only on a miss and not on `schedule`). The job always re-saves the verified
  image with `docker save`, so the legs never receive the cache's bytes, and both the job and the legs refuse an
  archive that loads any image other than the target. Within a run the artifact's digest is checked by
  `actions/download-artifact` and the image ID by the leg.
- **Copies of the collections.** `install` verifies the copies in a `mktemp -d` directory with mode `0700` that the
  invoking user owns, and `ansible-galaxy` runs as that user into a path it owns. A process of the same user could
  swap a copy after its check, but it could as well edit the installed collection afterwards; no privilege boundary is
  crossed, and the copy still protects against a change through the downloaded file's path.
- **Dependencies are matched by name.** `make molecule-collections-lock` refuses a dependency that
  `requirements.yml` does not pin, but compares names only, not the dependency's version range. A pinned version
  outside the range passes the lock and then fails the `--offline` install, so it fails closed, only later.
- **Shell scripts, not Ansible.** The image and collection steps are `tools/molecule/instance-images.sh` and
  `tools/molecule/galaxy-collections.sh`, called by `make`, for the same reason as the cloud image fetch: tools and
  plugins stay free of `subprocess` outside the audited process helper, and playbooks use no `shell` or `command`.
  The tag computation, which needs YAML, is the pure Python `tools/molecule/instance_images.py`.

- **Measured.** Before, on runs 41112773853 and 41113885988, the Docker legs spent a median of 27 to 29 seconds
  building images and up to 472 when the mirror was slow, and every Molecule job and `lint` spent a median of 17 to 18
  seconds installing collections from Galaxy. After, on both attempts of run 41128905509, no leg built an image or
  contacted Galaxy: loading and verifying an image took a median of 7 to 9 seconds, the offline install 4 seconds,
  `molecule-images` 56 seconds when it built both images and 32 on cache hits, and `molecule-collections` 7 to 11
  seconds. The tables are in the [Molecule guide](../molecule.md#durations).
