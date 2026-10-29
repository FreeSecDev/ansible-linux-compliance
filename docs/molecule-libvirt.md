# Molecule libvirt scenarios

Scope: the libvirt Molecule scenarios under `extensions/molecule/`, which boot real virtual machines with KVM, how to run
them, what they prove and how they keep the developer host and every unrelated virtual machine out of reach.
Audience: contributors adding or changing roles, modules, topics and scenarios.
Decision record: [ADR 0009](adr/0009-molecule-layout-and-drivers.md#amendment-2026-10-30-libvirt-scenarios-frees-61).
Jira: FREES-61. The Docker scenarios, the shared playbooks and the toggle lifecycle harness are described in the
[Molecule guide](molecule.md).

The Docker containers drop every capability and share the host kernel, so controls that need a real kernel, init
system, boot loader or root with full capabilities cannot be proven there: kernel parameters, kernel modules,
services, mounts, the boot loader, auditd and even a change of file ownership (`CAP_CHOWN`). The libvirt scenarios run
the same playbooks against a full virtual machine. A topic whose controls need one declares
`requires: [libvirt]` (see [driver requirements](#driver-requirements-of-a-topic)).

## Run the scenarios

Prerequisites:

- KVM: `/dev/kvm` must exist. The scenarios refuse to run without it rather than fall back to software emulation.
- libvirt with `qemu:///system`, reachable by your user (on Ubuntu, membership of the `libvirt` group). The scenarios
  never use `qemu:///session` (see [isolation](#isolation)).
- `libvirt-dev`, `pkg-config` and a C compiler, because the `libvirt` dependency group of `pyproject.toml` builds
  `libvirt-python` from source. Only the libvirt targets install that group (`uv run --group libvirt`).
- `curl`, `gpg`, `gpgv` and `sha256sum` for the image download.

```text
make test-molecule-libvirt
make test-molecule-libvirt MOLECULE_LIBVIRT_SCENARIOS=libvirt-ubuntu MOLECULE_LIBVIRT_PLATFORMS=ubuntu \
  MOLECULE_LIBVIRT_SELFTEST=false
make test-molecule-libvirt-selftest
make molecule-libvirt-images
```

`test-molecule-libvirt` installs the pinned collections (`make molecule-dependencies`), fetches the datastreams
(`make molecule-content`), fetches and verifies the cloud images and packages (`make molecule-libvirt-images`), checks
that KVM and `qemu:///system` are usable (`make molecule-libvirt-preflight`), runs `molecule test -s <scenario>` for each
scenario and stops at the first failure, and then runs the self-test. `molecule test` runs `destroy` after a failed
step too.

Record the libvirt objects of your host before and after a local run and compare them:

```text
virsh -c qemu:///system list --all
virsh -c qemu:///system net-list --all
virsh -c qemu:///system pool-list --all
```

A run leaves nothing behind except the empty, root-owned parent directory `/var/lib/libvirt/freesecdev-molecule`, which
libvirt creates when it builds the first pool and does not remove when it deletes a pool.

## Scenarios

| Scenario | Cloud image | Datastream and profile |
|---|---|---|
| `libvirt-ubuntu` | Ubuntu 24.04 LTS server cloud image, release 20260926 | `ubuntu2404`, `cis_level1_server` |
| `libvirt-rhel-compatible` | Rocky Linux 9.8 GenericCloud Base, 20260525.0 | `rhel9`, `cis_server_l1` |

Each scenario runs `create`, `prepare`, `converge`, `idempotence`, `verify`, `side_effect` (the
[toggle lifecycle](molecule.md#toggle-lifecycle-of-every-native-topic)) and `destroy`, the same playbooks as the Docker
scenarios except `create_libvirt.yml` and `destroy_libvirt.yml`. The platform keys are those of the Docker scenarios
(`ubuntu`, `rhel_compatible` in `shared/vars/versions.yml`), so a topic declaration that names a platform applies to
both drivers. A platform takes `memory_mib` (1024 to 4096, default 2048), `vcpus` (1 to 4, default 2) and `disk_gib` (8
to 16, default 12); any other key is refused.

As for Docker, Rocky Linux stands in for RHEL and the RHEL 9 datastream reports every rule `notapplicable` there
([ADR 0010](adr/0010-initial-os-and-benchmark-scope.md)). On Ubuntu the virtual machine is a `machine` platform, so
ComplianceAsCode evaluates rules that it skips in a container: the reference rule `file_permissions_crontab` goes from
`fail` before remediation to `pass` after it, which the container scenarios could not show.

## Images and packages

`extensions/molecule/shared/images/cloud-images.pins` is the single record of what a virtual machine boots and installs.
Each line is one of:

| Line | Fields |
|---|---|
| `image <platform> <file> <url> <sha256> <size>` | The cloud image |
| `listing <platform> <checksum url> <signature url> <key> <fingerprint>` | The vendor's checksum file, its detached signature, the vendor key below `images/keys/` and the key's fingerprint |
| `package <platform> <url> <sha256> <size>` | A package that the image lacks, in installation order |

| Platform | Image SHA-256 | Signed by |
|---|---|---|
| `ubuntu` | `6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2` | UEC Image Automatic Signing Key, fingerprint `D2EB 4462 6FDD C30B 513D 5BB7 1A5D 6C4C 7DB8 7C81`, on `SHA256SUMS.gpg` |
| `rhel_compatible` | `92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8` | Rocky Enterprise Software Foundation release key 2022, fingerprint `21CB 256A E16F C54C 6E65 2949 702D 426D 350D 275D`, on `CHECKSUM.asc` |

`tools/molecule/fetch-cloud-images.sh` (`make molecule-libvirt-images`) accepts only HTTPS URLs of
`cloud-images.ubuntu.com`, `archive.ubuntu.com` and `dl.rockylinux.org`. For every image it downloads the checksum file
and its signature, refuses a key file that does not hold exactly the pinned fingerprint, verifies the signature with
`gpgv` against that key alone and requires that the signed file lists the pinned SHA-256 for the image's file name. It
stores each image as `build/molecule-libvirt/cache/images/<sha256>.qcow2` and each package below
`build/molecule-libvirt/cache/packages/<platform>/`, each only after its SHA-256 matched, and reuses a cached file only
after checking it again. `create_libvirt.yml` checks the SHA-256 of the cached image once more before it copies it,
and `prepare` checks every package on the controller before copying it into the virtual machine.

The packages are those that `openscap-scanner` needs and the image lacks, determined against the image's own package
list: on Ubuntu seven packages of the `noble` release pocket (`openscap-scanner` 1.3.9+dfsg-1.1ubuntu2, the version
that `oscap-integration` pins, with its libraries), whose digests come from the signed archive index; on Rocky five
packages of Rocky 9.8 AppStream (`openscap-scanner` and `openscap` 1.3.14-1.el9_8.rocky.0.1, `xmlsec1`,
`xmlsec1-openssl`, `libxslt`). On Rocky, `prepare` also imports the image's own vendor key
`/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9` with `ansible.builtin.rpm_key` and the pinned fingerprint, so that `dnf` checks
the signature of every package as well. Nothing is installed from a network mirror: the virtual machine has none.

To update a pin, take a vendor release at least seven days old, verify its checksum file with the vendor key, update
the image line, then boot it and determine the missing packages again. When Rocky Linux moves 9.8 to its vault, the
package URLs stop working and must be updated by hand, as for the Docker images. Renovate does not read the pins file
yet (FREES-81).

## What a run creates

Every name carries the scenario and the run id that `create` generates once and records in the instance config:

| Object | Name |
|---|---|
| Domain | `fsd-mol-<scenario>-<run id>-<platform>` |
| Network | `fsd-mol-<scenario>-<run id>`, bridge `fsdm<run id>` |
| Storage pool | `fsd-mol-<scenario>-<run id>`, directory `/var/lib/libvirt/freesecdev-molecule/<pool>`, owned by your user |
| Keys and known hosts | `$MOLECULE_EPHEMERAL_DIRECTORY/libvirt/` (mode `0700`) |

The domain and the network carry the run's labels as libvirt metadata (namespace
`https://github.com/FreeSecDev/ansible-linux-compliance/molecule`, elements `scenario`, `run` and, on a domain,
`instance`). The domain also carries a random 32-character marker as its SMBIOS system serial, which the guard reads
back from inside the virtual machine.

`create_libvirt.yml`:

1. Validates the scenario name and the platforms, and checks the cached image against its pin.
2. Writes the instance config before any libvirt object exists, then generates an ephemeral Ed25519 client key and one
   Ed25519 host key per instance with `community.crypto.openssh_keypair`, and pins each host key in the run's
   `known_hosts`.
3. Defines and starts the network, defines, builds and starts the pool, copies the image into the pool, bounds the
   disk to its `disk_gib` and creates the cloud-init seed (`community.libvirt.virt_volume` `create_cidata_cdrom`). The
   seed authorises the client key for root only, installs the host key, sets no password, creates no other user, and
   gives the interface a static address.
4. Defines the domain (q35, BIOS, host CPU, the disk and the seed from the pool, one virtio interface on the run's
   network, a serial console on a pseudo terminal, a VGA adapter without any graphical console, a virtio random number
   generator) and boots it, then waits up to 15 minutes for SSH. The Rocky image does not boot without a video
   adapter; a VGA adapter has no channel to the host.
5. If any step fails, removes everything of the run and fails.

`destroy_libvirt.yml` lists the domains, networks and pools whose names match this scenario's pattern, reads each
definition, and removes only those whose labels (for a pool: its directory) belong to a run that the instance config
records, or, when the config is empty or missing, to any run of this scenario. It powers off and undefines the
domains, stops and undefines the networks, deletes every volume of each pool, deletes and undefines the pool, removes
the run's keys and resets the instance config. An object whose name does not match is never read, and one whose
labels do not match is never touched.

## Isolation

- The network has no `<forward>` element, no DHCP and no DNS (`<dns enable='no'/>`), so libvirt starts no dnsmasq for
  it and installs firewall rules that reject forwarding into and out of its bridge. The virtual machine can reach only
  its own subnet: the host's address on the bridge, and nothing beyond. It has no route to the host's LAN or the
  internet; packages therefore come from the pins, not from a mirror.
- The host's address on the bridge is reachable from the virtual machine, so a service that the host exposes on every
  address is reachable too. The subnet is `10.200.0.0/24` to `10.249.255.0/24`, derived from the run id; libvirt
  refuses to start a network whose subnet collides with an existing route, and `create` then removes the run.
- `qemu:///session` would need user-mode networking, which reaches the host's LAN and, with passt, the host's
  loopback addresses; the scenarios therefore use `qemu:///system` with a network of their own.
- SSH runs with `-F /dev/null`, the run's `known_hosts` and `StrictHostKeyChecking=yes`, so a connection succeeds only
  against the host key that `create` generated for this instance, whatever `~/.ssh/config` says.

## Guard

The guard of the [Molecule guide](molecule.md#localhost-guard) runs first in `prepare`, `converge`, `verify` and the
lifecycle. The driver is decided by the scenario name (`libvirt-` prefix), which comes from `MOLECULE_SCENARIO_NAME`,
and the record of the target must carry the same driver. The first task refuses, as for Docker, every `guard_*`,
`molecule_target*`, `molecule_docker_default_paths` and `molecule_libvirt_*` variable that exists before the guard
runs, and `inventory_hostname`, `ansible_host`, `ansible_connection` and `molecule_allowed_connections` given as extra
variables. Then, for a libvirt target:

1. From the inventory: the name and address match exactly one record of this scenario and driver; the address is an
   address of the scenario's subnet range and not a loopback form; the connection is `ssh`; `ansible_user` is `root`,
   `ansible_port` is 22, `ansible_private_key_file` is the run's key and `ansible_ssh_common_args` is exactly the
   options above with the run's `known_hosts`; no `ansible_ssh_*` other than the common arguments, `ansible_scp_*`,
   `ansible_sftp_*`, `ansible_password`, `ansible_host_key_checking`, `ansible_become_*` or Docker variable is set.
2. From the controller, through `community.libvirt` with the literal URI `qemu:///system`: the domain carries the run's
   labels and marker, has exactly two disks, both volumes of the run's pool (the disk and the seed), exactly one
   interface, of type `network` on the run's network with the recorded MAC address, and none of `hostdev`,
   `filesystem`, `shmem`, `redirdev`, `smartcard`, `channel`, `graphics`, `vsock`, `iommu`, `parallel`, `hub`,
   `lease`, `sound`, `tpm`, a serial port or console other than a pseudo terminal, or QEMU command-line arguments. The
   network carries the run's labels, has no `<forward>`, DHCP, route or second address, has DNS disabled and the
   recorded bridge and gateway. The pool is a directory pool at the run's directory. The effective Ansible
   configuration has host key checking on, the default `ssh_args`, no extra SSH, SCP or SFTP arguments and the `ssh`
   executable.
3. Over the real connection: `/sys/class/dmi/id/product_serial` is the marker, `product_uuid` is the UUID of the
   inspected domain, and the boot id and the machine id differ from the controller's, so the connection reaches the
   recorded virtual machine and not the controller itself. The lifecycle repeats this check after every remediate run.

The checks of the second group read libvirt's canonical XML with regular expressions, because `ansible.builtin` has
no XML parser and the scenarios add no collection for it; the simulations below pin them.

### Simulated bypass attempts

`verify` of every scenario, Docker and libvirt, feeds 59 simulated libvirt cases (`shared/vars/guard_cases_libvirt.yml`)
to the same task files: an accepted virtual machine, with and without a video adapter, and refusals for localhost,
loopback, another address, a Docker connection, a proxy command, switched-off host key checking in the arguments, a
variable or the configuration, extra arguments, another executable, port, user, key, a password, another become
method, a domain of another scenario or run, without labels, with another marker or name, a second, bridged, direct or
user-mode interface, another network or MAC address, a shared host directory, a passed-through device, shared memory,
a host socket channel, a graphical console, a TCP serial port, QEMU arguments, a disk from a host file, another pool or
a host block device, a network with NAT, bridging, DHCP, DNS, a route, another bridge or address, a second address
family or another run's labels, a pool outside the run's directory or on a block device, and a connection whose boot
id or machine id is the controller's or whose SMBIOS serial or UUID differs. Each refusal must start with "Refusing to
run".

### Self-test against real libvirt objects

`make test-molecule-libvirt-selftest` (`extensions/molecule/selftest/libvirt_*.yml`) runs the shared playbooks outside
Molecule as scenario `libvirt-selftest`, with its state in `build/molecule-libvirt-selftest/`:

1. `create_libvirt.yml` twice, then `libvirt_assert_created.yml`: one domain, network and pool, all of one run.
2. `libvirt_bypass.yml` defines, but never starts, three decoys of the same run with its labels, marker, disk and
   network, each with one device that the guard refuses (a shared host directory, a second interface bridged to the
   run's bridge, a host socket channel), records each in its own instance config and writes one inventory per
   bypass attempt and one extra-variable attempt per variable the libvirt guard relies on (every `guard_*` name in
   `guard.yml`, `tasks/guard.yml` and the `tasks/guard_libvirt_*.yml` files, plus the outside names). It fails when one
   has no attempt. `libvirt_strangers.yml` defines a domain named like this scenario without labels, one with another
   scenario's labels, a labelled orphan of an unrecorded run, a domain named outside the prefix and an unlabelled
   network named like this scenario.
3. The guard accepts the real probe over SSH and refuses every attempt with "Refusing to run": the decoys with "is not
   isolated", `ANSIBLE_HOST_KEY_CHECKING=False` likewise, and every extra variable as "supplied from outside".
4. `destroy_libvirt.yml` with the recorded run must remove the probe and the decoys and leave the orphan and every
   stranger (`libvirt_assert_destroyed.yml`). With an empty instance config it must remove the orphan too and still
   leave the strangers. `libvirt_cleanup.yml` then removes the strangers by their exact names and asserts that nothing
   of the self-test is left.

## Prepare

`prepare` runs the guard, then, for a libvirt target, waits for cloud-init to finish, installs the pinned packages
from the controller (one `ansible.builtin.apt` `deb` at a time on Ubuntu, `ansible.builtin.dnf` with every repository
disabled on Rocky), removes the package files, and stops and masks every systemd timer of the image and the services
that act on their own schedule (`snapd`, `unattended-upgrades`, `packagekit`, where present). A scheduled job, for
example an `apt` index update, `logrotate` or `man-db`, would otherwise change files that the toggle lifecycle compares
in the middle of a test. Then it copies the datastream as for Docker.

## Differences that only a virtual machine has

A running system writes to some files continuously. For a libvirt target the no-change snapshot and the whole-instance
comparison of the lifecycle ignore the size, times and content of these files, but not their existence, type, mode,
owner or inode (`contract_snapshot_volatile_contents_by_driver` in `shared/vars/contract.yml`):

| Path | Why |
|---|---|
| `/var/log/syslog`, `auth.log`, `kern.log`, `messages`, `secure`, `cron` | rsyslog writes every log line, including the SSH sessions of the test itself |
| `/var/log/wtmp`, `btmp`, `lastlog` | login accounting of the SSH sessions |
| `/var/log/audit/audit.log` | auditd records every session and privileged action on Rocky |
| `/var/log/journal/<machine id>/system.journal` | journald writes every log line |
| `/var/lib/systemd/timesync/clock` | systemd-timesyncd stores the time in the modification time of this empty file |
| `/var/lib/rsyslog` and `imjournal.state` | rsyslog saves its position in the journal |
| `/var/lib/NetworkManager` and `timestamps` | NetworkManager saves the time of the last activation of each connection |

A topic that manages one of these files cannot rely on the whole-instance comparison for it; its declaration must
then name the file and its expected state. Kernel counters, packages, users, groups and services need no addition: in
the measured runs no kernel parameter outside the Docker list changed.

## Driver requirements of a topic

A lifecycle declaration may name the drivers that its topic needs, and a pre-state may do the same:

```yaml
requires:
  - libvirt
pre_states:
  - name: customised ownership
    audit: true
    requires:
      - libvirt
    files:
      - path: /etc/crontab
        owner: daemon
        group: adm
```

The drivers are the prefixes of the scenario directories, `docker` and `libvirt`. A topic without `requires` runs in
every scenario. A topic with `requires` runs only in the scenarios of those drivers and is reported as skipped in the
others; a pre-state with `requires` likewise. `make lint-lifecycle` refuses an unknown or repeated driver, a pre-state
that requires a driver that its topic does not, and a declaration that requires a driver for which no scenario runs
every platform that the topic does not list under `unselected_platforms`, so a topic that requires libvirt must run in
a libvirt scenario on each of its platforms. A unit test checks that CI runs every scenario of each driver.

The `file_permissions` declaration has the pre-state above. It changes the owner and group of `/etc/crontab`, which a
container without `CAP_CHOWN` cannot do, and proves that the remediation sets only the mode, that cleanup restores the
recorded mode without touching the ownership, and that the harness gives the file back its original owner and group.
Each libvirt scenario therefore runs six cycles (topic and rule toggle from the as-built state, a customised mode and a
customised ownership), the Docker scenarios four.

## CI

The `molecule-libvirt` job of `.github/workflows/ci.yml` runs on the GitHub-hosted `ubuntu-24.04` runners, one matrix
entry per scenario plus `libvirt-selftest`, and is part of `ci-gate`. It:

1. fails with an error annotation when `/dev/kvm` is missing, and prints it otherwise;
2. installs the udev rule that GitHub documents for hosted runners
   (`KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"`) and reloads it;
3. installs exact versions of `qemu-system-x86`, `qemu-utils`, `libvirt-daemon-system`, `libvirt-dev` and
   `pkg-config` from a fixed Ubuntu archive snapshot (`apt-get --snapshot`), checks the installed versions and adds the
   runner user to the `libvirt` group;
4. restores `build/molecule-libvirt/cache` keyed by the platform and the SHA-256 of the pins file; the fetch script
   checks every restored file again;
5. runs the make target under `sg libvirt`, because the group membership is new, with a timeout of 240 minutes, and
   prints the libvirt objects afterwards.

If a hosted runner does not expose `/dev/kvm`, the job fails at its first step and says so; it does not fall back to
emulation, and `ci-gate` fails with it. The fallback is a self-hosted or larger runner with KVM, or a developer host
with KVM that runs `make test-molecule-libvirt` and records the result on the Jira issue; the scenarios must not be
reported as passing otherwise.

## Troubleshooting

- `molecule-libvirt-preflight` fails: check `ls -l /dev/kvm` and `virsh -c qemu:///system list`.
- A boot times out: `virsh -c qemu:///system console <domain>` shows the serial console while the domain runs; with the
  VGA adapter, `virsh -c qemu:///system screenshot <domain> <file>` captures the screen.
- A run was interrupted: `molecule destroy -s <scenario>` removes
  every labelled object of the scenario when the instance config is gone. Objects without the labels are never
  removed automatically; remove them with `virsh` by their exact names.
