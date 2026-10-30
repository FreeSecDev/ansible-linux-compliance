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
only what a container cannot prove: the cycles of the toggle lifecycle that declare `requires: [libvirt]`
([driver requirements](#driver-requirements-of-a-topic)), the move of the reference rule from `fail` to `pass` in a real
scan, one idempotence pass and the guard on a real machine. Everything a container can prove stays in the Docker
scenarios, so the libvirt legs stay short as native topics are added. As for Docker, each platform has a base scenario
and a lifecycle scenario, and CI runs the lifecycle as one leg per topic and toggle mode
([CI](#ci)).

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
make test-molecule-libvirt MOLECULE_LIBVIRT_SCENARIOS=libvirt-ubuntu-lifecycle MOLECULE_LIBVIRT_PLATFORMS=ubuntu \
  MOLECULE_LIBVIRT_SELFTEST=false MOLECULE_LIFECYCLE_TOPIC=file_permissions MOLECULE_LIFECYCLE_MODE=rule
make -s molecule-matrix MOLECULE_MATRIX_DRIVER=libvirt
make test-molecule-libvirt-selftest
make molecule-libvirt-images
```

`test-molecule-libvirt` installs the pinned collections (`make molecule-dependencies`), fetches the datastreams
(`make molecule-content`), fetches and verifies the cloud images and packages (`make molecule-libvirt-images`), checks
that KVM and `qemu:///system` are usable (`make molecule-libvirt-preflight`), runs `molecule test -s <scenario>` for each
scenario and stops at the first failure, and then runs the self-test. `molecule test` runs `destroy` after a failed
step too.

`MOLECULE_LIFECYCLE_TOPIC` and `MOLECULE_LIFECYCLE_MODE` select one native topic and one toggle mode of the
lifecycle, as for Docker ([Molecule guide](molecule.md)); left empty, the lifecycle scenario runs every topic in both
modes. A selected topic that runs no cycle with the libvirt driver on the platform fails the run, because the leg
would prove nothing. Run one scenario at a time on a host: two Molecule runs in the same checkout share `ANSIBLE_HOME`
and collide when they install the collection. The [measured durations](#durations) are below.

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
| `libvirt-ubuntu`, `libvirt-ubuntu-lifecycle` | Ubuntu 24.04 LTS server cloud image, release 20260926 | `ubuntu2404`, `cis_level1_server` |
| `libvirt-rhel-compatible`, `libvirt-rhel-compatible-lifecycle` | Rocky Linux 9.8 GenericCloud Base, 20260525.0 | `rhel9`, `cis_server_l1` |

The base scenarios run `create`, `prepare`, `converge`, `idempotence`, `verify` and `destroy`; the lifecycle scenarios
run `create`, `prepare`, `side_effect` and `destroy`. Apart from these steps and their names, the four configurations
are identical but for the platform, which a unit test checks.

| Step | Playbook | What it proves on the machine |
|---|---|---|
| `create`, `destroy` | `create_libvirt.yml`, `destroy_libvirt.yml` | below |
| `prepare` | `prepare.yml` (shared) | the guard, the pinned scanner, the quieted schedulers, the datastream |
| `converge` (base) | `converge_libvirt.yml` | a real scan, remediation of the reference rule and a second scan; the outcome moves from `molecule_libvirt_reference_outcomes[platform].before` to `.after` (`fail` to `pass` on Ubuntu) |
| `idempotence` (base) | `converge_libvirt.yml` again | the second remediation finds the rule compliant and nothing changes |
| `verify` (base) | `verify_libvirt.yml` | the cleanup restores `0644` and empties the ledger |
| `side_effect` (lifecycle) | `lifecycle.yml` (shared) | the warm-up scan and the cycles of the selected topic and mode that require libvirt, plus the two whole-instance self-check cases whose outcome depends on the driver (a system log's contents and mode); the other self-check cases test controller-side logic and run in Docker only |

The no-change snapshots around the run without the opt-in, the check-mode runs, the invalid inputs, the simulated guard
cases and every cycle that does not require libvirt are container-capable and run in the Docker scenarios only. The
platform keys are those of the Docker scenarios (`ubuntu`, `rhel_compatible` in `shared/vars/versions.yml`), so a topic
declaration that names a platform applies to both drivers. A platform takes `memory_mib` (1024 to 4096, default 2048;
the scenarios use 4096, so that `/usr` stays in the page cache between the snapshots), `vcpus` (1 to 4, default 2) and
`disk_gib` (8 to 16, default 12); any other key is refused.

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
4. Defines the domain (q35, BIOS, host CPU, the disk and the seed as files of the pool directory, one virtio interface on the run's
   network, a serial console on a pseudo terminal, a VGA adapter without any graphical console, a virtio random number
   generator) and boots it, then waits up to 15 minutes for SSH. The Rocky image does not boot without a video
   adapter; a VGA adapter has no channel to the host. The disks are `type='file'` with their path in the pool
   directory, not `type='volume'`, because the AppArmor helper of libvirt on Ubuntu (`virt-aa-helper`) does not
   resolve pool volumes, so QEMU is denied a volume disk on a host with AppArmor, such as the GitHub runners.
5. If any step fails, removes everything of the run and fails.

A repeated `create` reuses the run id and marker of the instance config, as for Docker. When every domain, the network
and the pool of that run exist with its labels, it creates nothing and only waits for SSH again; when only some of
them exist, it refuses to continue and asks for `molecule destroy`.

`destroy_libvirt.yml` lists the domains, networks and pools whose names match this scenario's pattern, reads each
definition, and removes only those whose labels belong to a run that the instance config records, or, when the config
is empty or missing, to any run of this scenario. It powers off and undefines the domains, stops and undefines the
networks, deletes every volume of each pool, deletes and undefines the pool, removes the run's keys and resets the
instance config. An object whose name does not match is never read, and one whose labels do not match is never
touched. Domains are undefined without libvirt's `delete_volumes` flag, so undefining a domain never deletes a disk
that another domain may name; only the deletion of the run's own pool removes files.

A libvirt storage pool has no metadata element, so a pool cannot carry the labels. A pool belongs to a run only when
both its name and its directory are the run's: the name `fsd-mol-<scenario>-<run id>` and exactly the directory
`/var/lib/libvirt/freesecdev-molecule/<that name>`. A pool named like the scenario anywhere else is never touched;
the self-test defines one.

The keys are deleted only from `$MOLECULE_EPHEMERAL_DIRECTORY/libvirt`, and only when `MOLECULE_EPHEMERAL_DIRECTORY` is
an absolute path without `.` or `..` components whose last component ends with the scenario name (Molecule's own
`molecule.<key>.<scenario>`; the self-test uses `build/molecule-libvirt-selftest/ephemeral/libvirt-selftest`), and both
it and `libvirt` are real directories, not symbolic links, with the same owner.

The fallback with an empty or missing instance config removes every labelled run of the scenario. Two concurrent runs
of the same scenario on one host (two checkouts, for example) would therefore remove each other's objects if one of
them lost its instance config; run one scenario at a time per host, as above.

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
- The scenarios add no libvirt `nwfilter` that would limit the machine to SSH from the host. `community.libvirt` has
  no module for network filters, and defining one would need `virsh` through a command module, which the collection's
  rules forbid. The isolated network already confines the machine to the host's address on the bridge; a filter
  remains a possible hardening for services that the host exposes on every address.

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
   `ansible_sftp_*`, `ansible_password`, `ansible_host_key_checking`, `ansible_control_path`,
   `ansible_control_path_dir`, `ansible_become_*` or Docker variable is set.
2. From the controller, through `community.libvirt` with the literal URI `qemu:///system`, an allow-list of the
   domain: every element must be one that `create_libvirt.yml` defines or libvirt adds to a running domain (the
   controllers, `memballoon`, mouse and keyboard `input` without a source, `watchdog`, `panic`, aliases and addresses),
   and only the `fsd` namespace may appear. That refuses, among others, `hostdev`, `filesystem`, `shmem`, `channel`,
   `graphics`, `redirdev`, `tpm`, `<os><kernel>`, `<initrd>`, `<cmdline>`, `<loader>`, `<nvram>`, `memoryBacking`,
   QEMU command-line arguments and a serial log file. Within the allowed elements: the run's labels and marker; every
   `<source>` is one of the two files of the run's pool directory (the disk and the seed), the run's network or a
   pseudo terminal; exactly two `file` disks without a backing file and with the plain QEMU driver; exactly one
   interface, of type `network` on the run's network with the recorded MAC address; a plain memory size; exactly one
   emulator, `/usr/bin/qemu-system-x86_64` or `/usr/libexec/qemu-kvm`; a serial port and console on a pseudo terminal;
   audio of type `none`; exactly one random number generator, on `/dev/urandom`; the resource partition `/machine`;
   exactly one `<sysinfo type='smbios'>` with only the manufacturer, product and serial entries, `<smbios
   mode='sysinfo'/>`, no `file` attribute outside a disk source, and a watchdog only with the action `reset`,
   `poweroff` or `none`, the lifecycle actions `destroy` on power off, `restart` on reboot and `destroy` or `restart`
   on a crash (never `coredump-*`, which makes libvirt write guest memory to the host), and an interface target
   `vnet<N>` without `managed`;
   and at least one security label, each `type='dynamic'` with `relabel='yes'`, with labels that are neither root nor
   unconfined (a DAC label of a non-zero user and group, `libvirt-<uuid>` or an `svirt` context). On a host with
   AppArmor (`/sys/module/apparmor/parameters/enabled` is `Y`, as on the GitHub runners), a dynamic AppArmor label is
   required. The network may hold only its name, UUID, labels, the bridge (name, `stp` and `delay` only, no `zone`), MAC
   address, DNS switched off and one IPv4
   address, without `<forward>`, DHCP, a route or `ipv6='yes'`; the pool only the elements of a directory pool at
   the run's directory, with mode `0711` and owned by the user that owns the run's key. The effective Ansible configuration has host key checking on, the default `ssh_args`, no extra SSH, SCP
   or SFTP arguments, the `ssh` executable, the default control path directory and either no control path or
   Molecule's `%(directory)s/%%h-%%p-%%r`, so no setting can point the connection at another master socket.
3. Over the real connection: `/sys/class/dmi/id/product_serial` is the marker, `product_uuid` is the UUID of the
   inspected domain, and the boot id and the machine id differ from the controller's, so the connection reaches the
   recorded virtual machine and not the controller itself. The lifecycle repeats this check after every remediate run.

The checks of the second group read libvirt's canonical XML with regular expressions, because `ansible.builtin` has
no XML parser and the scenarios add no collection for it; the simulations below pin them.

### Simulated bypass attempts

`verify` of every scenario, Docker and libvirt, feeds 124 simulated libvirt cases (`shared/vars/guard_cases_libvirt.yml`)
to the same task files. The simulated domain is the definition of a running scenario domain as libvirt prints it.
Accepted: that domain, without a video adapter, with a dynamic AppArmor label on an AppArmor host, with a dynamic
SELinux label, with the RHEL family's emulator, with a watchdog that powers off, with a restart after a crash, with a bridge that has only its name and with Molecule's control path. Refused: localhost, loopback, another
address, a Docker connection, a proxy command, switched-off host key checking in the arguments, a variable or the
configuration, extra arguments, another executable, port, user, key, a password, another become method, a control
path or control path directory from a variable or the configuration; a domain of another scenario or run, without
labels, with another marker or name, a second, bridged, direct or user-mode interface, another network or MAC address,
a shared host directory, a passed-through device, shared memory, a host socket channel, a graphical console, a TCP
serial port, QEMU arguments, an element of another namespace, a disk from a host file, another run's directory, a pool
volume or a host block device; security labels of type `none`, a static DAC label of root, a dynamic label of root by
number or name, labels without relabelling, no security label, a static or dynamic unconfined AppArmor profile, an
AppArmor host without an AppArmor label and a disk label that switches relabelling off; NVDIMM memory backed by
`/etc/shadow`, memory backed by a shared file, direct kernel boot with `init=/bin/sh`, a firmware loader and variables
from host files, a backing file `/etc/shadow`, another disk driver, an `evdev` input device from `/dev/input/event0`, a
random number generator on a TCP service (`127.0.0.1:2375`) or on `/dev/random` and a second one, another emulator,
host audio, a serial log file, a redirected device, a host TPM, another resource partition, an fw_cfg `sysinfo`
with an entry from `/etc/shadow` or an inline value, an SMBIOS entry from a host file or an additional one, the
host's SMBIOS data, a watchdog that dumps guest memory on the host, a crash action `coredump-destroy` or
`coredump-restart`, another power-off or reboot action, a lock failure action and an interface target with
`managed='no'` or on a host device; a network with NAT,
bridging, DHCP, DNS, a route, another bridge or address, a bridge in a firewalld zone or with another attribute, an address or network element with
another attribute, a second address family, `ipv6='yes'`, a port group, an
unknown element or
another run's labels; a pool outside the run's directory, on a block device, with a host device as its source, of
another name, with mode `0777`, owned by another user or without permissions; and a connection whose boot id or machine id is the controller's or whose SMBIOS serial or UUID differs.
Each refusal must start with "Refusing to run".

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
   scenario's labels, a labelled orphan of an unrecorded run, a domain named outside the prefix, an unlabelled
   network named like this scenario and a pool named like this scenario whose directory is outside
   `/var/lib/libvirt/freesecdev-molecule`.
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
that act on their own schedule (`snapd`, `unattended-upgrades`, `packagekit`, and the cron daemon `cron` or `crond` with
`anacron`, where present). A scheduled job, for
example an `apt` index update, `logrotate`, `man-db` or anacron updating `/var/spool/anacron` from `cron.hourly`, would
otherwise change files that the toggle lifecycle compares in the middle of a test. In CI, anacron once changed the
times of its timestamp files between two cycles. A future topic that manages one of these services (the cron topic, for
example) must revisit this list. Then `prepare` copies the datastream as for Docker.

## Differences that only a virtual machine has

A running system writes to some files continuously. For a libvirt target the no-change snapshot and the whole-instance
comparison of the lifecycle ignore the size, times, content and inode of these files (a service may replace one by
renaming a new copy over it), but not their existence, type, mode or owner
(`contract_snapshot_volatile_contents_by_driver` in `shared/vars/contract.yml`):

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
    audit: false
    requires:
      - libvirt
    files:
      - path: /etc/crontab
        owner: daemon
        group: adm
```

The drivers are the prefixes of the scenario directories, `docker` and `libvirt`. Each cycle runs with one set of
drivers: a pre-state runs with the drivers it `requires`, else with those its topic `requires`, else in the Docker
scenarios only. A topic with `requires: [libvirt]` therefore runs every cycle in the libvirt scenarios, and a topic
without `requires` runs its plain pre-states in Docker and only its libvirt pre-states in the virtual machines. The
harness skips the topic, including its whole-instance records, on a driver that runs none of its cycles.
`make lint-lifecycle` refuses an unknown or repeated driver, a pre-state that requires a driver that its topic does
not, and a declaration with a cycle whose driver has no lifecycle scenario (one whose `side_effect` is the harness) on
every platform that the topic does not list under `unselected_platforms`, so every declared cycle is exercised by some
driver. `make molecule-matrix` plans the CI legs from the same map, so every such cycle also runs in a leg that gates
merges.

The `file_permissions` declaration has the pre-state above. It changes the owner and group of `/etc/crontab`, which a
container without `CAP_CHOWN` cannot do, and proves that the remediation sets only the mode, that cleanup restores the
recorded mode without touching the ownership, and that the harness gives the file back its original owner and group.
The Docker scenarios run its other four cycles (topic and rule toggle from the as-built state and a customised mode),
each libvirt lifecycle scenario the two ownership cycles, one per CI leg (`file_permissions` with `topic` and with
`rule`). The ownership pre-state runs no scan: no assertion
about it needs one, and the real scans of `converge` already show the outcome on the machine.

Running every cycle on the virtual machines as well would repeat what the Docker scenarios prove: the mode change, its
cleanup and the whole-instance comparison do not depend on the kernel, so the extra hour per platform would add no
evidence. A cycle that does depend on the machine declares `requires: [libvirt]` and runs there.

## CI

The `molecule-libvirt` job of `.github/workflows/ci.yml` runs on the GitHub-hosted `ubuntu-24.04` runners and is part
of `ci-gate`, which the merge queue requires within its 30-minute check timeout. Its matrix comes from the
`molecule-plan` job, which runs `make -s molecule-matrix MOLECULE_MATRIX_DRIVER=libvirt`
(`tools/roles/molecule_matrix.py`) and is part of `ci-gate` too. The plan holds, per platform, the base leg
(`libvirt-<platform>`), one lifecycle leg (`libvirt-<platform>-lifecycle` with `MOLECULE_LIFECYCLE_TOPIC` and
`MOLECULE_LIFECYCLE_MODE`) per native topic with a cycle that requires libvirt on that platform and per toggle mode,
and the `libvirt-selftest` leg. A new topic or pre-state that requires libvirt therefore gets its legs without a change
to the workflow, and each leg holds one machine, one topic and one mode. Each leg:

1. fails with an error annotation when `/dev/kvm` is missing, and prints it otherwise;
2. installs the udev rule that GitHub documents for hosted runners
   (`KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"`) and waits for udev;
3. installs exact versions of `qemu-system-x86`, `qemu-utils`, `libvirt-daemon-system`, `libvirt-dev` and
   `pkg-config` from a fixed Ubuntu archive snapshot (`apt-get --snapshot`), checks the installed versions and adds the
   runner user to the `libvirt` group;
4. restores `build/molecule-libvirt/cache`, which holds the cloud image and the pinned packages of the platform, keyed
   by the platform and the SHA-256 of the pins file (so every pinned digest), except in a pull request from a fork, as
   for the SCC download; the fetch script checks the SHA-256 of every restored file again and downloads only what is
   missing or wrong;
5. runs the make target under `sg libvirt`, because the group membership is new, and prints the libvirt objects
   afterwards. The job's timeout is about one and a half times the slowest observed leg.

If a hosted runner does not expose `/dev/kvm`, the job fails at its first step and says so; it does not fall back to
emulation, and `ci-gate` fails with it. The fallback is a self-hosted or larger runner with KVM, or a developer host
with KVM that runs `make test-molecule-libvirt` and records the result on the Jira issue; the scenarios must not be
reported as passing otherwise.

### Durations

Job durations on GitHub's `ubuntu-24.04` runners, in minutes. The first version ran `create` to `destroy` with every
lifecycle cycle on the machine in one leg per platform.

| Leg | First version | Run 41007894604 | Run 41011440146 |
|---|---|---|---|
| `libvirt-ubuntu` | 65 (everything) | failed in `converge`, fixed in a8f8050 | 10.3 |
| `libvirt-ubuntu-lifecycle`, `file_permissions`, `topic` | (included above) | 18.8 | 16.0 |
| `libvirt-ubuntu-lifecycle`, `file_permissions`, `rule` | (included above) | 12.5 | 18.3 |
| `libvirt-rhel-compatible` | 34 (everything) | failed in `converge`, fixed in a8f8050 | 6.0 |
| `libvirt-rhel-compatible-lifecycle`, `file_permissions`, `topic` | (included above) | 6.9 | 12.2 |
| `libvirt-rhel-compatible-lifecycle`, `file_permissions`, `rule` | (included above) | 6.9 | 8.7 |
| `libvirt-selftest` | 4 | 5.5 | 7.9 |

Each leg spends about a minute installing QEMU and libvirt and seconds restoring the cache; `create` and `prepare`
take about 1.5 minutes. The rest of a lifecycle leg is one cycle: seven no-change snapshots and four whole-instance
records of the machine, each a `find` with a SHA-256 of every file below `/etc`, `/usr` and the other watched paths,
plus the warm-up scan. The same steps took up to 1.7 times as long on a slow runner as on a fast one, which explains
the spread between legs that do the same work. The job's `timeout-minutes` is 28, about one and a half times the
slowest observed leg, and stays within the merge queue's 30 minutes.

## Troubleshooting

- `molecule-libvirt-preflight` fails: check `ls -l /dev/kvm` and `virsh -c qemu:///system list`.
- A boot times out: `virsh -c qemu:///system console <domain>` shows the serial console while the domain runs; with the
  VGA adapter, `virsh -c qemu:///system screenshot <domain> <file>` captures the screen.
- A run was interrupted: `molecule destroy -s <scenario>` removes
  every labelled object of the scenario when the instance config is gone. Objects without the labels are never
  removed automatically; remove them with `virsh` by their exact names.
