# Molecule scenarios

Scope: the Docker Molecule scenarios under `extensions/molecule/`, how to run them and what they prove.
Audience: contributors adding or changing roles, modules and scenarios.
Decision record: [ADR 0009](adr/0009-molecule-layout-and-drivers.md). Jira: FREES-59, follow-up FREES-60.

Molecule is configured ansible-native: every scenario is a flat directory `extensions/molecule/<scenario>/` that holds
only a `molecule.yml`. There is no molecule-plugins driver. Every playbook lives in `extensions/molecule/shared/` and
`molecule.yml` names it directly, because the repository source rules refuse `import_playbook` targets with `..`.
The playbooks use only `community.docker`, `ansible.builtin` and this collection's modules and roles; none uses
`shell`, `command`, `raw` or `script` (AGENTS.md).

## Run the scenarios

Prerequisites: the Python environment from `make bootstrap`, and a running Docker daemon that your user can reach.

```text
make test-molecule-docker
make test-molecule-docker MOLECULE_DOCKER_SCENARIOS=docker-ubuntu MOLECULE_DOCKER_SELFTEST=false
make test-molecule-docker-selftest
```

`test-molecule-docker` installs the pinned collections from `extensions/molecule/requirements.yml` into
`build/collections` (`make molecule-dependencies`), fetches and verifies the pinned ComplianceAsCode datastreams into
`build/content` (`make molecule-content`, the same `tools/content/fetch_content.py` as `test-oscap-integration`), runs
`molecule test -s <scenario>` for each scenario and stops at the first failure, and then runs the self-test.

A local run of both scenarios takes about three to five minutes once the instance images are built; the first run
builds them. The images stay in the local Docker cache (`freesecdev-molecule/*`); remove them with `docker image rm`
when no longer needed.

CI runs the same targets as the `molecule-docker` job, one matrix entry per scenario plus `docker-selftest`, on
`ubuntu-24.04` GitHub-hosted runners. The job is part of `ci-gate`.

## Scenarios

| Scenario | Image | Datastream and profile |
|---|---|---|
| `docker-ubuntu` | Ubuntu 24.04 | `ubuntu2404`, `cis_level1_server` ([ADR 0010](adr/0010-initial-os-and-benchmark-scope.md)) |
| `docker-rhel-compatible` | Rocky Linux 9 | `rhel9`, `cis_server_l1` |

Each scenario runs `create`, `prepare`, `converge`, `idempotence`, `verify` and `destroy`. `destroy` runs even when an
earlier step failed. Molecule warns that the scenario has no `cleanup` playbook; there is nothing to clean up outside
the container, so that is expected.

Rocky Linux is a stand-in for RHEL. Per ADR 0010, RHEL ComplianceAsCode content is listed as "RHEL datastream,
unverified" on Rocky and AlmaLinux. The RHEL 9 datastream's platform checks do not recognise Rocky, so every rule of the
profile is `notapplicable` there. The scenario shows that the roles run on a RHEL-compatible userland; it makes no
benchmark claim about Rocky or AlmaLinux.

## Images and content pins

`extensions/molecule/shared/vars/versions.yml` is the only place that records image references, digests and the
datastream and profile of each image:

| Key | Reference | Digest |
|---|---|---|
| `ubuntu` | `docker.io/library/ubuntu:24.04` | `sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac` |
| `rhel_compatible` | `docker.io/rockylinux/rockylinux:9` | `sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f` |

Both digests are multi-architecture manifest list digests of images older than seven days. The Dockerfiles in
`extensions/molecule/shared/images/` take the pinned reference as the `BASE_IMAGE` build argument and install exact
package versions:

| Image | Packages |
|---|---|
| `ubuntu` | `python3=3.12.3-0ubuntu2.1`, `openscap-scanner=1.3.9+dfsg-1.1ubuntu2` (the version that `oscap-integration` pins), `cron=3.0pl1-184ubuntu2` |
| `rhel_compatible` | `openscap-scanner-1:1.3.14-1.el9_8.rocky.0.1`, `cronie-1.5.7-16.el9`; Python 3.9 comes with the base image |

`cron` and `cronie` provide `/etc/crontab` with mode `0644`, the starting point of the reference rule. When a
distribution archive drops a pinned version, the image build fails and the pin must be updated by hand; no Renovate
manager reads `versions.yml` or the Dockerfiles yet (FREES-81).

The image tag is `<first 12 hex digits of the base digest>-<first 12 hex digits of a SHA-256 over the base reference
and the Dockerfile>`. Every build input is in that hash (the Dockerfiles copy nothing from the build context), so a
changed Dockerfile or base image builds a new image even though `community.docker.docker_image` uses `state: present`.

The datastreams are the ones pinned in `content/manifest.yml`. `prepare` checks the SHA-256 of the fetched file on the
controller, then copies it into the instance as `/usr/share/freesecdev-molecule/content/<file>` (root-owned, directory
`0755`, file `0644`); the discover role verifies the SHA-256 again inside the instance.

## Isolation and cleanup

- Containers are unprivileged: `privileged: false`, `cap_drop: ALL`, `no-new-privileges`, no network
  (`network_mode: none`), a private cgroup namespace, a process and memory limit, and an init process. The scenarios
  run as root inside the container without `sudo`, so they pass `ansible_become=false`. Remote temporary files go to
  `/tmp`.
- `create.yml` refuses platforms that are privileged, use `network_mode` `host` or `container:*`, declare `volumes`,
  `mounts` or `devices`, or add capabilities without a `capabilities_reason`.
- The run id is generated once, as the first fact of `create.yml`, and persisted in the instance config. A repeated
  `create` reuses the recorded run id and marker, so it starts no second container. Container names are
  `fsd-mol-<scenario>-<run id>-<platform>`.
- Every container carries the labels `org.freesecdev.molecule.scenario` and `org.freesecdev.molecule.run`. The keys
  are built as a dictionary expression, because Ansible does not template mapping keys. After the start,
  `create.yml` inspects each container and asserts the name, both labels and the marker on it.
- Every container also gets a random 32-character marker in the environment variable `FREESECDEV_MOLECULE_MARKER`,
  recorded in the instance config. The guard reads it back over the real connection.
- `create.yml` writes the instance config before starting anything. If a later step of `create` fails, its rescue
  block removes the containers and fails the play.
- `destroy.yml` lists the containers that carry this scenario's label, inspects each one and removes it only when its
  name has the form `fsd-mol-<scenario>-<run id>-`, its scenario label matches and, if an instance config with
  entries exists, its run label is a recorded run. When the config is empty or missing it removes every container
  of the scenario, which would also remove a concurrent run of the same scenario from another checkout. It never
  removes a container without this scenario's label, is safe to repeat and resets the instance config.

## Localhost guard

`extensions/molecule/shared/guard.yml` runs first in `prepare`, `converge` and `verify`, before anything else runs on
a target, with `any_errors_fatal`. It targets `hosts: all`, so the implicit `localhost` is never part of it. A target
is accepted only when all of the following hold. The first group is checked from the inventory alone:

- Its name and address match exactly one entry that this scenario's create step wrote to the instance config. The
  address is `ansible_host`, or the inventory name when it is unset, and must have the form
  `fsd-mol-<scenario>-<8 character run id>-<platform>`.
- The connection is in the allow-list (`community.docker.docker`; a scenario can override
  `molecule_allowed_connections`) and is not a local connection. An unset connection counts as `ssh` and is refused.
- No `ansible_docker_*` or `docker_*` variable is set. This covers `ansible_docker_host`, which takes precedence over
  `ansible_host`, `ansible_docker_extra_args`, which can select another daemon, `ansible_docker_privileged` and
  `ansible_docker_extra_env`. The `ANSIBLE_DOCKER_PRIVILEGED` environment variable must be unset or empty.
- Neither name nor address is a loopback or unspecified form after normalisation (lower case, trimmed, brackets,
  zone index and trailing dots removed): `localhost` variants, `ip6-localhost`, `127.0.0.0/8` in dotted, octal and
  hexadecimal notation, a bare decimal or hexadecimal number, `::1` and `::` in any spelling, IPv4-mapped loopback in
  dotted or hexadecimal form, and `0.0.0.0`.

The second group is checked by inspecting the recorded container from the controller. It must be unprivileged and
drop all capabilities, adding only those recorded in the config. It must have no bind mounts, mounts, volumes,
devices, device requests or device cgroup rules. It must share no host or container network, pid, ipc, uts, user
or cgroup namespace. Its `SecurityOpt` must be exactly `no-new-privileges` (or `no-new-privileges:true`): any
`seccomp=`, `apparmor=`, `label=` or `systempaths=` entry is refused, which covers a custom allow-all seccomp profile.
Its `MaskedPaths` and `ReadonlyPaths` must contain every path that `molecule_docker_default_paths` in
`shared/vars/versions.yml` pins for the major version of the Docker daemon (Docker 29 today: `/proc/kcore`,
`/proc/keys`, `/sys/firmware` and the others masked, `/proc/sys`, `/proc/sysrq-trigger`, `/proc/bus`, `/proc/fs` and
`/proc/irq` read-only). `--security-opt systempaths=unconfined` does not show up in `SecurityOpt`; it empties those two
lists, which leaves `/proc/sysrq-trigger` and `/proc/sys/kernel/core_pattern` writable for root, so this check is
what refuses it. A daemon whose major version has no pin is refused, so a Docker upgrade is noticed, and the self-test
asserts that a default container gets exactly the pinned lists, which catches changed defaults within a major
version. Finally, the container must carry this run's labels.

The last group is checked over the real connection, by reading `/proc/1/environ` and `/proc/self/status`. PID 1 must
carry this instance's marker. The process that the connection runs must have no permitted, effective or bounding
capabilities, and `NoNewPrivs` must be 1. That catches a connection that reaches another container or daemon, and
`docker exec --privileged`.

`verify` feeds simulated bypass attempts to the same task files (`shared/vars/guard_cases.yml`, 64 cases). It asserts
that each is refused with a message that starts with "Refusing to run" and that a disposable container is accepted.
The loopback check does not enumerate the controller's own addresses; the exact match against the create step's
records is what keeps every other target out.

`create.yml`, `destroy.yml` and the delegated container inspection run on `localhost` with `connection: local` by
design. They talk to the Docker daemon through `community.docker`, and they write only the instance config.
`prepare` also checks the fetched datastream on the controller with `stat`.

### Self-test against real containers

`make test-molecule-docker-selftest` (`extensions/molecule/selftest/`) runs the shared playbooks outside Molecule, as
scenario `docker-selftest`, with the instance config in `build/molecule-selftest/`:

1. `create.yml` twice, then `assert_created.yml`: one container, whose name, labels and instance config agree on one
   persisted run id, and whose masked and read-only paths are exactly the pinned Docker defaults.
2. `bypass.yml` starts three decoys of the same run, each with this run's labels and marker: one that bind-mounts the
   empty directory `build/molecule-selftest/host-directory`, one with `systempaths=unconfined` (started with
   `community.docker.docker_compose_v2`, because the Docker API takes that option only as empty path lists) and one
   with a custom allow-all seccomp profile. It records each decoy in its own instance config, as create would, and
   writes one inventory per bypass attempt.
3. The guard accepts the real instance. It refuses each attempt with "Refusing to run": `ansible_docker_host`
   steered to the mounted decoy, `ansible_docker_extra_args`, `ansible_docker_privileged`, a local connection, an
   explicit `localhost`, `127.0.0.1`, an unrecorded container name, and each of the three recorded decoys, which must
   be refused by the isolation check ("is not isolated").
4. The instance config is emptied and `destroy.yml` must remove all four containers by label. A new `create` follows,
   the instance config is deleted, and `destroy.yml` must again remove the container. `assert_destroyed.yml` checks
   after each destroy that no container with the `docker-selftest` label is left.

The recipe always ends with both destroy runs, so a failed step does not leave containers behind.

## What the scenarios run

The scenarios apply the real `discover`, `audit`, `remediate` and `verify` roles with `include_role`. They set only
public role inputs (profiles, the content path and SHA-256, `linux_compliance_remediate_enabled` and the rule
toggle), never an internal `__linux_compliance_*` variable. The reference rule is
`xccdf_org.ssgproject.content_rule_file_permissions_crontab`, the only rule in the remediation catalogue.

`converge`:

1. discover: verifies the datastream and the profile, and that the reference rule is in the profile.
2. audit with a real `oscap` scan, then `verify` `baseline.yml` records it as the baseline.
3. remediate with the opt-in off. Every rule is skipped with `remediation_disabled`, and the snapshot (below) before
   and after is identical.
4. remediate with `linux_compliance_remediate_enabled: true`. Exactly one result: the reference rule, applied
   (`0644` to `0600`) on the first converge and `compliant` with no change on the second. Owner, group and content
   of `/etc/crontab` are unchanged.
5. audit again with a real scan, then the `verify` role compares it with the baseline. The comparison must be
   complete, with no regression and no new failure.

`idempotence` runs converge again and Molecule requires zero changed tasks. The second remediation finds the file
compliant and records nothing in the state ledger, so the test is meaningful for the reference rule.

`verify`:

1. The guard cases above.
2. `/etc/crontab` is `0600` and the state ledger holds one entry for the reference rule with the prior mode `0644`.
3. A real audit of the remediated instance.
4. Cleanup: remediate with the opt-in on and `linux_compliance_rule_file_permissions_crontab_enabled: false`. The
   result is one `cleanup` with status `restored`, `/etc/crontab` is `0644` again and the ledger is empty.
5. Snapshot. Then, with no change allowed: the cleanup again (no result), remediate with the opt-in on in check mode
   (the rule is planned as `apply`), remediate with the opt-in off, audit in check mode, and every invalid input.
   The snapshot must be identical afterwards, and `/etc/crontab` must still be `0644`.
6. Invalid inputs (`shared/vars/contract.yml`): each must fail with its expected message pattern. Examples are an
   empty or path-like profile, a profile the datastream does not contain, a wrong or malformed content SHA-256, a
   missing content path, non-boolean and string `"true"` booleans, unknown backends, modes and disruptive families,
   a relative output directory, a zero timeout, and a profile that discover did not verify, also with the opt-in on.
7. `linux_compliance_remediate_enabled` defaults to `false` and `linux_compliance_remediate_allow_disruptive` to `[]`,
   in both `defaults/main.yml` and `meta/argument_specs.yml` of the remediate role.

Every audit goes through `shared/tasks/audit.yml`, with `linux_compliance_audit_scan_timeout: 180` (a scan takes a few
seconds). The audit assertions (`shared/tasks/assert_audit.yml`) require `run_status` `completed` and no `error` finding. They
require one finding per profile rule and a finding for the reference rule. They require that evidence was written
for a real scan and not for a check-mode scan. Role failures are captured with `block` and `rescue`
(`shared/tasks/run_role.yml`) and then asserted on, because the registered result of `include_role` does not carry
the failure of a task inside the role.

### The no-change snapshot

`shared/tasks/snapshot.yml` records path, mode, uid, gid, size, mtime, ctime and SHA-1 checksum of every entry below
`/etc`, `/usr`, `/root`, `/home`, `/var/spool`, `/var/log`, `/opt`, `/srv`, `/var/lib/dpkg`, `/var/lib/rpm`,
`/var/lib/linux_compliance` and
`/var/lib/freesecdev`. The state ledger and the evidence directory are part of it. On a mismatch the assertion prints
up to 20 differing entries.

Two exceptions are recorded explicitly:

- For the evidence directory `/var/lib/freesecdev/linux_compliance/evidence` itself, only path, mode and owner count,
  not its size and times. A check-mode scan runs in a private `.check-<run id>` directory below it and removes that
  directory before it returns, which updates the parent's times. Every entry below the evidence directory still
  counts, so evidence that a check-mode run kept would fail the snapshot.
- For `/var/lib/rpm/rpmdb.sqlite-shm` and `rpmdb.sqlite-wal` (`contract_snapshot_volatile_times`), the times do not
  count; path, mode, owner, size and checksum still do. The scanner's RPM probes open the RPM database read-only, and
  SQLite updates the times of its shared-memory and write-ahead-log files when it opens a database in WAL mode.

### What a container audit can and cannot show

The scans are real `oscap` runs against the pinned datastreams and take seconds. ComplianceAsCode marks most rules
`notapplicable` in a container (their platform is `machine`, which excludes containers), including the reference
rule. On Rocky every rule is `notapplicable` (see above). The audits therefore prove that discovery, the scan
pipeline, evidence handling, check mode and the comparison work end to end. They do not show the reference rule
moving from `fail` to `pass`; the scenarios assert that change on the file itself (`0644`, `0600`, then restored
`0644`). The audit step logs the outcome of the reference rule and the summary of each scan.

### Scanner hangs

During development, one of roughly thirty `oscap` 1.3.9 scans in the Ubuntu container hung for more than ten
minutes. All 48 threads were waiting on a futex (`futex_do_wait`), with no child process and no I/O. The cause is not
established; it looks like a deadlock in the scanner's probe threads. With the role default of 1800 seconds that
would stall a run for half an hour. `shared/tasks/audit.yml` therefore sets the 180-second timeout. When the audit
role fails because the scan of this audit timed out, and only then (the published `run_id` must differ from the one
before the audit, `run_status` must be `timed_out` and the failure message must name it, so a stale result of an
earlier audit never decides), it logs a `WARNING: oscap did not finish` line, counts the timeout in
`molecule_scan_timeouts` and runs the audit once more. A second timeout, or any other failure, fails the scenario.
`verify` tests that decision: it leaves a timed-out `linux_compliance_audited` from an earlier audit in place, runs
the wrapper with an invalid profile and asserts that the input error fails the audit without a retry or a warning. Search the Molecule log for that warning to see whether a run needed the retry. Each scenario runs six
scans (two in converge, two in idempotence, one real and one check-mode scan in verify); the check-mode audit
runs only in verify.

### Known limitation of check mode through include_role

The scenarios request check mode with `include_role` and `apply: {check_mode: true}`. Modules honour it: the snapshot
proves that nothing changes. But `ansible_check_mode` only reflects `--check` on the command line, so
`linux_compliance_remediated.check_mode` reads `false` in that case. The scenarios do not assert that field. They
assert the plan and the unchanged snapshot instead.

### Extending the scenarios

New platforms need a key in `shared/vars/versions.yml` (with `datastream` and `profile`) and a Dockerfile in
`shared/images/`. New invalid inputs go into `shared/vars/contract.yml` with an `expect` pattern. A new input name
must also be added to `contract_input_names` and to the include in `shared/tasks/run_role.yml`. When the
remediation catalogue grows, add the new rule's file-level assertions next to the reference rule in `converge.yml` and
`verify.yml`. FREES-60 tracks importing the real `playbooks/*.yml` instead of applying the roles one by one, and diff
mode.

## Container-meaningful and not

Meaningful in a container: input validation, argument specs, defaults, check-mode behaviour, file-based and
package-based controls, idempotence, the remediation ledger and its cleanup, the scan pipeline, and the absence of host
changes in audit mode.

Not meaningful in a container, and therefore not covered by these scenarios:

- Boot loader and Secure Boot controls (GRUB, kernel command line).
- Mount options, partitions and file system layout.
- Kernel parameters (sysctl) and kernel modules.
- Services that need systemd as PID 1, and anything that restarts services.
- Firewall rules (nftables, iptables, ufw, firewalld), network configuration and the network stack.
- PAM, SSH daemon and sudo behaviour that depends on a real login, and auditd.
- Findings of rules whose ComplianceAsCode platform excludes containers.

## Tests that need libvirt

These belong to the libvirt scenarios (FREES-61, FREES-63) and run on a KVM-capable host:

- `libvirt-ubuntu-bare` and `libvirt-rhel-bare`: full VM from a bare cloud image.
- `libvirt-negative`: invalid profile, unavailable scanner, bad arguments on a real OS.
- `libvirt-idempotency`: repeated converge with zero unexpected changes on a full system.
- `libvirt-ubuntu-golden` and `libvirt-rhel-golden`: golden images from the manifest.
- `libvirt-baseline-regression`: findings compared with the recorded baseline.
- `libvirt-remediation`: opt-in remediation then verify, including every disruptive family (bootloader, mounts, kernel
  parameters, firewall, network, PAM, SSH, sudo, crypto policy), and the reference rule moving from `fail` to `pass`.
- Any real OpenSCAP scan that depends on the kernel, the boot configuration or systemd services.
