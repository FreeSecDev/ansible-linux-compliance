# Molecule scenarios

Scope: the Docker Molecule scenarios under `extensions/molecule/`, how to run them and what they prove.
Audience: contributors adding or changing roles, modules and scenarios.
Decision record: [ADR 0009](adr/0009-molecule-layout-and-drivers.md). Jira: FREES-59, FREES-60, FREES-61.
The libvirt scenarios, which run the same playbooks in KVM virtual machines, have their own
[libvirt guide](molecule-libvirt.md).

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
make test-molecule-docker MOLECULE_DOCKER_SCENARIOS=docker-ubuntu-lifecycle MOLECULE_DOCKER_SELFTEST=false \
  MOLECULE_LIFECYCLE_TOPIC=pwquality MOLECULE_LIFECYCLE_MODE=rule
make test-molecule-docker-selftest
```

`test-molecule-docker` installs the pinned collections from `extensions/molecule/requirements.yml` into
`build/collections` (`make molecule-dependencies`), fetches and verifies the pinned ComplianceAsCode datastreams into
`build/content` (`make molecule-content`, the same `tools/content/fetch_content.py` as `test-oscap-integration`), runs
`molecule test -s <scenario>` for each scenario and stops at the first failure, and then runs the self-test. Without
`MOLECULE_DOCKER_SCENARIOS` it runs all four scenarios, so the lifecycle scenarios run every native topic in both
toggle modes; `MOLECULE_LIFECYCLE_TOPIC` and `MOLECULE_LIFECYCLE_MODE` select one topic and one mode, as a
[CI leg](#ci-legs) does. The first run builds the images. The images stay in the local Docker cache
(`freesecdev-molecule/*`); remove them with `docker image rm` when no longer needed.

CI runs the same target in two jobs on `ubuntu-24.04` GitHub-hosted runners: `molecule-docker`, one matrix entry per
standard scenario plus `docker-selftest`, and `molecule-lifecycle`, one leg per platform, native topic and toggle mode
(see [CI legs](#ci-legs)). Both are part of `ci-gate`.

## Scenarios

| Scenario | Image | Datastream and profile |
|---|---|---|
| `docker-ubuntu` | Ubuntu 24.04 | `ubuntu2404`, `cis_level1_server` ([ADR 0010](adr/0010-initial-os-and-benchmark-scope.md)) |
| `docker-rhel-compatible` | Rocky Linux 9 | `rhel9`, `cis_server_l1` |
| `docker-ubuntu-lifecycle` | Ubuntu 24.04 | as `docker-ubuntu` |
| `docker-rhel-compatible-lifecycle` | Rocky Linux 9 | as `docker-rhel-compatible` |

The standard scenarios run `create`, `prepare`, `converge`, `idempotence`, `verify` and `destroy`. The lifecycle
scenarios share every playbook, the image, the guard and the label scheme with them and run `create`, `prepare`,
`side_effect` and `destroy`: their `side_effect` step is the
[toggle lifecycle](#toggle-lifecycle-of-every-native-topic), on an instance that no `converge` has touched. `destroy`
runs even when an earlier step failed. Molecule warns that the scenario has no `cleanup` playbook; there is nothing to clean up outside
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
| `ubuntu` | `python3=3.12.3-0ubuntu2.1`, `openscap-scanner=1.3.9+dfsg-1.1ubuntu2` (the version that `oscap-integration` pins), `cron=3.0pl1-184ubuntu2`, `python3-apt=2.7.7ubuntu5.3` (for `package_facts` in the toggle lifecycle), `libpam-pwquality=1.4.5-3build1` (libpwquality and its `pwquality.conf`, so that the `pwquality` lifecycle runs on Ubuntu as on Rocky Linux, where the library is part of `pam`), `sudo=1.9.15p5-3ubuntu5.24.04.4` (`/etc/sudoers`, `/etc/sudoers.d` and `visudo` for the `sudo` lifecycle) |
| `rhel_compatible` | `openscap-scanner-1:1.3.14-1.el9_8.rocky.0.1`, `cronie-1.5.7-16.el9`, `sudo-1.9.17p2-3.el9_8.3` (for the `sudo` lifecycle); Python 3.9 comes with the base image |

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
  run as root inside the container without `sudo`, so they pass `ansible_become=false`. sudo itself cannot run in
  them: without `CAP_SETUID` it fails with `PERM_SUDOERS: setresuid(-1, 1, -1): Operation not permitted` before it
  reads its policy, so that sudo still works with the `sudo` topic's drop-ins is proven by `visudo` and the golden
  tests here, and by a real `become` only in the libvirt scenarios (FREES-61). Remote temporary files go to `/tmp`.
- `create.yml` refuses platforms that are privileged, use `network_mode` `host` or `container:*`, declare `volumes`,
  `mounts` or `devices`, or add capabilities without a `capabilities_reason`.
- The run id is generated once, as the first fact of `create.yml`, and persisted in the instance config. A repeated
  `create` reuses the recorded run id and marker, so it starts no second container. Container names are
  `fsd-mol-<scenario>-<run id>-<platform>`. Every record names its driver (`docker`); a Docker scenario name may not
  start with `libvirt-`, the prefix from which the guard decides that a target is a virtual machine.
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
a target, with `any_errors_fatal`. It targets `hosts: all`, so the implicit `localhost` is never part of it.

Before anything else, the guard refuses variables that it relies on but did not compute itself (FREES-150). Extra
variables (`-e`) take precedence over everything a play can set: play variables, `vars_files`, task variables,
include variables, `set_fact` facts and also registered results. With `-e guard_container=<inspect JSON of an isolated
container>`, an earlier guard accepted a decoy with a host bind mount, and the next task read a host file through
it; the same worked with `guard_inspect`, `molecule_target` and `inventory_hostname`. Measured with ansible-core
2.21.5, only the loop variable of a task's own `loop`, the magic variables computed after the extra variables
(`hostvars`, `vars`, `groups`, `ansible_play_hosts_all`, `ansible_play_batch`, `playbook_dir`) and lookups such as
`env` are out of reach. `inventory_hostname` is not: it is a host variable. The first task therefore uses only those,
and literal values:

- No variable named `guard_*`, `molecule_target*`, `molecule_docker_default_paths` or `molecule_libvirt_*` may exist
  in `hostvars[inventory_hostname]` when the play starts. `hostvars` holds inventory variables, facts and registered
  results of earlier plays and extra variables, but not play variables or `vars_files`. Any such name is therefore
  supplied from outside, whatever its value.
- `ansible_play_hosts_all`, mapped to each host's `inventory_hostname`, must give back `ansible_play_hosts_all`, which
  refuses an `inventory_hostname` extra variable.
- `ansible_host`, `ansible_connection` and `molecule_allowed_connections` come legitimately from the inventory. The
  task sets each to a sentinel as a task variable, which beats every inventory source, and requires the sentinel to
  survive, which only an extra variable prevents. The sentinel connection is `ansible.builtin.local`, because the
  `assert` task loads the connection plugin without using it. An extra variable that repeats a sentinel is refused by
  the later checks: `ansible.builtin.local` is a local connection, the sentinel address is no recorded address, and
  a sentinel allow-list contains no connection.
- The guard reads the instance config from the `MOLECULE_INSTANCE_CONFIG` environment variable, which Molecule sets,
  and `molecule_instance_config` must equal it.

Once that holds, every fact, registered result and include variable of the guard is the value the guard computed.
Reading values back and comparing them against a fresh inspection would not help, because the fresh result is a
registered variable that the same extra variable can shadow. The guard refuses an inventory variable named `guard_*`
as well. A target is accepted only when all of the following hold. The first group is checked from the inventory
alone:

- Its name and address match exactly one entry that this scenario's create step wrote to the instance config. The
  address is `ansible_host`, or the inventory name when it is unset, and must have the form
  `fsd-mol-<scenario>-<8 character run id>-<platform>`.
- The connection is in the allow-list (`community.docker.docker`; a scenario can override it with the inventory
  variable `molecule_allowed_connections`, never with an extra variable) and is not a local connection. An unset connection counts as `ssh` and is refused.
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
`shared/vars/versions.yml` pins for the major version of the Docker daemon. Docker 28 (28.0.4 on the GitHub
runners) and Docker 29 (29.5.3 locally) are pinned with the same lists: `/proc/kcore`, `/proc/keys`, `/sys/firmware`
and the others masked, and `/proc/sys`, `/proc/sysrq-trigger`, `/proc/bus`, `/proc/fs` and `/proc/irq` read-only. `--security-opt systempaths=unconfined` does not show up in `SecurityOpt`; it empties those two
lists, which leaves `/proc/sysrq-trigger` and `/proc/sys/kernel/core_pattern` writable for root, so this check is
what refuses it. A daemon whose major version has no pin is refused, so a Docker upgrade is noticed, and the self-test
asserts that a default container gets exactly the pinned lists, which catches changed defaults within a major
version. Finally, the container must carry this run's labels.

The last group is checked over the real connection, by reading `/proc/1/environ` and `/proc/self/status`. PID 1 must
carry this instance's marker. The process that the connection runs must have no permitted, effective or bounding
capabilities, and `NoNewPrivs` must be 1. That catches a connection that reaches another container or daemon, and
`docker exec --privileged`.

`verify` feeds simulated bypass attempts to the same task files (`shared/vars/guard_cases.yml`, 69 cases). It asserts
that each is refused with a message that starts with "Refusing to run" and that a disposable container is accepted.
Every scenario's `verify` also runs the 133 simulated libvirt cases of the [libvirt guard](molecule-libvirt.md#guard),
whatever its own driver, so the libvirt guard is exercised even where no KVM is available.
The loopback check strips brackets, a zone index and trailing dots from the host name and the address before it matches
them, so `[::1]`, `localhost.`, `LOCALHOST..` and `[::ffff:127.0.0.1]` are loopback. In `{{ }}` templates a regex
literal is used as written, so its backslashes are single (`\[`, `\.`); only `that:` and `when:` conditionals decode
escapes. Five simulated cases record such a host name for the run, with a matching address, so that only the loopback
rule can refuse them.
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
   writes one inventory per bypass attempt. It also writes one extra-variable attempt per variable the guard relies
   on, into `build/molecule-selftest/extra-vars/<variable>/`: every `guard_*` name that occurs in `shared/guard.yml`,
   `tasks/guard.yml`, `tasks/guard_isolation.yml` and `tasks/guard_connection.yml`, plus `molecule_target`,
   `molecule_docker_default_paths`, `molecule_instance_config`, `molecule_allowed_connections`, `ansible_host`,
   `ansible_connection` and `inventory_hostname`. It fails when one of them has no attempt. Each attempt targets the
   mounted decoy, records it in its instance config and sets a value that disguises it, for example the inspection of
   the real instance as `guard_container` or `guard_inspect`, or the real instance's record as `molecule_target`.
3. The guard accepts the real instance. It refuses each attempt with "Refusing to run": `ansible_docker_host`
   steered to the mounted decoy, `ansible_docker_extra_args`, `ansible_docker_privileged`, a local connection, an
   explicit `localhost`, `127.0.0.1`, an unrecorded container name, and each of the three recorded decoys, which must
   be refused by the isolation check ("is not isolated"). Each extra-variable attempt (39) runs the guard with
   `-e @extra-vars/<variable>/vars.yml` and must be refused because the variable "was supplied from outside" the
   guard. Against the guard before FREES-150, the `guard_container`, `guard_inspect`, `molecule_target` and
   `inventory_hostname` attempts were accepted and a following task read a file in the mounted host directory.
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
up to 20 differing entries. Both this snapshot and the whole-instance record take their entries from
`shared/tasks/find_with_checksums.yml` (FREES-175): one `find` with checksums, as before. Root in the Docker
containers has no capabilities, and a file that it cannot read (`/etc/shadow` on Rocky Linux, `/usr/bin/sudo` with
mode `4111`) stops that `find`'s walk of its whole path, so every later entry of the path would be missing. For a
path whose walk stopped that way, and only for it, the task lists the entries again without reading content and takes
the checksums in a second `find` of the regular files whose owner may read them, and fails when that second pass
stops early as well. It then remembers, per set of paths, the names of the files that root cannot read: later
records leave those names out of the one walk and list the entries of such a name with two `find`s that do not
recurse, one without content and one with the checksums that their owner may read, which is how they stay one walk on
Rocky Linux too. Those two `find`s look in the directories that held such an entry in the first record and, for the
whole-instance record, in the parent directory of every path that the topic declares, so a new entry of one of those
names next to a declared path is seen. A walk that stops again, because a file that root cannot read appeared, takes
the second pass over every path and refreshes the names. A new entry with one of those names in any other directory
after the first record is not seen; the names are those of the shadow files and the sudo binaries. Paths whose walk
did not stop, and every path on the libvirt drivers, where root keeps its capabilities, cost one walk as before.

Two exceptions are recorded explicitly, and a virtual machine has a third, for the system logs and service state files
that a running system rewrites by itself ([libvirt guide](molecule-libvirt.md#differences-that-only-a-virtual-machine-has)):

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
`0644`). The audit step logs the outcome of the reference rule and the summary of each scan. One outcome does not
depend on the platform: after the toggle lifecycle switches a topic off, the audit must report its rules `disabled`
by the controlling toggle (114 disabled rules for the `file_permissions` topic toggle on Ubuntu, 57 on Rocky, and
one for the rule toggle).

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
the wrapper with an invalid profile and asserts that the input error fails the audit without a retry or a warning. Search the Molecule log for that warning to see whether a run needed the retry. Each scenario runs ten
scans (two in converge, two in idempotence, one real and one check-mode scan in verify, and four in the toggle
lifecycle of `file_permissions`); the check-mode audit runs only in verify.

### Known limitation of check mode through include_role

The scenarios request check mode with `include_role` and `apply: {check_mode: true}`. Modules honour it: the snapshot
proves that nothing changes. But `ansible_check_mode` only reflects `--check` on the command line, so
`linux_compliance_remediated.check_mode` reads `false` in that case. The scenarios do not assert that field. They
assert the plan and the unchanged snapshot instead.

### Extending the scenarios

New platforms need a key in `shared/vars/versions.yml` (with `datastream` and `profile`) and a Dockerfile in
`shared/images/`. New invalid inputs go into `shared/vars/contract.yml` with an `expect` pattern. A new input name
must also be added to `contract_input_names` and to the include in `shared/tasks/run_role.yml`. When the
remediation catalogue gains a native rule, extend the [lifecycle declaration](#declaring-a-topic) of its topic, or add
one for a new topic; `make lint-lifecycle` fails until it exists. Importing the real `playbooks/*.yml` instead of
applying the roles one by one, and diff mode, are still open under FREES-60.

## Toggle lifecycle of every native topic

`shared/lifecycle.yml` (FREES-60) is the `side_effect` step of the lifecycle scenarios. It proves, for every topic that has a
rule with a native remediation, that switching the topic on applies its controls and that switching it off again
restores the state before it, with the topic toggle and with the rule toggles. It runs the real remediate role, never
an internal variable, and only after the [guard](#localhost-guard) accepted the instance; it runs in a container of
its own, which no other step uses, and `destroy` removes the container afterwards.

Run it step by step during development, against a fresh instance:

```text
uv run --frozen molecule create -s docker-ubuntu-lifecycle
uv run --frozen molecule prepare -s docker-ubuntu-lifecycle
MOLECULE_LIFECYCLE_TOPIC=banners MOLECULE_LIFECYCLE_MODE=topic uv run --frozen molecule side-effect -s docker-ubuntu-lifecycle
uv run --frozen molecule destroy -s docker-ubuntu-lifecycle
```

with `ANSIBLE_HOME` and `ANSIBLE_COLLECTIONS_PATH` set as the `Makefile` exports them. Without the two selection
variables the step runs every native topic in both modes. Before any topic runs, the harness refuses a selection that
sets only one of them, names a topic without a native rule or names a mode other than `topic` and `rule`. On an instance where
`converge` already applied a topic, the harness refuses to run, because the state before the collection is then
unknown. `converge` and `verify` therefore prove the reference rule alone: their plays set the topic toggles of every
other native topic to `false` (`molecule_other_native_topics` in `shared/vars/target.yml`), and their first task fails
when that list differs from the native topics of the catalogue, so a new native topic cannot be applied by them by
accident.

### What it runs

The topics are derived from the catalogue at run time: every family of `roles/remediate/vars/rules.yml` with a rule
whose strategy is not `audit_only`, in registry order with the non-disruptive families first. The rules of a topic
are its native rules that the verified profile of the platform selects. A platform whose profile selects none must
be listed under `unselected_platforms` in the declaration, with a reason, and a listed platform must select none; the
run fails otherwise, and the coverage gate refuses a declaration that lists every platform, so no topic can be skipped
everywhere. Before the first topic, two self-checks feed synthetic states to the comparisons and fail the run if a
comparison would pass what it must refuse: `shared/tasks/lifecycle_selfcheck.yml` for the declared state (a missing
control, a change that nothing declares, a file left behind or removed, a declared change that did not happen) and
`shared/tasks/lifecycle_broad_selfcheck.yml` for the [whole instance](#the-whole-instance-comparison) (an undeclared
file left behind, modified or only touched, a declared file replaced by another inode, a file next to the ledger, a
kernel parameter, a package, a user, a group and a service added or changed must be refused; the listed differences
must be accepted).

Every remediate run of a topic narrows `linux_compliance_discovered.rule_ids` to the native rules of that topic, the
way a profile that selects only them would, and restores the verified profile right after the run, so the audits and
the next topic see it unchanged. A run that applies or cleans up a rule outside the topic fails. Without the narrowing,
the cycles of one topic would apply every other native topic as well and its cleanup could not be compared exactly.

A pre-state may declare rules `unchanged`: rules that it already satisfies (`compliant`, such as the mode of an
`/etc/issue` that is already `0644`) or that do not apply (`notapplicable`), optionally per platform. In the steps
below such a rule must report exactly that status and `changed: false` in check mode, on apply and on the second
apply, is not recorded in the ledger, is planned `none` when the topic is switched off and reports no cleanup. Every
other rule must be `applied` and changed, and at least one rule of a pre-state must change something.

For each topic, for the topic toggle and then the rule toggles, and for each declared pre-state:

1. The pre-state is set (only file modes and ownership), the topic is switched on and the **declared state** is
   recorded: per file existence, type, mode, owner, group, uid, gid, inode, mtime, `lsattr` attributes, SHA-256 and
   link target (`stat` without following links); per package whether it is installed and its versions (`package_facts`); per service whether it exists, its
   state and its status (`service_facts`); per kernel parameter its value (`slurp` of `/proc/sys`); per user and group
   whether it exists and its entry (`getent`); and every entry of the state ledger (`control_state` `list`). The
   ledger must not record any rule of the topic. The state of the whole instance is recorded as well (see below).
2. **Check mode on.** The remediate role runs in check mode. The plan must have `apply` for every rule of the topic and
   the results must report each as `applied` and changed, while the [no-change snapshot](#the-no-change-snapshot) of
   every watched path stays identical.
3. **Apply.** Every rule must be `applied` and changed. The declared state must match the declaration's `applied`
   expectations, and every other declared attribute must be unchanged. The ledger must record every rule of the topic
   whose strategy is `recorded_value` or `recorded_state`, and every other ledger entry must be unchanged. For a
   pre-state with `audit: true` a real scan follows, and every rule must be `pass` or `fixed`, or an outcome the
   declaration adds with a reason.
4. **Idempotence.** A second apply must report every rule `compliant` and unchanged, and the no-change snapshot must
   be identical.
5. **Check mode off.** The topic is switched off, with `linux_compliance_<topic>_enabled: false` in the topic-toggle
   cycle and with every `linux_compliance_rule_<rule>_enabled: false` (topic toggle on) in the rule-toggle cycle. In
   check mode the plan must have `cleanup` for every rule, with `disabled_by` naming the toggle that switched it off,
   the results must report the cleanup, and the no-change snapshot must be identical.
6. **Cleanup.** Every rule must be cleaned up, changed and not `cleanup_incomplete`. The declared state must equal the
   state of step 1 exactly: a file that did not exist before must not exist, a file that existed must still exist with
   only the collection's changes reverted, and the ledger must equal its entries of step 1. The whole instance must
   equal its state of step 1, with only the listed differences. With `audit: true` a real scan must report every rule
   `disabled` by the same toggle.
7. **Off again.** A further run must plan `none` for every rule, give no result and leave the no-change snapshot
   identical.

After every remediate run the harness reads `/proc/1/environ` and `/proc/self/status` over the connection and applies
the guard's own connection test (`shared/tasks/guard_connection.yml`): the run still reaches the container that the
create step started, by its marker, without capabilities and with `NoNewPrivs`. After the last cycle the files of the
pre-states get their original mode and ownership back, and the declared state, the ledger and the whole instance
must equal those before the first cycle.

### The whole-instance comparison

A declaration names what a topic is expected to touch, so a cleanup that forgets something the declaration also
forgot, such as a backup file, a second drop-in or a package, would pass a comparison of the declared items alone.
`shared/tasks/lifecycle_broad.yml` therefore records the whole instance before each cycle and before the first cycle,
and the state after the cleanup and after the last cycle must equal it:

- every entry below `/etc`, `/usr`, `/root`, `/home`, `/opt`, `/srv`, `/var/spool`, `/var/log` and `/var/lib`
  (`find` without following links): path, type, mode, uid, gid, size, inode, mtime, ctime and the SHA-256 of every
  regular file that root can read, through the same task as the [no-change snapshot](#the-no-change-snapshot);
- every kernel parameter that the instance may read (`find` over `/proc/sys` with a SHA-256 of each value);
- every installed package with its versions (`package_facts`), every user and group with its entry (`getent`), and
  every service where a service manager runs (`service_facts`; the containers have none, which is recorded as such).

Only these differences are allowed, each listed in `shared/vars/lifecycle.yml`:

| Difference | Why |
|---|---|
| mtime and ctime of the declared files and of their parent directories | changing a mode changes the ctime, and creating or removing a drop-in changes the times of its directory; everything else about these entries still counts, and the declared state compares the declared files exactly |
| the inode of a declared file with `rewritten: true` | rewriting a file's content (`copy`, `lineinfile`, `template`) replaces it through a new inode; its type, mode, uid, gid, size and SHA-256 still count, so the restored content must be byte for byte the original |
| `/var/lib/freesecdev`, `/var/lib/freesecdev/linux_compliance` and its `state.json` | the ledger, compared entry by entry instead; any other file in that directory counts |
| `/var/lib/freesecdev/linux_compliance/evidence` and everything below it | the evidence and output of the real scans of the cycle |
| the times of `/var/lib/rpm/rpmdb.sqlite-shm` and `-wal` | the scanner's RPM probes, as in the [no-change snapshot](#the-no-change-snapshot) |
| the kernel usage counters `fs/aio-nr`, `fs/dentry-state`, `fs/file-nr`, `fs/inode-nr`, `fs/inode-state`, `fs/quota/*`, `kernel/hung_task_detect_count`, `kernel/ns_last_pid`, `kernel/pty/nr`, `kernel/random/entropy_avail` and `kernel/random/uuid` | they count current kernel use, change between two reads without any write, and are not settings; two reads in a fresh container differed in six of them |

`find` does not report the target of a symbolic link. A link cannot be changed in place, so a new target shows up as
a new inode, mtime and ctime of the link, which are recorded. Extended attributes, POSIX ACLs and SELinux contexts are
not recorded: `ansible.builtin` has no module that reads them (`ansible.posix.acl` and `community.general.xattr` are
not pinned dependencies, and the images have neither the `acl` tools nor SELinux), so a topic that manages them needs
a module or the libvirt scenarios first. `lsattr` attributes are recorded for declared files only, through `stat`;
where the file system of the container does not support them, `stat` reports none both times.

Three mutations of the remediate role, each applied only to a local copy and reverted, made the harness fail at the
first cleanup with the offending entry: writing an undeclared `/etc/fsd-review-stray` during apply, appending a line
to `/etc/issue`, and appending a user to `/etc/passwd` (which shows as the changed file and the new `user` entry).

The topic-toggle cycles run before the rule-toggle cycles, because a rule toggle that is set wins over the topic
toggle and set facts cannot be unset. The harness asserts that no rule toggle of the topic exists before a
topic-toggle cycle. The toggles are set with `set_fact` under the names that the catalogue gives, which the remediate
and audit roles find through `varnames`, exactly as inventory values.

For `file_permissions` each scenario runs four cycles (topic and rule toggle, from the as-built state and from a
customised mode), 24 remediate runs, four real scans and ten whole-instance records; the Ubuntu step took seven and a
half minutes on a WSL2 workstation. The customised pre-state (`0640`) is what shows that cleanup
restores the recorded prior value and not a distribution default: with the cleanup changed to always restore `0644`,
the harness fails with `cleanup: files /etc/crontab: mode changed from 0640 to 0644`.

After the last topic and mode, `shared/tasks/lifecycle_pwquality_regressions.yml` runs regressions of the security review of
PR #56 on both platforms: it applies pwquality, pretends the content of the other platform and checks that apply
reports `method_changed` and cleanup `cleanup_incomplete` (`method_changed`) with every ledger entry kept and no file
touched; it changes `minlen` by hand and checks that cleanup keeps the change as `modified_since_apply` while the other
rules are restored; on Ubuntu it puts a symbolic link in place of `pwquality.conf.d`, selects the drop-in method and
checks that every rule is `not_directory` and nothing is written through the link; and it compares the whole instance
with its state before the regressions.

A topic declares its regressions as named groups under `regressions` (FREES-175); each group lists task files of
`shared/tasks` that the static dispatch `shared/tasks/lifecycle_regressions.yml` includes, optionally for some
`platforms` only. `make lint-lifecycle` requires every include of the dispatch to run exactly when its own file is
in the group (no other condition, no tags), every dispatched file to be named by some group and to end by adding its
name to `lifecycle_regression_files_run`, and the harness fails a regression leg in which a file of its group did not
run to its end. A group runs at the end of its topic, with the topic's facts, on the Docker driver: in a full run
after every cycle, and in CI in a leg of its own, `MOLECULE_LIFECYCLE_MODE=regressions-<group>`, which runs no cycle
(see [CI legs](#ci-legs)). `pwquality` has one group, `changes`, with the regressions above.

`sudo` has three groups. In `changes` (both platforms), `shared/tasks/lifecycle_sudo_regressions.yml` does the same
for `sudo`: it applies the topic, records every ledger entry as if another method had written it and checks that apply
reports `method_changed` and cleanup `cleanup_incomplete` (`method_changed`) with every entry kept and no drop-in
touched; it changes the `timestamp_timeout` drop-in by hand and removes the `logfile` drop-in, and checks that cleanup
keeps the change as `modified_since_apply` and reports the removed one `restored` without a write.
In the same group, `shared/tasks/lifecycle_sudo_refusals.yml` puts a `timestamp_timeout` of its own into `/etc/sudoers.d` and replaces `/usr/sbin/visudo` with a copy of
`false` (after giving root, which cannot override modes there, the write bit on `/usr/sbin`), and checks
that the rule is `conflicting_setting`, that every other drop-in is `invalid_sudoers` and that nothing was installed or
recorded; and it replaces `/etc/sudoers.d` by a symbolic link and checks that every rule is `not_directory` and nothing
is written through the link. `visudo`, `/usr/sbin`, `/etc/sudoers.d` and its `README` are put back with their content,
mode and ownership, so the whole-instance comparison after the refusals treats them as rewritten (new inodes and times
only). The group `files` runs on Ubuntu only. `shared/tasks/lifecycle_sudo_states.yml` takes the `@includedir` line out of `/etc/sudoers` (`not_included`), removes `visudo` (`validator_missing`),
occupies one drop-in path with a file without the header (`not_owned`) and another with a symbolic link
(`not_regular_file`), and, after an apply, removes the header (`not_owned` at cleanup), records a malformed checksum
(`invalid_record`) and cleans up an attribute entry while `/etc/sudoers` is gone (`target_absent`), each time with
nothing changed and every entry kept. `shared/tasks/lifecycle_sudo_effective.yml` covers the files that
sudo reads: a rule's exact line only in `hardening.conf` or `admin~`, which sudo skips, never makes it `compliant`
(`applied`, and `conflicting_setting` for `timestamp_timeout`), and a `Defaults` line continued with `\` or a linked
drop-in that names an option is `conflicting_setting`, and so is an option right after a full-line comment that
ends in `\`, which sudo does not continue. Every swap of these files is undone in an `always` section, so
a failure does not leave `visudo`, `/usr/sbin` or `/etc/sudoers.d` changed. `shared/tasks/lifecycle_sudo_other_profiles.yml`
(group `profiles`, both platforms) applies, repeats and cleans up for real the
seven native sudo rules that the CIS profiles of the lifecycle do not select (`sudoers_validate_passwd` and the mode,
owner and group of `/etc/sudoers` and `/etc/sudoers.d`), from a loosened `/etc/sudoers` (`0640`) and `/etc/sudoers.d` (`0755`, as Ubuntu ships it): the stricter mode an
administrator sets afterwards is kept as `modified_since_apply`, the recorded `0640` and not a default is restored, and
a directory mode put back by hand is `restored` without a write.

### CI legs

With `file_permissions` (four cycles), `banners` (four cycles) and `pwquality` (two cycles), one lifecycle step per
platform ran ten cycles in a row, and on PR #56 each `molecule-docker` job took 52 minutes on GitHub's `ubuntu-24.04`
runners, past the 30-minute response limit of the merge queue. The job logs at 6628b92 showed where the time went, per
platform: `file_permissions` 11 to 12 minutes, `banners` 18 to 19, `pwquality` 12 to 14 and the pwquality regressions
3 to 4.5, against 5 to 6 minutes for `create` to `verify`. The 18 real scans took under a minute in all and the image
build under half a minute; most of each cycle is remediate runs, check-mode runs and the 76 whole-instance records
(seven to ten minutes of `find` and `stat` over the instance). Every scan backs an assertion of an `audit: true`
pre-state, so none was dropped; the time grows with the number of cycles, and so with every native topic.

The lifecycle therefore runs in CI as one leg per platform, native topic and toggle mode. The `molecule-plan` job runs
`make -s molecule-matrix` (`tools/roles/molecule_matrix.py`), which derives the legs from the catalogue with
`generate_toggles.native_families`, the predicate of the remediation dispatch and of `make lint-lifecycle`, and from
the platforms of `shared/vars/versions.yml`, and prints them as JSON. The `molecule-lifecycle` job runs each leg
(`fromJSON`, `fail-fast: false`) in a fresh container of the `docker-<platform>-lifecycle` scenario, with
`MOLECULE_LIFECYCLE_TOPIC` and `MOLECULE_LIFECYCLE_MODE` set. Each leg runs every declared pre-state of its topic and
mode, the self-checks of the comparisons, the run-time coverage check and the whole-instance comparison, exactly as a
full run does for that topic and mode. No `converge` has scanned a lifecycle instance, so the harness runs one real
scan before it records any state: on Rocky Linux the scanner's first write to the RPM database copies `/var/lib/rpm`
up into the container's writable layer, which gives the directory a new ctime, and without that first scan the
whole-instance comparison of the first topic with a real scan refused it (as it did in the first local run of the
`banners` topic leg). A new native topic gets its two legs per platform without a change to the
workflow, and the tool fails when a platform has no lifecycle scenario. `ci-gate` needs `molecule-plan` and
`molecule-lifecycle`, so every leg is required, on `pull_request` and `merge_group` alike, and a plan that fails or
lists no leg fails the gate.

On GitHub's runners at b1630d8 the twelve legs took 5.5 to 11.6 minutes (the longest is `ubuntu`, `pwquality`,
`rule`, which includes the regressions), the standard scenarios 4.0 and 4.6 and the self-test 2.9; the run took
12 minutes from the first job to `ci-gate`. Each job's `timeout-minutes` is about one and a half times its longest
duration: 18 for `molecule-lifecycle`, 18 for `molecule-docker`, 17 for `test` (11.2) and 16 for `test-playbooks`
(10.8). One [scanner timeout](#scanner-hangs) and its retry add three minutes. `molecule-docker` was raised from 8
on 2026-10-30: over the 15 latest CI runs its successful jobs took 3 to 7.9 minutes, but 7 of 42 were cancelled, and
in job 124055287121 building the Rocky Linux instance image alone took 9 minutes because the package mirror was slow.
Building the instance images once per run and reusing them in every leg is tracked as FREES-182. A leg that
approaches 20 minutes should be split further, for example per pre-state, rather than given a longer limit, so that
no required job comes near the merge queue's 30 minutes. The `test` job, 21 minutes at 6628b92, was split the same way: `test` keeps
the coverage, audit-exception, golden-content and browser tests, and `test-playbooks` runs the check-mode playbooks
(`test-evidence`, `test-remediate-check`, `test-role-guards`, `test-verify`).

With `sudo` (FREES-175) the regressions moved out of the cycle legs: `make molecule-matrix` adds one leg per regression
group that a declaration lists and platform it runs on, with the mode `regressions-<group>`, after the two toggle
modes of the topic, so 16 cycle legs and 7 regression legs (`pwquality` `changes`, `sudo` `changes` and `profiles` on
both platforms, `sudo` `files` on Ubuntu). `tests/unit/tools/test_molecule_matrix.py` checks that every declared group
gets its legs and no libvirt leg, `make lint-lifecycle` checks the groups, and the harness fails a regression leg whose
group did not run. Before the split the `sudo` cycle legs carried up to four minutes of regressions each and took 14 to
19 minutes on slow runners.

### Declaring a topic

Each native topic has exactly one declaration, `extensions/molecule/shared/vars/topics/<topic>.yml`, read with the
`file` lookup as plain data (no Jinja). The declaration of the reference topic:

```yaml
---
family: file_permissions
disruptive: false
audit:
  applied_outcomes:
    - notapplicable
  reason: >-
    ComplianceAsCode limits file_permissions_crontab to the machine platform, which excludes containers, so a
    container audit reports it notapplicable whatever the mode of /etc/crontab.
state:
  files:
    - path: /etc/crontab
  packages:
    - name: cron
      platforms:
        - ubuntu
    - name: cronie
      platforms:
        - rhel_compatible
  users:
    - name: root
  groups:
    - name: root
applied:
  files:
    - path: /etc/crontab
      mode: "0600"
pre_states:
  - name: as built
    audit: true
  - name: customised mode
    audit: false
    files:
      - path: /etc/crontab
        mode: "0640"
```

| Key | Required | Meaning |
|---|---|---|
| `family` | yes | The topic; must equal the file name |
| `disruptive` | yes | Must equal the flag of the family in the registry |
| `containment` | for disruptive topics only | What the topic can break in the container and why the harness still reaches it; see below |
| `state` | yes | The items to record, per category: `files` (`path`), `packages`, `services`, `sysctl`, `users`, `groups` (`name`). Any item may name `platforms` (keys of `shared/vars/versions.yml`); without it the item applies to every platform. A file may set `rewritten: true` when the topic rewrites its content: its inode and mtime are then not compared after a cleanup, everything else is |
| `applied` | yes, with at least one expectation | Expectations after apply, per category, for declared items only: an attribute with its value (for files `exists`, `type`, `mode`, `owner`, `group`, `uid`, `gid`, `inode`, `mtime`, `attributes`, `checksum`, `link_target`; for packages `installed`, `versions`; for services `exists`, `state`, `status`; for kernel parameters `value`; for users and groups `exists`, `entry`), or `changes`, a list of attributes that must differ from before without a fixed value (for example the `checksum` of an owned drop-in). Every attribute that is not named must stay unchanged |
| `audit` | no | `applied_outcomes`: outcomes accepted after apply in addition to `pass` and `fixed`, only `notapplicable`, with a `reason` |
| `pre_states` | no | The states each cycle starts from, each with a unique `name`, `audit` (run real scans in its cycles), `files` (mode, owner or group of declared files), `unchanged` (rules of the topic, by short identifier, that the pre-state already satisfies with the `status` `compliant` or that are `notapplicable`, optionally with `platforms`) and `requires` (the drivers that can set it, see below); the default is the as-built state with scans |
| `unselected_platforms` | no | Platforms whose profile selects no native rule of the topic, each with `platform` and `reason`; it may not list every platform |
| `regressions` | no | Named groups of regression task files, each with a unique `name` (lower case), `files` (file names of `shared/tasks` that `shared/tasks/lifecycle_regressions.yml` includes) and optional `platforms`; each group gets one Docker CI leg per platform, mode `regressions-<name>` |
| `requires` | no | The drivers whose scenarios run the cycles of the topic, `docker` or `libvirt`; without it, the cycles of a pre-state without `requires` run in the Docker scenarios ([driver requirements](molecule-libvirt.md#driver-requirements-of-a-topic)) |

Services can only be recorded where a service manager runs. The containers have no systemd as PID 1, so a declaration
with services fails there with a clear message. A topic whose remediation must write kernel parameters, mounts or
the boot loader cannot apply them in these containers either (see below); its declaration names
`requires: [libvirt]`, so its lifecycle runs in the [libvirt lifecycle scenarios](molecule-libvirt.md) only, and
`make lint-lifecycle` requires that a libvirt lifecycle scenario runs each of its platforms. A pre-state runs with the
drivers it requires, else with those of its topic, else in Docker only, so the virtual machines run only what a
container cannot prove. The `file_permissions` declaration has one pre-state that requires libvirt: an ownership
change, which a container without `CAP_CHOWN` cannot make.

### The coverage gate

No topic can gain a native rule without its lifecycle test:

- `make lint-lifecycle` (part of `make lint` and of the CI `lint` job) runs `tools/roles/check_lifecycle_topics.py`.
  It derives the native topics with `generate_toggles.native_families`, the same predicate as the remediation dispatch,
  and fails when a native topic has no declaration, when a declaration names a topic without a native rule, or when a
  declaration breaks the format above: unknown keys, attributes or platforms, a family or disruptive flag that
  disagrees with the file name or the registry, a disruptive topic without `containment`, an expectation or pre-state
  for an undeclared item, a declaration without an `applied` expectation, an expectation that expects nothing, a
  mode that is not a four-digit octal string, or `unselected_platforms` that list every platform. A container audit
  often reports `notapplicable`, so the state after apply is the positive evidence that the remediation works, and it
  is required.
- `shared/lifecycle.yml` repeats the coverage check at run time, before any topic runs, checks each declaration
  against the registry again, and fails when a platform skips a topic that its declaration does not list under
  `unselected_platforms`, so every lifecycle leg fails too.
- `make molecule-matrix` derives the CI legs with the same predicate, so every topic that `make lint-lifecycle`
  requires a declaration for runs in both modes on every platform; `tests/unit/tools/test_molecule_matrix.py` checks
  that the legs of the repository cover every declared topic.

### Disruptive topics

`pwquality` is the first disruptive family with native rules; the others (`ssh`, `pam`, `sssd`, `sudo`, `faillock`
and the rest that the registry flags) have none yet. A disruptive topic is opted in by its declaration:
`disruptive: true`, which must match the registry, and a `containment` note. The harness then passes `linux_compliance_remediate_allow_disruptive` with
that one family, for that topic's runs only, both for apply and for cleanup (ADR 0011). The breakage stays in the
container:

- The connection is `docker exec` through the Docker API (`community.docker.docker`). It uses neither `sshd`, PAM,
  `sssd`, `sudo` nor a login shell inside the container, so a broken SSH, PAM, SSSD or sudo configuration does not cut
  the harness off. A disruptive topic must still name in `containment` what it can break and why that holds.
- The container is unprivileged, drops every capability, has `no-new-privileges`, no network and no mounts, volumes or
  devices; the guard checked all of it before the first task. A broken service inside it cannot reach the host, and
  nothing in the harness changes those settings.
- After every remediate run the harness re-checks the marker and the missing privileges over the connection, so a
  topic that breaks the connection or the container fails the run at that point instead of producing results from
  somewhere else.
- Disruptive topics run after every non-disruptive topic, and the first failure ends the play (`any_errors_fatal`), so
  a broken container cannot hide a regression in another topic or let a later topic run on a broken instance. In CI
  each topic and mode has a container of its own, so no topic runs after another at all.
- The lifecycle is the last step before `destroy`, which removes only the containers that carry this scenario's
  labels, and runs even after a failure. The container is never reused.

A disruptive topic that cannot be applied meaningfully in a container (boot loader, mounts, kernel parameters,
firewall, auditd) declares `requires: [libvirt]` and runs in the [libvirt scenarios](molecule-libvirt.md), where the
connection is SSH as root to a disposable virtual machine; its `containment` note must then say why a broken SSH, PAM
or network configuration still cannot reach the host.

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

`libvirt-ubuntu` and `libvirt-rhel-compatible` (FREES-61) run the scenarios above, including the toggle lifecycle, in
KVM virtual machines ([libvirt guide](molecule-libvirt.md)). These further scenarios build on them (FREES-62, FREES-63):

- `libvirt-ubuntu-bare` and `libvirt-rhel-bare`: full VM from a bare cloud image.
- `libvirt-negative`: invalid profile, unavailable scanner, bad arguments on a real OS.
- `libvirt-idempotency`: repeated converge with zero unexpected changes on a full system.
- `libvirt-ubuntu-golden` and `libvirt-rhel-golden`: golden images from the manifest.
- `libvirt-baseline-regression`: findings compared with the recorded baseline.
- `libvirt-remediation`: opt-in remediation then verify, including every disruptive family (bootloader, mounts, kernel
  parameters, firewall, network, PAM, SSH, sudo, crypto policy), and the reference rule moving from `fail` to `pass`.
- Any real OpenSCAP scan that depends on the kernel, the boot configuration or systemd services.
