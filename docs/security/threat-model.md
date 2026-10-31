# Threat model

Scope: the `freesecdev.linux_compliance` collection on managed hosts. Audience: reviewers using the `security-review`
skill, and authors of changes that add an asset, trust boundary or entry point. Jira: FREES-134, FREES-138 and
FREES-139 (audit content), FREES-51 (evidence bundles). The
platform-wide threat model (CI, AWS OIDC, supply chain, reporting) is FREES-25; it extends this file and does not
replace these entries.

Each threat names the attacker capability it assumes, the failure, the impact, the mitigation and what is left.
Residual risk that needs further work has a Jira issue; accepting a residual risk is the lead architect's decision and
is recorded on the Jira issue of the change.

## Audit on a managed host

The `compliance_scan` module runs as root (`become: true` on that one task of the `audit` role) and evaluates a pinned
SCAP datastream with `oscap` ([audit guide](../audit.md), [ADR 0004](../adr/0004-audited-process-execution.md),
[ADR 0013](../adr/0013-normalized-findings-model.md), [ADR 0015](../adr/0015-content-acquisition-and-pinning.md)).

### Assets

| Asset | Why it matters |
|---|---|
| Root execution on the managed host | The module and `oscap` run as root; anything they execute or read has full access |
| Integrity of the scan result | A wrong `pass` hides a non-compliant host; findings feed reports and exceptions |
| Availability of the audit | A hung audit blocks the play and leaves the host unassessed |
| Evidence directory | Proof of what was scanned, with which content and tailoring |

### Trust boundaries and entry points

| Entry point | Supplied by | Trust |
|---|---|---|
| `content_path` (the datastream file or its directory) | Operator, through the `discover` role | The path is operator input; the bytes are trusted only if their SHA-256 equals the pin from `content/manifest.yml` |
| `expected_sha256` | The pinned content manifest in this repository | Trusted: reviewed in Git |
| The file system around `content_path`, including symlinks on the way to it | Whoever owns or can write those directories and links | Untrusted unless root-owned and not writable by others |
| Scanner output in the run directory | `oscap` | Untrusted input to the parser (hostile XML, oversized files, symlinks) |
| `/usr/bin/oscap` and its libraries | The distribution package manager | Trusted: root-owned binary in a trusted directory ([ADR 0004](../adr/0004-audited-process-execution.md)) |

### T-AUDIT-1: the datastream is replaced by a FIFO or symlink

- **Attacker:** a local non-root user who can write the directory that holds the datastream, or one of its ancestors,
  who owns the datastream in a sticky directory, or who owns or can replace a symlink on the way to it.
- **Failure:** `xmlsafe.RegularFile` checks the path with `lstat` and then opens it; it cannot use `O_NOFOLLOW` or
  `O_NONBLOCK`, because the repository guard allows only `os.path` in plugins. Between the two calls the user swaps the
  file for a FIFO, and root's `open` blocks. A swap for a symlink makes root copy the link's target.
- **Impact:** the audit, or a discover task under `become`, hangs (availability). There is no wrong result, because every read is hashed and compared with
  the pin, and no disclosure, because a copy that does not match is deleted and only the digest is reported.
- **Mitigation (FREES-134, FREES-139):** before the datastream is opened, `catalog.vetted_content_path` resolves the
  real path once, walking from `/` with `lstat`. It refuses (`unsafe_content_dir`) a component of the resolved chain
  that is not a directory, is not owned by root or is writable by group or others without the sticky bit, a followed
  symlink that is not owned by root (its directory is a component of the resolved chain, so it obeys the same rules),
  more than 40 symlinks (loops), and a datastream that is not owned by root or that is writable by group or others.
  The resolved path is what is hashed, parsed and copied. A root-owned link in a root-controlled directory, such as
  `/opt` to `var/opt` on image-mode RHEL, cannot be repointed by another user and is accepted; FREES-134 refused it.
  Hard links add nothing: owner and mode belong to the inode. Unit tests cover writable, sticky and foreign
  directories, foreign owners of links, directories and the file, links in writable directories, chains through
  writable directories, loops, races, and that a refused path is never opened.
- **Mitigation (FREES-138):** `benchmark_info` and `profile_info` run the same check, from the same code, before they
  open anything, and fail with the same `unsafe_content_dir`. It always applies; the accepted owners are root and the
  user that the module runs as (the owner of `/proc/self`, root if it cannot be read). Under `become` that is root
  only, exactly the audit rules; without it, only the connecting user's own files are added, and that user can only
  stall their own task.
- **Residual:** path-based checks; only root can change a vetted component or a followed link. Root, network and FUSE
  file systems are out of scope ([audit guide](../audit.md#content-directory-rules)).

### T-AUDIT-2: SCE check scripts run as root

- **Asset:** root execution on the managed host.
- **Fact:** the pinned datastreams embed Script Check Engine (SCE) shell scripts. The Ubuntu 24.04 datastream
  (`ssg-ubuntu2404-ds.xml`, SHA-256 in `content/manifest.yml`) has 81. `oscap` 1.3.9 writes them into a new
  `/tmp/oscap.XXXXXX` directory (`mkdtemp`, scripts `0700`, `O_NOFOLLOW`) and executes them as root with a fixed
  `PATH`. It runs SCE only for rules that have no OVAL check, because it uses the last supported check of a rule and
  ComplianceAsCode lists SCE first: 18 rules, 16 of them in `cis_level1_server`. The CI job `oscap-integration`
  asserts that no rule with an OVAL check is evaluated through SCE.
- **Attacker:** whoever can change the content that the scanner reads: the upstream project or its release
  infrastructure, someone who can change the pin in this repository, or a local user who can swap the file.
- **Failure:** a modified datastream carries a script that changes the host, exfiltrates data or persists.
- **Mitigation:** the content is trusted only through its pinned SHA-256 ([ADR 0015](../adr/0015-content-acquisition-and-pinning.md)):
  the archive SHA-512 and the datastream SHA-256 are verified when it is fetched, the module verifies the digest again,
  and `oscap` reads only a private copy in the root-only run directory whose bytes were hashed while they were copied.
  A change of the pin is a reviewed pull request. A local user cannot swap the copy, and T-AUDIT-1 stops a swap of the
  source.
- **Not remediation:** the scripts are XCCDF checks, not `fix` elements. `--remediate` is refused by the process
  policy, so [ADR 0003](../adr/0003-native-module-remediation.md) (no upstream Bash fixes) still holds, and
  `make lint-repo` refuses Python that reads `fix` elements and any committed upstream remediation content
  ([ADR 0025](../adr/0025-own-ansible-remediation-only.md)). ADR 0003 is about
  what changes a host; SCE checks are meant to read it, but nothing technical confines them to reading.
- **Option to disable:** the pinned `oscap` 1.3.9 has no command-line option to disable SCE (the source lines are
  cited in [ADR 0025](../adr/0025-own-ansible-remediation-only.md), Security implications). SCE is the auto-loaded
  plugin `libopenscap_sce.so.25`, shipped in `libopenscap25t64` with the library itself. The undocumented variable
  `OSCAP_CHECK_ENGINE_PLUGIN_DIR` would redirect its `dlopen`, but the process helper does not pass it and redirecting
  root's library loading would add a code-loading path. Without SCE, the 16 SCE-only rules of `cis_level1_server` are
  `notchecked` (13 firewall rules and 3 file-system-wide ownership and permission rules); the other 392 rules are
  unaffected. An operator who does not want to run any SCE script can list those rules in `disabled_rules`: the
  tailoring file deselects them, their scripts do not run, and they are reported as `disabled`. That is not the
  default, so the owner's requirement that ComplianceAsCode code never runs is not yet met for SCE;
  [FREES-191](https://vidlunnia.atlassian.net/browse/FREES-191) tracks it.
- **Residual:** the pinned content and its 81 scripts are trusted as a whole, like the OVAL definitions, which
  `oscap` also evaluates as root. A content update is therefore a change to code that runs as root: its review covers
  the SCE scripts that changed, not only the digest.

## CI-only SCC image

FREES-144 builds a CI image with the SCAP Compliance Checker (SCC) from NIWC Atlantic, which runs as root
([ADR 0019](../adr/0019-scc-scanner-backend-and-ci-image.md)). The image is built on the GitHub-hosted runner, used
by the `scc-smoke` job and never published.

### T-SCC-1: a tampered SCC bundle runs in CI

- **Asset:** the CI runner and its job token (read-only `contents`), and the integrity of later SCC results.
- **Attacker:** whoever controls the DISA download host or the path to it, or can write the Actions cache of this
  repository.
- **Failure:** a modified bundle installs a backdoored `cscc`, or the image is built from something other than the
  reviewed release.
- **Mitigation:** `tools/scc/fetch-scc.sh` accepts only HTTPS URLs on `dl.dod.cyber.mil`, follows HTTPS redirects
  only, caps the size and requires the pinned size and SHA-256 of the bundle. It requires that the published checksum
  file lists the same bundle and `cscc` digests, and checks the pinned SHA-256 of the Debian package that it extracts
  by exact member name. The build runs with `--network none`, checks the package digest again, and checks the installed
  `/opt/scc/cscc` against the published digest. A cached bundle is used only after its SHA-256 matches the pin. A pull
  request from a fork neither restores nor saves the cache (FREES-155): the cache step runs only when the event is
  not `pull_request` or the head repository is this repository and not a fork. A pin change is a reviewed pull
  request. The job has `contents: read` and no secrets.
- **Residual:** the checksum file comes from the same host as the bundle, so a compromise of that host before the pin
  is set is detected only if the reviewer checks the release against NIWC's release record. Only `cscc` has a
  published per-file digest; the bundled interpreter, libraries and content are trusted through the bundle and package
  digests. The package's maintainer scripts run as root in the build container.

### T-SCC-2: the SCC image or bundle is redistributed

- **Asset:** compliance with the no-redistribution rule.
- **Failure:** a workflow or recipe pushes the image, uploads the bundle as an artifact, or a bundle, package, binary
  or checklist is committed.
- **Mitigation:** the image carries only a `localhost/` tag. `tests/unit/tools/test_scc_image.py` fails if:
  - an SCC identifier (the image name, the SCC paths, `cscc`, an `SCC_*` variable or an `scc-*` target) appears
    outside the allow-list. The allow-list is:
    - the `scc-changes`, `scc-smoke` and `ci-gate` jobs, and the `scc-release-watch` job of its own workflow
      (FREES-176);
    - the SCC variables and targets of the Makefile;
    - `tools/scc/` and `extensions/ci/scc/`;
    - documentation and tests.

    This covers a workflow-level `env`, another job, another target, an indirect variable and a new script.
  - a tracked file that names an SCC identifier, or any file under `tools/scc/` or `extensions/ci/scc/`,
    contains a push, login, save or export command. This covers scripts, Makefile fragments, test modules under
    `tests/` and, since FREES-155, Markdown. A Markdown file that must show such a command needs a reviewed
    `ACCEPTED_PUBLISHING_MARKDOWN` entry of its path and the SHA-256 of its exact content, so any later change
    fails again. Only the guard module is exempt. The check joins line continuations and collapses whitespace,
    quotes, commas and brackets first, so a command split over several lines, for example a ruff-formatted
    argument list or a continued shell command, is caught too (FREES-155);
  - the Makefile includes any file other than `$(SCC_PINS)` that is untracked, computed, or breaks the same rules;
  - something loads or runs a Markdown file as code (FREES-152, kept as defence in depth by FREES-155):
    - the Makefile or an included file uses `$(eval`, `$(file`, `MAKEFILES`, `GNUMAKEFLAGS`, `.INCLUDE_DIRS` or
      `--eval`;
    - a workflow, at any level, or an SCC file names `MAKEFILES`, `MAKEFLAGS`, `GNUMAKEFLAGS`, `.INCLUDE_DIRS`
      or `--eval`;
    - a Makefile line, workflow string or SCC file runs a `.md` file with a shell, `.`, `source`, `make -f` or a
      script interpreter, directly, by redirect or through a pipe;
  - an SCC job uses a publishing action or widens its permissions beyond `contents: read`, or, for
    `scc-release-watch` only, beyond exactly `contents: read` and `issues: write`;
  - a tracked file looks like an SCC bundle, package, binary or checklist (plain, compressed, base64 at any alignment,
    or hexadecimal) or has a pinned SCC digest.

  The release workflow (ADR 0012) may still publish the collection, because it cannot name the SCC image. `.gitignore` ignores the package
  and checklist types, and `galaxy.yml` excludes `extensions/ci` from the collection.
- **Residual:**
  - The Actions cache holds the verified bundle. It is readable only by workflow runs of this repository, which
    the licence permits (ADR 0019). A pull request from a fork is also a run of this repository, but its workflow
    code is the fork's, and with the approval policy `first_time_contributors` a returning outside contributor's
    run starts without approval. Such a run could read the cached bundle, so the cache step is skipped for fork
    pull requests and they download from DISA themselves (FREES-155). This adds no capability either way, because
    the bundle is a public DISA download; it keeps the cache for this repository's own code.
  - The Markdown execution check is word-level. A command assembled from variables, a renamed copy, a glob or
    `find -exec` evades it; that is deliberate evasion, which review catches. Since FREES-155 it is a second line:
    a Markdown file that names SCC cannot hold a publishing command unless its exact content is accepted.

### T-SCC-3: an SCC change skips the smoke test

- **Asset:** the guarantee that every change to an SCC input is built and run before it merges.
- **Attacker:** the author of a pull request that changes an SCC path.
- **Failure:** the `scc-changes` filter reports `scc=false` for an SCC change, so `scc-smoke` is skipped and
  `ci-gate` accepts the skip. Examples are a rename out of an SCC path, a pull request that edits the filter to
  print `false`, or a filter output or event name that only partly matches.
- **Mitigation (FREES-152):**
  - The filter diffs with `git diff --no-renames`, so a rename lists the old path.
  - For `pull_request` and `merge_group`, the job runs the base revision's copy of the filter (`git show` of the
    validated base SHA into a temporary file, run with `bash`, never sourced). A filter change takes effect only
    after it merges.
  - A missing base file, a failing `git show` or filter, and any output other than exactly `false` give
    `scc=true`.
  - `ci-gate` matches the filter output and the event name exactly with jq `IN`, not with the substring-based
    `inside()`.
  - The push run on `main` and the daily schedule always run the smoke test.
- **Residual:** the step script that fetches the base filter, and `ci-gate` itself, are in `ci.yml`, which the
  pull request controls. Editing them is a change to a workflow, which is an SCC path, and is caught by review.
  The first push run on `main` after the merge runs the smoke test regardless.
- **Expiry skip (FREES-176).** After the hard stop, while no newer pin exists, `ci-gate` also accepts a skipped
  `scc-smoke` for a pull request or merge group whose `scc-changes` output is exactly `expiry=expired`
  ([ADR 0019 amendment](../adr/0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-30-release-watch-and-expiry-fallback-frees-176)).
  - **Failure:** a pull request fabricates an expiry to skip its own smoke test.
  - **Mitigation:** the output comes from the base revision's `tools/scc/expiry-state.sh` and pins, run as a
    separate `bash` process. It is `expired` only when the base and the head `scc.pins` are byte-identical and both
    are past the hard stop, and anything unexpected gives `current`. A pull request that changes any pin (the version,
    `SCC_EXPIRES`, the bundle, deb or `cscc` SHA-256, a size, or the content file or its SHA-256) or edits the script is
    therefore smoke-tested. `ci-gate` matches `current` and `expired` exactly, names
    the skip in a warning annotation, and never accepts it on `push`, `schedule` or dispatch.
  - **Residual:** while the skip applies, an SCC change merges without a real SCC scan. The pull request that bumps
    the pin runs `scc-smoke` and `scc-integration` on a merge commit that holds every such change, before it can
    merge. Meanwhile `main` and the release watch fail every day.

### T-SCC-4: off-platform checks run on another release

- **Asset:** root execution on an Ubuntu 26.04 managed host, and the meaning of its results.
- **Fact:** with `allow_off_platform_benchmark`, the per-run options set SCC's `ignoreCPEOVALResults`. SCC then
  evaluates the pinned Ubuntu 24.04 stream on a 26.04 host although the stream's CPE-OVAL platform test does not
  match ([ADR 0019](../adr/0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-26-off-platform-opt-in-for-ubuntu-2604-frees-161)).
  The stream includes NIWC shell-command checks, which SCC runs as root. SCC warns that results may be incomplete or
  false positives.
- **Attacker:** whoever can change the pinned stream, as in T-AUDIT-2. The setting adds no content and no network
  path. It also opens no way to switch it on for another host: it is written only for the one allowed pair, and the
  confirmation refuses it on every other run.
- **Failure:** a 24.04 check misreads a 26.04 host. Or a run with the platform test ignored is read as compliance of
  the host.
- **Mitigation:**
  - The setting is written only for the allowed pair.
  - The confirmation requires SCC's options dump to show it as `1` exactly then and as `0` for every other run, and
    `saveResultsForNotApplicableContent` as `0` for every run.
  - The module compares the asserted release with the host's `/etc/os-release`, or `/usr/lib/os-release` when that is missing (`host_mismatch`, also when neither exists). Below that, SCC's
    own CPE platform test still stops an unmarked scan of a 26.04 host claimed as 24.04, which the integration case
    proves.
  - Raw copies are named `*.off-platform.xml`. The report refuses them and any XCCDF or ARF next to a marked
    `scan-run.json`, and a host with only an off-platform scan is not covered in a fleet report.
  - The report parsers also read the content (FREES-164): SCC results whose `TestResult` lists none of the benchmark's
    operating system platforms are refused, so a copy taken out of its bundle is refused too.
  - Retrieval stays confirmed off, and the egress test covers it.
  - Every result carries the off-platform marker. Reports keep marked results out of every figure, and FREES-147
    maps them to Not Reviewed.
  - A run that is mostly `notapplicable` is failed.
- **Residual:**
  - The same signed checks that run as root on 24.04 run on 26.04. A check that behaves differently on 26.04 can
    report a wrong outcome, which the marker and the exclusion from figures contain but do not prevent.
  - `/etc/os-release` is written by the host itself, so the release check binds the caller's claim to the host's own
    claim, not to an independent fact.

### T-SCC-5: the release watch is abused

- **Asset:** the repository's issues, and the `issues: write` token of the `scc-release-watch` job.
- **Attacker:** whoever controls NIWC's release record or the network path to it.
- **Failure:** a hostile record makes the watch open many issues, plant links or mentions in them, or fetch
  something else; or a pull request obtains a token that can write issues.
- **Mitigation (FREES-176):** the watch fetches one fixed HTTPS URL with a verified certificate, no redirects, a
  timeout and a 64 KiB bound, parses it with the hardened XML reader, and accepts only a strictly formed version and
  time stamp. No free text of the record reaches an issue. Each finding has one body marker, and the watch reopens
  an existing issue instead of creating another, so a changing record yields at most one issue per distinct
  version. The job runs only on `schedule` and dispatch on `main`, with `contents: read` and `issues: write` only,
  and the never-publish guard refuses `issues` on every other job. The token is sent only to `api.github.com`.
- **Residual:** a hostile record can still open one issue for each version it names, which stays open while the
  record names that version, and it can hide a real release by naming the pinned version. A hostile or wrong record
  can also close an open, genuine `scc-release` issue by naming the pinned version or another one (`close_stale`,
  `tools/scc/release_watch.py:507`); the issue reopens once the record is right again. NIWC's README and the DISA
  host remain the other sources, and the expiry issue and the hard stop do not depend on the record.

## SSH server remediation on a managed host

The `ssh` family of the `remediate` role writes sshd drop-ins and changes conflicting lines of the vendor files
`/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/50-redhat.conf`, and the module `sshd_validate` runs `sshd -t` as
root through the audited process helper ([ADR 0023](../adr/0023-native-ssh-server-configuration.md),
[ADR 0004](../adr/0004-audited-process-execution.md), FREES-109).

### Assets

| Asset | Why it matters |
|---|---|
| Remote access to the host | A wrong or refused sshd configuration locks out every operator who logs in over SSH |
| Root execution of `sshd -t` | The helper runs `/usr/sbin/sshd` as root; it reads every included file and the host keys |
| The vendor files and their recorded lines | The collection changes package-owned files and must restore them exactly |

### Trust boundaries and entry points

| Entry point | Supplied by | Trust |
|---|---|---|
| `/usr/sbin/sshd` | The distribution package manager | Trusted: resolved only in the trusted directories, root-owned and not writable by group or others; anything else fails the module |
| The `-o` settings of `sshd_validate` | The catalogue values and the profile values generated from the pinned content | Checked twice: by the family (keyword and one-word value) and by the helper's policy (`option_values`, 28 keywords) |
| `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` | Root, packages, administrators | Read as data; a symbolic link or non-regular file is never written through |
| `linux_compliance_remediate_allow_disruptive` | The operator | The acknowledgement that the topic may change and revert sshd settings |

### T-SSH-1: the ssh topic locks operators out

- **Attacker:** none; an operator applies a profile whose settings (`PermitRootLogin no`, `MaxAuthTries`, algorithm
  lists) do not suit how the host is reached, or a configuration that sshd refuses is installed.
- **Failure:** sshd refuses the configuration at the next start or reload, or rejects the operators' logins.
- **Impact:** loss of remote access to the host.
- **Mitigation:** the family is disruptive and runs only with `ssh` in the allow-list, for apply and cleanup alike.
  Every change is validated with `sshd -t` on the whole effective configuration before anything is written; when sshd
  refuses, nothing is installed. After the changes `sshd -t` runs again; when it refuses, the run rolls back what it
  created and fails without reloading. sshd is reloaded, never restarted, and only where `service_facts` reports it
  running, so open sessions, including the controller's, continue. A run that applies `PermitRootLogin no` or
  `prohibit-password` while it reaches the host over SSH as root prints a warning. Check mode reports every change and
  changes nothing.
- **Residual:** the settings themselves are the profile's; a profile that forbids root logins locks out an operator who
  has no other account. The rollback restores drop-ins and vendor lines that the run created, not a drop-in that it
  rewrote for a changed value; what a cleanup removed stays removed, which is the prior state. On a host without sshd
  the configuration after a cleanup is not validated, because there is nothing to validate it with. Containers cannot show a real login; the libvirt scenarios (FREES-61) are needed for
  that.

### T-SSH-2: `sshd -t` is turned into something else

- **Attacker:** a caller of the helper or of `sshd_validate` who controls the settings, or a local user who can place a
  file where sshd is resolved.
- **Failure:** sshd runs in another mode (`-D`, `-T` with a connection specification, `-E` writing a log file), reads
  another configuration or host key, or runs a command (`AuthorizedKeysCommand`).
- **Impact:** a daemon started as root, a file written as root, or a command run as root.
- **Mitigation:** the helper's policy fixes the prefix `-t -f /etc/ssh/sshd_config` and accepts after it only `-o`
  followed by one `<Keyword>=<value>` with a keyword of the native rules and a one-word value; every other option and
  positional argument is refused before anything runs. In test mode sshd does not run `AuthorizedKeysCommand` or start
  a listener. The executable is vetted like `oscap`; the environment is fixed and the run has a timeout and bounded
  output.
- **Residual:** sshd still reads every file that the configuration includes and the host keys, as root; a malicious
  include is already a root compromise of the configuration.

### T-SSH-3: a revert overwrites an administrator's change

- **Attacker:** none; an administrator changes a drop-in or a vendor line after the collection changed it.
- **Failure:** cleanup removes or rewrites the administrator's line.
- **Impact:** a deliberate site setting is silently lost.
- **Mitigation:** cleanup removes a drop-in only with the recorded SHA-256 and writes a vendor line back only when the
  file still sets the keyword on exactly the line written; otherwise the result is `cleanup_incomplete` with
  `modified_since_apply`, nothing changes and the ledger entry is kept. A line that already equals the recorded
  original is left alone.
- **Residual:** a package update that rewrites a vendor file also stops the revert, which then needs a review.

## auditd settings and audit rules on a managed host

The `auditd_conf` and `auditd_rules_time` families of the `remediate` role write `/etc/audit/auditd.conf` and drop-ins
below `/etc/audit/rules.d`, and the module `audit_control` runs `auditctl` and `augenrules` as root through the audited
process helper ([ADR 0030](../adr/0030-native-auditd-settings-and-audit-rules.md),
[ADR 0004](../adr/0004-audited-process-execution.md), FREES-110).

### Assets

| Asset | Why it matters |
|---|---|
| The loaded audit rules | A rule set that loads only in part silently stops recording everything after the first error |
| The audit daemon's configuration | A setting that auditd refuses keeps it from starting at the next boot; a disk action can halt the host |
| Root execution of `auditctl` and `augenrules` | They change the kernel's audit state |

### T-AUDIT-1: a change leaves the rule set half loaded or auditd unable to start

- **Attacker:** none; a repeated rule, a watch below a missing directory, or an administrator's broken file.
- **Failure:** `auditctl -R` stops at the first error and every later rule is unloaded; or auditd refuses its
  configuration at the next start.
- **Impact:** audit events are lost without notice, or the host runs without auditd.
- **Mitigation:** every rule line has a strict form without control lines; a rule whose lines another file holds in
  part is refused before anything is written; the module refuses to load a set with a repeated rule; after the load
  every applied line is checked with `auditctl -l`, and a refused or failed load rolls back the drop-ins and ledger
  entries of the run, loads the set again and fails the run. The settings that auditd checks together are computed as
  they will be after the run and refused as a whole when auditd would refuse them; the line always has the spaces
  around `=` that auditd requires.
- **Residual:** two rules that differ only in a spelling the normalisation does not cover are found only by the load,
  which is then rolled back; a broken rule of an administrator makes every load fail until it is fixed. auditd has no
  configuration test, so a check that the collection does not know about is not made.

### T-AUDIT-2: the audit tools are turned into something else

- **Attacker:** a caller of the helper or of `audit_control`.
- **Failure:** `auditctl` deletes rules (`-D`), unlocks or disables auditing (`-e 0`), sets the failure mode
  (`-f`), or loads an arbitrary rule file (`-R`).
- **Impact:** auditing switched off as root.
- **Mitigation:** the helper's policies accept only the exact forms `auditctl -s`, `auditctl -l`,
  `auditctl --signal reload` and `augenrules --load`; no argument comes from a variable. The executables are resolved
  in the trusted directories, root-owned and not writable by group or others.
- **Residual:** `augenrules --load` loads whatever `/etc/audit/rules.d` holds, as auditd does at boot; a root-owned
  malicious rule file is already a root compromise.

### T-AUDIT-3: a disk action of the profile halts the host

- **Attacker:** none; a profile requires `halt` or `single` when the audit log fills or fails.
- **Failure:** the host stops or drops to single-user mode when the disk fills.
- **Impact:** loss of service.
- **Mitigation:** `auditd_conf` is disruptive and runs only with the allow-list, for apply and cleanup; an alternation
  of the profile is written as its least disruptive choice (`syslog`, `email`, `single` before `halt`).
- **Residual:** a profile that allows only `halt` gets `halt`, as its benchmark requires.

## Libvirt CI caches

The `molecule-libvirt` legs of `ci.yml` restore two Actions caches whose contents are installed or booted:
`build/molecule-libvirt/host-packages`, the QEMU and libvirt packages that are installed as root on the runner
(FREES-180), and `build/molecule-libvirt/cache`, the cloud images and the scanner packages that are booted and
installed in the test virtual machines (FREES-61)
([libvirt guide](../molecule-libvirt.md#host-packages-of-the-ci-runner), [ADR 0009](../adr/0009-molecule-layout-and-drivers.md)).

### T-LIBVIRT-1: a tampered cache entry is installed or booted

- **Asset:** the GitHub-hosted runner, its job token (read-only `contents`), and the integrity of the libvirt scenario
  results that gate merges.
- **Attacker:** whoever can write an Actions cache entry of this repository (a workflow run of this repository,
  including a pull request from a branch of it), or controls the Ubuntu snapshot, the cloud image hosts or the path to
  them.
- **Failure:** a modified `.deb` runs its maintainer scripts as root on the runner, or a modified image or scanner
  package changes what the virtual machine proves.
- **Mitigation:** every file is checked against a SHA-256 and size pinned in a reviewed file of this repository (`tools/molecule/libvirt-host.pins`,
  `extensions/molecule/shared/images/cloud-images.pins`) after it is restored and before it is used:
  `tools/molecule/libvirt-host-packages.sh` checks every host package in place, copies the ones it installs with
  `sudo install -o root -m 0644` into a private directory of root in the sticky `/tmp`, checks the copies there as root
  and installs only those, with `apt-get` given no package source so that it can
  neither download nor install anything else; `fetch-cloud-images.sh` checks every image and package, and
  `create_libvirt.yml` and `prepare` check them again before use. A file that fails is downloaded again from the
  pinned HTTPS source and checked once more; a symbolic link or a planted file of another name is never used. The
  host package pins come from the signed index of the snapshot, the image pins from the vendors' signed checksum
  files. A pull request from a fork neither restores nor saves either cache, as for SCC (T-SCC-1). The install
  refuses to run outside a GitHub-hosted runner.
- **Residual:** the checks catch a corrupt or stale entry, which then costs only a download. They do not stop a crafted
  entry: `actions/cache` (v6.1.0) extracts a restored entry with `tar -xf … -P`, which keeps absolute and `../` member
  names, so an entry can write any file the runner user can write, `tools/molecule/*.sh` and the `Makefile` included,
  before the checks run. The boundary is who can write an entry in a scope that a run restores; see T-MOLECULE-1,
  which applies to these caches too. A pin change is trusted through review: a reviewer who
  accepts a wrong digest accepts the file. The runner image itself, and the packages that it already has in the
  pinned version or later, are trusted as the runner is. No update bot refreshes the pins (FREES-81). The runner user has passwordless
  `sudo`, so no privilege boundary separates it from the install; the root-owned copies only close the window in
  which a process of that user could swap a checked copy before `apt-get` reads it.

## Molecule CI inputs

The `molecule-images` and `molecule-collections` jobs of `ci.yml` prepare the Docker instance images and the Galaxy
collections once per run (FREES-182, FREES-184). They restore two kinds of Actions cache: `build/molecule-images/<image>`
(the archive of an instance image, key `molecule-image-<image>-<tag>-<ISO week>`) and
`build/molecule-collections` (the collection artifacts, key `galaxy-collections-<hash of the pins>`). They pass on two
run artifacts, `molecule-images` and `molecule-collections`, which every Docker leg, every libvirt leg and `lint`
download ([Molecule guide](../molecule.md#images-and-collections-built-once-per-run),
[ADR 0009](../adr/0009-molecule-layout-and-drivers.md)).

### T-MOLECULE-1: a planted cache entry or artifact changes what the Molecule legs prove

- **Asset:** the integrity of the Molecule results that gate merges. The jobs hold `contents: read` and no secrets, so
  no credential or write token is reachable.
- **Attacker:** whoever can write an Actions cache entry in a scope that a run restores. A pull request from a branch
  of this repository writes only to its own `refs/pull/<n>/merge` scope, which only that pull request reads. A
  `merge_group` run reads its queue ref and `main`. A `main` entry can be written by any code that runs in any
  workflow run on `main` (push or schedule), for example a compromised pinned dependency that reaches the runtime
  token; it takes no push to `main`. Such a writer can plant an entry under a key that has not been written yet, or
  after the original was evicted (seven days without use, or the 10 GB limit).
- **Failure:** `actions/cache` (v6.1.0) restores with `tar -xf … -P`, which keeps absolute and `../` member names, so a
  crafted entry can write any file the runner user can write, `tools/molecule/instance-images.sh`,
  `tools/molecule/galaxy-collections.sh` and the `Makefile` included, before the job's checks run. Or it simply holds
  an image with the right label on the pinned base layers and other layers on top. `molecule-images` then publishes
  that image and its ID, and every Docker leg that loads it, on `main`, in the merge queue and in pull requests,
  accepts it while the key lasts; a planted collection is installed the same way.
- **Mitigation:**
  - The checks in the job are corruption and staleness checks, not a boundary against a cache writer. A collection
    file must match the SHA-256 and size of `extensions/molecule/collections.pins`. A restored image must carry
    `org.freesecdev.molecule.inputs=<tag>` on exactly the layers of the base pulled by digest, and its archive must load
    that one image and nothing else. Unlike the collections and the libvirt files, **the image cache has no content
    pin**: builds are not reproducible, so a matching label on the base layers says nothing about the layers on top.
  - The image cache key carries the ISO week of the run, so a planted image entry is restored at most until the week
    ends; a scheduled run never saves an image entry, and a push to `main` saves one only on a miss.
  - The job always writes the archive it shares anew from the verified image, so the legs never receive
    the cache's bytes, and a leg refuses an archive that loads any other image.
  - A pull request from a fork neither restores nor saves these caches, as for SCC (T-SCC-1).
  - Within a run, `actions/download-artifact` checks each artifact's digest, every Docker leg checks each image ID
    against the job output of `molecule-images`, which no other job can change, and every consumer of the
    collections checks every file against the pins again. Every job of a run executes the same commit, so another job
    of the run adds no trust beyond that commit's.
- **Residual:** a writer of the `main` cache scope gets arbitrary file writes in every job that restores a cache of
  this repository (SCC, libvirt, images, collections), and with the image cache can make the Docker legs pass or fail
  at will until the week's key changes. The real boundary is write access to the `main` cache scope. Owner: the lead
  architect, whose acceptance is recorded on FREES-182 (raised in the review of PR #71). Restoring the image cache only in `pull_request` and `merge_group` runs, or dropping
  it (a hit saves about 24 seconds), remain options if that boundary weakens.

## Report inputs on the controller

`tools/reporting` turns operator-supplied files into the normalized report and the dashboard
([reporting data model](../reporting-data-model.md), [ADR 0016](../adr/0016-report-schema-and-summary-semantics.md)).
This section covers the two entries that FREES-130 and FREES-132 changed; the rest of the reporting threat model is
part of FREES-25.

### T-REPORT-1: a forged scan run raises a host's figure

- **Attacker:** anyone who can add a file to the report inputs, for example a ScanRun JSON with the host name and
  machine ID of a real host (a machine ID is not a secret).
- **Failure:** runs of one host and benchmark version were merged rule by rule; the forgery adds passing rules that
  the real run did not evaluate (0.0 to 99.0 percent in the FREES-130 probe). With the profile outside the key, a
  forgery that only changed `profile_id` did the same, and an honest CIS and STIG run were pooled into one number.
- **Mitigation (FREES-130):** every figure key includes the profile, so a run of another profile is its own group
  and cannot change the real run's figure. A second completed ScanRun in the same group (host, benchmark, content
  version, profile) is refused unless `--allow-repeated-scans` is given, and every group built from more than one
  input carries a `merged_inputs` note that the dashboard shows. An XCCDF target and fqdn fact that disagree are an
  input error.
- **Residual:** a forged run with another profile appears as an extra group for the host, and a self-asserted XCCDF
  file of the same profile is merged with a visible note; neither is detected as forged. Signed evidence bundles
  ([ADR 0018](../adr/0018-evidence-bundle-provenance.md), proposed) are the fix.

### T-REPORT-2: an edited exceptions evaluation hides a failure

- **Attacker:** anyone who can change an evaluation document between the `apply_exceptions` filter and the report.
- **Failure:** a status, mark or count is changed so that a failure reads as waived or an expired waiver as in effect.
- **Mitigation (FREES-132):** the report requires the exceptions file (`--exceptions-file`) and
  `exceptions.verify_evaluation` checks every evaluation against it: same SHA-256, a valid file, and a new evaluation
  of the scan run with that file equal to the document. Anything else, including an evaluation built consistently
  from a made-up exceptions file, is an input error, never a waiver. Justification text is rendered with DOM text
  APIs only.
- **Residual:** the exceptions file is trusted because it is reviewed in Git; whoever can merge it can waive failures.
  A waived finding inside a plain ScanRun JSON has no exceptions file to check against. ADR 0018 proposes signed
  evidence for both.

## Evidence bundles on the controller

The `evidence` role fetches the audit evidence of each host into a bundle on the controller, and the report reads
bundles with `--evidence-bundle` ([evidence bundles](../evidence.md)).

### T-EVIDENCE-1: secrets leak into a bundle

- **Asset:** credentials and other secrets on the host, in the play and on the controller.
- **Attacker:** anyone who later receives the bundle (an auditor, a ticket, an artifact store).
- **Failure:** the bundle copies the environment, facts, `no_log` values, the state ledger with its sensitive prior
  values, or scanner output that holds collected file contents.
- **Mitigation (FREES-51):** the documents are built only from the fetched files, the re-verified evaluation, the
  exceptions file and the stale result; no fact or variable is dumped, only the machine ID is taken from facts, and the
  skeleton option to include host facts is removed. Only four file names directly inside the run directory are
  fetched; a recorded path outside it fails the host. The ARF results, which hold OVAL system characteristics such as
  matched lines of `/etc/shadow`, are excluded unless `linux_compliance_evidence_include_arf` is set. `make
  test-evidence` plants an environment variable, a `no_log` fact, a ledger with a sensitive value, an unlisted file and
  a shadow-like ARF line and checks that none reaches a bundle or the output.
- **Residual:** `results.xml` is copied verbatim: it carries the target facts (host names, every IP and MAC
  address) and the standard output of the SCE check scripts (firewall rule dumps, listening ports, lists of
  world-writable, unowned or privileged files). `make test-evidence` shows that these are carried. The exceptions file
  names owners and approvers. With the ARF opt-in a bundle can hold password hashes. Bundles are `0600` in `0700`
  directories of the controller user; share them like the report.

### T-EVIDENCE-2: a host or a file on the way changes the evidence

- **Attacker:** a local user on the host between the audit and the fetch, the transport, or a compromised host.
- **Failure:** the controller collects different bytes than the audit recorded, or a different file.
- **Mitigation (FREES-51):** every fetched file must have the SHA-256 and size that the audit module recorded, the
  fetched `scan-run.json` must be the scan run of the fact, and the evaluation must verify against the byte-exact
  exceptions file and must have been made from the raw scan run. Any mismatch fails the host and removes the bundle.
  Before anything is transferred, each file is inspected on the host with `stat` and `follow: false`: a symbolic link,
  a special file or a size other than the recorded one (bounded at 256 MiB) refuses the host, so the fetch never
  follows a link as root and never copies an oversized file. The audit evidence is root-owned `0600` in a root-only
  `0700` run directory, so only root can change it on the host.
- **Residual:** the recorded digests come from the host. A compromised host can return consistent lies; the checks
  bind the bundle to what the audit module reported, not to the truth about the host. This is out of scope for any
  controller-side check (ADR 0018 states the same for signatures).

### T-EVIDENCE-3: a bundle is edited after it was written

- **Attacker:** anyone who can write the bundle directory or a copy of it before it reaches the report.
- **Failure:** a finding, waiver or digest is changed so that the report shows a better result.
- **Mitigation (FREES-51):** the report reads the bundle without following links, refuses unlisted files, special
  files and unexpected directories, and verifies every size and SHA-256, `SHA256SUMS`, the scan run against the
  manifest and the evaluation against the bundled exceptions file and the raw scan run. A partial edit is an input
  error. A file that looks like a signature is refused, never ignored. A bundle with applied exceptions requires
  `--exceptions-file`, and its copy must be byte-identical to it, so a bundle forged consistently from a made-up
  exceptions file cannot turn a failure into a waiver (PR #31 review, B1).
- **Residual:** the bundle is not signed. Whoever can rewrite every file and digest consistently can forge the scan
  run of a bundle that verifies (with no waiver the reviewed file does not grant); the report labels nothing as
  verified. Signed bundles are FREES-140 ([ADR 0018](../adr/0018-evidence-bundle-provenance.md), proposed).

### T-EVIDENCE-4: the hosts that matter most have no bundle

- **Attacker:** none; the failure is the play's own control flow.
- **Failure:** the failure gate, or a scan that did not complete, fails a host in the audit play, Ansible drops it from
  every later play, and a collection play never sees it. A report over the bundles then covers only compliant hosts
  and its fleet figures are inflated, with nothing saying that hosts are missing (PR #31 review, B2).
- **Mitigation (FREES-51):** `playbooks/evidence.yml` audits with the audit role's `deferred.yml` entry point, then
  enforces the gates with `enforce.yml` in a `block` whose `always` section collects the evidence, so every audited
  host is collected (failed rules and incomplete scans included) and the gates still fail the same hosts and the
  play. It names every target host without a bundle with the reason (no audit result, no evidence written, collection
  failed). The deferral is chosen only by the entry point: no variable defers a gate (the round 2 review found that a
  public `linux_compliance_audit_defer_gate` failed open, B3, and it was removed). The bundle records the gate
  (`deferred`, `enforced` and the decision); the evidence role refuses a deferred gate that was not enforced and the
  report refuses a manifest without an enforced gate. `tests/playbooks/evidence-gate.yml` shows a gated host and an
  incomplete scan collected, an unreachable and an empty host named, and the play failing;
  `tests/playbooks/audit-gate-routes.yml` shows that the removed variable and a forged internal one, set with `-e`,
  `group_vars`, `host_vars`, an include parameter or a role import parameter, do not defer the gate.
- **Mitigation (FREES-142):** the run writes a collection summary that names every target host with its status
  (`collected`, `unreachable`, `limited_out`, `no_audit_result`, `no_evidence_written`, `collection_failed`) and the
  manifest SHA-256 of every bundle, and no host fails before it is written, so a run in which every host fails still
  names the unreachable one. The report built with `--evidence-collection` refuses a bundle that the summary does not
  list, lists every target host without a bundle as a missing input, has no figure while a host is missing and exits
  1. Without the summary the report labels its host coverage `unknown`.
- **Mitigation (FREES-154):** `--require-host-coverage` makes the report exit 1 unless its host coverage is
  `complete`, so a pipeline that gates on the exit status also fails when the summary was not supplied (`unknown`);
  the fleet workflow and `make test-evidence` use it. A host is `collected` only on the strength of an internal marker
  that the evidence role sets after it wrote and re-hashed the bundle in this run; a `linux_compliance_evidence_bundle`
  planted through the inventory, `group_vars`, `host_vars` or `-e` for a host whose collection failed leaves it
  `collection_failed`, and the last play fails it. `reached.yml` refuses the run at the start of the audit play when
  any `__linux_compliance_evidence_*` variable is already in `hostvars` of an inventory host or `localhost`, which is
  where an extra variable, an inventory value or a fact cache would put a forged marker; the condition uses only
  `groups`, `hostvars` and literals, as the FREES-150 Molecule guard does. `make test-evidence` plants the public
  fact in the inventory and with `-e`, and the marker itself with `-e` and in the inventory of an unreachable host.
- **Residual: the collection summary is unsigned until ADR 0018 (FREES-140).** The summary is what tells the report
  which hosts to account for, and nothing proves who wrote it. Whoever can write the evidence directory can rewrite
  the summary consistently so that it lists fewer target hosts, and remove or keep the bundles to match: every
  report built from it then has `complete` coverage, figures over the remaining hosts and exit status 0, also with
  `--require-host-coverage`, and the dropped hosts are not named anywhere in it. The report cannot detect this; it is
  the same trust boundary as the unsigned bundles (T-EVIDENCE-2). The mitigation is signing: ADR 0018 (proposed) signs
  the run's evidence, with the summary as a subject of the run's statement, and the report verifies it. Until then the interim
  control is the operator's: **protect the evidence directory** (`linux_compliance_evidence_output_dir` and the
  directories the report reads from) so that only the account that runs the playbook can write it, for example by
  keeping it on the controller with the role's `0700` directories and `0600` files, not on a share that other
  accounts or hosts can write, and by copying the summary and the bundles to write-once or access-controlled storage
  right after the run; compare the number of target hosts in the summary with the inventory when the fleet size is
  known.
- **Residual:** unreachable and limited-out hosts cannot be collected; a report names them only when it is built with
  `--evidence-collection`. A run whose plays on `localhost` are limited out,
  or in which every host fails in the audit play, writes no summary. A custom playbook that deliberately calls `deferred.yml` or `evaluate_deferred.yml` and never runs `enforce.yml`,
  or that writes `linux_compliance_audited.gate` with its own `set_fact`, can still end without the gates. That is a
  deliberate act by whoever writes the playbook, the same class as the documented residual of the `verify` role's
  baseline marker; no variable from the inventory, `group_vars`, `host_vars`, `-e`, a role parameter or an include
  parameter can defer a gate. Such a run never produces a bundle: the evidence role refuses an audit result whose
  gate is recorded as deferred and not enforced, and the report refuses a manifest without an enforced gate.
