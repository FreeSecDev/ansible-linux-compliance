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
  policy, so [ADR 0003](../adr/0003-native-module-remediation.md) (no upstream Bash fixes) still holds. ADR 0003 is about
  what changes a host; SCE checks are meant to read it, but nothing technical confines them to reading.
- **Option to disable:** the pinned `oscap` 1.3.9 has no command-line option to disable SCE. SCE is the auto-loaded
  plugin `libopenscap_sce.so.25`, shipped in `libopenscap25t64` with the library itself. The undocumented variable
  `OSCAP_CHECK_ENGINE_PLUGIN_DIR` would redirect its `dlopen`, but the process helper does not pass it and redirecting
  root's library loading would add a code-loading path. Without SCE, the 16 SCE-only rules of `cis_level1_server` are
  `notchecked` (13 firewall rules and 3 file-system-wide ownership and permission rules); the other 392 rules are
  unaffected. An operator who does not want to run any SCE script can list those rules in `disabled_rules`: the
  tailoring file deselects them, their scripts do not run, and they are reported as `disabled`.
- **Residual:** the pinned content and its 81 scripts are trusted as a whole, like the OVAL definitions, which
  `oscap` also evaluates as root. A content update is therefore a change to code that runs as root: its review covers
  the SCE scripts that changed, not only the digest.

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
- **Residual:** the XCCDF results and the scan run are host evidence (host names, addresses, rule results), and the
  exceptions file names owners and approvers. With the ARF opt-in a bundle can hold password hashes. Bundles are
  `0600` in `0700` directories of the controller user; share them like the report.

### T-EVIDENCE-2: a host or a file on the way changes the evidence

- **Attacker:** a local user on the host between the audit and the fetch, the transport, or a compromised host.
- **Failure:** the controller collects different bytes than the audit recorded, or a different file.
- **Mitigation (FREES-51):** every fetched file must have the SHA-256 and size that the audit module recorded, the
  fetched `scan-run.json` must be the scan run of the fact, and the evaluation must verify against the byte-exact
  exceptions file and must have been made from the raw scan run. Any mismatch fails the host and removes the bundle.
  The audit evidence is root-owned `0600` in a root-only `0700` run directory, so only root can change it on the host.
- **Residual:** the recorded digests come from the host. A compromised host can return consistent lies; the checks
  bind the bundle to what the audit module reported, not to the truth about the host. This is out of scope for any
  controller-side check (ADR 0018 states the same for signatures).

### T-EVIDENCE-3: a bundle is edited after it was written

- **Attacker:** anyone who can write the bundle directory or a copy of it before it reaches the report.
- **Failure:** a finding, waiver or digest is changed so that the report shows a better result.
- **Mitigation (FREES-51):** the report reads the bundle without following links, refuses unlisted files, special
  files and unexpected directories, and verifies every size and SHA-256, `SHA256SUMS`, the scan run against the
  manifest and the evaluation against the bundled exceptions file and the raw scan run. A partial edit is an input
  error. A file that looks like a signature is refused, never ignored.
- **Residual:** the bundle is not signed. Whoever can rewrite every file and digest consistently, including the
  exceptions file, can forge a bundle that verifies; the report labels nothing as verified. Signed bundles are
  FREES-140 ([ADR 0018](../adr/0018-evidence-bundle-provenance.md), proposed).
