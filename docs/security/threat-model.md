# Threat model

Scope: the `freesecdev.linux_compliance` collection on managed hosts. Audience: reviewers using the `security-review`
skill, and authors of changes that add an asset, trust boundary or entry point. Jira: FREES-134 (audit content). The
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
| The file system around `content_path` | Whoever owns or can write those directories | Untrusted unless root-owned and not writable by others |
| Scanner output in the run directory | `oscap` | Untrusted input to the parser (hostile XML, oversized files, symlinks) |
| `/usr/bin/oscap` and its libraries | The distribution package manager | Trusted: root-owned binary in a trusted directory ([ADR 0004](../adr/0004-audited-process-execution.md)) |

### T-AUDIT-1: the datastream is replaced by a FIFO or symlink

- **Attacker:** a local non-root user who can write the directory that holds the datastream, or one of its ancestors,
  or who owns the datastream in a sticky directory.
- **Failure:** `xmlsafe.open_regular` checks the path with `lstat` and then opens it; it cannot use `O_NOFOLLOW` or
  `O_NONBLOCK`, because the repository guard allows only `os.path` in plugins. Between the two calls the user swaps the
  file for a FIFO, and root's `open` blocks. A swap for a symlink makes root copy the link's target.
- **Impact:** the audit hangs (availability). There is no wrong result, because every read is hashed and compared with
  the pin, and no disclosure, because a copy that does not match is deleted and only the digest is reported.
- **Mitigation (FREES-134):** before the datastream is opened, `audit.inspect_content_path` walks the directory that
  holds it from `/` and refuses (`unsafe_content_dir`) a symlink, a component that is not a directory, a directory that
  is not owned by root or that is writable by group or others without the sticky bit, and a datastream that is not
  owned by root or that is writable by group or others. These are the rules for the ancestors of the output directory.
  Unit tests cover world- and group-writable directories, writable and sticky ancestors, non-root owners of directories
  and of the file, symlinks, and that a refused path is never opened.
- **Residual:** path-based checks; only root can change a vetted component. Root, network and FUSE file systems are out
  of scope ([audit guide](../audit.md#content-directory-rules)). The `discover` modules read the same path without the
  directory checks; under `become` the hang is possible there (FREES-138).

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
- **Failure:** two runs of one host, benchmark version and profile were merged rule by rule; the forgery adds passing
  rules that the real run did not evaluate (0.0 to 99.0 percent in the FREES-130 probe).
- **Mitigation (FREES-130):** a second completed ScanRun for the same host, benchmark, content version and profile is
  refused unless `--allow-repeated-scans` is given, and every group built from more than one input carries a
  `merged_inputs` note that the dashboard shows. An XCCDF target and fqdn fact that disagree are an input error.
- **Residual:** a forged run with another profile, or a self-asserted XCCDF file, is merged with a visible note but not
  detected. Signed evidence bundles ([ADR 0018](../adr/0018-evidence-bundle-provenance.md), proposed) are the fix.

### T-REPORT-2: an edited exceptions evaluation hides a failure

- **Attacker:** anyone who can change an evaluation document between the `apply_exceptions` filter and the report.
- **Failure:** a status, mark or count is changed so that a failure reads as waived or an expired waiver as in effect.
- **Mitigation (FREES-132):** `exceptions.load_evaluation` evaluates the scan run again from the exceptions, target and
  times in the document and accepts it only when the result is identical; anything else is an input error, never a
  waiver. Justification text is rendered with DOM text APIs only.
- **Residual:** the SHA-256 of the exceptions file and the exception records themselves are taken as given, so a
  document rebuilt consistently from a different exceptions file is accepted with that file's digest. ADR 0018 proposes
  binding the file and the evaluation in a signed bundle.
