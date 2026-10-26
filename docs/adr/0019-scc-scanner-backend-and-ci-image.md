# 0019. SCAP Compliance Checker as a second scanner backend, with a CI-only image

- **Status:** proposed
- **Date:** 2026-10-26
- **Deciders:** lead architect; product owner (platform facts and the checklist export decision)
- **Jira:** FREES-144 (this ADR and the CI image), FREES-145 (backend), FREES-146 (STIG to ComplianceAsCode
  mapping), FREES-147 (CKL and CKLB export), FREES-152 (hardening of the path filter, the gate and the guard),
  FREES-155 (Markdown in the publishing check, no SCC cache for pull requests from forks), FREES-161 (opt-in
  off-platform scan of Ubuntu 26.04 with the 24.04 benchmark)
- **Pull requests:** introduced by the pull request for FREES-144 (the CI image, its make targets, the `scc-smoke`
  job and the repository tests). The pull request for FREES-145 adds the backend, the SCC integration and egress
  tests and the amendment at the end of this ADR. The pull request for FREES-147 adds the exporter
  ([ADR 0020](0020-stig-viewer-checklist-export.md)). The mapping is not implemented.
- **Related:** [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0013](0013-normalized-findings-model.md), [ADR 0015](0015-content-acquisition-and-pinning.md),
  [ADR 0018](0018-evidence-bundle-provenance.md)

## Context

Some government organisations must scan with the SCAP Compliance Checker (SCC) of the Naval Information Warfare
Center (NIWC) Atlantic and submit DISA STIG results, often as STIG Viewer checklists for eMASS. The collection
scans with OpenSCAP and ComplianceAsCode content today. The product owner confirmed these facts from production use:

- SCC runs on Ubuntu 24.04 as the scanner host.
- SCC scans Ubuntu 24.04 and 26.04 targets. There is no 26.04 profile yet.
- The project never redistributes SCC. Downloading it during a CI build is not redistribution.
- STIG Viewer checklist export (CKL and CKLB) is in scope (decided 2026-10-26, FREES-147).

The research below was done on 2026-10-26. The NIWC Atlantic page
(<https://www.niwcatlantic.navy.mil/Technology/SCAP/>) answered automated requests with HTTP 403 and
<https://www.cyber.mil/stigs/SCAP/> returned only a script shell, so neither page could be read here. Every fact
below comes from files on the DISA download host `dl.dod.cyber.mil`, from NIWC Atlantic's own GitHub repository
<https://github.com/niwc-atlantic/scap-scc>, or from the documentation shipped inside the SCC 5.15 download. Facts
seen only by running SCC are marked as observed. Observed behaviour is not documented behaviour.

### Releases and downloads

- The SCC release record `scc_release.xml` in `niwc-atlantic/scap-scc` holds only the current release: 5.15
  (2026-09-01). Its commit history records the earlier ones: 5.13 (2025-12-19, commit `e0a22714`), 5.14
  (2026-02-11, `d0796f86`), 5.14.1 (2026-05-04, `40908320`) and 5.15 (`9d2a3743`). The current README says
  "Current release: 5.15". The installed SCC reads the same file as its update URL (`appUpdateURL` in
  `/opt/scc/options.xml`).
- The brief for this issue named 5.13 as the current release. That is out of date. 5.13 is no longer on the DISA
  host: `scc-5.13_ubuntu22_ubuntu24_amd64_bundle.zip`, `scc-5.13_ubuntu22_amd64_bundle.zip` and
  `SCC_5.13_Checksums.txt` return 404, and the NIWC archive does not hold 5.13. 5.14, 5.14.1 and 5.15 are on the
  DISA host. This ADR pins **5.15**.
- 5.15 combines the Linux builds into one x86_64 and one aarch64 bundle (`SCC_5.15_Readme.txt`, release record).
  The Readme says the Linux build "is designed to work on any Linux with kernel 3.10 or later", with an RPM for
  RHEL, Oracle Linux, SUSE and Amazon Linux and a DEB for Debian and Ubuntu.
- Downloads and their published SHA-256 values:

  | File | URL | SHA-256 |
  |---|---|---|
  | `scc-5.15_linux_x86_64_bundle.zip` (138,893,023 bytes, `Last-Modified` 2026-09-09) | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.15_linux_x86_64_bundle.zip> | `f3fac797a54efe8fb8bba8604b984a73302a98a4900befda17be85c6ef7fcee4` (published) |
  | `SCC_5.15_Checksums.txt` | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_5.15_Checksums.txt> | lists the SHA-256 of every bundle, RPM, tar.gz and `cscc` binary |
  | `scc-5.15.linux_amd64.deb` inside the bundle | member `scc-5.15_linux_x86_64/scc-5.15.linux_amd64.deb` | `912c04a377ccbbb790144663e89c88585707eef9e02e12b42259cd785e5d7e21` (**not published**; computed here from the verified bundle) |
  | `/opt/scc/cscc` installed from that package | | `ba908a907b8cbef7a3c7b1d2cad65c1c255e6290ef2ac3dd8a98ba2163afce8d` (published, section `SCC_5.15_linux_x86_64`) |

  The downloaded bundle and the installed `cscc` match the published values. The checksum file does not list the
  DEB, although the Readme and the bundle contain it.
- The User Manual (section 3) says "It is recommended to verify the SHA256 checksums of the downloaded zip files
  with the SCC checksum file". It documents signature checking only for the RPM, with a GPG key
  (`RPM-GPG-KEY-scc-5.15`). For the DEB it documents none.
- No CAC is needed: "DISA maintains the authoritative download of SCC, and starting with SCC 5.4, no longer
  requires a CAC to obtain" (User Manual, appendix G.3.1).

### Licence terms

The terms are the same text in `/opt/scc/Documentation/TermsOfUse.txt`, appendix F.1 "End User License Agreement" of
`SCC_5.15_linux_x86_64_UserManual.pdf`, and the notice that the DEB post-install script prints. The terms that matter
here:

- **Warranty and liability.** The Navy and Government disclaim all warranties and liability.
- **Redistribution.** The terms do not forbid it. "ANY REPRODUCTION OF THIS WORK MUST INCLUDE THE ABOVE NOTICES AND
  THE FOLLOWING NOTICE: 'PORTIONS OF THIS SOFTWARE ARE OFFICIAL WORKS OF THE U.S. GOVERNMENT. THE U.S. GOVERNMENT MAY
  PUBLISH OR REPRODUCE THIS SOFTWARE, OR ALLOW OTHERS TO DO SO, FOR ANY PURPOSE WHATSOEVER.'" The `LICENSE.md` of
  `niwc-atlantic/scap-scc` and the notice inside `options.xml` describe the NIWC portions as public domain under 17
  U.S.C. 105, redistributable if derivative works say so. But the package also bundles third-party components
  under GPL-3.0, LGPL-2.0, LGPL-3.0, MPL-2.0, Artistic 1.0 and 2.0, Apache-2.0 and a Microsoft licence
  (`Documentation/ThirdPartyLicenses.txt`), plus DISA and NIWC SCAP content. Redistribution would therefore carry
  obligations that the project does not want. The product owner's rule stands: **the project never redistributes
  SCC.**
- **Automated and CI use.** The terms say nothing about it. The User Manual (section 5) describes `cscc` as
  allowing "scripted or automated reviews by other applications or scheduled tasks". No restriction was found.
- **Caching.** The terms say nothing about it. A private cached copy of the verified download, used only by this
  repository's CI, is a reproduction for the project's own use. The reproduction notice permits that, and nothing
  is handed to third parties. The download is therefore cached (see the decision).
- **Registration.** `--register EMAIL CODE` only removes a funding notice. It is optional and never used.

### Command-line interface (SCC 5.15)

Sources: `/opt/scc/Documentation/CSCC-Readme.txt` and User Manual section 5 "Command Line Usage", both from the 5.15
download.

- Package `spawarscc` 5.15. It installs under `/opt/scc` with `cscc` (command line), `scc` (graphical; the same
  binary, same SHA-256), `cscc-remote`, a bundled interpreter tree (`bin/`, `lib64/`), `options.xml`, and content under
  `Resources/Content`. It needs root: "On Linux, Mac, and Solaris, root is required to run SCC" (FAQ A.13, section
  2.2.1).
- One `options.xml` in the installation directory holds the configuration of both the GUI and the CLI.
  "Any configuration change from a Scanning Parameter is temporary, and does not get saved for future use."
- Confirmed scan options, documented as combinable: `-o, --options FILE` (review with a given options file),
  `-u, --userDir DIRECTORY` (save results and logs there), `-cd, --configDir DIRECTORY` (save configuration files
  there), `-q, --quiet`, `-dn, --doNotSaveChanges` (run without updating `options.xml`), `-r`, `-mr`, `-rr` (rule
  filters), `-d` and `-ds` (debug).
- Confirmed content options, documented as stand-alone: `-is, --installScap FILE [PROFILE] [--force]`,
  `-isr, --installSCAPRun FILE [PROFILE] [--force]` (install, enable and scan), `-eb` and `-db` (enable or disable a
  benchmark by ID and optional version), `-ea` and `-da`, `--setProfile PROFILE BENCHMARK_ID`,
  `--installTailoringProfile FILE`, `-ct, --createTailoringFile ID [VERSION]`, `--installDeviationFile FILE`. Profiles
  are named in short form in the examples (`MAC-3_Sensitive`). Benchmarks are named by SCC benchmark ID
  (`RHEL_8_STIG`), not by XCCDF identifier.
- Confirmed information options: `-v, --version` ("Display one liner version information"), `-V, --verboseVersion`,
  `--listAllBenchmarks`, `--listAllProfiles`, `--listOpt`, `--getOpt OPTION`.
- Options with network or remote reach: `--ssh [cisco|unix]`, `--wmi ...`, `-h, --host`, `-f, --file`,
  `--scanDomain`, `--cisco FILE`, `--checkForSCCUpdates`, `--checkForContentUpdates [--installUpdates|--installAll]`,
  `--installUnixPlugin`, `--installCredentialDB`. The shipped `options.xml` sets `appCheckForUpdates` and
  `contentCheckForUpdates` to `0`, and **`downloadExternalFiles` to `1`** ("Download external SCAP 1.2 content
  files").
- No remediation: "Does SCC provide any remediation functionality? No. This software only analyzes the system, it
  does not modify any setting" (FAQ A.8).
- Output (User Manual section 7.2 and the options table in section 4.4). Each run makes a session directory. XML goes
  to `Results/SCAP/XML`: the XCCDF results (`keepXCCDFXML`, default `1`), the NIST ARF 1.1 file (`keepARFXML`,
  default `0`) and OVAL results. Checklists go to `Results/SCAP/Checklists` (`saveDISACKL`, `saveDISACKLB`, both
  default `1`). The manual says CKL and CKLB are created only "when running NIWC Enhanced SCAP content, which
  contains Manual Questions", and "Creating CKL results from 'standard' DISA SCAP content is not supported". The
  same table documents `CKLMarking`, `CKLClassification` and `primaryIPAddressPrefix`.
- Observed: `cscc --version` prints `scc version: 5.15 date: 2026-08-27 build: 8478-21156`. A default local scan in the
  CI image ran with `-u /out` and evaluated the bundled NIWC Enhanced Ubuntu 24.04 content with profile
  `xccdf_mil.disa.stig_profile_MAC-1_Classified`. It wrote
  `Sessions/<timestamp>/Results/SCAP/XML/<host>_SCC-5.15_<timestamp>_XCCDF-Results_CAN_Ubuntu_24-04_STIG-001.005.007.xml`
  with mode 0600, plus a `.ckl` and a `.cklb`. The XCCDF file uses the XCCDF 1.2 namespace and holds the whole
  `Benchmark` with one `TestResult` (`test-system="cpe:/a:niwc:scc:5.15"`). It has no DOCTYPE, starts with an XML
  comment, has times without a zone offset (`start-time="2026-10-26T07:21:34"`) and results `pass`, `fail`,
  `notapplicable`, `notchecked` and `unknown`. Rule IDs look like `xccdf_mil.disa.stig_rule_SV-270649r1067136_rule`.
  The file name separator is `SCC-5.15`, where the manual writes `SCC_5.15`.

### Options and state: what SCC actually loads and writes

These observations come from the CI image on 2026-10-26, after the review of PR #33.

- **Which options apply.**
  - Without `-o`, SCC prints `Loading options from: /opt/scc/options.xml`, and the shipped value of
    `downloadExternalFiles` there is `1` (`cscc --getOpt downloadExternalFiles` prints `downloadExternalFiles = 1`).
  - With `-o /work/o.xml`, it prints `Loading options from: /work/o.xml`.
  - With `-d`, the debug log records `options file = /work/o.xml`, validates that file against
    `Resources/Schemas/options.xsd`, and dumps it after the header `Contents of /work/o.xml:`, including the line
    `<downloadExternalFiles>0</downloadExternalFiles>`. That dump is the content of the file SCC loaded. It does not
    prove the value SCC uses at run time: the same log shows SCC also checks for an enabled configuration profile
    (`checking to see if a config profile is enabled`), and `sharedOptions` is `1`.
- **No effective-options report.** No SCC option reports the effective configuration of a scan. `--getOpt` reads the
  installed `options.xml` and must be used on its own. `cscc -o /work/o.xml --getOpt downloadExternalFiles` did not
  finish: it ran at 100 % CPU for more than five minutes and was killed.
- **A copied options file fails closed, but exits 0.** A scan with `-o` pointing at an unmodified copy of the shipped
  `options.xml` (with only `downloadExternalFiles`, `keepARFXML`, `saveDISACKL` and `saveDISACKLB` changed), `-u`
  and `-dn` skipped every stream. It logged "SCAP content has been modified since last options file was saved ...
  content skipped" and "Canceling scan due to content file modified failure", reported `Total Errors: 18` and
  "SCC Scan Completed: No Applicable Content", wrote no XCCDF results, and exited 0.
- **SCC writes its own state even with `-o`, `-u` and `-dn`.** After such a scan, these were new or changed:
  - `/opt/scc/Resources/Content/DB/SCC_SCAP12_Content.db`, `SCC_SCAP12_Content.db.archive` and `ocil.db`;
  - a new `/opt/scc/Local/<host>_<timestamp>.db`;
  - the `/opt/scc` directory itself.

  The independent review saw that, with a read-only root file system, even `--getOpt` tries to create `/root/SCC`
  and to write to `/opt/scc` ("Unable to write to: /opt/scc this is a fatal error"), and still exits 0.
- **Expiry.** The debug log of 2026-10-26 says "Checking if software is out of date. Software expires in 30 days."
  The options table documents `expignore` ("Over-ride software expiration for pre-release versions"). What SCC does
  once a release expires was not observed.

### Exit codes

The `CSCC-Readme.txt`, the `cscc.1` man page and the User Manual do not document exit codes. All three were searched
for exit, return and status. Observed in the CI image:

| Invocation | Exit status |
|---|---|
| `cscc --version`, `cscc -V` | 0 |
| `cscc --no-such-option` (prints "Unable to parse all command line parameters") | 0 |
| Full local scan with 133 failed rules | 0 |

The exit status therefore does not separate success, failed rules or a usage error.

### DISA SCAP benchmarks

- Standard DISA STIG SCAP benchmarks come from <https://www.cyber.mil/stigs/SCAP> (User Manual 4.2.2 and E.1). The
  files are on the same DISA host, for example
  <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-3_Benchmark.zip>
  (100,438 bytes, `Last-Modified` 2026-07-10, SHA-256 `d31ad8190149508aab04591d29c3f76125db93d2a18cdcc1ffddd1b897c43fe0`
  computed here). NIWC Enhanced content with manual questions is published separately (User Manual 4.2.2), and SCC 5.15
  bundles it (`U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.xml`).
- Versioning: version and release are in the file name (`V1R5`) and in the XCCDF `version` (`001.005`). Each rule
  carries its STIG ID as the rule `version` (`UBTU-24-100010`). Rule IDs include a revision (`SV-270645r1068357`) that
  changes between releases.
- Format: the Ubuntu 24.04 V1R5 file is a SCAP 1.3 data-stream collection with XCCDF 1.2. It has benchmark
  `xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG`, 165 rules and profiles `MAC-1`, `MAC-2` and `MAC-3` (each
  `_Classified`, `_Public`, `_Sensitive`), plus `CAT_I_Only` and `Disable_Slow_Rules`. There is no DOCTYPE and no
  XML signature. The NIWC Enhanced files are XML-signed, and SCC checks the signatures by default
  (`validateDigitalSignature` and `failOnXMLDSig` are `1`).
- Checksums: no checksum file for DISA benchmarks was found on the DISA host. Integrity therefore rests on a pin
  that the project records itself, as in ADR 0015.
- Ubuntu 26.04: SCC 5.15 ships Ubuntu 18.04, 20.04, 22.04 and 24.04 content and nothing for 26.04, which matches the
  product owner's statement.

## Decision

### 1. A second backend behind the scanner protocol (FREES-145)

SCC becomes the backend `scc`. It is registered in `plugins/module_utils/compliance/backends.py` next to `openscap`
and implements `scanner.ScanBackend.audit`. Orchestration, exceptions, toggles, evidence and reporting stay
backend-neutral. A ScanRun from SCC has `scanner.name: scc` and the version parsed from `cscc --version`. Scan runs,
evidence bundles (ADR 0018) and reports treat it like an `oscap` run, with scanner provenance.

### 2. Process policy

`cscc` is run only through `process.py`, with a policy bound at import time (`bind_policy`, ADR 0004).

- **Fixed executable path.** The only permitted path is `/opt/scc/cscc`. `/opt/scc` is not added to the trusted
  search directories. The policy names that one absolute path, which gets the same vetting as the trusted
  directories: it must be a regular file, not a symlink, root-owned and not writable by group or others, and so must
  `/opt` and `/opt/scc`. This extends ADR 0004 and needs a security review in FREES-145.
- **Validated arguments only.** The permitted sequences are `--version` alone and one scan form, built only from
  documented, combinable options: `-o FILE`, `-u DIR`, `-cd DIR`, `-q`, `-dn`, and `-d` only if FREES-145 adopts the
  debug log as part of the options confirmation below. All paths come from the backend and are confined to the run
  directory. Content is given through the per-run options file. If FREES-145 finds that it can only be given with
  `-isr FILE PROFILE`, that form is added by an amendment of this ADR, not silently.
- **Refused everywhere:** every remote and network option (`--ssh`, `--wmi`, `-h`, `-f`, `--scanDomain`, `--cisco`,
  `--checkForSCCUpdates`, `--checkForContentUpdates`, `--installUnixPlugin`, `--installCredentialDB`), every
  command that changes the installation (`--config`, `--setOpt`, `--upgrade`, `--generateOptionsFile`,
  `--restoreDefault`, `--register`, `-ub`, `-ua`, `-is`, `-iv`, `-ea`, `-ear`), `--getOpt` and `--listOpt` (which
  read the installed options, not the run's), `-ds`, and the post-scan report commands. `-d` writes large logs with
  host data. If it is used, those logs stay in the root-only run directory and are not collected into evidence bundles. The words `remediate` and `--remediate` and the
  `generate fix` sequence are refused for every executable, as before. SCC has no remediation feature (FAQ A.8), so
  ADR 0003 holds.
- **Per-run options file.** The backend writes it from a reviewed template, mode 0600, in the run directory. It
  enables exactly the pinned stream and profile, sets `sshEnabled`, `saveDISACKL` and `saveDISACKLB` to `0`, keeps
  `keepXCCDFXML=1` and `keepARFXML=1`, and turns signature checks on. A plain copy of the shipped `options.xml` does
  not work: SCC skips every stream. How the template stays consistent with SCC's content database is for FREES-145
  to establish.
- **Remote retrieval MUST be off, and the backend MUST confirm it for every run.**
  - Every scan MUST run with `downloadExternalFiles=0`, `appCheckForUpdates=0` and `contentCheckForUpdates=0`.
    Writing these values into the per-run file is necessary but not sufficient: SCC also reads the installed
    `options.xml`, where `downloadExternalFiles` is `1`, and may apply a configuration profile.
  - The backend MUST refuse to scan, as a `failed` run with every expected rule `error`, unless it confirms for that
    run that SCC used these three values.
  - What was found (see Context): SCC has no option that reports the effective configuration of a scan, and
    `--getOpt` cannot be combined with `-o`. The best available evidence is SCC's own record of the run:
    - the `Loading options from:` line naming the run's options file;
    - with `-d`, the `options file =` debug line and the `Contents of <file>:` dump showing the three values as `0`;
    - no configuration profile enabled;
    - the file's SHA-256 unchanged after the run.

    This shows which file SCC loaded and what it contained. It does not yet prove the value in effect.
  - FREES-145 MUST therefore show that this evidence matches SCC's behaviour, through the egress test below. If it
    cannot establish a confirmation that holds, **the backend does not run SCC at all**: `backend: scc` refuses every
    scan, and this ADR is amended. No release enables the backend on an unconfirmed basis.
- **Egress test (FREES-145).**
  - **Primary control: a network namespace with a logging sink.** The scan container runs on an internal Docker
    network (`docker network create --internal`) whose only peer is a sink container. The sink:
    - runs a DNS server that answers every name with the sink's own address and logs each query;
    - accepts TCP on every port and UDP datagrams, logs each attempt, then resets.

    The scan container's resolver points at the sink. The test asserts zero DNS queries and zero connections or
    datagrams. This catches DNS through any resolver path (the embedded `127.0.0.11`, a stub resolver, nscd), child
    or daemon processes outside a traced tree, `sendmmsg` and io_uring.
  - **Secondary signal: strace.** If used, it traces the whole `network` syscall class (`strace -f -e trace=network`),
    and resolver-socket traffic counts as an attempt. No loopback or local socket is exempted, except ones the test
    names explicitly as SCC's own.
  - The scanned content references an external file, for example an `xccdf:check-content-ref` to a remote OVAL
    document or an external variable file.
  - **Positive control, mandatory.** The test also runs once with `downloadExternalFiles=1` and asserts that the sink
    sees the attempt, so the test is shown to detect a violation.
  - A run with `--network none` alone does not prove anything: a blocked fetch fails quietly.
- **SCC changes its own state on the managed host.** Audit mode never changes a managed host (AGENTS.md rule 7). SCC
  writes `/opt/scc/Resources/Content/DB/*.db` and a new `/opt/scc/Local/<host>_<timestamp>.db` even with `-o`, `-u`
  and `-dn`, and it may create `/root/SCC`.
  - The FREES-145 integration job MUST hash `/opt/scc` and `/root` before and after a scan, list every path that
    changed, and show that `options.xml`, the installed content and the binaries are byte-identical.
  - The remaining writes to SCC's own state are a residual that the lead architect must accept on FREES-145, the
    way `oscap` writes to `/tmp`. Until then, the backend stays off.

### 3. Pinned DISA content, never committed

DISA SCAP benchmarks, or NIWC Enhanced benchmarks, are pinned like ComplianceAsCode datastreams (ADR 0015). A
manifest entry records the source URL, size, SHA-256, benchmark identifier and version, the profiles read from the
file, the retrieval date and the `Last-Modified` time (seven-day rule). The fetch tool verifies the SHA-256 on the
controller, the module verifies it again on the host, and SCC reads a private copy in the run directory. DISA
publishes no checksum, so the person who sets a pin downloads the file twice, from two networks, and the pull request
records both digests. Benchmark files, SCC output and checklists are never committed, packaged or published.
`.gitignore` ignores `*.zip`, `*.deb`, `*.rpm`, `*.ckl` and `*.cklb`, and the repository test fails if any tracked
file looks like an SCC bundle, package, binary or checklist. The test detects ELF, zip, deb, rpm, gzip, xz, zstd,
bzip2 and 7z files. It also detects those payloads when they are base64-encoded (at all four alignments, with the
magic anywhere in the decoded data) or written as long hexadecimal runs. A hit names the file and the offset. A
reviewed false positive is accepted only by an entry of path and SHA-256 of the exact content in
`ACCEPTED_BINARY_FINDINGS` of the test module, so a changed file is checked again. The content bundled inside the
SCC package is not used implicitly: the per-run options file enables only the pinned stream. A target with no pinned benchmark, Ubuntu 26.04
today, is refused with a clear error and is never scanned with 24.04 content (AGENTS.md rule 8), unless the
explicit, labelled opt-in of the [FREES-161 amendment](#amendment-2026-10-26-off-platform-opt-in-for-ubuntu-2604-frees-161)
is given.

### 4. Results through the existing hardened parsers

The backend reads the single XCCDF results file of the session with the existing parser in `openscap.py` through
`xmlsafe` (size, element and depth bounds, no DOCTYPE or entities, UTF-8 only). It applies the same integrity rules:
the benchmark and profile must match the request, a missing rule-result is `error`, an unexpected or duplicate one
fails the run, and `unknown` maps to `error` (ADR 0013). The ARF file is kept as evidence. Findings carry
`scanner: scc`. Because the exit status proves nothing, a non-zero status is always a failed run, and exit 0 is
never evidence of completion. A run is `completed` only when all of these hold:

- the `-u` user directory was created by the backend for this run, freshly and empty, and is never reused;
- the options confirmation of decision 2 succeeded;
- exactly one XCCDF results file exists in it for the requested stream, and it parses;
- its `TestResult` matches the request and carries both `start-time` and `end-time`;
- once the zone of SCC's times is known, `start-time` is no earlier than the start of the run.

Anything else is `failed` with every expected rule as `error`, so a stale, partial or missing result never looks
compliant. The observed "No Applicable Content" scan that exited 0 is such a case. SCC writes times without a zone.
FREES-145 must establish which zone they are in and convert explicitly; it must not guess.

Real SCC output is not committed as test fixtures. It embeds the full benchmark text and details of the scanned
host. FREES-145 unit tests use small synthetic documents in the observed shape, and real output is generated in the
CI image during the integration job and discarded.

### 5. Operator-installed SCC; the collection never downloads it

On managed hosts the operator installs SCC from DISA with the package manager. The collection never downloads,
installs, updates or registers SCC. The backend may take an expected version and an expected SHA-256 of
`/opt/scc/cscc` (published in the checksum file). It refuses to run on a mismatch, and the ScanRun records the
version.

### 6. No redistribution

SCC bundles, packages, binaries and SCC-produced files are never committed, never part of the collection tarball or a
release, never uploaded as workflow artifacts and never pushed to any registry. The CI image exists only in the
runner's local image store under a `localhost/` tag. The verified bundle is kept in the GitHub Actions cache of this
repository, which the licence allows (see Context) and which hands nothing to third parties. A pull request from a
fork neither restores nor saves that cache, because its workflow code is the fork's (FREES-155).

### 7. Version updates: manual pin bump

Renovate cannot track SCC: DISA's host has no release API, and NIWC publishes neither tags nor releases. An update is
a reviewed pull request that changes `extensions/ci/scc/scc.pins`:

1. Read the new version and date from `scc_release.xml` and the new Readme. Wait seven days after publication,
   unless the release fixes a security issue.
2. Download the Linux x86_64 bundle and `SCC_<version>_Checksums.txt` from the DISA host, verify the bundle, and
   record its size and SHA-256 and the published SHA-256 of `cscc`.
3. Extract the DEB and record its SHA-256, which DISA does not publish.
4. Refresh `SCC_EXPIRES` (open item 12):
   - Run a scan with `-d` in the new image and read the "Software expires in N days" line of the application
     debug log. The expiry is the date of that run plus N days.
   - Check it against the version date that `cscc --version` prints plus 90 days. For 5.15 both give 2026-11-25.
   - If the two disagree, record the earlier date and the reason in the pull request.
5. Run `make scc-smoke` and paste the verification output into the pull request.

The expiry is enforced on the SCC path, not in every pull request:

- **Hard stop.** `make scc-expiry-check` (`tools/scc/check-expiry.sh '$(SCC_EXPIRES)'`) is a prerequisite of
  `scc-image`, and so of `scc-smoke`. From seven days before `SCC_EXPIRES` it fails, so an expiring SCC is never
  built or run.
- **When it runs.** `scc-smoke` runs on every pull request and every merge group that touches an SCC path. It
  always runs for a push to `main`, on the daily schedule of `ci.yml` and on manual dispatch. The SCC
  paths are `extensions/ci/scc/`, `tools/scc/`, the hadolint fetcher, the `Makefile`, the workflows, the SCC tests,
  this ADR, and the FREES-145 code (`scc*`, `process` and `backends` in `plugins/module_utils/compliance/`).
- **Path filter.** The `scc-changes` job decides with `tools/scc/needs-smoke.sh`.
  - For `pull_request`, it diffs the pull request's base SHA against the checked-out merge commit.
  - For `merge_group`, it diffs `github.event.merge_group.base_sha` against `head_sha`.
  - It diffs with `git diff --no-renames`, so a file renamed out of an SCC path still lists its old path and
    runs the smoke test (FREES-152).
  - It fails closed: any other event, a missing or malformed SHA, or a failing `git diff` means the smoke test
    runs.
- **The base revision's filter decides (FREES-152).** For `pull_request` and `merge_group`, the job does not
  run the filter from the checkout. It validates the base SHA, writes
  `git show "$BASE_SHA:tools/scc/needs-smoke.sh"` to a temporary file and runs that file as a separate `bash`
  process; it never sources it into the job shell.
  - A pull request that edits the filter so that it prints `false` therefore cannot exempt itself, in its own
    run or in the merge queue. **A change to the filter takes effect only after it merges.** The first pull
    request and merge group after the change still use the old filter.
  - It fails safe. If the event is not `pull_request` or `merge_group`, the base SHA is not 40 hexadecimal
    digits, the base has no such file, `git show` fails, or the filter exits non-zero, the output is `scc=true`.
    Any output other than exactly `false` also becomes `scc=true`.
  - The step script itself lives in `ci.yml`, which the pull request controls. Editing it is a change to a
    workflow, which is an SCC path, and has the same trust as editing `ci-gate`: it is caught by review, and the
    push run on `main` and the daily schedule always run the smoke test.
- **Gate.** `ci-gate` accepts a `skipped` `scc-smoke` only when all of these hold:
  - the event is `pull_request` or `merge_group`;
  - `scc-changes` succeeded and output exactly `scc=false`.

  A skip on `push` to `main`, `schedule` or manual dispatch, a missing or unexpected filter output, and any other
  result fail the gate. The gate compares with jq `IN("true", "false")` and `IN("pull_request", "merge_group")`,
  which are exact. It no longer uses `inside()`, which matches substrings and so accepted an output of `""`, `ru`
  or `fals` and an event named `pull`, `merge` or `merge_grou` (FREES-152).
- **Early warning.** A plain unit test only checks that the publication date is before the expiry date. The
  scheduled check of FREES-149 fails loudly and opens or updates an issue from 21 days before `SCC_EXPIRES`, and also
  reports a newer release in `scc_release.xml`.
- **Effect.** After the cutoff, only pull requests and merge groups that touch an SCC path are blocked until the
  pin is bumped. Unrelated pull requests keep passing `ci-gate` and keep flowing through the merge queue. The push
  runs on `main` and the daily scheduled run always run `scc-smoke`, so they go red and fail loudly. The FREES-149
  warning starts 21 days before expiry, so the bump can happen before the cutoff.

### 8. STIG to ComplianceAsCode mapping (FREES-146)

SCC results use DISA rule IDs, while the catalogue, toggles and remediation use ComplianceAsCode rule IDs. The
mapping is generated, not written by hand. The pinned ComplianceAsCode Ubuntu 24.04 datastream references 194
distinct STIG IDs (`UBTU-24-*`) through `reference` elements pointing at cyber.mil. Each DISA rule carries its STIG
ID as the rule `version`. The generator joins the two pinned files on the STIG ID, keeps rule IDs only (no benchmark
text), records both digests as provenance, and is checked in CI against the pinned files. The revisioned `SV-`
identifier is resolved through the pinned DISA file, never stored as the join key. Unmapped STIG rules stay audit-only
and are reported as such. A disabled topic or rule toggle excludes the mapped SCC rules through SCC's tailoring
mechanism (`--installTailoringProfile` or a tailoring in the per-run options file, to be confirmed in FREES-146),
and they are reported as `disabled`.

### 9. STIG Viewer checklist export (FREES-147): our own exporter

The product owner decided that CKL (STIG Viewer 2, XML) and CKLB (STIG Viewer 3, JSON) export is in scope. It is a
reporting exporter in `tools/reporting` over normalized findings, the same input for SCC and `oscap` results. SCC
results already carry STIG rule IDs. `oscap` results get them through the FREES-146 mapping. Rule titles and other
benchmark text come from the pinned DISA content at export time and are never committed.

SCC writes CKL and CKLB itself (`saveDISACKL`, `saveDISACKLB`; observed in the CI image). We do not use them. We
export our own, for these reasons:

- SCC creates checklists only from NIWC Enhanced content with manual questions, never from standard DISA content
  (User Manual 4.4), and never for `oscap` results. One exporter covers every case.
- SCC's checklists know nothing of the collection's exceptions, toggles or non-completed runs, so a waived or
  disabled rule would appear differently in the checklist than in the report.
- SCC's checklist is written on the managed host, which is untrusted (threat model). The exporter works on the
  controller from validated, and with ADR 0018 verified, ScanRuns.

The per-run options file therefore turns SCC's own checklists off.

Status mapping (exact values and format versions are validated in FREES-147):

| Normalized finding | Checklist status |
|---|---|
| `pass` in a completed run | Not a Finding |
| `fail` | Open |
| `notapplicable` | Not Applicable |
| `error`, `notchecked`, `disabled` | Not Reviewed, with the outcome and its reason in the finding details |
| any finding of a run that is not `completed` | Not Reviewed, with the run status and error message |
| `waived` | the status of its evaluated outcome (Open for `fail`, Not Reviewed for `error`), **never Not a Finding**, with the exception ID, justification and expiry in the details and comments |
| STIG rule without a result (unmapped, or not automated) | Not Reviewed |

`error`, `notchecked`, `disabled`, non-completed runs and waived findings never map to Not a Finding. Asset fields
come only from the validated host identity, and self-asserted values are marked as such. Output is written
atomically with mode 0600 and escaped as untrusted data.

### 10. The CI image

- **Location: `extensions/ci/scc/`.** The image is a build definition for this repository's CI, not a script, so it
  does not belong in `tools/`. It is not the toolbox image of `linux-compliance-runner`, which is built, signed and
  published for others to consume by digest. This image must never be published, and FREES-145 runs this
  repository's collection code inside it. `extensions/` is where the collection keeps non-Ansible build definitions
  (Renovate already expects `extensions/packer/`). `galaxy.yml` lists `extensions/ci` in `build_ignore`, so the
  definition is not shipped in the collection tarball. Renovate's `dockerfile` manager updates the base image digest.
- **Supply chain.**
  - The base is `docker.io/library/ubuntu:24.04` pinned by index digest.
  - `tools/scc/fetch-scc.sh`, run by `make scc-fetch`, accepts only `https://dl.dod.cyber.mil/wp-content/uploads/stigs/`
    URLs. It downloads with HTTPS-only redirects and a size cap, then checks the pinned size and the pinned SHA-256
    of the bundle.
  - It then fetches the published checksum file and requires that it lists the pinned digests of the bundle and of
    `cscc`. A mismatch fails. A checksum file that cannot be fetched gives a warning, because it comes from the same
    server and proves little against a compromised host (ADR 0015); the reviewed pin is the anchor.
  - It extracts only the DEB member, by its exact name, and checks its pinned SHA-256.
  - `docker build --network none` copies the DEB in, checks its SHA-256 again, installs it with `dpkg`, checks the
    package version, checks that `/opt/scc/cscc` has the published SHA-256 and is `root:root 0755`, and removes the
    package file.
  - The maintainer scripts run as root in the build container. They print the licence, save an old `options.xml`,
    `chown` the tree and copy desktop files. The `chown` of the man pages fails harmlessly because the Ubuntu base
    image excludes `/usr/share/man`.
- **Root inside the container only.** SCC requires root, so the image keeps the default root user. This deviates
  from the `container-security` skill: non-root user, Alpine base, CodeBuild build, signing and scanning. Those rules
  are for published images. This image is never published, is built on the runner, and has its base fixed by the
  product owner's platform fact. The smoke test still runs it with `--network none`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, a read-only root file system and a `noexec` `/tmp`.
- **Never pushed.**
  - `make scc-image` requires a `localhost/` tag and has no push, login, save or export step.
  - The `scc-smoke` job has `permissions: contents: read` only, no secrets, no registry login and no artifact
    upload.
  - A repository test enforces an allow-list. The SCC identifiers may appear only in the allowed places:
    - identifiers: the image name `freesecdev-scc`, `build/scc`, `extensions/ci/scc`, `tools/scc`, `scc.pins`,
      `cscc`, any `SCC_*` variable and the `scc-*` make targets;
    - allowed places: the `scc-changes`, `scc-smoke` and `ci-gate` jobs (other jobs may name them only in
      `needs`); the `SCC_*` variables, the SCC targets and `lint-containerfile` of the Makefile, its help text and
      `.PHONY`; `tools/scc/` and `extensions/ci/scc/`; documentation, changelog fragments and tests.
  - Every other tracked file fails the test, and so does a workflow-level `env`, another job, another Makefile
    target or variable, or an indirect variable that names them.
  - **No publishing anywhere near SCC.** Every tracked file that names an SCC identifier, and every file under
    `tools/scc/` or `extensions/ci/scc/`, must not contain a push, login, save or export command. This includes
    scripts, Makefile fragments and test modules under `tests/`, where FREES-145 will put its integration tests.
  - **Multi-line commands count (FREES-155).** Before matching, the guard joins backslash-newline continuations
    and collapses every run of whitespace, quotes, commas, brackets, parentheses, backticks and `*` into one
    space. The container tool and the publishing verb then only have to be within 60 characters of that text.
    A ruff-formatted argument list with one element per line, a continued shell command in a script, a code
    fence or a workflow `run` block, and Markdown emphasis around each word are therefore caught. A hit names
    the original file and line. The window keeps prose in which the two words are far apart from matching.
  - **Markdown is checked too (FREES-155).** A Markdown file that names an SCC identifier, or lies under
    `tools/scc/` or `extensions/ci/scc/`, must not contain a publishing command either. A document that genuinely
    has to show one needs a reviewed entry in `ACCEPTED_PUBLISHING_MARKDOWN` in the guard module: the path and the
    SHA-256 of the file's exact content, as `ACCEPTED_BINARY_FINDINGS` does for binary findings. Any later change
    to that file fails the check again until the entry is reviewed and updated. A test refuses an entry that is
    not Markdown or no longer matches its tracked file. The list is empty: no tracked Markdown file needs one. Only
    the guard's own test module, whose mutation strings are data, is exempt.
  - **Includes.** The Makefile may `include $(SCC_PINS)`. Every other included file must be tracked, and it is
    checked as Makefile text under the same rules. An include through a variable or pattern is refused.
  - **No Markdown as code (FREES-152), kept as defence in depth (FREES-155).** Nothing may load or run a Markdown
    file. FREES-152 added this check because Markdown was then exempt from the publishing check. FREES-155 keeps
    it after removing that exemption: an accepted Markdown file may still quote a publishing command, the check
    costs nothing at run time, and it stops documentation from turning into a recipe by another route. It is not
    the primary control any more; the publishing check is.
    - The Makefile and every included file may not use `$(eval`, `$(file`, `MAKEFILES`, `GNUMAKEFLAGS`,
      `.INCLUDE_DIRS` or `--eval`, or a short `-E` in `MAKEFLAGS`.
    - No workflow may name `MAKEFILES`, `MAKEFLAGS`, `GNUMAKEFLAGS`, `.INCLUDE_DIRS` or `--eval` anywhere. This
      covers `env` at workflow, job and step level, `run` scripts, and writes to `$GITHUB_ENV`. The same applies
      to every file that names an SCC identifier.
    - No Makefile line, workflow string or SCC file may run a `.md` file. The guard finds a shell, `.`,
      `source`, `make -f` or a script interpreter whose script operand is a `.md` file, `< file.md` into such a
      command, and a `.md` file piped into one. It sees through recipe prefixes, `env`, `xargs`, `$(shell …)`,
      `$(MAKE)`, `$(SHELL)` and command strings in quotes.
    - This detection is word-level. A command assembled from variables, a copy of the file under another name,
      a glob or `find -exec` evades it. That is deliberate evasion, which review catches, as with a split image
      name.
  - The SCC jobs must not use a publishing action, and their permissions are at most `contents: read`.
  - Splitting the image name across variables to evade the regex is deliberate evasion. Review catches it, not
    this test.
  - The release workflow of ADR 0012 may still publish the collection to GHCR and upload artifacts, because it can
    never name the SCC image.
- **Make targets:** `scc-expiry-check`, `scc-fetch`, `scc-image` (runs `scc-expiry-check` and
  `lint-containerfile`, a pinned hadolint, first), `scc-smoke`, `scc-image-clean`.
- **CI job `scc-smoke`.** It restores `build/scc/download` from the Actions cache, keyed by the SHA-256 of
  `scc.pins`, so a pin change starts a new entry. A restored bundle is used only after its SHA-256 matches the pin,
  so a poisoned entry fails closed and is replaced by a fresh download.
  - **No cache for forks (FREES-155).** The cache step runs only when the event is not `pull_request`, or when the
    head repository is not a fork and its full name equals `github.repository`. A pull request from a fork is a
    run of this repository whose workflow code is the fork's. With the approval policy `first_time_contributors`,
    a returning outside contributor's run is not held for approval. Without this condition it could read the
    cached bundle. That adds no capability, because the bundle is a public DISA download, but the cache stays
    for this repository's own code: a fork run downloads from DISA itself.
  - The step uses the combined `actions/cache` action, whose save runs as the post step of the same step. A
    skipped step has no post step, so the condition stops both the restore and the save. GitHub already scopes
    a save from a pull request to that pull request's merge ref, so a fork could never write the entry that
    `main` restores; the condition removes even that write. A null head repository, for example a deleted fork,
    fails the full-name comparison, so the step is skipped. Then it runs `make scc-smoke`. It needs
  the `scc-changes` path filter and runs as described in decision 7. `ci-gate` needs both jobs. Downloads from the DISA host took under two seconds for the 139 MB bundle in local testing. The
  pull request records how the job behaved on GitHub-hosted runners. If downloads prove unreliable there, the job
  leaves `ci-gate` by an amendment, not by a silent skip.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Pin 5.13 as briefed | No longer on the DISA host; 5.14, 5.14.1 and 5.15 superseded it |
| Download SCC with `curl` inside the Containerfile | Needs `curl` and `unzip` from the archive in the image, network during `RUN`, and cannot use the Actions cache; the host-side script is smaller and testable |
| Push the image to GHCR or ECR, even privately | Redistribution; forbidden |
| Build the image in `linux-compliance-runner` | That repository publishes images; this one must never be published |
| Buildx GitHub Actions layer cache | Would cache image layers with the installed SCC; caching the verified download is enough |
| Install from the tar.gz | The DEB mirrors how an operator installs SCC on Ubuntu and gives a package version to check |
| Trust the published checksum file alone | Same server as the download; the reviewed pin is the anchor |
| Use the SCC content bundled in the package | The content version would change with every SCC release, unseen by the content manifest |
| Use SCC's own CKL and CKLB | Enhanced content only, no `oscap` support, unaware of exceptions and toggles, written on the managed host |
| Rely on the `cscc` exit status | Observed 0 for a usage error and for failed rules; undocumented |
| Commit real SCC output as fixtures | Embeds the full benchmark and host details; generated in CI instead |

## Benefits

Organisations that must use SCC get its results in the same findings model, reports, exceptions, evidence bundles and
checklists as `oscap` results. The CI image is reproducible from pins, verified three times (bundle, DEB, installed
binary) and never leaves the runner.

## Trade-offs

SCC is a large closed bundle that runs as root, with its own interpreter, libraries and content. Only `cscc` itself
is verified against a published digest; the rest of `/opt/scc` is trusted through the bundle and DEB digests. Updates
are manual. The exit status carries no information, so completion depends on the results files. Checklist export
depends on the FREES-146 mapping for `oscap` results.

## Security implications

- New supply-chain input: a root-run third-party bundle. Mitigated by the pins, the cross-check with the published
  checksum file, network-less builds and an image that never leaves the runner. See the threat model entry
  "CI-only SCC image".
- On managed hosts, SCC runs as root from a fixed path with a fixed argument shape, and its output is parsed as
  untrusted input. FREES-145 needs an independent security review.
- `downloadExternalFiles` is `1` in the shipped `options.xml`, and SCC offers no report of the effective value.
  Remote retrieval would break the pinned-content model (ADR 0015) on managed hosts, which have network. Decision 2
  makes it a fail-closed requirement: no confirmation, no scan. It is backed by an egress test that is shown to
  detect a violation. Without both, the backend stays off.

## Operational consequences

- New make targets `scc-expiry-check`, `scc-fetch`, `scc-image`, `scc-smoke`, `scc-image-clean` and
  `lint-containerfile` (part of `make lint`).
- New CI jobs `scc-changes` and `scc-smoke`, both in `ci-gate`, and a daily `schedule` trigger for `ci.yml`.
- SCC pins live in `extensions/ci/scc/scc.pins` and are updated by hand ([dependency management](../dependency-management.md)).
- SCC releases expire (open item 12). `SCC_EXPIRES` in `scc.pins` and `make scc-expiry-check` stop the SCC path
  seven days before that date, so a pin bump may be forced by the calendar, not only by a new release. After that
  date, pull requests and merge groups that touch SCC paths are blocked, and the push and scheduled runs on `main`
  go red. Unrelated merges keep flowing.
- Local builds need Docker. Use a unique `localhost/` tag on a shared daemon and remove it with `make scc-image-clean`.

## Open items

1. Exit codes are undocumented. Ask NIWC (`scc.fct@navy.mil`) whether any exit status is defined; until then, rule 4
   applies.
2. SCC does not leave `/opt/scc` unchanged. Even with `-o`, `-u` and `-dn` it writes
   `Resources/Content/DB/*.db` and `Local/<host>_<timestamp>.db`, and even `--getOpt` tries to create `/root/SCC`
   and to write to `/opt/scc`. FREES-145 must:
   - list every path that changes;
   - prove that `options.xml`, the content and the binaries do not change;
   - get the remaining state writes accepted by the lead architect;
   - find out how a per-run options file can enable an external stream without `-is` or `-isr`. A plain copy of
     `options.xml` skips all content.
3. Whether `--setProfile`, the options file and tailoring accept full XCCDF profile identifiers or only the short
   names of the examples (FREES-145, FREES-146).
4. The zone of SCC's zone-less `start-time` and `end-time` (FREES-145).
5. Whether `cscc` needs environment variables beyond the helper's fixed `PATH`, `LC_ALL` and `LANG`, for example
   `HOME` (FREES-145).
6. A digest for the rest of `/opt/scc`, for example `dpkg --verify` against the pinned package, so that
   operator-installed SCC is checked beyond `cscc` (FREES-145). The package also ships `/opt/scc/scc.sig`, a text
   file of hexadecimal digests whose format and use are not documented.
7. The cyber.mil and NIWC Atlantic web pages could not be read by automated fetch. Their site terms of use and the
   download listing should be checked by a person once.
8. DISA publishes no checksum for SCAP benchmarks. The two-download rule in decision 3 stands until DISA does.
9. Exact CKL and CKLB status strings, schema versions and STIG Viewer compatibility (FREES-147).
10. An aarch64 image and Ubuntu 26.04 content: none until a DISA benchmark for 26.04 exists.
11. Confirming the effective `downloadExternalFiles`, `appCheckForUpdates` and `contentCheckForUpdates` for a run
    (decision 2). SCC reports only which file it loaded and that file's contents. If FREES-145 cannot tie this to
    behaviour with the egress test, the backend never runs SCC.
12. Software expiry.
    - SCC 5.15 logged "Software expires in 30 days" on 2026-10-26, which gives 2026-11-25. Its version date
      2026-08-27 plus 90 days gives the same date. It is pinned as `SCC_EXPIRES := 2026-11-25`.
    - `make scc-expiry-check` fails from 2026-11-18, seven days before that date. FREES-149 starts warning on
      2026-11-04, 21 days before it.
    - The 5.14.1 to 5.15 gap was 120 days, longer than this lifetime, so SCC changes may be blocked and `main`
      may stay red between expiry and the next release. If that happens, the lead architect decides whether to bump
      to whatever release is current or to amend this ADR. The check is never removed silently.
    - What SCC does after expiry is not known. The independent review faked the clock at +40 and +400 days and
      `cscc --version` still exited 0. It could not confirm that the faked time reached SCC's expiry check, so
      `scc-smoke` alone would not notice.
    - `expignore` is documented only for pre-release versions and is not used.

## Amendment 2026-10-26: the backend (FREES-145)

`plugins/module_utils/compliance/scc.py` implements `backend: scc`. Everything below was observed with SCC 5.15 in
the CI image on 2026-10-26 and is exercised again by `make scc-integration` in the `scc-smoke` job.

### What SCC 5.15 does with a per-run options file

| Invocation | Observed |
|---|---|
| `-o FILE -u DIR -dn` (the form decision 2 expected) | Every stream skipped: "SCAP content has been modified since last options file was saved", "No Applicable Content", exit 0. The same happens with `-dn` alone, with a byte-identical copy of the installed `options.xml`, with `-o /opt/scc/options.xml` and after a saving run |
| `-o FILE -u DIR` with `FILE` or `DIR` in a directory owned by another user (a bind mount) | Spins at 100 % CPU after "Gathering system information" with no log, also with input on stdin; killed after 4 and 11 minutes |
| `-cd DIR -u DIR` | Ignores the options in `DIR`, loads and rewrites the installed `options.xml` |
| No `-o` (the default scan) | Scans, and rewrites the installed `options.xml` |
| `-o FILE -u DIR -q -d`, `FILE` mode 0600 in a root-only directory | Scans the stream that `FILE` enables, honours its settings (no checklists, no HTML reports, ARF kept), leaves the installed `options.xml` byte-identical and rewrites `FILE` itself during the run |

The last form is the one the backend uses. It is built from the documented combinable options of decision 2 and
drops `-dn`, which disables scanning, so no `-isr` amendment is needed.

- **Content.** SCC scans only streams in its own content database: an entry for a file outside
  `Resources/Content` is never evaluated, and SCC rescans that directory and updates its database on every run.
  The backend therefore never points SCC at the private copy. `content_path` names the pinned stream as SCC
  installed it (a stream bundled with the pinned release, or one the operator installed with SCC's installer), the
  audit verifies and copies it as for `oscap`, and the backend requires the installed file to have exactly the bytes
  of the private copy before and after the scan. The private copy remains what is hashed and recorded. This
  replaces "SCC reads a private copy in the run directory" in decision 3 and the "bundled content" alternative: a
  bundled stream is used only when it is pinned by its SHA-256, so a new SCC release cannot change it unseen. The CI
  integration test uses the Ubuntu 24.04 stream bundled with 5.15, pinned as `SCC_CONTENT_FILE` and
  `SCC_CONTENT_SHA256` in `scc.pins`.
- **Template.** The options schema of 5.15 requires every global setting in a fixed order. `OPTIONS_TEMPLATE` lists
  all 185, with `downloadExternalFiles`, `appCheckForUpdates` and `contentCheckForUpdates` at `0`, SSH transfer, SCC
  checklists and reports, the summary viewer, deviations and OVAL, OCIL and CPE result files off, the update URLs
  empty, and XCCDF and ARF results and signature checks on. A content entry needs `stream`, `family`,
  `benchmarkID`, `scapVersion`, `filepath`, `checksumSCAP12`, `version`, `xccdf`, the OVAL components and `enabled`;
  without SCC's own `checksumSCAP12` it disables the stream as modified. `checksumSCAP12` is not the SHA-256 of the
  file and its algorithm is not documented, so the backend copies these identifying fields from SCC's record of the
  stream in the installed `options.xml`, parsed through `xmlsafe`, each checked against a strict pattern, and
  enables that one stream with the requested profile. The full XCCDF profile identifier is accepted (open item 3).
- **Zone.** SCC writes `start-time` and `end-time` in the local time zone of its process: with `TZ=FST+05` a scan
  at 12:55 UTC recorded 07:55. The process policy fixes `TZ=UTC0` for `cscc`, and the results parser reads zone-less
  times as UTC only when the caller asks for it (`assume_utc`, used only by this backend). Open item 4 is closed.
- **Environment.** No variable beyond the fixed `PATH`, `LC_ALL`, `LANG` and `TZ` is needed; without `HOME` SCC
  creates no `/root/SCC` (open item 5).

### Process policy (amends decision 2)

`process.py` gains a policy for `cscc` (ADR 0004 amendment of FREES-145): the fixed path `/opt/scc/cscc`, vetted
before every run with every directory on the way to it; `--version` alone; exactly one scan form,
`-o <path> -u <path> -q -d`, with absolute normalised paths; and `TZ=UTC0`. `/opt/scc` is not a trusted directory.
`-d` is used because the debug log is the confirmation. Those logs, and SCC's rewritten options file, stay in the
root-only `scan/scc` directory of the run and are not recorded as evidence.

### Confirmation and the egress test (decision 2)

For every run the backend reads SCC's application debug log and requires that SCC loaded the per-run file and no
other (`options file =`, `Loading options from:`), checked it for a configuration profile and found none
(`selectedConfigProfile:` empty, configuration profile `default`), and dumped it once with the three values at `0`.
Otherwise the run is `failed` with every rule `error`. Unit tests cover a missing confirmation, another options
file, each value at `1` and an enabled configuration profile.

The egress test (`tests/system/scc/test_scc_egress.py`) follows the primary control of decision 2: an internal
network whose only peer is a sink that answers every DNS name with its own address and logs every query, TCP
connection and datagram it receives (a packet socket sees connections to any port). The scanned stream is the pinned
DISA Ubuntu 24.04 benchmark with a remote `component-ref` and a remote `check-content-ref` added, built in CI and
never committed. The installed `options.xml` keeps `downloadExternalFiles=1`, so only the per-run file can turn it
off. Result on 2026-10-26:

- `compliance_scan` with `backend: scc`: `completed`, no query for any probe host, no connection and no datagram.
  SCC did send two DNS queries for `<hostname>.localdomain`, the target's own name, which it resolves to describe
  the host whatever the download setting. The test names that one name, and the bare host name, explicitly as SCC's
  own; every other query fails it.
- Positive control, the same scan form and per-run options with `downloadExternalFiles=1`: a DNS query for the
  remote component host and a TCP connection to port 80 on the sink. The backend's confirmation refuses that run's
  log ("SCC's options dump shows downloadExternalFiles as '1'").

The evidence that the backend reads therefore matches SCC's behaviour, and open item 11 is closed for 5.15. strace
is not in the image and is not used; `--network none` is not used as evidence.

### Completion (decision 4)

A run is `completed` only when the backend created the output and user directories fresh for the run, the
confirmation holds, the user directory holds exactly one application debug log, one session, one XCCDF and one ARF
results file, the results parse through the hardened parser and name the requested benchmark and profile, carry
`start-time` and `end-time` with `start-time` no earlier than the start of the run and no later than `end-time`,
`cscc --version` reported the pinned release, the SHA-256 of `/opt/scc/cscc` is the pinned one, the release has not
expired (2026-11-25 for 5.15, and SCC's own "Software expires in N days" must be positive), and the installed stream
and the private copy did not change. A non-zero exit, a start failure or a timeout is `failed` or `timed_out`; exit 0
is never evidence.

The outcomes map through ADR 0013, with one SCC-specific exception:

| SCC XCCDF result | Finding |
|---|---|
| `pass`, `fail`, `notapplicable`, `notchecked`, `error` | the same outcome |
| `unknown` and any unlisted value | `error`, with a message naming the value |
| `informational` | `notchecked` (flag `informational`) |
| `notselected` | dropped for a rule the profile does not select, otherwise `notchecked` (flag `notselected`) |
| `fixed` | **`error`** ("SCC reported 'fixed', but SCC never remediates"), not the `pass` of ADR 0013 |
| expected rule without a result, or any rule of a run that did not complete | `error` |

SCC has no remediation (FAQ A.8), so a `fixed` result is contradictory output and never evidence of compliance; it is
the only route by which SCC output could otherwise have become `pass` without SCC reporting `pass`. The same
question for `oscap xccdf eval` without `--remediate` is a follow-up for ADR 0013. The integration test asserts that
the 194 findings of a real MAC-1 scan are only `pass`, `fail`, `notapplicable`, `notchecked` and `error`.

The audit accepts datastream file names of up to 128 characters only for `backend: scc` (`LONG_CONTENT_NAME_BACKENDS`
in `audit.py`), because SCC's stream names are longer than 64. Every other backend, OpenSCAP included, keeps the
64-character label rule.

A local user on the managed host who can make text appear in SCC's debug log (for example through a file name that
SCC logs) can add a second, mismatching options record and so make the confirmation refuse the run. That is a denial
of service, a `failed` run with every rule `error`; it can never produce a false confirmation, because every record
must name the run's file and the dump must hold each value exactly once. A directory that SCC fills with more than 16
entries also fails the run instead of being read partly.

### Residual state writes (decision 2, open item 2)

The integration test hashes every file below `/opt/scc` and `/root` before and after a real and a check-mode scan.
`options.xml`, the installed content, the binaries and `/root` are byte-identical. The only changes are:

- `/opt/scc/Resources/Content/DB/SCC_SCAP12_Content.db`, `SCC_SCAP12_Content.db.archive` and `ocil.db` (SCC's
  content database, rebuilt from the installed content on every run);
- a new `/opt/scc/Local` directory and one `<host>_<timestamp>-<number>.db` session database in it.

These are SCC's own bookkeeping, like the temporary files of `oscap`. This amendment proposes to accept them as the
residual of an SCC audit; merging it is the lead architect's acceptance. The test fails on any other change, so the
residual cannot grow unseen.

Operator housekeeping: SCC adds one session database to `/opt/scc/Local` per scan and never removes it, so the
directory grows with every audit (the files observed in CI were small). The collection never deletes anything below
`/opt/scc`, because an audit does not change the host beyond this residual. Operators who scan often remove old
`/opt/scc/Local/*.db` files with their own housekeeping, outside any scan, or reinstall SCC; the content databases in
`Resources/Content/DB` are rebuilt by SCC on every run and need no care.

### Test tooling

`make scc-integration` (an SCC target that builds the image first, run in the `scc-smoke` job after `scc-smoke`)
runs `tests/system/scc` against `SCC_IMAGE`. The image has no Python, so the tests mount the uv-managed interpreter
that runs them, the project's site packages and the repository read-only, and run the real `compliance_scan` module
file inside the container. The integration container has no network (the egress containers only the internal
one), all capabilities dropped except `CHOWN`,
`DAC_OVERRIDE` and `FOWNER` (SCC sets owners and modes of its own files) and `no-new-privileges`. Ruff S603 and S104
are ignored for `tests/system/scc/*.py` only: the tests run Docker and the interpreter with argument
lists, and the sink binds every address of its isolated network.
The tests skip without `FREESECDEV_SCC_IMAGE` and fail instead in CI (`FREESECDEV_REQUIRE_SCC=1`).

### Not yet done

- Disabled rules (`--installTailoringProfile` or a tailoring entry) and the STIG to ComplianceAsCode mapping:
  FREES-146. The backend refuses `disabled_rules`.
- A digest of the rest of `/opt/scc` (open item 6); only `cscc` and the scanned stream are pinned.
- The audit role still offers only `openscap`.
- Pinned DISA benchmarks in the content manifest: the backend accepts any installed stream whose SHA-256 the caller
  pins, and only the benchmark `xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG` for Ubuntu 24.04 hosts.

## Amendment 2026-10-26: off-platform opt-in for Ubuntu 26.04 (FREES-161)

### Context

- **Approval.** The product owner approved this on 2026-10-26. From production use, the owner reports that SCC scans
  Ubuntu 26.04 targets with the Ubuntu 24.04 STIG benchmark.
- **No 26.04 benchmark.** SCC 5.15 ships Ubuntu 18.04 to 24.04 content only. No DISA benchmark for 26.04 was
  published on 2026-10-26.
- **Decision 3 refuses a 26.04 host.** AGENTS.md rule 8 forbids substituting one benchmark for another *silently*.
- **This amendment makes the substitution explicit:**
  - an opt-in that is off by default;
  - exactly one allowed pair;
  - a marker on every result;
  - results kept out of every compliance figure.

**Observed with SCC 5.15 on 2026-10-26.** These runs used `docker.io/library/ubuntu:26.04` pinned by index digest
`sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944` (created 2026-10-06), with the pinned SCC
DEB installed exactly as in the 24.04 image. They scanned the bundled Ubuntu 24.04 stream (`SCC_CONTENT_FILE`) with
profile `MAC-1_Classified`, through the backend's own scan form.

- **With the per-run options of decision 2:**
  - SCC evaluated the stream's CPE-OVAL platform test (`oval:mil.disa.stig.ind:tst:10000006 [false]`).
  - It logged "The SCAP content stream: 'CAN_Ubuntu_24-04_STIG' is not applicable to this target system ... based on
    the Common Platform Enumeration (CPE) tests defined in the content".
  - It ended with "SCC Scan Completed: No Applicable Content", wrote no XCCDF results and exited 0.
  - The backend already reports such a run as `failed` ("SCC wrote 0 XCCDF results files").
  - `filterSCAPContentPerFamily=0` changed nothing.
- **With `saveResultsForNotApplicableContent=1`:**
  - SCC logged "The SCAP content stream <CAN_Ubuntu_24-04_STIG> not applicable to this platform per the XCCDF
    platform-specifications".
  - It wrote one XCCDF results file in which **all 194** rules of the profile are `notapplicable`.
- **The same scan in the 24.04 image** wrote 31 `pass`, 133 `fail`, 13 `notapplicable`, 16 `notchecked` and 1
  `unknown` (6.7 % `notapplicable`).

So with the default options the stream's own platform test rejects Ubuntu 26.04.

**The setting that skips the platform test.** The owner then reported that production uses an SCC setting that skips
the platform applicability check. SCC 5.15 documents two settings for it.

| Setting | Where | Default | Documented meaning |
|---|---|---|---|
| `ignoreCPEOVALResults` | Global option in `options.xml` and `options.xsd`. GUI: Options, SCAP Processing, "Run all content regardless of applicability" | `0` (shipped `options.xml` and the FREES-145 template) | "Run SCAP content even if CPE OVAL applicability fails" (User Manual, option table, page 73). "This option will ignore the content's CPE-OVAL results and continue processing the content against the system. This option can be used to run content that is not normally applicable to the target system (e.g. Red Hat SCAP content on a Debian system). Note that this option alters the standard SCAP rules for gathering certain objects which can result in incomplete results and/or false positives." (section 4.4.1.1) |
| `applicableToAllTargets` | Per stream, in each `content` record of `options.xml`; not declared in `options.xsd`. CLI `-aa, --applicableToAll ID [VERSION]` and `-na, --notApplicableToAll`. GUI: section 4.2.7.4 "Applicability" | `0` for every stream | "Make benchmark applicable to all targets" (section 5). "By default, SCC only performs scan using SCAP content if the content is applicable to a given target. This option forces SCC to perform a scan of a specific content stream against all targets." (4.2.7.4) |

What was checked:

- `cscc --help` and the CLI options of `CSCC-Readme.txt` and the User Manual (section 5). The only applicability
  options are `-aa` and `-na`. Both change the installed `options.xml`, which decision 2 refuses.
- The shipped `/opt/scc/options.xml`, `Resources/Schemas/options.xsd`, `ReleaseNotes.txt` and the 137-page
  `SCC_UserManual.pdf` shipped in the DEB. No configuration profile is installed: only the GUI forms for profiles (`bin/Forms_wx/Form_ConfigProfiles.pm`) exist.
- The settings named in the question (`applicabilityCheck`, `ignoreCPE`, `scanAllContent`, `forceApplicable`,
  `applicableContentOnly`, `contentApplicability`) do not exist in 5.15. `filterSCAPContentPerFamily` filters by OS
  family only, and was shown above to change nothing.

Observed on 26.04 on 2026-10-26, each setting on its own in the per-run options, with everything else from the backend:

- **`ignoreCPEOVALResults=1`:**
  - SCC's scan log says "Ignoring CPE-OVAL Results and continuing scanning with the selected SCAP stream."
  - Result: 28 `pass`, 136 `fail`, 13 `notapplicable`, 16 `notchecked` and 1 `unknown` (6.7 % `notapplicable`).
  - SCC's options dump shows `ignoreCPEOVALResults` as `1`, once.
  - The confirmation of decision 2 accepts the log, with the three download and update settings at `0`.
- **`applicableToAllTargets=1` in the content record:**
  - SCC also logs "Content has been set to be applicable to all targets".
  - The results are the same.
  - SCC's dump shows that element several times, so it cannot be confirmed as one value.

The owner's statement is therefore reproduced with SCC's documented global setting.

With `ignoreCPEOVALResults=1` and `saveResultsForNotApplicableContent=1` together, SCC still logged that the stream is
"not applicable to this platform per the XCCDF platform-specifications" but then evaluated it, with the same results
and without the "Ignoring CPE-OVAL Results" line. The second setting therefore adds nothing and blurs SCC's record, so
it stays `0`.

### Decision

1. **Opt-in.**
   - `compliance_scan` gains `allow_off_platform_benchmark`, a strictly typed `bool` that defaults to `false`.
   - It is carried as `AuditJob.allow_off_platform_benchmark` and `ScanRequest.allow_off_platform_benchmark`, and a
     non-boolean value is refused at both places.
   - Only `backend: scc` accepts it (`audit.OFF_PLATFORM_BACKENDS`). With `openscap` the job is refused with
     `invalid_argument`, and the OpenSCAP backend refuses such a request as well. OpenSCAP behaves exactly as
     before.
2. **Allowed pairs, exact.**
   - `scc.OFF_PLATFORM_BENCHMARKS` sits next to `SUPPORTED_BENCHMARKS`. It holds exactly one tuple of benchmark ID,
     distribution and version: `("xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG", "ubuntu", "26.04")`.
   - The request's benchmark ID and host distribution and version must equal one tuple exactly. Nothing is
     loosened: the gate is still an exact platform comparison.
   - The refusals:

     | Request | Result |
     |---|---|
     | 26.04 host without the opt-in | Refused, as before. The message says that the opt-in exists. |
     | Opt-in, any other host (22.04, 26.10, Debian, RHEL) | Refused. The message names the allowed pairs. |
     | Opt-in, any unpinned benchmark | Refused. |
     | Opt-in with tailoring | Refused (FREES-146). |
     | Opt-in, 24.04 host | An ordinary on-platform run, without a marker. |

3. **Marker** ([ADR 0013 amendment](0013-normalized-findings-model.md#amendment-2026-10-26-off-platform-marker-frees-161)).
   - An allowed off-platform run carries `off_platform`, with `benchmark_platform` (`ubuntu 24.04`) and
     `target_platform` (`ubuntu 26.04`), each as `distribution_id` and `distribution_version`.
   - The marker is on the ScanRun and on every finding, also when the run fails or times out.
   - The scan run is then findings model schema 1.1.
4. **Per-run options.**
   - Only for a marked off-platform run, the backend writes one setting as `1` (`scc.OFF_PLATFORM_OVERRIDES`):
     `ignoreCPEOVALResults`, so that SCC evaluates the 24.04 stream on the 26.04 host although the stream's CPE-OVAL
     platform test does not match.
   - Every other value of the template is unchanged, `saveResultsForNotApplicableContent` included (`0`). An unmarked
     options document is the template byte for byte, which a unit test checks.
   - The global setting is used, not `applicableToAllTargets`. It is documented in the option table and the schema,
     the per-run file enables only the one pinned stream, and SCC's dump shows it exactly once, so the confirmation
     can bind it to the run.
   - **The confirmation covers both settings.** `confirm_options` requires SCC's dump to show each exactly once:
     - `ignoreCPEOVALResults` as `1` for a marked run and as `0` for every other run;
     - `saveResultsForNotApplicableContent` as `0` for every run.

     A 24.04 run whose log showed the platform test ignored is therefore `failed`, like a run with a download setting
     at `1`. The check still requires `downloadExternalFiles`, `appCheckForUpdates` and `contentCheckForUpdates` at `0`
     for every run, as before.
   - On-platform runs keep both settings at `0`, so their options are byte-identical to FREES-145.
   - **Scope of the change:**
     - **What it changes.** Ignoring the platform test changes which checks of the pinned, signed stream SCC
       evaluates on the host: the same OVAL definitions and NIWC shell-command checks that run as root on a 24.04
       host now run on a 26.04 host.
     - **What it leaves alone.** It does not change what SCC may fetch: retrieval is governed by
       `downloadExternalFiles` and the update settings, which stay confirmed at `0`. The egress test of decision 2
       therefore still covers the setting it was built for. The off-platform integration case runs without a network.
     - **State.** It does not change where SCC writes. The off-platform case checks that the state changes stay within
       the accepted residual.
     - **Accuracy.** SCC itself warns that the results may be incomplete or false positives. This is why every result
       is marked and kept out of every figure, and why the threshold of decision 5 stays.
     - **Threat model.** See T-SCC-4 in the [threat model](../security/threat-model.md#t-scc-4-off-platform-checks-run-on-another-release).
5. **Mostly-notapplicable runs are failed, not flagged.**
   - The rule: a completed off-platform run in which `notapplicable` findings exceed
     `OFF_PLATFORM_NOTAPPLICABLE_PERCENT` (50) percent of the expected rules becomes `failed`. Every expected rule is
     then `error`. The comparison is strict and in integer arithmetic: `notapplicable * 100 > 50 * expected`.
   - The message names the counts and the two platforms. SCC's `results.xml` and `results-arf.xml` stay in the
     evidence directory.
   - The threshold never applies to an on-platform run.
   - Why failed and not a flag:
     - **Existing consumers already handle a failed run.** A failed run follows the ADR 0013 path that every consumer
       already handles:
       - the module fails the task by default (`fail_on_incomplete`);
       - summaries and reports withhold the percentage;
       - `compare_scans` reports an incomplete comparison with no figures;
       - FREES-147 maps the run to Not Reviewed.

       A new flag would have to be learnt by each of them. One consumer that missed it would read "0 failed" as clean.
       A run that SCC judged entirely not applicable has 0 `fail` and 0 `error`, which is exactly what a gate counts.
     - **Most rules not applying is not evidence.** When most rules do not apply, the benchmark's applicability checks
       do not fit the host, and the few `pass` and `fail` results are not meaningful evidence about it.
     - **Nothing is lost.** SCC's own results remain as evidence for the operator.
   - Why 50 percent:
     - "Mostly" means more than half.
     - On the benchmark's own platform the CI image reports 6.7 %. Minimal hosts and containers report more, so a much
       lower limit would fail legitimate off-platform runs.
     - On 26.04 with the platform test ignored the result is also 6.7 %; with the platform test applied, 100 %.
   - **The threshold stays as a safety net.** With `ignoreCPEOVALResults` the threshold no longer decides the observed
     26.04 run. It still fails any run in which SCC ignored the setting, or in which the benchmark's rule-level checks
     reject most of the host.
   - Rejected alternatives:

     | Alternative | Reason rejected |
     |---|---|
     | A flag on a completed run | See above |
     | A limit of 20 % or less | Fails legitimate runs on minimal hosts |
     | A comparison with a 24.04 reference scan of the same host | No such reference exists for a 26.04 host |

6. **Never read as compliant.**
   - An off-platform run that completes below the threshold is still never compliance with a 26.04 baseline.
   - The module's `summary` carries `off_platform`, the marker or `null`, so a consumer that reads only the summary
     sees the label.
   - **Host coverage (review of PR #47, blocking).** A target host whose bundles in a report all carry the marker has
     no on-platform evidence. `host_coverage` counts it in `off_platform`, it gets a missing input of its own, and the
     coverage is `incomplete`, so `--require-host-coverage` fails and the compliance section has no summary or pooled
     figure. No option lets such a fleet pass; one would need its own decision and must never be the default.
   - The report keeps it out of every figure and lists it separately
     ([ADR 0016 amendment](0016-report-schema-and-summary-semantics.md#amendment-2026-10-26-schema-22-off-platform-results-frees-161)).
   - The dashboard labels it ([ADR 0017 amendment](0017-offline-html-dashboard.md#amendment-2026-10-26-off-platform-results-frees-161)).
   - The `audit` role still offers only `openscap`, so the opt-in is available to direct module use only.
7. **CKL and CKLB export (FREES-147, not yet built).**
   - **Every finding that carries the off-platform marker maps to Not Reviewed, whatever its outcome.**
   - So does every finding of a run that carries it.
   - The finding details name the benchmark platform and the target platform.
   - The status mapping table of decision 9 gains this row; it precedes every other row:

     | Normalized finding | Checklist status |
     |---|---|
     | any finding with an `off_platform` marker, or of a run with one | Not Reviewed, with "off-platform: the ubuntu 24.04 benchmark on an ubuntu 26.04 host" in the finding details |

   - An off-platform `pass` never becomes Not a Finding. An off-platform `fail` is not Open either, because the
     checklist would otherwise record a 26.04 host against a 24.04 STIG as if it had been reviewed.
8. **Host identity.**
   - The gate, like the 24.04 gate, compares the `host` that the caller supplies, usually from gathered facts.
   - **The module checks it.** For `backend: scc` the module reads `/etc/os-release` on the managed host before
     anything is created (`audit.check_host_release`). It stops with `host_mismatch` unless `ID` and `VERSION_ID` equal
     `host.distribution_id` and `host.distribution_version`, and also when the file cannot be read. The OpenSCAP
     backend is unchanged: Ansible's distribution facts differ from `os-release` on several of its platforms (for
     example `redhat` and `rhel`).
   - **SCC is the backstop below that check.** A 26.04 host declared as 24.04 reaches SCC only if the release check
     is bypassed. The unmarked options then keep the platform test, SCC rejects the stream, and the run fails ("SCC
     wrote 0 XCCDF results files"). The integration case proves this through the backend itself.
9. **Raw copies are named and refused.**
   - The XCCDF and ARF copies of a marked run are `scan/results.off-platform.xml` and
     `scan/results-arf.off-platform.xml`. Evidence bundles allow-list both names as `raw/scan/...`.
   - The report's XCCDF and ARF parsers refuse, as an input `error`, any file named `*.off-platform.xml`. They also
     refuse any file whose directory, or the directory above it, holds a `scan-run.json` that carries the marker or
     cannot be read as a scan run.
   - Off-platform runs are reported through `scan-run.json` or evidence bundles, which carry the marker.
10. **Integration case.**
    - `extensions/ci/scc/Containerfile.ubuntu2604` is the Containerfile of decision 10. Only the base, pinned by index
      digest, and two labels differ, and a repository test enforces that.
    - `make scc-image-ubuntu2604` builds it as `SCC_IMAGE_UBUNTU2604` (`$(SCC_IMAGE)-ubuntu2604`, a `localhost/` tag).
      `make scc-integration` builds it and runs `tests/system/scc/test_scc_off_platform.py`. `make scc-image-clean`
      removes both images.
    - It runs inside the existing `scc-smoke` job, whose path filter already covers `extensions/ci/scc/`,
      `tests/.*scc` and `scc.py`.
    - The test asserts:
      - without the opt-in, a 26.04 host is refused;
      - a host that claims 24.04 is refused by the release check (`host_mismatch`);
      - below the release check, an unmarked backend scan of the host self-asserted as 24.04 is still stopped by SCC's
        CPE platform test: SCC logs that the stream "is not applicable to this target system", writes no results, and
        the run is `failed` with every rule `error` and no marker;
      - with the opt-in, SCC's scan log says that it ignored the CPE-OVAL results;
      - the run completes with real results: honest outcomes only, both `pass` and `fail`, and at most 50 %
        `notapplicable`, equal to SCC's own kept XCCDF results;
      - the run and every finding are marked, and the raw copies have the off-platform names;
      - the state changes stay within the accepted residual.
    - The never-publish guard covers the new file and target like the others.

### Consequences

- A DISA benchmark for Ubuntu 26.04, once published and pinned, replaces the pair. It is added to
  `SUPPORTED_BENCHMARKS`, and the pair is removed from `OFF_PLATFORM_BENCHMARKS` by an amendment.
- Open item 10 is unchanged: the project still has no 26.04 content.
- Completed off-platform runs below the threshold are now the normal case. They remain labelled, excluded from every
  figure, and Not Reviewed in checklists.
- If SCC stops honouring `ignoreCPEOVALResults`, its platform test rejects the stream again and writes no results, so
  the run fails. If its dump stops showing the value, the confirmation fails the run. If it evaluates the stream but
  most rules come back `notapplicable`, the threshold fails the run. In every case the integration test fails, and the
  change is reviewed.

## Note 2026-10-26: the checklist exporter (FREES-147)

Decision 9 and decision 7 of the FREES-161 amendment are implemented by
[ADR 0020](0020-stig-viewer-checklist-export.md), which closes open item 9:

- The status strings are `NotAFinding`, `Open`, `Not_Applicable` and `Not_Reviewed` in CKL and `not_a_finding`,
  `open`, `not_applicable` and `not_reviewed` in CKLB; the sources and the `cklb_version` are in ADR 0020.
- The table of decision 9 holds, with the off-platform row first. Two refinements: a `pass` reported as `fixed` is Not
  Reviewed, and an expired or lapsed exception is named in the comments of an Open entry.
- "Rule titles and other benchmark text come from the pinned DISA content at export time" means the pinned stream as
  SCC evaluated it: the XCCDF results in the run's evidence bundle, which embed it, or the stream itself given with
  `--checklist-content`.
- `oscap` results are refused with a message that names FREES-146 until decision 8 is built.
- `make scc-integration` exports the real scans of both images and reads the checklists back inside the container.

## References

- NIWC Atlantic SCC release record and archive: <https://github.com/niwc-atlantic/scap-scc> (`scc_release.xml`,
  `README.md`, `LICENSE.md`, commit history), read 2026-10-26.
- DISA download host: <https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_5.15_Readme.txt>,
  <https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_5.15_Checksums.txt>,
  <https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_5.15_ReleaseNotes.txt>,
  <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.15_linux_x86_64_bundle.zip>, read 2026-10-26.
- Shipped documentation in the 5.15 bundle: `SCC_5.15_linux_x86_64_UserManual.pdf` (sections 2.2, 3, 4.2.2, 4.4,
  5, 7.2, appendices A, E, F, G), and in the DEB `/opt/scc/Documentation/CSCC-Readme.txt`,
  `/opt/scc/Documentation/TermsOfUse.txt`, `/opt/scc/Documentation/ThirdPartyLicenses.txt`, `/opt/scc/options.xml`
  and the package maintainer scripts.
- DISA benchmark: <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-3_Benchmark.zip>,
  read 2026-10-26.
- Official landing pages (not machine-readable here): <https://www.niwcatlantic.navy.mil/Technology/SCAP/>,
  <https://www.cyber.mil/stigs/SCAP/>.
