# 0015. Content acquisition and pinning

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-42, FREES-43
- **Pull requests:** pending (FREES-42)
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

Audits are only as trustworthy as the benchmark content they evaluate. The first scope is Ubuntu 24.04 and RHEL 9
([ADR 0010](0010-initial-os-and-benchmark-scope.md)) with ComplianceAsCode (SCAP Security Guide) datastreams, which
are published under the BSD-3-Clause licence. A datastream is a large XML document that a host reads as root through
`oscap`, so content that changed silently, or that was swapped by whoever controls a mirror, would change what is
reported as compliant. The release archive also contains Ansible playbooks and Bash remediation scripts, which this
project must never run ([ADR 0003](0003-native-module-remediation.md)).

## Decision

### Pin and double verification

`content/manifest.yml` is the single record of the content that the project uses. It names one release of
ComplianceAsCode, currently `v0.1.82`, and records for that release:

- the release and download URLs, the licence, the publication time (a pin is at least seven days old, unless it is a
  security fix) and the size and **SHA-512 of the release zip**, copied from the `.sha512` file that upstream
  publishes next to the zip;
- for each in-scope datastream, its path inside the zip, its size, its **SHA-256**, its benchmark identifier and
  version, and the profiles it contains, with identifiers and titles read from the datastream itself. A profile is
  listed only if the datastream contains it. Nothing is added by hand.

The manifest is updated by a person who downloads the zip, verifies it against the upstream `.sha512` file, extracts
the datastreams and computes their SHA-256. The digest is never taken from the same download that it is used to
verify. Verification happens twice, at two different places:

1. **Controller, at fetch time.** `tools/content/fetch_content.py` verifies the archive SHA-512 before it opens the
   archive and the SHA-256 of every extracted datastream before it is renamed into place. A mismatch deletes the
   partial file and fails. Amended by [ADR 0026](0026-no-content-scripts-on-hosts.md) (FREES-191): the extracted
   member is checked against `source_sha256` and `source_size_bytes`, its Script Check Engine checks and scripts are
   removed (`removed_sce_checks`, `removed_sce_scripts`), and the processed datastream must have `sha256` and
   `size_bytes`, which every later step pins. Only the processed datastream is written.
2. **Managed host, at use time.** The `benchmark_info` and `profile_info` modules (and every later consumer) take the
   expected SHA-256 as an argument, hash the file and refuse to parse it when the digest differs. The file is opened
   once, hashed, rewound and hashed again while it is parsed, so content that changes between the two reads, or a path
   swapped after the type check, is rejected too (the repository guard allows `os` only as `os.path`, so `O_NOFOLLOW`
   is not available).

### Fetching, offline mode and the extraction rules

The tool downloads the archive over HTTPS only. Redirects are followed only to other HTTPS URLs, certificates are
verified with the default trust store, and the download is capped at the size in the manifest. With `--from-file`
the tool reads a pre-downloaded archive and never touches the network, which is the supported way to work in air-gapped
environments and in tests.

The tool extracts only the datastreams that the manifest lists. It finds each member by its exact manifest path and
never builds a path from a name in the archive, so a hostile archive cannot write elsewhere (zip-slip). A member must
be unique, a regular file (symlinks, directories and special files are refused), unencrypted and exactly the size that
the manifest records. The bytes are streamed into a temporary file with mode 0600, hashed, and renamed to the output
directory with mode 0644 only if the SHA-256 matches. Nothing else in the archive is read.

### No redistribution

The repository contains the manifest and the existing BSD-3-Clause notice in `NOTICE`, and nothing else from
ComplianceAsCode. Downloaded archives and datastreams are never committed, packaged into the collection tarball or
published as release artifacts; `.gitignore` ignores `*.zip`, the default output directory is `build/content`, and a
unit test fails if anything but the manifest appears in `content/`. The profile titles that the manifest records are
short identifying strings, not benchmark text. Profiles named after CIS, DISA STIG or ANSSI are ComplianceAsCode
implementations, not content certified or endorsed by those organisations. Restricted content such as CIS-CAT or CIS
PDFs is outside this decision and stays excluded.

### Playbooks and Bash fixes are never used

The release zip contains generated Ansible playbooks and Bash fixes. They are never extracted, read or executed.
Their Ansible tasks use `shell` and `command` for many rules, and `oscap --remediate` runs Bash as root, which
ADR 0003 excludes. The manifest has no field that could name such a member, the manifest validator accepts only paths
that end in `-ds.xml`, and the process helper already refuses `--remediate` and `generate fix`
([ADR 0004](0004-audited-process-execution.md)). Remediation is implemented natively and is keyed by the rule
identifiers that the datastream defines.

### Discovery on the host

`benchmark_info` and `profile_info` are read-only (`changed` is always false, check mode behaves like a normal run)
and parse the datastream through a bounded streaming parser (`plugins/module_utils/compliance/xmlsafe.py`) that
rejects DOCTYPE and entity declarations. `plugins/module_utils/compliance/catalog.py` keeps only the benchmark, its
profiles and the identifier, severity and title of each rule. The selected rules of a profile are the rules that
profile selects, the last `select` winning and the rule's own `selected` default applying to rules it does not
mention. A profile that selects a rule the benchmark does not define is rejected, a missing profile is an error and
never replaced by another one, an unresolved construct (see the trade-offs) is an error, and a datastream with more than one benchmark is refused. The audit module (FREES-49)
uses the sorted rule identifiers as `expected_rule_ids`.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Install the distribution package (`ssg-base`, `scap-security-guide`) | Version differs per distribution and release, so results are not reproducible and the pin is lost |
| Commit the datastreams | Redistribution of upstream content and a 40 MB repository growth per update; the manifest gives the same assurance |
| Trust the `.sha512` file fetched at run time | The digest and the file come from the same server, so they prove nothing against a compromised mirror |
| Extract the whole archive | Brings playbooks and Bash fixes into the working tree where they can be run by mistake (ADR 0003) |
| `urllib.request.urlopen` | Follows redirects to any scheme that the opener supports and is flagged by Bandit; `http.client` with an explicit HTTPS-only redirect loop is smaller and stricter |

## Benefits

Reproducible audits against a known content version, tamper detection at two places, a small attack surface for the
archive and an air-gapped path that needs no special code.

## Trade-offs

Updating the pin is a manual, reviewed step. The catalog fails closed on XCCDF constructs whose rule selection it does
not resolve: a profile with `extends`, or a profile that selects a rule below a deselected group, makes the whole
datastream fail with `unsupported_content`, naming the profile, and no partial or guessed rule list is returned. Group
`select` entries and group `selected` defaults are otherwise evaluated (the last `select` wins, then the group default).
All 25 pinned profiles contain group deselections (`selected="false"`), none selects a group `true`, no group is
deselected by default and no selected rule sits below a deselected group, so they resolve to the same lists as plain
rule selection. `select` entries are classified by what the benchmark defines (a Rule or a Group), never by the shape of
the identifier, because rule identifiers such as `..._rule_ensure_pam_wheel_group_empty` contain `_group_`; an
identifier that is neither, or both, fails closed. A golden file (`tests/fixtures/catalog/golden-rules.yml`) records, for
every profile of both pinned datastreams (all 25), the rule count and the SHA-256 of the sorted rule list, and
`make test-content-golden` fetches the pinned content through the digest-verified downloader and compares the catalog
with it. The CI `test-suites` job runs that target and fails, rather than skips, when the content cannot be fetched. Supporting `extends` or deselected groups with selected rules needs a change to the catalog.
Since FREES-126 `openscap.py` parses through `xmlsafe.py` too and no longer carries its own copy of the parser.

One residual risk remains: the open helper of `xmlsafe` (`_open_regular`, private since FREES-129) checks the type with `lstat` and then opens the path. If an attacker who
controls the directory swaps a regular file for a FIFO in that window, the open could block until the module times out.
The result can never be wrong content, because the bytes read are hashed, and an `fstat` check on the descriptor needs
`os`, which the repository guard forbids in plugins. This is accepted and documented. Since FREES-134 (audit) and
FREES-138 (`benchmark_info` and `profile_info`), `catalog.vetted_content_path` refuses content that a user other than
root, or the user the module runs as, could replace, so only those users can open that window
([ADR 0013](0013-normalized-findings-model.md), note of FREES-138 and FREES-139).

## Security implications

The datastream is untrusted until its digest matches the pin, and is still parsed defensively afterwards. The parser
rejects DOCTYPE and entities, UTF-16, NUL bytes, files over 256 MiB, more than 2,000,000 elements (5,000,000 before FREES-126, which took the stricter bound of
the results parser; the pinned datastreams have about 155,000 and 70,000 elements) and nesting deeper
than 64. The fetch tool cannot be made to write outside its output directory or to extract a link. A compromised
upstream release is detected only if the pin is reviewed against an independent source; the manifest records the
publication time so a reviewer can enforce the seven-day rule.

## Operational consequences

Updating content means a pull request that changes `content/manifest.yml` and the profile list together, with the
verification evidence in the description. Changing the repository rule list: `tools/lint/check_repo_rules.py` now
allows `xml.parsers.expat` in `plugins/module_utils/compliance/xmlsafe.py` as well as in `openscap.py`. FREES-126
later removed `openscap.py` from that allowance, so only `xmlsafe.py` may import expat (ADR 0004).
