# 0026. No script or remediation code of the scanner content reaches a managed host

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement of 2026-10-30: remediation is our own Ansible, and the code
  of ComplianceAsCode is not trusted)
- **Jira:** FREES-191 (follows from the FREES-188 audit)
- **Pull requests:** introduced by the pull request for FREES-191
- **Related:** ADR 0025 "Remediation is our own Ansible only" (pull request #72, FREES-188), which this ADR amends;
  [ADR 0003](0003-native-module-remediation.md), [ADR 0004](0004-audited-process-execution.md),
  [ADR 0013](0013-normalized-findings-model.md), [ADR 0015](0015-content-acquisition-and-pinning.md) (amended here),
  [threat model T-AUDIT-2](../security/threat-model.md#t-audit-2-sce-check-scripts-run-as-root)

## Context

ADR 0025 (FREES-188) makes remediation our own Ansible and keeps the scanner content for auditing. The audit itself
still ran code written by ComplianceAsCode. The pinned datastreams embed shell scripts for the OpenSCAP Script Check
Engine (SCE), and `oscap xccdf eval` runs them as root while it audits (threat model T-AUDIT-2). Nothing confines
those scripts to reading the host.

Counted in the pinned content (`v0.1.82`, `make content`, golden test
`tests/unit/tools/test_content_golden_scripts.py`):

| Datastream | Rule checks by system | SCE scripts (`ds:extended-component`) | Rules with an SCE check | SCE plus OVAL | SCE plus OCIL only |
|---|---|---|---|---|---|
| `ssg-ubuntu2404-ds.xml` | OVAL 625, OCIL 586, SCE 81 | 81 | 81 | 63 | 18 |
| `ssg-rhel9-ds.xml` | OVAL 1467, OCIL 1497, SCE 438 | 438 | 438 | 434 | 4 |

No other check system appears, and the content has no `complex-check`. OCIL is a questionnaire, which `oscap` does not
run. OVAL is declarative. Per pinned profile, the rules with an SCE check and the rules whose only automated check is SCE
are:

| Profile | Rules | With SCE | SCE without OVAL |
|---|---|---|---|
| Ubuntu `cis_level1_server` | 408 | 72 | 16 |
| Ubuntu `cis_level1_workstation` | 399 | 68 | 16 |
| Ubuntu `cis_level2_server` | 510 | 75 | 17 |
| Ubuntu `cis_level2_workstation` | 507 | 75 | 17 |
| Ubuntu `stig` | 239 | 12 | 1 |
| RHEL 9 `anssi_bp28_enhanced`, `_high`, `_intermediary`, `_minimal` | 310, 388, 227, 40 | 68, 72, 66, 7 | 0 |
| RHEL 9 `bsi` | 192 | 12 | 0 |
| RHEL 9 `ccn_advanced`, `ccn_basic`, `ccn_intermediate` | 153, 101, 140 | 27, 26, 27 | 0 |
| RHEL 9 `cis`, `cis_server_l1`, `cis_workstation_l1`, `cis_workstation_l2` | 401, 295, 288, 395 | 42, 41, 37, 41 | 0 |
| RHEL 9 `cui`, `e8`, `hipaa`, `ism_o`, `ospp` | 139, 94, 131, 146, 139 | 16, 22, 14, 26, 16 | 0 |
| RHEL 9 `pci-dss` | 252 | 27 | 1 |
| RHEL 9 `stig`, `stig_gui` | 481, 477 | 52, 52 | 2, 2 |

`oscap` 1.3.9 uses the last check of a rule whose system it supports, and ComplianceAsCode lists the SCE check first.
A rule that also has an OVAL check is therefore evaluated through OVAL, and the scripts run for the rules without one.
With the default `cis_level1_server` profile, that is 16 rules on every Ubuntu 24.04 audit.

`oscap` 1.3.9 cannot be told to skip SCE. This was checked on 2026-10-30 against the pinned `openscap-scanner`
`1.3.9+dfsg-1.1ubuntu2` in the CI oscap image, and against the OpenSCAP source at tag `1.3.9`:

- `oscap --version` lists `SCE Version: 1.0 (from libopenscap_sce.so.25)` under "Capabilities added by auto-loaded
  plugins". `libopenscap_sce.so.25` ships in `libopenscap25t64`, the library package itself, so it cannot be
  removed on its own.
- `oscap xccdf eval --help` has no option for check engines except `--check-engine-results`, which only exports
  their results. `--skip-rule` and a tailoring file deselect single rules, which would also drop the result of every
  rule they name.
- `src/XCCDF/xccdf_session.c`: `xccdf_session_new_from_source` sets `loading_flags = XCCDF_SESSION_LOAD_ALL`, and
  `xccdf_session_load` calls `xccdf_session_load_check_engine_plugins` whenever `XCCDF_SESSION_LOAD_CHECK_ENGINE_PLUGINS`
  is set. That function loads every name in `check_engine_plugin_get_known_plugins()`, which is only
  `libopenscap_sce.so.<n>` (`src/XCCDF_POLICY/check_engine_plugin.c`).
- `utils/oscap-xccdf.c` calls `xccdf_session_set_loading_flags` only in `generate fix` and `generate guide`, never in
  `app_evaluate_xccdf`. So `xccdf eval` always loads SCE, and no command-line option clears the flag.
- `check_engine_plugin_load2` reads only the environment variable `OSCAP_CHECK_ENGINE_PLUGIN_DIR`, a prefix for the
  `dlopen` path. Pointing root's `dlopen` at another directory would add a code-loading path, and the process helper
  does not pass the variable (ADR 0004).
- `src/XCCDF_POLICY/xccdf_policy.c` `_xccdf_policy_rule_get_applicable_check` keeps the last check whose engine is
  registered. This is why a check that the scanner never registers (OCIL) leaves a rule `notchecked`.

The only reliable control is therefore the content: an SCE check or script that is not in the datastream cannot run.

## Decision

1. **The controller removes every SCE check and script before the content leaves it.**
   `tools/content/fetch_content.py` (`make content`, `make molecule-content`, `make test-oscap-integration`) extracts the
   published datastream, checks it against `source_sha256` and `source_size_bytes`, and runs
   `tools/content/script_checks.py`. That removes every SCE `check` of a rule, every `ds:extended-component`, every
   `ds:component-ref` that points at one and every catalog `uri` that points at such a reference. It also removes
   every XCCDF `fix` of a rule: the content's remediation code (Bash, Ansible, Puppet, kickstart, Anaconda, bootc,
   Kubernetes and image blueprint). `oscap` would run a fix only with `--remediate`, which the process helper refuses,
   but the owner does not want that code on a managed host at all, and FREES-188 already stopped the collection from
   reading it. The `fixtext` prose stays, because the checklist export shows it. A `fixtext` whose `fixref` names a
   removed `fix` fails closed, and so does a `fix` outside a rule. The pinned content has no `fixtext`.

   | Datastream | `fix` elements | By system |
   |---|---|---|
   | `ssg-ubuntu2404-ds.xml` | 1257 | sh 589, ansible 503, puppet 88, blueprint 53, kubernetes 24 |
   | `ssg-rhel9-ds.xml` | 3460 | sh 1316, ansible 1294, kickstart 179, puppet 152, kubernetes 160, anaconda 134, blueprint 126, bootc 99 |

   Stripping the fixes needs the catalogue's values to come from the profile, not from the fixes. FREES-188 (ADR
   0025, pull request #72) provides that, so this change is based on it.
   - The document is parsed once with the bounded parser of `xmlsafe` (no DOCTYPE, no entities, bounded size and
     depth). The parser now reports the byte offset of every tag, and the elements are cut out of the original bytes.
     Nothing is serialised again, so every other byte stays as published and the result is reproducible.
   - It fails closed on anything it does not recognise, then parses the result again and refuses any script check left.
   - Both processed datastreams passed `oscap ds sds-validate` in the CI oscap image when this was introduced, and
     the CI job `oscap-integration` evaluates the processed Ubuntu 24.04 datastream on every run.
2. **Both digests are pinned.** `content/manifest.yml` records, per datastream:
   - `source_sha256` and `source_size_bytes`: the published member;
   - `removed_sce_checks`, `removed_sce_scripts` and `removed_fix_elements`: 81, 81 and 1257 for Ubuntu 24.04, and
     438, 438 and 3460 for RHEL 9;
   - `sha256` and `size_bytes`: the processed datastream.

   A difference in any of them stops the fetch, and no file is written. Every consumer of `sha256` pins the processed
   datastream: the discover and audit roles, Molecule, the catalogue (`content_sha256` of the profile values) and the
   STIG mapping. A published datastream with scripts no longer has a pinned digest.
3. **The hosts refuse script checks at run time, whatever the source of the content.**
   - `catalog.refuse_script_check` refuses an XCCDF `check` whose system is not OVAL or OCIL, any element of the SCE
     namespace, any `ds:extended-component`, and any XCCDF `fix`.
   - The refusal runs on every parse of a datastream (`benchmark_info`, `profile_info` and the audit's profile check)
     and on the bytes of the private copy that `oscap` reads, which `audit.copy_content` parses while it hashes them.
   - Modules report `script_check_content`, and nothing is scanned. Operator-supplied content is held to the same rule.
4. **Reporting stays accurate.** A rule whose only automated check was SCE keeps its OCIL check. `oscap` cannot
   evaluate that, so the rule is `notchecked`: never `pass`, and never `fail` on a script we did not write. A rule with
   an OVAL check keeps its result. The CI job `oscap-integration` asserts both on the runner:
   - no rule-result names an SCE check;
   - the 16 former SCE-only rules of `cis_level1_server` keep only OCIL and are `notchecked` or `notapplicable`.

   A container evaluation of `cis_level1_server`, before and after, changed exactly the rules that had run SCE (`pass`
   to `notchecked`). The other 646 results were identical. Removing the fixes as well gave the same results: they
   play no part in an evaluation.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Keep SCE and trust the pinned digest (the previous T-AUDIT-2 position) | Runs ComplianceAsCode code as root on every audited host |
| Ask operators to list the SCE rules in `disabled_rules` | Opt-in, per profile, and the scripts still ship to the host |
| Disable the plugin with `OSCAP_CHECK_ENGINE_PLUGIN_DIR` | Undocumented, redirects root's `dlopen` and adds a code-loading path (ADR 0004) |
| Re-serialise the datastream with an XML library | Changes prefixes and bytes that QName values depend on; harder to review and to reproduce |
| Remove only the SCE checks and keep the scripts | The scripts would still reach the host; a future content or scanner change could reach them again |
| Refuse content with SCE without preprocessing it | Every pinned datastream has SCE checks, so nothing could be audited |

## Benefits

- No script or remediation code written by ComplianceAsCode reaches or runs on a managed host. The scanner evaluates
  only OVAL, which `oscap` interprets. The processed datastreams are a third smaller (8.6 MB and 18.6 MB).
- The decision holds for operator-supplied content too, and it fails closed.
- The change is reproducible and pinned: the processed digests and the numbers removed are in the manifest and the
  golden test.

## Trade-offs

- 18 Ubuntu 24.04 rules and 4 RHEL 9 rules have no automated check left, and they report `notchecked`: the iptables,
  ip6tables, nftables and ufw firewall rules, and the file-system-wide checks for world-writable or unowned files.
  Native OVAL or our own checks for them are follow-up work.
- `fetch_content` now holds a datastream in memory while it processes it (at most the 256 MiB member limit; the pinned
  ones are 12.6 and 28.9 MB). It runs as a module (`python -m tools.content.fetch_content`, through `make content`)
  because it uses the collection's hardened parser.
- A content update must pin the new processed digest and the new removal numbers.

## Security implications

Removes root code execution from the audit path. The remaining trust in the content is the OVAL, which `oscap`
evaluates as root but which is declarative. The refusal runs on the bytes that `oscap` reads, after the digest
check, so a swapped or operator-supplied datastream cannot bring scripts back. The `xmlsafe` change only adds a
position callback to its existing bounded parse. The transform parses with the same parser and never serialises
untrusted content again. A change to `script_checks.py`, `catalog.refuse_script_check` or `xmlsafe` needs a security
review.

## Operational consequences

- Fetch content only with `make content` (or `make molecule-content`), and pass the processed datastream's `sha256`
  from `content/manifest.yml` to the discover role. A raw ComplianceAsCode datastream fails discovery with
  `script_check_content`.
- Once ADR 0025 (pull request #72) has merged, its decision gains the item "no script of the content runs on a managed
  host, not even to audit (ADR 0026)" and a link to this ADR, and this ADR links back to it.
