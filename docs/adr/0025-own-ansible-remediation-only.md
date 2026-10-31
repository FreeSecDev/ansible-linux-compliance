# 0025. Remediation is our own Ansible only; scanner remediation content is never used

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement of 2026-10-30: remediation is written in Ansible by this
  project, and the code of the scanner content is not trusted)
- **Jira:** FREES-188; the open SCE gap is [FREES-191](https://vidlunnia.atlassian.net/browse/FREES-191)
- **Pull requests:** introduced by the pull request for FREES-188
- **Related:** [ADR 0003](0003-native-module-remediation.md) (made stricter here),
  [ADR 0004](0004-audited-process-execution.md), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0015](0015-content-acquisition-and-pinning.md), [ADR 0021](0021-native-banners-pwquality-and-profile-values.md)
  and [ADR 0022](0022-native-sudo-drop-ins.md) (both amended here), [native remediation guide](../native-remediation-guide.md)

## Context

The collection audits with OpenSCAP and the ComplianceAsCode (SSG) datastreams. The same release archive and the
same datastreams also carry the project's remediation: generated Ansible playbooks, Bash scripts, kickstart and
blueprint snippets, and `fix` elements inside every rule of the datastream. ADR 0003 already rules out running
upstream playbooks and `oscap --remediate`, and the process helper refuses the remediation words and the
`generate fix` sequence (ADR 0004). One path still read upstream remediation: since FREES-175 the catalogue generator
could take a profile value from the values that a rule's `fix` elements substitute (`profile_value_source: fix`),
which `sudo_require_reauthentication` used for `var_sudo_timestamp_timeout`. Its check accepts any non-negative
timeout and so does not export the value.

The owner's requirement is that every remediation is written in Ansible by this project and that the scanner
content's code is not trusted. A value read out of a fix is a decision taken by that code. Nothing checked that no
other path would come to rely on it.

## Decision

1. **Remediation is native Ansible only.** Every remediation is a task file of `roles/remediate` that uses only
   `ansible.builtin` modules and this collection's typed modules (ADR 0003). The collection never executes,
   imports, generates, copies or parses remediation content of ComplianceAsCode or OpenSCAP: no generated playbook,
   Bash fix, kickstart or blueprint snippet, no `fix` element of a datastream, no `oscap xccdf eval --remediate`,
   `oscap xccdf remediate`, `oscap xccdf generate fix` or `--fix-type`, and no script that the scanner or its content
   provides.
2. **The OVAL is for auditing and reference only.** The pinned datastreams are evaluated by the scanner to audit a
   host. The OVAL definitions are also read in golden tests (`tests/unit/tools/test_content_golden_native.py`) as the
   reference that pins what our own remediation writes, so that the audit agrees with it. They are never turned into
   remediation.
3. **Values come from the profile's XCCDF values through our own pinned mappings.** `make catalogue` resolves a
   rule's value from the selected profile's `refine-value` and the `Value`'s default and selector options, and from
   nothing else. The mapping from a rule to its `Value` is ours, in `content/catalogue.yml`:
   - `profile_value: <short id>` when the rule's checks export the value (`check-export`), which the generator
     verifies;
   - `profile_value_id: <full XCCDF Value id>` when the check accepts a range and exports nothing, as for
     `sudo_require_reauthentication` and `xccdf_org.ssgproject.content_value_var_sudo_timestamp_timeout`. A golden
     test pins that the identifier exists in every pinned datastream and the value of every profile that selects the
     rule (15 for the CIS profiles, 0 for the STIG profiles, 5 for CCN and PCI DSS), so a content update that changes
     either fails before it reaches a host.

   `profile_value_source` is removed. The generator refuses the key, and `tools/roles/profile_values.py` no longer
   reads `fix` elements at all.
4. **Without a native implementation a rule is scan-only.** Its catalogue strategy is `audit_only`; the audit
   evaluates it, and remediation reports it as `not_implemented` with `changed: false` (ADR 0011). It is never
   remediated by another tool.
5. **A repository guard enforces the decision.** The rule group `tools/lint/repo_rules/own_remediation.py` runs in
   `make lint-repo`, and so in `make lint` and `make ci`, on every tracked file. It refuses:
   - Python outside `tests/unit/`, `docs/` and `changelogs/` (so `tools/`, `plugins/`, the Molecule harness in
     `extensions/` and `tests/system/`) that names the XCCDF `fix` element in a string or bytes constant: a
     constant whose last step, or a step followed by `/`, is `fix` or `fixtext` with an optional predicate, at the
     start or after `/`, `}` or `:`. That covers `fix`, `.//xccdf:fix`, `xccdf:Rule/xccdf:fix`, `.//{ns}fix`,
     `f".//{NS}fix"` (an f-string counts with its placeholders), `.//{*}fix`, the suffix test `}fix` and
     `.//xccdf:fix/text()`. It also refuses a `fix` tag in markup or in a regular expression (`<(\w+:)?fix\b`), a
     `local-name()` test for it and a fix system URN. Unit tests hold these forms as test cases and are not
     checked;
   - any file that is ComplianceAsCode or OpenSCAP remediation content: the release archive's file names (`ssg-*`,
     `*-playbook-*.yml`, `*-script-*.sh`, `*-ks.cfg`), paths below `scap-security-guide*`, generated Bash fixes and
     playbook headers, XCCDF `fix` elements and fix systems, the OpenSCAP kickstart add-on, and task lists tagged like
     the generated playbooks. The collection ships only tracked files, so none of these can reach the tarball;
   - in tasks, playbooks, makefiles, workflows, scripts, Jinja templates (`*.j2`), container files and Python
     outside `tests/unit/`: the scanner's remediation options and sub-commands, also across a backslash line
     continuation and as consecutive items of an argument list; `usg fix` and `usg generate-fix` of the Ubuntu
     Security Guide, which applies the ComplianceAsCode remediation on Ubuntu; and running a script or playbook
     from the fetched content, the release archive, the SCC installation or the distribution's SSG directories.

   The guard pins three exceptions exactly, with their number per file: `fixtext` in
   `tools/reporting/stig_content.py`, which the STIG checklist export only displays to the reader (ADR 0020); the
   forbidden words and the `generate fix` sequence in `plugins/module_utils/compliance/process.py`, which exist to
   refuse them; and the `fix` object of a Grype vulnerability in `tools/reporting/parsers/grype.py`, which is not
   XCCDF. Any other occurrence, or a change in the number of a pinned one, fails. ADR 0026 (FREES-191) adds two
   exceptions with the same rule: the element name in `tools/content/script_checks.py`, which removes every `fix`
   from the content on the controller, and in `plugins/module_utils/compliance/catalog.py`, which refuses one on the
   host. Neither reads what a `fix` holds.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Keep `profile_value_source: fix` and audit the fix text by hand | Still parses upstream remediation code and trusts what it substitutes |
| Hard-code `timestamp_timeout` per profile in the task file | The value would no longer follow the profile's XCCDF value, against ADR 0021 |
| Choose one timeout for every profile | Changes the current behaviour (STIG requires 0, CIS 15) and invents a value |
| Leave `sudo_require_reauthentication` `audit_only` | Loses a working native remediation; the value is available from the profile without the fix |
| Rely on review and the process helper only | Nothing would stop a future reader of `fix` elements or a committed upstream playbook |

## Benefits

- No code path reads, runs or ships ComplianceAsCode or OpenSCAP remediation. The guard fails closed on the first
  attempt, so this no longer depends on review alone.
- The generated catalogue is unchanged: every profile keeps the value it had (CIS 15, STIG 0, CCN and PCI DSS 5).
- The pinned mapping is visible in our own catalogue and checked against the content on every content update.

## Trade-offs

- A rule whose check exports nothing needs a reviewed `profile_value_id` and a golden test, instead of a value taken
  automatically from the content.
- The guard is static analysis of the tracked files' text and Python syntax, not a sandbox. These limits remain,
  and the guard does not see:
  - a name or an option built at run time in Python: concatenation (`"fi" + "x"`), `str.join`, `%` formatting
    (`"%sfix" % NS`), a case change (`"FIX".lower()`), `chr()`, a variable that holds such a string, a regular
    expression that splits the name (`fi(x)`), or an XPath test on part of the name
    (`starts-with(local-name(), 'fi')`);
  - Jinja indirection: an expression such as `--{{ 'reme' ~ 'diate' }}`, or `oscap xccdf {{ verb }}` with a YAML
    variable `verb: remediate` joined in the template;
  - Makefile indirection (`$(R)diate`, `$(MODE)`) and shell or environment variables (`"$M"`,
    `"$D/remediation.sh"`);
  - configuration formats outside the executed set above, such as INI, TOML or JSON.

  Review and ADR 0004's process policy remain the other layers. The process helper refuses `remediate`,
  `--remediate` and the `generate fix` sequence in every argument vector it runs, however it was built, and runs
  only the executables it allows, so this indirection cannot reach a managed host through the collection's
  modules. It does not cover CI and developer tooling that does not use the helper.

## Security implications

Upstream remediation content runs as root by design. Not reading it removes a path by which a change to the pinned
content could decide what the collection writes to a host.

**The owner's requirement that ComplianceAsCode code is never run is not yet met.** The pinned datastreams embed
Script Check Engine (SCE) shell scripts, and `oscap xccdf eval` writes them out and runs them as root while it
audits (threat model T-AUDIT-2). It does so for the 18 rules of the Ubuntu 24.04 datastream that have no OVAL check.
Per T-AUDIT-2, 16 of those rules are in `cis_level1_server`, so a default audit of that profile runs ComplianceAsCode
code as root. The scripts are checks, not `fix` elements, and this guard does not stop them.
[FREES-191](https://vidlunnia.atlassian.net/browse/FREES-191) tracks closing that gap.

What OpenSCAP 1.3.9, the version on Ubuntu 24.04, offers, from its source at tag `1.3.9`:

- `oscap xccdf eval` has no option to turn SCE off. Its option table
  ([`utils/oscap-xccdf.c` lines 1213-1257](https://github.com/OpenSCAP/openscap/blob/1.3.9/utils/oscap-xccdf.c#L1213-L1257))
  and its manual page ([`utils/oscap.8`](https://github.com/OpenSCAP/openscap/blob/1.3.9/utils/oscap.8)) have
  only `--sce-template`, for reports, and `--check-engine-results`, for exporting results.
- A new session loads everything, check engine plugins included
  ([`src/XCCDF/xccdf_session.c` line 166](https://github.com/OpenSCAP/openscap/blob/1.3.9/src/XCCDF/xccdf_session.c#L166)
  and [lines 714-718](https://github.com/OpenSCAP/openscap/blob/1.3.9/src/XCCDF/xccdf_session.c#L714-L718)).
  `eval` (`app_evaluate_xccdf`) does not narrow that; only `generate fix` and `generate guide` do
  ([`utils/oscap-xccdf.c` line 1021](https://github.com/OpenSCAP/openscap/blob/1.3.9/utils/oscap-xccdf.c#L1021)
  and [line 1095](https://github.com/OpenSCAP/openscap/blob/1.3.9/utils/oscap-xccdf.c#L1095)). So `eval` always
  tries to load the one known plugin, `libopenscap_sce.so.<n>`
  ([`src/XCCDF_POLICY/check_engine_plugin.c` line 210](https://github.com/OpenSCAP/openscap/blob/1.3.9/src/XCCDF_POLICY/check_engine_plugin.c#L210)).
  A plugin that does not load is ignored
  ([`xccdf_session.c` lines 1249-1265](https://github.com/OpenSCAP/openscap/blob/1.3.9/src/XCCDF/xccdf_session.c#L1249-L1265)).
- The plugin path can be redirected with the undocumented environment variable `OSCAP_CHECK_ENGINE_PLUGIN_DIR`
  ([`check_engine_plugin.c` lines 57-60](https://github.com/OpenSCAP/openscap/blob/1.3.9/src/XCCDF_POLICY/check_engine_plugin.c#L57-L60)).
  The process helper does not pass it: redirecting root's library loading would add a code-loading path.
- Per run, the SCE rules can be deselected with `--skip-rule` or a tailoring
  ([`utils/oscap.8`](https://github.com/OpenSCAP/openscap/blob/1.3.9/utils/oscap.8)). The collection's
  `disabled_rules` writes such a tailoring, but that is the operator's choice and not the default.

So SCE can be avoided, but not with a switch, and the collection does not avoid it by default today.

A change to the rule group or to its pinned exceptions changes the repository guard and needs a security review.

## Operational consequences

- `make catalogue` fails for an entry that sets `profile_value_source`, and for a `profile_value_id` that a pinned
  datastream does not define.
- `make lint-repo` fails on any of the patterns above. A new exception needs a change to `PINNED_EXCEPTIONS` with a
  security review.
- The documentation says this plainly: [README](../../README.md), [remediation guide](../remediation.md) and
  [native remediation guide](../native-remediation-guide.md).
