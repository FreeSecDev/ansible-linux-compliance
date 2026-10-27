# 0017. Offline single-file HTML dashboard

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-77
- **Pull requests:** introduced by the pull request that adds `tools/reporting/dashboard.py`
- **Related:** [ADR 0013](0013-normalized-findings-model.md), [ADR 0016](0016-report-schema-and-summary-semantics.md),
  [dashboard user guide](../dashboard.md)

## Context

[ADR 0016](0016-report-schema-and-summary-semantics.md) defines one versioned report document. People need to read it
in a browser, often offline, from a CI artifact or an e-mail attachment. Every string in the report comes from files
that an attacker may control, and a dashboard that rounds, pools or relabels figures can turn an honest report into a
false compliance claim ([AGENTS.md](../../AGENTS.md) rules 9 and 13). The FREES-77 review also requires that hosts
which share a name stay distinguishable, with their identity, input sources and merge notes.

## Decision

- `tools/reporting/dashboard.py` renders one HTML file. `python -m tools.reporting --html PATH` (and `make report`)
  write it from the same in-memory document as the JSON report. Equal reports give byte-identical files.
- The page embeds the report **unchanged** together with a small view: for each compliance group its input files
  (format, path, SHA-256) and its merges, and for each host key whether a machine ID identifies it or its name
  is self-asserted, plus a variant number when keys share a name. The view holds no figures. Its host key derivation
  repeats `compliance.host_key` on the JSON and a unit test compares the two.
- The page script computes no figure. It shows counts, percentages and assessments only where the report has them,
  and writes numbers as they are (a whole-number percentage gets one decimal, matching the report's rounding).
  Table row counts and page numbers are user-interface state, not report figures.
- Data is embedded as compact, key-sorted ASCII JSON in `<script type="application/json">` with `<`, `>`, `&`,
  U+2028 and U+2029 escaped. The script and style are static assets; the renderer refuses an asset that contains
  `</script`, `</style`, `<script` or `<!--`.
- The Content-Security-Policy `<meta>` element is `default-src 'none'`, `script-src` and `style-src` with the SHA-256
  of the inline script and style, `base-uri 'none'`, `form-action 'none'`, `require-trusted-types-for 'script'` and
  `trusted-types 'none'`. There is no `unsafe-inline`, `unsafe-eval` or `img-src`.
- Rendering uses DOM text APIs and an allow-list of attribute names only; no HTML string sink, no links, no images, no
  inline styles or handlers.
- Tables are paginated (25, 100 or 500 rows) and only the current page is in the DOM. Searching, filtering and sorting
  run over the in-memory rows.
- The embedded data is capped at 128 MiB. Above the cap the JSON report is still written, the dashboard is not, a
  dashboard left at that path by an earlier run is removed, and the command exits with the distinct status 3, which
  takes precedence over status 1. A browser limit must not block the JSON pipeline (FREES-78), and a distinct status
  lets CI tell "no dashboard" apart from both success and a damaged input. Both outputs are written atomically
  (temporary file in the same directory, `fsync`, rename) with mode 0600, and `--html` must differ from `--output`.
- Merge notes: the report writes one `shared_self_asserted_host` note per host across benchmarks and content versions
  (ADR 0016). A group shows a merge only when at least two of the note's sources are inputs of that group, and lists
  only those; the note itself is shown at report level as "counted as one host". A note is never attached to a group by
  host name alone, because that would claim that a figure includes inputs it does not.
- A machine ID is shown in a neutral tone as "reported by the scan run": the scanned host writes it, so it is a
  stronger identity than a bare name but it is not verified.
- Tabs follow the WAI-ARIA tabs pattern with automatic activation; a section tab exists only when inputs were
  supplied, and the overview lists the rest.
- Browser tests use Playwright for Python (a `uv` development dependency, hash-locked, owned by Dependabot) driving a
  pinned Chrome for Testing headless shell, and axe-core injected by the tests only. Both are downloaded by
  `tools/browser/fetch-test-deps.sh` and checked against SHA-256 values in that script; they are not committed and
  never shipped.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| A front-end framework or bundler | A large dependency and build chain for a page whose security depends on a small, reviewable renderer |
| Server-side rendering of HTML strings | Every value would need HTML escaping in Python; one missed field is an injection. DOM text APIs make escaping structural |
| `'unsafe-inline'` or nonces | Inline code from report data could run; nonces need a random value and break determinism |
| A projected, compacted data model | Smaller files, but the page would no longer show the report as it is, and projection bugs could drop states |
| Virtualised scrolling | Needs scroll-position arithmetic and absolutely positioned rows, and complicates keyboard and screen reader use; pagination is simpler and accessible |
| Playwright's own browser download | Not checksum-verified by this repository; the headless shell is fetched by URL and SHA-256 instead |
| Committing axe-core | 650 KB, above the repository's 512 KB file limit, and it must never be part of the product |

## Benefits

The dashboard cannot execute report content, cannot reach the network, and cannot show a figure that the report does
not contain. It works from a file, is reproducible, and is tested for keyboard use, accessibility, hostile data and
size.

## Trade-offs

- The schema allows 1,000,000 rules, but such a report does not fit in a browser string. The 128 MiB cap is the
  practical maximum; the size test runs at that cap.
- The whole report is embedded, so findings appear both in the items and in the deduplicated rules.
- A browser without Trusted Types support still enforces the hash policy; only the additional sink protection is lost.
- The test browser and axe-core are pinned in a script, not by a bot, and are updated by hand (FREES-81).
- Chrome for Testing publishes no checksum file. The headless shell is downloaded from the upstream bucket
  (`storage.googleapis.com/chrome-for-testing-public`); on 2026-10-25 that object was byte-identical to the
  `cdn.playwright.dev` mirror (same SHA-256), and the pinned SHA-256 of the zip and of the extracted binary were taken
  then. The binary and `axe.min.js` are re-verified on every run, also from the cache. The axe-core tarball is checked
  against both a pinned SHA-256 and npm's published `dist.integrity` SHA-512.

## Security implications

The page treats every report value as hostile: escaping in the data block, DOM text rendering, bidi isolation, a
hash-only policy with Trusted Types, and no network access. Tests inject script tags, `</script>`, comments, U+2028,
HTML entities, bidi controls and 4000-character strings into every free-text field and check that nothing executes,
that no element, handler or request appears, and that the layout does not overflow. The dashboard contains the whole
report, including host evidence, and must be shared with the same care.

## Operational consequences

- `make report` writes the dashboard; `make report-serve` serves it on 127.0.0.1.
- `make test-browser` runs in the CI `test` job and in `make ci`; it needs network access to fetch the pinned browser
  and axe-core on first use.
- A schema version change needs a dashboard update: the renderer refuses versions it does not know.

## References

- [Dashboard user guide](../dashboard.md), [reporting data model](../reporting-data-model.md)
- WAI-ARIA Authoring Practices, tabs pattern: <https://www.w3.org/WAI/ARIA/apg/patterns/tabs/>
- Content Security Policy Level 3: <https://www.w3.org/TR/CSP3/>

## Amendment 2026-10-26: per-group notes and the Exceptions tab (FREES-130, FREES-132)

The dashboard reads report schema 2.0 only ([ADR 0016](0016-report-schema-and-summary-semantics.md)) and refuses 1.0.

- **Merge notes.** The report now writes one `merged_inputs` note per group with its group key, so the view no longer
  infers merges. `views.groups[i].note` is the index of the note whose group key (benchmark, content version,
  profile and the structured host key) equals the key of `groups[i]`, or `null`; the old intersection of a per-host note's sources
  with the group's inputs is removed. A group shows "Merged in this group" exactly when the report has such a note,
  with the note's sources and, when two completed inputs repeat a profile, a "repeated scan" badge.
- **Profiles.** The pooled figures, host groups and rules tables show and filter by profile, because a figure
  covers one profile; a host with a CIS and a STIG run has two rows, never one combined figure.
- **Exceptions file.** The Exceptions tab shows the exceptions file path and SHA-256 with "every evaluation verified
  against this file", which the report states only when every evaluation was verified against it.
- **Hosts counted as one.** `same_host_across_groups` notes are listed under "Hosts counted as one" on the Compliance
  tab with the host, its identity, the groups and the inputs, and the text says that the figures stay separate and
  nothing is combined across the groups.
- **Exceptions tab.** A tab for `sections.exceptions` appears when evaluations were supplied. It shows the summary
  (counts per review status, removal candidates, expiry passed, exceptions file SHA-256), a sortable and filterable
  table of every exception (ID, rule, review, removal candidate, expiry, risk, framework, scope, matched inventory
  hosts) with details (justification, owner, approver, dates, scope, scan runs per status, matched hosts) and the
  evaluation inputs. It states that nothing on the tab changes a figure and that hosts are inventory names. The
  Overview shows the stale, expired, expiry-passed, removal-candidate and in-effect counts from
  `overview.exceptions`, or that no evaluation was supplied.
- **Lapsed waivers.** Findings whose waiver lapsed after the scan started are marked "waiver lapsed after the scan
  started", and the expired-waiver count says that it includes them.
- The safety properties are unchanged: every value, including exception justifications, is rendered with DOM text APIs
  inside `bdi` or `pre` elements; the script and style hashes in the Content-Security-Policy are computed from the
  assets at render time; browser tests inject hostile justifications, check that nothing executes and that the layout
  does not overflow, run axe-core on the tab with all details open in both themes, and load an exceptions file at its
  1000-entry limit.

## Amendment 2026-10-26: host coverage (FREES-142)

The dashboard reads report schema 2.0 and 2.1 ([ADR 0016 amendment](0016-report-schema-and-summary-semantics.md#amendment-2026-10-26-schema-21-host-coverage-frees-142))
and refuses every other version.

- **Overview.** A "Target hosts" callout precedes the compliance result. With incomplete coverage it says how many of
  the target hosts have no evidence bundle in the report, that no figure covers them, and lists every missing host
  with its collection status. With unknown coverage it says that hosts without an input are not visible and how to
  build the report with `--evidence-collection`. A 2.0 report is shown as unknown, with its schema version as the
  reason.
- **Compliance tab.** The same callout, the coverage counts (target hosts, in the report, missing, per status), the
  collection summary path, SHA-256 and ID, and a sortable, filterable table of every target host with "in this
  report", its collection status, run and manifest SHA-256.
- **No new figure.** Every count comes from `host_coverage.summary`; the script computes none. The badges of missing
  hosts use the "bad" tone and always carry text.
- The safety properties are unchanged: host names, paths and reasons are rendered with DOM text APIs inside `bdi`
  elements. `tests/browser/test_dashboard_host_coverage.py` checks the text, a hostile summary path rendered as text,
  a 2.0 report, and axe on the Overview and Compliance tabs in both themes.

## Amendment 2026-10-26: off-platform results (FREES-161)

The dashboard reads report schema 2.0, 2.1 and 2.2
([ADR 0016 amendment](0016-report-schema-and-summary-semantics.md#amendment-2026-10-26-schema-22-off-platform-results-frees-161))
and refuses every other version.

- **Overview.** When `sections.compliance.off_platform` lists inputs, an "Off-platform results" callout comes before
  the compliance result. Its title is "Off-platform results: never compliance with the host's own release.", in the
  warning tone. It says:
  - how many inputs were scanned, by explicit opt-in, with a benchmark made for another platform;
  - that they are never compliance with a baseline of the host's own release;
  - that they are excluded from every figure, pooled figure and summary.

  It then lists each input with its host, its benchmark, the platform the benchmark is made for, the host's platform
  and the run status.
- **Compliance tab.**
  - **The table.** The same callout, then the table "Off-platform results (never in a figure)": host, benchmark,
    benchmark platform, host platform, run status and the label "off-platform: not a figure". Its details hold the
    input, its SHA-256, the content version, the profile and the rules per outcome, captioned "not a figure".
  - **Inputs and findings.** The inputs table shows "off-platform: no figure" instead of a per-input figure. The
    findings table flags each marked finding "off-platform" with both platforms, and the flag can be filtered.
- **Host coverage.** When a target host has only an off-platform scan, the "Target hosts are missing from this
  report." callout adds how many target hosts have only an off-platform scan, says that they are not covered, and
  names each. The coverage pairs show "Only an off-platform scan (not covered)". The target host table shows "only an
  off-platform scan: not covered" in the bad tone.
- **No new figure.** The script computes nothing. Every count comes from the report. A report without off-platform
  inputs shows neither the callout nor the table.
- **Safety unchanged.**
  - Every value is rendered with DOM text APIs inside `bdi` elements.
  - `tests/browser/test_dashboard_off_platform.py` checks:
    - the labels, and that the off-platform host is absent from the pooled figures and the host groups;
    - hostile host, platform and benchmark values in a forged report, rendered as text with no element, request or
      script;
    - axe-core on the Overview and Compliance tabs in both themes.

## Amendment 2026-10-27: control families (FREES-170)

The Rules table of the Compliance tab gains two filterable columns, **Family** and **Topic**, from each rule's
`control` (report schema 2.3). A rule without a placement shows "not placed". The detail row of a placed rule lists the
family, topic, tags, STIG ID, mapped ComplianceAsCode rules and the variables that disable it in part, before the
sources. Nothing else changes: the assets stay inline, the content security policy and the sink checks are unchanged,
and every value is still rendered as text.
