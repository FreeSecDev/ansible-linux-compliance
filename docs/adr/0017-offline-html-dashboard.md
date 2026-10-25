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
