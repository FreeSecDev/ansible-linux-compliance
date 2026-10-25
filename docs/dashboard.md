# Report dashboard user guide

The report dashboard is one self-contained HTML file that shows a normalized report
([reporting data model](reporting-data-model.md)) in a browser. It works offline, from a `file://` URL, and makes no
network requests. The decision record is [ADR 0017](adr/0017-offline-html-dashboard.md).

## Building it

```bash
make report REPORT_SCOPE=fleet REPORT_ARGS='--xccdf results.xml --junit junit.xml'
python -m tools.reporting --scope fleet --output build/report/report.json --html build/report/report.html \
  --xccdf results.xml
```

`make report` writes `build/report/report.json` and `build/report/report.html` (`REPORT_OUTPUT` and `REPORT_HTML`
override them). With `--html` the command line renders the dashboard from the same document that it writes as JSON.
When the dashboard cannot be rendered, nothing is written and the exit status is 2; the other exit statuses are the
ones in the data model page.

Open the HTML file directly in a browser. `make report-serve` serves the report directory on `127.0.0.1` only
(`REPORT_PORT`, default 8765), for browsers that restrict `file://` pages.

Equal reports give byte-identical dashboards: the file has no generation time, no random identifiers and a fixed
order. Times shown are the ones the report carries.

## What the page shows

The header states the scope of the report (single host, multi-host, benchmark or fleet). Every figure in the
report describes that scope. A button switches between the light and dark theme; the page starts in the theme that
the operating system prefers.

The tabs are:

| Tab | Content |
|---|---|
| Overview | The scope, the run metadata, the compliance summary and the status of every section, plus the report types that were not supplied |
| Compliance | Summary, merge notes, figures per benchmark and content version, figures per host, rules, inputs and findings |
| Tests, Coverage, Ansible lint, Vulnerabilities, SBOM, Molecule, Packer images, AWS CodeBuild | The section status, its summary when the report has one, its inputs and the entries of each input |
| Raw artifacts | Every input file as supplied, with its format, status, SHA-256 and size |

A section tab appears only when at least one input was supplied for it. A section without inputs is listed on the
Overview as not supplied; it is never shown as passed. A tab whose section is not `available` names its state, for
example "Tests (partial)".

### Reading the compliance figures

The dashboard shows figures only as the report gives them. It does not compute, round, combine or average anything.

- The run status comes first: run completed, run failed, run timed out, or not every run completed. A run that did
  not complete has no pass percentage.
- The assessment is one of "findings open", "all evaluated rules passed", "nothing evaluated: no figure is given" and
  "run not completed: no figure is given". "All evaluated rules passed" appears only where the report states
  `all_evaluated_passed`. None of them is a statement of compliance with a framework.
- A pass percentage is always shown with its denominator, for example "33.3 % (3 pass of 9 evaluated, scope fleet)".
  The number is the report's `compliance_percent` written as it is; a whole number is written with one decimal
  (100.0), which is how the report rounds it.
- The outcome table lists every outcome and whether it is in the denominator. `waived`, `notchecked` and `error` are
  in it and never count as pass; `notapplicable` and `disabled` are shown separately.
- Results that the profile did not select (`notselected`) are counted separately and are never in the figures.
  Expired waivers are counted as their evaluated outcome and marked "waiver expired".
- A figure covers one benchmark and content version. When the report covers several, there is no single summary;
  the figures per benchmark and per host are shown instead.

### Host groups

Each row of "Figures per host" is one benchmark and content version on one host, and shows:

- the host name, or "unnamed input" when the input file names no host;
- its identity: the machine ID when a scan run supplied one, otherwise "self-asserted", because the name comes from
  the input file and is not verified;
- its input sources: the format, SHA-256 and path of every input that contributed to the group;
- its merge notes, when several inputs claim the same self-asserted host name and were combined.

Two hosts that share a name, for example a machine-identified `web01` and a self-asserted `web01`, are separate
groups. They are marked "same name as another host: variant 1 of 2" and "variant 2 of 2" with a dashed outline, and
their identity differs, so they can be told apart. The rules table uses the same marks.

### Sections that are partial, in error or unavailable

A section that is not `available` shows its state, the reason from the report and a table of the missing or invalid
inputs. Such a section has no summary. Entries of the inputs that did parse are still listed; nothing in them is a
pass. Lists that the report cut at 1000 entries are marked as truncated; the totals in the report stay complete.

## Using the tables

Every table has a search field, filters for columns with few distinct values, a page size (25, 100 or 500 rows) and
page buttons. Column headers are buttons: activating one sorts ascending, activating it again sorts descending, and
the header carries `aria-sort`. Outcome and severity columns sort from worst to best. The status line under the
controls states which rows are shown. Rows with more data have a "Show details" button.

Only the current page of a table is in the page, so large reports stay responsive.

## Keyboard use

| Key | Where | Action |
|---|---|---|
| Tab, Shift+Tab | Anywhere | Move between the theme button, the selected tab, the panel and its controls |
| Left and Right arrows | Tab list | Select the previous or next tab (wraps around) |
| Home, End | Tab list | Select the first or last tab |
| Enter, Space | Sort header, page button, details button | Sort, change page, show or hide details |

Focus is always visible as a 3 pixel outline. Status is never shown by colour alone: every badge carries its text,
and the border style differs between error, warning and neutral states.

## Printing

The print layout shows every tab as its own page, in light colours, without the tab list, filters, page buttons and
the theme button. Each table prints its current page.

## Limits

- The embedded report (as escaped JSON) may be at most 128 MiB. A larger report is refused with exit status 2 and no
  file is written. Split such a report by benchmark or host.
- This cap is below some schema maxima: a report with the schema's maximum of 1,000,000 rules, each with its findings,
  is several hundred megabytes and above the string size a browser can parse. The browser tests use a report at the
  cap, with 1000 inputs in every section, 9000 raw artifacts, detail lists past their 1000-entry cap and about
  149,000 rules.

## Security

Report contents are untrusted. The dashboard is built so that no report value can run code or load anything:

- The report is embedded as JSON in a `<script type="application/json">` element. `<`, `>`, `&`, U+2028 and U+2029
  are written as `\u` escapes, so no value can close the element.
- The page script renders every value with DOM text APIs (`textContent`, text nodes and an allow-list of attributes).
  It never uses `innerHTML`, `document.write`, `eval`, `Function`, inline event handlers or links built from data.
  Hashes and paths are text. Values are isolated for bidirectional text, so control characters cannot reorder the page.
- The Content-Security-Policy is a `<meta>` element:
  `default-src 'none'; script-src 'sha256-...'; style-src 'sha256-...'; base-uri 'none'; form-action 'none';
  require-trusted-types-for 'script'; trusted-types 'none'`. The hashes are those of the inline script and style,
  computed when the page is built. No other script or style runs, nothing can be loaded or sent, and the Trusted
  Types directives make HTML string sinks throw.
- The file contains the whole report, including host evidence. Share it like the report itself.

## Tests

`make test-browser` runs the browser tests in a pinned Chrome for Testing headless shell, with a pinned axe-core.
`tools/browser/fetch-test-deps.sh` downloads both into `build/browser-test/` and checks their SHA-256 before use.
axe-core is injected by the tests only and is never part of the dashboard. The tests cover keyboard use of tabs and
tables, hostile report data, offline rendering with all requests blocked, Content-Security-Policy violations, both
themes, printing, accessibility (no serious or critical axe-core violation) and a report at the size cap.
