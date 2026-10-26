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
Both files are written atomically with mode 0600. When the report is above the dashboard size cap, the JSON is
still written, the dashboard is not (an older dashboard at that path is removed) and the exit status is 3. `--html` and
`--output` must name different files. The other exit statuses are the
ones in the data model page.

Open the HTML file directly in a browser. `make report-serve` serves `build/report/` on `127.0.0.1` only, and refuses
a `REPORT_HTML` outside that directory
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
| Overview | The scope, the run metadata, the target hosts (host coverage), the compliance summary, the stale, expired and removal-candidate exception counts, and the status of every section, plus the report types that were not supplied |
| Compliance | Target hosts, summary, hosts counted as one, figures per benchmark, content version and profile, figures per host, rules, inputs and findings |
| Exceptions | Every exception of the exceptions file with its review, removal candidacy, expiry, scope and matched inventory hosts, and the evaluation inputs |
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

### Target hosts

The report says whether it accounts for every target host of an evidence collection
([host coverage](reporting-data-model.md#host-coverage)), and the dashboard shows it first, on the Overview and on
the Compliance tab:

- **Target hosts are missing from this report.** The report was built with `--evidence-collection` and at least one
  target host has no evidence bundle in it. The callout gives the count and lists every missing host with its status
  (unreachable, limited out, no audit result, no evidence written, collection failed, or collected but its bundle not
  in the report). The compliance section is then partial and shows no summary or pooled figure.
- **Every target host is accounted for.** Every target host of the collection has a bundle in the report.
- **Host coverage unknown.** The report was built without a collection summary, so hosts without an input are not
  visible and the figures may not cover every host. A report with schema version 2.0 is always shown this way.

The Compliance tab also shows the counts per status, the path, SHA-256 and ID of the collection summary, and a table
of every target host with whether it is in the report, its status, run and manifest SHA-256.

### Off-platform results

A scan run made with `allow_off_platform_benchmark` evaluated a benchmark made for another platform than the host, for
example the Ubuntu 24.04 STIG benchmark on an Ubuntu 26.04 host
([off-platform results](reporting-data-model.md#off-platform-results)). When the report has such inputs, the Overview
and the Compliance tab show the callout **Off-platform results: never compliance with the host's own release.** It
gives the number of inputs, says that they are excluded from every figure, pooled figure and summary, and lists each
with its host, benchmark, both platforms and run status. The Compliance tab adds the table "Off-platform results
(never in a figure)" with the rules per outcome in its details, the inputs table shows "off-platform: no figure", and
the findings table flags each marked finding "off-platform". A report without off-platform inputs shows none of this.

### Host groups

Each row of "Figures per host" is one benchmark, content version and profile on one host, and shows:

- the host name, or "unnamed input" when the input file names no host;
- its identity: "machine ID reported by the scan run" with the ID when a scan run supplied one, otherwise
  "self-asserted", because the name comes from the input file. Neither is verified by the dashboard: the machine ID is
  also written by the scanned host, so it is shown in a neutral tone, not as a trusted identity;
- its input sources: the format, SHA-256 and path of every input that contributed to the group;
- its merge notes: "Merged in this group" with the number and SHA-256 of the combined inputs, exactly when the report
  has a `merged_inputs` note for this group, which it writes for every group built from more than one input of any
  type (two scan runs with the same host name and machine ID included). A "repeated scan" badge appears when two
  completed inputs report the same profile, which the report allows only with `--allow-repeated-scans`.

When inputs of one host fall into several groups (for example a CIS and a STIG profile, or two benchmarks), the report
writes one host-level note.
The Compliance tab lists these under "Hosts counted as one": the inputs are counted as one host, but every group keeps
its own figure and nothing is combined across them, so such a note never appears inside a group.

Two hosts that share a name, for example a machine-identified `web01` and a self-asserted `web01`, are separate
groups. They are marked "same name as another host: variant 1 of 2" and "variant 2 of 2" with a dashed outline, and
their identity differs, so they can be told apart. The rules table uses the same marks.

### Exceptions

The Exceptions tab appears when exceptions evaluations were supplied (`--exceptions-evaluation` with
`--exceptions-file`). It names the exceptions file and its SHA-256 as "every evaluation verified against this file",
which the report states only when every evaluation passed the check against that file. Nothing on it changes
a figure: a waived finding is counted as waived and never as a pass, and an expired waiver as its evaluated outcome.

- The summary counts the exceptions per review (in effect, expired, not yet in effect, superseded, not failing, stale),
  the removal candidates, the exceptions whose expiry had passed at an evaluation, and gives the SHA-256 of the
  exceptions file.
- The table lists every exception with its ID, rule, review, whether it is a removal candidate (stale, superseded or
  not failing everywhere), expiry, risk, framework, scope and the inventory hosts where its scope matched. Details
  show the justification, owner, approver, dates, the scope, the scan runs per status and every matched host with its
  status and the exception that superseded it.
- Hosts on this tab are the controller's inventory names, not names that the scanned hosts report.
- Findings whose waiver lapsed after the scan started are marked on the Compliance tab, and the expired-waiver count
  includes them.

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

- The embedded report (as escaped JSON) may be at most 128 MiB. For a larger report only the JSON is written, and the
  exit status is 3. Split such a report by benchmark and profile, or by host.
- Capacity estimate: the scale fixture works out to about 900 bytes per rule entry (with its findings and sources), so
  one dashboard holds roughly 350 to 400 hosts at 300 to 400 rules each under the cap. Larger fleets need one report
  per benchmark and profile, or per group of hosts.
- This cap is below some schema maxima: a report with the schema's maximum of 1,000,000 rules, each with its findings,
  is several hundred megabytes and above the string size a browser can parse. The browser tests use a report at the
  cap, with 1000 inputs in every section except Exceptions (whose evaluations share the compliance inputs), 9000 raw artifacts, detail lists past their 1000-entry cap and about
  145,000 rules (each rule entry names its host, benchmark, content version and profile).

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
themes, printing, accessibility (no serious or critical axe-core violation) and a report at the size cap. The
Exceptions tab is tested with hostile justification text, with all details open under axe-core in both themes, and
with an exceptions file at its 1000-entry limit. The target hosts are tested with missing hosts, a hostile collection
summary path, unknown coverage and a schema 2.0 report, under axe-core in both themes.
