# Progress comment templates

Never include credentials, sensitive environment variables, host evidence or infrastructure secrets. Link to CI runs instead of pasting logs. Omit fields that do not apply; do not invent values.

## Start

```text
Started: <what is being built and why now>
Branch: <type>/FREES-<n>-<slug>
Approach: <two or three lines>
Risks: <known risks>
```

## Significant milestone

```text
Milestone: <what is now true>
Commit: <sha>   PR: <url>   CI: <run url>
Tests: <passed/failed counts and suites>
Next: <next step>
```

## Blocker

```text
Blocked: <what cannot proceed and why>
Needs: <decision, access or issue FREES-n>
Impact: <what is delayed>
Remaining risks: <risks>
```

## Important decision

```text
Decision: <what was chosen>
Rationale: <why>
Rejected alternatives: <alternative: reason>
Remaining risks: <risks>
ADR: <link or "not required: reason">
```

## Failed test

```text
Failed: <test or check name>
Evidence: <CI run url, commit sha, short non-sensitive error summary>
Suspected cause: <hypothesis, labelled as such>
Plan: <next action>
```

## Resolved failure

```text
Resolved: <test or check name>
Root cause: <confirmed cause>
Fix: <commit sha, PR url>
Verification: <CI run url, test results>
Regression test: <name>
```

## Pull request opened

```text
PR: <url>
Summary: <what changed and why>
Commit: <sha>   CI: <run url, status>
ADR: <link>   Docs: <pages changed>
Review requested from: <independent reviewer>
```

## Review complete

```text
Review: <approve | approve-with-follow-ups | request-changes>
Reviewer: <independent agent or person>   PR: <url>
Findings: <count by severity, link to review comment>
Follow-ups: <FREES keys>
```

## Done

```text
Done: <outcome>
Merged: <squash commit sha>   PR: <url>   CI: <run url>
Tests: <results>
Decisions: <ADR links>
Remaining risks: <risks and follow-up keys>
```
