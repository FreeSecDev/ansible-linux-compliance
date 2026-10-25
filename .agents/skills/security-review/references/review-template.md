# Security review template

```markdown
## Security review — FREES-<number>

**Reviewer:** <name or agent>
**Verdict:** approve | approve-with-follow-ups | request-changes
**Scope reviewed:** <commit SHA range>
**ADRs:** <links>

### Checklist

| Area | Item | Result | Notes |
|---|---|---|---|

### Findings

#### <severity>: <title>

- **Location:** `<path>:<line>`
- **Attacker capability:** <what the attacker controls>
- **Scenario:** <inputs and state that lead to the failure>
- **Impact:** <what is compromised>
- **Required fix:** <specific change and regression test>

### Accepted residual risk

| Risk | Owner | Follow-up issue |
|---|---|---|
```
