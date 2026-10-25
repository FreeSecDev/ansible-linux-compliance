# Runbook template

Scope: operational procedures under `docs/runbooks/`. Audience: operators on call.

```markdown
# <Short symptom title>

Scope: <system and conditions>
Audience: <who runs this>

## Symptom
<What the operator observes: message, failing check, alert.>

## Diagnosis
1. <Read-only step and expected output>
2. <How to tell the likely causes apart>

## Fix
1. <Reversible step>
2. <Step requiring approval, marked as such>

## Verification
<Exact check proving the fix worked and what a pass looks like.>

## Escalation
<Who to contact, which Jira project and labels, what evidence to attach without secrets.>

## Related
<ADRs, issues, other runbooks.>
```

Rules: diagnosis steps never change state; fixes name the rollback; no credentials in examples.
