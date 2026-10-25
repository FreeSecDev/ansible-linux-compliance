# Pull request template content

The file `.github/pull_request_template.md` is created from the block below by a separate task.

```markdown
## Summary
<What changed and why, in a few lines.>

## Jira
FREES-<n>

## ADR
<Link, or "not required: reason".>

## Type of change
- [ ] feat  - [ ] fix  - [ ] docs  - [ ] ci  - [ ] refactor  - [ ] test  - [ ] chore

## Testing
<Commands run and results; link to CI run.>

## Documentation
<Pages changed in this pull request, or "none: reason".>

## Changelog fragment
<Path in changelogs/fragments/, or "not user-visible: reason".>

## Security considerations
<Trust boundaries touched; security-review verdict link, or "not triggered: reason".>

## Checklist
- [ ] Branch is `<type>/FREES-<n>-<slug>` and rebased on latest `main`
- [ ] Title is a Conventional Commit with the FREES reference
- [ ] No shell, command, raw or script modules; FQCN used; YAML starts with `---`
- [ ] No inline comments, secrets or unpinned references
- [ ] Tests and docs updated; required CI is green including the report artifact
- [ ] Reviewer is not the author
```
