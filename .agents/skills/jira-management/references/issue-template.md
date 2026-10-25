# Issue body template

Use this structure in every FREES issue description. Delete no heading; write "none" with a reason when a section does not apply.

```markdown
## Purpose
<One or two sentences: the problem and the outcome.>

## Technical requirements
- <Concrete, verifiable requirement>

## Dependencies
- Blocked by FREES-<n>: <why>
- Blocks FREES-<n>: <why>

## Acceptance criteria
- [ ] <Observable condition>

## Testing requirements
- <Unit, integration, Molecule, lint or scan checks that must pass>

## Documentation deliverables
- <docs/ pages and ADRs to create or update>

## Security considerations
- <Trust boundaries touched, secrets handling, security-review needed yes/no>

## Complexity estimate
<S | M | L | XL>

## Responsible skill or agent
<skill name and agent or owner>
```

## Labels

| Family | Form | Example |
|---|---|---|
| Plan identity | `plan-<slug>` | `plan-openscap-audit-module` |
| Component | `area-<component>` | `area-reporting` |
| Skill | `skill-<skill-name>` | `skill-ansible-modules` |
| Milestone | `milestone-<n>` | `milestone-2` |

Slugs are lowercase letters, digits and hyphens, and never change after first creation.

## Estimates

| Size | Meaning |
|---|---|
| S | Under half a day, one file area, no interface change |
| M | Up to two days, one component |
| L | Up to a week, several components or a new interface |
| XL | Must be split into smaller issues before work starts |
