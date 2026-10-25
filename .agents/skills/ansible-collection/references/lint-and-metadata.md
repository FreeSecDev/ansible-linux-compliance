# Lint and metadata

## Lint

- Profile: `production` in the repository ansible-lint configuration.
- Tool versions are the ones pinned in the toolbox lock files; never hardcode them in skills or docs.
- A suppression (`skip_list`, `warn_list`, `# noqa` is forbidden as an inline comment) must be listed in the lint config with a justification and Jira issue reference.

## Collection metadata

- `galaxy.yml`: namespace `freesecdev`, name `linux_compliance`, license, repository, issue tracker and dependency collections with version ranges.
- `meta/runtime.yml`: `requires_ansible` matching the tested ansible-core versions.
- `meta/argument_specs.yml` in every role, mirroring `defaults/main.yml`.

## Changelog

- Fragments live in `changelogs/fragments/<jira-key>-<slug>.yml`.
- Sections: `major_changes`, `minor_changes`, `bugfixes`, `security_fixes`, `breaking_changes`, `deprecated_features`, `removed_features`.
- Fragments describe user-visible behaviour, not implementation.

## Sanity

Run ansible-test sanity for every supported ansible-core version. Ignore files need a justification in the pull request and an ADR if permanent.
