# Module template

## Layout

- `plugins/modules/<name>.py`: argument spec, documentation, thin `main()` calling typed `module_utils` functions.
- `plugins/module_utils/compliance/<area>.py`: logic, typed and unit-testable without AnsibleModule.
- `tests/unit/plugins/modules/` and `tests/unit/plugins/module_utils/`: mirrored tests.

## Documentation blocks

- DOCUMENTATION: `module`, `short_description`, `description`, `version_added`, `author`, `options` (type, required, default, choices, elements), `attributes` (check_mode, diff_mode), `notes`.
- EXAMPLES: at least one minimal and one realistic example using the FQCN.
- RETURN: every key with type, description, `returned` and a sample.

## Error contract

- `fail_json(msg=..., error_type=<stable identifier>, **context)`.
- Scanner problems return a result with outcome `error` and a reason; they are not silent passes.

## Check mode

- Audit modules run the scan in check mode, since they do not change the host.
- Mutating modules compute the change, report `changed`, and write nothing.
