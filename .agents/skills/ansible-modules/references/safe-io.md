# Safe process, parsing and file handling

## Process helper (`process.py`)

- Signature takes `argv: Sequence[str]`, a timeout, an output size bound and an optional minimal environment.
- Calls `subprocess.run(argv, shell=False, timeout=timeout, env=env, check=False, capture_output=True)`.
- Returns a frozen result type (return code, bounded stdout, bounded stderr, timed_out).
- Environment is built explicitly (for example locale and a fixed `PATH`); nothing is inherited implicitly.

## Argument validation

- Profile and rule IDs: anchored regex over a restricted character set.
- Paths: absolute, no NUL, resolved and confined to an allowed base directory.
- Anything starting with `-` is rejected where a positional value is expected.

## XML

- Check file size against a limit before reading.
- Reject any DOCTYPE or ENTITY declaration before handing data to the stdlib parser.
- Cap element depth and count where the format allows.

## Files

- Resolve the real path, confirm it is inside the base directory, reject symlinks for write targets.
- Write to a temporary file in the same directory with an explicit mode, flush, fsync, then rename.
- Never create files with default umask-dependent permissions.

## Adversarial fixtures

Keep inert samples in `tests/fixtures/adversarial/`: billion-laughs XML, external entities, oversized files, symlink targets, path traversal strings, option-looking arguments.
