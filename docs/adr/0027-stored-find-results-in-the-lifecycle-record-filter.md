# 0027. Stored find results in the lifecycle_record filter

- **Status:** proposed
- **Date:** 2026-10-31
- **Deciders:** lead architect; project owner (every required CI job under 20 minutes, every lifecycle leg under
  about 15)
- **Jira:** FREES-180 (part 2: snapshot speed)
- **Pull requests:** introduced by the pull request for FREES-180 part 2
- **Related:** [ADR 0004](0004-audited-process-execution.md) (the guard of `plugins/`),
  [ADR 0009](0009-molecule-layout-and-drivers.md), [Molecule scenarios](../molecule.md#the-no-change-snapshot)

## Context

The lifecycle harness records the whole instance and takes no-change snapshots of the watched paths several times per
cycle. On the libvirt virtual machine a record has about 100,000 `ansible.builtin.find` entries. The lines of the
records were built in Jinja, which took 105 to 175 seconds per CI leg for the whole-instance records and 147 seconds
for the snapshots (part 1 of FREES-180, `make molecule-task-timings`).

The filter `freesecdev.linux_compliance.lifecycle_record` builds the same lines in Python. Measured on 88,680 entries
in a Docker container with ansible-core 2.21.5:

| How the entries reach Python | Time per record |
|---|---|
| The Jinja templates of the harness | 7.6 s |
| A filter that reads every entry through the container that ansible-core passes it | 4.7 s |
| The same filter reading the stored entries (this decision) | 1.0 s |

ansible-core 2.19 and later pass a filter its list arguments as lazy containers. Reading an item renders it: the
container wraps the item and each of its 34 values again, about 30 microseconds per entry, and that is most of the
4.7 seconds. The container keeps every item that it has not rendered yet in a wrapper, `_LazyValue`, with the stored
item as its `value`.

An action plugin would get the variables unrendered, but it must import `ansible.plugins.action`, which the guard of
`plugins/` does not allow (ADR 0004), and adding it would also change the standard library name sets of the guard. A
module that walks the instance and returns compact lines would replace `ansible.builtin.find` and its checksum
handling on every managed instance, which FREES-180 did not ask for.

## Decision

`stored_items` in `plugins/filter/lifecycle_record.py` is the one adapter to that internal of ansible-core. For each
item of a list argument it takes the stored item, unwrapped from a `_LazyValue` if it is one, and uses it only if it
is a `dict` whose keys are `str` and whose values are exactly `str`, `int`, `float`, `bool` or `None`. Every other
item is read through the container, and so rendered as before.

That choice cannot change a line. ansible-core renders only text that is trusted as a template, and such text is a
tagged subclass of `str`, never exactly `str`; numbers, booleans and null render to themselves. Every entry of a
`find` result is such a plain mapping, so it is used as stored; an entry that the harness builds from a template,
such as the synthetic states of the self-checks, is rendered. If a later ansible-core stores items differently, no
item matches and every item is rendered: slower, with the same lines.

## Consequences

- A record takes about a second of Python per 100,000 entries instead of 5 to 25 seconds of templating.
- The filter depends on the name and the `value` attribute of `_LazyValue` for its speed, never for its result. The
  pinned ansible-core is updated by review (`uv.lock`), and the Molecule legs would show the slowdown in their timings.
- `tests/unit/plugins/filter/test_lifecycle_record.py` checks the adapter with a fake container: stored plain entries
  are not read through it, and a tagged, nested or non-mapping item is. The same file renders
  `tests/fixtures/lifecycle_record/filter.yml` with the real ansible-core, which passes the recorded walks through
  real lazy containers, and requires the lines that the old Jinja templates rendered (`record.yml`), byte for byte.

## Alternatives considered

- **Keep the Jinja templates.** Too slow for the 15-minute budget of a lifecycle leg.
- **A filter without the adapter.** Correct, and 40% faster than the templates, but still about 15 seconds per record
  on a CI runner.
- **An action plugin.** Needs an import that the guard of `plugins/` refuses (ADR 0004).
- **A module that returns compact walks.** The largest saving left, because `find` itself now dominates a record,
  but a new module that reads every file of an instance needs its own review; it is left for a follow-up.
