"""Generate ``playbooks/run_start.yml``, the check that every shipped playbook runs first.

An extra variable (``-e``) outranks every fact that a role sets, and the internal-variable guard
of a role can only compare values, which a template can imitate (FREES-157). The shipped
playbooks therefore start by importing ``playbooks/run_start.yml``. Its one play targets
``all:localhost``, so that every ``--limit`` that selects any host keeps it, and runs its one
task once (``run_once``, no facts): an assertion over ``hostvars`` and ``groups``, an action
that never connects to the host it runs for. It refuses the run when an inventory host or
``localhost`` already has, in ``hostvars``, an internal ``__linux_compliance_*`` variable of any
role or a role output that a later role trusts, such as ``linux_compliance_audited``. Before the
run starts only an extra variable, the inventory, ``group_vars``, ``host_vars`` or a fact cache
can put such a name there, and the check refuses it by its name, whatever its value. It also
refuses ``inventory_hostname`` as an extra variable, which would make ``hostvars`` of every host
answer for another one, and ``group_names`` as an extra variable: it compares the group
memberships in ``hostvars`` with those of the ``groups`` magic variable, which an extra variable
cannot replace, because a forged ``group_names`` would widen the scope of an exception. Like the
Molecule guard of FREES-150, the check reads only magic variables and literals.

A fact that a role sets with ``cacheable: true`` survives in a persistent fact cache by
design and is checked by the role where it is read, so it is exempt. A shipped playbook that
imports another one passes the play variable ``linux_compliance_run_start_checked`` to it,
because the facts of its own earlier plays are in ``hostvars`` by then. A play variable is not
in ``hostvars``, so the check is skipped only when the marker is defined and no inventory host
and not ``localhost`` has it in ``hostvars``: then it can only be a variable of the play, set
by the importing playbook. An extra variable, an inventory, ``group_vars`` or ``host_vars``
value or a fact of that name on any host is in ``hostvars``, so the check runs and refuses the
marker like any other name. The condition is the same on every host, so it does not depend on
the host that ``run_once`` picks.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tools.roles import generate_toggles

if TYPE_CHECKING:
    from collections.abc import Iterable

RUN_START: Final[Path] = Path("playbooks/run_start.yml")
MARKER: Final[str] = "linux_compliance_run_start_checked"
INTERNAL_PATTERN: Final[str] = "^__linux_compliance_"
HOSTS: Final[str] = "(groups['all'] + ['localhost']) | unique"
NAMES: Final[str] = f"{HOSTS} | map('extract', hostvars) | map('list') | flatten"
HOSTVARS_MEMBERS: Final[str] = (
    f"{HOSTS} | map('extract', hostvars) | ansible.builtin.subelements('group_names')"
)
GROUP_MEMBERS: Final[str] = (
    "groups | dict2items | rejectattr('key', 'equalto', 'all')"
    " | ansible.builtin.subelements('value')"
)


def memberships() -> str:
    """Return the check that ``group_names`` in ``hostvars`` matches the ``groups`` magic variable.

    Both sides are sorted lists of ``"<host> <group>"`` strings. ``group_names`` holds every
    group of the host except ``all``, ``ungrouped`` included.
    """
    stated = (
        f"({HOSTVARS_MEMBERS} | map('first') | map(attribute='inventory_hostname')"
        f" | zip({HOSTVARS_MEMBERS} | map('last')) | map('join', ' ') | sort | list)"
    )
    actual = (
        f"({GROUP_MEMBERS} | map('last') | zip({GROUP_MEMBERS} | map('first')"
        " | map(attribute='key')) | map('join', ' ') | sort | list)"
    )
    return f"{stated} == {actual}"


def _literal(names: Iterable[str]) -> str:
    return "[" + ", ".join(f"'{name}'" for name in sorted(names)) + "]"


def refused(outputs: Iterable[str], exempt: Iterable[str]) -> str:
    """Return the expression that lists every refused name found in ``hostvars``."""
    internal = f"{NAMES} | select('match', '{INTERNAL_PATTERN}') | reject('in', {_literal(exempt)})"
    public = f"{NAMES} | select('in', {_literal([*outputs, MARKER])})"
    return f"(({internal} | list) + ({public} | list))"


def _folded(text: str, indent: int) -> list[str]:
    width = generate_toggles.MAX_LINE - indent
    return [" " * indent + line for line in textwrap.wrap(text, width, break_on_hyphens=False)]


def play(outputs: Iterable[str], exempt: Iterable[str]) -> str:
    """Return the run-start playbook that refuses ``outputs`` and internal names in ``hostvars``.

    ``outputs`` are the role outputs that a later role trusts and ``exempt`` the cacheable
    internal facts.
    """
    names = refused(outputs, exempt)
    identity = f"{HOSTS} | map('extract', hostvars, 'inventory_hostname') | list == {HOSTS} | list"
    message = (
        "Refusing to run: internal variables or role outputs of the freesecdev.linux_compliance "
        f"roles ({{{{ {names} | unique | sort | join(', ') or 'none' }}}}) are set before the run "
        "started, or inventory_hostname or group_names is an extra variable. Only the roles set "
        "them during the run; a value from an extra variable (-e), the inventory, group_vars, "
        "host_vars or a fact cache would replace what a role computes and another role trusts, "
        "and a template can imitate any value that a role checks. Remove it, and do not set "
        "inventory_hostname or group_names as an extra variable. Nothing was audited, remediated, "
        "compared or collected."
    )
    condition = (
        f"{MARKER} is not defined or {NAMES} | select('equalto', '{MARKER}') | list | length > 0"
    )
    lines = [
        "---",
        "- name: Refuse internal variables and role outputs that exist before the run starts",
        "  hosts: all:localhost",
        "  gather_facts: false",
        "  tasks:",
        "    - name: Refuse internal variables and role outputs supplied from outside the run",
        "      ansible.builtin.assert:",
        "        that:",
        "          - >-",
        *_folded(f"{names} | length == 0", 12),
        "          - >-",
        *_folded(identity, 12),
        "          - >-",
        *_folded(memberships(), 12),
        "        fail_msg: >-",
        *_folded(message, 10),
        "        quiet: true",
        "      when: >-",
        *_folded(condition, 8),
        "      run_once: true",
        "      tags:",
        "        - always",
    ]
    return "\n".join(lines) + "\n"
