"""Composition root that wires the shipped scanner backends.

Orchestration code calls :func:`default_registry` and asks the registry for a
backend by name. This is the only module that imports concrete backends.
"""

from __future__ import annotations

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    openscap,
    scanner,
)


def default_registry() -> scanner.BackendRegistry:
    """Return a new registry holding every shipped backend."""
    registry = scanner.BackendRegistry()
    openscap.register(registry)
    return registry
