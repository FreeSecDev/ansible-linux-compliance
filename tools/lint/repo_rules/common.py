"""Values that every rule group of the repository guard shares."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

YAML_SUFFIXES: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
PYTHON_SUFFIXES: Final[frozenset[str]] = frozenset({".py"})
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
PLUGINS_DIRECTORY: Final[str] = "plugins"


@dataclass(frozen=True, order=True, slots=True)
class Violation:
    """A single rule violation at ``path:line``."""

    path: Path
    line: int
    message: str

    def __str__(self) -> str:
        """Render the violation as ``path:line: message``."""
        return f"{self.path}:{self.line}: {self.message}"
