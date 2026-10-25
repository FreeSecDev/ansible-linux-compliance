from __future__ import annotations

from pathlib import Path

import pytest

COLLECTIONS_LINK = Path("build") / "collections"


def pytest_configure(config: pytest.Config) -> None:
    if not (Path(config.rootpath) / COLLECTIONS_LINK).is_dir():
        message = f"{COLLECTIONS_LINK} is missing: run 'make install' (or 'make collection-link')"
        raise pytest.UsageError(message)
