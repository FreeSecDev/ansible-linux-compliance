"""Shared helpers of the SCC integration and egress tests (ADR 0019, FREES-145).

The tests run only against local images whose tags start with ``localhost/``,
given in ``FREESECDEV_SCC_IMAGE`` and, for the Ubuntu 26.04 off-platform case
(FREES-161), ``FREESECDEV_SCC_IMAGE_UBUNTU2604`` (``make scc-integration`` sets
both). They never
build, tag or transfer an image; ``make scc-image`` builds it and
``make scc-image-clean`` removes it. Without the variable the tests skip, and with
``FREESECDEV_REQUIRE_SCC=1`` (CI) a skip is a failure.

The image has no Python. The tests mount the standalone interpreter that runs
the tests (``sys.base_prefix``, a uv-managed CPython) read-only at ``/opt/py``,
the project's site packages at ``/site`` and the repository at ``/src``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import cast

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
IMAGE_VARIABLE = "FREESECDEV_SCC_IMAGE"
IMAGE_UBUNTU2604_VARIABLE = "FREESECDEV_SCC_IMAGE_UBUNTU2604"
REQUIRE_VARIABLE = "FREESECDEV_REQUIRE_SCC"
LOCAL_TAG = re.compile(r"localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+")
PYTHON_MOUNT = "/opt/py"
SITE_MOUNT = "/site"
SOURCE_MOUNT = "/src"
DRIVER = f"{SOURCE_MOUNT}/tests/system/scc/scc_driver.py"
SYSTEM_PREFIXES = frozenset({Path("/"), Path("/usr"), Path("/usr/local")})
CONTAINER_TIMEOUT_SECONDS = 3600
CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER")
CONTENT_DIRECTORY = "/opt/scc/Resources/Content/SCAP12_Content"
PINS = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "scc.pins"


def image(variable: str = IMAGE_VARIABLE) -> str:
    """Return the local SCC image named by ``variable``, or skip (fail in CI) without one."""
    value = os.environ.get(variable, "")
    if not value:
        if os.environ.get(REQUIRE_VARIABLE) == "1":
            pytest.fail(f"{variable} is required in CI")
        pytest.skip(f"{variable} is not set; run make scc-integration")
    if LOCAL_TAG.fullmatch(value) is None:
        pytest.fail(f"{variable} must be a localhost/ tag")
    return value


def pin(name: str) -> str:
    """Return one value of ``scc.pins``."""
    for line in PINS.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition(" := ")
        if key == name:
            return value
    message = f"{name} is not pinned"
    raise KeyError(message)


def docker() -> str:
    """Return the Docker client."""
    path = shutil.which("docker")
    if path is None:
        pytest.fail("docker is required for the SCC tests")
    return path


def python_mounts() -> list[str]:
    """Return the volume options that give the container this Python and its packages."""
    prefix = Path(sys.base_prefix).resolve()
    if prefix in SYSTEM_PREFIXES:
        pytest.fail("the tests need a standalone (uv-managed) Python, not the system one")
    site = Path(sysconfig.get_paths()["purelib"]).resolve()
    return [
        "--volume",
        f"{prefix}:{PYTHON_MOUNT}:ro",
        "--volume",
        f"{site}:{SITE_MOUNT}:ro",
        "--volume",
        f"{REPOSITORY_ROOT}:{SOURCE_MOUNT}:ro",
        "--env",
        f"PYTHONPATH={SOURCE_MOUNT}/build/collections",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
    ]


def interpreter() -> str:
    """Return the path of the mounted interpreter inside the container."""
    return f"{PYTHON_MOUNT}/bin/python{sys.version_info.major}.{sys.version_info.minor}"


def hardening() -> list[str]:
    """Return the options that confine the SCC container."""
    options = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    for capability in CAPABILITIES:
        options += ["--cap-add", capability]
    return options


def run(arguments: list[str], timeout: int = CONTAINER_TIMEOUT_SECONDS) -> str:
    """Run the Docker client and return its standard output, failing on error."""
    completed = subprocess.run(
        [docker(), *arguments], check=False, capture_output=True, text=True, timeout=timeout
    )
    if completed.returncode != 0:
        pytest.fail(f"docker {arguments[0]} failed: {completed.stderr[-2000:]}")
    return completed.stdout


def driver_report(output: str) -> dict[str, object]:
    """Return the JSON report that the driver printed last."""
    lines = [line for line in output.splitlines() if line.startswith("{")]
    assert lines, f"the driver printed no report: {output[-2000:]}"
    report: object = json.loads(lines[-1])
    assert isinstance(report, dict)
    return cast("dict[str, object]", report)


def report_line(label: str, data: object) -> None:
    """Print one labelled JSON line, so the CI log records what was measured."""
    sys.stdout.write(f"\n[scc] {label}: {json.dumps(data, sort_keys=True)}\n")
    sys.stdout.flush()
