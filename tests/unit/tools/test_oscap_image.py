"""The CI-only OpenSCAP image of the OpenSCAP STIG checklist test (FREES-146).

It shares the pinned base of the SCC image, so both scanners see the same Ubuntu 24.04
file system; it installs the same pinned ``openscap-scanner`` as the ``oscap-integration``
job; it has a ``localhost/`` tag and is removed with the SCC images.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CONTAINERFILE = REPOSITORY_ROOT / "extensions" / "ci" / "oscap" / "Containerfile"
SCC_CONTAINERFILE = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "Containerfile"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"


def test_the_image_has_the_pinned_base_of_the_scc_image() -> None:
    lines = CONTAINERFILE.read_text(encoding="utf-8").splitlines()
    assert lines[0] == SCC_CONTAINERFILE.read_text(encoding="utf-8").splitlines()[0]
    assert re.fullmatch(r"FROM docker\.io/library/ubuntu:24\.04@sha256:[0-9a-f]{64}", lines[0])
    assert sum(line.startswith("FROM ") for line in lines) == 1
    assert not any(line.lstrip().startswith("#") for line in lines)
    assert "never published" in CONTAINERFILE.read_text(encoding="utf-8")


def test_the_scanner_version_is_the_one_of_the_oscap_integration_job() -> None:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    jobs = cast("dict[str, dict[str, dict[str, str]]]", workflow["jobs"])
    pinned = jobs["oscap-integration"]["env"]["OPENSCAP_SCANNER_VERSION"]
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert f"OPENSCAP_SCANNER_VERSION := {pinned}\n" in makefile
    assert '"openscap-scanner=${OPENSCAP_SCANNER_VERSION}"' in CONTAINERFILE.read_text()


def test_the_image_is_local_and_removed_with_the_scc_images() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert "OSCAP_IMAGE ?= localhost/freesecdev-oscap:local\n" in makefile
    assert (
        "$(DOCKER) image rm --force '$(SCC_IMAGE)' '$(SCC_IMAGE_UBUNTU2604)' '$(OSCAP_IMAGE)'"
        in (makefile)
    )
    assert "scc-integration: scc-image scc-image-ubuntu2604 oscap-image" in makefile
    assert "$(OSCAP_CONTAINERFILE)\n" in makefile
