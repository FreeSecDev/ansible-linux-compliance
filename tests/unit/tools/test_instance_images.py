"""The plan of the Docker instance images that CI builds once per run (FREES-182, ADR 0009).

``tools/molecule/instance_images.py`` must compute exactly the tag of ``shared/create.yml``.
The expected tags of the fixture were computed once with ansible-core 2.21.5 from the same
expression, including its literal backslash and ``n`` between the base reference and the
Dockerfile, which Jinja does not decode inside the folded scalar.
"""

from __future__ import annotations

import runpy
import sys
from typing import TYPE_CHECKING

import pytest

from tools.molecule import instance_images

if TYPE_CHECKING:
    from pathlib import Path

DIGEST = "sha256:" + "ab" * 32
VERSIONS = f"""---
molecule_images:
  web:
    reference: docker.io/library/ubuntu
    tag: "24.04"
    digest: {DIGEST}
    dockerfile: web.Dockerfile
    datastream: ubuntu2404
  db:
    reference: docker.io/rockylinux/rockylinux
    tag: "9"
    digest: {DIGEST}
    dockerfile: db.Dockerfile
"""
WEB_DOCKERFILE = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\nRUN true\n\n"
DB_DOCKERFILE = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
WEB_TAG = "abababababab-c3afe47ac216"
DB_TAG = "abababababab-985d8e8b798b"


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Write a versions file, two Dockerfiles and two platform files below ``tmp_path``."""
    (tmp_path / "versions.yml").write_text(VERSIONS, encoding="utf-8")
    images = tmp_path / "images"
    images.mkdir()
    (images / "web.Dockerfile").write_text(WEB_DOCKERFILE, encoding="utf-8")
    (images / "db.Dockerfile").write_text(DB_DOCKERFILE, encoding="utf-8")
    (tmp_path / "molecule.yml").write_text(
        "platforms:\n  - name: one\n    image: web\n  - name: two\n    image: web\n",
        encoding="utf-8",
    )
    (tmp_path / "selftest.yml").write_text(
        "molecule_yml:\n  platforms:\n    - name: probe\n      image: db\n", encoding="utf-8"
    )
    return tmp_path


def run(tree: Path, *arguments: str) -> int:
    return instance_images.main(
        ["--versions", str(tree / "versions.yml"), "--images-dir", str(tree / "images"), *arguments]
    )


def test_the_tag_is_the_one_that_create_computes() -> None:
    image = instance_images.Image(
        "web", "docker.io/library/ubuntu", "24.04", DIGEST, "web.Dockerfile"
    )
    assert image.base == f"docker.io/library/ubuntu:24.04@{DIGEST}"
    assert instance_images.image_tag(image, WEB_DOCKERFILE) == WEB_TAG
    assert instance_images.image_tag(image, WEB_DOCKERFILE.rstrip()) == WEB_TAG
    assert instance_images.image_tag(image, "FROM x\n") != WEB_TAG
    other = instance_images.Image(
        "db", "docker.io/rockylinux/rockylinux", "9", DIGEST, "db.Dockerfile"
    )
    assert instance_images.image_tag(other, DB_DOCKERFILE) == DB_TAG


def test_every_pinned_image_of_the_repository_has_a_plan() -> None:
    planned = instance_images.plan(
        instance_images.DEFAULT_VERSIONS, instance_images.DEFAULT_IMAGES, []
    )
    assert [image.key for image, _tag in planned] == ["rhel_compatible", "ubuntu"]
    for image, tag in planned:
        assert tag.startswith(image.digest.removeprefix("sha256:")[:12] + "-")


def test_the_plan_lists_every_image_without_platform_files(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(tree) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[0] for line in lines] == ["db", "web"]
    key, tag, base, dockerfile = lines[1].split()
    assert (key, tag) == ("web", WEB_TAG)
    assert base == f"docker.io/library/ubuntu:24.04@{DIGEST}"
    assert dockerfile == str((tree / "images" / "web.Dockerfile").resolve())


def test_the_plan_lists_only_the_images_of_the_platform_files_once(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(tree, "--platforms", str(tree / "molecule.yml"), "--output", "github") == 0
    assert capsys.readouterr().out == f"web={WEB_TAG}\n"
    platforms = [
        "--platforms",
        str(tree / "molecule.yml"),
        "--platforms",
        str(tree / "selftest.yml"),
    ]
    assert run(tree, *platforms, "--output", "github") == 0
    assert [line.split("=")[0] for line in capsys.readouterr().out.splitlines()] == ["db", "web"]


@pytest.mark.parametrize(
    ("versions", "message"),
    [
        ("[]\n", "is not a mapping"),
        ("molecule_images: []\n", "molecule_images is not a mapping"),
        ("molecule_images: {}\n", "pins no image"),
        ("molecule_images:\n  Web: {}\n", "the image key is malformed"),
        ("molecule_images:\n  web: x\n", "web is not a mapping"),
        ("molecule_images:\n  web: {reference: docker.io/x}\n", "tag is missing or malformed"),
        (
            "molecule_images:\n  web: {reference: 'docker.io/x', tag: '1', digest: 'sha256:00'}\n",
            "digest is missing or malformed",
        ),
        (
            (
                "molecule_images:\n  web: {reference: 'docker.io/x', tag: '1',"
                f" digest: '{DIGEST}', dockerfile: '../web.Dockerfile'}}\n"
            ),
            "dockerfile is missing or malformed",
        ),
        (
            (
                "molecule_images:\n  web: {reference: 'evil.example:5000/x', tag: '1',"
                f" digest: '{DIGEST}', dockerfile: 'web.Dockerfile'}}\n"
            ),
            "reference is missing or malformed",
        ),
        ("molecule_images: [\n", "while parsing"),
    ],
)
def test_malformed_pins_are_refused(
    tree: Path, capsys: pytest.CaptureFixture[str], versions: str, message: str
) -> None:
    (tree / "versions.yml").write_text(versions, encoding="utf-8")
    assert run(tree) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("platforms", "message"),
    [
        ("platforms: []\n", "lists no platforms"),
        ("molecule_yml: []\n", "molecule_yml is not a mapping"),
        ("platforms:\n  - x\n", "a platform is not a mapping"),
        ("platforms:\n  - name: one\n", "a platform names no image"),
        ("platforms:\n  - image: other\n", "no image 'other' is pinned"),
    ],
)
def test_malformed_platform_files_are_refused(
    tree: Path, capsys: pytest.CaptureFixture[str], platforms: str, message: str
) -> None:
    (tree / "molecule.yml").write_text(platforms, encoding="utf-8")
    assert run(tree, "--platforms", str(tree / "molecule.yml")) == 2
    assert message in capsys.readouterr().err


def test_a_missing_dockerfile_is_refused(tree: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tree / "images" / "db.Dockerfile").unlink()
    assert run(tree) == 2
    assert "db.Dockerfile" in capsys.readouterr().err


def test_the_module_runs_as_a_script(
    tree: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "instance_images",
            "--versions",
            str(tree / "versions.yml"),
            "--images-dir",
            str(tree / "images"),
        ],
    )
    sys.modules.pop("tools.molecule.instance_images", None)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.molecule.instance_images", run_name="__main__")
    assert raised.value.code == 0
    assert capsys.readouterr().out.count("\n") == 2
