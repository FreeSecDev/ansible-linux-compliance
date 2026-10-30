"""The Galaxy collections of the Molecule jobs, fetched once per run (FREES-184, ADR 0009).

- ``tools/molecule/galaxy-collections.sh fetch`` downloads each pinned collection artifact only
  from Galaxy over HTTPS, with a bounded number of retries, and keeps a file only after its
  SHA-256 and size match ``extensions/molecule/collections.pins``. A cached file is checked again
  before it is reused, and a file that is not pinned is removed.
- ``install`` checks every file again, copies it into a private directory, checks the copy and
  installs only those copies with ``ansible-galaxy collection install --offline``, with an
  unresolvable Galaxy server, so that no step after the fetch contacts Galaxy.
- ``lock`` writes the pins from Galaxy's metadata and refuses a dependency that
  ``requirements.yml`` does not pin.
- The pins match ``requirements.yml`` exactly, the ``molecule-collections`` job is the only one
  that fetches, a pull request from a fork neither restores nor saves its cache, and every job
  that installs collections needs that job and downloads its artifact. The tests run the script
  with a fake ``curl``, ``ansible-galaxy`` and ``jq``-free metadata fixtures where possible.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "tools" / "molecule" / "galaxy-collections.sh"
PINS = REPOSITORY_ROOT / "extensions" / "molecule" / "collections.pins"
REQUIREMENTS = REPOSITORY_ROOT / "extensions" / "molecule" / "requirements.yml"
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
TIMEOUT_SECONDS = 60
GALAXY = "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections"
FORK_CONDITION = (
    "github.event_name != 'pull_request'"
    " || (!github.event.pull_request.head.repo.fork"
    " && github.event.pull_request.head.repo.full_name == github.repository)"
)
INSTALLING_JOBS = ("lint", "molecule-docker", "molecule-lifecycle", "molecule-libvirt")

FAKE_CURL = """#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
printf '%s\\n' "$*" >> "${FAKE_LOG}/curl"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --max-filesize|--proto|--proto-redir|--retry|--retry-delay) shift 2 ;;
    --connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
source_file="$(awk -v url="${url}" '$1 == url { print $2 }' "${FAKE_ROUTES}")"
[[ -n "${source_file}" ]] || exit 22
cp "${source_file}" "${output}"
"""
FAKE_GALAXY = """#!/usr/bin/env bash
printf '%s|%s|%s\\n' "${ANSIBLE_GALAXY_SERVER:-}" "${ANSIBLE_GALAXY_SERVER_LIST-unset}" "$*" \\
  >> "${FAKE_LOG}/ansible-galaxy"
"""


def executable(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is required"
    return path


class Galaxy:
    """A fake Galaxy that serves two collections, and their pins below ``root``."""

    def __init__(self, root: Path) -> None:
        """Create the fake tools, two served artifacts and their pins below ``root``."""
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, text in {"curl": FAKE_CURL, "ansible-galaxy": FAKE_GALAXY}.items():
            path = self.bin / name
            path.write_text(text, encoding="utf-8")
            path.chmod(0o755)
        self.log = root / "log"
        self.log.mkdir()
        self.served = root / "served"
        self.served.mkdir()
        self.routes: dict[str, Path] = {}
        self.cache = root / "cache"
        self.collections = {
            "community.docker": ("5.4.0", b"docker artifact"),
            "community.library_inventory_filtering_v1": ("1.1.5", b"filter artifact"),
        }
        self.lines: list[str] = []
        for name, (version, data) in self.collections.items():
            artifact = f"{name.replace('.', '-')}-{version}.tar.gz"
            self.serve(f"{GALAXY}/artifacts/{artifact}", data)
            digest = hashlib.sha256(data).hexdigest()
            self.lines.append(f"collection {name} {version} {digest} {len(data)}")
        self.pins = root / "collections.pins"
        self.write_pins(self.lines)

    def serve(self, url: str, data: bytes) -> None:
        path = self.served / str(len(self.routes))
        path.write_bytes(data)
        self.routes[url] = path
        (self.root / "routes").write_text(
            "".join(f"{key} {value}\n" for key, value in self.routes.items()), encoding="utf-8"
        )

    def write_pins(self, lines: list[str]) -> None:
        self.pins.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [executable("bash"), str(SCRIPT), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            env={
                "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "FAKE_LOG": str(self.log),
                "FAKE_ROUTES": str(self.root / "routes"),
            },
        )

    def calls(self, tool: str) -> list[str]:
        path = self.log / tool
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


@pytest.fixture
def galaxy(tmp_path: Path) -> Galaxy:
    return Galaxy(tmp_path)


def test_fetch_downloads_each_pin_from_galaxy_with_bounded_retries(galaxy: Galaxy) -> None:
    result = galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache))
    assert result.returncode == 0, result.stderr
    calls = galaxy.calls("curl")
    assert len(calls) == 2
    for call in calls:
        assert f" {GALAXY}/artifacts/community-" in call
        assert "--proto =https --proto-redir =https" in call
        assert "--retry 4 --retry-delay 10 --retry-all-errors" in call
        assert "--max-time 90" in call
    assert sorted(path.name for path in galaxy.cache.iterdir()) == [
        "community-docker-5.4.0.tar.gz",
        "community-library_inventory_filtering_v1-1.1.5.tar.gz",
    ]


def test_fetch_reuses_only_verified_files_and_removes_unpinned_ones(galaxy: Galaxy) -> None:
    assert galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache)).returncode == 0
    (galaxy.log / "curl").unlink()
    (galaxy.cache / "community-docker-5.4.0.tar.gz").write_bytes(b"docker artifacX")
    (galaxy.cache / "community-docker-5.3.0.tar.gz").write_bytes(b"stale")
    result = galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache))
    assert result.returncode == 0, result.stderr
    assert (
        "reusing the verified community-library_inventory_filtering_v1-1.1.5.tar.gz"
        in result.stdout
    )
    assert "removed the unpinned community-docker-5.3.0.tar.gz" in result.stdout
    [call] = galaxy.calls("curl")
    assert "community-docker-5.4.0.tar.gz" in call
    assert (galaxy.cache / "community-docker-5.4.0.tar.gz").read_bytes() == b"docker artifact"
    assert not (galaxy.cache / "community-docker-5.3.0.tar.gz").exists()


def test_fetch_refuses_a_download_that_does_not_match_its_pin(galaxy: Galaxy) -> None:
    galaxy.serve(f"{GALAXY}/artifacts/community-docker-5.4.0.tar.gz", b"tampered artifact")
    result = galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache))
    assert result.returncode == 1
    assert "does not match the pinned SHA-256 and size" in result.stderr
    assert not (galaxy.cache / "community-docker-5.4.0.tar.gz").exists()


def test_fetch_fails_when_galaxy_does_not_answer(galaxy: Galaxy) -> None:
    (galaxy.root / "routes").write_text("", encoding="utf-8")
    result = galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache))
    assert result.returncode == 22


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("collection community.docker 5.4.0 " + "a" * 64 + " 1 extra", "every line of"),
        ("deb community.docker 5.4.0 " + "a" * 64 + " 1", "every line of"),
        (
            "collection community 5.4.0 " + "a" * 64 + " 1",
            "is not a collection name and exact version",
        ),
        (
            "collection community.docker >=5 " + "a" * 64 + " 1",
            "is not a collection name and exact version",
        ),
        ("collection community.docker 5.4.0 " + "A" * 64 + " 1", "not 64 lower-case hex digits"),
        ("collection community.docker 5.4.0 " + "a" * 64 + " 999999999", "is not a bound"),
    ],
)
def test_malformed_pins_are_refused_before_any_download(
    galaxy: Galaxy, line: str, message: str
) -> None:
    galaxy.write_pins([line])
    result = galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache))
    assert result.returncode == 2
    assert message in result.stderr
    assert galaxy.calls("curl") == []


def test_empty_or_linked_pins_are_refused(galaxy: Galaxy) -> None:
    galaxy.write_pins([])
    assert galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache)).returncode == 2
    link = galaxy.root / "link.pins"
    link.symlink_to(galaxy.pins)
    result = galaxy.run("install", str(link), str(galaxy.cache), str(galaxy.root / "out"))
    assert result.returncode == 2
    assert "is not a regular file" in result.stderr
    assert galaxy.run("other").returncode == 2


def test_install_installs_only_verified_copies_offline(galaxy: Galaxy) -> None:
    assert galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache)).returncode == 0
    result = galaxy.run("install", str(galaxy.pins), str(galaxy.cache), str(galaxy.root / "out"))
    assert result.returncode == 0, result.stderr
    assert "installed 2 verified collections offline; Galaxy was not contacted" in result.stdout
    [call] = galaxy.calls("ansible-galaxy")
    server, server_list, arguments = call.split("|")
    assert (server, server_list) == ("https://galaxy.invalid", "")
    words = arguments.split()
    assert words[:6] == [
        "collection",
        "install",
        "--offline",
        "--force",
        "-p",
        str(galaxy.root / "out"),
    ]
    assert words[6] == "--"
    assert len(words[7:]) == 2
    assert all(word.endswith(".tar.gz") and str(galaxy.cache) not in word for word in words[7:])
    assert "-r" not in words


@pytest.mark.parametrize("damage", ["missing", "tampered"])
def test_install_refuses_a_missing_or_changed_file_and_installs_nothing(
    galaxy: Galaxy, damage: str
) -> None:
    assert galaxy.run("fetch", str(galaxy.pins), str(galaxy.cache)).returncode == 0
    target = galaxy.cache / "community-docker-5.4.0.tar.gz"
    if damage == "missing":
        target.unlink()
    else:
        target.write_bytes(b"docker artifacX")
    result = galaxy.run("install", str(galaxy.pins), str(galaxy.cache), str(galaxy.root / "out"))
    assert result.returncode == 1
    assert "is missing or does not match its pin; nothing was installed" in result.stderr
    assert "the only step that contacts Galaxy" in result.stderr
    assert galaxy.calls("ansible-galaxy") == []
    assert galaxy.calls("curl") == galaxy.calls("curl")[:2]


def metadata(name: str, version: str, data: bytes, dependencies: dict[str, str]) -> bytes:
    return json.dumps(
        {
            "artifact": {
                "filename": f"{name.replace('.', '-')}-{version}.tar.gz",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            },
            "metadata": {"dependencies": dependencies},
        }
    ).encode("utf-8")


def serve_metadata(galaxy: Galaxy, docker_dependencies: dict[str, str], filename: str = "") -> None:
    for name, (version, data) in galaxy.collections.items():
        namespace, short = name.split(".")
        document = metadata(name, version, data, docker_dependencies if short == "docker" else {})
        if filename and short == "docker":
            document = document.replace(b"community-docker-5.4.0.tar.gz", filename.encode("utf-8"))
        galaxy.serve(f"{GALAXY}/index/{namespace}/{short}/versions/{version}/", document)


def write_requirements(galaxy: Galaxy, text: str) -> Path:
    path = galaxy.root / "requirements.yml"
    path.write_text(text, encoding="utf-8")
    return path


REQUIREMENTS_TEXT = """---
collections:
  - name: community.docker
    version: 5.4.0
  - name: community.library_inventory_filtering_v1
    version: "1.1.5"
"""


def test_lock_writes_the_pins_from_galaxy_metadata(galaxy: Galaxy) -> None:
    serve_metadata(galaxy, {"community.library_inventory_filtering_v1": ">=1.0.0"})
    result = galaxy.run("lock", str(write_requirements(galaxy, REQUIREMENTS_TEXT)))
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == galaxy.lines


def test_lock_refuses_a_dependency_that_is_not_pinned(galaxy: Galaxy) -> None:
    serve_metadata(galaxy, {"community.library_inventory_filtering_v1": "*", "ansible.utils": "*"})
    result = galaxy.run("lock", str(write_requirements(galaxy, REQUIREMENTS_TEXT)))
    assert result.returncode == 1
    assert "community.docker needs ansible.utils; pin it in" in result.stderr


def test_lock_refuses_an_artifact_of_another_name(galaxy: Galaxy) -> None:
    serve_metadata(galaxy, {}, filename="evil-docker-5.4.0.tar.gz")
    result = galaxy.run("lock", str(write_requirements(galaxy, REQUIREMENTS_TEXT)))
    assert result.returncode == 1
    assert "Galaxy names the artifact" in result.stderr


@pytest.mark.parametrize(
    "text",
    [
        "---\ncollections:\n  - name: community.docker\n",
        "---\ncollections:\n  - name: community.docker\n    version: '>=5'\n",
        "---\ncollections:\n  - community.docker\n",
        "---\nroles:\n  - name: x\n",
        "---\ncollections: []\n",
    ],
)
def test_lock_refuses_requirements_without_exact_pairs(galaxy: Galaxy, text: str) -> None:
    result = galaxy.run("lock", str(write_requirements(galaxy, text)))
    assert result.returncode == 2
    assert galaxy.calls("curl") == []


def test_lock_refuses_a_missing_requirements_file(galaxy: Galaxy) -> None:
    assert galaxy.run("lock", str(galaxy.root / "missing.yml")).returncode == 2


def test_the_pins_cover_exactly_the_pinned_requirements() -> None:
    requirements = cast(
        "list[dict[str, str]]", yaml.safe_load(REQUIREMENTS.read_text("utf-8"))["collections"]
    )
    required = {entry["name"]: str(entry["version"]) for entry in requirements}
    lines = [line.split() for line in PINS.read_text("utf-8").splitlines()]
    assert all(len(line) == 5 and line[0] == "collection" for line in lines)
    assert {line[1]: line[2] for line in lines} == required
    assert [line[1] for line in lines] == sorted(line[1] for line in lines)
    for line in lines:
        assert len(line[3]) == 64
        assert int(line[4]) > 0
    assert "community.library_inventory_filtering_v1" in required


def workflow() -> dict[str, dict[str, dict[str, object]]]:
    return cast(
        "dict[str, dict[str, dict[str, object]]]", yaml.safe_load(CI_WORKFLOW.read_text("utf-8"))
    )


def steps(job: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", job["steps"])


def test_only_the_collections_job_fetches_and_it_holds_read_only_permissions() -> None:
    jobs = workflow()["jobs"]
    fetchers = [
        name
        for name, job in jobs.items()
        for step in steps(job)
        if "molecule-collections-fetch" in str(step.get("run", ""))
    ]
    assert fetchers == ["molecule-collections"]
    job = jobs["molecule-collections"]
    assert job["permissions"] == {"contents": "read"}
    assert "secrets" not in yaml.safe_dump(job)
    [cache] = [
        step for step in steps(job) if str(step.get("uses", "")).startswith("actions/cache@")
    ]
    assert cache["if"] == FORK_CONDITION
    assert cast("dict[str, str]", cache["with"]) == {
        "path": "build/molecule-collections",
        "key": "galaxy-collections-${{ hashFiles('extensions/molecule/collections.pins') }}",
    }
    [upload] = [
        step
        for step in steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert cast("dict[str, object]", upload["with"])["retention-days"] == 1
    assert "molecule-collections" in cast("list[str]", jobs["ci-gate"]["needs"])
    assert "ansible-galaxy" not in CI_WORKFLOW.read_text("utf-8")


@pytest.mark.parametrize("name", INSTALLING_JOBS)
def test_every_job_that_installs_collections_downloads_the_verified_ones(name: str) -> None:
    job = workflow()["jobs"][name]
    needs = job["needs"]
    assert "molecule-collections" in (
        [needs] if isinstance(needs, str) else cast("list[str]", needs)
    )
    job_steps = steps(job)
    download = next(
        index
        for index, step in enumerate(job_steps)
        if cast("dict[str, str]", step.get("with", {})).get("name") == "molecule-collections"
    )
    assert cast("dict[str, str]", job_steps[download]["with"]) == {
        "name": "molecule-collections",
        "path": "build/molecule-collections",
    }
    assert str(job_steps[download]["uses"]).startswith("actions/download-artifact@")
    first_install = next(
        index
        for index, step in enumerate(job_steps)
        if any(target in str(step.get("run", "")) for target in ("make lint", "make test-molecule"))
    )
    assert download < first_install


def test_only_the_install_mode_reaches_ansible_galaxy_install_from_make() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "ansible-galaxy collection install" not in text
    assert "$(RUN) $(MOLECULE_GALAXY_COLLECTIONS) install '$(MOLECULE_COLLECTIONS_PINS)'" in text
    assert (
        "molecule-dependencies: require-uv collection-link "
        "$(if $(filter true,$(MOLECULE_OFFLINE)),,molecule-collections-fetch)\n"
    ) in text
