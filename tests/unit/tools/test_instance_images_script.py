"""The instance images of the Docker Molecule legs, built once per run (FREES-182, ADR 0009).

- ``tools/molecule/instance-images.sh build`` pulls each pinned base by digest, reuses a cached
  archive or a local image only after it carries the inputs label of its tag on exactly the
  base's layers, and otherwise builds with a bounded number of attempts, each under a time limit.
  ``save`` writes the archive that the cache and the run's artifact hold. It records the image
  ID of every image.
- ``load`` loads the archive of the run, refuses an image whose ID is not the one the build job
  recorded and never pulls or builds.
- The ``molecule-images`` job is the only one that builds, it has read-only permissions, a pull
  request from a fork neither restores nor saves its cache, and every Docker leg needs it, loads
  its artifact and gets its image IDs. ``create.yml`` never builds an image, and nothing pushes
  one. The tests run the script with a fake ``docker`` and ``zstd`` that record their calls.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "tools" / "molecule" / "instance-images.sh"
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
CREATE = REPOSITORY_ROOT / "extensions" / "molecule" / "shared" / "create.yml"
IMAGES = REPOSITORY_ROOT / "extensions" / "molecule" / "shared" / "images"
TIMEOUT_SECONDS = 60
BASE = "docker.io/library/ubuntu:24.04@sha256:" + "ab" * 32
TAG = "abababababab-0123456789ab"
IMAGE = f"freesecdev-molecule/ubuntu:{TAG}"
LABEL = "org.freesecdev.molecule.inputs"
FORK_CONDITION = (
    "github.event_name != 'pull_request'"
    " || (!github.event.pull_request.head.repo.fork"
    " && github.event.pull_request.head.repo.full_name == github.repository)"
)
DOCKER_LEGS = ("molecule-docker", "molecule-lifecycle")

FAKE_DOCKER = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FAKE_LOG}/docker"
record() { printf '%s/%s' "${FAKE_STATE}" "${1//[\/:@]/_}"; }
countdown() {
  local file="${FAKE_STATE}/$1" left
  left="$(cat "${file}" 2>/dev/null || printf 0)"
  if [[ "${left}" -gt 0 ]]; then printf '%s' "$((left - 1))" > "${file}"; return 0; fi
  return 1
}
case "$1" in
  pull)
    reference="${!#}"
    if countdown pull-failures; then exit 1; fi
    printf 'name %s\nid sha256:%s\nlabel \nlayer base-1\nlayer base-2\n' "${reference}" \
      "$(printf 64 | sha256sum | cut -c1-64)" \
      > "$(record "${reference}")"
    printf '%s\n' "${reference}"
    ;;
  image)
    case "$2" in
      inspect)
        if [[ "$3" == --format ]]; then format="$4"; name="$5"; else format=""; name="$3"; fi
        file="$(record "${name}")"
        [[ -f "${file}" ]] || { printf 'Error: No such image: %s\n' "${name}" >&2; exit 1; }
        case "${format}" in
          *RootFS*) awk '$1 == "layer" { print $2 } END { print "" }' "${file}" ;;
          *Labels*) awk '$1 == "label" { print $2 }' "${file}" ;;
          *.Id*) awk '$1 == "id" { print $2 }' "${file}" ;;
          *) cat "${file}" ;;
        esac
        ;;
      rm) rm -f "$(record "${!#}")" ;;
    esac
    ;;
  build)
    if [[ -n "${FAKE_BUILD_SLEEP:-}" ]] && countdown slow-builds; then
      exec sleep "${FAKE_BUILD_SLEEP}"
    fi
    if countdown build-failures; then printf 'mirror too slow\n' >&2; exit 1; fi
    shift
    tag="" label="" base=""
    while [[ $# -gt 1 ]]; do
      case "$1" in
        --tag) tag="$2"; shift 2 ;;
        --label) label="${2#*=}"; shift 2 ;;
        --build-arg) base="${2#BASE_IMAGE=}"; shift 2 ;;
        --file) shift 2 ;;
        *) shift ;;
      esac
    done
    {
      printf 'name %s\nid sha256:%s\nlabel %s\n' "${tag}" \
        "$(printf '%s' "${tag}${RANDOM}" | sha256sum | cut -c1-64)" \
        "${FAKE_BUILD_LABEL:-${label}}"
      if [[ -z "${FAKE_BUILD_OTHER_BASE:-}" ]]; then awk '$1 == "layer"' "$(record "${base}")"; fi
      printf 'layer packages\n'
    } > "$(record "${tag}")"
    ;;
  save) cat "$(record "$2")" ;;
  load)
    data="$(cat)"
    name="$(awk '$1 == "name" { print $2 }' <<< "${data}")"
    printf '%s\n' "${data}" > "$(record "${name}")"
    printf 'Loaded image: %s\n' "${name}"
    awk '$1 == "extra" { print "Loaded image: " $2 }
      $1 == "untagged" { print "Loaded image ID: " $2 }' <<< "${data}"
    ;;
  *) exit 2 ;;
esac
"""
FAKE_ZSTD = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FAKE_LOG}/zstd"
if [[ "$1" == --decompress ]]; then cat -- "${!#}"; exit 0; fi
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then cat > "$2"; exit 0; fi
  shift
done
exit 2
"""


def executable(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is required"
    return path


class Host:
    """A fake Docker daemon and zstd below ``root``, and a plan of one image."""

    def __init__(self, root: Path) -> None:
        """Create the fake tools, their state and a plan of the Ubuntu image."""
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, text in {"docker": FAKE_DOCKER, "zstd": FAKE_ZSTD}.items():
            path = self.bin / name
            path.write_text(text, encoding="utf-8")
            path.chmod(0o755)
        self.log = root / "log"
        self.log.mkdir()
        self.state = root / "state"
        self.state.mkdir()
        self.cache = root / "cache"
        self.record = root / "verified.yml"
        self.plan = root / "plan"
        self.write_plan(f"ubuntu {TAG} {BASE} {IMAGES / 'ubuntu.Dockerfile'}\n")

    def write_plan(self, text: str) -> None:
        self.plan.write_text(text, encoding="utf-8")

    def set(self, name: str, value: int) -> None:
        (self.state / name).write_text(str(value), encoding="utf-8")

    def forget_images(self) -> None:
        for path in self.state.iterdir():
            path.unlink()
        (self.log / "docker").unlink(missing_ok=True)

    def run(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [executable("bash"), str(SCRIPT), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            env={
                "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "FAKE_LOG": str(self.log),
                "FAKE_STATE": str(self.state),
                "MOLECULE_IMAGE_RETRY_DELAY": "0",
                **(environment or {}),
            },
        )

    def build(
        self, *extra: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            "build",
            str(self.plan),
            str(self.cache),
            str(self.record),
            *extra,
            environment=environment,
        )

    def load(self, ids: str) -> subprocess.CompletedProcess[str]:
        return self.run("load", str(self.plan), str(self.cache), str(self.record), ids)

    def calls(self) -> list[str]:
        path = self.log / "docker"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def verified(self) -> dict[str, dict[str, str]]:
        return cast("dict[str, dict[str, str]]", yaml.safe_load(self.record.read_text("utf-8")))


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def test_a_build_pulls_the_base_by_digest_builds_saves_and_records_the_image(host: Host) -> None:
    result = host.build("save")
    assert result.returncode == 0, result.stderr
    calls = host.calls()
    assert calls[0] == f"pull --quiet {BASE}"
    [build] = [call for call in calls if call.startswith("build ")]
    assert f"--build-arg BASE_IMAGE={BASE}" in build
    assert f"--label {LABEL}={TAG} --tag {IMAGE}" in build
    assert "--provenance=false" in build
    assert build.endswith(str(IMAGES))
    assert f"save {IMAGE}" in calls
    assert not any(call.split()[0] in {"push", "login", "tag"} for call in calls)
    assert (host.cache / "ubuntu" / "image.tar.zst").is_file()
    record = host.verified()
    assert record["ubuntu"]["tag"] == TAG
    assert record["ubuntu"]["id"].startswith("sha256:")
    ids = host.run("ids", str(host.record))
    assert ids.stdout == f"ubuntu={record['ubuntu']['id']}\n"
    assert "[ubuntu] built " + IMAGE in result.stdout


def test_a_failed_or_slow_build_is_retried_within_the_bound(host: Host) -> None:
    host.set("build-failures", 1)
    host.set("slow-builds", 1)
    environment = {"MOLECULE_IMAGE_BUILD_TIMEOUT": "1", "FAKE_BUILD_SLEEP": "20"}
    result = host.build(environment=environment)
    assert result.returncode == 0, result.stderr
    assert "exceeded 1 seconds (attempt 1 of 3)" in result.stdout
    assert "(attempt 2 of 3)" in result.stdout
    assert len([call for call in host.calls() if call.startswith("build ")]) == 3


def test_a_build_that_keeps_failing_stops_after_the_last_attempt(host: Host) -> None:
    host.set("build-failures", 5)
    result = host.build("save", environment={"MOLECULE_IMAGE_BUILD_ATTEMPTS": "2"})
    assert result.returncode == 1
    assert "building " + IMAGE + " failed 2 times" in result.stdout
    assert not host.record.exists()
    assert not (host.cache / "ubuntu").exists()


def test_a_failed_pull_is_retried(host: Host) -> None:
    host.set("pull-failures", 1)
    result = host.build()
    assert result.returncode == 0, result.stderr
    assert host.calls()[:2] == [f"pull --quiet {BASE}"] * 2


def test_a_cached_archive_is_reused_only_after_it_verifies(host: Host) -> None:
    assert host.build("save").returncode == 0
    built = host.verified()["ubuntu"]["id"]
    host.forget_images()
    result = host.build("save")
    assert result.returncode == 0, result.stderr
    assert "reusing the cached " + IMAGE in result.stdout
    assert not any(call.startswith("build ") for call in host.calls())
    assert f"save {IMAGE}" in host.calls()
    assert host.verified()["ubuntu"]["id"] == built


EXTRAS = ["extra docker.io/library/python:3", "untagged sha256:" + "ef" * 32]


@pytest.mark.parametrize("extra", EXTRAS)
def test_a_cached_archive_with_another_image_is_discarded_and_only_the_target_is_saved(
    host: Host, extra: str
) -> None:
    assert host.build("save").returncode == 0
    archive = host.cache / "ubuntu" / "image.tar.zst"
    archive.write_text(archive.read_text("utf-8") + extra + "\n", encoding="utf-8")
    host.forget_images()
    result = host.build("save")
    assert result.returncode == 0, result.stdout
    assert "the archive loads more than " + IMAGE in result.stdout
    assert "does not verify; it is discarded and the image is built" in result.stdout
    assert any(call.startswith("build ") for call in host.calls())
    assert extra not in archive.read_text("utf-8")


@pytest.mark.parametrize("extra", EXTRAS)
def test_a_leg_refuses_an_archive_that_loads_another_image(host: Host, extra: str) -> None:
    assert host.build("save").returncode == 0
    built = host.verified()["ubuntu"]["id"]
    archive = host.cache / "ubuntu" / "image.tar.zst"
    archive.write_text(archive.read_text("utf-8") + extra + "\n", encoding="utf-8")
    host.forget_images()
    host.record.unlink()
    result = host.load(f"ubuntu={built}")
    assert result.returncode == 1
    assert "the archive loads more than " + IMAGE in result.stderr
    assert not host.record.exists()


@pytest.mark.parametrize(
    "forged",
    [
        f"name {IMAGE}\nid sha256:{'cd' * 32}\nlabel x\nlayer base-1\nlayer base-2\nlayer p\n",
        f"name {IMAGE}\nid sha256:{'cd' * 32}\nlabel {TAG}\nlayer other\nlayer base-2\nlayer p\n",
        f"name {IMAGE}\nid sha256:{'cd' * 32}\nlabel {TAG}\nlayer base-1\nlayer base-2\n",
        f"name freesecdev-molecule/ubuntu:latest\nid sha256:{'cd' * 32}\nlabel {TAG}\n",
    ],
)
def test_a_cached_archive_that_does_not_verify_is_discarded_and_rebuilt(
    host: Host, forged: str
) -> None:
    (host.cache / "ubuntu").mkdir(parents=True)
    (host.cache / "ubuntu" / "image.tar.zst").write_text(forged, encoding="utf-8")
    result = host.build("save")
    assert result.returncode == 0, result.stdout
    assert "does not verify; it is discarded and the image is built" in result.stdout
    assert any(call.startswith("build ") for call in host.calls())
    assert host.verified()["ubuntu"]["id"] != "sha256:" + "cd" * 32
    assert (host.cache / "ubuntu" / "image.tar.zst").read_text("utf-8") != forged


@pytest.mark.parametrize(
    "environment", [{"FAKE_BUILD_LABEL": "other"}, {"FAKE_BUILD_OTHER_BASE": "1"}]
)
def test_a_built_image_that_does_not_verify_fails(host: Host, environment: dict[str, str]) -> None:
    result = host.build("save", environment=environment)
    assert result.returncode == 1
    assert "does not carry its inputs label on the pinned base layers" in result.stdout
    assert not host.record.exists()


def test_a_local_image_is_reused_without_saving_unless_asked(host: Host) -> None:
    assert host.build().returncode == 0
    assert not (host.cache / "ubuntu").exists()
    (host.log / "docker").unlink()
    result = host.build()
    assert result.returncode == 0, result.stderr
    assert "reusing the local " + IMAGE in result.stdout
    assert not any(call.startswith("build ") for call in host.calls())


def test_a_local_image_without_the_label_is_rebuilt(host: Host) -> None:
    old = f"name {IMAGE}\nid sha256:{'cd' * 32}\nlabel \nlayer base-1\nlayer base-2\nlayer p\n"
    (host.state / IMAGE.replace("/", "_").replace(":", "_")).write_text(old, encoding="utf-8")
    result = host.build()
    assert result.returncode == 0, result.stderr
    assert f"image rm --force {IMAGE}" in host.calls()


def test_a_leg_loads_the_image_of_the_run_and_never_pulls_or_builds(host: Host) -> None:
    assert host.build("save").returncode == 0
    built = host.verified()["ubuntu"]["id"]
    host.forget_images()
    host.record.unlink()
    result = host.load(f"rhel_compatible=sha256:{'ef' * 32} ubuntu={built}")
    assert result.returncode == 0, result.stderr
    assert "verified its image ID " + built + "; nothing was built" in result.stdout
    assert not any(call.startswith(("build", "pull", "save")) for call in host.calls())
    assert host.verified() == {"ubuntu": {"tag": TAG, "id": built}}


def test_a_leg_refuses_an_image_whose_id_is_not_the_recorded_one(host: Host) -> None:
    assert host.build("save").returncode == 0
    host.forget_images()
    host.record.unlink()
    result = host.load(f"ubuntu=sha256:{'ef' * 32}")
    assert result.returncode == 1
    assert (
        "not sha256:" + "ef" * 32 + " of the molecule-images job; nothing is built here"
        in result.stderr
    )
    assert f"image rm --force {IMAGE}" in host.calls()
    assert not host.record.exists()


@pytest.mark.parametrize(
    ("ids", "status", "message"),
    [
        ("", 1, "no image ID of ubuntu was given"),
        ("ubuntu=sha256:abc", 2, "is not <image>=<image ID>"),
        ("ubuntu sha256:" + "ab" * 32, 2, "is not <image>=<image ID>"),
    ],
)
def test_a_leg_refuses_missing_or_malformed_image_ids(
    host: Host, ids: str, status: int, message: str
) -> None:
    assert host.build("save").returncode == 0
    result = host.load(ids)
    assert result.returncode == status
    assert message in result.stderr


def test_a_leg_without_the_archive_fails_instead_of_building(host: Host) -> None:
    result = host.load(f"ubuntu=sha256:{'ab' * 32}")
    assert result.returncode == 1
    assert "never builds one" in result.stderr
    assert host.calls() == []


def test_a_leg_refuses_an_archive_of_another_image(host: Host) -> None:
    (host.cache / "ubuntu").mkdir(parents=True)
    other = (
        "name freesecdev-molecule/ubuntu:abababababab-ffffffffffff\n"
        f"id sha256:{'ab' * 32}\nlabel {TAG}\n"
    )
    (host.cache / "ubuntu" / "image.tar.zst").write_text(other, encoding="utf-8")
    result = host.load(f"ubuntu=sha256:{'ab' * 32}")
    assert result.returncode == 1
    assert "does not hold " + IMAGE in result.stderr


def test_a_leg_refuses_an_image_without_the_inputs_label(host: Host) -> None:
    (host.cache / "ubuntu").mkdir(parents=True)
    archive = f"name {IMAGE}\nid sha256:{'ab' * 32}\nlabel other\n"
    (host.cache / "ubuntu" / "image.tar.zst").write_text(archive, encoding="utf-8")
    result = host.load(f"ubuntu=sha256:{'ab' * 32}")
    assert result.returncode == 1
    assert "does not carry the inputs label of its tag" in result.stderr


@pytest.mark.parametrize(
    ("plan", "message"),
    [
        ("", "plans no image"),
        (f"Ubuntu {TAG} {BASE} {IMAGES / 'ubuntu.Dockerfile'}\n", "is not an image key and tag"),
        (f"ubuntu latest {BASE} {IMAGES / 'ubuntu.Dockerfile'}\n", "is not an image key and tag"),
        (
            f"ubuntu {TAG} docker.io/library/ubuntu:24.04 {IMAGES / 'ubuntu.Dockerfile'}\n",
            "not pinned by digest",
        ),
        (f"ubuntu {TAG} {BASE} /etc/passwd\n", "not one of extensions/molecule/shared/images"),
    ],
)
def test_a_malformed_plan_is_refused_before_docker_runs(
    host: Host, plan: str, message: str
) -> None:
    host.write_plan(plan)
    result = host.build()
    assert result.returncode == 2
    assert message in result.stderr
    assert host.calls() == []


@pytest.mark.parametrize(
    "arguments",
    [
        ["other"],
        ["build", "plan-missing", "c", "r"],
        ["ids", "record-missing"],
    ],
)
def test_unknown_modes_and_missing_files_are_refused(host: Host, arguments: list[str]) -> None:
    result = host.run(*arguments)
    assert result.returncode == 2
    assert "error:" in result.stderr


def test_a_build_refuses_an_unknown_option_and_malformed_bounds(host: Host) -> None:
    assert host.build("push").returncode == 2
    assert host.build(environment={"MOLECULE_IMAGE_BUILD_TIMEOUT": "1; true"}).returncode == 2


@pytest.mark.parametrize(
    "record",
    ["", '---\nubuntu:\n  id: "sha256:abc"\n', '---\n  id: "sha256:' + "ab" * 32 + '"\n'],
)
def test_ids_refuse_a_malformed_record(host: Host, record: str) -> None:
    host.record.write_text(record, encoding="utf-8")
    result = host.run("ids", str(host.record))
    assert result.returncode == 2


def workflow() -> dict[str, dict[str, dict[str, object]]]:
    return cast(
        "dict[str, dict[str, dict[str, object]]]", yaml.safe_load(CI_WORKFLOW.read_text("utf-8"))
    )


def steps(job: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", job["steps"])


def test_only_the_images_job_builds_and_it_holds_read_only_permissions() -> None:
    jobs = workflow()["jobs"]
    builders = [
        name
        for name, job in jobs.items()
        for step in steps(job)
        if "molecule-images-build" in str(step.get("run", ""))
    ]
    assert builders == ["molecule-images"]
    job = jobs["molecule-images"]
    assert job["permissions"] == {"contents": "read"}
    assert "secrets" not in yaml.safe_dump(job)
    assert job["timeout-minutes"] == 15
    assert cast("dict[str, str]", job["outputs"])["ids"] == "${{ steps.ids.outputs.ids }}"
    uses = [str(step.get("uses", "")).split("@", maxsplit=1)[0] for step in steps(job)]
    assert "actions/cache" not in uses
    restores = [
        step for step, use in zip(steps(job), uses, strict=True) if use == "actions/cache/restore"
    ]
    saves = [
        step for step, use in zip(steps(job), uses, strict=True) if use == "actions/cache/save"
    ]
    paths = ["build/molecule-images/ubuntu", "build/molecule-images/rhel_compatible"]
    assert [cast("dict[str, str]", step["with"])["path"] for step in restores] == paths
    assert [cast("dict[str, str]", step["with"])["path"] for step in saves] == paths
    assert [step["if"] for step in restores] == [FORK_CONDITION] * 2
    for restore, save in zip(restores, saves, strict=True):
        image = cast("dict[str, str]", restore["with"])["path"].rsplit("/", 1)[1]
        week = "${{ steps.plan.outputs.week }}"
        key = f"molecule-image-{image}-${{{{ steps.plan.outputs.{image} }}}}-{week}"
        assert cast("dict[str, str]", restore["with"])["key"] == key
        assert cast("dict[str, str]", save["with"])["key"] == key
        assert " ".join(str(save["if"]).split()) == (
            f"steps.{restore['id']}.outcome == 'success'"
            f" && steps.{restore['id']}.outputs.cache-hit != 'true'"
            " && github.event_name != 'schedule'"
        )
    assert uses.index("actions/cache/save") > uses.index("actions/upload-artifact")
    makefile = MAKEFILE.read_text("utf-8")
    assert "@printf 'week=%s\\n' \"$$(date -u +%G-W%V)\"" in makefile
    [upload] = [
        step
        for step in steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert cast("dict[str, object]", upload["with"])["retention-days"] == 1
    assert cast("dict[str, object]", upload["with"])["name"] == "molecule-images"
    assert "molecule-images" in cast("list[str]", jobs["ci-gate"]["needs"])


@pytest.mark.parametrize("name", DOCKER_LEGS)
def test_every_docker_leg_loads_the_images_of_the_run_with_their_recorded_ids(name: str) -> None:
    job = workflow()["jobs"][name]
    assert "molecule-images" in cast("list[str]", job["needs"])
    assert cast("dict[str, str]", job["env"]) == {
        "MOLECULE_IMAGE_IDS": "${{ needs.molecule-images.outputs.ids }}"
    }
    downloads = [
        cast("dict[str, str]", step["with"])
        for step in steps(job)
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]
    assert {"name": "molecule-images", "path": "build/molecule-images"} in downloads
    assert all(set(download) == {"name", "path"} for download in downloads)
    first_make = next(
        index for index, step in enumerate(steps(job)) if "make " in str(step.get("run", ""))
    )
    last_download = max(
        index
        for index, step in enumerate(steps(job))
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    )
    assert last_download < first_make


def test_create_never_builds_and_nothing_pushes_an_instance_image() -> None:
    create = CREATE.read_text(encoding="utf-8")
    assert "community.docker.docker_image:" not in create
    assert "source: build" not in create
    assert "community.docker.docker_image_info:" in create
    script = SCRIPT.read_text(encoding="utf-8")
    for verb in ("docker push", "docker login", "docker tag", "--push", "buildx"):
        assert verb not in script
    text = CI_WORKFLOW.read_text(encoding="utf-8") + MAKEFILE.read_text(encoding="utf-8")
    assert "docker push" not in text
    assert "docker/login-action" not in text
    assert (
        "MOLECULE_OFFLINE ?= $(if $(filter true,$(GITHUB_ACTIONS)),true,false)\n"
        in MAKEFILE.read_text("utf-8")
    )
