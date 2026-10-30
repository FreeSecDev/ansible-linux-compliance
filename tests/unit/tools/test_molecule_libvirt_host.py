"""The QEMU and libvirt packages of the libvirt CI legs (FREES-180, ADR 0009).

- ``tools/molecule/libvirt-host-packages.sh fetch`` downloads every pinned ``.deb`` only from
  the pinned Ubuntu archive snapshot over HTTPS and keeps a file only after its SHA-256 and size
  match the pin; a cached file is checked again before it is reused.
- ``install`` checks every file again before it installs anything, installs only the packages
  that the runner lacks, gives ``apt-get`` no package source so that nothing unverified can be
  downloaded, and checks the required versions afterwards. It refuses to run outside a
  GitHub-hosted runner. The tests run it with fake ``curl``, ``sudo``, ``apt-get``, ``dpkg`` and
  ``dpkg-query`` that record what they were asked.
- ``resolve`` asks ``apt`` with a private configuration whose only source is the snapshot, signed
  by the Ubuntu archive key, and prints the pins of the files that the host lacks from the
  index; a pins file without a final newline keeps its last line.
- The repository pins are well formed, the workflow restores and saves the verified packages
  under a key of the pins, and the timings come from the job log, without a callback plugin.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY_ROOT / "tools" / "molecule" / "libvirt-host-packages.sh"
PINS = REPOSITORY_ROOT / "tools" / "molecule" / "libvirt-host.pins"
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
REQUIREMENTS = REPOSITORY_ROOT / "extensions" / "molecule" / "requirements.yml"
TIMEOUT_SECONDS = 60
SNAPSHOT = "20261027T000000Z"
ARCHIVE = f"https://snapshot.ubuntu.com/ubuntu/{SNAPSHOT}/"
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}

FAKE_CURL = """#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --max-filesize|--proto|--proto-redir|--retry|--retry-delay) shift 2 ;;
    --connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\\n' "${url}" >> "${FAKE_LOG}/curl"
source_file="$(awk -v url="${url}" '$1 == url { print $2 }' "${FAKE_ROUTES}")"
[[ -n "${source_file}" ]] || exit 22
cp "${source_file}" "${output}"
"""
FAKE_SUDO = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${FAKE_LOG}/sudo"
exec env "$@"
"""
FAKE_APT_GET = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${FAKE_LOG}/apt-get"
for argument in "$@"; do
  case "${argument}" in
    Dir::Etc::SourceList=/dev/null) ;;
    Dir::Etc::SourceList=*) cp "${argument#*=}" "${FAKE_LOG}/sources" ;;
    --print-uris) cat "${FAKE_URIS}"; exit 0 ;;
    /*.deb)
      file="$(basename "${argument}")"
      name="${file%%_*}"
      version="${file#*_}"
      printf '%s %s\\n' "${name}" "${version%_*}" >> "${FAKE_STATUS}"
      ;;
  esac
done
"""
FAKE_DPKG_QUERY = """#!/usr/bin/env bash
format="$2"
name="$3"
record="$(awk -v name="${name}" '$1 == name { print $2, ($3 == "" ? "ii" : $3) }' \\
  "${FAKE_STATUS}" | tail -n 1)"
[[ -n "${record}" ]] || exit 1
version="${record% *}"
if [[ "${format}" == *Status-Abbrev* ]]; then
  printf '%s %s' "${record#* }" "${version}"
else
  printf '%s' "${version}"
fi
"""
FAKE_APT_CACHE = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${FAKE_LOG}/apt-cache"
cat "${FAKE_RECORDS}"
"""
FAKE_DPKG = """#!/usr/bin/env bash
[[ "$1" == --compare-versions && "$3" == ge ]] || exit 2
printf '%s\\n%s\\n' "$4" "$2" | sort -V -C
"""


def executable(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is required"
    return path


class Host:
    """A fake runner: a served archive, fake package tools and a package database."""

    def __init__(self, root: Path) -> None:
        """Create the fake tools, two served packages and their pins below ``root``."""
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, text in {
            "curl": FAKE_CURL,
            "sudo": FAKE_SUDO,
            "apt-get": FAKE_APT_GET,
            "dpkg-query": FAKE_DPKG_QUERY,
            "dpkg": FAKE_DPKG,
            "apt-cache": FAKE_APT_CACHE,
        }.items():
            path = self.bin / name
            path.write_text(text, encoding="utf-8")
            path.chmod(0o755)
        self.log = root / "log"
        self.log.mkdir()
        self.status = root / "status"
        self.status.write_text("pkg-config 1.8\n", encoding="utf-8")
        self.served = root / "served"
        self.served.mkdir()
        self.routes: dict[str, Path] = {}
        self.cache = root / "cache"
        self.packages = {
            "qemu-utils": ("8.2", "pool/main/q/qemu/qemu-utils_8.2_amd64.deb", b"qemu utils"),
            "libfdt1": ("1.7", "pool/main/d/dtc/libfdt1_1.7_amd64.deb", b"libfdt"),
        }
        for _version, pool, data in self.packages.values():
            self.serve(ARCHIVE + pool, data)
        self.lines = [
            f"snapshot {SNAPSHOT}",
            "require qemu-utils 8.2",
            "require pkg-config 1.8",
            *(
                f"deb {name} {version} {path} {hashlib.sha256(data).hexdigest()} {len(data)}"
                for name, (version, path, data) in self.packages.items()
            ),
        ]

    def serve(self, url: str, data: bytes) -> None:
        """Serve ``data`` at ``url``."""
        path = self.served / f"file-{len(self.routes)}"
        path.write_bytes(data)
        self.routes[url] = path

    def pins(self, lines: list[str] | None = None, *, final_newline: bool = True) -> Path:
        """Write the pins, by default the valid ones, with or without a final newline."""
        path = self.root / "host.pins"
        text = "\n".join(lines or self.lines)
        path.write_text(text + "\n" if final_newline else text, encoding="utf-8")
        return path

    def run(
        self,
        mode: str,
        lines: list[str] | None = None,
        environment: dict[str, str] | None = None,
        *,
        final_newline: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run the script in ``mode`` against the fake runner."""
        routes = self.root / "routes"
        routes.write_text(
            "".join(f"{url} {path}\n" for url, path in self.routes.items()), encoding="utf-8"
        )
        return subprocess.run(
            [
                executable("bash"),
                str(SCRIPT),
                mode,
                str(self.pins(lines, final_newline=final_newline)),
                str(self.cache),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            env={
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "HOME": str(self.root),
                "FAKE_ROUTES": str(routes),
                "FAKE_LOG": str(self.log),
                "FAKE_STATUS": str(self.status),
                "FAKE_URIS": str(self.root / "uris"),
                "FAKE_RECORDS": str(self.root / "records"),
                **(environment or {}),
            },
            cwd=self.root,
        )

    def calls(self, tool: str) -> list[str]:
        """Return the command lines that a fake tool was called with."""
        path = self.log / tool
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def test_fetch_downloads_verifies_and_reuses(host: Host) -> None:
    first = host.run("fetch")
    assert first.returncode == 0, first.stderr
    assert (host.cache / "qemu-utils_8.2_amd64.deb").read_bytes() == b"qemu utils"
    assert sorted(host.calls("curl")) == sorted(
        ARCHIVE + path for _version, path, _data in host.packages.values()
    )
    second = host.run("fetch")
    assert second.returncode == 0, second.stderr
    assert second.stdout.count("reusing the verified") == 2
    assert len(host.calls("curl")) == 2


def test_fetch_replaces_a_cached_file_that_no_longer_matches(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    cached = host.cache / "libfdt1_1.7_amd64.deb"
    cached.write_bytes(b"libfdX")
    result = host.run("fetch")
    assert result.returncode == 0, result.stderr
    assert cached.read_bytes() == b"libfdt"


def test_fetch_refuses_a_download_that_does_not_match_its_pin(host: Host) -> None:
    host.serve(ARCHIVE + host.packages["libfdt1"][1], b"libfdX")
    result = host.run("fetch")
    assert result.returncode == 1
    assert "does not match the pinned SHA-256 and size" in result.stderr
    assert not (host.cache / "libfdt1_1.7_amd64.deb").exists()


def test_install_refuses_outside_a_github_hosted_runner(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    for environment in ({}, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
        result = host.run("install", environment=environment)
        assert result.returncode == 2
        assert "runs only on a GitHub-hosted runner" in result.stderr
    assert host.calls("sudo") == []


def test_install_refuses_an_unverified_file_before_installing_anything(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    (host.cache / "qemu-utils_8.2_amd64.deb").write_bytes(b"qemu utilX")
    result = host.run("install", environment=HOSTED)
    assert result.returncode == 1
    assert "does not match its pin; nothing was installed" in result.stderr
    assert host.calls("sudo") == []
    (host.cache / "qemu-utils_8.2_amd64.deb").unlink()
    result = host.run("install", environment=HOSTED)
    assert result.returncode == 1
    assert host.calls("sudo") == []


def test_install_uses_only_the_verified_files_that_the_runner_lacks(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    with host.status.open("a", encoding="utf-8") as status:
        status.write("libfdt1 1.7\n")
    result = host.run("install", environment=HOSTED)
    assert result.returncode == 0, result.stderr
    assert "keeping the installed libfdt1 1.7" in result.stdout
    [call] = host.calls("apt-get")
    assert "-o Dir::Etc::SourceList=/dev/null" in call
    assert "Dir::State::Lists=" in call
    assert "--no-install-recommends" in call
    installed = call.rsplit(" -- ", 1)[1].split()
    assert len(installed) == 1
    assert installed[0].endswith("/debs/qemu-utils_8.2_amd64.deb")
    assert not installed[0].startswith(str(host.cache))
    second = host.run("install", environment=HOSTED)
    assert second.returncode == 0, second.stderr
    assert len(host.calls("apt-get")) == 1


def test_install_fails_when_a_required_version_is_not_installed(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    lines = [*host.lines, "require libvirt-dev 10.0"]
    result = host.run("install", lines=lines, environment=HOSTED)
    assert result.returncode == 1
    assert "libvirt-dev is missing, not the pinned 10.0" in result.stderr
    host.status.write_text("pkg-config 1.9\n", encoding="utf-8")
    result = host.run("install", environment=HOSTED)
    assert result.returncode == 1
    assert "pkg-config is 1.9, not the pinned 1.8" in result.stderr


def replaced(lines: list[str], index: int, field: int, value: str) -> list[str]:
    fields = lines[index].split()
    fields[field] = value
    return [*lines[:index], " ".join(fields), *lines[index + 1 :]]


@pytest.mark.parametrize(
    ("index", "field", "value", "message"),
    [
        (0, 1, "2026-10-27", "must name one snapshot"),
        (1, 1, "Qemu", "is not a package name"),
        (1, 2, "8.2 extra", "too many fields"),
        (3, 2, "8 2", "too many fields"),
        (3, 2, "8;2", "is not a package version"),
        (3, 3, "https://example.org/pool/main/q/qemu/qemu-utils_8.2_amd64.deb", "pool path"),
        (3, 3, "pool/main/q/qemu/../../../x/qemu-utils_8.2_amd64.deb", "pool path"),
        (3, 3, "pool/restricted/q/qemu/qemu-utils_8.2_amd64.deb", "pool path"),
        (3, 3, "pool/main/q/qemu/libfdt1_1.7_amd64.deb", "is not a pool path of qemu-utils"),
        (3, 4, "A" * 64, "is not 64 lower-case hex digits"),
        (3, 5, "big", "is not a bound"),
        (3, 5, "268435457", "is not a bound"),
        (3, 0, "mirror", "unknown line kind mirror"),
    ],
)
def test_malformed_pins_are_refused_before_any_download(
    host: Host, index: int, field: int, value: str, message: str
) -> None:
    result = host.run("fetch", lines=replaced(host.lines, index, field, value))
    assert result.returncode == 2
    assert message in result.stderr
    assert host.calls("curl") == []


def test_pins_without_a_snapshot_or_a_requirement_are_refused(host: Host) -> None:
    for lines in (host.lines[1:], [host.lines[0], *host.lines[3:]], [*host.lines, host.lines[0]]):
        result = host.run("fetch", lines=lines)
        assert result.returncode == 2
        assert "snapshot" in result.stderr
    assert host.calls("curl") == []


def test_an_unknown_mode_is_refused(host: Host) -> None:
    result = host.run("upgrade")
    assert result.returncode == 2
    assert "unknown mode upgrade" in result.stderr


def repository_pins() -> list[list[str]]:
    return [line.split() for line in PINS.read_text(encoding="utf-8").splitlines() if line]


def test_the_repository_pins_are_well_formed_and_cover_the_requirements() -> None:
    pins = repository_pins()
    assert [line[0] for line in pins].count("snapshot") == 1
    debs = {line[1]: line for line in pins if line[0] == "deb"}
    assert len(debs) == len([line for line in pins if line[0] == "deb"])
    for name, line in debs.items():
        assert len(line) == 6
        assert Path(line[3]).name.startswith(f"{name}_"), line
        assert len(line[4]) == 64
    requires = {line[1]: line[2] for line in pins if line[0] == "require"}
    expected = {"qemu-system-x86", "qemu-utils", "libvirt-daemon-system", "libvirt-dev"}
    assert expected <= set(requires)
    for name, version in requires.items():
        if name in debs:
            assert debs[name][2] == version


def test_ci_installs_only_the_verified_packages_under_a_key_of_the_pins() -> None:
    workflow = cast(
        "dict[str, dict[str, dict[str, object]]]", yaml.safe_load(CI_WORKFLOW.read_text("utf-8"))
    )
    job = workflow["jobs"]["molecule-libvirt"]
    steps = cast("list[dict[str, object]]", job["steps"])
    text = yaml.safe_dump(steps)
    assert "--snapshot" not in text
    assert "apt-get" not in text
    key = "libvirt-host-packages-${{ hashFiles('tools/molecule/libvirt-host.pins') }}"
    uses = {
        str(step["uses"]).split("@", maxsplit=1)[0]: cast("dict[str, str]", step["with"])
        for step in steps
        if str(step.get("uses", "")).startswith("actions/cache/")
    }
    assert uses["actions/cache/restore"]["key"] == key
    assert uses["actions/cache/save"]["key"] == key
    runs = [str(step.get("run", "")) for step in steps]
    fetch = next(index for index, run in enumerate(runs) if "molecule-libvirt-host-fetch" in run)
    install = next(index for index, run in enumerate(runs) if "libvirt-host-install" in run)
    save = next(
        index
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/cache/save")
    )
    assert fetch < save < install


def test_the_timings_come_from_the_job_log_without_a_callback_plugin() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "python -m tools.molecule.task_timings" in text
    assert "CALLBACKS_ENABLED" not in text
    collections = cast(
        "list[dict[str, str]]", yaml.safe_load(REQUIREMENTS.read_text("utf-8"))["collections"]
    )
    assert "ansible.posix" not in {collection["name"] for collection in collections}


def test_a_removed_package_with_its_configuration_left_is_not_installed(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    host.status.write_text("pkg-config 1.8 rc\nlibfdt1 1.7 rc\n", encoding="utf-8")
    result = host.run("install", environment=HOSTED)
    assert result.returncode == 1
    assert "pkg-config is missing, not the pinned 1.8" in result.stderr
    [call] = host.calls("apt-get")
    assert "/debs/libfdt1_1.7_amd64.deb" in call


def test_pins_without_a_final_newline_keep_their_last_line(host: Host) -> None:
    assert host.run("fetch").returncode == 0
    lines = [*host.lines, "require libvirt-dev 10.0"]
    result = host.run("install", lines=lines, environment=HOSTED, final_newline=False)
    assert result.returncode == 1
    assert "libvirt-dev is missing, not the pinned 10.0" in result.stderr
    (host.cache / "libfdt1_1.7_amd64.deb").unlink()
    result = host.run("fetch", final_newline=False)
    assert result.returncode == 0, result.stderr
    assert "downloaded and verified libfdt1_1.7_amd64.deb" in result.stdout


def test_resolve_prints_the_pins_of_what_the_host_lacks_from_the_signed_index(host: Host) -> None:
    (host.root / "uris").write_text(
        f"'{ARCHIVE}pool/main/q/qemu/qemu-utils_1%3a8.2_amd64.deb' qemu-utils_1%3a8.2_amd64.deb"
        " 10 SHA512:00\n",
        encoding="utf-8",
    )
    (host.root / "records").write_text(
        "Package: qemu-utils\nVersion: 1:8.2\n"
        "Filename: pool/main/q/qemu/qemu-utils_8.2_amd64.deb\n"
        f"Size: 10\nSHA256: {'a' * 64}\n\nPackage: other\nVersion: 2\n",
        encoding="utf-8",
    )
    result = host.run("resolve")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"snapshot {SNAPSHOT}",
        "require qemu-utils 8.2",
        "require pkg-config 1.8",
        f"deb qemu-utils 1:8.2 pool/main/q/qemu/qemu-utils_8.2_amd64.deb {'a' * 64} 10",
    ]
    assert host.calls("apt-cache")[0].endswith("show qemu-utils=1:8.2")
    sources = (host.log / "sources").read_text(encoding="utf-8").splitlines()
    for suite, line in zip(("noble", "noble-updates", "noble-security"), sources, strict=True):
        assert line == (
            "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
            f"{ARCHIVE.rstrip('/')} {suite} main universe"
        )
    assert host.calls("sudo") == []


def test_resolve_refuses_malformed_pins_before_asking_apt(host: Host) -> None:
    result = host.run("resolve", lines=host.lines[1:])
    assert result.returncode == 2
    assert "must name a snapshot" in result.stderr
    assert host.calls("apt-get") == []
