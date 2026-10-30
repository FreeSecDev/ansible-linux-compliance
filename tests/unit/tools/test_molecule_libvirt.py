"""Repository guarantees of the libvirt Molecule scenarios (FREES-61, ADR 0009).

- ``tools/molecule/fetch-cloud-images.sh`` downloads only from the pinned vendor hosts over
  HTTPS, checks every file against its pinned SHA-256, checks the vendor's signature on the
  checksum file with a key of the pinned fingerprint and requires that the signed file lists
  the pinned digest. It refuses malformed pins before downloading anything. The tests run it
  with a fake ``curl`` that serves local files and a throw-away signing key.
- The pins name one image and one signed listing per platform of ``versions.yml``.
- Both libvirt scenarios use the SSH options that the guard expects, with host key checking
  on, and differ only in their platform and name.
- CI runs every scenario of each driver and the libvirt self-test, and ``ci-gate`` needs
  the libvirt job.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import molecule_matrix as matrix

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MOLECULE = REPOSITORY_ROOT / "extensions" / "molecule"
PINS = MOLECULE / "shared" / "images" / "cloud-images.pins"
FETCH = REPOSITORY_ROOT / "tools" / "molecule" / "fetch-cloud-images.sh"
LIBVIRT_VARS = MOLECULE / "shared" / "vars" / "libvirt.yml"
VERSIONS = MOLECULE / "shared" / "vars" / "versions.yml"
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
TIMEOUT_SECONDS = 120
KNOWN_HOSTS = (
    "{{ lookup('ansible.builtin.env', 'MOLECULE_EPHEMERAL_DIRECTORY') }}/libvirt/known_hosts"
)
UBUNTU_HOST = "https://cloud-images.ubuntu.com/releases/noble/release-1/"
ARCHIVE_HOST = "https://archive.ubuntu.com/ubuntu/pool/universe/o/openscap/"
IMAGE_NAME = "image.img"
PACKAGE_NAME = "openscap-scanner_1_amd64.deb"


def load(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def executable(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is required"
    return path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Vendor:
    """A fake vendor: files served by a fake curl and a throw-away signing key."""

    def __init__(self, root: Path) -> None:
        """Create the served directory, the fake curl and a signing key below ``root``."""
        self.root = root
        self.served = root / "served"
        self.served.mkdir()
        self.routes: dict[str, Path] = {}
        self.served_count = 0
        self.gnupg = root / "gnupg"
        self.gnupg.mkdir(mode=0o700)
        self.bin = root / "bin"
        self.bin.mkdir()
        curl = self.bin / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'output=""\n'
            'url=""\n'
            "while [[ $# -gt 0 ]]; do\n"
            '  case "$1" in\n'
            '    --output) output="$2"; shift 2 ;;\n'
            "    --max-filesize|--proto|--proto-redir|--retry|--connect-timeout|--max-time)"
            " shift 2 ;;\n"
            "    -*) shift ;;\n"
            '    *) url="$1"; shift ;;\n'
            "  esac\n"
            "done\n"
            'printf "%s\\n" "${url}" >> "${FAKE_CURL_LOG}"\n'
            'source_file="$(awk -v url="${url}" \'$1 == url { print $2 }\' \\\n'
            '  "${FAKE_CURL_ROUTES}")"\n'
            '[[ -n "${source_file}" ]] || exit 22\n'
            'cp "${source_file}" "${output}"\n',
            encoding="utf-8",
        )
        curl.chmod(0o755)
        self.gpg(
            "--quick-generate-key", "FreeSecDev test <test@example.invalid>", "ed25519", "sign"
        )
        listing = self.gpg("--with-colons", "--list-keys").stdout
        self.fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        )
        self.key = self.gpg("--armor", "--export", self.fingerprint).stdout

    def gpg(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        """Run gpg with the vendor's private key ring."""
        return subprocess.run(
            [
                executable("gpg"),
                "--batch",
                "--no-options",
                "--homedir",
                str(self.gnupg),
                "--passphrase",
                "",
                "--pinentry-mode",
                "loopback",
                *arguments,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )

    def serve(self, url: str, data: bytes) -> Path:
        """Serve ``data`` at ``url`` and return the served file."""
        self.served_count += 1
        path = self.served / f"file-{self.served_count}"
        path.write_bytes(data)
        self.routes[url] = path
        return path

    def sign(self, path: Path) -> bytes:
        """Return a detached armored signature of ``path``."""
        signature = path.with_suffix(".sig")
        self.gpg("--armor", "--output", str(signature), "--detach-sign", str(path))
        return signature.read_bytes()

    def run(self, pins: Path, cache: Path, *platforms: str) -> subprocess.CompletedProcess[str]:
        """Run the fetch script against the fake vendor."""
        routes = self.root / "routes"
        routes.write_text(
            "".join(f"{url} {path}\n" for url, path in self.routes.items()), encoding="utf-8"
        )
        environment = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.root),
            "FAKE_CURL_ROUTES": str(routes),
            "FAKE_CURL_LOG": str(self.root / "requests"),
        }
        return subprocess.run(
            [executable("bash"), str(FETCH), str(pins), str(cache), *platforms],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            env=environment,
            cwd=self.root,
        )

    def requests(self) -> list[str]:
        """Return the URLs that the fake curl was asked for."""
        log = self.root / "requests"
        return log.read_text(encoding="utf-8").split() if log.exists() else []


@pytest.fixture(scope="module")
def vendor_key(tmp_path_factory: pytest.TempPathFactory) -> Vendor:
    return Vendor(tmp_path_factory.mktemp("vendor"))


class Release:
    """A pinned release served by a fake vendor, with one image and one package."""

    def __init__(self, vendor: Vendor, root: Path) -> None:
        """Serve a valid release of ``vendor`` and write its pins below ``root``."""
        self.vendor = vendor
        self.root = root
        self.image = b"qcow2 image"
        self.package = b"debian package"
        self.image_sha = sha256(self.image)
        self.package_sha = sha256(self.package)
        self.vendor.routes.clear()
        vendor.serve(UBUNTU_HOST + IMAGE_NAME, self.image)
        checksums = vendor.serve(
            UBUNTU_HOST + "SHA256SUMS",
            f"{self.image_sha} *{IMAGE_NAME}\n{'0' * 64} *other.img\n".encode(),
        )
        vendor.serve(UBUNTU_HOST + "SHA256SUMS.gpg", vendor.sign(checksums))
        vendor.serve(ARCHIVE_HOST + PACKAGE_NAME, self.package)
        self.directory = root / "pins"
        (self.directory / "keys").mkdir(parents=True)
        (self.directory / "keys" / "vendor.asc").write_text(vendor.key, encoding="utf-8")
        self.lines = {
            "image": (
                f"image ubuntu {IMAGE_NAME} {UBUNTU_HOST}{IMAGE_NAME} {self.image_sha} "
                f"{len(self.image)}"
            ),
            "listing": (
                f"listing ubuntu {UBUNTU_HOST}SHA256SUMS {UBUNTU_HOST}SHA256SUMS.gpg "
                f"keys/vendor.asc {vendor.fingerprint}"
            ),
            "package": (
                f"package ubuntu {ARCHIVE_HOST}{PACKAGE_NAME} {self.package_sha} "
                f"{len(self.package)}"
            ),
        }
        self.cache = root / "cache"

    def pins(self, **overrides: str) -> Path:
        """Write the pins with some lines replaced or, given an empty string, left out."""
        lines = [overrides.get(kind, line) for kind, line in self.lines.items()]
        path = self.directory / "cloud-images.pins"
        path.write_text("".join(f"{line}\n" for line in lines if line), encoding="utf-8")
        return path

    def run(self, *platforms: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        """Fetch the release with the given pin overrides."""
        return self.vendor.run(self.pins(**overrides), self.cache, *platforms)


@pytest.fixture
def release(vendor_key: Vendor, tmp_path: Path) -> Release:
    log = vendor_key.root / "requests"
    if log.exists():
        log.unlink()
    return Release(vendor_key, tmp_path)


def test_a_valid_release_is_fetched_verified_and_reused(release: Release) -> None:
    first = release.run()
    assert first.returncode == 0, first.stderr
    assert "lists the pinned SHA-256 of image.img" in first.stdout
    image = release.cache / "images" / f"{release.image_sha}.qcow2"
    package = release.cache / "packages" / "ubuntu" / PACKAGE_NAME
    assert image.read_bytes() == release.image
    assert package.read_bytes() == release.package
    second = release.run("ubuntu")
    assert second.returncode == 0, second.stderr
    assert "reusing the verified" in second.stdout


def test_a_cached_file_that_no_longer_matches_is_downloaded_again(release: Release) -> None:
    assert release.run().returncode == 0
    image = release.cache / "images" / f"{release.image_sha}.qcow2"
    image.write_bytes(b"tampered")
    result = release.run()
    assert result.returncode == 0, result.stderr
    assert image.read_bytes() == release.image


def test_another_platform_fetches_nothing_and_fails(release: Release) -> None:
    result = release.run("rhel_compatible")
    assert result.returncode == 2
    assert "no image of the requested platforms" in result.stderr
    assert release.vendor.requests() == []


def test_a_download_that_does_not_match_its_pin_is_refused(release: Release) -> None:
    release.vendor.serve(UBUNTU_HOST + IMAGE_NAME, b"another image")
    result = release.run()
    assert result.returncode == 1
    assert "does not match the pinned SHA-256" in result.stderr
    assert not (release.cache / "images" / f"{release.image_sha}.qcow2").exists()


def test_a_listing_with_a_bad_signature_is_refused(release: Release) -> None:
    release.vendor.serve(UBUNTU_HOST + "SHA256SUMS.gpg", b"not a signature")
    result = release.run()
    assert result.returncode == 1
    assert "does not verify" in result.stderr


def test_a_listing_signed_for_other_content_is_refused(release: Release) -> None:
    other = release.vendor.serve(UBUNTU_HOST + "OTHER", b"other content\n")
    release.vendor.serve(UBUNTU_HOST + "SHA256SUMS.gpg", release.vendor.sign(other))
    result = release.run()
    assert result.returncode == 1
    assert "does not verify" in result.stderr


def test_a_signed_listing_without_the_pinned_digest_is_refused(release: Release) -> None:
    checksums = release.vendor.serve(
        UBUNTU_HOST + "SHA256SUMS", f"{'1' * 64} *image.img\n".encode()
    )
    release.vendor.serve(UBUNTU_HOST + "SHA256SUMS.gpg", release.vendor.sign(checksums))
    result = release.run()
    assert result.returncode == 1
    assert f"lists {'1' * 64} for image.img" in result.stderr


def test_a_rocky_style_listing_is_understood(release: Release) -> None:
    checksums = release.vendor.serve(
        UBUNTU_HOST + "SHA256SUMS",
        f"# {IMAGE_NAME}: 11 bytes\nSHA256 ({IMAGE_NAME}) = {release.image_sha}\n".encode(),
    )
    release.vendor.serve(UBUNTU_HOST + "SHA256SUMS.gpg", release.vendor.sign(checksums))
    result = release.run()
    assert result.returncode == 0, result.stderr


def test_a_key_with_another_fingerprint_is_refused(release: Release) -> None:
    listing = release.lines["listing"].replace(release.vendor.fingerprint, "A" * 40)
    result = release.run(listing=listing)
    assert result.returncode == 1
    assert f"must hold exactly the key {'A' * 40}" in result.stderr


def test_an_image_without_a_signed_listing_is_refused(release: Release) -> None:
    result = release.run(listing="")
    assert result.returncode == 1
    assert "has no signed checksum listing" in result.stderr


def test_a_missing_pins_file_is_refused(release: Release) -> None:
    result = release.vendor.run(release.directory / "missing.pins", release.cache)
    assert result.returncode == 2
    assert "is not a regular file" in result.stderr


def with_field(line: str, index: int, value: str) -> str:
    fields = line.split()
    fields[index] = value
    return " ".join(fields)


@pytest.mark.parametrize(
    ("kind", "index", "value", "message"),
    [
        ("image", 3, "https://example.org/image.img", "is not an HTTPS URL of a pinned vendor"),
        ("image", 3, UBUNTU_HOST.replace("https", "http") + IMAGE_NAME, "is not an HTTPS URL"),
        ("package", 2, "https://example.org/x.deb", "is not an HTTPS URL of a pinned vendor"),
        ("listing", 3, UBUNTU_HOST + "SHA256SUMS.gpg?x=1", "is not an HTTPS URL of a pinned"),
        ("image", 1, "Ubuntu", "names an invalid platform"),
        ("image", 2, "../image.img", "is not a plain file name"),
        ("image", 5, "11 extra", "too many fields"),
        ("image", 5, "eleven", "the size of the ubuntu image is not a bound"),
        ("image", 5, "4294967296", "the size of the ubuntu image is not a bound"),
        ("package", 4, "lots", "is not a bound"),
        ("image", 2, "other.img", "does not end in other.img"),
        ("listing", 4, "../vendor.asc", "must be a file below keys/"),
        ("listing", 4, "keys/absent.asc", "is missing"),
        ("package", 0, "mirror", "unknown line kind mirror"),
    ],
)
def test_malformed_pins_are_refused(
    release: Release, kind: str, index: int, value: str, message: str
) -> None:
    result = release.run(**{kind: with_field(release.lines[kind], index, value)})
    assert result.returncode in {1, 2}
    assert message in result.stderr


def test_a_digest_that_is_not_lower_case_hex_is_refused(release: Release) -> None:
    line = release.lines["image"].replace(release.image_sha, release.image_sha.upper())
    result = release.run(image=line)
    assert result.returncode == 2
    assert "is not 64 lower-case hex digits" in result.stderr


def test_a_fingerprint_that_is_not_upper_case_hex_is_refused(release: Release) -> None:
    listing = release.lines["listing"].replace(
        release.vendor.fingerprint, release.vendor.fingerprint.lower()
    )
    result = release.run(listing=listing)
    assert result.returncode == 2
    assert "is not 40 upper-case hex digits" in result.stderr


def test_a_listing_before_its_image_is_refused(release: Release) -> None:
    pins = release.directory / "cloud-images.pins"
    pins.write_text(release.lines["listing"] + "\n" + release.lines["image"] + "\n", "utf-8")
    result = release.vendor.run(pins, release.cache)
    assert result.returncode == 2
    assert "must follow its image line" in result.stderr


def repository_pins() -> list[list[str]]:
    return [line.split() for line in PINS.read_text(encoding="utf-8").splitlines() if line]


def test_every_platform_has_one_image_and_one_signed_listing() -> None:
    images = cast("dict[str, object]", load(VERSIONS)["molecule_images"])
    pins = repository_pins()
    for platform in images:
        kinds = [line[0] for line in pins if line[1] == platform]
        assert kinds.count("image") == 1, platform
        assert kinds.count("listing") == 1, platform
        assert kinds.count("package") > 0, platform
        assert kinds.index("listing") == kinds.index("image") + 1, platform
    assert {line[1] for line in pins} == set(images)


def test_the_repository_pins_are_well_formed() -> None:
    for line in repository_pins():
        if line[0] == "image":
            assert len(line) == 6
            assert line[3].startswith("https://")
            assert line[3].endswith("/" + line[2])
            assert len(line[4]) == 64
        elif line[0] == "listing":
            assert len(line) == 6
            assert (PINS.parent / line[4]).is_file()
            assert len(line[5]) == 40
        else:
            assert line[0] == "package"
            assert len(line) == 5
            assert len(line[3]) == 64


def libvirt_scenarios() -> list[Path]:
    return sorted(MOLECULE.glob("libvirt-*/molecule.yml"))


def test_the_libvirt_scenarios_use_the_ssh_options_that_the_guard_expects() -> None:
    expected = [
        option.replace("@KNOWN_HOSTS@", KNOWN_HOSTS)
        for option in cast("list[str]", load(LIBVIRT_VARS)["molecule_libvirt_ssh_options"])
    ]
    assert len(libvirt_scenarios()) == 4
    for path in libvirt_scenarios():
        config = load(path)
        driver = cast("dict[str, object]", config["driver"])
        assert driver["ssh_connection_options"] == expected, path
        ansible = cast("dict[str, dict[str, dict[str, object]]]", config["ansible"])
        assert ansible["cfg"]["defaults"]["host_key_checking"] is True, path


BASE_SEQUENCE = ["create", "prepare", "converge", "idempotence", "verify", "destroy"]
LIFECYCLE_SEQUENCE = ["create", "prepare", "side_effect", "destroy"]


def test_the_libvirt_scenarios_differ_only_in_their_platform_name_and_steps() -> None:
    kinds: dict[bool, list[dict[str, object]]] = {True: [], False: []}
    for path in libvirt_scenarios():
        config = load(path)
        scenario = cast("dict[str, object]", config["scenario"])
        assert scenario["name"] == path.parent.name
        playbooks = cast("dict[str, dict[str, str]]", config["ansible"])["playbooks"]
        assert playbooks["create"] == "../shared/create_libvirt.yml"
        assert playbooks["destroy"] == "../shared/destroy_libvirt.yml"
        lifecycle = path.parent.name.endswith(matrix.SCENARIO_SUFFIX)
        if lifecycle:
            assert scenario["test_sequence"] == LIFECYCLE_SEQUENCE, path
            assert playbooks["side_effect"] == "../shared/lifecycle.yml", path
            assert "converge" not in playbooks, path
            assert (
                path.parent.parent / path.parent.name.removesuffix(matrix.SCENARIO_SUFFIX)
            ).is_dir()
        else:
            assert scenario["test_sequence"] == BASE_SEQUENCE, path
            assert playbooks["converge"] == "../shared/converge_libvirt.yml", path
            assert playbooks["verify"] == "../shared/verify_libvirt.yml", path
            assert "side_effect" not in playbooks, path
        for key in ("converge", "verify", "side_effect"):
            playbooks.pop(key, None)
        config.pop("platforms")
        scenario.pop("name")
        scenario.pop("test_sequence")
        kinds[lifecycle].append(config)
    configs = kinds[True] + kinds[False]
    assert len(kinds[True]) == len(kinds[False]) == 2
    assert all(config == configs[0] for config in configs)


def ci_jobs() -> dict[str, dict[str, object]]:
    return cast("dict[str, dict[str, object]]", load(CI_WORKFLOW)["jobs"])


def test_ci_runs_every_scenario_of_each_driver_and_gates_on_it() -> None:
    jobs = ci_jobs()
    docker = cast("dict[str, dict[str, list[str]]]", jobs["molecule-docker"]["strategy"])
    libvirt = cast("dict[str, dict[str, str]]", jobs["molecule-libvirt"]["strategy"])
    docker_scenarios = {path.parent.name for path in MOLECULE.glob("docker-*/molecule.yml")}
    assert set(docker["matrix"]["scenario"]) == docker_scenarios | {"docker-selftest"}
    assert libvirt["matrix"] == "${{ fromJSON(needs.molecule-plan.outputs.libvirt) }}"
    assert jobs["molecule-libvirt"]["needs"] == "molecule-plan"
    plan = cast("list[dict[str, str]]", jobs["molecule-plan"]["steps"])
    assert any(
        "make -s molecule-matrix MOLECULE_MATRIX_DRIVER=libvirt" in step.get("run", "")
        for step in plan
    )
    included = matrix.legs(REPOSITORY_ROOT, "libvirt")
    assert {entry["scenario"] for entry in included} == {
        path.parent.name for path in libvirt_scenarios()
    } | {"libvirt-selftest"}
    for entry in included:
        if entry["scenario"] != "libvirt-selftest":
            images = {
                cast("dict[str, str]", platform)["image"]
                for platform in cast(
                    "list[object]", load(MOLECULE / entry["scenario"] / "molecule.yml")["platforms"]
                )
            }
            assert images == {entry["platform"]}
    needs = cast("list[str]", jobs["ci-gate"]["needs"])
    assert {"molecule-plan", "molecule-libvirt"} <= set(needs)
    assert jobs["molecule-libvirt"]["permissions"] == {"contents": "read"}
    assert jobs["molecule-plan"]["permissions"] == {"contents": "read"}


def test_the_makefile_runs_every_libvirt_scenario() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    line = next(
        line for line in text.splitlines() if line.startswith("MOLECULE_LIBVIRT_SCENARIOS :=")
    )
    assert set(line.split(":=")[1].split()) == {path.parent.name for path in libvirt_scenarios()}


def test_the_cloud_image_cache_is_ignored_by_git() -> None:
    result = subprocess.run(
        [
            executable("git"),
            "-C",
            str(REPOSITORY_ROOT),
            "check-ignore",
            "-q",
            "build/molecule-libvirt",
        ],
        check=False,
        timeout=TIMEOUT_SECONDS,
        env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
    )
    assert result.returncode == 0
