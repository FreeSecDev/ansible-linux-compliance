"""Drive SCC inside the CI-only SCC image for the integration and egress tests.

The host-side tests start the image with the repository mounted read-only and
run this script with a standalone Python that is mounted too, because the image
has none. It prints one JSON document; the tests on the host decide.

Commands:

- ``scan``: record the SHA-256 of every file below ``/opt/scc`` and ``/root``,
  run the real ``compliance_scan`` module file with ``backend: scc`` (for real,
  then in check mode) exactly as Ansible runs it on a managed host, record the
  state again and report both results and every added, removed or changed path.
  It then exports the real run's STIG Viewer checklists with the reporting command
  (FREES-147), once with SCC's own XCCDF results and once with the pinned stream as
  content, and reports what ``checklist_check.py`` reads back. The checklists stay
  in the container.
- ``install``: install a stream with SCC's own installer. This is test set-up
  only, in a throwaway container: the backend never installs content.
- ``positive``: the positive control of the egress test. It builds the per-run
  options with the backend's own functions, sets ``downloadExternalFiles`` to
  ``1``, runs ``cscc`` in the backend's scan form and reports whether the
  backend's confirmation accepts SCC's debug log (it must not).
- ``off-platform``: in the Ubuntu 26.04 image (FREES-161):
  - run the module for a 26.04 host without the opt-in (it must be refused);
  - run the module for a host that claims 24.04 (``/etc/os-release`` refuses it);
  - run the module with ``allow_off_platform_benchmark``;
  - run the SCC backend itself, below the module's release check, for a host
    self-asserted as 24.04, so that only SCC's own CPE platform test can stop it.

  It reports every result, the outcomes in the kept XCCDF copy, whether SCC's logs
  say that it ignored the platform test (opted in) or rejected the stream by it
  (backstop), the ``VERSION_ID`` of the image, the state changes below
  ``/opt/scc`` and ``/root`` and the read-back of the marked run's checklists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    model,
    openscap,
    scanner,
    scc,
)

WATCHED = ("/opt/scc", "/root")
MODULE_TIMEOUT_SECONDS = 3300
SCC_TIMEOUT_SECONDS = 1800
CHUNK = 1024 * 1024
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SCC = "/opt/scc/cscc"
INSTALLED_OPTIONS = "/opt/scc/options.xml"
DOWNLOAD_OFF = "<downloadExternalFiles>0</downloadExternalFiles>"
DOWNLOAD_ON = "<downloadExternalFiles>1</downloadExternalFiles>"
PROFILE = "xccdf_mil.disa.stig_profile_MAC-1_Classified"
OS_RELEASE = Path("/etc/os-release")
IGNORED_PLATFORM_TEST = "Ignoring CPE-OVAL Results and continuing scanning"
REJECTED_BY_PLATFORM_TEST = "is not applicable to this target system"
BACKSTOP_ROOT = Path("/root/backstop")
MAX_RESULTS_BYTES = 128 * 1024 * 1024
EXPORT_TIMEOUT_SECONDS = 600
CHECKLIST_CHECK = "tests/system/scc/checklist_check.py"


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(roots: tuple[str, ...]) -> dict[str, str]:
    """Return a digest or a type marker for every path below ``roots``."""
    state: dict[str, str] = {}
    for root in roots:
        for directory, names, files in os.walk(root):
            state[directory] = "directory"
            for name in [*names, *files]:
                path = Path(directory) / name
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    state[str(path)] = f"symlink:{path.readlink()}"
                elif stat.S_ISREG(mode):
                    state[str(path)] = _digest(path)
    return state


def difference(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    """Return the added, removed and changed paths."""
    common = before.keys() & after.keys()
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(path for path in common if before[path] != after[path]),
    }


def run_module(module: Path, arguments: dict[str, object], python_path: str) -> dict[str, object]:
    """Run the module file with ``arguments`` and return its JSON result."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump({"ANSIBLE_MODULE_ARGS": arguments}, handle)
    try:
        completed = subprocess.run(
            [sys.executable, str(module), handle.name],
            check=False,
            capture_output=True,
            text=True,
            timeout=MODULE_TIMEOUT_SECONDS,
            env={"PATH": SAFE_PATH, "PYTHONPATH": python_path, "LANG": "C"},
        )
    finally:
        Path(handle.name).unlink()
    parsed: object = json.loads(completed.stdout)
    if not isinstance(parsed, dict):
        message = "the module did not print a JSON object"
        raise TypeError(message)
    result = cast("dict[str, object]", parsed)
    result["_returncode"] = completed.returncode
    return result


def module_arguments(options: argparse.Namespace) -> dict[str, object]:
    """Return the module arguments for a scan of ``options.content``."""
    return {
        "backend": "scc",
        "content_path": options.content,
        "expected_sha256": options.sha256,
        "profile_id": PROFILE,
        "host": {
            "hostname": "scc-integration",
            "distribution_id": "ubuntu",
            "distribution_version": "24.04",
            "architecture": "x86_64",
        },
        "output_dir": options.output_dir,
        "fail_on_incomplete": False,
    }


def _reporting_environment(options: argparse.Namespace) -> dict[str, str]:
    paths = (options.repository / "build" / "collections", options.repository)
    python_path = ":".join([*(str(path) for path in paths), options.site_packages])
    return {
        "PATH": SAFE_PATH,
        "PYTHONPATH": python_path,
        "LANG": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _run_python(
    options: argparse.Namespace, arguments: list[str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=EXPORT_TIMEOUT_SECONDS,
        cwd=options.repository,
        env=_reporting_environment(options),
    )


def export_checklists(
    options: argparse.Namespace, run_directory: Path, content: Path
) -> dict[str, object]:
    """Export the checklists of a real run with the reporting command and read them back."""
    target = Path(tempfile.mkdtemp(prefix="checklists-")) / "out"
    scan_run = run_directory / "scan-run.json"
    command = ["-m", "tools.reporting", "--scope", "single_host"]
    command += ["--output", str(target.parent / "report.json"), "--scan-run", str(scan_run)]
    command += ["--checklist-content", str(content)]
    command += ["--export-ckl", str(target), "--export-cklb", str(target)]
    exported = _run_python(options, command)
    report: dict[str, object] = {
        "returncode": exported.returncode,
        "stderr": exported.stderr[-2000:],
    }
    if exported.returncode != 0:
        return report
    check = str(options.repository / CHECKLIST_CHECK)
    checked = _run_python(options, ["-s", check, str(target), str(scan_run)])
    report["check_returncode"] = checked.returncode
    report["check_stderr"] = checked.stderr[-2000:]
    if checked.returncode == 0:
        report.update(cast("dict[str, object]", json.loads(checked.stdout)))
    return report


def scan(options: argparse.Namespace) -> dict[str, object]:
    """Run a real scan and a check-mode scan through the module."""
    module = options.repository / "plugins" / "modules" / "compliance_scan.py"
    python_path = f"{options.repository / 'build' / 'collections'}:{options.site_packages}"
    arguments = module_arguments(options)
    before = snapshot(WATCHED)
    real = run_module(module, {**arguments, "run_id": "real"}, python_path)
    preview = run_module(
        module, {**arguments, "_ansible_check_mode": True, "run_id": "check"}, python_path
    )
    after = snapshot(WATCHED)
    run_directory = Path(options.output_dir) / "real"
    results = run_directory / "scan" / scc.RESULTS_FILE_NAME
    checklists = {
        "results": export_checklists(options, run_directory, results),
        "stream": export_checklists(options, run_directory, Path(options.content)),
    }
    return {
        "scan": real,
        "check_mode": preview,
        "state": difference(before, after),
        "checklists": checklists,
    }


def install(options: argparse.Namespace) -> dict[str, object]:
    """Install a stream with SCC's own installer (test set-up only)."""
    completed = subprocess.run(
        [SCC, "-is", options.content],
        check=False,
        capture_output=True,
        text=True,
        timeout=SCC_TIMEOUT_SECONDS,
        stdin=subprocess.DEVNULL,
        cwd="/opt/scc",
        env={"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C", "TZ": "UTC0"},
    )
    return {"returncode": completed.returncode, "installed": Path(options.content).name}


def positive(options: argparse.Namespace) -> dict[str, object]:
    """Run the backend's scan form with ``downloadExternalFiles`` set to 1."""

    record = scc.read_installed_content(INSTALLED_OPTIONS, Path(options.content).name)
    document = scc.options_document(record, PROFILE)
    if document.count(DOWNLOAD_OFF) != 1:
        message = "the per-run options do not set downloadExternalFiles exactly once"
        raise ValueError(message)
    work = Path(tempfile.mkdtemp(prefix="positive-", dir="/root"))
    user = work / "user"
    user.mkdir(mode=0o700)
    path = work / "options.xml"
    path.write_text(document.replace(DOWNLOAD_OFF, DOWNLOAD_ON), encoding="utf-8")
    path.chmod(0o600)
    completed = subprocess.run(
        [SCC, "-o", str(path), "-u", str(user), "-q", "-d"],
        check=False,
        capture_output=True,
        text=True,
        timeout=SCC_TIMEOUT_SECONDS,
        stdin=subprocess.DEVNULL,
        env={"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C", "TZ": "UTC0"},
    )
    logs = sorted((user / "ApplicationLogs").glob("*_Debug_Log_001.txt"))
    refusal = "no application debug log"
    if len(logs) == 1:
        try:
            scc.confirm_options(logs[0].read_text(encoding="utf-8", errors="replace"), str(path))
            refusal = ""
        except scc.OptionsConfirmationError as error:
            refusal = str(error)
    results = sorted(user.glob("Sessions/*/Results/SCAP/XML/*_XCCDF-Results_*.xml"))
    return {"returncode": completed.returncode, "refusal": refusal, "results": len(results)}


def egress_scan(options: argparse.Namespace) -> dict[str, object]:
    """Run one real scan of the probe stream through the module."""
    module = options.repository / "plugins" / "modules" / "compliance_scan.py"
    python_path = f"{options.repository / 'build' / 'collections'}:{options.site_packages}"
    return run_module(module, {**module_arguments(options), "run_id": "egress"}, python_path)


def version_id() -> str:
    """Return ``VERSION_ID`` of ``/etc/os-release``."""
    for line in OS_RELEASE.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key == "VERSION_ID":
            return value.strip('"')
    return ""


def kept_outcomes(results: Path) -> dict[str, int]:
    """Return the count per outcome of SCC's kept XCCDF results, read with the hardened parser."""
    if not results.is_file():
        return {}
    parsed = openscap.read_results(str(results), MAX_RESULTS_BYTES, assume_utc=True)
    counts: dict[str, int] = {}
    for finding in parsed.findings:
        counts[finding.outcome.value] = counts.get(finding.outcome.value, 0) + 1
    return counts


def logged(scc_tree: Path, text: str) -> bool:
    """Return whether any log that SCC wrote below ``scc_tree`` contains ``text``."""
    return any(
        text in path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(scc_tree.rglob("*.txt"))
        if path.is_file()
    )


def backstop(content: str, digest: str) -> dict[str, object]:
    """Run the SCC backend for a host self-asserted as 24.04, without the opt-in."""
    BACKSTOP_ROOT.mkdir(mode=0o700)
    stream = catalog.vetted_content_path(content)
    benchmark = catalog.single_benchmark(catalog.read_benchmarks(stream, digest))
    rules = catalog.profile_rules(benchmark, catalog.find_profile(benchmark, PROFILE))
    settings = scanner.ScanSettings(
        str(Path(stream).parent), str(BACKSTOP_ROOT), SCC_TIMEOUT_SECONDS
    )
    request = scanner.ScanRequest(
        run_id="backstop",
        host=model.HostIdentity("scc-backstop", "ubuntu", "24.04", "x86_64", None),
        benchmark_id=benchmark.benchmark_id,
        profile_id=PROFILE,
        content_path=Path(stream).name,
        output_dir="scan",
        expected_rule_ids=tuple(rule.rule_id for rule in rules),
    )
    run = scc.create_backend(settings).audit(request)
    tree = BACKSTOP_ROOT / "scan" / "scc"
    return {
        "status": run.status.value,
        "error_message": run.error_message,
        "off_platform": run.off_platform is not None,
        "outcomes": sorted({finding.outcome.value for finding in run.findings}),
        "rejected_by_platform_test": logged(tree, REJECTED_BY_PLATFORM_TEST),
    }


def off_platform(options: argparse.Namespace) -> dict[str, object]:
    """Scan this Ubuntu 26.04 container with the 24.04 benchmark in every way it is gated."""
    module = options.repository / "plugins" / "modules" / "compliance_scan.py"
    python_path = f"{options.repository / 'build' / 'collections'}:{options.site_packages}"
    arguments = module_arguments(options)
    host = cast("dict[str, object]", arguments["host"])
    arguments["host"] = {**host, "hostname": "scc-off-platform", "distribution_version": "26.04"}
    refused = run_module(module, {**arguments, "run_id": "refused"}, python_path)
    claimed = {**arguments, "host": {**host, "hostname": "scc-claims-2404"}}
    mismatch = run_module(module, {**claimed, "run_id": "mismatch"}, python_path)
    before = snapshot(WATCHED)
    marked = run_module(
        module,
        {**arguments, "allow_off_platform_benchmark": True, "run_id": "off-platform"},
        python_path,
    )
    after = snapshot(WATCHED)
    scan_directory = Path(options.output_dir) / "off-platform" / "scan"
    return {
        "refused": refused,
        "mismatch": mismatch,
        "scan": marked,
        "kept_outcomes": kept_outcomes(scan_directory / scc.OFF_PLATFORM_RESULTS_FILE_NAME),
        "ignored_platform_test": logged(scan_directory / "scc", IGNORED_PLATFORM_TEST),
        "backstop": backstop(options.content, options.sha256),
        "version_id": version_id(),
        "state": difference(before, after),
        "checklists": export_checklists(
            options,
            Path(options.output_dir) / "off-platform",
            scan_directory / scc.OFF_PLATFORM_RESULTS_FILE_NAME,
        ),
    }


COMMANDS = {
    "scan": scan,
    "install": install,
    "positive": positive,
    "egress-scan": egress_scan,
    "off-platform": off_platform,
}


def main(argv: list[str]) -> int:
    """Run one command and print its report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--site-packages", default="")
    parser.add_argument("--content", required=True)
    parser.add_argument("--sha256", default="")
    parser.add_argument("--output-dir", default="/var/lib/freesecdev/linux_compliance/evidence")
    options = parser.parse_args(argv)
    report = COMMANDS[options.command](options)
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
