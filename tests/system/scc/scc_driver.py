"""Drive SCC inside the CI-only SCC image for the integration and egress tests.

The host-side tests start the image with the repository mounted read-only and
run this script with a standalone Python that is mounted too, because the image
has none. It prints one JSON document; the tests on the host decide.

Commands:

- ``scan``: record the SHA-256 of every file below ``/opt/scc`` and ``/root``,
  run the real ``compliance_scan`` module file with ``backend: scc`` (for real,
  then in check mode) exactly as Ansible runs it on a managed host, record the
  state again and report both results and every added, removed or changed path.
  Between the two snapshots it also runs a third scan, ``toggled``, with the topic
  ``ssh`` switched off (FREES-170): ``toggle_resolution.py`` maps the toggles to the
  DISA rules exactly as the audit role does, the module gets the resulting
  ``disabled_rules`` and ``control_placement``, and the report holds the resolution,
  the run and SCC's own kept result of every rule.
  It then exports the real run's STIG Viewer checklists with the reporting command
  (FREES-147), once with SCC's own XCCDF results and once with the pinned stream as
  content, and reports what ``checklist_check.py`` reads back. The checklists stay
  in the container. With ``--export-log`` it copies the real run's application
  debug log there for ``make scc-own-expiry-check`` (FREES-179), and the scan's UTC
  start from the log's name to the same path with ``.start`` appended, both owned by
  ``--export-owner`` with mode 0600, and reports which of SCC's logs of that run
  mention the software's expiry.
- ``install``: install a stream with SCC's own installer. This is test set-up
  only, in a throwaway container: the backend never installs content.
- ``negative``: the same run with the backend's own per-run options, so with
  ``downloadExternalFiles`` at ``0``. The module refuses the probe stream before SCC
  runs (it refers outside the datastream, FREES-191), so this shows SCC's own setting.
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
- ``oscap-scan``: in the CI-only OpenSCAP image (FREES-146), on the same pinned Ubuntu
  24.04 base as the SCC image: copy the pinned ComplianceAsCode stream into a root-owned
  directory and run the module with ``backend: openscap`` and the ComplianceAsCode STIG
  profile, for the same host name as the SCC scan.
- ``oscap-export``: in the SCC image, export the OpenSCAP run (``/work``, read-only) as
  CKL and CKLB through the STIG mapping with the DISA stream that SCC ships as
  ``--checklist-content``, read the files back with ``checklist_check.py mapped``, and
  compare the OpenSCAP run with the SCC run by DISA STIG rule (``--compare-stig``). Only
  counts leave the container; the checklists and the comparison stay in it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
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
STIG_MAPPING = "content/stig-mapping.json"
OSCAP_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
OSCAP_CONTENT_ROOT = Path("/root/content")
OSCAP_TIMEOUT_SECONDS = 3000
OSCAP_RUN_FILE = "oscap-scan-run.json"
SCC_RUN_FILE = "scc-scan-run.json"
TOGGLE_RESOLUTION = "tests/system/scc/toggle_resolution.py"
TOGGLED_TOPICS = {"linux_compliance_ssh_enabled": False}
APPLICATION_LOGS = "ApplicationLogs"
APPLICATION_LOG_PATTERN = "*_Debug_Log_001.txt"
EXPIRY_MENTION = "Software expires"
OWNER = re.compile(r"([0-9]{1,10}):([0-9]{1,10})")
LOG_START = re.compile(
    r"[A-Za-z0-9_.-]{1,160}_([0-9]{4}-[0-9]{2}-[0-9]{2})_([0-9]{2})([0-9]{2})([0-9]{2})"
    r"_Debug_Log_001\.txt"
)
START_SUFFIX = ".start"


def log_start(name: str) -> str | None:
    """Return the UTC start ``YYYY-MM-DDTHH:MM:SSZ`` that SCC put in its debug log's name.

    SCC names the log after the start of the scan in its process time zone, which
    the backend and this driver fix to UTC (``TZ=UTC0``).
    """
    match = LOG_START.fullmatch(name)
    if match is None:
        return None
    day, hours, minutes, seconds = match.groups()
    return f"{day}T{hours}:{minutes}:{seconds}Z"


def _write_owned(path: Path, owner: re.Match[str]) -> None:
    os.chown(path, int(owner.group(1)), int(owner.group(2)))
    path.chmod(0o600)


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


def kept_results(results: Path) -> dict[str, str]:
    """Return SCC's kept outcome of every rule, read with the hardened parser."""
    parsed = openscap.read_results(str(results), MAX_RESULTS_BYTES, assume_utc=True)
    return {finding.rule_id: finding.outcome.value for finding in parsed.findings}


def toggled_scan(options: argparse.Namespace, module: Path, python_path: str) -> dict[str, object]:
    """Scan with the ssh topic switched off, the toggles mapped as the audit role maps them."""
    resolver = str(options.repository / TOGGLE_RESOLUTION)
    arguments = [resolver, str(options.repository), options.content, options.sha256, PROFILE]
    resolved = _run_python(options, ["-s", *arguments, json.dumps(TOGGLED_TOPICS)])
    if resolved.returncode != 0:
        return {"resolver_stderr": resolved.stderr[-2000:], "scan": None}
    document = cast("dict[str, object]", json.loads(resolved.stdout))
    resolution = cast("dict[str, object]", document["resolution"])
    if resolution["errors"]:
        return {"resolution": resolution, "scan": None}
    toggled = run_module(
        module,
        {
            **module_arguments(options),
            "run_id": "toggled",
            "disabled_rules": resolution["disabled_rules"],
            "control_placement": resolution["control_placement"],
        },
        python_path,
    )
    results = Path(options.output_dir) / "toggled" / "scan" / scc.RESULTS_FILE_NAME
    return {
        "benchmark_version": document["benchmark_version"],
        "resolution": resolution,
        "scan": toggled,
        "kept": kept_results(results) if results.is_file() else {},
    }


def export_application_log(options: argparse.Namespace, run_directory: Path) -> dict[str, object]:
    """Copy the real run's debug log and its UTC start to ``--export-log`` and ``.start``.

    It also says which of SCC's logs of the run mention the software's expiry.
    """
    user = run_directory / "scan" / scc.WORK_DIRECTORY_NAME / scc.USER_DIRECTORY_NAME
    logs = sorted((user / APPLICATION_LOGS).glob(APPLICATION_LOG_PATTERN))
    mentions = sorted(
        str(path.relative_to(user))
        for path in user.rglob("*.txt")
        if path.is_file() and EXPIRY_MENTION in path.read_text(encoding="utf-8", errors="replace")
    )
    start = log_start(logs[0].name) if len(logs) == 1 else None
    report: dict[str, object] = {
        "application_logs": [str(path.relative_to(user)) for path in logs],
        "mentions": mentions,
        "start": start,
        "exported": False,
    }
    owner = OWNER.fullmatch(options.export_owner)
    if not options.export_log or start is None or owner is None:
        return report
    target = Path(options.export_log)
    shutil.copy2(logs[0], target)
    _write_owned(target, owner)
    start_file = target.with_name(target.name + START_SUFFIX)
    start_file.write_text(start + "\n", encoding="utf-8")
    _write_owned(start_file, owner)
    report["exported"] = True
    return report


def scan(options: argparse.Namespace) -> dict[str, object]:
    """Run a real scan, a check-mode scan and a scan with a topic switched off."""
    module = options.repository / "plugins" / "modules" / "compliance_scan.py"
    python_path = f"{options.repository / 'build' / 'collections'}:{options.site_packages}"
    arguments = module_arguments(options)
    before = snapshot(WATCHED)
    real = run_module(module, {**arguments, "run_id": "real"}, python_path)
    preview = run_module(
        module, {**arguments, "_ansible_check_mode": True, "run_id": "check"}, python_path
    )
    toggled = toggled_scan(options, module, python_path)
    after = snapshot(WATCHED)
    run_directory = Path(options.output_dir) / "real"
    results = run_directory / "scan" / scc.RESULTS_FILE_NAME
    expiry = export_application_log(options, run_directory)
    checklists = {
        "results": export_checklists(options, run_directory, results),
        "stream": export_checklists(options, run_directory, Path(options.content)),
    }
    return {
        "scan": real,
        "check_mode": preview,
        "toggled": toggled,
        "state": difference(before, after),
        "checklists": checklists,
        "expiry_log": expiry,
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
    return _direct(options, download=True)


def negative(options: argparse.Namespace) -> dict[str, object]:
    """Run the backend's scan form with the backend's own per-run options (downloads off).

    The module refuses the probe stream before SCC runs, because it refers to a component
    outside the datastream (FREES-191). This run gives SCC the stream anyway, so the egress
    test still shows that SCC's own download setting keeps it off the network (ADR 0019).
    """
    return _direct(options, download=False)


def _direct(options: argparse.Namespace, *, download: bool) -> dict[str, object]:
    record = scc.read_installed_content(INSTALLED_OPTIONS, Path(options.content).name)
    document = scc.options_document(record, PROFILE)
    if document.count(DOWNLOAD_OFF) != 1:
        message = "the per-run options do not set downloadExternalFiles exactly once"
        raise ValueError(message)
    work = Path(tempfile.mkdtemp(prefix="positive-" if download else "negative-", dir="/root"))
    user = work / "user"
    user.mkdir(mode=0o700)
    path = work / "options.xml"
    path.write_text(
        document.replace(DOWNLOAD_OFF, DOWNLOAD_ON) if download else document, encoding="utf-8"
    )
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


def oscap_scan(options: argparse.Namespace) -> dict[str, object]:
    """Scan this container with the ComplianceAsCode STIG profile through the module."""
    OSCAP_CONTENT_ROOT.mkdir(mode=0o755)
    stream = OSCAP_CONTENT_ROOT / Path(options.content).name
    shutil.copyfile(options.content, stream)
    stream.chmod(0o644)
    module = options.repository / "plugins" / "modules" / "compliance_scan.py"
    python_path = f"{options.repository / 'build' / 'collections'}:{options.site_packages}"
    arguments = {
        **module_arguments(options),
        "backend": "openscap",
        "content_path": str(stream),
        "profile_id": OSCAP_PROFILE,
        "scan_timeout": OSCAP_TIMEOUT_SECONDS,
        "run_id": "oscap",
    }
    return {"scan": run_module(module, arguments, python_path)}


def _comparison_summary(path: Path) -> dict[str, object]:
    document = cast("dict[str, object]", json.loads(path.read_text(encoding="utf-8")))
    pairs = cast("list[dict[str, object]]", document["comparisons"])
    summary: dict[str, object] = {"comparisons": len(pairs)}
    if len(pairs) == 1:
        pair = pairs[0]
        differences = cast("list[dict[str, str]]", pair["disagreements"])
        by_pair: dict[str, int] = {}
        for item in differences:
            key = f"{item['disa']}/{item['compliance_as_code']}"
            by_pair[key] = by_pair.get(key, 0) + 1
        summary.update(
            {
                "host": pair["host"],
                "rules": pair["rules"],
                "agree": pair["agree"],
                "disagree": pair["disagree"],
                "statuses": pair["statuses"],
                "disagreements_by_status": by_pair,
                "mode": stat.S_IMODE(path.stat().st_mode),
            }
        )
    return summary


def oscap_export(options: argparse.Namespace) -> dict[str, object]:
    """Export a real OpenSCAP STIG run through the mapping and compare it with the SCC run."""
    work = Path(options.work)
    oscap_run = work / OSCAP_RUN_FILE
    scc_run = work / SCC_RUN_FILE
    target = Path(tempfile.mkdtemp(prefix="checklists-")) / "out"
    command = ["-m", "tools.reporting", "--scope", "single_host"]
    command += ["--output", str(target.parent / "report.json"), "--scan-run", str(oscap_run)]
    command += ["--checklist-content", options.content]
    command += ["--export-ckl", str(target), "--export-cklb", str(target)]
    exported = _run_python(options, command)
    report: dict[str, object] = {
        "returncode": exported.returncode,
        "stderr": exported.stderr[-2000:],
    }
    if exported.returncode == 0:
        mapping = str(options.repository / STIG_MAPPING)
        check = str(options.repository / CHECKLIST_CHECK)
        checked = _run_python(
            options, ["-s", check, "mapped", str(target), str(oscap_run), mapping]
        )
        report["check_returncode"] = checked.returncode
        report["check_stderr"] = checked.stderr[-2000:]
        if checked.returncode == 0:
            report.update(cast("dict[str, object]", json.loads(checked.stdout)))
    comparison = target.parent / "comparison" / "stig-comparison.json"
    command = ["-m", "tools.reporting", "--scope", "single_host"]
    command += ["--output", str(target.parent / "compare-report.json")]
    command += ["--scan-run", str(scc_run), "--scan-run", str(oscap_run)]
    command += ["--checklist-content", options.content, "--compare-stig", str(comparison)]
    compared = _run_python(options, command)
    result: dict[str, object] = {
        "returncode": compared.returncode,
        "stderr": compared.stderr[-2000:],
    }
    if compared.returncode == 0:
        result.update(_comparison_summary(comparison))
    report["comparison"] = result
    return report


COMMANDS = {
    "scan": scan,
    "install": install,
    "positive": positive,
    "negative": negative,
    "egress-scan": egress_scan,
    "off-platform": off_platform,
    "oscap-scan": oscap_scan,
    "oscap-export": oscap_export,
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
    parser.add_argument("--work", default="/work")
    parser.add_argument("--export-log", default="")
    parser.add_argument("--export-owner", default="")
    options = parser.parse_args(argv)
    report = COMMANDS[options.command](options)
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
