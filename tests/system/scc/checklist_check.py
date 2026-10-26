"""Read back the checklists of a real scan inside the SCC image (FREES-147, FREES-146).

``scc_driver.py`` runs the reporting command on the scan run of a real scan and then
this script on the directory it wrote. The script reads the CKL and CKLB files with
the exporter's strict readers, derives the expected status of every finding from the
scan run with the table of ADR 0020, written out again here so that the exporter's
own mapping is not checked against itself, and prints one JSON document of counts and
mismatches. No checklist text leaves the container: the files stay in its throwaway
file system and are never collected or committed.

With ``mapped`` first, the scan run is a ComplianceAsCode run exported through the STIG
mapping (FREES-146). The script reads the mapping file as plain JSON, and for every
checklist entry takes the ComplianceAsCode rules that the mapping lists for the entry's
``Rule_Ver`` and aggregates their expected statuses with the rule of the ADR 0020
amendment, written out again here: any Open is Open, one status shared by every check is
that status, anything else and no check at all is Not Reviewed.
"""

from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path
from typing import cast

from defusedxml.ElementTree import fromstring

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import checklist_formats

RULE = re.compile(r"xccdf_mil\.disa\.stig_rule_(SV-[0-9]+r[0-9]+_rule)")
VULN_NUMBER = re.compile(r"V-[0-9]+")
CKLB_NAMES = {
    "NotAFinding": "not_a_finding",
    "Open": "open",
    "Not_Applicable": "not_applicable",
    "Not_Reviewed": "not_reviewed",
}


def expected_status(run: model.ScanRun, finding: model.Finding) -> str:
    """Return the CKL status that ADR 0020 gives ``finding`` of ``run``."""
    if run.off_platform is not None or finding.off_platform is not None:
        return "Not_Reviewed"
    if run.status is not model.ScanStatus.COMPLETED:
        return "Not_Reviewed"
    if finding.outcome is model.Outcome.PASS and model.ResultFlag.FIXED not in finding.flags:
        return "NotAFinding"
    if finding.outcome in (model.Outcome.FAIL, model.Outcome.WAIVED):
        return "Open"
    if finding.outcome is model.Outcome.NOTAPPLICABLE:
        return "Not_Applicable"
    return "Not_Reviewed"


def expected_mapped(run: model.ScanRun, rules: list[str]) -> str:
    """Return the CKL status of a DISA rule whose mapped ComplianceAsCode rules are ``rules``."""
    findings = {finding.rule_id: finding for finding in run.findings}
    statuses = [
        "Not_Reviewed" if rule not in findings else expected_status(run, findings[rule])
        for rule in rules
    ]
    if "Open" in statuses:
        return "Open"
    if statuses and len(set(statuses)) == 1:
        return statuses[0]
    return "Not_Reviewed"


def _vulns(ckl: bytes) -> list[dict[str, str]]:
    root = fromstring(ckl)
    return [
        {
            item.findtext("VULN_ATTRIBUTE") or "": item.findtext("ATTRIBUTE_DATA") or ""
            for item in vuln
        }
        for vuln in root.findall("STIGS/iSTIG/VULN")
    ]


def mismatches(run: model.ScanRun, ckl: dict[str, str], cklb: dict[str, str]) -> list[str]:
    """Return the rules whose CKL or CKLB status is not the one ADR 0020 gives their finding."""
    found: list[str] = []
    for finding in run.findings:
        matched = RULE.fullmatch(finding.rule_id)
        reference = matched.group(1) if matched else finding.rule_id
        expected = expected_status(run, finding)
        if ckl.get(reference) != expected or cklb.get(reference) != CKLB_NAMES[expected]:
            found.append(reference)
    return found


def _files(directory: Path) -> tuple[dict[str, object], list[Path], list[Path]]:
    ckl_files = sorted(directory.glob("*.ckl"))
    cklb_files = sorted(directory.glob("*.cklb"))
    report: dict[str, object] = {
        "files": [path.name for path in (*ckl_files, *cklb_files)],
        "modes": sorted({stat.S_IMODE(path.stat().st_mode) for path in (*ckl_files, *cklb_files)}),
        "directory_mode": stat.S_IMODE(directory.stat().st_mode),
    }
    return report, ckl_files, cklb_files


def _counts(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _common(vulns: list[dict[str, str]], cklb_file: Path) -> dict[str, object]:
    return {
        "vuln_numbers": sum(1 for vuln in vulns if VULN_NUMBER.fullmatch(vuln["Vuln_Num"])),
        "titled": sum(1 for vuln in vulns if vuln["Rule_Title"] and vuln["Rule_Ver"]),
        "with_cci": sum(1 for vuln in vulns if vuln.get("CCI_REF", "").startswith("CCI-")),
        "host_name": json.loads(cklb_file.read_text())["target_data"]["host_name"],
    }


def check(directory: Path, scan_run: Path) -> dict[str, object]:
    """Return the counts and mismatches of the checklists in ``directory``."""
    report, ckl_files, cklb_files = _files(directory)
    if len(ckl_files) != 1 or len(cklb_files) != 1:
        return report
    ckl = checklist_formats.read_ckl(ckl_files[0].read_bytes())
    cklb = checklist_formats.read_cklb(cklb_files[0].read_bytes())
    run = model.loads(scan_run.read_text(encoding="utf-8"))
    report.update(
        {
            "entries": len(ckl),
            "cklb_entries": len(cklb),
            "findings": len(run.findings),
            "statuses": _counts(list(ckl.values())),
            "ckl": ckl,
            "mismatches": mismatches(run, ckl, cklb),
            **_common(_vulns(ckl_files[0].read_bytes()), cklb_files[0]),
        }
    )
    return report


def _profile_checks(mapping: Path, run: model.ScanRun) -> dict[str, list[str]]:
    document = json.loads(mapping.read_text(encoding="utf-8"))
    for stream in document["datastreams"]:
        for profile in stream["profiles"]:
            if (stream["benchmark_id"], profile["profile_id"]) == (
                run.benchmark_id,
                run.profile_id,
            ):
                return cast("dict[str, list[str]]", profile["stig_ids"])
    return {}


def check_mapped(directory: Path, scan_run: Path, mapping: Path) -> dict[str, object]:
    """Return the counts and mismatches of the checklist of a mapped ComplianceAsCode run."""
    report, ckl_files, cklb_files = _files(directory)
    if len(ckl_files) != 1 or len(cklb_files) != 1:
        return report
    ckl = checklist_formats.read_ckl(ckl_files[0].read_bytes())
    cklb = checklist_formats.read_cklb(cklb_files[0].read_bytes())
    run = model.loads(scan_run.read_text(encoding="utf-8"))
    checks = _profile_checks(mapping, run)
    vulns = _vulns(ckl_files[0].read_bytes())
    found: list[str] = []
    covered: set[str] = set()
    mapped = 0
    for vuln in vulns:
        rules = checks.get(vuln["Rule_Ver"], [])
        expected = expected_mapped(run, rules)
        reference = vuln["Rule_ID"]
        if ckl.get(reference) != expected or cklb.get(reference) != CKLB_NAMES[expected]:
            found.append(reference)
        mapped += 1 if rules else 0
        covered.update(rules)
    exported = sum(1 for finding in run.findings if finding.rule_id in covered)
    report.update(
        {
            "entries": len(ckl),
            "cklb_entries": len(cklb),
            "findings": len(run.findings),
            "outcomes": _counts([finding.outcome.value for finding in run.findings]),
            "mapped_stig_ids": len(checks),
            "mapped_entries": mapped,
            "no_check_entries": len(vulns) - mapped,
            "exported_findings": exported,
            "unexported_findings": len(run.findings) - exported,
            "statuses": _counts(list(ckl.values())),
            "mismatches": found,
            **_common(vulns, cklb_files[0]),
        }
    )
    return report


def main(argv: list[str]) -> int:
    """Print the report of the checklists in a directory for a scan run.

    The arguments are ``DIRECTORY SCAN_RUN``, or ``mapped DIRECTORY SCAN_RUN MAPPING``.
    """
    if argv[0] == "mapped":
        report = check_mapped(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    else:
        report = check(Path(argv[0]), Path(argv[1]))
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
