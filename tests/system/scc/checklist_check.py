"""Read back the checklists of a real SCC scan inside the SCC image (FREES-147).

``scc_driver.py`` runs the reporting command on the scan run of a real scan and then
this script on the directory it wrote. The script reads the CKL and CKLB files with
the exporter's strict readers, derives the expected status of every finding from the
scan run with the table of ADR 0020, written out again here so that the exporter's
own mapping is not checked against itself, and prints one JSON document of counts and
mismatches. No checklist text leaves the container: the files stay in its throwaway
file system and are never collected or committed.
"""

from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

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


def _vulns(ckl: bytes) -> list[dict[str, str]]:
    root = fromstring(ckl)
    return [
        {
            item.findtext("VULN_ATTRIBUTE") or "": item.findtext("ATTRIBUTE_DATA") or ""
            for item in vuln
        }
        for vuln in root.findall("STIGS/iSTIG/VULN")
    ]


def check(directory: Path, scan_run: Path) -> dict[str, object]:
    """Return the counts and mismatches of the checklists in ``directory``."""
    ckl_files = sorted(directory.glob("*.ckl"))
    cklb_files = sorted(directory.glob("*.cklb"))
    report: dict[str, object] = {
        "files": [path.name for path in (*ckl_files, *cklb_files)],
        "modes": sorted({stat.S_IMODE(path.stat().st_mode) for path in (*ckl_files, *cklb_files)}),
        "directory_mode": stat.S_IMODE(directory.stat().st_mode),
    }
    if len(ckl_files) != 1 or len(cklb_files) != 1:
        return report
    ckl = checklist_formats.read_ckl(ckl_files[0].read_bytes())
    cklb = checklist_formats.read_cklb(cklb_files[0].read_bytes())
    run = model.loads(scan_run.read_text(encoding="utf-8"))
    mismatches: list[str] = []
    for finding in run.findings:
        matched = RULE.fullmatch(finding.rule_id)
        reference = matched.group(1) if matched else finding.rule_id
        expected = expected_status(run, finding)
        if ckl.get(reference) != expected or cklb.get(reference) != CKLB_NAMES[expected]:
            mismatches.append(reference)
    vulns = _vulns(ckl_files[0].read_bytes())
    counts: dict[str, int] = {}
    for status in ckl.values():
        counts[status] = counts.get(status, 0) + 1
    report.update(
        {
            "entries": len(ckl),
            "cklb_entries": len(cklb),
            "findings": len(run.findings),
            "statuses": counts,
            "ckl": ckl,
            "mismatches": mismatches,
            "vuln_numbers": sum(1 for vuln in vulns if VULN_NUMBER.fullmatch(vuln["Vuln_Num"])),
            "titled": sum(1 for vuln in vulns if vuln["Rule_Title"] and vuln["Rule_Ver"]),
            "with_cci": sum(1 for vuln in vulns if vuln.get("CCI_REF", "").startswith("CCI-")),
            "host_name": json.loads(cklb_files[0].read_text())["target_data"]["host_name"],
        }
    )
    return report


def main(argv: list[str]) -> int:
    """Print the report of the checklists in ``argv[0]`` for the scan run ``argv[1]``."""
    sys.stdout.write(json.dumps(check(Path(argv[0]), Path(argv[1])), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
