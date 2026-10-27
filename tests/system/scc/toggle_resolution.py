"""Resolve the SCC toggles for the integration test exactly as the audit role does (FREES-170).

The audit role reads the SCC profile with ``profile_info``, loads the rule catalogue of the
remediate role and the STIG mapping, and passes them with the toggle variables to the
``scc_toggles`` filter. This script does the same inside the CI-only SCC image, with the real
installed stream, and prints the filter's result and the benchmark version as one JSON document.

Arguments: the repository, the stream, its SHA-256, the DISA profile and a JSON object of toggle
variables.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import scc_toggles
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import catalog

CATALOGUE = Path("roles") / "remediate" / "vars" / "rules.yml"
MAPPING = Path("content") / "stig-mapping.json"


def main(argv: list[str]) -> int:
    """Print the resolution for the arguments in ``argv``."""
    repository, content, sha256, profile, toggles = argv
    report = catalog.profile_report(content, sha256, profile)
    catalogue = yaml.safe_load((Path(repository) / CATALOGUE).read_text(encoding="utf-8"))
    resolution = scc_toggles.scc_toggles(
        catalogue["__linux_compliance_remediate_rules"],
        {
            "audit_only": catalogue["__linux_compliance_remediate_audit_only"],
            "families": catalogue["__linux_compliance_remediate_families"],
            "tags": catalogue["__linux_compliance_remediate_tags"],
            "toggles": json.loads(toggles),
            "disabled_rules": [],
            "mapping": (Path(repository) / MAPPING).read_text(encoding="utf-8"),
            "benchmark_id": report["benchmark_id"],
            "benchmark_version": report["benchmark_version"],
            "rules": report["rules"],
        },
    )
    document = {"benchmark_version": report["benchmark_version"], "resolution": resolution}
    sys.stdout.write(json.dumps(document, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
