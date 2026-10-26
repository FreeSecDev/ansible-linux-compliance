"""Build the egress probe stream from the pinned DISA Ubuntu 24.04 benchmark.

The probe is the DISA SCAP 1.3 data stream with two remote references added, so a
scanner that fetches external files has something to fetch:

- a ``component-ref`` in ``checks`` whose ``xlink:href`` is a remote URL, reached
  through the checklist catalog from the check of the first rule;
- a ``check-content-ref`` of the second rule whose ``href`` is a remote URL.

Both names resolve only through the sink's DNS server. The benchmark is fetched in
CI with a pinned SHA-256, the probe is written to a temporary directory and neither
is ever committed (ADR 0019, decision 3).
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from typing import TYPE_CHECKING

from tools.content import fetch_content

if TYPE_CHECKING:
    from pathlib import Path

DOWNLOAD_CHUNK_BYTES = 65536
BENCHMARK_ZIP_MAX_BYTES = 1024 * 1024

BENCHMARK_URL = (
    "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
    "U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-3_Benchmark.zip"
)
BENCHMARK_ZIP_SHA256 = "d31ad8190149508aab04591d29c3f76125db93d2a18cdcc1ffddd1b897c43fe0"
BENCHMARK_MEMBER = "U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-3_Benchmark.xml"
BENCHMARK_SHA256 = "a8abc64ebc1ee8e0aad20cbc3ee7e298ea9059fceef7f87208c78d7bf61c07d8"
BENCHMARK_MAX_BYTES = 4 * 1024 * 1024
PROBE_FILE_NAME = "U_FreeSecDev_Egress_Probe_SCAP_1-3_Benchmark.xml"
REMOTE_COMPONENT_HOST = "component.egress-probe.freesecdev.test"
REMOTE_CHECK_HOST = "check.egress-probe.freesecdev.test"
REMOTE_COMPONENT_URL = f"http://{REMOTE_COMPONENT_HOST}/remote-oval.xml"
REMOTE_CHECK_URL = f"http://{REMOTE_CHECK_HOST}/remote-check-oval.xml"
REMOTE_CATALOG_NAME = "freesecdev-remote-oval.xml"
REMOTE_CREF_ID = "scap_org.freesecdev_cref_egress-probe-remote-oval.xml"
PROBE_IDENTIFIER = "FreeSecDev_Egress_Probe"
CHECKS_END = "    </checks>"
CHECK_REF = re.compile(r'(<xccdf:check-content-ref href=")[^"]+(" name="[^"]+" />)')
CATALOG_END = "</catalog>"


class ProbeError(ValueError):
    """Raised when the benchmark does not have the expected shape."""


def verify_zip(archive: Path) -> bytes:
    """Return the benchmark member of the verified zip archive."""
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != BENCHMARK_ZIP_SHA256:
        message = f"the benchmark zip has SHA-256 {digest}, not the pinned {BENCHMARK_ZIP_SHA256}"
        raise ProbeError(message)
    with zipfile.ZipFile(archive) as bundle:
        info = bundle.getinfo(BENCHMARK_MEMBER)
        if info.file_size > BENCHMARK_MAX_BYTES:
            message = "the benchmark member is larger than expected"
            raise ProbeError(message)
        data = bundle.read(info)
    if hashlib.sha256(data).hexdigest() != BENCHMARK_SHA256:
        message = "the benchmark member does not have the pinned SHA-256"
        raise ProbeError(message)
    return data


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) < 1:
        message = f"the benchmark has no {old!r}"
        raise ProbeError(message)
    return text.replace(old, new, 1)


def probe_document(benchmark: str) -> str:
    """Return the probe stream built from the benchmark text."""
    text = benchmark.replace(
        "U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-3_Benchmark", PROBE_IDENTIFIER
    )
    component = (
        '      <component-ref xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'id="{REMOTE_CREF_ID}" xlink:href="{REMOTE_COMPONENT_URL}" />\n'
    )
    text = _replace_once(text, CHECKS_END, component + CHECKS_END)
    checklists = text.index("<checklists>")
    catalog_end = text.index(CATALOG_END, checklists)
    uri = f'  <uri name="{REMOTE_CATALOG_NAME}" uri="#{REMOTE_CREF_ID}" />\n        '
    text = text[:catalog_end] + uri + text[catalog_end:]
    references = list(CHECK_REF.finditer(text))
    if len(references) < 2:
        message = "the benchmark has fewer than two check-content-ref elements"
        raise ProbeError(message)
    first, second = references[0], references[1]
    return (
        text[: first.start()]
        + f"{first.group(1)}{REMOTE_CATALOG_NAME}{first.group(2)}"
        + text[first.end() : second.start()]
        + f"{second.group(1)}{REMOTE_CHECK_URL}{second.group(2)}"
        + text[second.end() :]
    )


def download_benchmark(directory: Path) -> Path:
    """Download the pinned benchmark zip over HTTPS into ``directory`` and verify it."""
    source = fetch_content.https_open(BENCHMARK_URL)
    target = directory / "benchmark.zip"
    received = bytearray()
    try:
        while chunk := source.read(DOWNLOAD_CHUNK_BYTES):
            received += chunk
            if len(received) > BENCHMARK_ZIP_MAX_BYTES:
                message = "the benchmark download is larger than expected"
                raise ProbeError(message)
    finally:
        source.close()
    target.write_bytes(bytes(received))
    verify_zip(target)
    return target


def write_probe(archive: Path, directory: Path) -> Path:
    """Verify the archive and write the probe stream into ``directory``."""
    benchmark = verify_zip(archive).decode("utf-8")
    target = directory / PROBE_FILE_NAME
    target.write_text(probe_document(benchmark), encoding="utf-8")
    return target
