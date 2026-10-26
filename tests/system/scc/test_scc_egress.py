"""Egress test of the SCC backend (ADR 0019, decision 2; FREES-145).

The scan container runs on an internal Docker network (``--internal``, on a random free
``172.31.x.0/24`` per run, so concurrent runs do not collide) whose only
peer is a sink container (:mod:`egress_sink`). The scan container's resolver is
the sink, which answers every name with its own address, accepts or resets TCP
on every port and logs every DNS query, connection and datagram it receives.

The scanned stream is the pinned DISA Ubuntu 24.04 benchmark with two remote
references added (:mod:`egress_content`). It is installed with SCC's own
installer in this throwaway container; the backend never installs content.

1. **Negative.** ``compliance_scan`` with ``backend: scc`` scans the probe. The
   backend writes ``downloadExternalFiles=0`` and confirms it from SCC's log,
   while the installed ``options.xml`` still says ``1``. The sink must see no
   DNS query for any name except the scanner's own host name (SCC resolves
   ``<hostname>`` and ``<hostname>.localdomain`` to describe the target; the
   test names these two explicitly) and no connection or datagram at all.
2. **Positive control.** The same scan form with the backend's per-run options,
   but ``downloadExternalFiles=1``. The sink must see the DNS query for a probe
   host and a TCP connection, which shows that the test detects a violation, and
   the backend's confirmation must refuse that run's log.

``--network none`` is not used as evidence: a blocked fetch fails quietly.
strace is not available in the image and is not used.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from tests.system.scc import egress_content, harness

SUBNET_ATTEMPTS = 8
SUBNET_OCTETS = range(16, 255)
HOSTNAME = "scc-egress-target"
OWN_NAMES = frozenset({HOSTNAME, f"{HOSTNAME}.localdomain"})
PROBE_HOSTS = frozenset({egress_content.REMOTE_COMPONENT_HOST, egress_content.REMOTE_CHECK_HOST})
SINK_READY_SECONDS = 30
SETTLE_SECONDS = 2
BENCHMARK_VARIABLE = "FREESECDEV_SCC_BENCHMARK_ZIP"


class Sink:
    """Reads the event log of the sink container."""

    def __init__(self, log: Path) -> None:
        """Remember the log file."""
        self.log = log

    def events(self) -> list[dict[str, object]]:
        """Return every event logged so far."""
        if not self.log.exists():
            return []
        return [
            cast("dict[str, object]", json.loads(line))
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def since(self, mark: int) -> list[dict[str, object]]:
        """Return the events logged after the first ``mark`` events."""
        time.sleep(SETTLE_SECONDS)
        return self.events()[mark:]


def _wait_ready(sink: Sink) -> None:
    deadline = time.monotonic() + SINK_READY_SECONDS
    while time.monotonic() < deadline:
        if any(event.get("kind") == "ready" for event in sink.events()):
            return
        time.sleep(0.5)
    pytest.fail("the egress sink did not start")


def _benchmark(directory: Path) -> Path:
    given = Path(os.environ.get(BENCHMARK_VARIABLE, ""))
    if given.name:
        return given
    return egress_content.download_benchmark(directory)


def _exec(name: str, *arguments: str) -> dict[str, object]:
    output = harness.run(
        [
            "exec",
            name,
            harness.interpreter(),
            "-s",
            harness.DRIVER,
            *arguments,
            "--repository",
            harness.SOURCE_MOUNT,
            "--site-packages",
            harness.SITE_MOUNT,
        ]
    )
    return harness.driver_report(output)


def _violations(events: list[dict[str, object]]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for event in events:
        if event.get("kind") == "dns" and event.get("name") in OWN_NAMES:
            continue
        if (
            event.get("kind") == "packet"
            and event.get("protocol") == "udp"
            and event.get("port") == 53
        ):
            continue
        found.append(event)
    return found


@dataclass(frozen=True)
class Network:
    """The internal network of one test run and the two addresses on it."""

    name: str
    subnet: str
    sink: str
    scan: str

    @classmethod
    def create(cls, name: str) -> Network:
        """Create an internal network on a random free /24, or fail clearly."""
        tried: list[str] = []
        for _attempt in range(SUBNET_ATTEMPTS):
            octet = SUBNET_OCTETS[secrets.randbelow(len(SUBNET_OCTETS))]
            prefix = f"172.31.{octet}"
            subnet = f"{prefix}.0/24"
            tried.append(subnet)
            completed = subprocess.run(
                [harness.docker(), "network", "create", "--internal", "--subnet", subnet, name],
                check=False,
                capture_output=True,
                text=True,
                timeout=harness.CONTAINER_TIMEOUT_SECONDS,
            )
            if completed.returncode == 0:
                return cls(name, subnet, f"{prefix}.2", f"{prefix}.3")
        message = f"no free subnet for the egress network after trying {', '.join(tried)}"
        raise RuntimeError(message)


@dataclass(frozen=True)
class Workspace:
    """The files that the sink and the scan container mount."""

    probe: Path
    probe_sha256: str
    logs: Path
    resolver: Path
    network: Network

    @classmethod
    def create(cls, work: Path, network: Network) -> Workspace:
        """Write the probe stream, the sink log directory and the resolver file."""
        probe_directory = work / "probe"
        probe_directory.mkdir()
        probe = egress_content.write_probe(_benchmark(work), probe_directory)
        probe_directory.chmod(0o755)
        probe.chmod(0o644)
        logs = work / "sink"
        logs.mkdir()
        logs.chmod(0o777)
        resolver = work / "resolv.conf"
        resolver.write_text(f"nameserver {network.sink}\noptions attempts:1 timeout:1\n", "utf-8")
        resolver.chmod(0o644)
        digest = hashlib.sha256(probe.read_bytes()).hexdigest()
        return cls(probe, digest, logs, resolver, network)


def _start_sink(name: str, network: str, workspace: Workspace) -> None:
    harness.run(
        [
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            network,
            "--ip",
            workspace.network.sink,
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_RAW",
            "--cap-add",
            "NET_BIND_SERVICE",
            "--security-opt",
            "no-new-privileges",
            *harness.python_mounts(),
            "--volume",
            f"{workspace.logs}:/log",
            "--entrypoint",
            harness.interpreter(),
            harness.image(),
            "-I",
            f"{harness.SOURCE_MOUNT}/tests/system/scc/egress_sink.py",
            "--address",
            workspace.network.sink,
            "--log",
            "/log/events.jsonl",
        ]
    )


def _start_scan(name: str, network: str, workspace: Workspace) -> None:
    harness.run(
        [
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            network,
            "--ip",
            workspace.network.scan,
            "--hostname",
            HOSTNAME,
            "--volume",
            f"{workspace.resolver}:/etc/resolv.conf:ro",
            "--volume",
            f"{workspace.probe.parent}:/probe:ro",
            *harness.hardening(),
            *harness.python_mounts(),
            "--entrypoint",
            "sleep",
            harness.image(),
            "infinity",
        ]
    )


def _measure(scan_name: str, sink: Sink, workspace: Workspace) -> dict[str, object]:
    installed = f"{harness.CONTENT_DIRECTORY}/{workspace.probe.name}"
    report: dict[str, object] = {
        "setup": _exec(scan_name, "install", "--content", f"/probe/{workspace.probe.name}")
    }
    mark = len(sink.events())
    report["negative"] = _exec(
        scan_name, "egress-scan", "--content", installed, "--sha256", workspace.probe_sha256
    )
    report["negative_events"] = sink.since(mark)
    mark = len(sink.events())
    report["control"] = _exec(scan_name, "positive", "--content", installed)
    report["control_events"] = sink.since(mark)
    return report


@pytest.fixture(scope="module")
def egress(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    harness.image()
    suffix = uuid.uuid4().hex[:12]
    network, sink_name, scan_name = (
        f"freesecdev-egress-{suffix}",
        f"sink-{suffix}",
        f"scan-{suffix}",
    )
    created = Network.create(network)
    try:
        workspace = Workspace.create(tmp_path_factory.mktemp("scc-egress"), created)
        sink = Sink(workspace.logs / "events.jsonl")
        _start_sink(sink_name, network, workspace)
        _wait_ready(sink)
        _start_scan(scan_name, network, workspace)
        return _measure(scan_name, sink, workspace)
    finally:
        harness.run(["rm", "--force", sink_name, scan_name])
        harness.run(["network", "rm", network])


def test_the_scan_with_downloads_off_completes_without_any_egress(
    egress: dict[str, object],
) -> None:
    negative = cast("dict[str, object]", egress["negative"])
    events = cast("list[dict[str, object]]", egress["negative_events"])
    harness.report_line("negative scan", {"run_status": negative.get("run_status")})
    harness.report_line("negative sink events", events)
    assert negative["run_status"] == "completed", negative.get("msg")
    run = cast("dict[str, object]", negative["scan_run"])
    assert run["scanner"] == {"name": "scc", "version": harness.pin("SCC_VERSION")}
    assert _violations(events) == []
    names = {event.get("name") for event in events if event.get("kind") == "dns"}
    assert not names & PROBE_HOSTS
    assert not [event for event in events if event.get("kind") == "connection"]


def test_the_positive_control_is_seen_by_the_sink_and_refused(egress: dict[str, object]) -> None:
    control = cast("dict[str, object]", egress["control"])
    events = cast("list[dict[str, object]]", egress["control_events"])
    harness.report_line("positive control", control)
    harness.report_line("positive sink events", events)
    names = {event.get("name") for event in events if event.get("kind") == "dns"}
    assert names & PROBE_HOSTS
    assert [event for event in events if event.get("kind") == "connection"]
    assert "downloadExternalFiles" in cast("str", control["refusal"])
