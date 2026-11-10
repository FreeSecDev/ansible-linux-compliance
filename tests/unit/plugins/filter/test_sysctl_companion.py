"""The sysctl_companion filter hands the entries to the companion check (FREES-107)."""

from __future__ import annotations

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sysctl_companion

SAMPLE_RATE = "kernel.perf_event_max_sample_rate"
CPU_TIME = "kernel.perf_cpu_time_max_percent"
BLOCKER: dict[str, object] = {"key": CPU_TIME, "refused": [0, 100]}
ENTRIES: list[dict[str, object]] = [
    {"path": "/etc/sysctl.d/50-perf.conf", "kind": "file", "text": f"{CPU_TIME} = 0\n"},
    {"path": "/etc/sysctl.d/99-rate.conf", "kind": "file", "text": f"{SAMPLE_RATE} = 1\n"},
]


def test_the_filter_is_registered() -> None:
    filters = sysctl_companion.FilterModule().filters()
    assert filters == {"sysctl_companion": sysctl_companion.sysctl_companion}


def test_a_companion_at_zero_refuses_the_key_before_and_after_the_run() -> None:
    setting = {"value": "0", "source": "/etc/sysctl.d/50-perf.conf"}
    assert sysctl_companion.sysctl_companion(ENTRIES, ENTRIES, SAMPLE_RATE, BLOCKER) == {
        "undecided": False,
        "planned": {"systemd": setting, "procps": setting},
        "current": {"systemd": setting, "procps": setting},
    }
