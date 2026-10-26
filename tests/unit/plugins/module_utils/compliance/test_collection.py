from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import evidence_collection
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    collection,
    evidence,
)

NOW = datetime(2026, 10, 26, 8, 0, 1, 234567, tzinfo=timezone.utc)
ROOT = "/srv/compliance/evidence"
DIGEST = "a" * 64


def bundle_fact(host: str, run_id: str = "", root: str = ROOT) -> dict[str, object]:
    run = run_id or f"run-{host}"
    return {
        "directory": f"{root}/{host}/{run}",
        "exceptions_applied": False,
        "excluded": [],
        "files": ["SHA256SUMS", "raw/scan-run.json"],
        "manifest_sha256": DIGEST,
        "run_id": run,
    }


def observed(**changes: object) -> dict[str, object]:
    base: dict[str, object] = {
        "targets": ["web01", "db01", "app01", "lost01", "gone01", "fail01", "spare01"],
        "play_hosts": ["web01", "db01", "app01", "lost01", "fail01", "spare01"],
        "reached": ["web01", "db01", "app01", "fail01", "spare01"],
        "audited": ["web01", "db01", "app01", "fail01"],
        "evidence_written": ["web01", "db01", "fail01"],
        "bundles": {"web01": bundle_fact("web01"), "db01": bundle_fact("db01")},
        "output_dir": "/elsewhere",
        "collection_version": "0.1.0",
    }
    base.update(changes)
    return base


def test_every_target_host_gets_one_status_and_the_summary_names_them_all() -> None:
    result = collection.summarize(observed(), NOW)
    assert result["statuses"] == {
        "app01": "no_evidence_written",
        "db01": "collected",
        "fail01": "collection_failed",
        "gone01": "limited_out",
        "lost01": "unreachable",
        "spare01": "no_audit_result",
        "web01": "collected",
    }
    assert result["collected_hosts"] == ["db01", "web01"]
    assert result["missing_hosts"] == ["app01", "fail01", "gone01", "lost01", "spare01"]
    assert result["unreachable"] == ["lost01"]
    assert result["limited_out"] == ["gone01"]
    assert result["no_audit_result"] == ["spare01"]
    assert result["no_evidence_written"] == ["app01"]
    assert result["collection_failed"] == ["fail01"]
    assert result["bundles"] == [
        {"inventory_hostname": "db01", "manifest_sha256": DIGEST, "run_id": "run-db01"},
        {"inventory_hostname": "web01", "manifest_sha256": DIGEST, "run_id": "run-web01"},
    ]
    assert result["collection_id"] == "20261026T080001.234567Z"
    assert result["output_dir"] == ROOT
    assert result["path"] == f"{ROOT}/collection-20261026T080001.234567Z.json"
    document = cast("str", result["document"])
    assert result["sha256"] == evidence.sha256_hex(document.encode("ascii"))
    assert document == evidence.canonical_json(json.loads(document))
    parsed = collection.parse_collection(document.encode("ascii"))
    assert parsed.collected_at == "2026-10-26T08:00:01Z"
    assert parsed.collection_version == "0.1.0"
    assert [host.inventory_host for host in parsed.hosts] == sorted(
        cast("list[str]", observed()["targets"])
    )
    assert parsed.to_dict() == json.loads(document)
    assert parsed.file_name == "collection-20261026T080001.234567Z.json"


def test_without_the_recorded_play_hosts_unreached_hosts_have_no_audit_result() -> None:
    result = collection.summarize(observed(play_hosts=None), NOW)
    assert result["unreachable"] == []
    assert result["limited_out"] == []
    assert result["no_audit_result"] == ["gone01", "lost01", "spare01"]


def test_the_output_directory_is_used_when_nothing_was_collected() -> None:
    result = collection.summarize(observed(bundles={}), NOW)
    assert result["output_dir"] == "/elsewhere"
    assert result["collected_hosts"] == []


def test_the_filter_builds_the_summary_with_the_controller_time() -> None:
    assert evidence_collection.FilterModule().filters() == {
        "evidence_collection": evidence_collection.evidence_collection
    }
    result = evidence_collection.evidence_collection(observed())
    assert result["collected_hosts"] == ["db01", "web01"]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"targets": "web01"}, "targets must be a list"),
        ({"targets": ["web01", "web01"]}, "targets names a host twice"),
        ({"targets": ["web 01"]}, "targets entry"),
        ({"reached": None}, "reached must be a list"),
        ({"play_hosts": [3]}, "play_hosts entry"),
        ({"bundles": []}, "bundles must be a mapping"),
        ({"bundles": {"other01": bundle_fact("other01")}}, "not a target host"),
        ({"bundles": {"web01": {"run_id": "run-web01"}}}, "must have exactly the keys"),
        ({"bundles": {"web01": bundle_fact("web01", "run web01")}}, "bundle run_id"),
        (
            {"bundles": {"web01": {**bundle_fact("web01"), "manifest_sha256": "A" * 64}}},
            "bundle manifest_sha256",
        ),
        (
            {"bundles": {"web01": {**bundle_fact("web01"), "directory": "relative/web01/run"}}},
            "the bundle directory of web01",
        ),
        (
            {"bundles": {"web01": {**bundle_fact("web01"), "directory": f"{ROOT}/db01/run-web01"}}},
            "is not <output directory>/web01/<run_id>",
        ),
        (
            {"bundles": {"web01": bundle_fact("web01", root="")}},
            "is not <output directory>/web01/<run_id>",
        ),
        (
            {
                "bundles": {
                    "web01": bundle_fact("web01"),
                    "db01": bundle_fact("db01", root="/other"),
                }
            },
            "more than one output directory",
        ),
        ({"bundles": {}, "output_dir": "evidence"}, "output_dir"),
        ({"bundles": {}, "output_dir": "/"}, "normalised absolute path"),
        ({"bundles": {}, "output_dir": "/srv/../etc"}, "normalised absolute path"),
        ({"bundles": {}, "output_dir": "//srv"}, "normalised absolute path"),
        ({"bundles": {}, "output_dir": "/srv/"}, "normalised absolute path"),
        ({"collection_version": "latest"}, "collection_version"),
        ({"targets": [], "bundles": {}}, "at least one target host"),
    ],
)
def test_malformed_observations_are_refused(changes: dict[str, object], message: str) -> None:
    with pytest.raises(collection.CollectionError, match=message):
        collection.summarize(observed(**changes), NOW)


def test_the_observation_must_have_exactly_the_documented_keys() -> None:
    with pytest.raises(collection.CollectionError, match="must have exactly the keys"):
        collection.summarize({**observed(), "extra": True}, NOW)
    with pytest.raises(collection.CollectionError, match="must be a mapping"):
        collection.summarize([], NOW)


def test_the_host_lists_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collection, "MAX_HOSTS", 2)
    with pytest.raises(collection.CollectionError, match="at most 2 items"):
        collection.summarize(observed(), NOW)


def document(**changes: object) -> dict[str, Any]:
    base: dict[str, Any] = json.loads(
        cast("str", collection.summarize(observed(), NOW)["document"])
    )
    base.update(changes)
    return base


def parse(value: object) -> collection.Collection:
    return collection.parse_collection(json.dumps(value).encode("utf-8"))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"schema_version": "2.0"}, "unsupported schema_version"),
        ({"schema_version": 1}, "unsupported schema_version"),
        ({"kind": "freesecdev.linux_compliance.evidence_bundle"}, "kind must be"),
        ({"collection": {"name": "other.collection", "version": "0.1.0"}}, "collection name"),
        ({"collection": {"name": "freesecdev.linux_compliance"}}, "exactly the keys"),
        ({"collection_id": "2026-10-26"}, "collection_id"),
        ({"collection_id": "20261399T080001.234567Z"}, "not a valid controller time"),
        ({"collected_at": "2026-10-26T08:00:02Z"}, "time of the collection_id"),
        ({"collected_at": "yesterday"}, "collected_at"),
        ({"hosts": {}}, "must be a list"),
        ({"hosts": []}, "at least one target host"),
        ({"hosts": "web01"}, "must be a list"),
    ],
)
def test_invalid_summaries_are_refused(changes: dict[str, object], message: str) -> None:
    with pytest.raises(collection.CollectionError, match=message):
        parse(document(**changes))


def test_host_entries_are_validated() -> None:
    hosts = document()["hosts"]
    with pytest.raises(collection.CollectionError, match="sorted by inventory_hostname"):
        parse(document(hosts=list(reversed(hosts))))
    with pytest.raises(collection.CollectionError, match="sorted by inventory_hostname"):
        parse(document(hosts=[hosts[0], hosts[0]]))
    with pytest.raises(collection.CollectionError, match="status 'gone' is unknown"):
        parse(document(hosts=[{**hosts[0], "status": "gone"}]))
    with pytest.raises(collection.CollectionError, match="exactly when it was collected"):
        parse(document(hosts=[{**hosts[0], "status": "collected"}]))
    collected = next(host for host in hosts if host["status"] == "collected")
    with pytest.raises(collection.CollectionError, match="exactly when it was collected"):
        parse(document(hosts=[{**collected, "status": "unreachable"}]))
    with pytest.raises(collection.CollectionError, match="exactly the keys"):
        parse(document(hosts=[{**collected, "bundle": {"run_id": "run-db01"}}]))
    with pytest.raises(collection.CollectionError, match="exactly the keys"):
        parse(document(hosts=[{"inventory_hostname": "web01"}]))
    with pytest.raises(collection.CollectionError, match="host inventory_hostname"):
        parse(document(hosts=[{**hosts[0], "inventory_hostname": "-web"}]))


def test_the_summary_is_strict_json() -> None:
    with pytest.raises(collection.CollectionError, match="not valid JSON"):
        collection.parse_collection(b"{")
    with pytest.raises(
        collection.CollectionError, match=r"^the collection summary contains a duplicate key$"
    ):
        collection.parse_collection(b'{"kind": 1, "kind": 2}')
    with pytest.raises(
        collection.CollectionError, match=r"^the collection summary contains a non-finite number$"
    ):
        collection.parse_collection(b'{"kind": NaN}')
    with pytest.raises(collection.CollectionError, match="must be a mapping"):
        collection.parse_collection(b"[]")


def test_the_number_of_hosts_is_bounded_when_built(monkeypatch: pytest.MonkeyPatch) -> None:
    hosts = tuple(
        collection.TargetHost(f"web{index:02d}", collection.UNREACHABLE, None) for index in range(3)
    )
    monkeypatch.setattr(collection, "MAX_HOSTS", 2)
    with pytest.raises(collection.CollectionError, match="at most 2 target hosts"):
        collection.Collection("20261026T080001.234567Z", "2026-10-26T08:00:01Z", "0.1.0", hosts)
