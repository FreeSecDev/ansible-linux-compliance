"""Render the normalized report as one self-contained, offline HTML dashboard (FREES-77).

The page embeds the report document unchanged, as JSON in a non-executable
``<script type="application/json">`` block, together with a small view that joins
compliance host groups to their input files. Nothing in the view is a figure: every
count, percentage and assessment comes from the report as it is. The inline style and
script are static assets whose SHA-256 hashes form the Content-Security-Policy, so the
page runs no other code, loads nothing from the network and works from ``file://``.

Report text is untrusted. The JSON block escapes ``<``, ``>``, ``&``, U+2028 and
U+2029, so no report value can close the element or start markup, and the script
renders values with DOM text APIs only. Equal reports give byte-identical pages.
"""

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from tools.reporting.common import Json

ASSET_DIRECTORY: Final[Path] = Path(__file__).parent / "assets"
SCRIPT_ASSET: Final[str] = "dashboard.js"
STYLE_ASSET: Final[str] = "dashboard.css"
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1.0"})
MAX_EMBEDDED_BYTES: Final[int] = 128 * 1024 * 1024
MACHINE_ID: Final[str] = "machine_id"
SELF_ASSERTED: Final[str] = "self_asserted"
UNNAMED: Final[str] = "unnamed"
JSON_ESCAPES: Final[dict[str, str]] = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}
FORBIDDEN_ASSET_SEQUENCES: Final[tuple[str, ...]] = ("</script", "</style", "<!--", "<script")
_ESCAPE_TABLE: Final[dict[int, str]] = str.maketrans(JSON_ESCAPES)

type HostTuple = tuple[str, str, str]


class DashboardError(ValueError):
    """Raised when a report cannot be rendered as a dashboard."""


def embed_json(document: Json) -> str:
    r"""Serialize ``document`` for a ``<script type="application/json">`` element.

    The output is compact, key-sorted ASCII JSON in which ``<``, ``>``, ``&``, U+2028
    and U+2029 are written as ``\uXXXX`` escapes. Those characters only occur inside
    JSON strings, so the result parses to the same value, and it can contain neither
    ``</script>`` nor ``<!--`` nor any other markup.
    """
    text = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return text.translate(_ESCAPE_TABLE)


def csp_hash(content: str) -> str:
    """Return the CSP hash source (``'sha256-<base64>'``) of an inline element's text."""
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def content_security_policy(script: str, style: str) -> str:
    """Return the page policy: nothing but the hashed inline script and style may run."""
    return "; ".join(
        (
            "default-src 'none'",
            f"script-src {csp_hash(script)}",
            f"style-src {csp_hash(style)}",
            "base-uri 'none'",
            "form-action 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types 'none'",
        )
    )


def check_asset(name: str, content: str) -> str:
    """Return ``content`` if it cannot end its element early, else raise :class:`DashboardError`."""
    lowered = content.lower()
    for sequence in FORBIDDEN_ASSET_SEQUENCES:
        if sequence in lowered:
            message = f"asset {name} contains {sequence!r}"
            raise DashboardError(message)
    return content


def load_asset(name: str) -> str:
    """Read a static dashboard asset and check it."""
    return check_asset(name, (ASSET_DIRECTORY / name).read_text(encoding="utf-8"))


def _mapping(value: Json) -> dict[str, Json]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Json) -> list[Json]:
    return value if isinstance(value, list) else []


def _text(value: Json) -> str:
    return value if isinstance(value, str) else ""


def key_of(host: Json) -> HostTuple:
    """Return a structured host key (``groups[].host`` or ``rules[].host``) as a tuple."""
    fields = _mapping(host)
    return (
        _text(fields.get("hostname")),
        _text(fields.get("machine_id")),
        _text(fields.get("input_sha256")),
    )


def item_host(data: Json) -> HostTuple:
    """Return the host key of a compliance input, as ``compliance.host_key`` derives it.

    A ScanRun names its host and machine ID, an XCCDF or ARF file a self-asserted name,
    and an input without a name is identified by the SHA-256 of its content.
    """
    fields = _mapping(data)
    host = _mapping(fields.get("host"))
    if host:
        return (_text(host.get("hostname")).lower(), _text(host.get("machine_id")), "")
    reported = fields.get("reported_host")
    if isinstance(reported, str):
        return (reported.lower(), "", "")
    return ("", "", _text(fields.get("input_sha256")))


def _group_sources(items: Sequence[Json]) -> dict[tuple[str, str, HostTuple], list[Json]]:
    sources: dict[tuple[str, str, HostTuple], list[Json]] = {}
    for raw in items:
        item = _mapping(raw)
        data = _mapping(item.get("data"))
        if item.get("status") != "available" or not data:
            continue
        key = (_text(data.get("benchmark_id")), _text(data.get("content_version")), item_host(data))
        artifact = _mapping(item.get("artifact"))
        sources.setdefault(key, []).append(
            {
                "format": item.get("format"),
                "path": artifact.get("path"),
                "sha256": artifact.get("sha256"),
            }
        )
    return sources


def _group_view(
    group: Json,
    sources: Mapping[tuple[str, str, HostTuple], list[Json]],
    notes: Sequence[Json],
) -> Json:
    fields = _mapping(group)
    host = key_of(fields.get("host"))
    key = (_text(fields.get("benchmark_id")), _text(fields.get("content_version")), host)
    matching = sorted(sources.get(key, []), key=lambda source: json.dumps(source, sort_keys=True))
    note_indexes: list[Json] = [
        index
        for index, note in enumerate(notes)
        if host[0] and not host[1] and _mapping(note).get("host") == host[0]
    ]
    return {"notes": note_indexes, "sources": list[Json](matching)}


def _label(host: HostTuple) -> tuple[bool, str]:
    return (bool(host[0]), host[0] or host[2])


def _identity(host: HostTuple) -> str:
    if host[1]:
        return MACHINE_ID
    return SELF_ASSERTED if host[0] else UNNAMED


def _host_table(hosts: set[HostTuple]) -> list[Json]:
    by_label: dict[tuple[bool, str], list[HostTuple]] = {}
    for host in hosts:
        by_label.setdefault(_label(host), []).append(host)
    table: list[Json] = []
    for host in sorted(hosts):
        siblings = sorted(by_label[_label(host)])
        table.append(
            {
                "hostname": host[0] or None,
                "identity": _identity(host),
                "input_sha256": host[2] or None,
                "machine_id": host[1] or None,
                "variant": siblings.index(host) + 1,
                "variants": len(siblings),
            }
        )
    return table


def dashboard_views(report: Mapping[str, Json]) -> dict[str, Json]:
    """Return the view that the page needs beside the report. It holds no figures.

    ``groups[i]`` lists the input files (format, path, SHA-256) and the indexes of the
    merge notes of ``sections.compliance.groups[i]``. ``hosts`` lists every host key of
    the groups and rules once, with whether a machine ID identifies it or the name is
    self-asserted, and a variant number when several keys share one name.
    """
    compliance = _mapping(_mapping(report.get("sections")).get("compliance"))
    groups = _sequence(compliance.get("groups"))
    notes = _sequence(compliance.get("notes"))
    sources = _group_sources(_sequence(compliance.get("items")))
    hosts = {key_of(_mapping(group).get("host")) for group in groups}
    hosts.update(key_of(_mapping(rule).get("host")) for rule in _sequence(compliance.get("rules")))
    return {
        "groups": [_group_view(group, sources, notes) for group in groups],
        "hosts": _host_table(hosts),
    }


def page(policy: str, style: str, data: str, script: str) -> str:
    """Assemble the HTML document. Every argument is already checked or escaped."""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{policy}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        '<meta name="color-scheme" content="light dark">\n'
        "<title>Compliance report dashboard</title>\n"
        f"<style>{style}</style>\n"
        "</head>\n"
        "<body>\n"
        '<header id="banner"><h1>Compliance report dashboard</h1></header>\n'
        '<main id="main"><noscript><p>This dashboard needs JavaScript to display the report. '
        "The report is embedded in this file as JSON in the element with the id "
        "report-data.</p></noscript></main>\n"
        '<footer id="footer"></footer>\n'
        f'<script id="report-data" type="application/json">{data}</script>\n'
        f"<script>{script}</script>\n"
        "</body>\n"
        "</html>\n"
    )


def render_dashboard(report: Mapping[str, Json]) -> str:
    """Return the dashboard HTML for a report document written by ``build_report``.

    Raises:
        DashboardError: If the schema version is not supported or the embedded data
            would exceed ``MAX_EMBEDDED_BYTES``.
    """
    version = report.get("schema_version")
    if not isinstance(version, str) or version not in SUPPORTED_SCHEMA_VERSIONS:
        message = "the report schema version is not supported by the dashboard"
        raise DashboardError(message)
    data = embed_json({"report": dict(report), "views": dashboard_views(report)})
    if len(data) > MAX_EMBEDDED_BYTES:
        message = (
            f"the report is too large for the dashboard (more than {MAX_EMBEDDED_BYTES} bytes)"
        )
        raise DashboardError(message)
    script = load_asset(SCRIPT_ASSET)
    style = load_asset(STYLE_ASSET)
    return page(content_security_policy(script, style), style, data, script)
