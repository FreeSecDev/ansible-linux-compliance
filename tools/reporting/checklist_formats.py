"""CKL (STIG Viewer 2, XML) and CKLB (STIG Viewer 3, JSON) writers and strict readers (FREES-147).

Both writers are deterministic: the same checklist always gives the same bytes. The CKL
writer is a small serializer with fixed element names; every text value is escaped
(``&``, ``<``, ``>`` and carriage return) and every character that XML 1.0 does not
allow, such as a lone surrogate, is replaced by U+FFFD. The CKLB writer uses
:func:`json.dumps` with ASCII escapes over the same sanitized text.

The readers check the exact structure that the writers produce and return each rule's
status. The exporter reads every file back before it is written, so a checklist whose
statuses differ from the mapping is never written. The formats and their sources are
in ADR 0020 and ``docs/ckl-export.md``.
"""

import json
import re
from typing import Final, cast

from tools.reporting.checklist import ASSET_TYPE, ROLE, STATUSES, Checklist, Entry
from tools.reporting.common import InvalidInputError, as_list, as_object, load_json
from tools.reporting.stig_content import DESCRIPTION_FIELDS
from tools.reporting.xmlsafe import XmlNode, parse_xml

CKLB_VERSION: Final[str] = "1.0"
XML_DECLARATION: Final[str] = '<?xml version="1.0" encoding="UTF-8"?>'
ASSET_FIELDS: Final[tuple[str, ...]] = (
    "ROLE",
    "ASSET_TYPE",
    "HOST_NAME",
    "HOST_IP",
    "HOST_MAC",
    "HOST_FQDN",
    "TARGET_COMMENT",
    "TECH_AREA",
    "TARGET_KEY",
    "WEB_OR_DATABASE",
    "WEB_DB_SITE",
    "WEB_DB_INSTANCE",
)
STIG_INFO_FIELDS: Final[tuple[str, ...]] = (
    "version",
    "classification",
    "customname",
    "stigid",
    "description",
    "filename",
    "releaseinfo",
    "title",
    "uuid",
    "notice",
    "source",
)
VULN_FIELDS: Final[tuple[str, ...]] = (
    "Vuln_Num",
    "Severity",
    "Group_Title",
    "Rule_ID",
    "Rule_Ver",
    "Rule_Title",
    "Vuln_Discuss",
    "IA_Controls",
    "Check_Content",
    "Fix_Text",
    "False_Positives",
    "False_Negatives",
    "Documentable",
    "Mitigations",
    "Potential_Impact",
    "Third_Party_Tools",
    "Mitigation_Control",
    "Responsibility",
    "Security_Override_Guidance",
    "Check_Content_Ref",
    "Weight",
    "Class",
    "STIGRef",
    "TargetKey",
    "STIG_UUID",
)
REPEATED_VULN_FIELDS: Final[tuple[str, ...]] = ("LEGACY_ID", "CCI_REF")
VULN_TAIL: Final[tuple[str, ...]] = (
    "STATUS",
    "FINDING_DETAILS",
    "COMMENTS",
    "SEVERITY_OVERRIDE",
    "SEVERITY_JUSTIFICATION",
)
DESCRIPTION_ATTRIBUTES: Final[dict[str, str]] = {
    "VulnDiscussion": "Vuln_Discuss",
    "IAControls": "IA_Controls",
    "FalsePositives": "False_Positives",
    "FalseNegatives": "False_Negatives",
    "Documentable": "Documentable",
    "Mitigations": "Mitigations",
    "PotentialImpacts": "Potential_Impact",
    "ThirdPartyTools": "Third_Party_Tools",
    "MitigationControl": "Mitigation_Control",
    "Responsibility": "Responsibility",
    "SeverityOverrideGuidance": "Security_Override_Guidance",
}
DESCRIPTION_KEYS: Final[dict[str, str]] = {
    "VulnDiscussion": "discussion",
    "IAControls": "ia_controls",
    "FalsePositives": "false_positives",
    "FalseNegatives": "false_negatives",
    "Documentable": "documentable",
    "Mitigations": "mitigations",
    "PotentialImpacts": "potential_impacts",
    "ThirdPartyTools": "third_party_tools",
    "MitigationControl": "mitigation_control",
    "Responsibility": "responsibility",
    "SeverityOverrideGuidance": "security_override_guidance",
}
CKLB_KEYS: Final[tuple[str, ...]] = (
    "title",
    "id",
    "active",
    "mode",
    "has_path",
    "target_data",
    "stigs",
    "cklb_version",
)
TARGET_KEYS: Final[tuple[str, ...]] = (
    "target_type",
    "host_name",
    "ip_address",
    "mac_address",
    "fqdn",
    "comments",
    "role",
    "is_web_database",
    "technology_area",
    "web_db_site",
    "web_db_instance",
)
STIG_KEYS: Final[tuple[str, ...]] = (
    "stig_name",
    "display_name",
    "stig_id",
    "release_info",
    "version",
    "uuid",
    "size",
    "rules",
)
RULE_KEYS: Final[tuple[str, ...]] = (
    "uuid",
    "stig_uuid",
    "target_key",
    "stig_ref",
    "group_id",
    "rule_id",
    "rule_id_src",
    "weight",
    "severity",
    "rule_version",
    "group_title",
    "rule_title",
    "fix_text",
    "false_positives",
    "false_negatives",
    "discussion",
    "check_content",
    "documentable",
    "mitigations",
    "potential_impacts",
    "third_party_tools",
    "mitigation_control",
    "responsibility",
    "security_override_guidance",
    "ia_controls",
    "check_content_ref",
    "legacy_ids",
    "ccis",
    "group_tree",
    "createdAt",
    "updatedAt",
    "STIGUuid",
    "status",
    "overrides",
    "comments",
    "finding_details",
)
_NOT_XML: Final[re.Pattern[str]] = re.compile(
    "[^\t\n\r\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]"
)


def sanitize(value: str) -> str:
    """Replace every character that XML 1.0 does not allow with U+FFFD."""
    return _NOT_XML.sub("\ufffd", value)


def xml_text(value: str) -> str:
    """Return ``value`` sanitized and escaped as XML character data."""
    return (
        sanitize(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", "&#13;")
    )


def _leaf(depth: int, name: str, value: str) -> str:
    return f"{chr(9) * depth}<{name}>{xml_text(value)}</{name}>"


def _open(depth: int, name: str) -> str:
    return f"{chr(9) * depth}<{name}>"


def _close(depth: int, name: str) -> str:
    return f"{chr(9) * depth}</{name}>"


def stig_ref(checklist: Checklist) -> str:
    """Return the ``STIGRef`` text: title, version and release information of the content."""
    benchmark = checklist.benchmark
    release = f", {benchmark.release_info}" if benchmark.release_info else ""
    return f"{benchmark.title} :: Version {benchmark.version}{release}"


def _asset_values(checklist: Checklist) -> dict[str, str]:
    asset = checklist.asset
    return {
        "ROLE": ROLE,
        "ASSET_TYPE": ASSET_TYPE,
        "HOST_NAME": asset.host_name,
        "HOST_IP": asset.host_ip,
        "HOST_MAC": "",
        "HOST_FQDN": asset.host_fqdn,
        "TARGET_COMMENT": asset.comment,
        "TECH_AREA": "",
        "TARGET_KEY": asset.target_key,
        "WEB_OR_DATABASE": "false",
        "WEB_DB_SITE": "",
        "WEB_DB_INSTANCE": "",
    }


def _stig_info(checklist: Checklist) -> dict[str, str]:
    benchmark = checklist.benchmark
    return {
        "version": benchmark.version,
        "classification": "",
        "customname": "",
        "stigid": benchmark.stig_id,
        "description": benchmark.description,
        "filename": checklist.filename,
        "releaseinfo": benchmark.release_info,
        "title": benchmark.title,
        "uuid": checklist.stig_uuid,
        "notice": benchmark.notice,
        "source": "",
    }


def _vuln_values(checklist: Checklist, entry: Entry) -> dict[str, str]:
    rule = entry.rule
    values = {
        "Vuln_Num": rule.group_id,
        "Severity": rule.severity,
        "Group_Title": rule.group_title,
        "Rule_ID": rule.rule_ref,
        "Rule_Ver": rule.version,
        "Rule_Title": rule.title,
        "Check_Content": rule.check_content,
        "Fix_Text": rule.fix_text,
        "Check_Content_Ref": rule.check_ref[1],
        "Weight": rule.weight,
        "Class": "",
        "STIGRef": stig_ref(checklist),
        "TargetKey": rule.target_key,
        "STIG_UUID": checklist.stig_uuid,
    }
    for tag, attribute in DESCRIPTION_ATTRIBUTES.items():
        values[attribute] = rule.description[tag]
    return values


def _vuln_lines(checklist: Checklist, entry: Entry) -> list[str]:
    values = _vuln_values(checklist, entry)
    pairs = [(name, values[name]) for name in VULN_FIELDS]
    pairs += [("LEGACY_ID", value) for value in entry.rule.legacy_ids]
    pairs += [("CCI_REF", value) for value in entry.rule.ccis]
    lines = [_open(3, "VULN")]
    for name, value in pairs:
        lines += [
            _open(4, "STIG_DATA"),
            _leaf(5, "VULN_ATTRIBUTE", name),
            _leaf(5, "ATTRIBUTE_DATA", value),
            _close(4, "STIG_DATA"),
        ]
    verdict = entry.verdict
    tail = (verdict.status.ckl, verdict.details, verdict.comments, "", "")
    lines += [_leaf(4, name, value) for name, value in zip(VULN_TAIL, tail, strict=True)]
    lines.append(_close(3, "VULN"))
    return lines


def render_ckl(checklist: Checklist) -> str:
    """Return the CKL document of ``checklist``."""
    asset = _asset_values(checklist)
    lines = [XML_DECLARATION, _open(0, "CHECKLIST"), _open(1, "ASSET")]
    lines += [_leaf(2, name, asset[name]) for name in ASSET_FIELDS]
    lines += [_close(1, "ASSET"), _open(1, "STIGS"), _open(2, "iSTIG"), _open(3, "STIG_INFO")]
    for name, value in _stig_info(checklist).items():
        lines += [_open(4, "SI_DATA"), _leaf(5, "SID_NAME", name)]
        if value:
            lines.append(_leaf(5, "SID_DATA", value))
        lines.append(_close(4, "SI_DATA"))
    lines.append(_close(3, "STIG_INFO"))
    for entry in checklist.entries:
        lines += _vuln_lines(checklist, entry)
    lines += [_close(2, "iSTIG"), _close(1, "STIGS"), _close(0, "CHECKLIST")]
    return "\n".join(lines) + "\n"


def _rule_object(checklist: Checklist, entry: Entry) -> dict[str, object]:
    rule = entry.rule
    described = {DESCRIPTION_KEYS[tag]: rule.description[tag] for tag in DESCRIPTION_FIELDS}
    document: dict[str, object] = {
        "uuid": entry.uuid,
        "stig_uuid": checklist.stig_uuid,
        "target_key": rule.target_key or None,
        "stig_ref": None,
        "group_id": rule.group_id,
        "rule_id": rule.rule_ref.removesuffix("_rule"),
        "rule_id_src": rule.rule_ref,
        "weight": rule.weight,
        "severity": rule.severity,
        "rule_version": rule.version,
        "group_title": rule.group_title,
        "rule_title": rule.title,
        "fix_text": rule.fix_text,
        "check_content": rule.check_content,
        "check_content_ref": {"href": rule.check_ref[0], "name": rule.check_ref[1]},
        "legacy_ids": list(rule.legacy_ids),
        "ccis": list(rule.ccis),
        "group_tree": [
            {"id": rule.group_id, "title": rule.group_title, "description": rule.group_description}
        ],
        "createdAt": checklist.timestamp,
        "updatedAt": checklist.timestamp,
        "STIGUuid": checklist.stig_uuid,
        "status": entry.verdict.status.cklb,
        "overrides": {},
        "comments": entry.verdict.comments,
        "finding_details": entry.verdict.details,
    }
    document.update(described)
    return {key: document[key] for key in RULE_KEYS}


def _sanitized(value: object) -> object:
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, dict):
        mapping = cast("dict[str, object]", value)
        return {key: _sanitized(item) for key, item in mapping.items()}
    if isinstance(value, list):
        return [_sanitized(item) for item in cast("list[object]", value)]
    return value


def render_cklb(checklist: Checklist) -> str:
    """Return the CKLB document of ``checklist``."""
    benchmark = checklist.benchmark
    asset = checklist.asset
    document: dict[str, object] = {
        "title": benchmark.title,
        "id": checklist.uuid,
        "active": False,
        "mode": 1,
        "has_path": True,
        "target_data": {
            "target_type": ASSET_TYPE,
            "host_name": asset.host_name,
            "ip_address": asset.host_ip,
            "mac_address": "",
            "fqdn": asset.host_fqdn,
            "comments": asset.comment,
            "role": ROLE,
            "is_web_database": False,
            "technology_area": "",
            "web_db_site": "",
            "web_db_instance": "",
        },
        "stigs": [
            {
                "stig_name": benchmark.title,
                "display_name": benchmark.title,
                "stig_id": benchmark.stig_id,
                "release_info": benchmark.release_info,
                "version": benchmark.version,
                "uuid": checklist.stig_uuid,
                "size": len(checklist.entries),
                "rules": [_rule_object(checklist, entry) for entry in checklist.entries],
            }
        ],
        "cklb_version": CKLB_VERSION,
    }
    return json.dumps(_sanitized(document), indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _invalid(message: str) -> InvalidInputError:
    return InvalidInputError(f"checklist structure: {message}")


def _names(node: XmlNode) -> list[str]:
    return [child.tag for child in node.children]


def _expect(node: XmlNode, names: list[str] | tuple[str, ...]) -> list[XmlNode]:
    if _names(node) != list(names):
        message = f"{node.tag} must hold {', '.join(names) or 'no elements'}"
        raise _invalid(message)
    return node.children


def _vuln_status(vuln: XmlNode) -> tuple[str, str]:
    count = len(vuln.children) - len(VULN_TAIL)
    data = vuln.children[: max(count, 0)]
    _expect(vuln, [*(["STIG_DATA"] * len(data)), *VULN_TAIL])
    pairs = [
        (pair[0].text, pair[1].text)
        for pair in (_expect(item, ("VULN_ATTRIBUTE", "ATTRIBUTE_DATA")) for item in data)
    ]
    names = [name for name, _ in pairs]
    fixed = names[: len(VULN_FIELDS)]
    repeated = names[len(VULN_FIELDS) :]
    ordered = [name for kind in REPEATED_VULN_FIELDS for name in repeated if name == kind]
    if fixed != list(VULN_FIELDS) or repeated != ordered:
        message = "a VULN has STIG_DATA attributes out of order"
        raise _invalid(message)
    status = vuln.children[len(data)].text
    if status not in {item.ckl for item in STATUSES}:
        message = "a VULN has an unknown STATUS"
        raise _invalid(message)
    return dict(pairs)["Rule_ID"], status


def _si_name(item: XmlNode) -> str:
    if item.tag != "SI_DATA" or _names(item) not in (["SID_NAME"], ["SID_NAME", "SID_DATA"]):
        message = "an SI_DATA must hold SID_NAME and, when it has a value, SID_DATA"
        raise _invalid(message)
    return item.children[0].text


def read_ckl(data: bytes) -> dict[str, str]:
    """Return the ``STATUS`` of every ``Rule_ID`` of a CKL document of the exporter's shape.

    Raises:
        InvalidInputError: If the document is not well-formed XML or not of that shape.
    """
    root = parse_xml(data)
    if root.tag != "CHECKLIST":
        message = "the root element must be CHECKLIST"
        raise _invalid(message)
    asset, stigs = _expect(root, ("ASSET", "STIGS"))
    _expect(asset, ASSET_FIELDS)
    istig = _expect(stigs, ("iSTIG",))[0]
    vulns = istig.children[1:]
    info = _expect(istig, ["STIG_INFO", *(["VULN"] * len(vulns))])[0]
    names = [_si_name(item) for item in info.children]
    if names != list(STIG_INFO_FIELDS):
        message = "STIG_INFO must list its SI_DATA names in order"
        raise _invalid(message)
    statuses = dict(_vuln_status(vuln) for vuln in vulns)
    if len(statuses) != len(vulns):
        message = "a Rule_ID appears in more than one VULN"
        raise _invalid(message)
    return statuses


def _keys(value: object, keys: tuple[str, ...], name: str) -> dict[str, object]:
    mapping = as_object(value, name)
    if tuple(mapping) != keys:
        message = f"{name} must hold exactly {', '.join(keys)}"
        raise _invalid(message)
    return mapping


def read_cklb(data: bytes) -> dict[str, str]:
    """Return the ``status`` of every ``rule_id_src`` of a CKLB document of the exporter's shape.

    Raises:
        InvalidInputError: If the document is not strict JSON or not of that shape.
    """
    document = _keys(load_json(data), CKLB_KEYS, "the checklist")
    _keys(document["target_data"], TARGET_KEYS, "target_data")
    stigs = as_list(document["stigs"], "stigs")
    if len(stigs) != 1 or document["cklb_version"] != CKLB_VERSION:
        message = f"a checklist holds one STIG and cklb_version {CKLB_VERSION}"
        raise _invalid(message)
    stig = _keys(stigs[0], STIG_KEYS, "stigs[0]")
    rules = [_keys(rule, RULE_KEYS, "a rule") for rule in as_list(stig["rules"], "rules")]
    statuses = {str(rule["rule_id_src"]): str(rule["status"]) for rule in rules}
    if stig["size"] != len(rules) or len(statuses) != len(rules):
        message = "size must count the rules, and each rule_id_src must appear once"
        raise _invalid(message)
    if not set(statuses.values()) <= {item.cklb for item in STATUSES}:
        message = "a rule has an unknown status"
        raise _invalid(message)
    return statuses
