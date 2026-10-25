"""SPDX 2.x JSON and CycloneDX 1.x JSON software bills of materials."""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_DETAIL_ITEMS,
    InvalidInputError,
    ParseResult,
    as_list,
    as_object,
    as_text,
    dig,
    load_json,
    maybe_text,
    require,
    run_parser,
)

UNASSERTED: Final[frozenset[str]] = frozenset({"NOASSERTION", "NONE"})


@dataclass(frozen=True)
class Component:
    """A listed component with its licence, if one is asserted."""

    name: str
    version: str | None
    license: str | None


@dataclass(frozen=True)
class SbomData:
    """Format, specification version, component count and licence counts."""

    format: str
    spec_version: str
    component_count: int
    license_counts: dict[str, int]
    unlicensed: int
    components: tuple[Component, ...]
    truncated: bool


def _spdx_license(package: dict[str, object]) -> str | None:
    for key in ("licenseConcluded", "licenseDeclared"):
        value = maybe_text(package.get(key))
        if value is not None and value not in UNASSERTED:
            return value
    return None


def _spdx(document: dict[str, object]) -> tuple[str, list[Component]]:
    version = as_text(document["spdxVersion"], "spdxVersion")
    if not version.startswith("SPDX-2."):
        message = "unsupported SPDX version, expected SPDX 2.x JSON"
        raise InvalidInputError(message)
    packages = [
        as_object(raw, "package")
        for raw in as_list(require(document, "packages", "SPDX document"), "packages")
    ]
    return version, [
        Component(
            as_text(require(package, "name", "package"), "package.name"),
            maybe_text(package.get("versionInfo")),
            _spdx_license(package),
        )
        for package in packages
    ]


def _cyclonedx_license(component: dict[str, object]) -> str | None:
    entry = dig(component, "licenses", 0)
    return maybe_text(
        dig(entry, "license", "id") or dig(entry, "license", "name") or dig(entry, "expression")
    )


def _cyclonedx(document: dict[str, object]) -> tuple[str, list[Component]]:
    version = as_text(require(document, "specVersion", "CycloneDX document"), "specVersion")
    if not version.startswith("1."):
        message = "unsupported CycloneDX version, expected 1.x JSON"
        raise InvalidInputError(message)
    components = [
        as_object(raw, "component")
        for raw in as_list(require(document, "components", "CycloneDX document"), "components")
    ]
    return version, [
        Component(
            as_text(require(component, "name", "component"), "component.name"),
            maybe_text(component.get("version")),
            _cyclonedx_license(component),
        )
        for component in components
    ]


def _build(data: bytes) -> SbomData:
    document = as_object(load_json(data), "SBOM")
    if "spdxVersion" in document:
        name = "spdx"
        version, components = _spdx(document)
    elif document.get("bomFormat") == "CycloneDX":
        name = "cyclonedx"
        version, components = _cyclonedx(document)
    else:
        message = "document is neither SPDX JSON nor CycloneDX JSON"
        raise InvalidInputError(message)
    if not components:
        message = "the SBOM lists no components"
        raise InvalidInputError(message)
    ordered = sorted(
        components, key=lambda item: (item.name, item.version or "", item.license or "")
    )
    licenses = [item.license for item in ordered if item.license is not None]
    return SbomData(
        format=name,
        spec_version=version,
        component_count=len(ordered),
        license_counts={key: licenses.count(key) for key in sorted(set(licenses))},
        unlicensed=len(ordered) - len(licenses),
        components=tuple(ordered[:MAX_DETAIL_ITEMS]),
        truncated=len(ordered) > MAX_DETAIL_ITEMS,
    )


def parse_sbom(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[SbomData]:
    """Parse an SPDX 2.x or CycloneDX 1.x JSON SBOM. Only top-level components are read."""
    return run_parser(path, "sbom", max_bytes, _build)
