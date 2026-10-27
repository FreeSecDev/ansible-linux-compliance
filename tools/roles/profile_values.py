"""Read the XCCDF values that native remediations need from the pinned datastreams (FREES-53).

A native rule whose check compares the host with a tailorable XCCDF ``Value`` (the minimum
password length, the required banner text) must apply the value that the selected profile
requires, not a value chosen by the collection. ADR 0021 decides that these values are read at
generation time: ``content/catalogue.yml`` names the ``Value`` of such a rule in
``profile_value``, and :func:`resolve` writes, per pinned datastream, the value of every profile
that selects the rule into the rule's parameters. The role selects the entry of the
digest-verified content and the profile that the ``discover`` role verified, so it never guesses
a value and never substitutes another profile's value.

:func:`read_values` verifies the pinned SHA-256 of a datastream before it parses a byte, parses
it with the bounded parser of :mod:`xmlsafe` while it hashes it a second time, and keeps only
three things of the XCCDF benchmark: every ``Value`` with its options (the option without a
``selector`` is the default), the ``refine-value`` selectors of every profile, and the values
that the checks of every rule export. A rule whose checks do not export the named value, a
profile that refines it to an option the value does not have, a value without a default and a
datastream that does not define the value are errors; nothing is guessed. Values are kept as
written in the BSD-3-Clause content and are split into chunks that the catalogue can render
within its line length.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    xmlsafe,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

XCCDF: Final[str] = "{http://checklists.nist.gov/xccdf/1.2}"
VALUE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_value_"
PROFILE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_profile_"
DEFAULT_SELECTOR: Final[str] = ""
MAX_VALUE_LENGTH: Final[int] = 16384
MAX_CHUNK: Final[int] = 72
MAX_BYTES: Final[int] = catalog.DEFAULT_MAX_BYTES

_BENCHMARK: Final[str] = f"{XCCDF}Benchmark"
_VALUE: Final[str] = f"{XCCDF}Value"
_OPTION: Final[str] = f"{XCCDF}value"
_PROFILE: Final[str] = f"{XCCDF}Profile"
_REFINE: Final[str] = f"{XCCDF}refine-value"
_RULE: Final[str] = f"{XCCDF}Rule"
_EXPORT: Final[str] = f"{XCCDF}check-export"


class ProfileValueError(ValueError):
    """A datastream cannot supply the value that a native rule needs."""


@dataclass(frozen=True)
class StreamValues:
    """The values, profile refinements and check exports of one verified datastream.

    ``values`` maps every value identifier to its options by selector, the default under
    :data:`DEFAULT_SELECTOR`; ``refinements`` maps every profile identifier to the selector it
    chooses per value; ``exports`` maps every rule identifier to the values its checks export.
    """

    content_sha256: str
    values: dict[str, dict[str, str]]
    refinements: dict[str, dict[str, str]]
    exports: dict[str, frozenset[str]]


@dataclass(frozen=True)
class StreamProfiles:
    """A pinned datastream as :func:`resolve` needs it: its name, values and profile rules."""

    name: str
    values: StreamValues
    profiles: Mapping[str, Sequence[str]]


class _Collector:
    """Receives parse events and keeps the values, refinements and exports of the benchmark."""

    def __init__(self) -> None:
        self.stack: list[str] = []
        self.values: dict[str, dict[str, str]] = {}
        self.refinements: dict[str, dict[str, str]] = {}
        self.exports: dict[str, set[str]] = {}
        self.value_id = ""
        self.selector: str | None = None
        self.profile_id = ""
        self.rule_id = ""
        self.parts: list[str] = []

    def _inside(self, name: str) -> bool:
        return name in self.stack

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        parent = self.stack[-1] if self.stack else ""
        self.stack.append(name)
        if not self._inside(_BENCHMARK):
            return
        if name == _VALUE:
            self.value_id = attributes.get("id", "")
            self.values.setdefault(self.value_id, {})
        elif name == _OPTION and parent == _VALUE:
            self.selector = attributes.get("selector", DEFAULT_SELECTOR)
            self.parts = []
        elif name == _PROFILE:
            self.profile_id = attributes.get("id", "")
            self.refinements.setdefault(self.profile_id, {})
        elif name == _REFINE and parent == _PROFILE:
            self.refinements[self.profile_id][attributes.get("idref", "")] = attributes.get(
                "selector", DEFAULT_SELECTOR
            )
        elif name == _RULE:
            self.rule_id = attributes.get("id", "")
            self.exports.setdefault(self.rule_id, set())
        elif name == _EXPORT and self._inside(_RULE):
            self.exports[self.rule_id].add(attributes.get("value-id", ""))

    def end(self, name: str, /) -> None:
        self.stack.pop()
        if name == _OPTION and self.selector is not None:
            text = "".join(self.parts)
            self.values[self.value_id].setdefault(self.selector, text)
            self.selector = None

    def text(self, data: str, /) -> None:
        if self.selector is not None:
            self.parts.append(data)
            if sum(map(len, self.parts)) > MAX_VALUE_LENGTH:
                message = f"the value {self.value_id} is longer than {MAX_VALUE_LENGTH} characters"
                raise ProfileValueError(message)


class _HashedChunks:
    def __init__(self, handle: BinaryIO, max_bytes: int) -> None:
        self.handle = handle
        self.max_bytes = max_bytes
        self.digest = hashlib.sha256()

    def __iter__(self) -> Iterator[bytes]:
        for chunk in xmlsafe.iter_handle_chunks(self.handle, self.max_bytes):
            self.digest.update(chunk)
            yield chunk


def read_values(path: str, expected_sha256: str, max_bytes: int = MAX_BYTES) -> StreamValues:
    """Verify the datastream ``path`` against its pinned digest and return its values.

    Raises:
        ProfileValueError: When the digest differs, before or during the parse, or the file
            cannot be parsed safely.
    """
    try:
        expected = catalog.verify_digest(path, expected_sha256, max_bytes)
        collector = _Collector()
        with xmlsafe.RegularFile(path, max_bytes) as handle:
            chunks = _HashedChunks(handle, max_bytes)
            xmlsafe.parse_chunks(chunks, collector)
            actual = chunks.digest.hexdigest()
    except (catalog.CatalogError, xmlsafe.XmlSafetyError) as error:
        raise ProfileValueError(str(error)) from error
    if actual != expected:
        message = f"{path} changed while it was read: expected {expected}, found {actual}"
        raise ProfileValueError(message)
    return StreamValues(
        content_sha256=expected,
        values=collector.values,
        refinements=collector.refinements,
        exports={rule: frozenset(found) for rule, found in collector.exports.items()},
    )


def chunks(text: str, width: int = MAX_CHUNK) -> list[str]:
    """Split ``text`` into pieces whose JSON rendering is at most ``width`` characters long."""
    pieces: list[str] = []
    current = ""
    for character in text:
        if current and len(json.dumps(current + character)) > width:
            pieces.append(current)
            current = ""
        current += character
    pieces.append(current)
    return pieces


def profile_value(stream: StreamValues, profile_id: str, value_id: str) -> str:
    """Return the value that ``profile_id`` of ``stream`` gives to ``value_id``.

    Raises:
        ProfileValueError: When the datastream does not define the value, the value has no
            default or the profile refines it to an option the value does not have.
    """
    options = stream.values.get(value_id)
    if options is None:
        message = f"the datastream does not define {value_id}"
        raise ProfileValueError(message)
    selector = stream.refinements.get(profile_id, {}).get(value_id, DEFAULT_SELECTOR)
    if selector not in options:
        what = "has no default" if selector == DEFAULT_SELECTOR else f"has no option {selector!r}"
        message = f"{value_id} {what}, which {profile_id} needs"
        raise ProfileValueError(message)
    return options[selector]


def resolve(
    streams: Sequence[StreamProfiles], rule_id: str, value_short_id: str
) -> list[dict[str, object]]:
    """Return the value of ``value_short_id`` for every profile that selects ``rule_id``.

    Each entry names the datastream and its pinned SHA-256, the sorted short identifiers of the
    profiles that share one value, and that value as chunks. Datastreams whose profiles do not
    select the rule contribute nothing.

    Raises:
        ProfileValueError: When a datastream that selects the rule cannot supply the value, or
            the rule's checks there do not export it.
    """
    value_id = VALUE_PREFIX + value_short_id
    entries: list[dict[str, object]] = []
    for stream in streams:
        selecting = sorted(
            profile_id for profile_id, rules in stream.profiles.items() if rule_id in rules
        )
        if not selecting:
            continue
        if value_id not in stream.values.exports.get(rule_id, frozenset()):
            message = f"{stream.name}: the checks of {rule_id} do not export {value_id}"
            raise ProfileValueError(message)
        grouped: dict[str, list[str]] = {}
        for profile_id in selecting:
            try:
                value = profile_value(stream.values, profile_id, value_id)
            except ProfileValueError as error:
                message = f"{stream.name}: {error}"
                raise ProfileValueError(message) from error
            grouped.setdefault(value, []).append(profile_id.removeprefix(PROFILE_PREFIX))
        entries.extend(
            {
                "datastream": stream.name,
                "content_sha256": stream.values.content_sha256,
                "profiles": profiles,
                "value": chunks(value),
            }
            for value, profiles in sorted(grouped.items(), key=lambda item: item[1])
        )
    return entries
