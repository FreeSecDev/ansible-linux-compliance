"""SCAP Compliance Checker (SCC) scanner backend (ADR 0019, FREES-145).

The backend runs NIWC Atlantic's ``cscc`` 5.15, which the operator installed from
DISA, through :mod:`process` only. The process policy names the one fixed path
``/opt/scc/cscc``, permits exactly ``--version`` and one scan form,
``-o OPTIONS -u USERDIR -q -d``, and fixes ``TZ=UTC0`` for the child, so the
zone-less times that SCC writes are UTC. The collection never downloads,
installs, updates or registers SCC.

What SCC 5.15 does, observed in the CI image (ADR 0019, amendment of FREES-145):

- SCC scans only content that is installed in its own content database below
  ``/opt/scc/Resources/Content``. The operator installs the pinned stream with
  SCC's own installer, or uses a stream bundled with the pinned SCC release. The
  backend checks that the installed file has exactly the bytes of the verified
  private copy, before and after the scan. It never installs content.
- A per-run options file given with ``-o`` is honoured, but only without ``-dn``
  (with ``-dn`` SCC skips every stream as "modified") and only when it is a
  root-only file in a root-only directory (in a directory of another owner SCC
  spins without output). SCC rewrites the per-run file during the scan and
  leaves the installed ``options.xml`` unchanged.
- The exit status of ``cscc`` is 0 for failures too. A non-zero status, a
  timeout or a start failure is a failed run, and exit 0 proves nothing.

Per-run options
---------------

The backend writes the options file from :data:`OPTIONS_TEMPLATE`, a reviewed
list of every global setting that the SCC 5.15 options schema requires, in schema
order. ``downloadExternalFiles``, ``appCheckForUpdates`` and
``contentCheckForUpdates`` are ``0``; SSH transfer, SCC's own checklists and
reports, the summary viewer, OVAL, OCIL and CPE result files and deviations are
off; XCCDF and ARF results are kept and signature checks are on. The single
content entry is SCC's own record of the pinned stream, read from the installed
``options.xml`` (only the identifying fields, each checked against a strict
pattern), enabled with the requested profile.

Confirmation and completion
---------------------------

Writing the values is not enough, because SCC also reads its installed options
and may apply a configuration profile. After every scan the backend reads SCC's
application debug log (``-d``) and confirms (:func:`confirm_options`) that SCC
loaded the per-run file and no other, that no configuration profile was enabled,
and that SCC's own dump of the options it used shows the three values as ``0``.
The egress test of ADR 0019 ties this evidence to SCC's behaviour. Without the
confirmation the run is ``failed`` and every expected rule is ``error``.

A run is ``completed`` only when the user directory was created empty for this
run, the confirmation holds, exactly one session holds exactly one XCCDF results
file and one ARF file, the results parse through the hardened parser of
:mod:`openscap` (and :mod:`xmlsafe`), name the requested benchmark and profile,
carry ``start-time`` and ``end-time`` no earlier than the start of the run, and
the installed stream and the private copy did not change. Anything else is
``failed``, a timeout is ``timed_out``, and both report every expected rule as
``error``. Result values map through :func:`model.map_xccdf_result`: ``unknown``
and every unlisted value become ``error`` and ``notchecked`` stays
``notchecked``; nothing that SCC could not evaluate becomes ``pass``.

The XCCDF and ARF results are copied to ``results.xml`` and ``results-arf.xml``
in the output directory, where the audit records them as evidence. SCC's own
tree, with its debug logs and the rewritten options file, stays in the root-only
``scc`` directory below it and is not recorded as evidence. Tailoring (disabled
rules) and STIG to ComplianceAsCode mapping are FREES-146; checklist export is
FREES-147.
"""

from __future__ import annotations

import hashlib
import re
import stat
from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, NoReturn

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    model,
    openscap,
    process,
    scanner,
    xmlsafe,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

BACKEND_NAME: Final[str] = "scc"
EXECUTABLE: Final[str] = "cscc"
INSTALL_ROOT: Final[str] = str(Path(process.SCC_EXECUTABLE_PATH).parent)
EXECUTABLE_NAME: Final[str] = Path(process.SCC_EXECUTABLE_PATH).name
INSTALLED_OPTIONS_NAME: Final[str] = "options.xml"
CONTENT_DIRECTORY: Final[str] = "Resources/Content/SCAP12_Content"
WORK_DIRECTORY_NAME: Final[str] = "scc"
OPTIONS_FILE_NAME: Final[str] = "options.xml"
USER_DIRECTORY_NAME: Final[str] = "user"
RESULTS_FILE_NAME: Final[str] = openscap.RESULTS_FILE_NAME
ARF_FILE_NAME: Final[str] = openscap.ARF_FILE_NAME
DIRECTORY_MODE: Final[int] = 0o700
FILE_MODE: Final[int] = 0o600
UNKNOWN_VERSION: Final[str] = "unknown"
VERSION_TIMEOUT_SECONDS: Final[float] = 120.0
VERSION_MAX_OUTPUT_BYTES: Final[int] = 64 * 1024
MAX_OPTIONS_BYTES: Final[int] = 16 * 1024 * 1024
MAX_LOG_BYTES: Final[int] = 64 * 1024 * 1024
MAX_MESSAGE_LENGTH: Final[int] = 1024
MAX_SESSION_ENTRIES: Final[int] = 16
HASH_CHUNK_BYTES: Final[int] = 1024 * 1024
DUMP_PREFIX: Final[str] = "*"
CONFIRMED_ZERO: Final[tuple[str, ...]] = (
    "downloadExternalFiles",
    "appCheckForUpdates",
    "contentCheckForUpdates",
)
DEFAULT_CONFIGURATION_PROFILE: Final[str] = "default"


@dataclass(frozen=True)
class Release:
    """A pinned SCC release that the backend supports.

    Attributes:
        version: Version that ``cscc --version`` prints.
        executable_sha256: Published SHA-256 of ``/opt/scc/cscc``.
        expires: First day on which SCC refuses to be used (ADR 0019, open item 12).
    """

    version: str
    executable_sha256: str
    expires: date


SUPPORTED_RELEASES: Final[Mapping[str, Release]] = MappingProxyType(
    {
        "ba908a907b8cbef7a3c7b1d2cad65c1c255e6290ef2ac3dd8a98ba2163afce8d": Release(
            "5.15",
            "ba908a907b8cbef7a3c7b1d2cad65c1c255e6290ef2ac3dd8a98ba2163afce8d",
            date(2026, 11, 25),
        )
    }
)
SUPPORTED_BENCHMARKS: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
    {"xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG": ("ubuntu", "24.04")}
)
OPTIONS_TEMPLATE: Final[tuple[tuple[str, str], ...]] = (
    ("sccConfigProfile", DEFAULT_CONFIGURATION_PROFILE),
    ("sccConfigProfileMetaData", "freesecdev.linux_compliance per-run options"),
    ("selectedConfigProfile", ""),
    ("reviewType", "local"),
    ("offlineConfigPath", ""),
    ("hostName", ""),
    ("hostFile", ""),
    ("multiRemoteMode", "Host File"),
    ("remoteWindowsOU", ""),
    ("remoteWMIEnabled", "0"),
    ("alternateWMICredentials", "0"),
    ("ignoreCPEOVALResults", "0"),
    ("answerOCILwithSCAP", "1"),
    ("warnMissingOCILResults", "1"),
    ("filterSCAPContentPerFamily", "1"),
    ("downloadExternalFiles", "0"),
    ("forceOVAL510", "0"),
    ("shareDeviationsAndTailoringAcrossVersions", "0"),
    ("saveResultsForNotApplicableContent", "0"),
    ("ignoreRemoteFileSystems", "1"),
    ("ignoreCase", "0"),
    ("itemCreationThresholdEnabled", "1"),
    ("itemCreationThreshold", "50000"),
    ("failedItemThresholdEnabled", "1"),
    ("failedItemThreshold", "100"),
    ("maskPasswords", "1"),
    ("useGetpwent", "0"),
    ("ignoreFileExtendedACL", "1"),
    ("useOldUnixFileTest", "0"),
    ("onlyCollectSecurityPrinciplesThatHavePrivilegesAssigned", "1"),
    ("excludeNtuserFilesNotLoggedIntoExplorer", "1"),
    ("forceCreationOfNTuserItems", "1"),
    ("sortOCILQuestionsByDISACAT", "1"),
    ("customManualQuestionAutoAnswerDirectoryValue", "0"),
    ("customManualQuestionAutoAnswerDirectory", ""),
    ("backupManualQuestionResults", "0"),
    ("ignoreManualQuestionVersionChangesOnUpgrade", "1"),
    ("allSettingsHTMLReport", "0"),
    ("allSettingsTextReport", "0"),
    ("nonComplianceHTMLReport", "0"),
    ("nonComplianceTextReport", "0"),
    ("allSettingsSummaryHTMLReport", "0"),
    ("allSettingsSummaryTextReport", "0"),
    ("nonComplianceSummaryHTMLReport", "0"),
    ("nonComplianceSummaryTextReport", "0"),
    ("sortReportsBySeverity", "1"),
    ("limitCollectedItemsInReports", "1"),
    ("maxOVALCollectedItemsDefPass", "50"),
    ("maxOVALCollectedItemsDefFail", "100"),
    ("keepXCCDFXML", "1"),
    ("maxOVALCollectedItemsPerXCCDFResult", "100"),
    ("keepOVALXML", "0"),
    ("keepOCILXML", "0"),
    ("keepARFXML", "1"),
    ("saveDISACKL", "0"),
    ("saveDISACKLB", "0"),
    ("cklReportStyle", "0"),
    ("CKLMarking", "CUI"),
    ("CKLClassification", "UNCLASSIFIED"),
    ("primaryIPAddressPrefix", ""),
    ("keepCPEXML", "0"),
    ("enableSummaryViewer", "0"),
    ("summaryViewerMaxReports", "50000"),
    ("summaryViewerSort1", "Session"),
    ("summaryViewerSort2", "Stream"),
    ("summaryViewerSort3", "Host"),
    ("enableScanSessionDB", "1"),
    ("openWithSCC", "0"),
    ("keepScreenLogs", "0"),
    ("debugEnabled", "0"),
    ("suppress_warnings", "0"),
    ("sharedOptions", "1"),
    ("setRestrictedPermissions", "1"),
    ("customPathLocal", ""),
    ("dirApplicationLogsEnabled", "1"),
    ("dirAllSessionsEnabled", "1"),
    ("dirSessionEnabled", "1"),
    ("dirSessionResultsEnabled", "1"),
    ("dirSessionLogsEnabled", "1"),
    ("dirContentTypeEnabled", "1"),
    ("dirTargetNameEnabled", "0"),
    ("dirStreamNameEnabled", "0"),
    ("dirXMLEnabled", "1"),
    ("fileTargetNameEnabled", "1"),
    ("fileTargetDNSDomainEnabled", "0"),
    ("fileSCCVersionEnabled", "1"),
    ("fileTimestampEnabled", "1"),
    ("fileContentVersionEnabled", "1"),
    ("newerContentInstall", "0"),
    ("contentDevModeSkipValidation", "0"),
    ("validateContent", "0"),
    ("validateContentOnInstall", "1"),
    ("validateDigitalSignature", "1"),
    ("failOnXMLDSig", "1"),
    ("validateXMLResults", "0"),
    ("sshEnabled", "0"),
    ("deleteOnTransferSession", "0"),
    ("sshServer", ""),
    ("sshPortNumber", "22"),
    ("sshConnectionType", "1"),
    ("username", ""),
    ("sshUserPassword", ""),
    ("sshPrivateKey", ""),
    ("sshUserKeyFile", ""),
    ("sshKeyPassphrase", ""),
    ("sshServerDirectory", ""),
    ("sshHostKey", ""),
    ("summarySourceDirectory", ""),
    ("summaryDestinationDirectory", ""),
    ("openSummaryDestinationDirectory", "0"),
    ("computerListHistoricalHTMLReport", "0"),
    ("computerListHistoricalExcelReport", "0"),
    ("computerListHTMLReport", "0"),
    ("computerListExcelReport", "0"),
    ("siteSummaryHTMLReport", "0"),
    ("siteSummaryNonComplianceHTMLReport", "0"),
    ("siteSummaryExcelReport", "0"),
    ("siteSummaryNonComplianceExcelReport", "0"),
    ("detailSummarySourceDirectory", ""),
    ("detailSummaryDestinationDirectory", ""),
    ("openDetailSummaryDestinationDirectory", "0"),
    ("detailSummaryOVALSourceDirectory", ""),
    ("detailSummaryOVALDestinationDirectory", ""),
    ("openDetailSummaryOVALDestinationDirectory", "0"),
    ("allSettingsHTMLReportDetailSummary", "0"),
    ("allSettingsTextReportDetailSummary", "0"),
    ("nonComplianceHTMLReportDetailSummary", "0"),
    ("nonComplianceTextReportDetailSummary", "0"),
    ("allSettingsSummaryHTMLReportDetailSummary", "0"),
    ("allSettingsSummaryTextReportDetailSummary", "0"),
    ("nonComplianceSummaryHTMLReportDetailSummary", "0"),
    ("nonComplianceSummaryTextReportDetailSummary", "0"),
    ("deviationsEnabled", "0"),
    ("thresholdsEnabled", "1"),
    ("thresholdsProfile", "default"),
    ("thresholdsUnlockCode", ""),
    ("frequency", "2"),
    ("schedule", "12"),
    ("randomizeSSHTransfer", "0"),
    ("randomizeValue", "300"),
    ("timeout", "86400"),
    ("lastServiceScan", "0"),
    ("nextServiceScan", "0"),
    ("remoteScanHostCooldown", "30"),
    ("remoteBaseLocation_unix", "/opt"),
    ("remoteStartupTimeout", "5"),
    ("remoteMaxThreads", "30"),
    ("remoteMaxThreads32", "10"),
    ("remoteSSHAppWhitelist", "0"),
    ("httpProxyType", "0"),
    ("httpProxyURL", ""),
    ("appCheckForUpdates", "0"),
    ("appUpdateCheckFrequency", "20"),
    ("appUpdateLastCheck", "0"),
    ("appUpdateURL", ""),
    ("contentCheckForUpdates", "0"),
    ("contentUpdateCheckFrequency", "5"),
    ("contentUpdateLastCheck", "0"),
    ("includeDraftContent", "0"),
    ("httpIgnoreSSLErrors", "0"),
    ("contentRepository", ""),
    ("debugExcludeDateTime", "0"),
    ("debugTraceEnabled", "0"),
    ("maxLogFileSize", "50"),
    ("maximumRecentReports", "24"),
    ("freeSpaceThreshold", "200"),
    ("validationThreshold", "30"),
    ("externalCmdTimeout", "600"),
    ("version", "5.15"),
    ("timeStamp", "2026-10-26T00:00:00"),
    ("newInstall", "1"),
    ("registeredEmail", ""),
    ("registeredCode", ""),
    ("load", "1"),
    ("scan", "0"),
    ("expignore", "0"),
    ("showSeverityRoleTailoring", "0"),
    ("scap12DBFilepath", "/opt/scc/Resources/Content/DB/SCC_SCAP12_Content.db"),
    ("iaControlDBFilepath", ""),
    ("nvdcceFile", "nvdcce-0.1-feed.xml"),
    ("cciFile", "U_CCI_List.xml"),
    ("xCoordinate", "0"),
    ("yCoordinate", "0"),
    ("windowHeight", "0"),
    ("windowWidth", "0"),
)
ENTRY_FIELDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "stream": r"scap_[A-Za-z0-9_.-]{1,240}",
        "family": r"[A-Za-z0-9]{1,32}",
        "benchmarkID": r"[A-Za-z0-9_.-]{1,128}",
        "scapVersion": r"1\.[0-9]",
        "filepath": r"Resources/Content/SCAP12_Content/[A-Za-z0-9._+-]{1,128}",
        "checksumSCAP12": r"[0-9a-f]{64}",
        "version": r"[0-9][0-9.]{0,31}",
        "xccdf": r"scap_[A-Za-z0-9_.-]{1,240}",
    }
)
OVAL_COMPONENT: Final[str] = r"scap_[A-Za-z0-9_.-]{1,240}"
OVAL_VERSION: Final[str] = r"[0-9][0-9.]{0,15}"
MAX_OVAL_COMPONENTS: Final[int] = 8
RECORD_DEPTH: Final[int] = 3
FIELD_DEPTH: Final[int] = 4

_VERSION_LINE: Final[str] = r"scc version:\s*([0-9][0-9.]{0,15})\b"
_SESSION: Final[str] = r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}"
_APPLICATION_LOG: Final[str] = r"[A-Za-z0-9_.-]{1,200}_Debug_Log_001\.txt"
_ANY_APPLICATION_DEBUG_LOG: Final[str] = r".*_Debug_Log_[0-9]+\.txt"
_XCCDF_RESULTS: Final[str] = r"[A-Za-z0-9_.+-]{1,240}_XCCDF-Results_[A-Za-z0-9_.+-]{1,240}\.xml"
_ARF_RESULTS: Final[str] = r"[A-Za-z0-9_.+-]{1,240}_ARF_[A-Za-z0-9_.+-]{1,240}\.xml"
_LOG_LINE: Final[str] = r"[0-9]{2}:[0-9]{2}:[0-9]{2}\t\s*([A-Z]+)\t\s*(\S+)\t\s*([0-9]+)\t(.*)"
_OPTIONS_FILE: Final[str] = r"--- options file = (.*)"
_LOADING: Final[str] = r"Loading options from: (.*)"
_PROFILE_CHECK: Final[str] = r"checking to see if a config profile is enabled (.*)"
_SELECTED_PROFILE: Final[str] = r"selectedConfigProfile:(.*)"
_USING_PROFILE: Final[str] = r"\s*Using configuration profile: (.*)"
_DUMP_HEADER: Final[str] = r"\*\s+Contents of (.*):"
_DUMP_ELEMENT: Final[str] = r"\*\s+<([A-Za-z0-9_]+)>([^<]*)</\1>\s*"
_DUMP_EMPTY: Final[str] = r"\*\s+<([A-Za-z0-9_]+)/>\s*"
_EXPIRY: Final[str] = r"Software expires in (-?[0-9]+) days"
_ERROR_OUTCOMES: Final[frozenset[model.Outcome]] = frozenset(
    {model.Outcome.FAIL, model.Outcome.ERROR}
)


class OptionsConfirmationError(ValueError):
    """Raised when SCC's own record does not confirm the options of a run."""


class InstallationError(ValueError):
    """Raised when the SCC installation or its record of the stream is unusable."""


def _refuse(message: str) -> NoReturn:
    raise OptionsConfirmationError(message)


def _broken(message: str) -> NoReturn:
    raise InstallationError(message)


def _clip(value: object) -> str:
    return repr(str(value)[: model.MAX_ECHO_LENGTH])


def _clean(text: str, limit: int = MAX_MESSAGE_LENGTH) -> str:
    printable = "".join(c if c.isascii() and c.isprintable() else "?" for c in text)
    return printable.strip()[:limit]


def xml_escape(value: str) -> str:
    """Escape ``&``, ``<``, ``>``, ``"`` and ``'`` for XML text."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


@dataclass(frozen=True)
class InstalledContent:
    """SCC's record of one installed stream, from the installed ``options.xml``.

    Attributes:
        fields: The identifying fields of :data:`ENTRY_FIELDS`, validated.
        oval: ``(version, component)`` pairs of the OVAL components.
    """

    fields: Mapping[str, str]
    oval: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        """Validate every field against its pattern."""
        if set(self.fields) != set(ENTRY_FIELDS):
            _broken("SCC's record of the stream lacks identifying fields")
        for name, pattern in ENTRY_FIELDS.items():
            if re.fullmatch(pattern, self.fields[name]) is None:
                _broken(f"SCC's record of the stream has an invalid {name}")
        if not self.oval or len(self.oval) > MAX_OVAL_COMPONENTS:
            _broken("SCC's record of the stream has no or too many OVAL components")
        for version, component in self.oval:
            if (
                re.fullmatch(OVAL_VERSION, version) is None
                or re.fullmatch(OVAL_COMPONENT, component) is None
            ):
                _broken("SCC's record of the stream has an invalid OVAL component")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))


class _Records:
    """Receiver of :mod:`xmlsafe` events that collects ``content`` records."""

    def __init__(self) -> None:
        self.path: list[str] = []
        self.buffer: list[str] = []
        self.current: dict[str, str] | None = None
        self.oval: list[tuple[str, str]] = []
        self.oval_version = ""
        self.records: list[tuple[dict[str, str], tuple[tuple[str, str], ...]]] = []

    def start(self, name: str, attributes: dict[str, str]) -> None:
        self.path.append(name)
        self.buffer = []
        if self.path == ["options", "contents", "content"]:
            self.current = {}
            self.oval = []
        elif self.path[-2:] == ["oval_components", "oval"]:
            self.oval_version = attributes.get("version", "")

    def end(self, name: str) -> None:
        value = "".join(self.buffer).strip()
        current = self.current
        if current is not None and len(self.path) == FIELD_DEPTH and name in ENTRY_FIELDS:
            if name in current:
                _broken(f"SCC's record of the stream repeats {name}")
            current[name] = value
        elif current is not None and self.path[-2:] == ["oval_components", "oval"]:
            self.oval.append((self.oval_version, value))
        elif current is not None and len(self.path) == RECORD_DEPTH:
            self.records.append((current, tuple(self.oval)))
            self.current = None
        self.path.pop()
        self.buffer = []

    def text(self, data: str) -> None:
        self.buffer.append(data)


def read_installed_content(options_path: str, file_name: str) -> InstalledContent:
    """Return SCC's record of the installed stream ``file_name``.

    The installed ``options.xml`` is parsed through :mod:`xmlsafe`, and the
    single ``content`` record whose ``filepath`` is
    ``Resources/Content/SCAP12_Content/<file_name>`` is returned.

    Raises:
        InstallationError: If the file is unsafe, malformed or has no or more
            than one record for the stream.
    """
    records = _Records()
    try:
        xmlsafe.parse_chunks(
            xmlsafe.iter_file_chunks(options_path, MAX_OPTIONS_BYTES, subject="SCC options"),
            records,
            xmlsafe.XmlBounds(),
        )
    except xmlsafe.XmlSafetyError as error:
        _broken(f"the installed SCC options cannot be read: {error}")
    wanted = f"{CONTENT_DIRECTORY}/{file_name}"
    matches = [record for record in records.records if record[0].get("filepath") == wanted]
    if len(matches) != 1:
        _broken(
            f"SCC's installed options hold {len(matches)} records of {_clip(file_name)}, "
            "expected exactly one; install the pinned stream with SCC first"
        )
    return InstalledContent(matches[0][0], matches[0][1])


def options_document(content: InstalledContent, profile_id: str) -> str:
    """Return the per-run options document for ``content`` and ``profile_id``.

    Every value is escaped, although every value is either a reviewed constant or
    a field that matched a pattern without markup characters.
    """
    scanner.check_xccdf_id(profile_id, "profile", "profile_id")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<options>"]
    lines.extend(f"  <{name}>{xml_escape(value)}</{name}>" for name, value in OPTIONS_TEMPLATE)
    entry = [
        ("stream", content.fields["stream"]),
        ("family", content.fields["family"]),
        ("benchmarkID", content.fields["benchmarkID"]),
        ("scapVersion", content.fields["scapVersion"]),
        ("filepath", content.fields["filepath"]),
        ("selectedProfile", profile_id),
        ("checksumSCAP12", content.fields["checksumSCAP12"]),
        ("version", content.fields["version"]),
        ("xccdf", content.fields["xccdf"]),
    ]
    lines.append("  <contents>")
    lines.append("    <content>")
    lines.extend(f"      <{name}>{xml_escape(value)}</{name}>" for name, value in entry)
    lines.append("      <oval_components>")
    lines.extend(
        f'        <oval version="{xml_escape(version)}">{xml_escape(component)}</oval>'
        for version, component in content.oval
    )
    lines.append("      </oval_components>")
    lines.extend(
        f"      <{name}>{value}</{name}>"
        for name, value in (("enabled", "1"), ("review", "1"), ("resume", "0"), ("resumeFile", ""))
    )
    lines.extend(["    </content>", "  </contents>", "  <ovalContents></ovalContents>"])
    lines.extend(["  <ocilContents></ocilContents>", "</options>", ""])
    return "\n".join(lines)


def _messages(log_text: str) -> Iterator[tuple[str, str]]:
    for line in log_text.splitlines():
        match = re.fullmatch(_LOG_LINE, line)
        if match is not None:
            yield match.group(2), match.group(4)


def _all_equal(values: list[str], expected: str, what: str) -> None:
    if not values:
        _refuse(f"SCC's debug log does not record {what}")
    other = [value for value in values if value.strip() != expected]
    if other:
        _refuse(f"SCC's debug log records {what} as {_clip(other[0].strip())}, not the run's")


_RECORD_PATTERNS: Final[tuple[str, ...]] = (
    _OPTIONS_FILE,
    _LOADING,
    _PROFILE_CHECK,
    _SELECTED_PROFILE,
    _USING_PROFILE,
    _DUMP_HEADER,
)


def _log_records(log_text: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    records: dict[str, list[str]] = {pattern: [] for pattern in _RECORD_PATTERNS}
    values: dict[str, list[str]] = {}
    for _package, message in _messages(log_text):
        for pattern in _RECORD_PATTERNS:
            found = re.search(pattern, message)
            if found is not None:
                records[pattern].append(found.group(1))
        element = re.fullmatch(_DUMP_ELEMENT, message)
        empty = re.fullmatch(_DUMP_EMPTY, message)
        if element is not None:
            values.setdefault(element.group(1), []).append(element.group(2))
        elif empty is not None:
            values.setdefault(empty.group(1), []).append("")
    return records, values


def confirm_options(log_text: str, options_path: str) -> None:
    """Confirm from SCC's application debug log that the run used ``options_path``.

    The log must show, every time SCC records it, that SCC loaded
    ``options_path`` (``options file =`` and ``Loading options from:``), that it
    checked that file for a configuration profile and found none enabled
    (``selectedConfigProfile:`` empty, configuration profile ``default``), and it
    must hold exactly one dump of that file (``Contents of <file>:``) in which
    ``downloadExternalFiles``, ``appCheckForUpdates`` and
    ``contentCheckForUpdates`` each appear exactly once with the value ``0`` and
    ``selectedConfigProfile`` is empty.

    Raises:
        OptionsConfirmationError: If any of this does not hold.
    """
    records, values = _log_records(log_text)
    _all_equal(records[_OPTIONS_FILE], options_path, "the options file")
    _all_equal(records[_LOADING], options_path, "the options file that was loaded")
    _all_equal(
        records[_PROFILE_CHECK], options_path, "the file checked for a configuration profile"
    )
    _all_equal(records[_SELECTED_PROFILE], "", "the selected configuration profile")
    _all_equal(records[_USING_PROFILE], DEFAULT_CONFIGURATION_PROFILE, "the configuration profile")
    dumps = records[_DUMP_HEADER]
    if len(dumps) != 1:
        _refuse(f"SCC's debug log holds {len(dumps)} dumps of the options, expected one")
    _all_equal(dumps, options_path, "the dumped options file")
    for name in (*CONFIRMED_ZERO, "selectedConfigProfile"):
        expected = "" if name == "selectedConfigProfile" else "0"
        seen = values.get(name, [])
        if len(seen) != 1:
            _refuse(f"SCC's options dump holds {name} {len(seen)} times, expected once")
        if seen[0].strip() != expected:
            _refuse(f"SCC's options dump shows {name} as {_clip(seen[0])}")


def expiry_days(log_text: str) -> int | None:
    """Return the days to expiry that SCC logged, or ``None`` when it logged none."""
    found = [
        int(match.group(1))
        for _package, message in _messages(log_text)
        for match in [re.search(_EXPIRY, message)]
        if match is not None
    ]
    return min(found) if found else None


@dataclass(frozen=True)
class _Failure:
    status: model.ScanStatus
    message: str


@dataclass(frozen=True)
class _Facts:
    version: str
    source: str
    digest: str
    started: datetime
    finished: datetime


@dataclass(frozen=True)
class _Prepared:
    content: str
    digest: str
    installed: str
    record: InstalledContent
    release: Release


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(model.TIMESTAMP_FORMAT)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    for chunk in xmlsafe.iter_file_chunks(path, catalog.DEFAULT_MAX_BYTES):
        digest.update(chunk)
    return digest.hexdigest()


def _confine(base: str, candidate: str) -> str:
    try:
        return process.confined_path(base, candidate)
    except process.ProcessPolicyError as error:
        raise scanner.ScanRequestError(str(error)) from error


def _new_directory(path: Path, what: str) -> None:
    try:
        path.mkdir(mode=DIRECTORY_MODE)
    except FileExistsError as error:
        message = f"{what} already exists: {_clip(path.name)}"
        raise scanner.ScanRequestError(message) from error
    except OSError as error:
        message = f"{what} cannot be created: {error.strerror or 'error'}"
        raise scanner.ScanRequestError(message) from error
    path.chmod(DIRECTORY_MODE)


def _write_new_file(path: Path, text: str) -> str:
    data = text.encode("utf-8")
    with path.open("xb") as handle:
        path.chmod(FILE_MODE)
        handle.write(data)
    return hashlib.sha256(data).hexdigest()


def _copy_regular(source: Path, target: Path, max_bytes: int) -> None:
    with (
        xmlsafe.RegularFile(str(source), max_bytes, subject="results") as handle,
        target.open("xb") as copy,
    ):
        target.chmod(FILE_MODE)
        for chunk in xmlsafe.iter_handle_chunks(handle, max_bytes, subject="results"):
            copy.write(chunk)


def _is_real(path: Path, kind: Callable[[int], bool]) -> bool:
    try:
        return kind(path.lstat().st_mode)
    except OSError:
        return False


def _entries(directory: Path, pattern: str, kind: Callable[[int], bool]) -> list[Path]:
    if not _is_real(directory, stat.S_ISDIR):
        return []
    entries = sorted(directory.iterdir())[: MAX_SESSION_ENTRIES + 1]
    return [
        entry
        for entry in entries
        if re.fullmatch(pattern, entry.name) is not None and _is_real(entry, kind)
    ]


def _single(entries: list[Path], what: str) -> Path | str:
    if len(entries) != 1:
        return f"SCC wrote {len(entries)} {what}, expected exactly one"
    return entries[0]


class SccBackend:
    """Backend that evaluates a profile with ``cscc`` (SCC 5.15).

    ``runner``, ``clock``, ``limits`` and ``install_root`` are seams for unit
    tests. Production code uses the defaults, and none is reachable from module
    arguments: the registry factory takes only :class:`scanner.ScanSettings`.
    """

    def __init__(
        self,
        settings: scanner.ScanSettings,
        *,
        runner: Callable[[process.CommandSpec], process.CommandResult] | None = None,
        clock: Callable[[], datetime] | None = None,
        limits: openscap.XmlLimits | None = None,
        install_root: str | None = None,
    ) -> None:
        """Create a backend with fixed settings."""
        self._settings = settings
        self._runner = process.run if runner is None else runner
        self._clock = _utc_now if clock is None else clock
        self._limits = openscap.XmlLimits() if limits is None else limits
        self._install_root = INSTALL_ROOT if install_root is None else install_root

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        """Evaluate ``request.profile_id`` with SCC and return the normalized scan run.

        Raises:
            ScanRequestError: If the request asks for something the backend
                never does: tailoring, a benchmark without an SCC pin, a host
                for which the benchmark is not made, or an unsafe path.
        """
        self._check_request(request)
        content = _confine(self._settings.content_root, request.content_path)
        try:
            digest = _sha256(content)
        except xmlsafe.XmlSafetyError as error:
            message = f"content is not a readable regular file: {error}"
            raise scanner.ScanRequestError(message) from error
        output = Path(_confine(self._settings.output_root, request.output_dir))
        _new_directory(output, "output directory")
        started = self._clock()
        prepared = self._prepare(content, digest)
        version = UNKNOWN_VERSION
        if isinstance(prepared, _Prepared):
            version = prepared.release.version
            outcome = self._scan(request, prepared, output, started)
        else:
            outcome = prepared
        finished = max(started, self._clock())
        facts = _Facts(version, Path(content).name, digest, started, finished)
        return _build_run(request, outcome, facts)

    @staticmethod
    def _check_request(request: scanner.ScanRequest) -> None:
        if request.tailoring_path is not None:
            message = (
                "the scc backend does not support disabled rules yet; SCC tailoring is FREES-146"
            )
            raise scanner.ScanRequestError(message)
        platform = SUPPORTED_BENCHMARKS.get(request.benchmark_id)
        if platform is None:
            message = f"no SCC benchmark is pinned for {_clip(request.benchmark_id)}"
            raise scanner.ScanRequestError(message)
        host = (request.host.distribution_id, request.host.distribution_version)
        if host != platform:
            message = (
                f"the pinned SCC benchmark is for {platform[0]} {platform[1]}, not for "
                f"{_clip(host[0])} {_clip(host[1])}; no SCC benchmark is pinned for that "
                "release, and a host is never scanned with the content of another release"
            )
            raise scanner.ScanRequestError(message)

    def _prepare(self, content: str, digest: str) -> _Prepared | _Failure:
        root = self._install_root
        name = Path(content).name
        try:
            executable = _sha256(str(Path(root) / EXECUTABLE_NAME))
            installed = catalog.vetted_content_path(str(Path(root) / CONTENT_DIRECTORY / name))
            installed_digest = _sha256(installed)
            options = catalog.vetted_content_path(str(Path(root) / INSTALLED_OPTIONS_NAME))
            record = read_installed_content(options, name)
        except (xmlsafe.XmlSafetyError, catalog.CatalogError, InstallationError) as error:
            return _Failure(
                model.ScanStatus.FAILED, _clean(f"the SCC installation is unusable: {error}")
            )
        release = SUPPORTED_RELEASES.get(executable)
        if release is None:
            message = (
                f"{process.SCC_EXECUTABLE_PATH} has SHA-256 {executable}, which is not a "
                "pinned SCC release"
            )
            return _Failure(model.ScanStatus.FAILED, message)
        if installed_digest != digest:
            message = (
                f"the stream installed in SCC has SHA-256 {installed_digest}, not the pinned "
                f"{digest}"
            )
            return _Failure(model.ScanStatus.FAILED, message)
        if self._clock().date() >= release.expires:
            message = f"SCC {release.version} expired on {release.expires.isoformat()}"
            return _Failure(model.ScanStatus.FAILED, message)
        return _Prepared(content, digest, installed, record, release)

    def _probe_version(self, release: Release) -> _Failure | None:
        spec = process.CommandSpec(
            EXECUTABLE, ("--version",), VERSION_TIMEOUT_SECONDS, VERSION_MAX_OUTPUT_BYTES
        )
        try:
            result = self._runner(spec)
        except process.ProcessError as error:
            return _Failure(model.ScanStatus.FAILED, _clean(f"cscc is not available: {error}"))
        if result.timed_out:
            return _Failure(model.ScanStatus.TIMED_OUT, "cscc --version timed out")
        match = re.search(_VERSION_LINE, result.stdout.decode("utf-8", "replace"))
        if result.returncode != 0 or match is None or match.group(1) != release.version:
            message = f"cscc --version does not report SCC {release.version}"
            return _Failure(model.ScanStatus.FAILED, message)
        return None

    def _scan(
        self,
        request: scanner.ScanRequest,
        prepared: _Prepared,
        output: Path,
        started: datetime,
    ) -> openscap.ParsedResults | _Failure:
        probe = self._probe_version(prepared.release)
        if probe is not None:
            return probe
        work = output / WORK_DIRECTORY_NAME
        user = work / USER_DIRECTORY_NAME
        options = work / OPTIONS_FILE_NAME
        _new_directory(work, "SCC work directory")
        _new_directory(user, "SCC user directory")
        _write_new_file(options, options_document(prepared.record, request.profile_id))
        spec = process.CommandSpec(
            EXECUTABLE,
            ("-o", str(options), "-u", str(user), "-q", "-d"),
            self._settings.timeout_seconds,
        )
        try:
            result = self._runner(spec)
        except process.ProcessError as error:
            return _Failure(model.ScanStatus.FAILED, _clean(f"cscc could not run: {error}"))
        if result.timed_out:
            message = f"cscc exceeded the timeout of {self._settings.timeout_seconds} seconds"
            return _Failure(model.ScanStatus.TIMED_OUT, message)
        if result.returncode != 0:
            return _Failure(model.ScanStatus.FAILED, f"cscc exited with status {result.returncode}")
        outcome = self._collect(request, user, str(options), output, started)
        unchanged = (
            _sha256(prepared.installed) == prepared.digest
            and _sha256(prepared.content) == prepared.digest
        )
        if isinstance(outcome, openscap.ParsedResults) and not unchanged:
            return _Failure(model.ScanStatus.FAILED, "the content changed during the scan")
        return outcome

    def _confirm(self, user: Path, options: str) -> _Failure | None:
        logs = user / "ApplicationLogs"
        every = _entries(logs, _ANY_APPLICATION_DEBUG_LOG, stat.S_ISREG)
        found = _single(_entries(logs, _APPLICATION_LOG, stat.S_ISREG), "application debug logs")
        if isinstance(found, str) or len(every) != 1:
            return _Failure(
                model.ScanStatus.FAILED,
                "the options of the run are not confirmed: SCC wrote no single application "
                "debug log",
            )
        try:
            data = b"".join(xmlsafe.iter_file_chunks(str(found), MAX_LOG_BYTES, subject="log"))
            text = data.decode("utf-8", "replace")
            confirm_options(text, options)
        except (xmlsafe.XmlSafetyError, OptionsConfirmationError) as error:
            return _Failure(
                model.ScanStatus.FAILED,
                _clean(f"the options of the run are not confirmed: {error}"),
            )
        days = expiry_days(text)
        if days is not None and days <= 0:
            return _Failure(model.ScanStatus.FAILED, "SCC reports that it has expired")
        return None

    @staticmethod
    def _results(user: Path) -> tuple[Path, Path] | _Failure:
        session = _single(_entries(user / "Sessions", _SESSION, stat.S_ISDIR), "scan sessions")
        if isinstance(session, str):
            return _Failure(model.ScanStatus.FAILED, session)
        xml = session / "Results" / "SCAP" / "XML"
        xccdf = _single(_entries(xml, _XCCDF_RESULTS, stat.S_ISREG), "XCCDF results files")
        if isinstance(xccdf, str):
            return _Failure(model.ScanStatus.FAILED, xccdf)
        arf = _single(_entries(xml, _ARF_RESULTS, stat.S_ISREG), "ARF results files")
        if isinstance(arf, str):
            return _Failure(model.ScanStatus.FAILED, arf)
        return xccdf, arf

    def _collect(
        self,
        request: scanner.ScanRequest,
        user: Path,
        options: str,
        output: Path,
        started: datetime,
    ) -> openscap.ParsedResults | _Failure:
        confirmation = self._confirm(user, options)
        if confirmation is not None:
            return confirmation
        located = self._results(user)
        if isinstance(located, _Failure):
            return located
        results = output / RESULTS_FILE_NAME
        try:
            _copy_regular(located[0], results, self._settings.max_result_bytes)
            _copy_regular(located[1], output / ARF_FILE_NAME, self._settings.max_result_bytes)
            parsed = openscap.read_results(
                str(results), self._settings.max_result_bytes, limits=self._limits, assume_utc=True
            )
        except (xmlsafe.XmlSafetyError, openscap.XccdfParseError) as error:
            return _Failure(model.ScanStatus.FAILED, _clean(f"results rejected: {error}"))
        return _verify(request, parsed, _format(started))


def _build_run(
    request: scanner.ScanRequest, outcome: openscap.ParsedResults | _Failure, facts: _Facts
) -> model.ScanRun:
    info = model.ScannerInfo(BACKEND_NAME, facts.version)
    if isinstance(outcome, openscap.ParsedResults):
        try:
            return model.ScanRun(
                run_id=request.run_id,
                started_at=outcome.started_at,
                finished_at=outcome.finished_at,
                host=request.host,
                scanner=info,
                content=model.Provenance(facts.source, outcome.benchmark_version, facts.digest),
                benchmark_id=request.benchmark_id,
                profile_id=request.profile_id,
                status=model.ScanStatus.COMPLETED,
                error_message=None,
                findings=outcome.findings,
            )
        except model.ModelError as error:
            outcome = _Failure(
                model.ScanStatus.FAILED, _clean(f"results rejected by the model: {error}")
            )
    return model.ScanRun(
        run_id=request.run_id,
        started_at=_format(facts.started),
        finished_at=_format(facts.finished),
        host=request.host,
        scanner=info,
        content=model.Provenance(facts.source, UNKNOWN_VERSION, facts.digest),
        benchmark_id=request.benchmark_id,
        profile_id=request.profile_id,
        status=outcome.status,
        error_message=outcome.message,
        findings=tuple(
            _error_finding(rule_id, outcome.message) for rule_id in request.expected_rule_ids
        ),
    )


def _verify(
    request: scanner.ScanRequest, parsed: openscap.ParsedResults, run_start: str
) -> openscap.ParsedResults | _Failure:
    expected_ids = set(request.expected_rule_ids)
    kept = tuple(
        finding
        for finding in parsed.findings
        if finding.rule_id in expected_ids or model.ResultFlag.NOTSELECTED not in finding.flags
    )
    reported = {finding.rule_id for finding in kept}
    missing = tuple(
        _error_finding(rule_id, "the results contain no rule-result for this rule")
        for rule_id in request.expected_rule_ids
        if rule_id not in reported
    )
    unexpected = len(reported - expected_ids)
    problem = None
    if parsed.profile_id != request.profile_id:
        problem = "the results are for a different profile than requested"
    elif parsed.benchmark_id != request.benchmark_id:
        problem = "the results are for a different benchmark than requested"
    elif unexpected:
        problem = f"the results contain {unexpected} rule(s) that the profile does not select"
    elif parsed.started_at < run_start:
        problem = "the results started before this run, so they are not this run's"
    elif parsed.finished_at < parsed.started_at:
        problem = "the results end before they start"
    if problem is not None:
        return _Failure(model.ScanStatus.FAILED, problem)
    return replace(parsed, findings=(*kept, *missing))


def _error_finding(rule_id: str, message: str) -> model.Finding:
    return model.Finding(
        rule_id=rule_id,
        outcome=model.Outcome.ERROR,
        evaluated_outcome=model.Outcome.ERROR,
        severity=model.Severity.UNKNOWN,
        message=message,
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(),
    )


def create_backend(settings: scanner.ScanSettings) -> SccBackend:
    """Create the production SCC backend for ``settings``."""
    return SccBackend(settings)


def register(target: scanner.BackendRegistry) -> None:
    """Register the SCC backend in ``target`` under ``scc``."""
    target.register(BACKEND_NAME, create_backend)
