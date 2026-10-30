"""Watch NIWC Atlantic's SCC release record and keep one issue per finding (ADR 0019, FREES-176).

The tool reads ``scc_release.xml`` from NIWC Atlantic's ``scap-scc`` repository over
HTTPS, parses it with the hardened reader of ``tools.reporting.xmlsafe`` (no DTD, no
entities, bounded size, depth and element count) and compares its version with the
pinned ``SCC_VERSION``. It never downloads an SCC bundle: the release record is the
only file it fetches, it follows no redirect, and the only other host it talks to is
the GitHub API of this repository.

Findings:

* The release record names a version other than the pin. One issue labelled
  ``scc-release`` names that version and links the upgrade procedure of ADR 0019.
* The pinned release is in its last ``WARNING_DAYS`` days. One issue labelled
  ``scc-expiry`` names the expiry and the fallback. From ``HARD_STOP_DAYS`` days
  before ``SCC_EXPIRES``, when ``make scc-expiry-check`` stops the SCC path, the
  tool also exits 1, so the scheduled run fails.

An issue is found again by the marker that starts its body, among all issues of the
repository that the workflow's bot opened, whatever their state and labels, so removing
a label cannot cause a duplicate. While the finding holds, the issue is brought up to
date on every run: its title and body are rewritten, a closed issue is reopened and a
removed label is put back. Only when no such issue exists is a new one created, so a
finding never has two issues. Once the finding no longer holds (the pin was bumped, or
the expiry is not near any more) the open issue is closed. A release finding is only
judged when the release record could be read. Without ``--manage-issues true`` the tool
only reports.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import ssl
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Final, cast
from urllib.parse import quote, urlsplit

from tools.reporting.common import InvalidInputError
from tools.reporting.xmlsafe import parse_xml

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

RELEASE_RECORD_URL: Final[str] = (
    "https://raw.githubusercontent.com/niwc-atlantic/scap-scc/main/scc_release.xml"
)
GITHUB_API: Final[str] = "https://api.github.com"
ADR_PATH: Final[str] = "docs/adr/0019-scc-scanner-backend-and-ci-image.md"
UPGRADE_ANCHOR: Final[str] = "#7-version-updates-manual-pin-bump"
FALLBACK_ANCHOR: Final[str] = "#amendment-2026-10-30-release-watch-and-expiry-fallback-frees-176"
RELEASE_LABEL: Final[str] = "scc-release"
EXPIRY_LABEL: Final[str] = "scc-expiry"
LABEL_COLOR: Final[str] = "b60205"
LABEL_DESCRIPTIONS: Final[dict[str, str]] = {
    RELEASE_LABEL: "The SCC release record names a version other than the pin (ADR 0019)",
    EXPIRY_LABEL: "The pinned SCC release is about to expire (ADR 0019)",
}
MARKER_PREFIX: Final[str] = "<!-- scc-release-watch:"
MARKER_KINDS: Final[dict[str, str]] = {RELEASE_LABEL: "release", EXPIRY_LABEL: "expiry"}
BOT_LOGIN: Final[str] = "github-actions[bot]"
WARNING_DAYS: Final[int] = 21
HARD_STOP_DAYS: Final[int] = 7
PUBLICATION_WAIT_DAYS: Final[int] = 7
MAX_RECORD_BYTES: Final[int] = 64 * 1024
MAX_API_BYTES: Final[int] = 8 * 1024 * 1024
TIMEOUT_SECONDS: Final[float] = 30.0
PAGE_SIZE: Final[int] = 100
MAX_PAGES: Final[int] = 10
HTTP_OK: Final[int] = 200
HTTP_CREATED: Final[int] = 201
HTTP_NOT_FOUND: Final[int] = 404
HTTP_UNPROCESSABLE: Final[int] = 422
EXIT_OK: Final[int] = 0
EXIT_HARD_STOP: Final[int] = 1
EXIT_ERROR: Final[int] = 2
USER_AGENT: Final[str] = "freesecdev-scc-release-watch"
VERSION: Final[re.Pattern[str]] = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}")
TIMESTAMP: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
)
REPOSITORY: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
TOKEN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.-]{20,255}")


class WatchError(Exception):
    """Raised when the release record or the GitHub API cannot be used safely."""


class Phase(Enum):
    """Where the pinned release stands relative to ``SCC_EXPIRES``."""

    CURRENT = "current"
    WARNING = "warning"
    HARD_STOP = "hard_stop"


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """One HTTPS request: method, absolute URL, headers and an optional body."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None = None


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """The status and the bounded body of a response."""

    status: int
    body: bytes


Transport = Callable[[HttpRequest, int], HttpResponse]


@dataclass(frozen=True, slots=True)
class Release:
    """The version and publication time that the release record names."""

    version: str
    published: str | None


@dataclass(frozen=True, slots=True)
class Finding:
    """An issue that must exist: its label, the body marker that finds it, title and body."""

    label: str
    marker: str
    title: str
    body: str


def https_transport(request: HttpRequest, limit: int) -> HttpResponse:
    """Send ``request`` over HTTPS with a verified certificate, no redirects and a timeout.

    Raises:
        WatchError: For a URL that is not plain HTTPS, a transport failure, or a body
            larger than ``limit`` bytes.
    """
    parts = urlsplit(request.url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.port is not None
    ):
        message = "only plain HTTPS URLs without credentials or ports are allowed"
        raise WatchError(message)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    connection = http.client.HTTPSConnection(
        parts.hostname, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context()
    )
    try:
        connection.request(request.method, target, body=request.body, headers=dict(request.headers))
        response = connection.getresponse()
        status = response.status
        body = response.read(limit + 1)
    except (OSError, http.client.HTTPException) as error:
        message = f"the request to {parts.hostname} failed ({type(error).__name__})"
        raise WatchError(message) from None
    finally:
        connection.close()
    if len(body) > limit:
        message = f"the response from {parts.hostname} is larger than {limit} bytes"
        raise WatchError(message)
    return HttpResponse(status, body)


def version_key(version: str) -> tuple[int, ...]:
    """Return the numeric parts of a validated version for comparison.

    Trailing zero components are dropped, so ``5.15.0`` and ``5.15`` compare equal.
    """
    if VERSION.fullmatch(version) is None:
        message = f"not an SCC version: {version!r}"
        raise WatchError(message)
    parts = [int(part) for part in version.split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _single_text(root_children: list[tuple[str, str]], name: str) -> str | None:
    values = [text.strip() for tag, text in root_children if tag == name]
    if len(values) > 1:
        message = f"the SCC release record has {len(values)} {name} elements"
        raise WatchError(message)
    return values[0] if values else None


def parse_release_record(data: bytes) -> Release:
    """Read the version and publication time from the bytes of ``scc_release.xml``.

    Raises:
        WatchError: For malformed or unsafe XML, another root element, or a missing,
            repeated or malformed version or time stamp.
    """
    try:
        root = parse_xml(data)
    except InvalidInputError as error:
        message = f"the SCC release record is not usable: {error}"
        raise WatchError(message) from None
    if root.tag != "scc":
        message = "the SCC release record does not have the root element scc"
        raise WatchError(message)
    children = [(child.tag, child.text) for child in root.children]
    version = _single_text(children, "version")
    if version is None or VERSION.fullmatch(version) is None:
        message = "the SCC release record has no valid version"
        raise WatchError(message)
    published = _single_text(children, "timeStamp")
    if published is not None and TIMESTAMP.fullmatch(published) is None:
        message = "the SCC release record has a malformed timeStamp"
        raise WatchError(message)
    return Release(version, published)


def fetch_release(transport: Transport) -> Release:
    """Fetch and parse the release record; nothing else is downloaded.

    Raises:
        WatchError: When the record cannot be fetched or parsed.
    """
    request = HttpRequest(
        "GET",
        RELEASE_RECORD_URL,
        {"Accept": "application/xml", "Accept-Encoding": "identity", "User-Agent": USER_AGENT},
    )
    response = transport(request, MAX_RECORD_BYTES)
    if response.status != HTTP_OK:
        message = f"the SCC release record returned HTTP status {response.status}"
        raise WatchError(message)
    return parse_release_record(response.body)


def expiry_phase(expires: date, today: date) -> Phase:
    """Return the phase of the pinned release on ``today``.

    ``HARD_STOP`` starts ``HARD_STOP_DAYS`` before ``expires``, the day from which
    ``make scc-expiry-check`` fails; ``WARNING`` starts ``WARNING_DAYS`` before it.
    """
    if today >= expires - timedelta(days=HARD_STOP_DAYS):
        return Phase.HARD_STOP
    if today >= expires - timedelta(days=WARNING_DAYS):
        return Phase.WARNING
    return Phase.CURRENT


def _adr_link(repository: str, anchor: str) -> str:
    return f"https://github.com/{repository}/blob/main/{ADR_PATH}{anchor}"


def _footer(repository: str) -> str:
    return (
        "Opened by the scheduled SCC release watch (`make scc-release-watch`, "
        "`.github/workflows/scc-release-watch.yml`). The watch reads only NIWC Atlantic's "
        "release record and never downloads SCC. It finds this issue again by the marker "
        "above, rewrites it while the finding holds, closes it when the finding no longer holds, "
        "and never opens a second one. "
        f"Fallback while no newer release exists: {_adr_link(repository, FALLBACK_ANCHOR)}"
    )


def release_finding(pinned: str, release: Release, repository: str) -> Finding | None:
    """Return the issue for a release record that names another version, else ``None``."""
    if version_key(release.version) == version_key(pinned):
        return None
    marker = f"{MARKER_PREFIX} release {release.version} -->"
    published = release.published or "an unrecorded time"
    if version_key(release.version) > version_key(pinned):
        title = f"SCC {release.version} is released: bump the pin from {pinned}"
        action = (
            f"Bump the pin with the upgrade procedure of ADR 0019: "
            f"{_adr_link(repository, UPGRADE_ANCHOR)}. Wait {PUBLICATION_WAIT_DAYS} days "
            "after publication unless the release fixes a security issue."
        )
    else:
        title = f"SCC release record names {release.version}, older than the pinned {pinned}"
        action = (
            "The release record went back to an older version. Check NIWC Atlantic's "
            "announcements before changing anything; never downgrade the pin without review. "
            f"Upgrade procedure: {_adr_link(repository, UPGRADE_ANCHOR)}."
        )
    body = (
        f"{marker}\n\n"
        f"NIWC Atlantic's SCC release record (`{RELEASE_RECORD_URL}`) names SCC "
        f"**{release.version}**, published {published}. This repository pins SCC {pinned} "
        "in `extensions/ci/scc/scc.pins`.\n\n"
        f"{action}\n\n{_footer(repository)}\n"
    )
    return Finding(RELEASE_LABEL, marker, title, body)


def expiry_finding(pinned: str, expires: date, phase: Phase, repository: str) -> Finding | None:
    """Return the issue for a pinned release in its warning or hard-stop phase, else ``None``."""
    if phase is Phase.CURRENT:
        return None
    stop = expires - timedelta(days=HARD_STOP_DAYS)
    marker = f"{MARKER_PREFIX} expiry {pinned} {expires.isoformat()} -->"
    title = f"SCC {pinned} expires on {expires.isoformat()}: the SCC path stops on {stop}"
    body = (
        f"{marker}\n\n"
        f"The pinned SCC {pinned} expires on {expires.isoformat()} (`SCC_EXPIRES` in "
        f"`extensions/ci/scc/scc.pins`). From {stop.isoformat()}, `make scc-expiry-check` "
        "refuses to build or run it: the push and scheduled runs of `ci.yml` fail, this watch "
        "fails every day, and pull requests and merge groups that touch an SCC path report "
        "the smoke test as not run instead of blocking the queue.\n\n"
        f"Bump the pin to a newer release as soon as NIWC Atlantic publishes one: "
        f"{_adr_link(repository, UPGRADE_ANCHOR)}.\n\n{_footer(repository)}\n"
    )
    return Finding(EXPIRY_LABEL, marker, title, body)


class GitHubIssues:
    """The issues and labels of one repository through the GitHub REST API."""

    def __init__(self, repository: str, token: str, transport: Transport) -> None:
        """Bind the client to a validated repository and token.

        Raises:
            WatchError: For a malformed repository name or token.
        """
        if REPOSITORY.fullmatch(repository) is None or ".." in repository:
            message = "GITHUB_REPOSITORY must be owner/name"
            raise WatchError(message)
        if TOKEN.fullmatch(token) is None:
            message = "GH_TOKEN is missing or malformed"
            raise WatchError(message)
        self._repository = repository
        self._token = token
        self._transport = transport

    def _call(
        self, method: str, path: str, payload: object | None, expected: frozenset[int]
    ) -> tuple[int, object]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        url = f"{GITHUB_API}/repos/{self._repository}{path}"
        response = self._transport(HttpRequest(method, url, headers, body), MAX_API_BYTES)
        if response.status not in expected:
            message = (
                f"GitHub API {method} {path.partition('?')[0]} returned HTTP {response.status}"
            )
            raise WatchError(message)
        if not response.body:
            return response.status, None
        try:
            return response.status, cast("object", json.loads(response.body))
        except (UnicodeDecodeError, json.JSONDecodeError):
            message = f"GitHub API {method} {path.partition('?')[0]} returned malformed JSON"
            raise WatchError(message) from None

    def ensure_label(self, name: str) -> None:
        """Create the label ``name`` unless it exists."""
        status, _ = self._call(
            "GET", f"/labels/{quote(name)}", None, frozenset({HTTP_OK, HTTP_NOT_FOUND})
        )
        if status == HTTP_NOT_FOUND:
            label = {"name": name, "color": LABEL_COLOR, "description": LABEL_DESCRIPTIONS[name]}
            self._call("POST", "/labels", label, frozenset({HTTP_CREATED, HTTP_UNPROCESSABLE}))

    def list_marked(self) -> list[IssueRef]:
        """Return every issue the watch's bot opened whose body starts with a watch marker.

        The listing covers all states and labels, so a removed label cannot hide an issue.
        Pull requests, issues of other authors and issues without the marker are skipped.

        Raises:
            WatchError: For an unexpected response, or more than ``MAX_PAGES`` pages.
        """
        found: list[IssueRef] = []
        for page in range(1, MAX_PAGES + 1):
            query = f"?state=all&per_page={PAGE_SIZE}&page={page}"
            _, listing = self._call("GET", f"/issues{query}", None, frozenset({HTTP_OK}))
            if not isinstance(listing, list):
                message = "GitHub API returned an issue listing that is not a list"
                raise WatchError(message)
            items = cast("list[object]", listing)
            for item in items:
                reference = _marked_issue(item)
                if reference is not None:
                    found.append(reference)
            if len(items) < PAGE_SIZE:
                return found
        message = f"more than {MAX_PAGES * PAGE_SIZE} issues need to be searched for a marker"
        raise WatchError(message)

    def create(self, finding: Finding) -> int:
        """Open a new issue for ``finding`` and return its number."""
        payload = {"title": finding.title, "body": finding.body, "labels": [finding.label]}
        _, created = self._call("POST", "/issues", payload, frozenset({HTTP_CREATED}))
        return _issue_number(created)

    def update(self, number: int, changes: Mapping[str, object]) -> None:
        """Apply ``changes`` (title, body, state, labels) to the issue ``number``."""
        self._call("PATCH", f"/issues/{number}", dict(changes), frozenset({HTTP_OK}))


@dataclass(frozen=True, slots=True)
class IssueRef:
    """An issue of the watch as listed: number, state, title, body and label names."""

    number: int
    state: str
    title: str
    body: str
    labels: tuple[str, ...]

    @property
    def marker(self) -> str:
        """The first line of the body, which is the marker."""
        return self.body.partition("\n")[0].strip()


def _issue_number(item: object) -> int:
    number = cast("dict[str, object]", item).get("number") if isinstance(item, dict) else None
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        message = "GitHub API returned an issue without a valid number"
        raise WatchError(message)
    return number


def _label_names(value: object) -> tuple[str, ...]:
    names: list[str] = []
    if isinstance(value, list):
        for entry in cast("list[object]", value):
            name = (
                cast("dict[str, object]", entry).get("name") if isinstance(entry, dict) else entry
            )
            if isinstance(name, str):
                names.append(name)
    return tuple(names)


def _marked_issue(item: object) -> IssueRef | None:
    if not isinstance(item, dict):
        message = "GitHub API returned an issue that is not an object"
        raise WatchError(message)
    issue = cast("dict[str, object]", item)
    body = issue.get("body")
    user = issue.get("user")
    login = cast("dict[str, object]", user).get("login") if isinstance(user, dict) else None
    if (
        "pull_request" in issue
        or login != BOT_LOGIN
        or not isinstance(body, str)
        or not body.startswith(MARKER_PREFIX)
    ):
        return None
    title, state = issue.get("title"), issue.get("state")
    return IssueRef(
        _issue_number(issue),
        state if isinstance(state, str) else "",
        title if isinstance(title, str) else "",
        body,
        _label_names(issue.get("labels")),
    )


def ensure_issue(issues: GitHubIssues, marked: Sequence[IssueRef], finding: Finding) -> str:
    """Make sure exactly one open, current issue carries ``finding``; return what was done.

    The issue is found by its marker alone, an open one before a closed one. It is
    rewritten when its title, body or labels differ, and reopened when it is closed.
    """
    issues.ensure_label(finding.label)
    matching = [issue for issue in marked if issue.marker == finding.marker]
    if not matching:
        return f"opened issue #{issues.create(finding)}: {finding.title}"
    issue = next((entry for entry in matching if entry.state == "open"), matching[0])
    changes: dict[str, object] = {}
    if issue.state != "open":
        changes["state"] = "open"
    if issue.title != finding.title:
        changes["title"] = finding.title
    if issue.body != finding.body:
        changes["body"] = finding.body
    if finding.label not in issue.labels:
        changes["labels"] = [*issue.labels, finding.label]
    if not changes:
        return f"issue #{issue.number} is already open and current: {finding.title}"
    issues.update(issue.number, changes)
    verb = "reopened and updated" if "state" in changes else "updated"
    return f"{verb} issue #{issue.number}: {finding.title}"


def close_stale(
    issues: GitHubIssues,
    marked: Sequence[IssueRef],
    findings: Sequence[Finding],
    judged: Sequence[str],
) -> list[str]:
    """Close the open issues of the ``judged`` labels whose marker no finding names any more."""
    current = {finding.marker for finding in findings}
    done: list[str] = []
    for label in judged:
        prefix = f"{MARKER_PREFIX} {MARKER_KINDS[label]} "
        for issue in marked:
            if issue.state != "open" or not issue.marker.startswith(prefix):
                continue
            if issue.marker not in current:
                issues.update(issue.number, {"state": "closed", "state_reason": "completed"})
                done.append(f"closed issue #{issue.number}: the finding no longer holds")
    return done


@dataclass(frozen=True, slots=True)
class WatchSettings:
    """The pin, the day to judge it on, and whether and where issues are managed."""

    pinned: str
    expires: date
    today: date
    manage_issues: bool
    repository: str
    token: str


def watch(settings: WatchSettings, transport: Transport) -> int:
    """Compare the release record with the pin, keep the issues and return the exit status.

    Raises:
        WatchError: For a malformed pinned version, before anything is fetched.

    Returns:
        ``EXIT_ERROR`` when the record or the API could not be used, otherwise
        ``EXIT_HARD_STOP`` inside the hard-stop phase and ``EXIT_OK`` before it.
    """
    version_key(settings.pinned)
    findings: list[Finding] = []
    judged = [EXPIRY_LABEL]
    errors: list[str] = []
    try:
        release = fetch_release(transport)
    except WatchError as error:
        errors.append(str(error))
    else:
        judged.append(RELEASE_LABEL)
        print(f"SCC release record: {release.version}; pinned: {settings.pinned}")
        finding = release_finding(settings.pinned, release, settings.repository)
        if finding is not None:
            findings.append(finding)
    phase = expiry_phase(settings.expires, settings.today)
    print(f"pinned SCC {settings.pinned} expires on {settings.expires}: {phase.value}")
    expiry = expiry_finding(settings.pinned, settings.expires, phase, settings.repository)
    if expiry is not None:
        findings.append(expiry)
    try:
        _report(settings, findings, judged, transport)
    except WatchError as error:
        errors.append(str(error))
    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    if errors:
        return EXIT_ERROR
    if phase is Phase.HARD_STOP:
        print(
            "error: the pinned SCC release is inside its hard stop; "
            "make scc-expiry-check refuses to build or run it",
            file=sys.stderr,
        )
        return EXIT_HARD_STOP
    return EXIT_OK


def _report(
    settings: WatchSettings,
    findings: list[Finding],
    judged: list[str],
    transport: Transport,
) -> None:
    if not settings.manage_issues:
        for finding in findings:
            print(f"finding (issues not managed): {finding.title}")
        if not findings:
            print("nothing to report")
        return
    issues = GitHubIssues(settings.repository, settings.token, transport)
    marked = issues.list_marked()
    for finding in findings:
        print(ensure_issue(issues, marked, finding))
    for line in close_stale(issues, marked, findings, judged):
        print(line)
    if not findings:
        print("nothing to report")


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        message = f"not a date in the form YYYY-MM-DD: {value!r}"
        raise argparse.ArgumentTypeError(message) from None


def main(
    argv: Sequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
    transport: Transport = https_transport,
) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description="Watch the SCC release record (ADR 0019).")
    parser.add_argument("--pinned-version", required=True)
    parser.add_argument("--expires", required=True, type=_date)
    parser.add_argument("--today", type=_date, default=datetime.now(tz=UTC).date())
    parser.add_argument("--manage-issues", choices=("true", "false"), default="false")
    arguments = parser.parse_args(argv)
    env = os.environ if environment is None else environment
    settings = WatchSettings(
        pinned=cast("str", arguments.pinned_version),
        expires=cast("date", arguments.expires),
        today=cast("date", arguments.today),
        manage_issues=arguments.manage_issues == "true",
        repository=env.get("GITHUB_REPOSITORY", "FreeSecDev/ansible-linux-compliance"),
        token=env.get("GH_TOKEN", ""),
    )
    try:
        return watch(settings, transport)
    except WatchError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
