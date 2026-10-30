"""The SCC release watch (ADR 0019 amendment of FREES-176).

The watch fetches only NIWC Atlantic's release record, parses it with the hardened
XML reader, compares it with the pin and keeps exactly one GitHub issue per finding.
A fake GitHub API holds issues and labels, so the duplicate check, the reopening of
a closed issue and the pagination run against the real client code.
"""

from __future__ import annotations

import http.client
import io
import json
import runpy
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import ClassVar, cast
from urllib.parse import parse_qs, urlsplit

import pytest

from tools.scc import release_watch as watch

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PINS = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "scc.pins"
CHECK_EXPIRY = REPOSITORY_ROOT / "tools" / "scc" / "check-expiry.sh"
EXPIRY_STATE = REPOSITORY_ROOT / "tools" / "scc" / "expiry-state.sh"
REPOSITORY = "FreeSecDev/ansible-linux-compliance"
TOKEN = "ghs_" + "a" * 36
EXPIRES = date(2026, 11, 25)
CURRENT_DAY = date(2026, 10, 30)
RECORD = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<scc>\n\t<version>{version}</version>\n'
    b"\t<timeStamp>2026-09-01T11:00:00</timeStamp>\n\t<releaseInfo>\n- Linux -\n"
    b"-- @someone [link](https://example.invalid)\n</releaseInfo>\n"
    b"\t<url>https://www.cyber.mil/stigs/SCAP/</url>\n</scc>\n"
)


def record(version: str = "5.15") -> bytes:
    return RECORD.replace(b"{version}", version.encode("ascii"))


@dataclass
class FakeGitHub:
    """A transport that serves the release record and a minimal GitHub issues API."""

    record_status: int = 200
    record_body: bytes = field(default_factory=record)
    record_error: str | None = None
    labels: set[str] = field(default_factory=set[str])
    issues: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    fail: dict[tuple[str, str], int] = field(default_factory=dict[tuple[str, str], int])
    requests: list[watch.HttpRequest] = field(default_factory=list[watch.HttpRequest])
    limits: list[int] = field(default_factory=list[int])

    def __call__(self, request: watch.HttpRequest, limit: int) -> watch.HttpResponse:
        self.requests.append(request)
        self.limits.append(limit)
        if request.url == watch.RELEASE_RECORD_URL:
            if self.record_error is not None:
                raise watch.WatchError(self.record_error)
            return watch.HttpResponse(self.record_status, self.record_body)
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        parts = urlsplit(request.url)
        assert f"{parts.scheme}://{parts.netloc}" == watch.GITHUB_API
        path = parts.path.removeprefix(f"/repos/{REPOSITORY}")
        failure = self.fail.get((request.method, path))
        if failure is not None:
            return watch.HttpResponse(failure, b"")
        return self._route(request, path, parse_qs(parts.query))

    def _route(
        self, request: watch.HttpRequest, path: str, query: dict[str, list[str]]
    ) -> watch.HttpResponse:
        payload = cast("dict[str, object]", json.loads(request.body)) if request.body else {}
        if request.method == "GET" and path.startswith("/labels/"):
            return watch.HttpResponse(
                200 if path.removeprefix("/labels/") in self.labels else 404, b"{}"
            )
        if request.method == "POST" and path == "/labels":
            self.labels.add(cast("str", payload["name"]))
            return watch.HttpResponse(201, b"{}")
        if request.method == "GET" and path == "/issues":
            return self._listing(query)
        if request.method == "POST" and path == "/issues":
            number = len(self.issues) + 1
            labels = cast("list[str]", payload["labels"])
            self.issues.append({**payload, "number": number, "state": "open", "labels": labels})
            return watch.HttpResponse(201, json.dumps({"number": number}).encode())
        number = int(path.removeprefix("/issues/"))
        self.issues[number - 1]["state"] = payload["state"]
        return watch.HttpResponse(200, b"{}")

    def _listing(self, query: dict[str, list[str]]) -> watch.HttpResponse:
        label, state = query["labels"][0], query["state"][0]
        page, size = int(query["page"][0]), int(query["per_page"][0])
        matching = [
            issue
            for issue in self.issues
            if issue["state"] == state and label in cast("list[str]", issue["labels"])
        ]
        return watch.HttpResponse(
            200, json.dumps(matching[(page - 1) * size : page * size]).encode()
        )

    def created(self) -> list[watch.HttpRequest]:
        return [
            request
            for request in self.requests
            if request.method == "POST" and request.url.endswith("/issues")
        ]


def settings(
    today: date = CURRENT_DAY, *, manage: bool = True, pinned: str = "5.15"
) -> watch.WatchSettings:
    return watch.WatchSettings(
        pinned=pinned,
        expires=EXPIRES,
        today=today,
        manage_issues=manage,
        repository=REPOSITORY,
        token=TOKEN,
    )


def test_the_release_record_is_parsed_without_its_free_text() -> None:
    release = watch.parse_release_record(record("5.16"))
    assert release == watch.Release("5.16", "2026-09-01T11:00:00")
    assert watch.parse_release_record(b"<scc><version> 5.14.1 </version></scc>") == watch.Release(
        "5.14.1", None
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"<scc><version>5.15</version>", "not usable"),
        (b"", "not usable"),
        (b"\xff\xfe<scc/>", "not usable"),
        (
            b'<!DOCTYPE scc [<!ENTITY v "5.16">]><scc><version>&v;</version></scc>',
            "not usable",
        ),
        (b'<!DOCTYPE scc SYSTEM "https://example.invalid/x.dtd"><scc/>', "not usable"),
        (b"<release><version>5.15</version></release>", "root element scc"),
        (b'<scc xmlns="urn:x"><version>5.15</version></scc>', "root element scc"),
        (b"<scc><timeStamp>2026-09-01T11:00:00</timeStamp></scc>", "no valid version"),
        (b"<scc><version>5.15; rm -rf /</version></scc>", "no valid version"),
        (b"<scc><version>v5.15</version></scc>", "no valid version"),
        (b"<scc><version>5</version></scc>", "no valid version"),
        (b"<scc><version></version></scc>", "no valid version"),
        (b"<scc><version>5.15</version><version>5.16</version></scc>", "2 version elements"),
        (b"<scc><version>5.15</version><timeStamp>soon</timeStamp></scc>", "malformed timeStamp"),
        (b"<scc><version>5.15</version>" + b"<timeStamp/>" * 2 + b"</scc>", "2 timeStamp elements"),
    ],
)
def test_a_malformed_or_unsafe_release_record_is_refused(data: bytes, message: str) -> None:
    with pytest.raises(watch.WatchError, match=message):
        watch.parse_release_record(data)


def test_a_deeply_nested_release_record_is_refused() -> None:
    nested = b"<scc>" + b"<a>" * 200 + b"</a>" * 200 + b"</scc>"
    with pytest.raises(watch.WatchError, match="not usable"):
        watch.parse_release_record(nested)


def test_the_watch_fetches_only_the_release_record_with_a_size_bound() -> None:
    github = FakeGitHub()
    assert watch.fetch_release(github) == watch.Release("5.15", "2026-09-01T11:00:00")
    assert [request.url for request in github.requests] == [watch.RELEASE_RECORD_URL]
    assert github.limits == [watch.MAX_RECORD_BYTES]
    assert github.requests[0].method == "GET"
    assert "Authorization" not in github.requests[0].headers


def test_the_release_record_url_names_no_download_host() -> None:
    assert watch.RELEASE_RECORD_URL.startswith("https://raw.githubusercontent.com/niwc-atlantic/")
    assert watch.RELEASE_RECORD_URL.endswith("/scc_release.xml")
    source = Path(watch.__file__).read_text(encoding="utf-8")
    assert "dl.dod.cyber.mil" not in source
    assert ".zip" not in source


@pytest.mark.parametrize("status", [301, 302, 403, 404, 500])
def test_a_release_record_that_is_not_served_fails(status: int) -> None:
    with pytest.raises(watch.WatchError, match=f"HTTP status {status}"):
        watch.fetch_release(FakeGitHub(record_status=status))


@pytest.mark.parametrize(
    ("released", "pinned", "newer"),
    [
        ("5.16", "5.15", True),
        ("5.15.1", "5.15", True),
        ("6.0", "5.15", True),
        ("5.14.1", "5.15", False),
    ],
)
def test_a_different_version_is_a_release_finding(released: str, pinned: str, newer: bool) -> None:
    finding = watch.release_finding(pinned, watch.Release(released, None), REPOSITORY)
    assert finding is not None
    assert finding.label == watch.RELEASE_LABEL
    assert finding.marker in finding.body
    assert released in finding.title
    assert ("is released" in finding.title) is newer
    assert ("older than" in finding.title) is not newer
    assert "an unrecorded time" in finding.body
    upgrade = f"https://github.com/{REPOSITORY}/blob/main/{watch.ADR_PATH}{watch.UPGRADE_ANCHOR}"
    assert upgrade in finding.body
    assert watch.FALLBACK_ANCHOR in finding.body


def test_the_same_version_is_no_release_finding() -> None:
    assert watch.release_finding("5.15", watch.Release("5.15", None), REPOSITORY) is None


def test_the_issue_body_carries_no_text_from_the_release_record() -> None:
    finding = watch.release_finding("5.15", watch.parse_release_record(record("5.16")), REPOSITORY)
    assert finding is not None
    assert "@someone" not in finding.body
    assert "example.invalid" not in finding.body
    assert "2026-09-01T11:00:00" in finding.body


@pytest.mark.parametrize("version", ["", "5", "5.x", "5.15.", "05.15.1.2.3", "5.15\n"])
def test_a_malformed_version_is_refused(version: str) -> None:
    with pytest.raises(watch.WatchError, match="not an SCC version"):
        watch.version_key(version)


@pytest.mark.parametrize(
    ("days_before_expiry", "phase"),
    [
        (60, watch.Phase.CURRENT),
        (22, watch.Phase.CURRENT),
        (21, watch.Phase.WARNING),
        (8, watch.Phase.WARNING),
        (7, watch.Phase.HARD_STOP),
        (0, watch.Phase.HARD_STOP),
        (-1, watch.Phase.HARD_STOP),
        (-400, watch.Phase.HARD_STOP),
    ],
)
def test_the_expiry_phase_turns_on_its_exact_days(
    days_before_expiry: int, phase: watch.Phase
) -> None:
    assert watch.expiry_phase(EXPIRES, EXPIRES - timedelta(days=days_before_expiry)) is phase


def test_the_pinned_expiry_starts_its_phases_on_the_documented_days() -> None:
    assert watch.expiry_phase(EXPIRES, date(2026, 11, 3)) is watch.Phase.CURRENT
    assert watch.expiry_phase(EXPIRES, date(2026, 11, 4)) is watch.Phase.WARNING
    assert watch.expiry_phase(EXPIRES, date(2026, 11, 17)) is watch.Phase.WARNING
    assert watch.expiry_phase(EXPIRES, date(2026, 11, 18)) is watch.Phase.HARD_STOP


def test_the_hard_stop_margin_matches_both_shell_scripts() -> None:
    for script in (CHECK_EXPIRY, EXPIRY_STATE):
        lines = script.read_text(encoding="utf-8").splitlines()
        assert f"readonly MARGIN_DAYS={watch.HARD_STOP_DAYS}" in lines, script


def test_the_expiry_finding_names_the_stop_and_the_fallback() -> None:
    assert watch.expiry_finding("5.15", EXPIRES, watch.Phase.CURRENT, REPOSITORY) is None
    for phase in (watch.Phase.WARNING, watch.Phase.HARD_STOP):
        finding = watch.expiry_finding("5.15", EXPIRES, phase, REPOSITORY)
        assert finding is not None
        assert finding.label == watch.EXPIRY_LABEL
        assert finding.title == "SCC 5.15 expires on 2026-11-25: the SCC path stops on 2026-11-18"
        assert finding.marker == "<!-- scc-release-watch: expiry 5.15 2026-11-25 -->"
        assert finding.body.startswith(finding.marker)
        assert watch.FALLBACK_ANCHOR in finding.body


def test_a_new_release_opens_exactly_one_issue_across_runs() -> None:
    github = FakeGitHub(record_body=record("5.16"))
    assert watch.watch(settings(), github) == watch.EXIT_OK
    assert watch.watch(settings(), github) == watch.EXIT_OK
    assert len(github.created()) == 1
    assert len(github.issues) == 1
    issue = github.issues[0]
    assert issue["title"] == "SCC 5.16 is released: bump the pin from 5.15"
    assert issue["labels"] == [watch.RELEASE_LABEL]
    assert watch.RELEASE_LABEL in github.labels


def test_a_closed_issue_is_reopened_not_duplicated() -> None:
    github = FakeGitHub(record_body=record("5.16"))
    watch.watch(settings(), github)
    github.issues[0]["state"] = "closed"
    assert watch.watch(settings(), github) == watch.EXIT_OK
    assert len(github.created()) == 1
    assert github.issues[0]["state"] == "open"
    patches = [request for request in github.requests if request.method == "PATCH"]
    assert [request.url.rsplit("/", 1)[-1] for request in patches] == ["1"]


def test_an_issue_is_found_by_its_marker_even_when_renamed() -> None:
    github = FakeGitHub(record_body=record("5.16"))
    watch.watch(settings(), github)
    github.issues[0]["title"] = "renamed by a maintainer"
    watch.watch(settings(), github)
    assert len(github.created()) == 1


def test_issues_without_the_marker_or_that_are_pull_requests_do_not_count() -> None:
    finding = watch.release_finding("5.15", watch.Release("5.16", None), REPOSITORY)
    assert finding is not None
    github = FakeGitHub(record_body=record("5.16"), labels={watch.RELEASE_LABEL})
    github.issues = [
        {"number": 1, "state": "open", "labels": [watch.RELEASE_LABEL], "body": None},
        {"number": 2, "state": "open", "labels": [watch.RELEASE_LABEL], "body": "other"},
        {
            "number": 3,
            "state": "open",
            "labels": [watch.RELEASE_LABEL],
            "body": finding.body,
            "pull_request": {},
        },
    ]
    watch.watch(settings(), github)
    assert len(github.created()) == 1
    assert github.issues[-1]["number"] == 4


def test_the_duplicate_search_follows_pages() -> None:
    finding = watch.release_finding("5.15", watch.Release("5.16", None), REPOSITORY)
    assert finding is not None
    github = FakeGitHub(record_body=record("5.16"), labels={watch.RELEASE_LABEL})
    github.issues = [
        {"number": number, "state": "open", "labels": [watch.RELEASE_LABEL], "body": "other"}
        for number in range(1, watch.PAGE_SIZE + 1)
    ]
    github.issues.append(
        {"number": 101, "state": "open", "labels": [watch.RELEASE_LABEL], "body": finding.body}
    )
    watch.watch(settings(), github)
    assert github.created() == []


def test_a_listing_longer_than_the_page_limit_fails_closed() -> None:
    github = FakeGitHub(record_body=record("5.16"), labels={watch.RELEASE_LABEL})
    github.issues = [
        {"number": number, "state": "open", "labels": [watch.RELEASE_LABEL], "body": "other"}
        for number in range(1, watch.PAGE_SIZE * watch.MAX_PAGES + 1)
    ]
    assert watch.watch(settings(), github) == watch.EXIT_ERROR
    assert github.created() == []


def test_the_expiry_issue_is_opened_in_the_warning_phase_without_failing() -> None:
    github = FakeGitHub()
    assert watch.watch(settings(date(2026, 11, 4)), github) == watch.EXIT_OK
    assert [issue["labels"] for issue in github.issues] == [[watch.EXPIRY_LABEL]]


def test_the_hard_stop_fails_the_run_and_reopens_the_expiry_issue(
    capsys: pytest.CaptureFixture[str],
) -> None:
    github = FakeGitHub()
    assert watch.watch(settings(date(2026, 11, 17)), github) == watch.EXIT_OK
    github.issues[0]["state"] = "closed"
    assert watch.watch(settings(date(2026, 11, 18)), github) == watch.EXIT_HARD_STOP
    assert len(github.issues) == 1
    assert github.issues[0]["state"] == "open"
    assert "inside its hard stop" in capsys.readouterr().err


def test_a_new_release_and_the_hard_stop_keep_one_issue_each() -> None:
    github = FakeGitHub(record_body=record("5.16"))
    for _ in range(3):
        assert watch.watch(settings(EXPIRES), github) == watch.EXIT_HARD_STOP
    assert sorted(cast("list[str]", issue["labels"])[0] for issue in github.issues) == [
        watch.EXPIRY_LABEL,
        watch.RELEASE_LABEL,
    ]


def test_no_finding_touches_no_issue(capsys: pytest.CaptureFixture[str]) -> None:
    github = FakeGitHub()
    assert watch.watch(settings(), github) == watch.EXIT_OK
    assert [request.url for request in github.requests] == [watch.RELEASE_RECORD_URL]
    assert "nothing to report" in capsys.readouterr().out


def test_without_issue_management_the_watch_only_reports(
    capsys: pytest.CaptureFixture[str],
) -> None:
    github = FakeGitHub(record_body=record("5.16"))
    assert watch.watch(settings(EXPIRES, manage=False), github) == watch.EXIT_HARD_STOP
    assert [request.url for request in github.requests] == [watch.RELEASE_RECORD_URL]
    output = capsys.readouterr().out
    assert "finding (issues not managed): SCC 5.16 is released" in output
    assert "finding (issues not managed): SCC 5.15 expires" in output


def test_a_network_failure_fails_the_run_and_still_reports_the_expiry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    github = FakeGitHub(record_error="the request to raw.githubusercontent.com failed (OSError)")
    assert watch.watch(settings(), github) == watch.EXIT_ERROR
    assert github.issues == []
    assert "failed (OSError)" in capsys.readouterr().err
    assert watch.watch(settings(EXPIRES), github) == watch.EXIT_ERROR
    assert [issue["labels"] for issue in github.issues] == [[watch.EXPIRY_LABEL]]


def test_a_malformed_record_opens_no_release_issue() -> None:
    github = FakeGitHub(record_body=b"<scc><version>5.16</version>")
    assert watch.watch(settings(), github) == watch.EXIT_ERROR
    assert github.issues == []


def test_a_malformed_pin_is_refused_before_anything_is_fetched() -> None:
    github = FakeGitHub()
    with pytest.raises(watch.WatchError, match="not an SCC version"):
        watch.watch(settings(pinned="5.15'"), github)
    assert github.requests == []


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/labels/scc-release", 500),
        ("POST", "/labels", 403),
        ("GET", "/issues", 403),
        ("POST", "/issues", 410),
    ],
)
def test_an_api_failure_fails_the_run(method: str, path: str, status: int) -> None:
    github = FakeGitHub(record_body=record("5.16"), fail={(method, path): status})
    assert watch.watch(settings(), github) == watch.EXIT_ERROR


def test_a_label_created_concurrently_is_accepted() -> None:
    github = FakeGitHub(record_body=record("5.16"), fail={("POST", "/labels"): 422})
    assert watch.watch(settings(), github) == watch.EXIT_OK
    assert len(github.issues) == 1


def test_an_existing_label_is_not_created_again() -> None:
    github = FakeGitHub(record_body=record("5.16"), labels={watch.RELEASE_LABEL})
    watch.watch(settings(), github)
    assert not [request for request in github.requests if request.url.endswith("/labels")]


@dataclass
class ScriptedApi:
    """A transport that answers every API call with one fixed response."""

    response: watch.HttpResponse

    def __call__(self, request: watch.HttpRequest, limit: int) -> watch.HttpResponse:
        assert limit == watch.MAX_API_BYTES
        assert request.url.startswith(f"{watch.GITHUB_API}/repos/{REPOSITORY}/")
        return self.response


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"{", "malformed JSON"),
        (b"\xff", "malformed JSON"),
        (b"{}", "not a list"),
        (b"[1]", "not an object"),
        (b'[{"body": "<!-- m -->", "number": true}]', "valid number"),
        (b'[{"body": "<!-- m -->", "number": 0}]', "valid number"),
        (b'[{"body": "<!-- m -->"}]', "valid number"),
    ],
)
def test_a_malformed_issue_listing_is_refused(body: bytes, message: str) -> None:
    issues = watch.GitHubIssues(REPOSITORY, TOKEN, ScriptedApi(watch.HttpResponse(200, body)))
    with pytest.raises(watch.WatchError, match=message):
        issues.find(watch.RELEASE_LABEL, "<!-- m -->", "open")


@pytest.mark.parametrize("body", [b"", b"[]", b'{"number": "7"}'])
def test_a_created_issue_without_a_number_is_refused(body: bytes) -> None:
    issues = watch.GitHubIssues(REPOSITORY, TOKEN, ScriptedApi(watch.HttpResponse(201, body)))
    finding = watch.Finding(watch.RELEASE_LABEL, "<!-- m -->", "t", "b")
    with pytest.raises(watch.WatchError, match="valid number"):
        issues.create(finding)


@pytest.mark.parametrize(
    ("repository", "token", "message"),
    [
        ("FreeSecDev", TOKEN, "owner/name"),
        ("FreeSecDev/../other", TOKEN, "owner/name"),
        ("Free Sec/x", TOKEN, "owner/name"),
        (REPOSITORY, "", "GH_TOKEN"),
        (REPOSITORY, "short", "GH_TOKEN"),
        (REPOSITORY, TOKEN + "\nX-Injected: 1", "GH_TOKEN"),
    ],
)
def test_the_api_client_refuses_a_malformed_repository_or_token(
    repository: str, token: str, message: str
) -> None:
    with pytest.raises(watch.WatchError, match=message):
        watch.GitHubIssues(repository, token, FakeGitHub())


def test_a_missing_token_fails_the_run_only_when_issues_are_managed() -> None:
    github = FakeGitHub(record_body=record("5.16"))
    for manage, status in ((False, watch.EXIT_OK), (True, watch.EXIT_ERROR)):
        tokenless = watch.WatchSettings(
            pinned="5.15",
            expires=EXPIRES,
            today=CURRENT_DAY,
            manage_issues=manage,
            repository=REPOSITORY,
            token="",
        )
        assert watch.watch(tokenless, github) == status
    assert github.issues == []


class FakeResponse:
    """A response of the fake HTTPS connection."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = io.BytesIO(body)

    def read(self, size: int) -> bytes:
        return self._body.read(size)


class FakeConnection:
    """A stand-in for ``http.client.HTTPSConnection`` that records its use."""

    created: ClassVar[list[FakeConnection]] = []
    outcome: ClassVar[FakeResponse | BaseException] = FakeResponse(200, b"")

    def __init__(self, host: str, **keywords: object) -> None:
        self.host = host
        self.keywords = keywords
        self.requested: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.closed = False
        FakeConnection.created.append(self)

    def request(
        self, method: str, target: str, body: bytes | None, headers: dict[str, str]
    ) -> None:
        self.requested.append((method, target, body, headers))

    def getresponse(self) -> FakeResponse:
        if isinstance(FakeConnection.outcome, BaseException):
            raise FakeConnection.outcome
        return FakeConnection.outcome

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> type[FakeConnection]:
    FakeConnection.created = []
    FakeConnection.outcome = FakeResponse(200, b"")
    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConnection)
    return FakeConnection


def test_the_transport_verifies_tls_and_bounds_the_response(
    connections: type[FakeConnection],
) -> None:
    connections.outcome = FakeResponse(200, b"x" * 10)
    request = watch.HttpRequest(
        "GET", "https://api.github.com/repos/a/b/issues?state=open", {"A": "1"}
    )
    assert watch.https_transport(request, 10) == watch.HttpResponse(200, b"x" * 10)
    connection = connections.created[0]
    assert connection.host == "api.github.com"
    assert connection.keywords["timeout"] == watch.TIMEOUT_SECONDS
    assert connection.keywords["context"] is not None
    assert connection.requested == [("GET", "/repos/a/b/issues?state=open", None, {"A": "1"})]
    assert connection.closed
    watch.https_transport(watch.HttpRequest("POST", "https://api.github.com", {}, b"{}"), 10)
    assert connections.created[1].requested[0][:3] == ("POST", "/", b"{}")


def test_the_transport_refuses_a_response_over_its_limit(
    connections: type[FakeConnection],
) -> None:
    connections.outcome = FakeResponse(200, b"x" * 11)
    with pytest.raises(watch.WatchError, match="larger than 10 bytes"):
        watch.https_transport(watch.HttpRequest("GET", watch.RELEASE_RECORD_URL, {}), 10)
    assert connections.created[0].closed


@pytest.mark.parametrize(
    "error", [OSError("unreachable"), TimeoutError(), http.client.RemoteDisconnected("gone")]
)
def test_a_network_failure_of_the_transport_is_a_watch_error(
    connections: type[FakeConnection], error: BaseException
) -> None:
    connections.outcome = error
    with pytest.raises(watch.WatchError, match="failed"):
        watch.https_transport(watch.HttpRequest("GET", watch.RELEASE_RECORD_URL, {}), 10)
    assert connections.created[0].closed


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/x",
        "https://user:secret@api.github.com/x",
        "https://user@api.github.com/x",
        "https://api.github.com:8443/x",
        "https:///x",
        "file:///etc/passwd",
    ],
)
def test_the_transport_refuses_anything_but_plain_https(
    connections: type[FakeConnection], url: str
) -> None:
    with pytest.raises(watch.WatchError, match="only plain HTTPS"):
        watch.https_transport(watch.HttpRequest("GET", url, {}), 10)
    assert connections.created == []


def test_the_command_line_reads_the_pin_and_today(
    capsys: pytest.CaptureFixture[str],
) -> None:
    github = FakeGitHub(record_body=record("5.16"))
    arguments = ["--pinned-version", "5.15", "--expires", "2026-11-25", "--today", "2026-11-18"]
    environment = {"GITHUB_REPOSITORY": REPOSITORY, "GH_TOKEN": TOKEN}
    assert watch.main([*arguments, "--manage-issues", "true"], environment, github) == 1
    assert len(github.issues) == 2
    assert watch.main(["--pinned-version", "5.15", "--expires", "2026-11-25"], {}, github) == 0
    assert "5.16 is released" in capsys.readouterr().out


def test_the_command_line_reports_a_malformed_pin(capsys: pytest.CaptureFixture[str]) -> None:
    assert watch.main(["--pinned-version", "x", "--expires", "2026-11-25"], {}, FakeGitHub()) == 2
    assert "not an SCC version" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["2026-13-01", "tomorrow", ""])
def test_the_command_line_refuses_a_malformed_date(value: str) -> None:
    with pytest.raises(SystemExit) as exit_info:
        watch.main(["--pinned-version", "5.15", "--expires", value], {}, FakeGitHub())
    assert exit_info.value.code == 2


def test_the_module_runs_as_a_script_with_the_process_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["release_watch", "--pinned-version", "x", "--expires", "2026-11-25"]
    )
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(watch.__file__, run_name="__main__")
    assert exit_info.value.code == 2
    assert "not an SCC version" in capsys.readouterr().err


def test_the_pins_name_a_version_the_watch_accepts() -> None:
    values = dict(
        line.split(" := ", 1)
        for line in PINS.read_text(encoding="utf-8").splitlines()
        if " := " in line
    )
    assert watch.version_key(values["SCC_VERSION"])
    assert date.fromisoformat(values["SCC_EXPIRES"])
