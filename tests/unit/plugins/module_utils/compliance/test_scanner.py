from __future__ import annotations

import dataclasses
import inspect
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    backends,
    model,
    openscap,
    process,
    scanner,
)

BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
RULE = "xccdf_org.example.synthetic_rule_alpha"
HOST = model.HostIdentity("host.example", "rhel", "9", "x86_64", None)


def request(**fields: Any) -> scanner.ScanRequest:
    values: dict[str, Any] = {
        "run_id": "run-1",
        "host": HOST,
        "benchmark_id": BENCHMARK,
        "profile_id": PROFILE,
        "content_path": "ds.xml",
        "output_dir": "out-1",
    }
    values.update(fields)
    return scanner.ScanRequest(**values)


class TestSettings:
    """Backend settings."""

    def test_defaults(self) -> None:
        settings = scanner.ScanSettings("/srv/content", "/srv/out")
        assert settings.timeout_seconds == scanner.DEFAULT_TIMEOUT_SECONDS
        assert settings.max_result_bytes == scanner.DEFAULT_MAX_RESULT_BYTES

    def test_accepts_the_limits(self) -> None:
        settings = scanner.ScanSettings(
            "/a", "/b", process.MAX_TIMEOUT_SECONDS, scanner.MAX_RESULT_BYTES_LIMIT
        )
        assert settings.timeout_seconds == process.MAX_TIMEOUT_SECONDS

    @pytest.mark.parametrize("root", ["", "relative", "-x", "/a\x00b", 5, None, "/" + "a" * 5000])
    def test_rejects_bad_roots(self, root: Any) -> None:
        with pytest.raises(scanner.ScanRequestError):
            scanner.ScanSettings(root, "/b")
        with pytest.raises(scanner.ScanRequestError):
            scanner.ScanSettings("/a", root)

    @pytest.mark.parametrize(
        "timeout", [0, -1, process.MAX_TIMEOUT_SECONDS + 1, float("nan"), float("inf"), True, "5"]
    )
    def test_rejects_bad_timeouts(self, timeout: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="timeout_seconds"):
            scanner.ScanSettings("/a", "/b", timeout)

    @pytest.mark.parametrize("size", [0, -1, scanner.MAX_RESULT_BYTES_LIMIT + 1, True, 1.5, "9"])
    def test_rejects_bad_sizes(self, size: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="max_result_bytes"):
            scanner.ScanSettings("/a", "/b", 1, size)

    def test_has_no_test_seams(self) -> None:
        names = {field.name for field in dataclasses.fields(scanner.ScanSettings)}
        assert names == {"content_root", "output_root", "timeout_seconds", "max_result_bytes"}


class TestRequest:
    """Scan requests."""

    def test_minimal_request(self) -> None:
        built = request()
        assert built.tailoring_path is None
        assert built.expected_rule_ids == ()

    def test_full_request(self) -> None:
        built = request(tailoring_path="t.xml", expected_rule_ids=(RULE,))
        assert built.tailoring_path == "t.xml"

    @pytest.mark.parametrize("run_id", ["", "-x", "a b", "a\n", 5, None, "a" * 129])
    def test_rejects_bad_run_ids(self, run_id: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="run_id"):
            request(run_id=run_id)

    def test_rejects_a_bad_host(self) -> None:
        with pytest.raises(scanner.ScanRequestError, match="host"):
            request(host={"hostname": "x"})

    @pytest.mark.parametrize(
        "value",
        [
            "profile",
            PROFILE + "\n",
            RULE,
            "xccdf_org.x_profile_",
            "--profile",
            "xccdf_x_profile_y" + "z" * 300,
            None,
            5,
        ],
    )
    def test_rejects_bad_profiles(self, value: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="profile_id"):
            request(profile_id=value)

    def test_rejects_a_bad_benchmark(self) -> None:
        with pytest.raises(scanner.ScanRequestError, match="benchmark_id"):
            request(benchmark_id=PROFILE)

    @pytest.mark.parametrize("path", ["", "-evil", "a\x00b", "/" + "a" * 5000, 5, None])
    def test_rejects_bad_paths(self, path: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="content_path"):
            request(content_path=path)
        with pytest.raises(scanner.ScanRequestError, match="output_dir"):
            request(output_dir=path)
        if path is not None:
            with pytest.raises(scanner.ScanRequestError, match="tailoring_path"):
                request(tailoring_path=path)

    @pytest.mark.parametrize(
        "rules",
        [[RULE], (PROFILE,), (RULE, RULE), (5,), tuple([RULE] * (scanner.MAX_EXPECTED_RULES + 1))],
    )
    def test_rejects_bad_expected_rules(self, rules: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="expected_rule_ids"):
            request(expected_rule_ids=rules)

    def test_identifier_patterns_agree_with_the_model(self) -> None:
        for kind, value in (("rule", RULE), ("profile", PROFILE), ("benchmark", BENCHMARK)):
            assert scanner.check_xccdf_id(value, kind, "x") == value
        finding = model.Finding(
            RULE,
            model.Outcome.PASS,
            model.Outcome.PASS,
            model.Severity.LOW,
            None,
            (),
            model.ExceptionStatus.none(),
            None,
            None,
            (),
        )
        assert finding.rule_id == RULE


class Backend:
    """A trivial backend."""

    def __init__(self, settings: scanner.ScanSettings) -> None:
        self.settings = settings

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        raise NotImplementedError


class TestRegistry:
    """The backend registry."""

    def test_registers_and_creates_backends(self) -> None:
        registry = scanner.BackendRegistry()
        registry.register("zeta", Backend)
        registry.register("alpha", Backend)
        settings = scanner.ScanSettings("/a", "/b")
        created = registry.create("zeta", settings)
        assert isinstance(created, Backend)
        assert created.settings is settings
        assert registry.names() == ("alpha", "zeta")

    def test_the_protocol_method_is_abstract(self) -> None:
        protocol_method: Any = scanner.ScanBackend.audit
        backend = Backend(scanner.ScanSettings("/a", "/b"))
        with pytest.raises(NotImplementedError):
            protocol_method(backend, request())

    def test_rejects_duplicates(self) -> None:
        registry = scanner.BackendRegistry()
        registry.register("one", Backend)
        with pytest.raises(scanner.ScanRequestError, match="already registered"):
            registry.register("one", Backend)

    @pytest.mark.parametrize("name", ["", "One", "1a", "a b", "a;b", 5, None, "a" * 65])
    def test_rejects_bad_names(self, name: Any) -> None:
        with pytest.raises(scanner.ScanRequestError, match="backend name"):
            scanner.BackendRegistry().register(name, Backend)

    @pytest.mark.parametrize("name", ["missing", "", "../openscap"])
    def test_unknown_backend(self, name: str) -> None:
        with pytest.raises(scanner.UnknownBackendError, match="unknown scanner backend"):
            scanner.BackendRegistry().create(name, scanner.ScanSettings("/a", "/b"))

    def test_registries_are_independent(self) -> None:
        first = scanner.BackendRegistry()
        first.register("one", Backend)
        assert scanner.BackendRegistry().names() == ()


class TestDefaultRegistry:
    """The composition root."""

    def test_holds_the_openscap_backend(self) -> None:
        registry = backends.default_registry()
        assert registry.names() == ("openscap",)
        backend = registry.create("openscap", scanner.ScanSettings("/a", "/b"))
        assert isinstance(backend, openscap.OpenScapBackend)

    def test_each_call_returns_a_new_registry(self) -> None:
        assert backends.default_registry() is not backends.default_registry()

    def test_the_factory_cannot_receive_test_seams(self) -> None:
        parameters = list(inspect.signature(openscap.create_backend).parameters)
        assert parameters == ["settings"]
        backend = backends.default_registry().create("openscap", scanner.ScanSettings("/a", "/b"))
        assert isinstance(backend, openscap.OpenScapBackend)

    def test_scanner_module_does_not_import_a_concrete_backend(self) -> None:
        assert not hasattr(scanner, "openscap")
        assert not hasattr(scanner, "backends")
