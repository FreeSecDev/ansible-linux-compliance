from __future__ import annotations

import dataclasses
import errno
import inspect
import math
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    process,
)

ANY_ARGUMENTS = ((),)
OWNER = os.getuid()
SHELL = process.ExecutablePolicy("sh", frozenset({"-c"}), command_prefixes=(("-c",),))
POLICIES = {
    "sh": SHELL,
    "true": process.ExecutablePolicy("true", command_prefixes=ANY_ARGUMENTS),
    "false": process.ExecutablePolicy("false", command_prefixes=ANY_ARGUMENTS),
    "yes": process.ExecutablePolicy("yes", command_prefixes=ANY_ARGUMENTS),
    "sleep": process.ExecutablePolicy("sleep", command_prefixes=ANY_ARGUMENTS),
}
FAST = 10.0
PLANTED = "canary-value"


def shell(script: str, *args: str, timeout: float = FAST, **fields: Any) -> process.CommandSpec:
    return process.CommandSpec("sh", ("-c", script, "sh", *args), timeout, **fields)


def resolve(name: Any, directories: Any) -> str:
    return process.resolve_executable(name, trusted_dirs=directories, owner_uid=OWNER)


def execute(spec: process.CommandSpec, **keywords: Any) -> process.CommandResult:
    return process.run(spec, policies=POLICIES, **keywords)


def process_alive(pid: int) -> bool:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return False
    return stat_text.rsplit(")", 1)[1].split()[0] != "Z"


def wait_until_dead(pid: int, limit: float = 5.0) -> bool:
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return True
        time.sleep(0.05)
    return not process_alive(pid)


def make_tool(directory: Path, name: str = "tool", mode: int = 0o755) -> Path:
    directory.mkdir(exist_ok=True)
    tool = directory / name
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(mode)
    return tool


def run_in(trusted: Path, executable: str = "true") -> process.CommandResult:
    return process.run(
        process.CommandSpec(executable, (), FAST),
        policies=POLICIES,
        trusted_dirs=[str(trusted)],
        owner_uid=OWNER,
    )


@pytest.fixture
def trusted(tmp_path: Path) -> Path:
    directory = tmp_path / "trusted"
    directory.mkdir()
    directory.chmod(0o755)
    return directory


class TestCommandSpec:
    """Validation of command specifications."""

    def test_defaults_and_normalisation(self) -> None:
        arguments: Any = ["--version"]
        spec = process.CommandSpec("oscap", arguments, 5)
        assert spec.args == ("--version",)
        assert spec.timeout_seconds == 5.0
        assert spec.max_output_bytes == process.DEFAULT_MAX_OUTPUT_BYTES
        assert spec.env_allow == ()
        assert spec.cwd is None

    def test_is_frozen(self) -> None:
        spec: Any = process.CommandSpec("oscap", (), 1)
        with pytest.raises(dataclasses.FrozenInstanceError):
            spec.timeout_seconds = 2.0

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "../oscap",
            "..",
            "/usr/bin/oscap",
            "a/b",
            "OSCAP",
            "oscap;ls",
            "oscap\n",
            " oscap",
            7,
        ],
    )
    def test_rejects_executable_names(self, name: Any) -> None:
        with pytest.raises(process.ProcessPolicyError, match="invalid executable name"):
            process.CommandSpec(name, (), 1)

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            (("a\x00b",), "control character or NUL"),
            (("a\nb",), "control character or NUL"),
            (("a\rb",), "control character or NUL"),
            (("a\x7fb",), "control character or NUL"),
            (("",), "must not be empty"),
            ((7,), "must be a string"),
            ((None,), "must be a string"),
            (("a" * (process.MAX_ARGUMENT_LENGTH + 1),), "exceeds"),
            (("x",) * (process.MAX_ARGUMENTS + 1), "too many arguments"),
            ("--version", "args must be a tuple"),
            (None, "args must be a tuple"),
        ],
    )
    def test_rejects_arguments(self, args: Any, message: str) -> None:
        with pytest.raises(process.ProcessPolicyError, match=message):
            process.CommandSpec("oscap", args, 1)

    @pytest.mark.parametrize(
        "argument",
        [";", "; touch /tmp/x", "`id`", "$(id)", "${HOME}", "a && b", "a | b", "*", "~", "a b"],
    )
    def test_shell_metacharacters_are_data_and_stay_unchanged(self, argument: str) -> None:
        assert process.CommandSpec("oscap", (argument,), 1).args == (argument,)

    @pytest.mark.parametrize(
        "timeout",
        [0, -1, 0.0, math.nan, math.inf, process.MAX_TIMEOUT_SECONDS + 1, True, "5", None],
    )
    def test_rejects_timeouts(self, timeout: Any) -> None:
        with pytest.raises(process.ProcessPolicyError, match="timeout_seconds"):
            process.CommandSpec("oscap", (), timeout)

    def test_accepts_the_maximum_timeout(self) -> None:
        spec = process.CommandSpec("oscap", (), process.MAX_TIMEOUT_SECONDS)
        assert spec.timeout_seconds == process.MAX_TIMEOUT_SECONDS

    @pytest.mark.parametrize("cap", [0, -1, process.MAX_OUTPUT_BYTES + 1, True, 1.5, "10", None])
    def test_rejects_output_caps(self, cap: Any) -> None:
        with pytest.raises(process.ProcessPolicyError, match="max_output_bytes"):
            process.CommandSpec("oscap", (), 1, max_output_bytes=cap)

    def test_accepts_the_maximum_output_cap(self) -> None:
        spec = process.CommandSpec("oscap", (), 1, max_output_bytes=process.MAX_OUTPUT_BYTES)
        assert spec.max_output_bytes == process.MAX_OUTPUT_BYTES

    @pytest.mark.parametrize(
        ("names", "message"),
        [
            (("SECRET_TOKEN",), "may not be copied"),
            (("PATH",), "may not be copied"),
            (("LC_ALL",), "may not be copied"),
            (("LD_PRELOAD",), "may not be copied"),
            (("tz",), "invalid environment variable name"),
            (("TZ=UTC",), "invalid environment variable name"),
            ((7,), "invalid environment variable name"),
            ("TZ", "env_allow must be a tuple"),
        ],
    )
    def test_rejects_environment_names(self, names: Any, message: str) -> None:
        with pytest.raises(process.ProcessPolicyError, match=message):
            process.CommandSpec("oscap", (), 1, env_allow=names)

    def test_accepts_listed_environment_names(self) -> None:
        names: Any = ["TZ", "TMPDIR"]
        spec = process.CommandSpec("oscap", (), 1, env_allow=names)
        assert spec.env_allow == ("TZ", "TMPDIR")

    def test_accepts_an_existing_absolute_cwd(self, tmp_path: Path) -> None:
        assert process.CommandSpec("oscap", (), 1, cwd=str(tmp_path)).cwd == str(tmp_path)

    @pytest.mark.parametrize(
        "cwd", ["relative", "", "/nonexistent-dir-for-test", "/etc/passwd", 7, "/usr\x00"]
    )
    def test_rejects_cwd(self, cwd: Any) -> None:
        with pytest.raises(process.ProcessPolicyError, match="cwd must be"):
            process.CommandSpec("oscap", (), 1, cwd=cwd)

    def test_messages_are_escaped_and_truncated(self) -> None:
        with pytest.raises(process.ProcessPolicyError) as raised:
            process.CommandSpec("oscap", ("bad\n" + "x" * 500,), 1)
        message = str(raised.value)
        assert "\\n" in message
        assert "\n" not in message
        assert len(message) < 200


class TestPolicy:
    """Executable and option allow-list policy."""

    def test_default_allow_list_is_only_oscap_the_scc_command_line_sshd_and_the_audit_tools(
        self,
    ) -> None:
        assert set(process.ALLOWED_EXECUTABLES) == {
            "oscap",
            "cscc",
            "sshd",
            "auditctl",
            "augenrules",
        }
        assert process.ALLOWED_EXECUTABLES["oscap"].fixed_path is None
        options = process.ALLOWED_EXECUTABLES["oscap"].allowed_options
        assert {
            "--profile",
            "--results-arf",
            "--results",
            "--report",
            "--tailoring-file",
        } <= options
        assert not options & process.FORBIDDEN_OPTIONS

    def test_sshd_runs_only_in_test_mode_on_the_main_configuration(self) -> None:
        policy = process.ALLOWED_EXECUTABLES["sshd"]
        assert policy.fixed_path is None
        assert policy.allowed_options == frozenset()
        assert policy.command_prefixes == (("-t", "-f", "/etc/ssh/sshd_config"),)
        assert policy.standalone_commands == ()
        assert policy.option_values == (("-o", process.SSHD_SETTING),)
        assert len(process.SSHD_KEYWORDS) == len(set(process.SSHD_KEYWORDS)) == 28
        for arguments in (
            ("-t", "-f", "/etc/ssh/sshd_config"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "PermitRootLogin=no"),
            (
                "-t",
                "-f",
                "/etc/ssh/sshd_config",
                "-o",
                "Ciphers=aes256-gcm@openssh.com,aes128-ctr",
                "-o",
                "MaxStartups=10:30:60",
                "-o",
                "Banner=/etc/issue.net",
            ),
        ):
            spec = process.CommandSpec("sshd", arguments, 1)
            assert process.check_policy(spec).name == "sshd"

    @pytest.mark.parametrize(
        "arguments",
        [
            (),
            ("-t",),
            ("-T", "-f", "/etc/ssh/sshd_config"),
            ("-D",),
            ("-t", "-f", "/srv/sshd_config"),
            ("-f", "/etc/ssh/sshd_config", "-t"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-D"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-d"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-h", "/srv/key"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-E", "/srv/log"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-C", "user=root"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-oPermitRootLogin=yes"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o=Include=/srv/x"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "Include=/srv/x"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "HostKey=/root/.ssh/id_rsa"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "AuthorizedKeysCommand=/bin/sh -c id"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "PermitRootLogin=-T"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "PermitRootLogin=no yes"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "permitrootlogin=no"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "PermitRootLogin="),
            ("-t", "-f", "/etc/ssh/sshd_config", "stray"),
            ("-t", "-f", "/etc/ssh/sshd_config", "stray", "-o"),
            ("-t", "-f", "/etc/ssh/sshd_config", "-o", "UsePAM=yes", "-o"),
        ],
    )
    def test_sshd_refuses_every_other_command_line(self, arguments: tuple[str, ...]) -> None:
        spec = process.CommandSpec("sshd", arguments, 1)
        with pytest.raises(process.ProcessPolicyError):
            process.check_policy(spec)

    def test_audit_tools_run_only_in_their_exact_forms(self) -> None:
        auditctl = process.ALLOWED_EXECUTABLES["auditctl"]
        augenrules = process.ALLOWED_EXECUTABLES["augenrules"]
        assert auditctl.fixed_path is None
        assert augenrules.fixed_path is None
        assert auditctl.argument_forms == (("-s",), ("-l",), ("--signal", "reload"))
        assert augenrules.argument_forms == (("--load",),)
        for executable, arguments in (
            ("auditctl", ("-s",)),
            ("auditctl", ("-l",)),
            ("auditctl", ("--signal", "reload")),
            ("augenrules", ("--load",)),
        ):
            spec = process.CommandSpec(executable, arguments, 1)
            assert process.check_policy(spec).name == executable

    @pytest.mark.parametrize(
        ("executable", "arguments"),
        [
            ("auditctl", ()),
            ("auditctl", ("-D",)),
            ("auditctl", ("-e", "0")),
            ("auditctl", ("-e", "2")),
            ("auditctl", ("-f", "0")),
            ("auditctl", ("-R", "/etc/audit/audit.rules")),
            ("auditctl", ("-R", "/srv/rules")),
            ("auditctl", ("-w", "/etc/passwd", "-p", "wa")),
            ("auditctl", ("-W", "/etc/passwd")),
            ("auditctl", ("-a", "always,exit", "-S", "all")),
            ("auditctl", ("-d", "always,exit", "-S", "all")),
            ("auditctl", ("-b", "0")),
            ("auditctl", ("-s", "-l")),
            ("auditctl", ("-l", "-k", "x")),
            ("auditctl", ("--signal", "stop")),
            ("auditctl", ("--signal", "TERM")),
            ("auditctl", ("--signal",)),
            ("auditctl", ("--signal=reload",)),
            ("auditctl", ("--loginuid-immutable",)),
            ("augenrules", ()),
            ("augenrules", ("--check",)),
            ("augenrules", ("--load", "--check")),
            ("augenrules", ("--load", "/srv/rules")),
            ("augenrules", ("/etc/audit/rules.d",)),
        ],
    )
    def test_audit_tools_refuse_every_other_command_line(
        self, executable: str, arguments: tuple[str, ...]
    ) -> None:
        spec = process.CommandSpec(executable, arguments, 1)
        with pytest.raises(process.ProcessPolicyError):
            process.check_policy(spec)

    def test_default_trusted_directories_are_fixed(self) -> None:
        assert process.TRUSTED_DIRECTORIES == ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

    @pytest.mark.parametrize("name", ["sh", "true", "bash", "python3", "rm"])
    def test_rejects_executables_that_are_not_allow_listed(self, name: str) -> None:
        spec = process.CommandSpec(name, (), 1)
        with pytest.raises(process.ProcessPolicyError, match="not allow-listed"):
            process.run(spec)

    def test_accepts_allowed_options_and_positionals(self) -> None:
        spec = process.CommandSpec(
            "oscap",
            (
                "xccdf",
                "eval",
                "--profile",
                "xccdf_x_profile_y",
                "--results-arf=/tmp/a.xml",
                "in.xml",
            ),
            1,
        )
        policy = process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES)
        assert policy.name == "oscap"

    def test_accepts_the_openscap_backend_command_line(self) -> None:
        arguments = (
            "xccdf",
            "eval",
            "--profile",
            "xccdf_x_profile_y",
            "--tailoring-file",
            "/srv/tailoring.xml",
            "--results-arf",
            "/srv/out/results-arf.xml",
            "--results",
            "/srv/out/results.xml",
            "/srv/content/ds.xml",
        )
        spec = process.CommandSpec("oscap", arguments, 1)
        assert process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES).name == "oscap"

    @pytest.mark.parametrize(
        "extra",
        [("--remediate",), ("--tailoring-file=/x", "--fetch-remote-resources"), ("--tailoring",)],
    )
    def test_tailoring_support_does_not_open_other_options(self, extra: tuple[str, ...]) -> None:
        spec = process.CommandSpec("oscap", ("xccdf", "eval", *extra), 1)
        with pytest.raises(process.ProcessPolicyError):
            process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES)

    @pytest.mark.parametrize(
        "argument",
        [
            "--fetch-remote-resources",
            "--fetch-remote-resources=1",
            "--oval-results",
            "--",
            "-",
            "-h",
            "--profile-x",
            "--PROFILE",
            "-oscap",
            "--rule",
        ],
    )
    def test_rejects_options_that_are_not_allow_listed(self, argument: str) -> None:
        spec = process.CommandSpec("oscap", ("xccdf", "eval", argument), 1)
        with pytest.raises(process.ProcessPolicyError, match="option is"):
            process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES)

    def test_remote_fetching_is_forbidden_even_if_a_policy_lists_it(self) -> None:
        policies = {
            "oscap": process.ExecutablePolicy(
                "oscap", frozenset({"--fetch-remote-resources"}), command_prefixes=ANY_ARGUMENTS
            )
        }
        spec = process.CommandSpec("oscap", ("--fetch-remote-resources",), 1)
        with pytest.raises(process.ProcessPolicyError, match="option is forbidden"):
            process.check_policy(spec, policies=policies)

    def test_option_value_that_looks_like_an_option_is_rejected(self) -> None:
        spec = process.CommandSpec(
            "oscap", ("xccdf", "eval", "--profile", "--fetch-remote-resources"), 1
        )
        with pytest.raises(process.ProcessPolicyError, match="option is forbidden"):
            process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES)

    def test_policy_rejection_happens_before_any_resolution(self, trusted: Path) -> None:
        spec = process.CommandSpec("oscap", ("xccdf", "eval", "--fetch-remote-resources"), 1)
        with pytest.raises(process.ProcessPolicyError, match="option is forbidden"):
            process.run(spec, trusted_dirs=[str(trusted)], owner_uid=OWNER)


class TestResolveExecutable:
    """Trusted-directory executable resolution."""

    def test_resolves_to_an_absolute_path_in_a_trusted_directory(self) -> None:
        resolved = process.resolve_executable("sh")
        assert Path(resolved).is_absolute()
        assert str(Path(resolved).parent) in process.TRUSTED_DIRECTORIES

    def test_ignores_the_caller_path(self, trusted: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        planted = make_tool(trusted, "sh")
        monkeypatch.setenv("PATH", str(trusted))
        assert process.resolve_executable("sh") != str(planted)

    @pytest.mark.parametrize(
        "name", ["", "../sh", "/bin/sh", "sh/", "./sh", "..", ".", "a\x00b", "sh\n", 3, None]
    )
    def test_rejects_traversal_and_malformed_names(self, name: Any, trusted: Path) -> None:
        with pytest.raises(process.ProcessPolicyError, match="invalid executable name"):
            resolve(name, [str(trusted)])

    def test_missing_binary(self, trusted: Path) -> None:
        with pytest.raises(process.ProcessExecutionError, match="not found"):
            resolve("missing", [str(trusted)])

    def test_missing_directories_are_skipped(self, trusted: Path, tmp_path: Path) -> None:
        tool = make_tool(trusted)
        resolved = resolve("tool", [str(tmp_path / "absent"), str(trusted)])
        assert resolved == str(tool)

    def test_a_file_is_not_a_trusted_directory(self, trusted: Path, tmp_path: Path) -> None:
        make_tool(trusted)
        blocker = tmp_path / "blocker"
        blocker.write_text("x", encoding="utf-8")
        resolved = resolve("tool", [str(blocker), str(trusted)])
        assert resolved == str(trusted / "tool")

    def test_first_trusted_directory_wins(self, tmp_path: Path) -> None:
        first = tmp_path / "first"
        second = tmp_path / "second"
        make_tool(first)
        make_tool(second)
        assert resolve("tool", [str(first), str(second)]) == str(first / "tool")

    @pytest.mark.parametrize("directory", ["relative/dir", "", "bin", 5, "/usr\x00"])
    def test_rejects_untrusted_directory_declarations(self, directory: Any) -> None:
        with pytest.raises(process.ProcessPolicyError, match="absolute path"):
            resolve("tool", [directory])

    def test_rejects_a_world_writable_directory(self, trusted: Path) -> None:
        make_tool(trusted)
        trusted.chmod(0o777)
        with pytest.raises(
            process.ProcessPolicyError, match="directory is writable by group or others"
        ):
            resolve("tool", [str(trusted)])

    def test_rejects_a_symlink_that_points_outside(self, trusted: Path, tmp_path: Path) -> None:
        outside = make_tool(tmp_path / "outside", "real")
        (trusted / "tool").symlink_to(outside)
        with pytest.raises(process.ProcessPolicyError, match="outside the trusted directories"):
            resolve("tool", [str(trusted)])

    def test_rejects_a_symlink_to_a_system_file_outside(self, trusted: Path) -> None:
        (trusted / "tool").symlink_to("/etc/hostname")
        with pytest.raises(process.ProcessPolicyError, match="outside the trusted directories"):
            resolve("tool", [str(trusted)])

    def test_accepts_a_symlink_chain_that_resolves_inside(
        self, trusted: Path, tmp_path: Path
    ) -> None:
        real = make_tool(trusted, "real")
        hop_dir = tmp_path / "hop"
        hop_dir.mkdir()
        hop = hop_dir / "hop"
        hop.symlink_to(real)
        (trusted / "tool").symlink_to(hop)
        assert resolve("tool", [str(trusted)]) == str(trusted / "tool")

    def test_accepts_a_symlink_inside_the_trusted_directories(self, trusted: Path) -> None:
        make_tool(trusted, "real")
        (trusted / "alias").symlink_to("real")
        assert resolve("alias", [str(trusted)]) == str(trusted / "alias")

    def test_rejects_a_symlink_loop(self, trusted: Path) -> None:
        (trusted / "tool").symlink_to("tool")
        with pytest.raises(process.ProcessError):
            resolve("tool", [str(trusted)])

    def test_rejects_an_unresolvable_candidate(
        self, trusted: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = Path.resolve

        def explode(path: Path, *, strict: bool = False) -> Path:
            if path.name == "tool":
                raise RuntimeError(strict)
            return real(path, strict=strict)

        make_tool(trusted)
        monkeypatch.setattr(Path, "resolve", explode)
        with pytest.raises(process.ProcessPolicyError, match="cannot be resolved"):
            resolve("tool", [str(trusted)])

    def test_a_broken_symlink_inside_is_not_found(self, trusted: Path) -> None:
        (trusted / "tool").symlink_to("gone")
        with pytest.raises(process.ProcessExecutionError, match="not found"):
            resolve("tool", [str(trusted)])

    def test_rejects_a_world_writable_binary(self, trusted: Path) -> None:
        make_tool(trusted, mode=0o777)
        with pytest.raises(process.ProcessPolicyError, match="writable by group or others"):
            resolve("tool", [str(trusted)])

    def test_rejects_a_directory(self, trusted: Path) -> None:
        (trusted / "tool").mkdir()
        with pytest.raises(process.ProcessPolicyError, match="not a regular file"):
            resolve("tool", [str(trusted)])

    def test_rejects_a_non_executable_file(self, trusted: Path) -> None:
        make_tool(trusted, mode=0o644)
        with pytest.raises(process.ProcessPolicyError, match="not executable"):
            resolve("tool", [str(trusted)])

    def test_unsafe_file_in_an_earlier_directory_is_not_skipped(self, tmp_path: Path) -> None:
        first = tmp_path / "first"
        second = tmp_path / "second"
        make_tool(first, mode=0o777)
        make_tool(second)
        with pytest.raises(process.ProcessPolicyError, match="writable by group or others"):
            resolve("tool", [str(first), str(second)])


class TestConfinedPath:
    """Path confinement."""

    def test_relative_candidate(self, tmp_path: Path) -> None:
        expected = tmp_path.resolve() / "a" / "b.xml"
        assert process.confined_path(str(tmp_path), "a/b.xml") == str(expected)

    def test_absolute_candidate_inside(self, tmp_path: Path) -> None:
        inside = tmp_path.resolve() / "x"
        assert process.confined_path(str(tmp_path), str(inside)) == str(inside)

    def test_candidate_may_be_the_base(self, tmp_path: Path) -> None:
        assert process.confined_path(str(tmp_path), ".") == str(tmp_path.resolve())

    def test_dot_dot_that_stays_inside(self, tmp_path: Path) -> None:
        assert process.confined_path(str(tmp_path), "a/../b") == str(tmp_path.resolve() / "b")

    @pytest.mark.parametrize(
        "candidate", ["..", "../x", "a/../../x", "/etc/passwd", "/", "a/../..", "//etc"]
    )
    def test_rejects_escapes(self, tmp_path: Path, candidate: str) -> None:
        with pytest.raises(process.ProcessPolicyError, match="escapes the base"):
            process.confined_path(str(tmp_path), candidate)

    def test_rejects_a_sibling_with_the_same_prefix(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        with pytest.raises(process.ProcessPolicyError, match="escapes the base"):
            process.confined_path(str(base), str(tmp_path / "base-evil" / "x"))

    def test_rejects_a_symlink_component(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        base = tmp_path / "base"
        base.mkdir()
        (base / "link").symlink_to(outside)
        with pytest.raises(process.ProcessPolicyError, match="contains a symlink"):
            process.confined_path(str(base), "link/file")

    def test_rejects_a_symlink_leaf(self, tmp_path: Path) -> None:
        (tmp_path / "leaf").symlink_to("/etc/passwd")
        with pytest.raises(process.ProcessPolicyError, match="contains a symlink"):
            process.confined_path(str(tmp_path), "leaf")

    def test_a_symlinked_base_is_resolved(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        alias = tmp_path / "alias"
        alias.symlink_to(real)
        assert process.confined_path(str(alias), "f") == str(real.resolve() / "f")

    def test_root_base(self) -> None:
        assert process.confined_path("/", "etc/hostname") == "/etc/hostname"

    @pytest.mark.parametrize(
        ("base", "candidate"),
        [("", "x"), ("/usr", ""), ("/usr\x00", "x"), ("/usr", "a\x00"), (None, "x"), ("/usr", 3)],
    )
    def test_rejects_malformed_inputs(self, base: Any, candidate: Any) -> None:
        with pytest.raises(process.ProcessPolicyError, match="non-empty string without NUL"):
            process.confined_path(base, candidate)

    @pytest.mark.parametrize("base", ["relative", "/nonexistent-dir-for-test", "/etc/passwd"])
    def test_rejects_a_bad_base(self, base: str) -> None:
        with pytest.raises(process.ProcessPolicyError, match="base must be"):
            process.confined_path(base, "x")


class TestEnvironment:
    """Child environment construction."""

    def test_fixed_values_only_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_TOKEN", PLANTED)
        spec = process.CommandSpec("oscap", (), 1)
        assert process.build_environment(spec) == {
            "PATH": process.SAFE_PATH,
            "LC_ALL": "C",
            "LANG": "C",
        }

    def test_copies_only_allowed_names_that_are_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TZ", "Europe/Amsterdam")
        monkeypatch.delenv("TMPDIR", raising=False)
        spec = process.CommandSpec("oscap", (), 1, env_allow=("TZ", "TMPDIR"))
        environment = process.build_environment(spec)
        assert environment["TZ"] == "Europe/Amsterdam"
        assert "TMPDIR" not in environment

    def test_child_does_not_see_the_parent_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SECRET_TOKEN", PLANTED)
        monkeypatch.setenv("TZ", "Europe/Amsterdam")
        monkeypatch.setenv("PATH", "/nonexistent-attacker-path")
        result = execute(shell("env"))
        lines = result.stdout.decode().splitlines()
        assert b"SECRET_TOKEN" not in result.stdout
        assert b"canary" not in result.stdout
        assert "PATH=" + process.SAFE_PATH in lines
        assert "LC_ALL=C" in lines
        assert "LANG=C" in lines
        assert not any(line.startswith("TZ=") for line in lines)

    def test_child_sees_an_explicitly_copied_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TZ", "Europe/Amsterdam")
        result = execute(shell("env", env_allow=("TZ",)))
        assert "TZ=Europe/Amsterdam" in result.stdout.decode().splitlines()

    def test_result_never_carries_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_TOKEN", PLANTED)
        result = execute(shell("true"))
        assert "canary" not in repr(result)
        assert {field.name for field in dataclasses.fields(result)} == {
            "argv",
            "returncode",
            "stdout",
            "stderr",
            "stdout_truncated",
            "stderr_truncated",
            "duration_seconds",
            "timed_out",
        }


class TestRun:
    """Execution, output capture and result contents."""

    def test_success(self) -> None:
        result = execute(process.CommandSpec("true", (), FAST))
        assert result.returncode == 0
        assert result.stdout == b""
        assert result.stderr == b""
        assert not result.timed_out
        assert not result.stdout_truncated
        assert not result.stderr_truncated
        assert 0 <= result.duration_seconds < FAST
        assert Path(result.argv[0]).is_absolute()
        assert result.argv[1:] == ()

    def test_failure_exit_status(self) -> None:
        result = execute(process.CommandSpec("false", (), FAST))
        assert result.returncode == 1
        assert not result.timed_out

    def test_captures_both_streams_and_the_exit_status(self) -> None:
        result = execute(shell("printf out; printf err >&2; exit 3"))
        assert (result.returncode, result.stdout, result.stderr) == (3, b"out", b"err")
        assert result.argv[1:] == ("-c", "printf out; printf err >&2; exit 3", "sh")

    def test_result_is_frozen(self) -> None:
        result: Any = execute(process.CommandSpec("true", (), FAST))
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.returncode = 5

    @pytest.mark.parametrize(
        "payload",
        [
            ";touch pwned",
            "`touch pwned`",
            "$(touch pwned)",
            "&& touch pwned",
            "| touch pwned",
            "'; touch pwned; '",
        ],
    )
    def test_injection_payloads_are_passed_as_data(self, tmp_path: Path, payload: str) -> None:
        result = execute(shell('printf %s "$1"', payload, cwd=str(tmp_path)))
        assert result.stdout == payload.encode()
        assert not (tmp_path / "pwned").exists()

    @pytest.mark.parametrize("payload", ["a\nb", "a\x00b", "a\rb"])
    def test_injection_payloads_with_control_characters_never_run(self, payload: str) -> None:
        with pytest.raises(process.ProcessPolicyError):
            shell('printf %s "$1"', payload)

    def test_disallowed_option_never_runs(self) -> None:
        spec = process.CommandSpec("true", ("--evil",), 1)
        with pytest.raises(process.ProcessPolicyError, match="option is not allow-listed"):
            execute(spec)

    def test_uses_the_hardened_process_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}
        real: Any = subprocess.Popen

        def spy(argv: Any, **keywords: Any) -> Any:
            captured["argv"] = argv
            captured.update(keywords)
            return real(argv, **keywords)

        monkeypatch.setattr(subprocess, "Popen", spy)
        execute(process.CommandSpec("true", (), FAST))
        assert isinstance(captured["argv"], tuple)
        assert captured["shell"] is False
        assert captured["stdin"] == subprocess.DEVNULL
        assert captured["close_fds"] is True
        assert captured["start_new_session"] is True
        assert captured["env"] == dict(process.FIXED_ENVIRONMENT)
        assert captured["cwd"] is None

    def test_standard_input_is_closed(self) -> None:
        result = execute(shell("cat; echo done"))
        assert result.stdout == b"done\n"
        assert not result.timed_out

    def test_runs_in_the_requested_directory(self, tmp_path: Path) -> None:
        result = execute(shell("pwd -P", cwd=str(tmp_path)))
        assert result.stdout.strip() == str(tmp_path.resolve()).encode()


class TestRunLimits:
    """Output caps and timeouts."""

    def test_caps_unbounded_output_and_times_out(self) -> None:
        spec = process.CommandSpec("yes", (), 0.5, max_output_bytes=1000)
        result = execute(spec)
        assert result.timed_out
        assert result.returncode == -9
        assert len(result.stdout) == 1000
        assert result.stdout_truncated
        assert not result.stderr_truncated

    def test_caps_finite_output_without_a_timeout(self) -> None:
        result = execute(shell("yes | head -c 3000000", max_output_bytes=4096))
        assert not result.timed_out
        assert result.returncode == 0
        assert len(result.stdout) == 4096
        assert result.stdout.startswith(b"y\ny\n")
        assert result.stdout_truncated

    def test_caps_stderr_independently(self) -> None:
        result = execute(shell("printf ok; head -c 100000 /dev/zero >&2", max_output_bytes=512))
        assert result.stdout == b"ok"
        assert len(result.stderr) == 512
        assert result.stderr_truncated
        assert not result.stdout_truncated

    def test_output_exactly_at_the_cap_is_not_truncated(self) -> None:
        result = execute(shell("head -c 100 /dev/zero", max_output_bytes=100))
        assert len(result.stdout) == 100
        assert not result.stdout_truncated

    def test_timeout_kills_the_process(self) -> None:
        started = time.monotonic()
        result = execute(process.CommandSpec("sleep", ("30",), 0.5))
        assert result.timed_out
        assert result.returncode == -9
        assert time.monotonic() - started < FAST

    def test_timeout_kills_the_whole_process_group(self) -> None:
        script = "sleep 60 & echo $!; sleep 60 & echo $!; wait"
        result = execute(shell(script, timeout=1.0))
        assert result.timed_out
        pids = [int(value) for value in result.stdout.split()]
        assert len(pids) == 2
        assert all(wait_until_dead(pid) for pid in pids)

    def test_timeout_when_output_pipes_are_closed(self) -> None:
        started = time.monotonic()
        result = execute(shell("exec >&- 2>&-; sleep 30", timeout=0.5))
        assert result.timed_out
        assert result.returncode == -9
        assert time.monotonic() - started < FAST

    def test_a_group_member_holding_the_pipes_cannot_outlive_the_timeout(self) -> None:
        result = execute(shell("sleep 60 & echo $!; exit 0", timeout=1.0))
        pid = int(result.stdout.split()[0])
        assert result.timed_out
        assert wait_until_dead(pid)

    def test_timeout_is_a_result_not_an_exception(self) -> None:
        result = execute(process.CommandSpec("sleep", ("30",), 0.2))
        assert isinstance(result, process.CommandResult)
        assert result.timed_out


class TestRunFailures:
    """Failures before or while starting a process."""

    def test_missing_binary(self, trusted: Path) -> None:
        with pytest.raises(process.ProcessExecutionError, match="not found"):
            run_in(trusted)

    def test_default_policy_missing_oscap(self, trusted: Path) -> None:
        spec = process.CommandSpec("oscap", ("--version",), 1)
        with pytest.raises(process.ProcessExecutionError, match="not found"):
            process.run(spec, trusted_dirs=[str(trusted)], owner_uid=OWNER)

    def test_unsafe_binary_is_refused_before_running(self, trusted: Path, tmp_path: Path) -> None:
        marker = tmp_path / "ran"
        tool = trusted / "true"
        tool.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        tool.chmod(0o777)
        with pytest.raises(process.ProcessPolicyError, match="writable by group or others"):
            run_in(trusted)
        assert not marker.exists()

    def test_symlink_outside_is_refused_before_running(self, trusted: Path, tmp_path: Path) -> None:
        marker = tmp_path / "ran"
        outside = tmp_path / "outside"
        outside.mkdir()
        evil = outside / "evil"
        evil.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        evil.chmod(0o755)
        (trusted / "true").symlink_to(evil)
        with pytest.raises(process.ProcessPolicyError, match="outside the trusted directories"):
            run_in(trusted)
        assert not marker.exists()

    def test_runs_a_binary_from_an_injected_trusted_directory(self, trusted: Path) -> None:
        tool = trusted / "sleep"
        tool.write_text("#!/bin/sh\nprintf custom\n", encoding="utf-8")
        tool.chmod(0o755)
        result = run_in(trusted, "sleep")
        assert result.stdout == b"custom"
        assert result.argv == (str(tool),)

    def test_start_failure_is_an_execution_error(self, trusted: Path) -> None:
        tool = trusted / "true"
        tool.write_text("not a program\n", encoding="utf-8")
        tool.chmod(0o755)
        with pytest.raises(process.ProcessExecutionError, match="cannot start"):
            run_in(trusted)

    def test_start_failure_without_a_strerror(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(*_: Any, **__: Any) -> Any:
            raise OSError

        monkeypatch.setattr(subprocess, "Popen", explode)
        with pytest.raises(process.ProcessExecutionError, match="OSError"):
            execute(process.CommandSpec("true", (), 1))

    def test_read_error_kills_the_child_and_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        children: list[Any] = []

        class Recording(subprocess.Popen[bytes]):
            """Popen that records every child it starts."""

            def __init__(self, *args: Any, **keywords: Any) -> None:
                super().__init__(*args, **keywords)
                children.append(self)

        def broken(descriptor: int) -> bytes:
            raise OSError(errno.EIO, f"Input/output error on {descriptor}")

        monkeypatch.setattr(subprocess, "Popen", Recording)
        monkeypatch.setattr(process, "_read_chunk", broken)
        with pytest.raises(process.ProcessExecutionError, match="Input/output error"):
            execute(shell("echo hi; sleep 30"))
        assert wait_until_dead(children[0].pid)
        assert children[0].returncode is not None


class TestExceptions:
    """Exception types and message escaping."""

    def test_hierarchy(self) -> None:
        assert issubclass(process.ProcessPolicyError, process.ProcessError)
        assert issubclass(process.ProcessExecutionError, process.ProcessError)
        assert issubclass(process.ProcessPolicyError, ValueError)
        assert not issubclass(process.ProcessPolicyError, process.ProcessExecutionError)

    def test_messages_never_contain_raw_untrusted_text(self) -> None:
        with pytest.raises(process.ProcessPolicyError) as raised:
            process.CommandSpec("true", ("-x\ty" + "z" * 200,), 1)
        message = str(raised.value)
        assert "\t" not in message
        assert "\\t" in message
        assert "z" * 100 not in message


class TestSubcommands:
    """Sub-command allow-list: only evaluation and information are permitted."""

    @pytest.mark.parametrize(
        "args",
        [
            ("xccdf", "eval"),
            (
                "xccdf",
                "eval",
                "--profile",
                "p",
                "--results",
                "r.xml",
                "--report",
                "r.html",
                "d.xml",
            ),
            ("info",),
            ("info", "datastream.xml"),
            ("--version",),
        ],
    )
    def test_permitted_commands(self, args: tuple[str, ...]) -> None:
        spec = process.CommandSpec("oscap", args, 1)
        assert process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES).name == "oscap"

    @pytest.mark.parametrize(
        "args",
        [
            ("xccdf", "remediate", "--results", "r.xml", "arf.xml"),
            ("xccdf", "generate", "fix", "arf.xml"),
            ("xccdf", "generate", "guide", "arf.xml"),
            ("xccdf", "eval", "--remediate", "d.xml"),
            ("xccdf", "eval", "--remediate=1", "d.xml"),
            ("xccdf", "eval", "remediate"),
            ("xccdf", "eval", "d.xml", "generate", "fix"),
            ("--remediate",),
            ("remediate",),
            ("generate", "fix"),
            ("info", "--remediate"),
            ("info", "remediate"),
            ("xccdf",),
            ("eval",),
            ("oval", "eval", "d.xml"),
            ("xccdf", "--profile", "p", "eval"),
            ("--version", "extra"),
            ("--version", "--version"),
            ("-V",),
            (),
        ],
    )
    def test_rejected_commands(self, args: tuple[str, ...]) -> None:
        spec = process.CommandSpec("oscap", args, 1)
        with pytest.raises(process.ProcessPolicyError):
            process.check_policy(spec, policies=process.ALLOWED_EXECUTABLES)

    def test_remediation_is_refused_before_resolution(self, trusted: Path) -> None:
        spec = process.CommandSpec("oscap", ("xccdf", "remediate", "a.xml"), 1)
        with pytest.raises(process.ProcessPolicyError, match="forbidden"):
            process.run(spec, trusted_dirs=[str(trusted)], owner_uid=OWNER)

    def test_forbidden_words_are_rejected_for_every_policy(self) -> None:
        policies = {"true": process.ExecutablePolicy("true", command_prefixes=ANY_ARGUMENTS)}
        for args in (("remediate",), ("--remediate",), ("generate", "fix")):
            spec = process.CommandSpec("true", args, 1)
            with pytest.raises(process.ProcessPolicyError, match="forbidden"):
                process.check_policy(spec, policies=policies)

    def test_a_policy_without_commands_permits_nothing(self) -> None:
        policies = {"true": process.ExecutablePolicy("true")}
        with pytest.raises(process.ProcessPolicyError, match="not allow-listed"):
            process.check_policy(process.CommandSpec("true", (), 1), policies=policies)


class TestHardening:
    """Ownership, encoding, re-validation and cleanup of detached children."""

    def test_defaults_are_strict(self) -> None:
        assert process.ROOT_UID == 0
        for function in (process.resolve_executable, process.run):
            assert inspect.signature(function).parameters["owner_uid"].default == 0

    def test_rejects_a_directory_with_the_wrong_owner(self, trusted: Path) -> None:
        make_tool(trusted)
        with pytest.raises(process.ProcessPolicyError, match="directory has the wrong owner"):
            process.resolve_executable("tool", trusted_dirs=[str(trusted)], owner_uid=OWNER + 1)

    def test_rejects_a_file_with_the_wrong_owner(
        self, trusted: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        make_tool(trusted)
        real = Path.stat

        def foreign(path: Path, *args: Any, **keywords: Any) -> os.stat_result:
            info = real(path, *args, **keywords)
            if path.name != "tool":
                return info
            fields = list(info)
            fields[4] = OWNER + 1
            return os.stat_result(tuple(fields))

        monkeypatch.setattr(Path, "stat", foreign)
        with pytest.raises(process.ProcessPolicyError, match="executable has the wrong owner"):
            resolve("tool", [str(trusted)])

    def test_rejects_a_group_writable_binary(self, trusted: Path) -> None:
        make_tool(trusted, mode=0o775)
        with pytest.raises(process.ProcessPolicyError, match="executable is writable"):
            resolve("tool", [str(trusted)])

    def test_rejects_a_group_writable_directory(self, trusted: Path) -> None:
        make_tool(trusted)
        trusted.chmod(0o775)
        with pytest.raises(process.ProcessPolicyError, match="directory is writable"):
            resolve("tool", [str(trusted)])

    def test_run_passes_the_owner_requirement_on(self, trusted: Path) -> None:
        make_tool(trusted, "true")
        spec = process.CommandSpec("true", (), 1)
        with pytest.raises(process.ProcessPolicyError, match="wrong owner"):
            process.run(spec, policies=POLICIES, trusted_dirs=[str(trusted)], owner_uid=OWNER + 1)

    @pytest.mark.parametrize("argument", ["\ud800", "a\udfffb"])
    def test_rejects_arguments_the_operating_system_cannot_encode(self, argument: str) -> None:
        with pytest.raises(process.ProcessPolicyError, match="cannot be encoded"):
            process.CommandSpec("oscap", (argument,), 1)

    def test_accepts_surrogate_escaped_bytes(self) -> None:
        spec = process.CommandSpec("oscap", ("\udc80",), 1)
        assert os.fsencode(spec.args[0]) == b"\x80"

    def test_rejects_a_cwd_the_operating_system_cannot_encode(self) -> None:
        with pytest.raises(process.ProcessPolicyError, match="cannot be encoded"):
            process.CommandSpec("oscap", (), 1, cwd="/\ud800")

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("args", ("a\x00b",)),
            ("args", ("x",) * (process.MAX_ARGUMENTS + 1)),
            ("args", ("\ud800",)),
            ("args", (7,)),
            ("timeout_seconds", 0.0),
            ("max_output_bytes", process.MAX_OUTPUT_BYTES + 1),
            ("env_allow", ("SECRET_TOKEN",)),
            ("cwd", "relative"),
            ("executable", "../true"),
        ],
    )
    def test_run_validates_a_mutated_specification_again(self, field: str, value: Any) -> None:
        spec = process.CommandSpec("true", (), FAST)
        object.__setattr__(spec, field, value)
        with pytest.raises(process.ProcessPolicyError):
            execute(spec)

    def test_a_detached_group_member_is_killed_after_a_normal_exit(self) -> None:
        result = execute(shell("sleep 60 >/dev/null 2>&1 & echo $!; exit 0"))
        pid = int(result.stdout.split()[0])
        assert not result.timed_out
        assert result.returncode == 0
        assert wait_until_dead(pid)

    def test_a_session_leader_holding_the_pipes_is_reported_as_timed_out(self) -> None:
        result = execute(shell("setsid sleep 60 & echo $!; exit 0", timeout=1.0))
        pid = int(result.stdout.split()[0])
        try:
            assert result.timed_out
            assert result.returncode == 0
        finally:
            os.kill(pid, signal.SIGKILL)


class TestImportTimePolicy:
    """The policy is bound when the module is imported."""

    def test_rebinding_module_globals_does_not_weaken_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(process, "ALLOWED_EXECUTABLES", POLICIES)
        monkeypatch.setattr(process, "TRUSTED_DIRECTORIES", ("/bin", "/usr/bin"))
        monkeypatch.setattr(process, "FORBIDDEN_OPTIONS", frozenset[str]())
        monkeypatch.setattr(process, "FORBIDDEN_WORDS", frozenset[str]())
        monkeypatch.setattr(process, "FORBIDDEN_SEQUENCES", frozenset[tuple[str, ...]]())
        spec = process.CommandSpec("sh", ("-c", "echo hi"), FAST)
        with pytest.raises(process.ProcessPolicyError, match="not allow-listed"):
            process.run(spec)
        remediate = process.CommandSpec("oscap", ("xccdf", "eval", "--remediate", "x"), FAST)
        with pytest.raises(process.ProcessPolicyError, match="forbidden"):
            process.check_policy(
                remediate,
                policies=dict(
                    POLICIES,
                    oscap=process.ExecutablePolicy(
                        "oscap", frozenset({"--remediate"}), command_prefixes=ANY_ARGUMENTS
                    ),
                ),
            )

    def test_rebinding_the_forbidden_options_does_not_weaken_check_policy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(process, "FORBIDDEN_OPTIONS", frozenset[str]())
        policies = {
            "oscap": process.ExecutablePolicy(
                "oscap", frozenset({"--fetch-remote-resources"}), command_prefixes=ANY_ARGUMENTS
            )
        }
        spec = process.CommandSpec("oscap", ("--fetch-remote-resources",), FAST)
        with pytest.raises(process.ProcessPolicyError, match="forbidden"):
            process.check_policy(spec, policies=policies)

    def test_the_bound_policy_is_a_copy(self) -> None:
        policies = {"true": POLICIES["true"]}
        none = frozenset[str]()
        run = process.bind_policy(policies, ("/bin",), none, none, frozenset[tuple[str, ...]]())[1]
        policies["sh"] = SHELL
        with pytest.raises(process.ProcessPolicyError, match="not allow-listed"):
            run(process.CommandSpec("sh", ("-c", "echo hi"), FAST))

    def test_the_bound_policy_values_are_deep_copies(self) -> None:
        mutable = {"-x"}
        loose = process.ExecutablePolicy(
            "true",
            allowed_options=cast("frozenset[str]", mutable),
            command_prefixes=ANY_ARGUMENTS,
        )
        none = frozenset[str]()
        run = process.bind_policy(
            {"true": loose}, ("/bin",), none, none, frozenset[tuple[str, ...]]()
        )[1]
        mutable.add("--evil")
        with pytest.raises(process.ProcessPolicyError, match="not allow-listed"):
            run(process.CommandSpec("true", ("--evil",), FAST))
