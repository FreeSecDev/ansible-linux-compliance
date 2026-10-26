"""Fixed-path executables, exact argument forms and fixed environments (ADR 0019)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    process,
)

OWNER = os.getuid()
FAST = 10.0
PATH = process.PATH_ARGUMENT
SCAN = ("-o", "/var/run/x/options.xml", "-u", "/var/run/x/user", "-q", "-d")
SCRIPT = '#!/bin/sh\nprintf \'%s|%s|%s\\n\' "$TZ" "$*" "${HOME:-unset}"\n'


def fixed_tool(base: Path, mode: int = 0o755) -> Path:
    holder = base / "opt" / "tool"
    holder.mkdir(parents=True)
    holder.parent.chmod(0o755)
    holder.chmod(0o755)
    tool = holder / "cscc"
    tool.write_text(SCRIPT, encoding="utf-8")
    tool.chmod(mode)
    return tool


FIXED_TZ = (("TZ", "UTC0"),)


def policy_for(
    tool: Path, environment: tuple[tuple[str, str], ...] = FIXED_TZ
) -> dict[str, process.ExecutablePolicy]:
    policy = process.ExecutablePolicy(
        "cscc",
        standalone_commands=(("--version",),),
        fixed_path=str(tool),
        argument_forms=(("-o", PATH, "-u", PATH, "-q", "-d"),),
        environment=environment,
    )
    return {"cscc": policy}


def run_tool(
    tool: Path, args: tuple[str, ...], environment: tuple[tuple[str, str], ...] = FIXED_TZ
) -> process.CommandResult:
    return process.run(
        process.CommandSpec("cscc", args, FAST),
        policies=policy_for(tool, environment),
        owner_uid=OWNER,
    )


class TestSccPolicy:
    """The shipped policy for the SCAP Compliance Checker."""

    def test_the_scc_policy_names_one_fixed_path_and_two_forms(self) -> None:
        policy = process.ALLOWED_EXECUTABLES["cscc"]
        assert policy.fixed_path == "/opt/scc/cscc"
        assert policy.standalone_commands == (("--version",),)
        assert policy.argument_forms == (("-o", PATH, "-u", PATH, "-q", "-d"),)
        assert policy.environment == (("TZ", "UTC0"),)
        assert policy.allowed_options == frozenset()
        assert policy.command_prefixes == ()
        assert "/opt/scc" not in process.TRUSTED_DIRECTORIES

    def test_the_scan_form_and_the_version_are_permitted(self) -> None:
        for args in (SCAN, ("--version",)):
            spec = process.CommandSpec("cscc", args, FAST)
            assert process.check_policy(spec).name == "cscc"

    @pytest.mark.parametrize(
        "args",
        [
            ("-v",),
            ("--version", "-d"),
            ("-o", "/x/o.xml", "-u", "/x/u", "-q"),
            ("-o", "/x/o.xml", "-u", "/x/u", "-q", "-d", "-dn"),
            ("-o", "/x/o.xml", "-u", "/x/u", "-d", "-q"),
            ("-u", "/x/u", "-o", "/x/o.xml", "-q", "-d"),
            ("-o", "relative.xml", "-u", "/x/u", "-q", "-d"),
            ("-o", "/x/../etc/o.xml", "-u", "/x/u", "-q", "-d"),
            ("-o", "//x/o.xml", "-u", "/x/u", "-q", "-d"),
            ("-o", "/x/o.xml", "-u", "/x/u/", "-q", "-d"),
            ("-o", "-d", "-u", "/x/u", "-q", "-d"),
            ("--getOpt", "downloadExternalFiles"),
            ("--setOpt", "downloadExternalFiles", "1"),
            ("-isr", "/x/c.xml", "MAC-1_Classified"),
            ("--ssh", "unix"),
            ("--checkForContentUpdates", "--installAll"),
            ("--register", "a@b.c", "x"),
            ("-ds",),
            (),
        ],
    )
    def test_every_other_argument_list_is_refused(self, args: tuple[str, ...]) -> None:
        spec = process.CommandSpec("cscc", args, FAST)
        with pytest.raises(process.ProcessPolicyError):
            process.check_policy(spec)

    @pytest.mark.parametrize("word", ["remediate", "--remediate"])
    def test_forbidden_words_are_refused_before_the_forms(self, word: str) -> None:
        spec = process.CommandSpec("cscc", ("-o", word, "-u", "/x", "-q", "-d"), FAST)
        with pytest.raises(process.ProcessPolicyError, match="forbidden"):
            process.check_policy(spec)

    def test_a_missing_or_unsafe_scc_installation_never_runs(self) -> None:
        if Path(process.SCC_EXECUTABLE_PATH).exists():
            pytest.skip("SCC is installed on this host")
        with pytest.raises(process.ProcessError):
            process.run(process.CommandSpec("cscc", ("--version",), FAST))


class TestFixedExecutable:
    """Vetting of the fixed path and running through it."""

    def test_runs_the_fixed_path_with_the_fixed_environment(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        result = run_tool(tool, ("-o", "/a/o.xml", "-u", "/a/u", "-q", "-d"))
        assert result.returncode == 0
        assert result.argv[0] == str(tool)
        assert result.stdout.decode() == "UTC0|-o /a/o.xml -u /a/u -q -d|unset\n"

    def test_the_fixed_environment_overrides_a_copied_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TZ", "EST5EDT")
        tool = fixed_tool(tmp_path)
        spec = process.CommandSpec("cscc", ("--version",), FAST, env_allow=("TZ",))
        result = process.run(spec, policies=policy_for(tool), owner_uid=OWNER)
        assert result.stdout.decode().startswith("UTC0|--version|")

    def test_the_fixed_path_is_used_even_when_the_trusted_directories_hold_the_name(
        self, tmp_path: Path
    ) -> None:
        tool = fixed_tool(tmp_path)
        other = tmp_path / "trusted"
        other.mkdir(mode=0o755)
        decoy = other / "cscc"
        decoy.write_text("#!/bin/sh\necho decoy\n", encoding="utf-8")
        decoy.chmod(0o755)
        result = process.run(
            process.CommandSpec("cscc", ("--version",), FAST),
            policies=policy_for(tool),
            trusted_dirs=[str(other)],
            owner_uid=OWNER,
        )
        assert "decoy" not in result.stdout.decode()

    @pytest.mark.parametrize("path", ["relative/cscc", "/a/../cscc", "//a/cscc", "/", "/a/b/"])
    def test_rejects_malformed_paths(self, path: str) -> None:
        with pytest.raises(process.ProcessPolicyError, match="absolute and normalised"):
            process.vet_fixed_executable(path, owner_uid=OWNER)

    def test_rejects_a_path_with_nul(self) -> None:
        with pytest.raises(process.ProcessPolicyError, match="absolute and normalised"):
            process.vet_fixed_executable("/a/\x00b", owner_uid=OWNER)

    def test_a_missing_file_is_an_execution_error(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        tool.unlink()
        with pytest.raises(process.ProcessExecutionError, match="executable not found"):
            process.vet_fixed_executable(str(tool), owner_uid=OWNER)

    def test_a_missing_directory_is_an_execution_error(self, tmp_path: Path) -> None:
        with pytest.raises(process.ProcessExecutionError, match="does not exist"):
            process.vet_fixed_executable(str(tmp_path / "none" / "cscc"), owner_uid=OWNER)

    def test_rejects_a_symlinked_executable(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        link = tool.with_name("link")
        link.symlink_to(tool)
        with pytest.raises(process.ProcessPolicyError, match="not a regular file"):
            process.vet_fixed_executable(str(link), owner_uid=OWNER)

    def test_rejects_a_symlinked_directory(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        alias = tmp_path / "alias"
        alias.symlink_to(tool.parent)
        with pytest.raises(process.ProcessPolicyError, match="not a real directory"):
            process.vet_fixed_executable(str(alias / "cscc"), owner_uid=OWNER)

    def test_rejects_a_writable_executable(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path, mode=0o775)
        with pytest.raises(process.ProcessPolicyError, match="executable is writable"):
            process.vet_fixed_executable(str(tool), owner_uid=OWNER)

    def test_rejects_a_file_that_is_not_executable(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path, mode=0o644)
        with pytest.raises(process.ProcessPolicyError, match="not executable"):
            process.vet_fixed_executable(str(tool), owner_uid=OWNER)

    def test_rejects_a_directory_instead_of_a_file(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        with pytest.raises(process.ProcessPolicyError, match="not a regular file"):
            process.vet_fixed_executable(str(tool.parent), owner_uid=OWNER)

    def test_rejects_a_file_of_another_owner(self) -> None:
        if OWNER == 0:
            pytest.skip("needs a file that is not owned by the test user")
        with pytest.raises(process.ProcessPolicyError, match=r"^executable has the wrong owner"):
            process.vet_fixed_executable(str(Path("/bin/sh").resolve()), owner_uid=OWNER)

    def test_rejects_a_directory_of_another_owner(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        if OWNER == 0:
            pytest.skip("every directory is owned by root or the owner when the owner is root")
        with pytest.raises(process.ProcessPolicyError, match="directory of the executable has"):
            process.vet_fixed_executable(str(tool), owner_uid=OWNER + 1)

    def test_rejects_a_writable_holding_directory_even_when_sticky(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        tool.parent.chmod(0o1777)
        try:
            with pytest.raises(process.ProcessPolicyError, match="directory of the executable is"):
                process.vet_fixed_executable(str(tool), owner_uid=OWNER)
        finally:
            tool.parent.chmod(0o755)

    def test_rejects_a_writable_ancestor_without_the_sticky_bit(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        tool.parent.parent.chmod(0o777)
        try:
            with pytest.raises(process.ProcessPolicyError, match="directory of the executable is"):
                process.vet_fixed_executable(str(tool), owner_uid=OWNER)
        finally:
            tool.parent.parent.chmod(0o755)

    def test_accepts_a_sticky_writable_ancestor(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        tool.parent.parent.chmod(0o1777)
        try:
            assert process.vet_fixed_executable(str(tool), owner_uid=OWNER) == str(tool)
        finally:
            tool.parent.parent.chmod(0o755)

    def test_vetting_happens_before_every_run(self, tmp_path: Path) -> None:
        tool = fixed_tool(tmp_path)
        assert run_tool(tool, ("--version",)).returncode == 0
        tool.chmod(0o777)
        with pytest.raises(process.ProcessPolicyError, match="writable"):
            run_tool(tool, ("--version",))


class TestFixedEnvironment:
    """Environment values that a policy fixes."""

    @pytest.mark.parametrize(
        ("name", "value", "message"),
        [
            ("PATH", "/var/x", "may not be fixed"),
            ("LD_PRELOAD", "/x.so", "may not be fixed"),
            ("TZ", "", "invalid"),
            ("TZ", "UTC 0", "invalid"),
            ("HOME", "/root\n", "invalid"),
        ],
    )
    def test_run_refuses_an_unsafe_fixed_environment(
        self, tmp_path: Path, name: str, value: str, message: str
    ) -> None:
        tool = fixed_tool(tmp_path)
        with pytest.raises(process.ProcessPolicyError, match=message):
            run_tool(tool, ("--version",), ((name, value),))

    def test_binding_refuses_an_unsafe_fixed_environment(self) -> None:
        unsafe = {"x": process.ExecutablePolicy("x", environment=(("PATH", "/var/x"),))}
        none = frozenset[str]()
        with pytest.raises(process.ProcessPolicyError, match="may not be fixed"):
            process.bind_policy(unsafe, ("/bin",), none, none, frozenset[tuple[str, ...]]())

    def test_the_bound_policy_copies_the_new_fields(self) -> None:
        forms = [["-o", PATH]]
        policy = process.ExecutablePolicy(
            "x",
            fixed_path="/opt/x/x",
            argument_forms=tuple(tuple(form) for form in forms),
            environment=(("TZ", "UTC0"),),
        )
        none = frozenset[str]()
        check = process.bind_policy(
            {"x": policy}, ("/bin",), none, none, frozenset[tuple[str, ...]]()
        )[0]
        forms[0].append("-d")
        bound = check(process.CommandSpec("x", ("-o", "/a"), FAST))
        assert bound.fixed_path == "/opt/x/x"
        assert bound.argument_forms == (("-o", PATH),)
        assert bound.environment == (("TZ", "UTC0"),)
