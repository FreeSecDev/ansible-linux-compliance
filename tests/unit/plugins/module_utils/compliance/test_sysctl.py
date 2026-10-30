from __future__ import annotations

import os
from pathlib import Path

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import sysctl


def tree(root: Path, values: dict[str, str]) -> Path:
    for name, value in values.items():
        path = root.joinpath(*(part.replace("/", ".") for part in name.split(".")))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")
    return root


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    return tree(
        tmp_path / "sys",
        {
            "kernel.dmesg_restrict": "0\n",
            "kernel.yama.ptrace_scope": "1\n",
            "net.ipv4.ip_local_port_range": "32768\t60999\n",
            "net.ipv4.conf.all.forwarding": "1\n",
            "net.ipv4.conf.default.forwarding": "1\n",
            "net.ipv4.conf.eth0/100.forwarding": "0\n",
            "net.ipv4.conf.lo.forwarding": "1\n",
            "kernel.core_pattern": "\n",
            "kernel.no_newline": "7",
        },
    )


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        ("kernel.dmesg_restrict", ("kernel", "dmesg_restrict")),
        ("net.ipv4.conf.eth0/100.forwarding", ("net", "ipv4", "conf", "eth0.100", "forwarding")),
        ("net.ipv6.conf.br-lan@x+1.accept_ra", ("net", "ipv6", "conf", "br-lan@x+1", "accept_ra")),
    ],
)
def test_names_become_path_components(name: str, parts: tuple[str, ...]) -> None:
    assert sysctl.components(name) == parts


@pytest.mark.parametrize(
    "name",
    [
        None,
        1,
        "",
        "kernel",
        "Kernel.x",
        "kernel..x",
        "kernel./",
        "kernel.//",
        "net.ipv4.conf.*.forwarding",
        "kernel.a b",
        "kernel.x\n",
        "kernel.-x/../..",
        "a.b.c.d.e.f.g.h.i",
        "kernel." + "x" * 65,
    ],
)
def test_names_of_another_form_are_refused(name: object) -> None:
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.components(name)
    assert raised.value.reason == "invalid_name"


def test_one_wildcard_is_allowed_only_where_asked() -> None:
    assert sysctl.components("net.ipv4.conf.*.forwarding", wildcard=True)[3] == "*"
    with pytest.raises(sysctl.SysctlError, match="wildcard"):
        sysctl.components("net.*.conf.*.forwarding", wildcard=True)


@pytest.mark.parametrize(
    "value", ["", "1", "32768 65535", "32768\t60999", "|/bin/false", "x" * 255]
)
def test_values_that_the_helper_writes(value: str) -> None:
    assert sysctl.check_value(value) == value


@pytest.mark.parametrize("value", [None, 1, "1\n", "x" * 256, "a\x00", "é"])
def test_values_that_the_helper_refuses(value: object) -> None:
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.check_value(value)
    assert raised.value.reason == "invalid_value"


def test_normalise_collapses_the_whitespace_between_fields() -> None:
    assert sysctl.normalise(" 32768\t 65535 ") == "32768 65535"
    assert sysctl.normalise("") == ""


def test_read_strips_one_line_break_and_reports_an_absent_parameter(proc: Path) -> None:
    assert sysctl.read("kernel.dmesg_restrict", proc_root=proc) == "0"
    assert sysctl.read("net.ipv4.ip_local_port_range", proc_root=proc) == "32768\t60999"
    assert sysctl.read("kernel.core_pattern", proc_root=proc) == ""
    assert sysctl.read("kernel.no_newline", proc_root=proc) == "7"
    assert sysctl.read("kernel.missing", proc_root=proc) is None
    assert sysctl.read("net.ipv4.conf.eth0/100.forwarding", proc_root=proc) == "0"


def test_read_refuses_a_directory_a_link_and_a_large_file(proc: Path) -> None:
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.read("net.ipv4.conf", proc_root=proc)
    assert raised.value.reason == "not_regular"
    (proc / "kernel" / "linked").symlink_to(proc / "kernel" / "dmesg_restrict")
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.read("kernel.linked", proc_root=proc)
    assert raised.value.reason == "unsafe_path"
    (proc / "fs").symlink_to(proc / "kernel")
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.read("fs.dmesg_restrict", proc_root=proc)
    assert raised.value.reason == "unsafe_path"
    (proc / "kernel" / "large").write_bytes(b"1" * (sysctl.MAX_READ_BYTES + 1))
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.read("kernel.large", proc_root=proc)
    assert raised.value.reason == "too_large"


def test_a_file_on_another_file_system_is_refused(
    proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Path.stat

    def other_device(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        found = real(self, follow_symlinks=follow_symlinks)
        if self == proc:
            values = list(found)
            values[2] = found.st_dev + 1
            return os.stat_result(values)
        return found

    monkeypatch.setattr(Path, "stat", other_device)
    with pytest.raises(sysctl.SysctlError, match="file system") as raised:
        sysctl.read("kernel.dmesg_restrict", proc_root=proc)
    assert raised.value.reason == "unsafe_path"


def test_inspection_and_read_errors_are_io_errors(
    proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(_self: Path) -> os.stat_result:
        raise PermissionError(13, "Permission denied")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", denied)
        with pytest.raises(sysctl.SysctlError, match="Permission denied") as raised:
            sysctl.read("kernel.dmesg_restrict", proc_root=proc)
    assert raised.value.reason == "io_error"
    (proc / "kernel" / "dmesg_restrict").chmod(0)
    if os.geteuid() != 0:
        with pytest.raises(sysctl.SysctlError) as raised:
            sysctl.read("kernel.dmesg_restrict", proc_root=proc)
        assert raised.value.reason == "io_error"
        assert sysctl.writable("kernel.dmesg_restrict", proc_root=proc) is False


def test_a_parameter_that_vanishes_while_it_is_read_is_absent(
    proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def vanished(_self: Path, *_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(Path, "open", vanished)
    assert sysctl.read("kernel.dmesg_restrict", proc_root=proc) is None


def test_expand_names_every_existing_entry_of_the_wildcard(proc: Path) -> None:
    (proc / "net" / "ipv4" / "conf" / "..x").mkdir()
    (proc / "net" / "ipv4" / "conf" / "bad name").mkdir()
    (proc / "net" / "ipv4" / "conf" / "bad name" / "forwarding").write_text("1\n")
    (proc / "net" / "ipv4" / "conf" / "nothing").mkdir()
    assert sysctl.expand("net.ipv4.conf.*.forwarding", proc_root=proc) == [
        "net.ipv4.conf.all.forwarding",
        "net.ipv4.conf.default.forwarding",
        "net.ipv4.conf.eth0/100.forwarding",
        "net.ipv4.conf.lo.forwarding",
    ]
    assert sysctl.expand("kernel.dmesg_restrict", proc_root=proc) == ["kernel.dmesg_restrict"]
    assert sysctl.expand("kernel.missing", proc_root=proc) == []
    assert sysctl.expand("net.ipv6.conf.*.forwarding", proc_root=proc) == []


def test_expand_refuses_a_linked_parent_and_too_many_entries(
    proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (proc / "linked").symlink_to(proc / "net")
    assert sysctl.expand("linked.ipv4.conf.*.forwarding", proc_root=proc) == []
    monkeypatch.setattr(sysctl, "MAX_EXPANDED", 2)
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.expand("net.ipv4.conf.*.forwarding", proc_root=proc)
    assert raised.value.reason == "too_large"


def test_expand_reports_a_listing_error(proc: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(_self: Path) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", denied)
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.expand("net.ipv4.conf.*.forwarding", proc_root=proc)
    assert raised.value.reason == "io_error"


def test_writable_opens_without_writing(proc: Path) -> None:
    assert sysctl.writable("kernel.dmesg_restrict", proc_root=proc) is True
    assert sysctl.read("kernel.dmesg_restrict", proc_root=proc) == "0"
    assert sysctl.writable("kernel.missing", proc_root=proc) is False


def test_a_read_only_parameter_is_not_writable(proc: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def read_only(_self: Path, *_args: object, **_kwargs: object) -> object:
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(Path, "open", read_only)
    assert sysctl.writable("kernel.dmesg_restrict", proc_root=proc) is False
    with pytest.raises(sysctl.SysctlError, match="Read-only file system") as raised:
        sysctl.write("kernel.dmesg_restrict", "1", proc_root=proc)
    assert raised.value.reason == "io_error"


def test_write_writes_the_value_and_a_line_break(proc: Path) -> None:
    sysctl.write("kernel.dmesg_restrict", "1", proc_root=proc)
    assert (proc / "kernel" / "dmesg_restrict").read_bytes() == b"1\n"
    sysctl.write("net.ipv4.ip_local_port_range", "32768\t60999", proc_root=proc)
    assert sysctl.read("net.ipv4.ip_local_port_range", proc_root=proc) == "32768\t60999"


def test_write_refuses_an_absent_parameter_and_a_bad_value(proc: Path) -> None:
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.write("kernel.missing", "1", proc_root=proc)
    assert raised.value.reason == "absent"
    with pytest.raises(sysctl.SysctlError) as raised:
        sysctl.write("kernel.dmesg_restrict", "1\n2", proc_root=proc)
    assert raised.value.reason == "invalid_value"
    assert sysctl.read("kernel.dmesg_restrict", proc_root=proc) == "0"


def test_the_error_keeps_its_reason() -> None:
    error = sysctl.SysctlError("absent", "gone")
    assert error.reason == "absent"
    assert str(error) == "gone"
    assert error.reason in sysctl.REASONS
