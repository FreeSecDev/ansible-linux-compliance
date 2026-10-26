from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path
from typing import cast

import yaml

from tools.lint.repo_rules import (
    ansible_tasks,
    exec_config,
    exec_modules,
    exec_variables,
    jinja_calls,
    load_config,
)

EXEC_OPTION = re.compile(r"(?:^|_)(?:args|exe|executable|flags|command|cmd)$|^pkcs11_provider$")
REVIEWED_MODULES = frozenset(
    {
        "add_host",
        "apt_key",
        "apt_repository",
        "assert",
        "async_status",
        "async_wrapper",
        "deb822_repository",
        "debconf",
        "debug",
        "dpkg_selections",
        "fail",
        "fetch",
        "file",
        "find",
        "get_url",
        "getent",
        "group",
        "group_by",
        "hostname",
        "import_playbook",
        "import_role",
        "import_tasks",
        "include_role",
        "include_tasks",
        "include_vars",
        "iptables",
        "known_hosts",
        "meta",
        "package_facts",
        "pause",
        "ping",
        "rpm_key",
        "service_facts",
        "set_fact",
        "set_stats",
        "slurp",
        "stat",
        "systemd",
        "systemd_service",
        "sysvinit",
        "tempfile",
        "uri",
        "user",
        "validate_argument_spec",
        "wait_for",
        "wait_for_connection",
        "yum_repository",
    }
)
REVIEWED_MODULE_OPTIONS = frozenset(
    {
        ("hostname", "use"),
        ("import_role", "rolespec_validate"),
        ("include_role", "rolespec_validate"),
        ("validate_argument_spec", "provided_arguments"),
        ("iptables", "tcp_flags"),
        ("iptables", "match_set_flags"),
        ("service", "arguments"),
        ("sysvinit", "arguments"),
        ("user", "shell"),
    }
)
REVIEWED_SETTINGS = frozenset(
    {
        "action_warnings",
        "agnostic_become_prompt",
        "allow_broken_conditionals",
        "allow_embedded_templates",
        "always",
        "ansible_managed",
        "any_errors_fatal",
        "any_unparsed_is_failed",
        "ask_pass",
        "ask_vault_pass",
        "become",
        "become_allow_same_user",
        "become_ask_pass",
        "become_user",
        "bin_ansible_callbacks",
        "cache_dir",
        "changed",
        "collection_skeleton_ignore",
        "collections_on_ansible_version_mismatch",
        "collections_path_warning",
        "collections_scan_sys_path",
        "command_timeout",
        "connect_retry_timeout",
        "connect_timeout",
        "console_prompt",
        "context",
        "control_path_dir",
        "cow_selection",
        "cowsay_enabled_stencils",
        "debug",
        "deprecate",
        "deprecated",
        "deprecation_warnings",
        "devel_warning",
        "diff_add",
        "diff_lines",
        "diff_remove",
        "disable_gpg_verify",
        "display_args_to_stdout",
        "display_progress",
        "display_skipped_hosts",
        "display_traceback",
        "doc_constant",
        "doc_deprecated",
        "doc_link",
        "doc_module",
        "doc_plugin",
        "doc_reference",
        "docsite_root_url",
        "dont_type_filters",
        "duplicate_dict_key",
        "enable_task_debugger",
        "error",
        "error_on_missing_handler",
        "error_on_undefined_vars",
        "export",
        "fact_caching_prefix",
        "fact_caching_timeout",
        "force_color",
        "force_handlers",
        "force_valid_group_names",
        "forks",
        "gathering",
        "gpg_keyring",
        "hash_behaviour",
        "highlight",
        "host_key_checking",
        "host_pattern_mismatch",
        "ignore_certs",
        "ignore_extensions",
        "ignore_patterns",
        "ignore_signature_status_codes",
        "included",
        "inject_facts_as_vars",
        "inject_invocation",
        "internal_poll_interval",
        "invalid_task_attribute_failed",
        "inventory_ignore_extensions",
        "inventory_ignore_patterns",
        "inventory_unparsed_warning",
        "jinja2_native",
        "keep_remote_files",
        "libvirt_lxc_noseclabel",
        "local_tmp",
        "localhost_warning",
        "log_filter",
        "log_path",
        "log_verbosity",
        "max_diff_size",
        "module_compression",
        "module_ignore_exts",
        "module_strict_utf8_response",
        "network_group_modules",
        "no_log",
        "no_target_syslog",
        "nocolor",
        "nocows",
        "null_representation",
        "ok",
        "old_plugin_cache_clear",
        "pipelining",
        "playbook_vars_root",
        "plugin_filters_cfg",
        "poll_interval",
        "precedence",
        "private_key_file",
        "private_role_vars",
        "python_module_rlimit_nofile",
        "remote_port",
        "remote_user",
        "required_valid_signature_count",
        "retry_files_enabled",
        "retry_files_save_path",
        "role_skeleton_ignore",
        "run",
        "run_vars_plugins",
        "server",
        "server_list",
        "server_timeout",
        "show_custom_stats",
        "skip",
        "special_context_filesystems",
        "ssh_agent",
        "ssh_agent_key_lifetime",
        "su",
        "syslog_facility",
        "system_warnings",
        "target_log_info",
        "task_debugger_ignore_errors",
        "task_timeout",
        "timeout",
        "token_path",
        "unparsed_is_failed",
        "unreachable",
        "use_persistent_connections",
        "valid",
        "valid2",
        "valid3",
        "validate_action_group_metadata",
        "vault_encrypt_identity",
        "vault_encrypt_salt",
        "vault_id_match",
        "vault_identity",
        "verbose",
        "verbose_to_stderr",
        "verbosity",
        "warn",
        "win_async_startup_timeout",
        "worker_session_isolation",
        "yaml_valid_extensions",
    }
)
REVIEWED_ENVIRONMENT_ONLY = frozenset(
    {
        "_ANSIBLE_CALLBACK_DISPATCH_ERROR_BEHAVIOR",
        "_ANSIBLE_MODULE_METADATA",
        "_ANSIBLE_COVERAGE_REMOTE_PATH_FILTER",
        "ANSIBLE_GALAXY_COLLECTION_IMPORT_POLL_INTERVAL",
        "ANSIBLE_GALAXY_COLLECTION_IMPORT_POLL_FACTOR",
        "_ANSIBLE_TEMPLAR_UNKNOWN_TYPE_CONVERSION",
        "_ANSIBLE_TEMPLAR_UNKNOWN_TYPE_ENCOUNTERED",
        "_ANSIBLE_TEMPLAR_UNTRUSTED_TEMPLATE_BEHAVIOR",
        "ANSIBLE_WORKER_SHUTDOWN_POLL_COUNT",
        "ANSIBLE_WORKER_SHUTDOWN_POLL_DELAY",
    }
)
EXEC_OPTION_DESTINATIONS = frozenset(
    {
        "ssh_common_args",
        "ssh_extra_args",
        "sftp_extra_args",
        "scp_extra_args",
        "vault_ids",
        "vault_password_files",
        "connection_password_file",
        "become_password_file",
    }
)


def ansible_package() -> Path:
    spec = importlib.util.find_spec("ansible")
    assert spec is not None
    assert spec.submodule_search_locations is not None
    return Path(next(iter(spec.submodule_search_locations)))


def source(relative: str) -> str:
    return (ansible_package() / relative).read_text(encoding="utf-8")


def plugin_names(kind: str) -> frozenset[str]:
    directory = ansible_package() / "plugins" / kind
    return frozenset(path.stem for path in directory.glob("*.py") if path.stem != "__init__")


def documentation(path: Path) -> dict[str, object]:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "DOCUMENTATION"
            and isinstance(node.value, ast.Constant)
        ):
            return cast("dict[str, object]", yaml.safe_load(str(node.value.value)))
    return {}


def options(path: Path) -> dict[str, dict[str, object]]:
    found = documentation(path).get("options")
    return cast("dict[str, dict[str, object]]", found) if isinstance(found, dict) else {}


def names(option: dict[str, object], kind: str, field: str = "name") -> set[str]:
    entries = option.get(kind)
    if not isinstance(entries, list):
        return set()
    return {
        str(cast("dict[str, object]", entry)[field])
        for entry in cast("list[object]", entries)
        if isinstance(entry, dict)
    }


def exec_plugin_options(kinds: tuple[str, ...]) -> list[dict[str, object]]:
    return [
        option
        for kind in kinds
        for plugin in sorted((ansible_package() / "plugins" / kind).glob("*.py"))
        for name, option in options(plugin).items()
        if EXEC_OPTION.search(name)
    ]


def base_settings() -> list[dict[str, object]]:
    loaded = cast("dict[str, dict[str, object]]", yaml.safe_load(source("config/base.yml")))
    return list(loaded.values())


def test_every_lookup_is_reviewed_and_the_command_lookups_are_the_ones_that_run_one() -> None:
    lookups = plugin_names("lookup")
    assert lookups == jinja_calls.REVIEWED_LOOKUPS | jinja_calls.COMMAND_LOOKUPS
    assert not jinja_calls.REVIEWED_LOOKUPS & jinja_calls.COMMAND_LOOKUPS
    process = re.compile(r"\b(?:subprocess|Popen|os\.system|os\.popen|os\.exec\w*|run_command)\b")
    running = {
        name for name in lookups if process.search(source(f"plugins/lookup/{name}.py")) is not None
    }
    assert running == jinja_calls.COMMAND_LOOKUPS == {"pipe", "lines"}
    assert "env" in jinja_calls.REVIEWED_LOOKUPS


def test_the_lookup_functions_are_the_jinja_globals_of_ansible() -> None:
    bits = source("_internal/_templating/_jinja_bits.py")
    globals_ = set(re.findall(r"^\s+(\w+)=_(?:lookup|query),$", bits, re.MULTILINE))
    assert globals_ == jinja_calls.LOOKUP_FUNCTIONS


def test_the_override_header_and_delimiters_are_the_ones_ansible_reads() -> None:
    bits = source("_internal/_templating/_jinja_bits.py")
    assert f"JINJA2_OVERRIDE = '{jinja_calls.OVERRIDE_HEADER}'" in bits
    overrides = next(
        node
        for node in ast.parse(bits).body
        if isinstance(node, ast.ClassDef) and node.name == "TemplateOverrides"
    )
    fields = {
        node.target.id
        for node in overrides.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    delimiters = {name for name in fields if name.endswith(("_string", "_prefix"))}
    assert delimiters == jinja_calls.DELIMITER_OPTIONS
    assert (
        "return value.startswith(JINJA2_OVERRIDE) or overrides._contains_start_string(value)"
        in (bits)
    )


def test_the_unsafe_lookup_options_are_the_documented_ones() -> None:
    base = source("config/base.yml")
    assert "users should first consider adding allow_unsafe=True to any lookups" in base
    assert "key: allow_unsafe_lookups" in base
    assert {"allow_unsafe", "allow_unsafe_lookups"} == jinja_calls.UNSAFE_OPTIONS


def test_every_ansible_core_module_is_classified() -> None:
    modules = frozenset(
        path.stem
        for path in (ansible_package() / "modules").glob("*.py")
        if path.stem != "__init__"
    )
    refused = ansible_tasks.TASK_BANNED_MODULES - {"win_shell", "win_command"}
    with_parameters = frozenset(exec_modules.MODULE_PARAMETERS)
    assert not REVIEWED_MODULES & (refused | with_parameters)
    assert modules == refused | with_parameters | REVIEWED_MODULES
    assert {"expect", "cron"} == ansible_tasks.TASK_ONLY_BANNED_MODULES


def module_options(name: str) -> set[str]:
    found: set[str] = set()
    for option, spec in options(ansible_package() / "modules" / f"{name}.py").items():
        found.add(option)
        aliases = spec.get("aliases")
        if isinstance(aliases, list):
            found.update(str(alias) for alias in cast("list[object]", aliases))
    return found


def test_every_refused_parameter_is_an_option_of_its_module() -> None:
    fragment = options(ansible_package() / "plugins" / "doc_fragments" / "validate.py")
    for module, parameters in exec_modules.MODULE_PARAMETERS.items():
        known = module_options(module)
        if parameters == exec_modules.VALIDATE:
            known |= set(fragment)
        if module == "gather_facts":
            known = module_options("setup")
        assert parameters <= known, module


def test_every_module_option_that_names_a_command_is_refused_or_reviewed() -> None:
    pattern = re.compile(
        r"(?:^|_)(?:exe|executable|command|cmd|args|arguments|opts|flags|binary|shell|use|"
        r"validate|fact_path|conf_file|job)$"
    )
    unreviewed = {
        (module, option)
        for module in REVIEWED_MODULES | frozenset(exec_modules.MODULE_PARAMETERS)
        for option in module_options(module)
        if pattern.search(option)
        and option not in exec_modules.MODULE_PARAMETERS.get(module, frozenset())
        and option != "args"
    }
    assert unreviewed == REVIEWED_MODULE_OPTIONS


def test_the_play_keyword_fact_path_exists() -> None:
    assert "fact_path = NonInheritableFieldAttribute" in source("playbook/play.py")
    assert {"fact_path"} == exec_modules.PLAY_KEYWORDS


def test_every_executable_option_of_a_connection_or_become_plugin_is_refused() -> None:
    found = exec_plugin_options(("connection", "become"))
    variables = {name for option in found for name in names(option, "vars")}
    assert (
        variables == exec_variables.CONNECTION_EXEC_VARIABLES | exec_variables.BECOME_EXEC_VARIABLES
    )
    assert {name for option in found for name in names(option, "keyword")} == (
        exec_variables.EXEC_KEYWORDS
    )
    assert {name for option in found for name in names(option, "ini", "key")} <= (
        exec_config.CODE_SETTINGS
    )
    assert {name for option in found for name in names(option, "env")} <= (
        exec_config.CODE_ENVIRONMENT_VARIABLES
    )
    assert all(exec_variables.is_exec_variable(name) for name in variables)


def test_every_executable_magic_variable_is_refused() -> None:
    tree = ast.parse(source("constants.py"))
    mapping = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "MAGIC_VARIABLE_MAPPING"
    )
    assert isinstance(mapping, ast.Call)
    executable = {
        cast("str", element.value)
        for keyword in mapping.keywords
        if keyword.arg is not None and EXEC_OPTION.search(keyword.arg)
        for element in cast("ast.Tuple", keyword.value).elts
        if isinstance(element, ast.Constant)
    }
    assert "ansible_shell_executable" in executable
    assert all(exec_variables.is_exec_variable(name) for name in executable)
    selectors = {"ansible_connection", "ansible_become_method", "ansible_shell_type"}
    assert selectors <= set(exec_variables.SELECTORS)


def test_the_interpreter_variables_are_the_ones_ansible_reads() -> None:
    common = source("executor/module_common.py")
    assert "interpreter_config = u'ansible_%s_interpreter' % interpreter_name" in common
    assert "discovered_interpreter_config = u'discovered_interpreter_%s' % interpreter_name" in (
        common
    )
    for name in (
        "ansible_python_interpreter",
        "ansible_bash_interpreter",
        "discovered_interpreter_ruby",
    ):
        assert exec_variables.is_exec_variable(name)
    package = source("plugins/action/package.py")
    assert "tvars.get('ansible_package_use', None)" in package
    assert "'pkg_mgr'" in package
    assert "ansible_facts.service_mgr" in source("plugins/action/service.py")


def test_the_selectable_plugins_are_the_plugins_of_ansible_core() -> None:
    assert plugin_names("connection") == exec_variables.CONNECTION_PLUGINS
    assert plugin_names("become") == exec_variables.BECOME_PLUGINS
    assert plugin_names("shell") == exec_variables.SHELL_PLUGINS
    selectors = exec_config.PLUGIN_SELECTOR_SETTINGS
    assert selectors["stdout_callback"] == plugin_names("callback")
    assert selectors["fact_caching"] == plugin_names("cache") - {"base"}
    assert selectors["strategy"] == plugin_names("strategy") - {"debug"}
    assert selectors["become_method"] == plugin_names("become")
    assert selectors["transport"] == plugin_names("connection")


def test_every_setting_of_base_yml_is_classified() -> None:
    settings = base_settings()
    keys = {key for setting in settings for key in names(setting, "ini", "key")}
    classified = (
        exec_config.BASE_CODE_SETTINGS
        | frozenset(exec_config.PLUGIN_SELECTOR_SETTINGS)
        | load_config.CONFIG_PATH_SETTINGS
    )
    assert not REVIEWED_SETTINGS & classified
    assert keys | {"collections_paths"} == classified | REVIEWED_SETTINGS
    environment_only = {
        name for setting in settings if not setting.get("ini") for name in names(setting, "env")
    }
    assert environment_only == REVIEWED_ENVIRONMENT_ONLY | (
        environment_only & exec_config.CODE_ENVIRONMENT_VARIABLES
    )


def test_every_environment_variable_and_variable_of_a_code_setting_is_refused() -> None:
    refused = exec_config.BASE_CODE_SETTINGS | frozenset(exec_config.PLUGIN_SELECTOR_SETTINGS)
    settings = [
        setting
        for setting in base_settings()
        if names(setting, "ini", "key") & refused
        or (not setting.get("ini") and names(setting, "env") - REVIEWED_ENVIRONMENT_ONLY)
    ]
    environment = {name for setting in settings for name in names(setting, "env")}
    assert environment - {"EDITOR", "PAGER"} <= exec_config.CODE_ENVIRONMENT_VARIABLES
    variables = {name for setting in settings for name in names(setting, "vars")}
    assert variables
    assert all(exec_variables.is_exec_variable(name) for name in variables)


def test_every_command_line_option_that_passes_arguments_or_a_script_is_refused() -> None:
    tree = ast.parse(source("cli/arguments/option_helpers.py"))
    flags: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            continue
        destination = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "dest"), None
        )
        if isinstance(destination, ast.Constant) and destination.value in EXEC_OPTION_DESTINATIONS:
            flags.update(
                str(argument.value)
                for argument in node.args
                if isinstance(argument, ast.Constant) and str(argument.value).startswith("--")
            )
    assert flags == exec_config.CODE_OPTIONS
