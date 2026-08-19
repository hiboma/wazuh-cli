use std::process::Command;

fn wazuh_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wazuh-cli"))
}

#[test]
fn root_help_contains_all_subcommands() {
    let output = wazuh_cli().arg("--help").output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let expected = vec![
        "agent",
        "group",
        "manager",
        "security",
        "rule",
        "decoder",
        "cluster",
        "syscheck",
        "syscollector",
        "rootcheck",
        "sca",
        "mitre",
        "list",
        "logtest",
        "task",
        "event",
        "active-response",
        "overview",
        "api-info",
        "completion",
    ];
    for sub in &expected {
        assert!(help.contains(sub), "Root help missing subcommand: {}", sub);
    }
}

#[test]
fn agent_help_contains_all_actions() {
    let output = wazuh_cli().args(["agent", "--help"]).output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let expected = vec![
        "list",
        "get",
        "create",
        "delete",
        "restart",
        "restart-all",
        "upgrade",
        "key",
        "groups",
        "add-group",
        "remove-group",
        "outdated",
        "summary-status",
        "summary-os",
    ];
    for action in &expected {
        assert!(
            help.contains(action),
            "Agent help missing action: {}",
            action
        );
    }
}

#[test]
fn agent_list_help_contains_filter_options() {
    let output = wazuh_cli()
        .args(["agent", "list", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let expected = vec![
        "--status", "--group", "--search", "--query", "--select", "--sort", "--limit", "--offset",
    ];
    for option in &expected {
        assert!(
            help.contains(option),
            "agent list help missing option: {}",
            option
        );
    }
}

#[test]
fn agent_list_accepts_filter_options() {
    // Parsing must succeed before any network access is attempted, so a missing
    // --api-url is the expected failure mode rather than a clap usage error (exit 2).
    let output = wazuh_cli()
        .args([
            "agent",
            "list",
            "--status",
            "active",
            "--group",
            "default",
            "--search",
            "compute-",
            "--query",
            "ip=10.0.0.1",
            "--select",
            "id,name,ip",
            "--sort",
            "name",
            "--limit",
            "10",
            "--offset",
            "0",
        ])
        .output()
        .unwrap();
    assert_ne!(
        output.status.code(),
        Some(2),
        "agent list filter options should parse without a usage error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_list_sort_accepts_descending_prefix() {
    // A descending sort value starts with '-', which clap would otherwise treat as
    // an unknown flag. allow_hyphen_values keeps the space-separated form working.
    for sort_value in ["-name", "-status,name"] {
        let output = wazuh_cli()
            .args(["agent", "list", "--sort", sort_value])
            .output()
            .unwrap();
        assert_ne!(
            output.status.code(),
            Some(2),
            "agent list --sort {} should parse without a usage error: {}",
            sort_value,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn agent_list_sort_rejects_a_following_option_as_its_value() {
    // allow_hyphen_values stops clap from rejecting a following option, so an
    // omitted value mid-command would otherwise consume the next flag and
    // silently drop it. A value_parser restores the usage error.
    for swallowed in ["--insecure", "--raw", "--quiet", "--limit"] {
        let output = wazuh_cli()
            .args(["agent", "list", "--sort", swallowed])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "agent list --sort {} should be a usage error, not silently swallow the flag: {}",
            swallowed,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn agent_list_sort_still_requires_a_value() {
    let status = wazuh_cli()
        .args(["agent", "list", "--sort"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(2),
        "agent list --sort without a value should be a usage error"
    );
}

#[test]
fn group_help_contains_all_actions() {
    let output = wazuh_cli().args(["group", "--help"]).output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let expected = vec![
        "list",
        "create",
        "delete",
        "agents",
        "config",
        "update-config",
        "files",
        "file",
    ];
    for action in &expected {
        assert!(
            help.contains(action),
            "Group help missing action: {}",
            action
        );
    }
}

#[test]
fn manager_help_contains_all_actions() {
    let output = wazuh_cli().args(["manager", "--help"]).output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let expected = vec![
        "status",
        "info",
        "config",
        "update-config",
        "stats",
        "logs",
        "restart",
        "validate-config",
        "api-config",
        "version-check",
    ];
    for action in &expected {
        assert!(
            help.contains(action),
            "Manager help missing action: {}",
            action
        );
    }
}

#[test]
fn security_help_contains_all_actions() {
    let output = wazuh_cli().args(["security", "--help"]).output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let expected = vec![
        "login",
        "logout",
        "user",
        "role",
        "policy",
        "rule",
        "config",
        "update-config",
        "reset-config",
    ];
    for action in &expected {
        assert!(
            help.contains(action),
            "Security help missing action: {}",
            action
        );
    }
}

#[test]
fn unknown_subcommand_exits_with_code_2() {
    let status = wazuh_cli().arg("nonexistent").status().unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn completion_generates_script_for_each_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = wazuh_cli().args(["completion", shell]).output().unwrap();
        assert!(
            output.status.success(),
            "completion {shell} exited non-zero: {:?}",
            output.status
        );
        assert!(
            !output.stdout.is_empty(),
            "completion {shell} produced empty stdout"
        );
    }
}

#[test]
fn completion_zsh_has_compdef_header() {
    let output = wazuh_cli().args(["completion", "zsh"]).output().unwrap();
    assert!(output.status.success());
    let script = String::from_utf8(output.stdout).unwrap();
    assert!(
        script.starts_with("#compdef wazuh-cli"),
        "zsh completion script should start with #compdef header"
    );
}

#[test]
fn completion_rejects_unknown_shell() {
    let status = wazuh_cli().args(["completion", "ksh"]).status().unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn global_options_are_accepted() {
    let output = wazuh_cli()
        .args([
            "--api-url",
            "https://localhost:55000",
            "--api-user",
            "wazuh",
            "--insecure",
            "agent",
            "--help",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Global options should be accepted without error"
    );
}
