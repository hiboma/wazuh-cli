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
