mod support;

use std::io::Write;
use std::process::{Command, Output, Stdio};
use support::{Reply, mock};

const PASSWORD: &str = "password-CLI-SENTINEL";
const USER_PASSWORD: &str = "user-password-CLI-SENTINEL";
const JWT: &str = "jwt-CLI-SENTINEL";
const SESSION: &str = "session-CLI-SENTINEL";

fn dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "wazuh-security-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

fn run(url: &str, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wazuh-cli"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("WAZUH_")) {
        command.env_remove(key);
    }
    command
        .env(
            "WAZUH_API_PASSWORD",
            if args.iter().any(|arg| arg.starts_with("--api-password-")) {
                "unused-env-SENTINEL"
            } else {
                PASSWORD
            },
        )
        .env("WAZUH_API_URL", url)
        .env("WAZUH_INSECURE", "true")
        .env("XDG_CONFIG_HOME", dir())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn no_secrets(output: &Output, secrets: &[&str]) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in secrets {
            assert!(!text.contains(secret), "secret appeared in process output");
        }
    }
}

#[test]
fn user_create_and_update_never_echo_reflected_credentials() {
    for raw in [false, true] {
        for action in [
            vec![
                "security",
                "user",
                "create",
                "--username",
                "alice",
                "--password-stdin",
            ],
            vec!["security", "user", "update", "101", "--password-stdin"],
        ] {
            for status in [200, 400] {
                let body = serde_json::json!({"message": format!("{PASSWORD} {USER_PASSWORD} {JWT}"), "data":{"affected_items":[{"username":"alice","password":USER_PASSWORD}]}});
                let server = mock(vec![
                    Reply::new(200, JWT),
                    Reply::new(status, body.to_string()),
                ]);
                let mut args = action.clone();
                if raw {
                    args.push("--raw");
                }
                let output = run(&server.url, &args, Some(USER_PASSWORD));
                assert_eq!(output.status.success(), status == 200);
                no_secrets(&output, &[PASSWORD, USER_PASSWORD, JWT]);
                let requests = server.finish();
                assert!(requests[1].contains(USER_PASSWORD));
                if status == 200 {
                    assert!(String::from_utf8_lossy(&output.stdout).contains("alice"));
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn api_password_stdin_and_file_reach_authentication_and_export_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let directory = dir();
    let password_file = directory.join("password");
    std::fs::write(&password_file, PASSWORD).unwrap();
    std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    for from_file in [false, true] {
        let export = directory.join(if from_file {
            "file-response"
        } else {
            "stdin-response"
        });
        let server = mock(vec![Reply::new(200, JWT), Reply::new(200, serde_json::json!({"data":{"token":SESSION,"key":"enrollment-SENTINEL","echo":SESSION}}).to_string())]);
        let mut args = vec![
            "logtest",
            "run",
            "--log",
            "example",
            "--raw",
            "--secret-output-file",
            export.to_str().unwrap(),
        ];
        if from_file {
            args.extend(["--api-password-file", password_file.to_str().unwrap()]);
        } else {
            args.push("--api-password-stdin");
        }
        let output = run(&server.url, &args, (!from_file).then_some(PASSWORD));
        assert!(output.status.success());
        no_secrets(&output, &[PASSWORD, JWT, SESSION, "enrollment-SENTINEL"]);
        let exported = std::fs::read_to_string(&export).unwrap();
        assert!(exported.contains(SESSION));
        assert!(!exported.contains(PASSWORD));
        assert_eq!(
            std::fs::metadata(&export).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            server.finish()[0]
                .to_ascii_lowercase()
                .contains("authorization: basic d2f6dwg6cgfzc3dvcmqtq0xjlvnftlrjtkvm")
        );
        assert!(wazuh_cli::output::write_secret_response(&export, &serde_json::json!({})).is_err());
        assert_eq!(std::fs::read_to_string(&export).unwrap(), exported);
    }
}

#[test]
fn session_stdin_is_sent_but_never_reflected_or_shown_on_failure() {
    let server = mock(vec![
        Reply::new(200, JWT),
        Reply::new(200, serde_json::json!({"echo":SESSION}).to_string()),
    ]);
    let output = run(
        &server.url,
        &["logtest", "delete-session", "--token-stdin"],
        Some(SESSION),
    );
    assert!(output.status.success());
    no_secrets(&output, &[SESSION, JWT, PASSWORD]);
    assert!(server.finish()[1].contains(&format!("/logtest/sessions/{SESSION}")));
    // The mock closes its listening socket after successful authentication;
    // the DELETE fails with a token-bearing URL, exercising HTTP redaction.
    let server = mock(vec![Reply::new(200, JWT)]);
    let output = run(
        &server.url,
        &["logtest", "delete-session", "--token-stdin"],
        Some(SESSION),
    );
    assert!(!output.status.success());
    no_secrets(&output, &[SESSION, JWT, PASSWORD]);
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn insecure_sources_warn_on_loopback_and_reject_remote_hosts() {
    for source in ["cli", "env", "file"] {
        for loopback in [false, true] {
            let directory = dir();
            let config = directory.join("config.toml");
            std::fs::write(
                &config,
                if source == "file" {
                    "[tls]\ninsecure=true\n"
                } else {
                    ""
                },
            )
            .unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_wazuh-cli"));
            command
                .env_clear()
                .env("WAZUH_API_PASSWORD", PASSWORD)
                .arg("--config")
                .arg(&config)
                .args([
                    "--api-url",
                    if loopback {
                        "https://127.0.0.1:9"
                    } else {
                        "https://example.invalid"
                    },
                ]);
            match source {
                "cli" => {
                    command.arg("--insecure");
                }
                "env" => {
                    command.env("WAZUH_INSECURE", "true");
                }
                _ => {}
            }
            let output = command.args(["agent", "list"]).output().unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(if loopback {
                "warning: TLS certificate verification is disabled"
            } else {
                "only be disabled for a literal loopback"
            }));
            no_secrets(&output, &[PASSWORD]);
        }
    }
}

#[test]
fn malformed_toml_never_echoes_secret_in_normal_or_raw_output() {
    let directory = dir();
    let config = directory.join("config.toml");
    std::fs::write(&config, format!("[api]\npassword = \"{PASSWORD}\" invalid")).unwrap();
    for raw in [false, true] {
        let mut args = vec!["--config", config.to_str().unwrap(), "agent", "list"];
        if raw {
            args.push("--raw");
        }
        let output = run("https://127.0.0.1:9", &args, None);
        assert!(!output.status.success());
        no_secrets(&output, &[PASSWORD]);
    }
}
