use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use clap::Parser;
use serde_json::{Value, json};
use wazuh_cli::api::experimental;
use wazuh_cli::cli::{Cli, Command, experimental::ExperimentalCommand};
use wazuh_cli::client::WazuhClient;
use wazuh_cli::config::{Config, OutputFormat};

fn parse(args: &[&str]) -> ExperimentalCommand {
    let cli = Cli::try_parse_from(
        ["wazuh-cli", "experimental"]
            .into_iter()
            .chain(args.iter().copied()),
    )
    .unwrap();
    match cli.command {
        Command::Experimental(cmd) => cmd,
        _ => panic!("expected experimental command"),
    }
}

#[test]
fn all_experimental_endpoints_parse() {
    for args in [
        vec!["rootcheck", "clear", "001"],
        vec!["syscheck", "clear", "all"],
        vec!["ciscat", "results"],
    ] {
        parse(&args);
    }
    for endpoint in [
        "hardware",
        "os",
        "packages",
        "processes",
        "ports",
        "netaddr",
        "netiface",
        "netproto",
        "hotfixes",
    ] {
        parse(&["syscollector", endpoint]);
    }
}

#[test]
fn clear_requires_explicit_agent_ids() {
    for endpoint in ["rootcheck", "syscheck"] {
        assert!(Cli::try_parse_from(["wazuh-cli", "experimental", endpoint, "clear"]).is_err());
        parse(&[endpoint, "clear", "001", "002"]);
    }
}

#[test]
fn malformed_filters_and_pagination_are_rejected() {
    for value in ["name", "=openssl", "name="] {
        assert!(
            Cli::try_parse_from([
                "wazuh-cli",
                "experimental",
                "syscollector",
                "packages",
                "--filter",
                value
            ])
            .is_err()
        );
    }
    for value in ["0", "100001", "-1"] {
        assert!(
            Cli::try_parse_from([
                "wazuh-cli",
                "experimental",
                "ciscat",
                "results",
                "--limit",
                value
            ])
            .is_err()
        );
    }
    for value in ["1", "100000"] {
        parse(&["ciscat", "results", "--limit", value]);
    }
    assert!(
        Cli::try_parse_from([
            "wazuh-cli",
            "experimental",
            "ciscat",
            "results",
            "--offset",
            "-1"
        ])
        .is_err()
    );
    parse(&[
        "syscollector",
        "packages",
        "--sort",
        "-name",
        "--filter",
        "name=a=b",
    ]);
    assert!(
        Cli::try_parse_from([
            "wazuh-cli",
            "experimental",
            "ciscat",
            "results",
            "--sort",
            "--limit",
            "5"
        ])
        .is_err()
    );
}

struct Expected {
    method: &'static str,
    path: &'static str,
    query: Vec<(&'static str, &'static str)>,
    response: Value,
}

// Each response closes its connection, keeping the small HTTP mock deterministic.
fn mock(expected: Vec<Expected>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = vec![Expected {
            method: "POST",
            path: "/security/user/authenticate",
            query: vec![("raw", "true")],
            response: Value::Null,
        }];
        requests.extend(expected);
        for expected in requests {
            let start = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            start.elapsed() < Duration::from_secs(5),
                            "request timed out"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 1024];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buf[..count]);
            }
            let request = String::from_utf8(bytes).unwrap();
            let user_agent = request
                .lines()
                .skip(1)
                .take_while(|line| !line.is_empty())
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .map(|(_, value)| value.trim());
            assert_eq!(
                user_agent,
                Some(concat!("wazuh-cli/", env!("CARGO_PKG_VERSION")))
            );
            let mut parts = request.lines().next().unwrap().split_whitespace();
            assert_eq!(parts.next().unwrap(), expected.method);
            let url =
                reqwest::Url::parse(&format!("http://localhost{}", parts.next().unwrap())).unwrap();
            assert_eq!(url.path(), expected.path);
            let query: BTreeMap<_, _> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let wanted: BTreeMap<_, _> = expected
                .query
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            assert_eq!(query, wanted);
            if expected.path.starts_with("/experimental/") {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer test-token\r\n")
                );
            }
            let body = if expected.path == "/security/user/authenticate" {
                "test-token".to_string()
            } else {
                expected.response.to_string()
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        }
    });
    (url, handle)
}

async fn client(url: String) -> WazuhClient {
    WazuhClient::new(&Config {
        api_url: url,
        api_user: "test".into(),
        api_password: "test".to_string().into(),
        ca_cert: None,
        client_cert: None,
        client_key: None,
        insecure: false,
        output_format: OutputFormat::Json,
        raw_output: false,
        progress: false,
        timeout: 5,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn get_preserves_filters_and_merges_pages() {
    let common = vec![
        ("agents_list", "001,002"),
        ("search", "Open SSL"),
        ("select", "name,version"),
        ("sort", "-name"),
        ("name", "a=b"),
        ("pretty", "true"),
        ("wait_for_complete", "true"),
        ("limit", "500"),
    ];
    let requests = ["0", "1"].into_iter().enumerate().map(|(index, offset)| {
        let mut query = common.clone();
        query.push(("offset", offset));
        Expected { method: "GET", path: "/experimental/syscollector/packages", query, response: json!({"error": 0, "data": {"affected_items": [{"name": format!("package-{index}")}], "total_affected_items": 2}}) }
    }).collect();
    let (url, handle) = mock(requests);
    let result = experimental::run(
        &client(url).await,
        parse(&[
            "syscollector",
            "packages",
            "--agents-list",
            "001,002",
            "--search",
            "Open SSL",
            "--select",
            "name,version",
            "--sort",
            "-name",
            "--filter",
            "name=a=b",
            "--pretty",
            "--wait-for-complete",
        ]),
    )
    .await
    .unwrap();
    handle.join().unwrap();
    assert_eq!(
        result["data"]["affected_items"],
        json!([{"name": "package-0"}, {"name": "package-1"}])
    );
    assert_eq!(result["data"]["total_affected_items"], 2);
}

#[tokio::test]
async fn either_limit_or_offset_disables_auto_pagination() {
    for (flag, value, query) in [
        ("--limit", "2", vec![("limit", "2")]),
        ("--offset", "7", vec![("offset", "7")]),
    ] {
        let response =
            json!({"data": {"affected_items": [{"score": 99}], "total_affected_items": 100}});
        let (url, handle) = mock(vec![Expected {
            method: "GET",
            path: "/experimental/ciscat/results",
            query,
            response: response.clone(),
        }]);
        let actual = experimental::run(
            &client(url).await,
            parse(&["ciscat", "results", flag, value]),
        )
        .await
        .unwrap();
        handle.join().unwrap();
        assert_eq!(actual, response);
    }
}

#[tokio::test]
async fn clear_sends_delete_with_explicit_ids_and_request_options() {
    for (endpoint, path, ids, wanted) in [
        (
            "rootcheck",
            "/experimental/rootcheck",
            vec!["001", "002"],
            "001,002",
        ),
        ("syscheck", "/experimental/syscheck", vec!["all"], "all"),
    ] {
        let response = json!({"data": {"affected_items": ["001"]}, "error": 0});
        let (url, handle) = mock(vec![Expected {
            method: "DELETE",
            path,
            query: vec![
                ("agents_list", wanted),
                ("pretty", "true"),
                ("wait_for_complete", "true"),
            ],
            response: response.clone(),
        }]);
        let mut args = vec![endpoint, "clear"];
        args.extend(ids);
        args.extend(["--pretty", "--wait-for-complete"]);
        let actual = experimental::run(&client(url).await, parse(&args))
            .await
            .unwrap();
        handle.join().unwrap();
        assert_eq!(actual, response);
    }
}

#[tokio::test]
async fn unsupported_and_duplicate_filters_fail_before_authentication() {
    let client = client("http://127.0.0.1:1".into()).await;
    for filters in [
        vec!["q=name=openssl"],
        vec!["name=openssl", "name=curl"],
        vec!["agents_list=all"],
    ] {
        let mut args = vec!["syscollector", "packages"];
        for filter in filters {
            args.extend(["--filter", filter]);
        }
        let err = experimental::run(&client, parse(&args)).await.unwrap_err();
        assert!(matches!(err, wazuh_cli::error::WazuhError::Config(_)));
    }
}
