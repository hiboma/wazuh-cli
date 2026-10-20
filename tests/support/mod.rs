#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use wazuh_cli::config::{Config, OutputFormat};

pub fn tls_config() -> Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap(),
    )
}

pub fn config(url: &str) -> Config {
    Config {
        api_url: url.into(),
        api_user: "test".into(),
        api_password: "api-password-SENTINEL".to_string().into(),
        ca_cert: None,
        client_cert: None,
        client_key: None,
        insecure: true,
        output_format: OutputFormat::Json,
        raw_output: false,
        progress: false,
        timeout: 5,
    }
}

pub struct Reply {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: vec![],
        }
    }
    pub fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            body: String::new(),
            headers: vec![("Location".into(), location.into())],
        }
    }
}

pub struct Mock {
    pub url: String,
    handle: thread::JoinHandle<Vec<String>>,
}

impl Mock {
    pub fn finish(self) -> Vec<String> {
        self.handle.join().unwrap()
    }
}

pub fn mock(replies: Vec<Reply>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let tls = tls_config();
    let handle = thread::spawn(move || {
        let mut requests = vec![];
        for reply in replies {
            let start = Instant::now();
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            start.elapsed() < Duration::from_secs(10),
                            "request timed out"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(tls.clone()).unwrap(),
                socket,
            );
            let mut bytes = vec![];
            let mut buf = [0; 1024];
            loop {
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buf[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]);
                    let length = header
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            write!(stream, "HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", reply.status, reply.body.len()).unwrap();
            for (key, value) in reply.headers {
                write!(stream, "{key}: {value}\r\n").unwrap();
            }
            write!(stream, "\r\n{}", reply.body).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    Mock { url, handle }
}
