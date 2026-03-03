use std::time::Duration;

use reqwest::Client;

use crate::config::Config;
use crate::error::WazuhError;

/// Reads a PEM-encoded private key and returns it as PKCS#8 PEM.
/// If the key is PKCS#1 (BEGIN RSA PRIVATE KEY), it re-wraps it with a PKCS#8 header.
/// If the key is already PKCS#8 (BEGIN PRIVATE KEY), it returns it as-is.
fn convert_to_pkcs8(pem_data: &[u8], path: &str) -> Result<Vec<u8>, WazuhError> {
    // Determine the format from the first line
    let content = std::str::from_utf8(pem_data)
        .map_err(|e| WazuhError::Tls(format!("Invalid UTF-8 in key file '{}': {}", path, e)))?;

    // Already in PKCS#8 format; return as-is
    if content.contains("BEGIN PRIVATE KEY") {
        return Ok(pem_data.to_vec());
    }

    // Parse the private key as DER using rustls-pemfile
    let mut reader = std::io::BufReader::new(pem_data);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| WazuhError::Tls(format!("Failed to parse private key '{}': {}", path, e)))?
        .ok_or_else(|| WazuhError::Tls(format!("No private key found in '{}'", path)))?;

    // Base64-encode the DER bytes and output as PKCS#8 PEM.
    // Wrap the PKCS#1 RSA DER with a PKCS#8 wrapper and re-encode.
    let der = key.secret_der();

    // Wrap the PKCS#1 RSA key in PKCS#8
    // PKCS#8 = SEQUENCE { AlgorithmIdentifier, OCTET STRING { PKCS#1 DER } }
    let pkcs8_der = wrap_pkcs1_in_pkcs8(der);

    let b64 = base64_encode(&pkcs8_der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    Ok(pem.into_bytes())
}

/// Wraps a PKCS#1 RSA private key DER in PKCS#8 format DER.
fn wrap_pkcs1_in_pkcs8(pkcs1_der: &[u8]) -> Vec<u8> {
    // RSA AlgorithmIdentifier (OID 1.2.840.113549.1.1.1, NULL parameter)
    let algorithm_id: &[u8] = &[
        0x30, 0x0d, // SEQUENCE (13 bytes)
        0x06, 0x09, // OID (9 bytes)
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1
        0x05, 0x00, // NULL
    ];

    // version INTEGER 0
    let version: &[u8] = &[0x02, 0x01, 0x00];

    // PKCS#1 DER wrapped in an OCTET STRING
    let octet_string = asn1_wrap(0x04, pkcs1_der);

    // Inner content: version + algorithmId + octetString
    let mut inner = Vec::new();
    inner.extend_from_slice(version);
    inner.extend_from_slice(algorithm_id);
    inner.extend_from_slice(&octet_string);

    // Outer SEQUENCE
    asn1_wrap(0x30, &inner)
}

/// Wraps content in an ASN.1 TLV encoding.
fn asn1_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    let len = content.len();
    if len < 0x80 {
        result.push(len as u8);
    } else if len < 0x100 {
        result.push(0x81);
        result.push(len as u8);
    } else if len < 0x10000 {
        result.push(0x82);
        result.push((len >> 8) as u8);
        result.push((len & 0xff) as u8);
    } else {
        result.push(0x83);
        result.push((len >> 16) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.push((len & 0xff) as u8);
    }
    result.extend_from_slice(content);
    result
}

/// Base64-encodes a byte slice (no external crate required).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3f) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Builds a reqwest::Client from Config.
/// Handles CA certificates, client certificates (mTLS), and insecure mode.
pub fn build_http_client(config: &Config) -> Result<Client, WazuhError> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(config.timeout))
        .use_rustls_tls();

    // Skip TLS verification in insecure mode
    if config.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }

    // Add CA certificate if specified
    if let Some(ca_path) = &config.ca_cert {
        let ca_pem = std::fs::read(ca_path).map_err(|e| {
            WazuhError::Tls(format!(
                "Failed to read CA certificate '{}': {}",
                ca_path, e
            ))
        })?;
        let ca_cert = reqwest::tls::Certificate::from_pem(&ca_pem).map_err(|e| {
            WazuhError::Tls(format!(
                "Failed to parse CA certificate '{}': {}",
                ca_path, e
            ))
        })?;
        builder = builder.add_root_certificate(ca_cert);
    }

    // mTLS: enable when both client certificate and private key are specified
    if let (Some(cert_path), Some(key_path)) = (&config.client_cert, &config.client_key) {
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            WazuhError::Tls(format!(
                "Failed to read client certificate '{}': {}",
                cert_path, e
            ))
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            WazuhError::Tls(format!("Failed to read client key '{}': {}", key_path, e))
        })?;

        // Convert PKCS#1 (BEGIN RSA PRIVATE KEY) to PKCS#8 (BEGIN PRIVATE KEY)
        // because rustls only supports PKCS#8
        let key_pkcs8 = convert_to_pkcs8(&key_pem, key_path)?;

        // Insert a newline if the certificate PEM does not end with one,
        // to prevent corruption when concatenating with the key PEM
        let mut identity_pem = cert_pem;
        if !identity_pem.ends_with(b"\n") {
            identity_pem.push(b'\n');
        }
        identity_pem.extend_from_slice(&key_pkcs8);

        let identity = reqwest::tls::Identity::from_pem(&identity_pem)
            .map_err(|e| WazuhError::Tls(format!("Failed to build client identity: {}", e)))?;
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|e| WazuhError::Tls(format!("Failed to build HTTP client: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutputFormat;

    fn test_config() -> Config {
        Config {
            api_url: "https://localhost:55000".to_string(),
            api_user: "wazuh".to_string(),
            api_password: "test".to_string(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            insecure: false,
            output_format: OutputFormat::Json,
            raw_output: false,
            progress: false,
            timeout: 30,
        }
    }

    #[test]
    fn test_build_default_client() {
        let config = test_config();
        let result = build_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_insecure_client() {
        let mut config = test_config();
        config.insecure = true;
        let result = build_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_with_custom_timeout() {
        let mut config = test_config();
        config.timeout = 120;
        let result = build_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_with_nonexistent_ca_cert() {
        let mut config = test_config();
        config.ca_cert = Some("/nonexistent/ca.pem".to_string());
        let result = build_http_client(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, WazuhError::Tls(_)));
    }

    #[test]
    fn test_build_with_nonexistent_client_cert() {
        let mut config = test_config();
        config.client_cert = Some("/nonexistent/cert.pem".to_string());
        config.client_key = Some("/nonexistent/key.pem".to_string());
        let result = build_http_client(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, WazuhError::Tls(_)));
    }
}
