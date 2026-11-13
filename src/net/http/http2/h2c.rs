use crate::crypto::encoding::pem;
use super::error::{ErrorCode, Http2Error, Result};

use std::io::{self, Read, Write};

pub const H2C_TOKEN: &str = "h2c";
pub const HTTP2_SETTINGS_HEADER: &str = "HTTP2-Settings";
pub const PREFACE_REQUEST_LINE: &str = "PRI * HTTP/2.0";
pub const PREFACE_TAIL: &[u8] = b"\r\nSM\r\n\r\n";
pub const SWITCHING_PROTOCOLS_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";

const HOP_BY_HOP_FIELDS: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "http2-settings", "te", "host"];

pub struct H2cTransport<R: Read, W: Write> {
    replay: Vec<u8>,
    replay_pos: usize,
    reader: R,
    writer: W,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H2cMode {
    #[default]
    Disabled,
    Upgrade,
    PriorKnowledge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2cUpgrade {
    NotRequested,
    Invalid(String),
    Requested(Vec<(u16, u32)>),
}

impl<R: Read, W: Write> H2cTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self::with_replay(Vec::new(), reader, writer)
    }

    pub fn with_replay(replay: Vec<u8>, reader: R, writer: W) -> Self {
        Self {
            replay,
            replay_pos: 0,
            reader,
            writer,
        }
    }
}

impl<R: Read, W: Write> Read for H2cTransport<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.replay_pos < self.replay.len() {
            let n = buf.len().min(self.replay.len() - self.replay_pos);
            buf[..n].copy_from_slice(&self.replay[self.replay_pos..self.replay_pos + n]);
            self.replay_pos += n;

            return Ok(n);
        }

        self.reader.read(buf)
    }
}

impl<R: Read, W: Write> Write for H2cTransport<R, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub fn encode_http2_settings(entries: &[(u16, u32)]) -> String {
    let mut payload = Vec::with_capacity(entries.len() * 6);
    for (id, value) in entries {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }

    pem::encode(&payload).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

pub fn decode_http2_settings(value: &str) -> Result<Vec<(u16, u32)>> {
    let value = value.trim().trim_end_matches('=');
    if !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(invalid_settings("HTTP2-Settings is not base64url"));
    }

    let mut standard = value.replace('-', "+").replace('_', "/");
    match standard.len() % 4 {
        0 => {}
        1 => return Err(invalid_settings("HTTP2-Settings has a truncated base64url quantum")),
        rem => standard.push_str(&"=="[..4 - rem]),
    }

    let payload = pem::decode(&standard).map_err(|_| invalid_settings("HTTP2-Settings is not base64url"))?;
    if payload.len() % 6 != 0 {
        return Err(invalid_settings("HTTP2-Settings payload is not a whole number of settings"));
    }

    Ok(payload.chunks_exact(6).map(|entry| {
        (u16::from_be_bytes([entry[0], entry[1]]), u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]))
    }).collect())
}

pub fn settings_payload(entries: &[(u16, u32)]) -> Vec<u8> {
    entries.iter().flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes())).collect()
}

pub fn parse_upgrade_request(fields: &[(String, String)]) -> H2cUpgrade {
    let values = |name: &str| -> Vec<&str> {
        fields.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    };

    if !has_token(&values("upgrade"), H2C_TOKEN) {
        return H2cUpgrade::NotRequested;
    }

    let connection = values("connection");
    if !has_token(&connection, "upgrade") || !has_token(&connection, HTTP2_SETTINGS_HEADER) {
        return H2cUpgrade::Invalid("Connection must list Upgrade and HTTP2-Settings".to_string());
    }

    match values(HTTP2_SETTINGS_HEADER).as_slice() {
        [single] => match decode_http2_settings(single) {
            Ok(entries) => H2cUpgrade::Requested(entries),
            Err(e) => H2cUpgrade::Invalid(e.to_string()),
        },
        [] => H2cUpgrade::Invalid("missing HTTP2-Settings".to_string()),
        _ => H2cUpgrade::Invalid("more than one HTTP2-Settings header field".to_string()),
    }
}

pub fn upgrade_request_fields(settings: &[(u16, u32)]) -> Vec<(String, String)> {
    vec![
        ("Connection".to_string(), format!("Upgrade, {}", HTTP2_SETTINGS_HEADER)),
        ("Upgrade".to_string(), H2C_TOKEN.to_string()),
        (HTTP2_SETTINGS_HEADER.to_string(), encode_http2_settings(settings)),
    ]
}

pub fn is_switching_to_h2c(status_code: u16, fields: &[(String, String)]) -> bool {
    let upgrade: Vec<&str> = fields.iter().filter(|(k, _)| k.eq_ignore_ascii_case("upgrade")).map(|(_, v)| v.as_str()).collect();
    status_code == 101 && has_token(&upgrade, H2C_TOKEN)
}

pub fn http1_request_to_h2_headers(method: &str, target: &str, fields: &[(String, String)]) -> Vec<(String, String)> {
    let authority = fields.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone()).unwrap_or_default();
    let mut headers = vec![
        (":method".to_string(), method.to_string()),
        (":scheme".to_string(), "http".to_string()),
        (":authority".to_string(), authority),
        (":path".to_string(), target.to_string()),
    ];

    let connection_options: Vec<String> = fields.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|o| o.trim().to_ascii_lowercase())).collect();

    for (name, value) in fields {
        let name = name.to_ascii_lowercase();
        if !is_hop_by_hop(&name) && !connection_options.contains(&name) {
            headers.push((name, value.clone()));
        }
    }

    headers
}

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP_FIELDS.iter().any(|field| field.eq_ignore_ascii_case(name))
}

fn has_token(values: &[&str], token: &str) -> bool {
    values.iter().flat_map(|v| v.split(',')).any(|t| t.trim().eq_ignore_ascii_case(token))
}

fn invalid_settings(msg: &str) -> Http2Error {
    Http2Error::Protocol(ErrorCode::ProtocolError, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_http2_settings_is_unpadded_base64url() {
        let entries = vec![(0x3, 100), (0x4, 0xffff_fffe), (0x2, 0)];
        let token = encode_http2_settings(&entries);
        assert!(!token.contains('=') && !token.contains('+') && !token.contains('/'));
        assert_eq!(decode_http2_settings(&token).unwrap(), entries);
        assert_eq!(decode_http2_settings("").unwrap(), Vec::new());

        assert_eq!(encode_http2_settings(&[(0x4, 0xfbff_ffff)]), "AAT7____");
        assert_eq!(decode_http2_settings("AAT7____").unwrap(), vec![(0x4, 0xfbff_ffff)]);
    }

    #[test]
    fn test_http2_settings_rejects_bad_tokens() {
        assert!(decode_http2_settings("AAT7+///").is_err(), "standard base64 alphabet is not base64url");
        assert!(decode_http2_settings("AAMAAABk!").is_err());
        assert!(decode_http2_settings("AAMAAA").is_err(), "4 bytes is not a whole setting");
        assert!(decode_http2_settings("A").is_err());
    }

    #[test]
    fn test_parse_upgrade_request() {
        let token = encode_http2_settings(&[(0x3, 100)]);
        let good = fields(&[("Host", "example.com"), ("Connection", "Upgrade, HTTP2-Settings"), ("Upgrade", "h2c"), ("HTTP2-Settings", &token)]);
        assert_eq!(parse_upgrade_request(&good), H2cUpgrade::Requested(vec![(0x3, 100)]));

        let other_protocol = fields(&[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
        assert_eq!(parse_upgrade_request(&other_protocol), H2cUpgrade::NotRequested);
        assert_eq!(parse_upgrade_request(&fields(&[("Host", "example.com")])), H2cUpgrade::NotRequested);

        let missing_connection_option = fields(&[("Connection", "Upgrade"), ("Upgrade", "h2c"), ("HTTP2-Settings", &token)]);
        assert!(matches!(parse_upgrade_request(&missing_connection_option), H2cUpgrade::Invalid(_)));

        let duplicated = fields(&[("Connection", "Upgrade, HTTP2-Settings"), ("Upgrade", "h2c"), ("HTTP2-Settings", &token), ("http2-settings", &token)]);
        assert!(matches!(parse_upgrade_request(&duplicated), H2cUpgrade::Invalid(_)));

        let missing = fields(&[("Connection", "Upgrade, HTTP2-Settings"), ("Upgrade", "h2c")]);
        assert!(matches!(parse_upgrade_request(&missing), H2cUpgrade::Invalid(_)));
    }

    #[test]
    fn test_http1_request_maps_to_pseudo_headers() {
        let headers = http1_request_to_h2_headers("POST", "/submit?x=1", &fields(&[
            ("Host", "example.com:8080"),
            ("Connection", "Upgrade, HTTP2-Settings, X-Trace"),
            ("Upgrade", "h2c"),
            ("HTTP2-Settings", "AAMAAABk"),
            ("X-Trace", "hop"),
            ("Content-Type", "text/plain"),
        ]));

        assert_eq!(&headers[..4], &fields(&[(":method", "POST"), (":scheme", "http"), (":authority", "example.com:8080"), (":path", "/submit?x=1")])[..]);
        assert_eq!(&headers[4..], &fields(&[("content-type", "text/plain")])[..]);
    }

    #[test]
    fn test_transport_replays_consumed_bytes_first() {
        let mut transport = H2cTransport::with_replay(b"PRI".to_vec(), io::Cursor::new(b" * HTTP".to_vec()), Vec::new());
        let mut out = String::new();
        transport.read_to_string(&mut out).unwrap();
        assert_eq!(out, "PRI * HTTP");
        transport.write_all(b"frames").unwrap();
        assert_eq!(transport.writer, b"frames");
    }

    #[test]
    fn test_switching_protocols_detection() {
        assert!(is_switching_to_h2c(101, &fields(&[("Connection", "Upgrade"), ("Upgrade", "h2c")])));
        assert!(!is_switching_to_h2c(101, &fields(&[("Upgrade", "websocket")])));
        assert!(!is_switching_to_h2c(200, &fields(&[("Upgrade", "h2c")])));
    }
}