use super::chunked::ChunkedDecoder;
use super::compression::{self, CompressionAlgorithm, CompressionLevel};
use super::{Headers, HttpResponse, HttpVersion, StatusCode};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::tcp::TcpStream;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP_PARSER_RESPONSE_BLOB_MAGIC: &str = "SINGULARITY_HTTP_PARSER_RESPONSE_BLOB_V1";
const HTTP_PARSER_RESPONSE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_PARSER_RESPONSE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureParsedHttpResponseBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub struct HttpParser;

impl HttpParser {
    pub fn parse_response(stream: &mut TcpStream) -> io::Result<HttpResponse> {
        let status_line = Self::read_line(stream)?;
        let (version, status, reason) = Self::parse_status_line(&status_line)?;
        let headers = Self::read_headers(stream)?;
        let wire_body = Self::read_body(stream, &headers)?;
        Self::verify_digest(&headers, &wire_body)?;
        let mut final_body = wire_body;
        let mut headers_map = headers.clone().into_map();
        if let Some(content_encoding) = headers.get("content-encoding") {
            final_body = Self::decode_content_encoding(content_encoding, &final_body)?;
            headers_map.remove("content-encoding");
            headers_map.insert("content-length".to_string(), final_body.len().to_string());
        }

        let response = HttpResponse::new(status.code(), reason, version, headers_map, final_body);
        Ok(response)
    }

    pub fn parse_response_to_secure_blob(stream: &mut TcpStream, algorithm: CompressionAlgorithm) -> io::Result<(SecureParsedHttpResponseBlobMeta, Vec<u8>)> {
        let response = Self::parse_response(stream)?;
        encode_secure_http_response(&response, algorithm)
    }

    pub fn parse_response_to_secure_blob_auto(stream: &mut TcpStream, accept_encoding: &str) -> io::Result<(SecureParsedHttpResponseBlobMeta, Vec<u8>)> {
        let response = Self::parse_response(stream)?;
        encode_secure_http_response_auto(&response, accept_encoding)
    }

    pub fn response_from_secure_blob(data: &[u8]) -> io::Result<(SecureParsedHttpResponseBlobMeta, HttpResponse)> {
        decode_secure_http_response(data)
    }

    fn read_line(stream: &mut TcpStream) -> io::Result<String> {
        let mut line = String::new();
        stream.read_line(&mut line)?;
        if line.ends_with("\r\n") {
            line.truncate(line.len() - 2);
        } else if line.ends_with('\n') {
            line.truncate(line.len() - 1);
        }

        Ok(line)
    }

    fn parse_status_line(line: &str) -> io::Result<(HttpVersion, StatusCode, String)> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Status Line",
            ));
        }

        let version = HttpVersion::from_str(parts[0]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP Version")
        })?;

        let status_code = parts[1].parse::<u16>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid Status Code")
        })?;

        let reason = parts.get(2).unwrap_or(&"").to_string();

        Ok((version, StatusCode::new(status_code), reason))
    }

    fn read_headers(stream: &mut TcpStream) -> io::Result<Headers> {
        let mut header_lines = Vec::new();
        loop {
            let line = Self::read_line(stream)?;
            if line.is_empty() {
                break;
            }

            header_lines.push(line);
        }

        Ok(Headers::parse(&header_lines))
    }

    fn read_body(stream: &mut TcpStream, headers: &Headers) -> io::Result<Vec<u8>> {
        if headers.is_chunked() {
            let decoder = ChunkedDecoder::new(stream);
            decoder.decode()
        } else if let Some(content_length) = headers.content_length() {
            let mut body = vec![0u8; content_length];
            stream.read_exact(&mut body)?;
            Ok(body)
        } else {
            let mut body = Vec::new();
            stream.read_to_end(&mut body)?;
            Ok(body)
        }
    }

    fn decode_content_encoding(content_encoding: &str, body: &[u8]) -> io::Result<Vec<u8>> {
        let encoding = content_encoding.trim().to_ascii_lowercase();
        if encoding == "identity" || encoding.is_empty() {
            return Ok(body.to_vec());
        }

        let algo = CompressionAlgorithm::from_content_encoding(&encoding).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported content-encoding: {}", content_encoding),
            )
        })?;

        compression::decompress(algo, body)
    }

    fn verify_digest(headers: &Headers, wire_body: &[u8]) -> io::Result<()> {
        let Some(digest_header) = headers.get("digest") else {
            return Ok(());
        };

        let mut has_sha256 = false;
        let mut matched = false;
        for part in digest_header.split(',') {
            let p = part.trim();
            let mut kv = p.splitn(2, '=');
            let algo = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let value = kv.next().unwrap_or("").trim();
            if algo == "sha-256" {
                has_sha256 = true;
                let expected = pem::decode(value).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid digest encoding: {}", e),
                    )
                })?;

                let actual = sha256(wire_body);
                if constant_time_eq(&expected, &actual) {
                    matched = true;
                }
            }
        }

        if has_sha256 && !matched {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Digest verification failed",
            ));
        }

        Ok(())
    }
}

pub fn select_secure_http_parser_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_http_response(response: &HttpResponse, algorithm: CompressionAlgorithm) -> io::Result<(SecureParsedHttpResponseBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_http_response(response);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate parser blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_http_parser_response_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = HTTP_PARSER_RESPONSE_BLOB_MAGIC,
        encoding = selected_algorithm.content_encoding(),
        nonce = nonce_b64,
        digest = digest_b64,
        tag = tag_b64,
        raw_size = raw_payload.len(),
        encoded_size = encoded_payload.len(),
        issued_at = issued_at_unix
    );

    let mut blob = header.into_bytes();
    blob.extend_from_slice(&encoded_payload);

    Ok((
        SecureParsedHttpResponseBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64,
            digest_b64,
            tag_b64,
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix,
        },
        blob,
    ))
}

pub fn encode_secure_http_response_auto(response: &HttpResponse, accept_encoding: &str) -> io::Result<(SecureParsedHttpResponseBlobMeta, Vec<u8>)> {
    let selected = select_secure_http_parser_algorithm(accept_encoding);
    encode_secure_http_response(response, selected)
}

pub fn decode_secure_http_response(data: &[u8]) -> io::Result<(SecureParsedHttpResponseBlobMeta, HttpResponse)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_http_parser_response_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid parser nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid parser digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid parser tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parser digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_http_parser_response_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http parser response blob HMAC mismatch",
        ));
    }

    let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        compression::decompress(meta.algorithm, body)?
    };

    if raw_payload.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "parser raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "http parser response blob digest mismatch",
        ));
    }

    let response = deserialize_http_response(&raw_payload)?;
    Ok((meta, response))
}

fn serialize_http_response(response: &HttpResponse) -> Vec<u8> {
    response.to_bytes()
}

fn deserialize_http_response(raw_payload: &[u8]) -> io::Result<HttpResponse> {
    HttpResponse::from_bytes(raw_payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid response payload: {}", e)))
}

fn compute_http_parser_response_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP_PARSER_RESPONSE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP_PARSER_RESPONSE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing blob header/body separator",
    ))
}

fn parse_secure_http_parser_response_meta(header: &str, body_len: usize) -> io::Result<SecureParsedHttpResponseBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP_PARSER_RESPONSE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http parser response blob magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure parser header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    },
                )?;
            }
            "nonce" => nonce_b64 = Some(value.trim().to_string()),
            "digest" => {
                let parsed = value.trim().strip_prefix("SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid digest header"))?.to_string();
                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid tag header"))?.to_string();
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(value.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing nonce in secure parser blob")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing digest in secure parser blob")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing tag in secure parser blob")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing raw-size in secure parser blob")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing encoded-size in secure parser blob")
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encoded-size mismatch: metadata {}, actual {}",
                encoded_size, body_len
            ),
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing issued-at in secure parser blob")
    })?;

    Ok(SecureParsedHttpResponseBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_status_line_valid() {
        let (version, status, reason) =
            HttpParser::parse_status_line("HTTP/1.1 200 OK").unwrap();
        assert_eq!(version, HttpVersion::Http11);
        assert_eq!(status.code(), 200);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn test_parse_status_line_invalid() {
        let err = HttpParser::parse_status_line("BROKEN").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_secure_http_response_blob_roundtrip_identity() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let response = HttpResponse::new(
            200,
            "OK".to_string(),
            HttpVersion::Http11,
            headers,
            br#"{"ok":true}"#.to_vec(),
        );

        let (meta, blob) = encode_secure_http_response(&response, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = decode_secure_http_response(&blob).unwrap();
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored.status_code(), 200);
        assert_eq!(restored.reason_phrase(), "OK");
        assert_eq!(restored.body(), br#"{"ok":true}"#);
    }

    #[test]
    fn test_secure_http_response_blob_tamper_detection() {
        let response = HttpResponse::new(
            204,
            "No Content".to_string(),
            HttpVersion::Http11,
            HashMap::new(),
            Vec::new(),
        );

        let (_, mut blob) = encode_secure_http_response(&response, CompressionAlgorithm::Identity).unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = decode_secure_http_response(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}