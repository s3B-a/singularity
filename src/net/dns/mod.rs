mod record;
mod packet;
mod cache;
mod query;
mod response;
mod resolver;

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub use record::{RecordType, RecordClass, RecordData, DnsRecord};
pub use packet::{DnsPacket, DnsHeader, DnsQuestion, OpCode, ResponseCode};
pub use cache::{DnsCache, CacheStats};
pub use query::DnsQuery;
pub use response::{DnsResponse, ValidationError};
pub use resolver::DnsResolver;

const DNS_SECURE_ENVELOPE_MAGIC: &str = "SINGULARITY_DNS_SECURE_V1";
const DNS_SECURE_ENVELOPE_CONTEXT: &str = "SINGULARITY_DNS_SECURE_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDnsEnvelopeMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

pub fn encode_secure_dns_packet(packet: &DnsPacket, algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
    let raw = packet.write()?;
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let encoded = if selected_algorithm == CompressionAlgorithm::Identity {
        raw.clone()
    } else {
        compression::compress(selected_algorithm, &raw, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate secure nonce: {}", e),
        )
    })?;

    let digest = compute_secure_digest(&nonce, &raw);
    let tag = compute_secure_tag(&nonce, selected_algorithm, raw.len(), &encoded);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let meta = SecureDnsEnvelopeMeta {
        algorithm: selected_algorithm,
        nonce_b64: pem::encode(&nonce),
        digest_b64: pem::encode(&digest),
        tag_b64: pem::encode(&tag),
        raw_size: raw.len(),
        encoded_size: encoded.len(),
        issued_at_unix,
    };

    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = DNS_SECURE_ENVELOPE_MAGIC,
        encoding = meta.algorithm.content_encoding(),
        nonce = meta.nonce_b64,
        digest = meta.digest_b64,
        tag = meta.tag_b64,
        raw_size = meta.raw_size,
        encoded_size = meta.encoded_size,
        issued_at = meta.issued_at_unix,
    );

    let mut out = header.into_bytes();
    out.extend_from_slice(&encoded);

    Ok(out)
}

pub fn encode_secure_dns_packet_auto(packet: &DnsPacket, accept_encoding: &str) -> io::Result<Vec<u8>> {
    let algorithm = select_algorithm_from_accept_encoding(accept_encoding);
    encode_secure_dns_packet(packet, algorithm)
}

pub fn decode_secure_dns_packet(data: &[u8]) -> io::Result<DnsPacket> {
    let (header, body) = split_secure_envelope(data)?;
    let meta = parse_secure_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid nonce encoding in secure DNS envelope",
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid digest encoding in secure DNS envelope",
        )
    })?;

    let expected_tag = pem::decode(&meta.tag_b64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tag encoding in secure DNS envelope",
        )
    })?;

    let computed_tag = compute_secure_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &computed_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure DNS envelope tag verification failed",
        ));
    }

    let decoded = if meta.algorithm == CompressionAlgorithm::Identity {
        body.to_vec()
    } else {
        compression::decompress(meta.algorithm, body)?
    };

    if decoded.len() != meta.raw_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decoded payload size mismatch",
        ));
    }

    let computed = compute_secure_digest(&nonce, &decoded);
    if !constant_time_eq(&computed, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure DNS envelope digest verification failed",
        ));
    }

    DnsPacket::read(&decoded)
}

pub fn encode_secure_dns_query_auto(id: u16, name: impl Into<String>, record_type: RecordType, accept_encoding: &str) -> io::Result<Vec<u8>> {
    let packet = DnsPacket::new_query(id, name.into(), record_type);
    encode_secure_dns_packet_auto(&packet, accept_encoding)
}

pub fn select_algorithm_from_accept_encoding(accept_encoding: &str) -> CompressionAlgorithm {
    let parsed = compression::parse_accept_encoding(accept_encoding);
    let mut identity_allowed = false;
    for (algo, q) in parsed {
        if q <= 0.0 {
            continue;
        }

        if algo == CompressionAlgorithm::Identity {
            identity_allowed = true;
            continue;
        }

        if algo.is_implemented() {
            return algo;
        }
    }

    if identity_allowed {
        CompressionAlgorithm::Identity
    } else {
        CompressionAlgorithm::Identity
    }
}

fn compute_secure_digest(nonce: &[u8], raw_payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(nonce.len() + raw_payload.len());
    material.extend_from_slice(nonce);
    material.extend_from_slice(raw_payload);

    sha256(&material)
}

fn compute_secure_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(DNS_SECURE_ENVELOPE_CONTEXT.as_bytes());
    key_material.extend_from_slice(nonce);
    key_material.extend_from_slice(algorithm.content_encoding().as_bytes());
    key_material.extend_from_slice(&(raw_size as u64).to_be_bytes());
    let hmac_key = sha256(&key_material);

    let mut msg = Vec::new();
    msg.extend_from_slice(DNS_SECURE_ENVELOPE_MAGIC.as_bytes());
    msg.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    msg.extend_from_slice(encoded_payload);

    hmac_sha256(&hmac_key, &msg)
}

fn split_secure_envelope(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    if let Some(pos) = data.windows(DELIM.len()).position(|w| w == DELIM) {
        let header = String::from_utf8(data[..pos].to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "secure DNS envelope header is not valid UTF-8",
            )
        })?;

        let body = &data[pos + DELIM.len()..];
        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "secure DNS envelope separator not found",
    ))
}

fn parse_secure_meta(header: &str, body_len: usize) -> io::Result<SecureDnsEnvelopeMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != DNS_SECURE_ENVELOPE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure DNS envelope magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut tag_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported secure DNS content-encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("nonce=") {
            nonce_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            digest_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("tag=HMAC-SHA-256=") {
            tag_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("issued-at=") {
            issued_at_unix = v.trim().parse::<u64>().ok();
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure DNS envelope missing nonce")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure DNS envelope missing digest")
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure DNS envelope missing tag")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure DNS envelope missing raw-size")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure DNS envelope missing encoded-size")
    })?;
    
    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure DNS envelope encoded-size does not match body length",
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "secure DNS envelope missing issued-at")
    })?;

    Ok(SecureDnsEnvelopeMeta {
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_module_exports() {
        let _resolver = DnsResolver::new();
        let _cache = DnsCache::new(100);
        let _query = DnsQuery::new();

        let _record_type = RecordType::A;
        let _record_class = RecordClass::IN;

        assert!(true);
    }

    #[test]
    fn test_resolver_integration() {
        let resolver = DnsResolver::new();

        assert!(resolver.enable_cache);
        assert_eq!(resolver.retries, 3);

        let servers = resolver.get_servers();
        assert!(!servers.is_empty());
    }

    #[test]
    fn test_cache_integration() {
        let cache = DnsCache::new(100);
        let record = DnsRecord::a(
            "test.com".to_string(),
            300,
            Ipv4Addr::new(192, 0, 2, 1),
        );

        cache.insert("test.com", record.clone());

        let cached = cache.get("test.com", RecordType::A);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);
    }

    #[test]
    fn test_record_types() {
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(28), RecordType::AAAA);
    }

    #[test]
    fn test_record_class() {
        assert_eq!(RecordClass::IN.to_u16(), 1);
        assert_eq!(RecordClass::from_u16(1), RecordClass::IN);
    }

    #[test]
    fn test_packet_creation() {
        let packet = DnsPacket::new_query(
            12345,
            "example.com".to_string(),
            RecordType::A,
        );

        assert_eq!(packet.header.id, 12345);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "example.com");
        assert_eq!(packet.questions[0].record_type, RecordType::A);
    }

    #[test]
    fn test_response_codes() {
        assert_eq!(ResponseCode::NoError as u8, 0);
        assert_eq!(ResponseCode::FormatError as u8, 1);
        assert_eq!(ResponseCode::ServerFailure as u8, 2);
        assert_eq!(ResponseCode::NameError as u8, 3);
        assert_eq!(ResponseCode::NotImplemented as u8, 4);
        assert_eq!(ResponseCode::Refused as u8, 5);
    }

    #[test]
    fn test_opcodes() {
        assert_eq!(OpCode::Query as u8, 0);
        assert_eq!(OpCode::IQuery as u8, 1);
        assert_eq!(OpCode::Status as u8, 2);
    }

    #[test]
    fn test_resolver_builder_pattern() {
        use std::time::Duration;

        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_secs(10))
            .with_retries(5)
            .with_cache(true)
            .with_cache_size(2048);

        assert_eq!(resolver.timeout, Duration::from_secs(10));
        assert_eq!(resolver.retries, 5);
        assert!(resolver.enable_cache);
    }

    #[test]
    fn test_query_builder_pattern() {
        use std::time::Duration;

        let query = DnsQuery::new()
            .with_timeout(Duration::from_secs(3))
            .with_id(9999);

        assert_eq!(query.timeout, Duration::from_secs(3));
        assert_eq!(query.id, 9999);
    }

    #[test]
    fn test_record_display() {
        let record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        let display = format!("{}", record);
        assert!(display.contains("example.com"));
        assert!(display.contains("300"));
    }

    #[test]
    fn test_cache_statistics() {
        let cache = DnsCache::new(100);
        let stats = cache.get_statistics();

        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.expired_entries, 0);
    }

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::NotAResponse;
        let display = format!("{}", error);
        assert!(display.contains("not a response"));
    }

    #[test]
    fn test_resolver_custom_servers() {
        let custom_server = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
        );

        let resolver = DnsResolver::with_servers(vec![custom_server]);
        let servers = resolver.get_servers();

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0], custom_server);
    }

    #[test]
    fn test_record_expiration() {
        let record = DnsRecord::a(
            "example.com".to_string(),
            10,
            Ipv4Addr::new(192, 0, 2, 1),
        );

        assert!(!record.is_expired(0));
        assert!(!record.is_expired(5));
        assert!(record.is_expired(10));
        assert!(record.is_expired(15));
    }

    #[test]
    fn test_multiple_record_types() {
        use std::net::Ipv6Addr;

        let a_record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        let aaaa_record = DnsRecord::aaaa(
            "example.com".to_string(),
            300,
            Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946),
        );

        let cname_record = DnsRecord::cname(
            "www.example.com".to_string(),
            300,
            "example.com".to_string(),
        );

        let mx_record = DnsRecord::mx(
            "example.com".to_string(),
            300,
            10,
            "mail.example.com".to_string(),
        );

        let txt_record = DnsRecord::txt(
            "example.com".to_string(),
            300,
            vec!["v=spf1 -all".to_string()],
        );

        assert_eq!(a_record.record_type, RecordType::A);
        assert_eq!(aaaa_record.record_type, RecordType::AAAA);
        assert_eq!(cname_record.record_type, RecordType::CNAME);
        assert_eq!(mx_record.record_type, RecordType::MX);
        assert_eq!(txt_record.record_type, RecordType::TXT);
    }

    #[test]
    fn test_secure_dns_roundtrip_identity() {
        let packet = DnsPacket::new_query(4242, "example.com".to_string(), RecordType::A);
        let encoded = encode_secure_dns_packet(&packet, CompressionAlgorithm::Identity).unwrap();
        let decoded = decode_secure_dns_packet(&encoded).unwrap();

        assert_eq!(decoded.header.id, 4242);
        assert_eq!(decoded.questions.len(), 1);
        assert_eq!(decoded.questions[0].name, "example.com");
        assert_eq!(decoded.questions[0].record_type, RecordType::A);
    }

    #[test]
    fn test_secure_dns_tamper_detection() {
        let packet = DnsPacket::new_query(77, "tamper.test".to_string(), RecordType::A);
        let mut encoded = encode_secure_dns_packet(&packet, CompressionAlgorithm::Identity).unwrap();

        let idx = encoded.len() - 1;
        encoded[idx] ^= 0x01;

        let result = decode_secure_dns_packet(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_algorithm_from_accept_encoding() {
        let algo = select_algorithm_from_accept_encoding("br;q=0.1, gzip;q=0.9, identity;q=0.5");
        assert_eq!(algo, CompressionAlgorithm::Gzip);
    }
}