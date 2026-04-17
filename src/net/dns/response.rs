use super::packet::{DnsPacket, ResponseCode};
use super::record::{DnsRecord, RecordType};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt;
use std::io;

const DNS_RESPONSE_BLOB_MAGIC: &str = "SINGULARITY_DNS_RESPONSE_BLOB_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDnsResponseBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub packet: DnsPacket,
}

impl DnsResponse {
    pub fn new(packet: DnsPacket) -> Self {
        Self { packet }
    }

    pub fn is_successful(&self) -> bool {
        self.packet.header.response_code == ResponseCode::NoError
    }

    pub fn is_authoritative(&self) -> bool {
        self.packet.header.authoritative
    }

    pub fn is_truncated(&self) -> bool {
        self.packet.header.truncated
    }

    pub fn response_code(&self) -> ResponseCode {
        self.packet.header.response_code
    }

    pub fn answers(&self) -> &[DnsRecord] {
        &self.packet.answers
    }

    pub fn authority(&self) -> &[DnsRecord] {
        &self.packet.authority
    }

    pub fn additional(&self) -> &[DnsRecord] {
        &self.packet.additional
    }

    pub fn get_records(&self, record_type: RecordType) -> Vec<&DnsRecord> {
        self.packet.answers.iter().filter(|r| r.record_type == record_type).collect()
    }

    pub fn get_a_records(&self) -> Vec<std::net::Ipv4Addr> {
        self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::A(ip) = r.data {
                    Some(ip)
                } else {
                    None
                }
            }).collect()
    }

    pub fn get_aaaa_records(&self) -> Vec<std::net::Ipv6Addr> {
        self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::AAAA(ip) = r.data {
                    Some(ip)
                } else {
                    None
                }
            }).collect()
    }

    pub fn get_cname_records(&self) -> Vec<String> {
        self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::CNAME(ref name) = r.data {
                    Some(name.clone())
                } else {
                    None
                }
            }).collect()
    }

    pub fn get_mx_records(&self) -> Vec<(u16, String)> {
        let mut records: Vec<_> = self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::MX { preference, ref exchange } = r.data {
                    Some((preference, exchange.clone()))
                } else {
                    None
                }
            }).collect();

        records.sort_by_key(|(pref, _)| *pref);
        records
    }

    pub fn get_txt_records(&self) -> Vec<Vec<String>> {
        self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::TXT(ref texts) = r.data {
                    Some(texts.clone())
                } else {
                    None
                }
            }).collect()
    }

    pub fn get_ns_records(&self) -> Vec<String> {
        self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::NS(ref name) = r.data {
                    Some(name.clone())
                } else {
                    None
                }
            }).collect()
    }

    pub fn get_ptr_records(&self) -> Vec<String> {
        self.packet.answers.iter().filter_map(|r| {
                if let super::record::RecordData::PTR(ref name) = r.data {
                    Some(name.clone())
                } else {
                    None
                }
            }).collect()
    }

    pub fn has_answers(&self) -> bool {
        !self.packet.answers.is_empty()
    }

    pub fn answer_count(&self) -> usize {
        self.packet.answers.len()
    }

    pub fn authority_count(&self) -> usize {
        self.packet.authority.len()
    }

    pub fn additional_count(&self) -> usize {
        self.packet.additional.len()
    }

    pub fn min_ttl(&self) -> Option<u32> {
        self.packet.answers.iter().map(|r| r.ttl).min()
    }

    pub fn max_ttl(&self) -> Option<u32> {
        self.packet.answers.iter().map(|r| r.ttl).max()
    }

    pub fn contains_record_type(&self, record_type: RecordType) -> bool {
        self.packet.answers.iter().any(|r| r.record_type == record_type)
    }

    pub fn follow_cname_chain(&self, max_depth: usize) -> Option<Vec<String>> {
        let mut chain = Vec::new();
        let mut current_names: Vec<String> = self.get_cname_records();
        if current_names.is_empty() {
            return None;
        }

        for _ in 0..max_depth {
            if current_names.is_empty() {
                break;
            }

            let name = current_names.pop()?;
            chain.push(name.clone());

            let next_cnames: Vec<String> = self.packet.answers.iter()
                .filter(|r| r.name.eq_ignore_ascii_case(&name))
                .filter_map(|r| {
                    if let super::record::RecordData::CNAME(ref cname) = r.data {
                        Some(cname.clone())
                    } else {
                        None
                    }
                }).collect();

            if next_cnames.is_empty() {
                break;
            }

            current_names.extend(next_cnames);
        }

        Some(chain)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.packet.header.is_response {
            return Err(ValidationError::NotAResponse);
        }

        if self.packet.header.truncated {
            return Err(ValidationError::Truncated);
        }

        if self.packet.header.response_code != ResponseCode::NoError {
            return Err(ValidationError::ErrorResponse(
                self.packet.header.response_code,
            ));
        }

        if self.packet.header.question_count == 0 {
            return Err(ValidationError::NoQuestions);
        }

        Ok(())
    }

    pub fn response_fingerprint_sha256_b64(&self) -> String {
        let mut material = Vec::new();
        material.extend_from_slice(&self.packet.header.id.to_be_bytes());
        material.extend_from_slice(&self.packet.header.answer_count.to_be_bytes());
        material.extend_from_slice(&self.packet.header.authority_count.to_be_bytes());
        material.extend_from_slice(&self.packet.header.additional_count.to_be_bytes());
        for rec in &self.packet.answers {
            material.extend_from_slice(rec.name.as_bytes());
            material.extend_from_slice(&rec.record_type.to_u16().to_be_bytes());
            material.extend_from_slice(&rec.record_class.to_u16().to_be_bytes());
            material.extend_from_slice(&rec.ttl.to_be_bytes());
        }

        pem::encode(&sha256(&material))
    }

    pub fn encode_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
        let raw = self.packet.write()?;
        let nonce = random::generate_random(16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate DNS response nonce: {}", e),
            )
        })?;

        let encoded = match algorithm {
            CompressionAlgorithm::Identity => raw.clone(),
            _ => compression::compress(algorithm, &raw, CompressionLevel::Default)?,
        };

        let digest = compute_secure_response_digest(&nonce, &raw);
        let digest_b64 = pem::encode(&digest);
        let nonce_b64 = pem::encode(&nonce);
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\nraw-size={raw_size}\nencoded-size={encoded_size}\n\n",
            magic = DNS_RESPONSE_BLOB_MAGIC,
            encoding = algorithm.content_encoding(),
            nonce = nonce_b64,
            digest = digest_b64,
            raw_size = raw.len(),
            encoded_size = encoded.len(),
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded);
        
        Ok(out)
    }

    pub fn encode_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<Vec<u8>> {
        let algorithm = select_algorithm_from_accept_encoding(accept_encoding);
        self.encode_secure_blob(algorithm)
    }

    pub fn decode_secure_blob(data: &[u8]) -> io::Result<DnsResponse> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_blob_meta(&header, body.len())?;
        let decoded = match meta.algorithm {
            CompressionAlgorithm::Identity => body.to_vec(),
            _ => compression::decompress(meta.algorithm, body)?,
        };

        if decoded.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded DNS response payload size mismatch",
            ));
        }

        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in DNS response blob",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in DNS response blob",
            )
        })?;

        let computed = compute_secure_response_digest(&nonce, &decoded);
        if !constant_time_eq(&computed, &expected_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure DNS response digest verification failed",
            ));
        }

        let packet = DnsPacket::read(&decoded)?;
        Ok(DnsResponse::new(packet))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    NotAResponse,
    Truncated,
    ErrorResponse(ResponseCode),
    NoQuestions,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::NotAResponse => write!(f, "Packet is not a response"),
            ValidationError::Truncated => write!(f, "Response is truncated"),
            ValidationError::ErrorResponse(code) => write!(f, "Error response: {:?}", code),
            ValidationError::NoQuestions => write!(f, "Response has no questions"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<DnsPacket> for DnsResponse {
    fn from(packet: DnsPacket) -> Self {
        Self::new(packet)
    }
}

fn select_algorithm_from_accept_encoding(accept_encoding: &str) -> CompressionAlgorithm {
    let parsed = compression::parse_accept_encoding(accept_encoding);
    for (algo, q) in parsed {
        if q > 0.0 && algo.is_implemented() {
            return algo;
        }
    }

    CompressionAlgorithm::Identity
}

fn compute_secure_response_digest(nonce: &[u8], raw_payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(nonce.len() + raw_payload.len());
    material.extend_from_slice(nonce);
    material.extend_from_slice(raw_payload);

    sha256(&material)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    if let Some(pos) = data.windows(DELIM.len()).position(|w| w == DELIM) {
        let header = String::from_utf8(data[..pos].to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response blob header is not valid UTF-8",
            )
        })?;

        let body = &data[pos + DELIM.len()..];
        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "DNS response blob separator not found",
    ))
}

fn parse_secure_blob_meta(header: &str, body_len: usize) -> io::Result<SecureDnsResponseBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != DNS_RESPONSE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS response blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    for line in lines {
        if let Some(v) = line.strip_prefix("content-encoding=") {
            algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported DNS response content-encoding",
                )
            })?;
        } else if let Some(v) = line.strip_prefix("nonce=") {
            nonce_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("digest=SHA-256=") {
            digest_b64 = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("raw-size=") {
            raw_size = v.trim().parse::<usize>().ok();
        } else if let Some(v) = line.strip_prefix("encoded-size=") {
            encoded_size = v.trim().parse::<usize>().ok();
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response blob missing nonce",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response blob missing digest",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response blob missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response blob missing encoded-size",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response blob encoded-size does not match body length",
        ));
    }

    Ok(SecureDnsResponseBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        raw_size,
        encoded_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::packet::{DnsHeader, DnsQuestion};
    use std::net::Ipv4Addr;

    fn create_test_response() -> DnsResponse {
        let mut header = DnsHeader::new_query(1234, true);
        header.is_response = true;
        header.question_count = 1;
        header.answer_count = 1;

        let question = DnsQuestion::new("example.com".to_string(), RecordType::A);
        let answer = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );

        let packet = DnsPacket {
            header,
            questions: vec![question],
            answers: vec![answer],
            authority: vec![],
            additional: vec![],
        };

        DnsResponse::new(packet)
    }

    #[test]
    fn test_response_creation() {
        let response = create_test_response();
        assert!(response.is_successful());
        assert!(response.has_answers());
        assert_eq!(response.answer_count(), 1);
    }

    #[test]
    fn test_get_a_records() {
        let response = create_test_response();
        let a_records = response.get_a_records();
        
        assert_eq!(a_records.len(), 1);
        assert_eq!(a_records[0], Ipv4Addr::new(93, 184, 216, 34));
    }

    #[test]
    fn test_contains_record_type() {
        let response = create_test_response();
        assert!(response.contains_record_type(RecordType::A));
        assert!(!response.contains_record_type(RecordType::AAAA));
    }

    #[test]
    fn test_ttl_functions() {
        let response = create_test_response();
        assert_eq!(response.min_ttl(), Some(300));
        assert_eq!(response.max_ttl(), Some(300));
    }

    #[test]
    fn test_validation_success() {
        let response = create_test_response();
        assert!(response.validate().is_ok());
    }

    #[test]
    fn test_validation_not_response() {
        let mut header = DnsHeader::new_query(1234, true);
        header.is_response = false;
        header.question_count = 1;

        let packet = DnsPacket {
            header,
            questions: vec![DnsQuestion::new("example.com".to_string(), RecordType::A)],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        let response = DnsResponse::new(packet);
        assert_eq!(response.validate(), Err(ValidationError::NotAResponse));
    }

    #[test]
    fn test_validation_truncated() {
        let mut header = DnsHeader::new_query(1234, true);
        header.is_response = true;
        header.truncated = true;
        header.question_count = 1;

        let packet = DnsPacket {
            header,
            questions: vec![DnsQuestion::new("example.com".to_string(), RecordType::A)],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        let response = DnsResponse::new(packet);
        assert_eq!(response.validate(), Err(ValidationError::Truncated));
    }

    #[test]
    fn test_empty_cname_chain() {
        let response = create_test_response();
        assert_eq!(response.follow_cname_chain(10), None);
    }

    #[test]
    fn test_response_fingerprint() {
        let response = create_test_response();
        let fp = response.response_fingerprint_sha256_b64();
        assert!(!fp.is_empty());
    }

    #[test]
    fn test_secure_blob_roundtrip_identity() {
        let response = create_test_response();
        let blob = response
            .encode_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();

        let decoded = DnsResponse::decode_secure_blob(&blob).unwrap();
        assert_eq!(decoded.packet.header.id, 1234);
        assert_eq!(decoded.answer_count(), 1);
        assert_eq!(decoded.get_a_records().len(), 1);
    }

    #[test]
    fn test_secure_blob_roundtrip_gzip() {
        let response = create_test_response();
        let blob = response
            .encode_secure_blob(CompressionAlgorithm::Gzip)
            .unwrap();

        let decoded = DnsResponse::decode_secure_blob(&blob).unwrap();
        assert_eq!(decoded.packet.header.id, 1234);
        assert_eq!(decoded.answer_count(), 1);
    }

    #[test]
    fn test_secure_blob_tamper_detection() {
        let response = create_test_response();
        let mut blob = response
            .encode_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = DnsResponse::decode_secure_blob(&blob);
        assert!(result.is_err());
    }
}