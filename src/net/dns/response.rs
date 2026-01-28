use super::packet::{DnsPacket, ResponseCode};
use super::record::{RecordType, DnsRecord};
use std::fmt;

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
        let answer = DnsRecord::a("example.com".to_string(), 300, Ipv4Addr::new(93, 184, 216, 34));

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
}