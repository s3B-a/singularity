mod record;
mod packet;
mod cache;
mod query;
mod response;
mod resolver;

pub use record::{RecordType, RecordClass, RecordData, DnsRecord};
pub use packet::{DnsPacket, DnsHeader, DnsQuestion, OpCode, ResponseCode};
pub use cache::{DnsCache, CacheStats};
pub use query::DnsQuery;
pub use response::{DnsResponse, ValidationError};
pub use resolver::DnsResolver;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, IpAddr};

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
        // Test record type conversions
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
}