use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            41 => RecordType::OPT,
            _ => RecordType::Unknown(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::Unknown(v) => v,
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    Unknown(u16),
}

impl RecordClass {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            2 => RecordClass::CS,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::Unknown(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CS => 2,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(Vec<String>),
    PTR(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32,
    pub data: RecordData,
}

impl DnsRecord {
    pub fn new(name: String, record_type: RecordType, record_class: RecordClass, ttl: u32, data: RecordData) -> Self {
        Self {
            name,
            record_type,
            record_class,
            ttl,
            data,
        }
    }

    pub fn a(name: String, ttl: u32, ip: Ipv4Addr) -> Self {
        Self::new(
            name,
            RecordType::A,
            RecordClass::IN,
            ttl,
            RecordData::A(ip),
        )
    }

    pub fn aaaa(name: String, ttl: u32, ip: Ipv6Addr) -> Self {
        Self::new(
            name,
            RecordType::AAAA,
            RecordClass::IN,
            ttl,
            RecordData::AAAA(ip),
        )
    }

    pub fn cname(name: String, ttl: u32, cname: String) -> Self {
        Self::new(
            name,
            RecordType::CNAME,
            RecordClass::IN,
            ttl,
            RecordData::CNAME(cname),
        )
    }

    pub fn mx(name: String, ttl: u32, preference: u16, exchange: String) -> Self {
        Self::new(
            name,
            RecordType::MX,
            RecordClass::IN,
            ttl,
            RecordData::MX { preference, exchange },
        )
    }

    pub fn txt(name: String, ttl: u32, texts: Vec<String>) -> Self {
        Self::new(
            name,
            RecordType::TXT,
            RecordClass::IN,
            ttl,
            RecordData::TXT(texts),
        )
    }

    pub fn is_expired(&self, elapsed_seconds: u32) -> bool {
        elapsed_seconds >= self.ttl
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::NS => write!(f, "NS"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::OPT => write!(f, "OPT"),
            RecordType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordData::A(ip) => write!(f, "{}", ip),
            RecordData::AAAA(ip) => write!(f, "{}", ip),
            RecordData::NS(name) => write!(f, "{}", name),
            RecordData::CNAME(name) => write!(f, "{}", name),
            RecordData::MX { preference, exchange } => {
                write!(f, "{} {}", preference, exchange)
            }
            RecordData::TXT(texts) => {
                write!(f, "\"{}\"", texts.join(" "))
            }
            RecordData::PTR(name) => write!(f, "{}", name),
            RecordData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
                write!(
                    f,
                    "{} {} {} {} {} {} {}",
                    mname, rname, serial, refresh, retry, expire, minimum
                )
            }
            RecordData::SRV { priority, weight, port, target } => {
                write!(f, "{} {} {} {}", priority, weight, port, target)
            }
            RecordData::Unknown(data) => {
                write!(f, "<{} bytes>", data.len())
            }
        }
    }
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.name,
            self.ttl,
            self.record_class.to_u16(),
            self.record_type,
            self.data
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(28), RecordType::AAAA);
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
    }

    #[test]
    fn test_record_creation() {
        let record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );
        
        assert_eq!(record.name, "example.com");
        assert_eq!(record.record_type, RecordType::A);
        assert_eq!(record.ttl, 300);
    }

    #[test]
    fn test_record_expiration() {
        let record = DnsRecord::a(
            "example.com".to_string(),
            300,
            Ipv4Addr::new(93, 184, 216, 34),
        );
        
        assert!(!record.is_expired(100));
        assert!(!record.is_expired(299));
        assert!(record.is_expired(300));
        assert!(record.is_expired(400));
    }
}