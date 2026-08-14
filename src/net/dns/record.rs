use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

const DNS_RECORD_BLOB_MAGIC: &str = "SINGULARITY_DNS_RECORD_BLOB_V1";

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
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
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
            43 => RecordType::DS,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            50 => RecordType::NSEC3,
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
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
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
    RRSIG {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    NSEC {
        next_domain_name: String,
        type_bit_maps: Vec<u8>,
    },
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner_name: Vec<u8>,
        type_bit_maps: Vec<u8>,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRecordBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
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
        Self::new(name, RecordType::TXT, RecordClass::IN, ttl, RecordData::TXT(texts))
    }

    pub fn is_expired(&self, elapsed_seconds: u32) -> bool {
        elapsed_seconds >= self.ttl
    }

    pub fn fingerprint_sha256_b64(&self) -> String {
        let mut material = Vec::new();
        material.extend_from_slice(self.name.as_bytes());
        material.extend_from_slice(&self.record_type.to_u16().to_be_bytes());
        material.extend_from_slice(&self.record_class.to_u16().to_be_bytes());
        material.extend_from_slice(&self.ttl.to_be_bytes());
        material.extend_from_slice(&encode_record_data(&self.data));

        pem::encode(&sha256(&material))
    }

    pub fn encode_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<Vec<u8>> {
        let raw = encode_raw_record(self);
        let nonce = random::generate_random(16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate DNS record nonce: {}", e),
            )
        })?;

        let encoded = match algorithm {
            CompressionAlgorithm::Identity => raw.clone(),
            _ => compression::compress(algorithm, &raw, CompressionLevel::Default)?,
        };

        let digest = compute_record_digest(&nonce, &raw);
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\nraw-size={raw_size}\nencoded-size={encoded_size}\n\n",
            magic = DNS_RECORD_BLOB_MAGIC,
            encoding = algorithm.content_encoding(),
            nonce = pem::encode(&nonce),
            digest = pem::encode(&digest),
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

    pub fn decode_secure_blob(data: &[u8]) -> io::Result<(SecureRecordBlobMeta, DnsRecord)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_blob_meta(&header, body.len())?;
        let decoded = match meta.algorithm {
            CompressionAlgorithm::Identity => body.to_vec(),
            _ => compression::decompress(meta.algorithm, body)?,
        };

        if decoded.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded DNS record payload size mismatch",
            ));
        }

        let nonce = pem::decode(&meta.nonce_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nonce encoding in DNS record blob",
            )
        })?;

        let expected_digest = pem::decode(&meta.digest_b64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid digest encoding in DNS record blob",
            )
        })?;

        let computed = compute_record_digest(&nonce, &decoded);
        if !constant_time_eq(&computed, &expected_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure DNS record digest verification failed",
            ));
        }

        let record = decode_raw_record(&decoded)?;
        Ok((meta, record))
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
            RecordType::DS => write!(f, "DS"),
            RecordType::RRSIG => write!(f, "RRSIG"),
            RecordType::NSEC => write!(f, "NSEC"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::NSEC3 => write!(f, "NSEC3"),
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
            RecordData::RRSIG { type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name, .. } => {
                write!(
                    f,
                    "{} {} {} {} {} {} {} {}",
                    type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name
                )
            }
            RecordData::DNSKEY { flags, protocol, algorithm, public_key } => {
                write!(f, "{} {} {} <{} bytes>", flags, protocol, algorithm, public_key.len())
            }
            RecordData::DS { key_tag, algorithm, digest_type, digest } => {
                write!(f, "{} {} {} <{} bytes>", key_tag, algorithm, digest_type, digest.len())
            }
            RecordData::NSEC { next_domain_name, type_bit_maps } => {
                write!(f, "{} <{} bytes>", next_domain_name, type_bit_maps.len())
            }
            RecordData::NSEC3 { hash_algorithm, flags, iterations, salt, next_hashed_owner_name, type_bit_maps } => {
                write!(
                    f,
                    "{} {} {} <{}-byte salt> <{}-byte hash> <{} bytes>",
                    hash_algorithm, flags, iterations, salt.len(), next_hashed_owner_name.len(), type_bit_maps.len()
                )
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

fn select_algorithm_from_accept_encoding(accept_encoding: &str) -> CompressionAlgorithm {
    let parsed = compression::parse_accept_encoding(accept_encoding);
    for (algo, q) in parsed {
        if q > 0.0 && algo.is_implemented() {
            return algo;
        }
    }

    CompressionAlgorithm::Identity
}

fn encode_raw_record(record: &DnsRecord) -> Vec<u8> {
    let data_payload = encode_record_data(&record.data);
    let body = format!(
        "name-b64={}\nrecord-type={}\nrecord-class={}\nttl={}\ndata-kind={}\ndata-b64={}\n",
        pem::encode(record.name.as_bytes()),
        record.record_type.to_u16(),
        record.record_class.to_u16(),
        record.ttl,
        record_data_kind(&record.data),
        pem::encode(&data_payload),
    );

    body.into_bytes()
}

fn decode_raw_record(raw: &[u8]) -> io::Result<DnsRecord> {
    let text = String::from_utf8(raw.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS record payload is not valid UTF-8",
        )
    })?;

    let map = parse_kv_payload(&text);
    let name_b64 = map.get("name-b64")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing name-b64"))?;

    let type_u16 = map.get("record-type").and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing/invalid record-type"))?;

    let class_u16 = map.get("record-class").and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing/invalid record-class"))?;

    let ttl = map.get("ttl").and_then(|v| v.parse::<u32>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing/invalid ttl"))?;

    let kind = map.get("data-kind")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing data-kind"))?;

    let data_b64 = map.get("data-b64")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing data-b64"))?;

    let name_bytes = pem::decode(name_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 name field")
    })?;

    let name = String::from_utf8(name_bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "name field is not valid UTF-8")
    })?;

    let data_payload = pem::decode(data_b64).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 data payload")
    })?;

    let data = decode_record_data(kind, &data_payload)?;

    Ok(DnsRecord {
        name,
        record_type: RecordType::from_u16(type_u16),
        record_class: RecordClass::from_u16(class_u16),
        ttl,
        data,
    })
}

fn record_data_kind(data: &RecordData) -> &'static str {
    match data {
        RecordData::A(_) => "A",
        RecordData::AAAA(_) => "AAAA",
        RecordData::NS(_) => "NS",
        RecordData::CNAME(_) => "CNAME",
        RecordData::MX { .. } => "MX",
        RecordData::TXT(_) => "TXT",
        RecordData::PTR(_) => "PTR",
        RecordData::SOA { .. } => "SOA",
        RecordData::SRV { .. } => "SRV",
        RecordData::RRSIG { .. } => "RRSIG",
        RecordData::DNSKEY { .. } => "DNSKEY",
        RecordData::DS { .. } => "DS",
        RecordData::NSEC { .. } => "NSEC",
        RecordData::NSEC3 { .. } => "NSEC3",
        RecordData::Unknown(_) => "UNKNOWN",
    }
}

fn encode_record_data(data: &RecordData) -> Vec<u8> {
    match data {
        RecordData::A(ip) => ip.octets().to_vec(),
        RecordData::AAAA(ip) => ip.octets().to_vec(),
        RecordData::NS(name) | RecordData::CNAME(name) | RecordData::PTR(name) => {
            name.as_bytes().to_vec()
        }
        RecordData::MX {preference, exchange} => {
            let mut out = Vec::new();
            out.extend_from_slice(&preference.to_be_bytes());
            out.extend_from_slice(&(exchange.len() as u16).to_be_bytes());
            out.extend_from_slice(exchange.as_bytes());
            out
        }
        RecordData::TXT(texts) => {
            let mut out = Vec::new();
            out.extend_from_slice(&(texts.len() as u16).to_be_bytes());
            for t in texts {
                out.extend_from_slice(&(t.len() as u16).to_be_bytes());
                out.extend_from_slice(t.as_bytes());
            }
            out
        }
        RecordData::SOA {mname, rname, serial, refresh, retry, expire, minimum} => {
            let mut out = Vec::new();
            out.extend_from_slice(&(mname.len() as u16).to_be_bytes());
            out.extend_from_slice(mname.as_bytes());
            out.extend_from_slice(&(rname.len() as u16).to_be_bytes());
            out.extend_from_slice(rname.as_bytes());
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
            
            out
        }
        RecordData::SRV {priority, weight, port, target} => {
            let mut out = Vec::new();
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&(target.len() as u16).to_be_bytes());
            out.extend_from_slice(target.as_bytes());

            out
        }
        RecordData::RRSIG {type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name, signature} => {
            let mut out = Vec::new();
            out.extend_from_slice(&type_covered.to_be_bytes());
            out.push(*algorithm);
            out.push(*labels);
            out.extend_from_slice(&original_ttl.to_be_bytes());
            out.extend_from_slice(&signature_expiration.to_be_bytes());
            out.extend_from_slice(&signature_inception.to_be_bytes());
            out.extend_from_slice(&key_tag.to_be_bytes());
            out.extend_from_slice(&(signer_name.len() as u16).to_be_bytes());
            out.extend_from_slice(signer_name.as_bytes());
            out.extend_from_slice(signature);
            out
        }
        RecordData::DNSKEY {flags, protocol, algorithm, public_key} => {
            let mut out = Vec::new();
            out.extend_from_slice(&flags.to_be_bytes());
            out.push(*protocol);
            out.push(*algorithm);
            out.extend_from_slice(public_key);
            out
        }
        RecordData::DS {key_tag, algorithm, digest_type, digest} => {
            let mut out = Vec::new();
            out.extend_from_slice(&key_tag.to_be_bytes());
            out.push(*algorithm);
            out.push(*digest_type);
            out.extend_from_slice(digest);
            out
        }
        RecordData::NSEC {next_domain_name, type_bit_maps} => {
            let mut out = Vec::new();
            out.extend_from_slice(&(next_domain_name.len() as u16).to_be_bytes());
            out.extend_from_slice(next_domain_name.as_bytes());
            out.extend_from_slice(type_bit_maps);
            out
        }
        RecordData::NSEC3 {hash_algorithm, flags, iterations, salt, next_hashed_owner_name, type_bit_maps} => {
            let mut out = Vec::new();
            out.push(*hash_algorithm);
            out.push(*flags);
            out.extend_from_slice(&iterations.to_be_bytes());
            out.extend_from_slice(&(salt.len() as u16).to_be_bytes());
            out.extend_from_slice(salt);
            out.extend_from_slice(&(next_hashed_owner_name.len() as u16).to_be_bytes());
            out.extend_from_slice(next_hashed_owner_name);
            out.extend_from_slice(type_bit_maps);
            out
        }
        RecordData::Unknown(data) => data.clone(),
    }
}

fn decode_record_data(kind: &str, payload: &[u8]) -> io::Result<RecordData> {
    match kind {
        "A" => {
            if payload.len() != 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid A payload"));
            }
            Ok(RecordData::A(Ipv4Addr::new(
                payload[0], payload[1], payload[2], payload[3],
            )))
        }
        "AAAA" => {
            if payload.len() != 16 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid AAAA payload"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(payload);
            Ok(RecordData::AAAA(Ipv6Addr::from(octets)))
        }
        "NS" => Ok(RecordData::NS(String::from_utf8(payload.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid NS payload")
        })?)),
        "CNAME" => Ok(RecordData::CNAME(
            String::from_utf8(payload.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid CNAME payload"))?,
        )),
        "PTR" => Ok(RecordData::PTR(String::from_utf8(payload.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid PTR payload")
        })?)),
        "MX" => decode_mx(payload),
        "TXT" => decode_txt(payload),
        "SOA" => decode_soa(payload),
        "SRV" => decode_srv(payload),
        "RRSIG" => decode_rrsig(payload),
        "DNSKEY" => decode_dnskey(payload),
        "DS" => decode_ds(payload),
        "NSEC" => decode_nsec(payload),
        "NSEC3" => decode_nsec3(payload),
        "UNKNOWN" => Ok(RecordData::Unknown(payload.to_vec())),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported record data kind",
        )),
    }
}

fn decode_mx(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid MX payload"));
    }

    let preference = u16::from_be_bytes([payload[0], payload[1]]);
    let name_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if payload.len() != 4 + name_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MX exchange length",
        ));
    }

    let exchange = String::from_utf8(payload[4..].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid MX exchange"))?;

    Ok(RecordData::MX {
        preference,
        exchange,
    })
}

fn decode_txt(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TXT payload"));
    }

    let mut idx = 0usize;
    let count = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    let mut texts = Vec::with_capacity(count);
    for _ in 0..count {
        if idx + 2 > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TXT item length",
            ));
        }

        let len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
        idx += 2;
        if idx + len > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TXT item bytes",
            ));
        }

        let text = String::from_utf8(payload[idx..idx + len].to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid TXT item"))?;
        
        idx += len;
        texts.push(text);
    }

    if idx != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes in TXT payload",
        ));
    }

    Ok(RecordData::TXT(texts))
}

fn decode_soa(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOA payload"));
    }

    let mut idx = 0usize;
    let mname_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if idx + mname_len > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOA mname"));
    }

    let mname = String::from_utf8(payload[idx..idx + mname_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SOA mname"))?;
    
    idx += mname_len;
    if idx + 2 > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOA rname len"));
    }

    let rname_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if idx + rname_len > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOA rname"));
    }

    let rname = String::from_utf8(payload[idx..idx + rname_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SOA rname"))?;
    
    idx += rname_len;
    if idx + 20 != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOA integer fields",
        ));
    }

    let serial = u32::from_be_bytes([payload[idx], payload[idx + 1], payload[idx + 2], payload[idx + 3]]);
    idx += 4;
    let refresh = u32::from_be_bytes([payload[idx], payload[idx + 1], payload[idx + 2], payload[idx + 3]]);
    idx += 4;
    let retry = u32::from_be_bytes([payload[idx], payload[idx + 1], payload[idx + 2], payload[idx + 3]]);
    idx += 4;
    let expire = u32::from_be_bytes([payload[idx], payload[idx + 1], payload[idx + 2], payload[idx + 3]]);
    idx += 4;
    let minimum = u32::from_be_bytes([payload[idx], payload[idx + 1], payload[idx + 2], payload[idx + 3]]);

    Ok(RecordData::SOA {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

fn decode_srv(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SRV payload"));
    }

    let priority = u16::from_be_bytes([payload[0], payload[1]]);
    let weight = u16::from_be_bytes([payload[2], payload[3]]);
    let port = u16::from_be_bytes([payload[4], payload[5]]);
    let target_len = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    if payload.len() != 8 + target_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SRV target length",
        ));
    }

    let target = String::from_utf8(payload[8..].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SRV target"))?;

    Ok(RecordData::SRV {
        priority,
        weight,
        port,
        target,
    })
}

fn decode_rrsig(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 18 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid RRSIG payload"));
    }

    let type_covered = u16::from_be_bytes([payload[0], payload[1]]);
    let algorithm = payload[2];
    let labels = payload[3];
    let original_ttl = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let signature_expiration = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let signature_inception = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let key_tag = u16::from_be_bytes([payload[16], payload[17]]);

    let mut idx = 18usize;
    if idx + 2 > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid RRSIG signer name length"));
    }

    let name_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if idx + name_len > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid RRSIG signer name"));
    }

    let signer_name = String::from_utf8(payload[idx..idx + name_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RRSIG signer name"))?;
    idx += name_len;
    let signature = payload[idx..].to_vec();

    Ok(RecordData::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        signature_expiration,
        signature_inception,
        key_tag,
        signer_name,
        signature,
    })
}

fn decode_dnskey(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNSKEY payload"));
    }

    let flags = u16::from_be_bytes([payload[0], payload[1]]);
    let protocol = payload[2];
    let algorithm = payload[3];
    let public_key = payload[4..].to_vec();

    Ok(RecordData::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

fn decode_ds(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DS payload"));
    }

    let key_tag = u16::from_be_bytes([payload[0], payload[1]]);
    let algorithm = payload[2];
    let digest_type = payload[3];
    let digest = payload[4..].to_vec();

    Ok(RecordData::DS {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

fn decode_nsec(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC payload"));
    }

    let name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if 2 + name_len > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC next domain name"));
    }

    let next_domain_name = String::from_utf8(payload[2..2 + name_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC next domain name"))?;
    let type_bit_maps = payload[2 + name_len..].to_vec();

    Ok(RecordData::NSEC {
        next_domain_name,
        type_bit_maps,
    })
}

fn decode_nsec3(payload: &[u8]) -> io::Result<RecordData> {
    if payload.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC3 payload"));
    }

    let hash_algorithm = payload[0];
    let flags = payload[1];
    let iterations = u16::from_be_bytes([payload[2], payload[3]]);
    let salt_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let mut idx = 6usize;
    if idx + salt_len > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC3 salt"));
    }

    let salt = payload[idx..idx + salt_len].to_vec();
    idx += salt_len;

    if idx + 2 > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC3 hash length"));
    }

    let hash_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if idx + hash_len > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC3 next hashed owner name"));
    }

    let next_hashed_owner_name = payload[idx..idx + hash_len].to_vec();
    idx += hash_len;
    let type_bit_maps = payload[idx..].to_vec();

    Ok(RecordData::NSEC3 {
        hash_algorithm,
        flags,
        iterations,
        salt,
        next_hashed_owner_name,
        type_bit_maps,
    })
}

fn compute_record_digest(nonce: &[u8], raw_payload: &[u8]) -> [u8; 32] {
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
                "DNS record blob header is not valid UTF-8",
            )
        })?;

        let body = &data[pos + DELIM.len()..];
        return Ok((header, body));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "DNS record blob separator not found",
    ))
}

fn parse_secure_blob_meta(header: &str, body_len: usize) -> io::Result<SecureRecordBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != DNS_RECORD_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS record blob magic",
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
                    "unsupported DNS record content-encoding",
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
        io::Error::new(io::ErrorKind::InvalidData, "DNS record blob missing nonce")
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS record blob missing digest")
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS record blob missing raw-size")
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS record blob missing encoded-size")
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS record blob encoded-size mismatch",
        ));
    }

    Ok(SecureRecordBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        raw_size,
        encoded_size,
    })
}

fn parse_kv_payload(payload: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in payload.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    
    map
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

    #[test]
    fn test_record_fingerprint() {
        let record = DnsRecord::txt(
            "example.com".to_string(),
            120,
            vec!["v=spf1".to_string(), "~all".to_string()],
        );
        let fp = record.fingerprint_sha256_b64();
        assert!(!fp.is_empty());
    }

    #[test]
    fn test_secure_record_roundtrip_identity() {
        let record = DnsRecord::mx(
            "example.com".to_string(),
            300,
            10,
            "mail.example.com".to_string(),
        );

        let blob = record
            .encode_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();

        let (meta, decoded) = DnsRecord::decode_secure_blob(&blob).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded.name, "example.com");
        assert_eq!(decoded.record_type, RecordType::MX);
        assert_eq!(decoded.ttl, 300);
    }

    #[test]
    fn test_secure_record_roundtrip_gzip() {
        let record = DnsRecord::txt(
            "txt.example".to_string(),
            600,
            vec!["hello".to_string(), "world".to_string()],
        );

        let blob = record
            .encode_secure_blob(CompressionAlgorithm::Gzip)
            .unwrap();

        let (meta, decoded) = DnsRecord::decode_secure_blob(&blob).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(decoded.record_type, RecordType::TXT);
        assert_eq!(decoded.ttl, 600);
        if let RecordData::TXT(values) = decoded.data {
            assert_eq!(values.len(), 2);
            assert_eq!(values[0], "hello");
            assert_eq!(values[1], "world");
        } else {
            panic!("expected TXT data");
        }
    }

    #[test]
    fn test_secure_record_tamper_detection() {
        let record = DnsRecord::a(
            "tamper.example".to_string(),
            1,
            Ipv4Addr::new(1, 2, 3, 4),
        );

        let mut blob = record
            .encode_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = DnsRecord::decode_secure_blob(&blob);
        assert!(result.is_err());
    }
}