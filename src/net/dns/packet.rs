use super::record::{DnsRecord, RecordClass, RecordData, RecordType};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::io::{self, Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

const DNS_PACKET_BLOB_MAGIC: &str = "SINGULARITY_DNS_PACKET_BLOB_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

impl OpCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OpCode::Query),
            1 => Some(OpCode::IQuery),
            2 => Some(OpCode::Status),
            4 => Some(OpCode::Notify),
            5 => Some(OpCode::Update),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl ResponseCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::NoError,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: OpCode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        Self {
            id,
            is_response: false,
            opcode: OpCode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired,
            recursion_available: false,
            response_code: ResponseCode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.id.to_be_bytes())?;
        let mut flags: u16 = 0;
        if self.is_response {
            flags |= 0x8000;
        }

        flags |= ((self.opcode as u16) & 0x0F) << 11;
        if self.authoritative {
            flags |= 1 << 10;
        }

        if self.truncated {
            flags |= 1 << 9;
        }

        if self.recursion_desired {
            flags |= 1 << 8;
        }

        if self.recursion_available {
            flags |= 1 << 7;
        }

        flags |= (self.response_code as u16) & 0x0F;

        writer.write_all(&flags.to_be_bytes())?;
        writer.write_all(&self.question_count.to_be_bytes())?;
        writer.write_all(&self.answer_count.to_be_bytes())?;
        writer.write_all(&self.authority_count.to_be_bytes())?;
        writer.write_all(&self.additional_count.to_be_bytes())?;

        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 12];
        reader.read_exact(&mut buf)?;

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let is_response = (flags & 0x8000) != 0;
        let opcode = OpCode::from_u8(((flags >> 11) & 0x0F) as u8).unwrap_or(OpCode::Query);
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let response_code = ResponseCode::from_u8((flags & 0x000F) as u8);
        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
        let authority_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]);

        Ok(Self {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

impl DnsQuestion {
    pub fn new(name: String, record_type: RecordType) -> Self {
        Self {
            name,
            record_type,
            record_class: RecordClass::IN,
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write_domain_name(writer, &self.name)?;
        writer.write_all(&self.record_type.to_u16().to_be_bytes())?;
        writer.write_all(&self.record_class.to_u16().to_be_bytes())?;
        Ok(())
    }

    pub fn read(reader: &mut Cursor<&[u8]>, packet: &[u8]) -> io::Result<Self> {
        let name = read_domain_name(reader, packet)?;
        
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        
        let record_type = RecordType::from_u16(u16::from_be_bytes([buf[0], buf[1]]));
        let record_class = RecordClass::from_u16(u16::from_be_bytes([buf[2], buf[3]]));

        Ok(Self {
            name,
            record_type,
            record_class,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDnsPacketBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new_query(id: u16, name: String, record_type: RecordType) -> Self {
        let mut header = DnsHeader::new_query(id, true);
        header.question_count = 1;

        Self {
            header,
            questions: vec![DnsQuestion::new(name, record_type)],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn write(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(512);
        self.header.write(&mut buffer)?;
        for question in &self.questions {
            question.write(&mut buffer)?;
        }

        for answer in &self.answers {
            write_record(&mut buffer, answer)?;
        }

        for auth in &self.authority {
            write_record(&mut buffer, auth)?;
        }

        for add in &self.additional {
            write_record(&mut buffer, add)?;
        }

        Ok(buffer)
    }

    pub fn read(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        let header = DnsHeader::read(&mut cursor)?;
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            questions.push(DnsQuestion::read(&mut cursor, data)?);
        }

        let mut answers = Vec::new();
        for _ in 0..header.answer_count {
            answers.push(read_record(&mut cursor, data)?);
        }

        let mut authority = Vec::new();
        for _ in 0..header.authority_count {
            authority.push(read_record(&mut cursor, data)?);
        }

        let mut additional = Vec::new();
        for _ in 0..header.additional_count {
            additional.push(read_record(&mut cursor, data)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    pub fn fingerprint_sha256_b64(&self) -> io::Result<String> {
        let raw = self.write()?;
        Ok(pem::encode(&sha256(&raw)))
    }

    pub fn encode_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureDnsPacketBlobMeta, Vec<u8>)> {
        let raw = self.write()?;
        let encoded = compression::compress(algorithm, &raw, CompressionLevel::Default)?;
        let mut nonce = [0u8; 24];
        random::fill_random(&mut nonce).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate packet nonce: {e}"),
            )
        })?;

        let digest = compute_packet_digest(&nonce, &raw);
        let nonce_b64 = pem::encode(&nonce);
        let digest_b64 = pem::encode(&digest);
        let encoding_str = match algorithm {
            CompressionAlgorithm::Identity => "identity",
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Deflate => "deflate",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zstd",
        };

        let header = format!(
            "{magic}\ncontent-encoding: {encoding}\nnonce: {nonce}\ndigest: {digest}\nraw-size: {raw_size}\nencoded-size: {encoded_size}\n\n",
            magic = DNS_PACKET_BLOB_MAGIC,
            encoding = encoding_str,
            nonce = nonce_b64,
            digest = digest_b64,
            raw_size = raw.len(),
            encoded_size = encoded.len(),
        );

        let mut out = header.into_bytes();
        out.extend_from_slice(&encoded);

        Ok((
            SecureDnsPacketBlobMeta {
                algorithm,
                nonce_b64,
                digest_b64,
                raw_size: raw.len(),
                encoded_size: encoded.len(),
            },
            out,
        ))
    }

    pub fn encode_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureDnsPacketBlobMeta, Vec<u8>)> {
        let algorithm = select_algorithm_from_accept_encoding(accept_encoding);
        self.encode_secure_blob(algorithm)
    }

    pub fn decode_secure_blob(data: &[u8]) -> io::Result<(SecureDnsPacketBlobMeta, DnsPacket)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_blob_meta(&header, body.len())?;
        let wire = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body)?
        };

        if wire.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "secure packet raw size mismatch: expected {}, got {}",
                    meta.raw_size,
                    wire.len()
                ),
            ));
        }

        let nonce = pem::decode(&meta.nonce_b64)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid packet nonce"))?;
        
        let expected_digest = pem::decode(&meta.digest_b64)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid packet digest"))?;

        let actual_digest = compute_packet_digest(&nonce, &wire);
        if !constant_time_eq(&expected_digest, &actual_digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure packet digest verification failed",
            ));
        }

        let packet = DnsPacket::read(&wire)?;
        Ok((meta, packet))
    }
}

fn select_algorithm_from_accept_encoding(accept_encoding: &str) -> CompressionAlgorithm {
    let mut prefs = compression::parse_accept_encoding(accept_encoding);
    if prefs.is_empty() {
        return CompressionAlgorithm::Identity;
    }

    prefs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    prefs.into_iter().find(|(alg, q)| *q > 0.0 && *alg != CompressionAlgorithm::Identity)
        .map(|(alg, _)| alg).unwrap_or(CompressionAlgorithm::Identity)
}

fn compute_packet_digest(nonce: &[u8], raw_packet: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(
        DNS_PACKET_BLOB_MAGIC.len() + nonce.len() + std::mem::size_of::<u64>() + raw_packet.len(),
    );

    material.extend_from_slice(DNS_PACKET_BLOB_MAGIC.as_bytes());
    material.extend_from_slice(nonce);
    material.extend_from_slice(&(raw_packet.len() as u64).to_be_bytes());
    material.extend_from_slice(raw_packet);
    
    sha256(&material)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    const DELIM: &[u8] = b"\n\n";
    let pos = data.windows(DELIM.len()).position(|w| w == DELIM)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "secure packet header missing"))?;

    let header = std::str::from_utf8(&data[..pos])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secure packet header not utf8"))?.to_string();

    let body = &data[pos + DELIM.len()..];
    Ok((header, body))
}

fn parse_secure_blob_meta(header: &str, body_len: usize) -> io::Result<SecureDnsPacketBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "secure packet magic missing"))?;
    
    if magic != DNS_PACKET_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure packet magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = String::new();
    let mut digest_b64 = String::new();
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    for line in lines {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        match key {
            "content-encoding" => {
                algorithm = compression::CompressionAlgorithm::from_content_encoding(value).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported packet content-encoding: {value}"),
                    )
                })?;
            }
            "nonce" => nonce_b64 = value.to_string(),
            "digest" => digest_b64 = value.to_string(),
            "raw-size" => {
                raw_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid secure packet raw-size")
                })?)
            }
            "encoded-size" => {
                encoded_size = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid secure packet encoded-size",
                    )
                })?)
            }
            _ => {}
        }
    }

    if nonce_b64.is_empty() || digest_b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure packet metadata missing nonce/digest",
        ));
    }

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure packet metadata missing raw-size",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure packet metadata missing encoded-size",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure packet encoded-size mismatch: metadata {}, body {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureDnsPacketBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        raw_size,
        encoded_size,
    })
}

fn write_domain_name<W: Write>(writer: &mut W, name: &str) -> io::Result<()> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }

        if label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "label too long"));
        }

        writer.write_all(&[label.len() as u8])?;
        writer.write_all(label.as_bytes())?;
    }

    writer.write_all(&[0u8])?;
    Ok(())
}

fn read_domain_name(reader: &mut Cursor<&[u8]>, packet: &[u8]) -> io::Result<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_position = reader.position();
    loop {
        let current_pos = reader.position() as usize;
        if current_pos >= packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "read past end of packet",
            ));
        }

        let len = packet[current_pos];
        reader.set_position(current_pos as u64 + 1);
        if len == 0 {
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if !jumped {
                jump_position = reader.position() + 1;
                jumped = true;
            }

            let next_pos = reader.position() as usize;
            if next_pos >= packet.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid pointer"));
            }

            let offset = (((len & 0x3F) as u16) << 8 | packet[next_pos] as u16) as usize;
            if offset >= packet.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid pointer"));
            }

            reader.set_position(offset as u64);
            continue;
        }

        let pos = reader.position() as usize;
        if pos + len as usize > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "label extends past packet",
            ));
        }

        let label = &packet[pos..pos + len as usize];
        labels.push(String::from_utf8_lossy(label).into_owned());
        reader.set_position((pos + len as usize) as u64);
    }

    if jumped {
        reader.set_position(jump_position);
    }

    Ok(labels.join("."))
}

fn write_record<W: Write>(writer: &mut W, record: &DnsRecord) -> io::Result<()> {
    write_domain_name(writer, &record.name)?;
    writer.write_all(&record.record_type.to_u16().to_be_bytes())?;
    writer.write_all(&record.record_class.to_u16().to_be_bytes())?;
    writer.write_all(&record.ttl.to_be_bytes())?;
    let mut data_buf = Vec::new();
    match &record.data {
        RecordData::A(ip) => data_buf.extend_from_slice(&ip.octets()),
        RecordData::AAAA(ip) => data_buf.extend_from_slice(&ip.octets()),
        RecordData::NS(name) | RecordData::CNAME(name) | RecordData::PTR(name) => {
            write_domain_name(&mut data_buf, name)?;
        }
        RecordData::MX {preference, exchange} => {
            data_buf.extend_from_slice(&preference.to_be_bytes());
            write_domain_name(&mut data_buf, exchange)?;
        }
        RecordData::TXT(texts) => {
            for text in texts {
                if text.len() > 255 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "txt item too long"));
                }
                data_buf.push(text.len() as u8);
                data_buf.extend_from_slice(text.as_bytes());
            }
        }
        RecordData::SOA {mname, rname, serial, refresh, retry, expire, minimum} => {
            write_domain_name(&mut data_buf, mname)?;
            write_domain_name(&mut data_buf, rname)?;
            data_buf.extend_from_slice(&serial.to_be_bytes());
            data_buf.extend_from_slice(&refresh.to_be_bytes());
            data_buf.extend_from_slice(&retry.to_be_bytes());
            data_buf.extend_from_slice(&expire.to_be_bytes());
            data_buf.extend_from_slice(&minimum.to_be_bytes());
        }
        RecordData::SRV {priority, weight, port, target} => {
            data_buf.extend_from_slice(&priority.to_be_bytes());
            data_buf.extend_from_slice(&weight.to_be_bytes());
            data_buf.extend_from_slice(&port.to_be_bytes());
            write_domain_name(&mut data_buf, target)?;
        }
        RecordData::RRSIG {type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name, signature} => {
            data_buf.extend_from_slice(&type_covered.to_be_bytes());
            data_buf.push(*algorithm);
            data_buf.push(*labels);
            data_buf.extend_from_slice(&original_ttl.to_be_bytes());
            data_buf.extend_from_slice(&signature_expiration.to_be_bytes());
            data_buf.extend_from_slice(&signature_inception.to_be_bytes());
            data_buf.extend_from_slice(&key_tag.to_be_bytes());
            write_domain_name(&mut data_buf, signer_name)?;
            data_buf.extend_from_slice(signature);
        }
        RecordData::DNSKEY {flags, protocol, algorithm, public_key} => {
            data_buf.extend_from_slice(&flags.to_be_bytes());
            data_buf.push(*protocol);
            data_buf.push(*algorithm);
            data_buf.extend_from_slice(public_key);
        }
        RecordData::DS {key_tag, algorithm, digest_type, digest} => {
            data_buf.extend_from_slice(&key_tag.to_be_bytes());
            data_buf.push(*algorithm);
            data_buf.push(*digest_type);
            data_buf.extend_from_slice(digest);
        }
        RecordData::NSEC {next_domain_name, type_bit_maps} => {
            write_domain_name(&mut data_buf, next_domain_name)?;
            data_buf.extend_from_slice(type_bit_maps);
        }
        RecordData::Unknown(data) => data_buf.extend_from_slice(data),
    }

    writer.write_all(&(data_buf.len() as u16).to_be_bytes())?;
    writer.write_all(&data_buf)?;
    Ok(())
}

fn read_record(reader: &mut Cursor<&[u8]>, packet: &[u8]) -> io::Result<DnsRecord> {
    let name = read_domain_name(reader, packet)?;
    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf)?;

    let record_type = RecordType::from_u16(u16::from_be_bytes([buf[0], buf[1]]));
    let record_class = RecordClass::from_u16(u16::from_be_bytes([buf[2], buf[3]]));
    let ttl = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let data_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let mut data_buf = vec![0u8; data_len];
    reader.read_exact(&mut data_buf)?;

    let mut data_cursor = Cursor::new(&data_buf[..]);
    let data = match record_type {
        RecordType::A => {
            if data_len != 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid A record"));
            }

            RecordData::A(Ipv4Addr::new(
                data_buf[0],
                data_buf[1],
                data_buf[2],
                data_buf[3],
            ))
        }
        RecordType::AAAA => {
            if data_len != 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid AAAA record",
                ));
            }

            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data_buf);
            RecordData::AAAA(Ipv6Addr::from(octets))
        }
        RecordType::NS | RecordType::CNAME | RecordType::PTR => {
            let target = read_domain_name(&mut data_cursor, packet)?;
            match record_type {
                RecordType::NS => RecordData::NS(target),
                RecordType::CNAME => RecordData::CNAME(target),
                RecordType::PTR => RecordData::PTR(target),
                _ => unreachable!(),
            }
        }
        RecordType::MX => {
            if data_len < 3 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid MX record"));
            }

            let preference = u16::from_be_bytes([data_buf[0], data_buf[1]]);
            data_cursor.set_position(2);
            let exchange = read_domain_name(&mut data_cursor, packet)?;
            RecordData::MX {preference, exchange}
        }
        RecordType::TXT => {
            let mut texts = Vec::new();
            let mut pos = 0;
            while pos < data_len {
                let txt_len = data_buf[pos] as usize;
                pos += 1;
                if pos + txt_len > data_len {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TXT record"));
                }

                texts.push(String::from_utf8_lossy(&data_buf[pos..pos + txt_len]).into_owned());
                pos += txt_len;
            }

            RecordData::TXT(texts)
        }
        RecordType::SOA => {
            let mname = read_domain_name(&mut data_cursor, packet)?;
            let rname = read_domain_name(&mut data_cursor, packet)?;
            let pos = data_cursor.position() as usize;
            if data_len < pos + 20 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOA record"));
            }

            let serial = u32::from_be_bytes([
                data_buf[pos],
                data_buf[pos + 1],
                data_buf[pos + 2],
                data_buf[pos + 3],
            ]);

            let refresh = u32::from_be_bytes([
                data_buf[pos + 4],
                data_buf[pos + 5],
                data_buf[pos + 6],
                data_buf[pos + 7],
            ]);

            let retry = u32::from_be_bytes([
                data_buf[pos + 8],
                data_buf[pos + 9],
                data_buf[pos + 10],
                data_buf[pos + 11],
            ]);

            let expire = u32::from_be_bytes([
                data_buf[pos + 12],
                data_buf[pos + 13],
                data_buf[pos + 14],
                data_buf[pos + 15],
            ]);

            let minimum = u32::from_be_bytes([
                data_buf[pos + 16],
                data_buf[pos + 17],
                data_buf[pos + 18],
                data_buf[pos + 19],
            ]);

            RecordData::SOA {mname, rname, serial, refresh, retry, expire, minimum}
        }
        RecordType::SRV => {
            if data_len < 7 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SRV record"));
            }

            let priority = u16::from_be_bytes([data_buf[0], data_buf[1]]);
            let weight = u16::from_be_bytes([data_buf[2], data_buf[3]]);
            let port = u16::from_be_bytes([data_buf[4], data_buf[5]]);
            data_cursor.set_position(6);
            let target = read_domain_name(&mut data_cursor, packet)?;
            RecordData::SRV {priority, weight, port, target}
        }
        RecordType::RRSIG => {
            if data_len < 18 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid RRSIG record"));
            }

            let type_covered = u16::from_be_bytes([data_buf[0], data_buf[1]]);
            let algorithm = data_buf[2];
            let labels = data_buf[3];
            let original_ttl = u32::from_be_bytes([data_buf[4], data_buf[5], data_buf[6], data_buf[7]]);
            let signature_expiration = u32::from_be_bytes([data_buf[8], data_buf[9], data_buf[10], data_buf[11]]);
            let signature_inception = u32::from_be_bytes([data_buf[12], data_buf[13], data_buf[14], data_buf[15]]);
            let key_tag = u16::from_be_bytes([data_buf[16], data_buf[17]]);
            data_cursor.set_position(18);
            let signer_name = read_domain_name(&mut data_cursor, packet)?;
            let sig_start = data_cursor.position() as usize;
            if sig_start > data_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid RRSIG signer name"));
            }

            let signature = data_buf[sig_start..].to_vec();
            RecordData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            }
        }
        RecordType::DNSKEY => {
            if data_len < 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNSKEY record"));
            }

            let flags = u16::from_be_bytes([data_buf[0], data_buf[1]]);
            let protocol = data_buf[2];
            let algorithm = data_buf[3];
            let public_key = data_buf[4..].to_vec();
            RecordData::DNSKEY {flags, protocol, algorithm, public_key}
        }
        RecordType::DS => {
            if data_len < 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DS record"));
            }

            let key_tag = u16::from_be_bytes([data_buf[0], data_buf[1]]);
            let algorithm = data_buf[2];
            let digest_type = data_buf[3];
            let digest = data_buf[4..].to_vec();
            RecordData::DS {key_tag, algorithm, digest_type, digest}
        }
        RecordType::NSEC => {
            let next_domain_name = read_domain_name(&mut data_cursor, packet)?;
            let pos = data_cursor.position() as usize;
            if pos > data_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NSEC next domain name"));
            }

            let type_bit_maps = data_buf[pos..].to_vec();
            RecordData::NSEC {next_domain_name, type_bit_maps}
        }
        _ => RecordData::Unknown(data_buf),
    };

    Ok(DnsRecord::new(name, record_type, record_class, ttl, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let header = DnsHeader::new_query(1234, true);
        let mut buffer = Vec::new();
        header.write(&mut buffer).unwrap();

        let mut cursor = Cursor::new(&buffer[..]);
        let parsed = DnsHeader::read(&mut cursor).unwrap();

        assert_eq!(header.id, parsed.id);
        assert_eq!(header.recursion_desired, parsed.recursion_desired);
    }

    #[test]
    fn test_question_serialization() {
        let question = DnsQuestion::new("example.com".to_string(), RecordType::A);
        let mut buffer = Vec::new();
        question.write(&mut buffer).unwrap();

        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_packet_creation() {
        let packet = DnsPacket::new_query(5678, "example.com".to_string(), RecordType::A);

        assert_eq!(packet.header.id, 5678);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "example.com");
    }

    #[test]
    fn test_secure_packet_blob_roundtrip_identity() {
        let packet = DnsPacket::new_query(42, "example.org".to_string(), RecordType::AAAA);

        let (meta, blob) = packet
            .encode_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded_packet) = DnsPacket::decode_secure_blob(&blob).unwrap();

        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(decoded_packet.header.id, packet.header.id);
        assert_eq!(decoded_packet.questions.len(), packet.questions.len());
        assert_eq!(decoded_packet.questions[0].name, "example.org");
    }

    #[test]
    fn test_secure_packet_blob_roundtrip_gzip() {
        let packet = DnsPacket::new_query(7, "www.example.com".to_string(), RecordType::A);

        let (meta, blob) = packet
            .encode_secure_blob(CompressionAlgorithm::Gzip)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Gzip);

        let (_decoded_meta, decoded_packet) = DnsPacket::decode_secure_blob(&blob).unwrap();
        assert_eq!(decoded_packet.header.id, 7);
        assert_eq!(decoded_packet.questions[0].name, "www.example.com");
    }

    #[test]
    fn test_secure_packet_blob_tamper_detection() {
        let packet = DnsPacket::new_query(123, "tamper.test".to_string(), RecordType::A);
        let (_meta, mut blob) = packet
            .encode_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let err = DnsPacket::decode_secure_blob(&blob).unwrap_err();
        assert!(err.to_string().contains("digest verification failed"));
    }

    #[test]
    fn test_fingerprint_generation() {
        let packet = DnsPacket::new_query(9000, "fingerprint.example".to_string(), RecordType::TXT);
        let fp = packet.fingerprint_sha256_b64().unwrap();
        assert!(!fp.is_empty());
    }
}