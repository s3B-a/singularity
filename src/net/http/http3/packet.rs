use super::error::{Error, Result};
use super::{decode_varint, encode_varint, ConnectionId};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const PACKET_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_PACKET_BLOB_V1";
const PACKET_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_PACKET_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePacketBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short,
    VersionNegotiation,
}

impl PacketType {
    pub fn to_long_header_type(&self) -> Option<u8> {
        match self {
            PacketType::Initial => Some(0x00),
            PacketType::ZeroRtt => Some(0x01),
            PacketType::Handshake => Some(0x02),
            PacketType::Retry => Some(0x03),
            _ => None,
        }
    }

    pub fn from_long_header_type(ty: u8) -> Result<Self> {
        match ty {
            0x00 => Ok(PacketType::Initial),
            0x01 => Ok(PacketType::ZeroRtt),
            0x02 => Ok(PacketType::Handshake),
            0x03 => Ok(PacketType::Retry),
            _ => Err(Error::InvalidPacket),
        }
    }

    pub fn is_long_header(&self) -> bool {
        !matches!(self, PacketType::Short)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

impl PacketNumberSpace {
    pub fn from_packet_type(ty: PacketType) -> Self {
        match ty {
            PacketType::Initial => PacketNumberSpace::Initial,
            PacketType::Handshake => PacketNumberSpace::Handshake,
            PacketType::ZeroRtt | PacketType::Short => PacketNumberSpace::ApplicationData,
            _ => PacketNumberSpace::Initial,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    pub token: Option<Vec<u8>>,
    pub packet_number: u64,
    pub key_phase: bool,
    pub largest_acked: u64,
}

pub struct ProtectedLongHeaderPrefix {
    pub packet_type: PacketType,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    pub token: Option<Vec<u8>>,
    pub pn_offset: usize,
}

pub struct ProtectedShortHeaderPrefix {
    pub dcid: ConnectionId,
    pub pn_offset: usize,
}

impl PacketHeader {
    pub fn new(packet_type: PacketType, version: u32, dcid: ConnectionId, scid: ConnectionId, packet_number: u64) -> Self {
        Self {
            packet_type,
            version,
            dcid,
            scid,
            packet_number,
            token: None,
            key_phase: false,
            largest_acked: 0,
        }
    }

    pub fn parse_protected_long_prefix(data: &[u8]) -> Result<ProtectedLongHeaderPrefix> {
        if data.len() < 5 {
            return Err(Error::BufferTooShort);
        }

        let mut offset = 0;
        let first = data[offset];
        offset += 1;
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        offset += 4;
        if version == 0 {
            return Err(Error::InvalidPacket);
        }

        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid_len = data[offset] as usize;
        offset += 1;
        if offset + dcid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid = ConnectionId::new(data[offset..offset + dcid_len].to_vec());
        offset += dcid_len;
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }

        let scid_len = data[offset] as usize;
        offset += 1;
        if offset + scid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let scid = ConnectionId::new(data[offset..offset + scid_len].to_vec());
        offset += scid_len;

        let type_bits = (first & 0x30) >> 4;
        let packet_type = PacketType::from_long_header_type(type_bits)?;
        if packet_type == PacketType::Retry {
            return Err(Error::InvalidPacket);
        }

        let mut token = None;
        if packet_type == PacketType::Initial {
            let (token_len, token_len_size) = decode_varint(&data[offset..])?;
            offset += token_len_size;
            if token_len > 0 {
                if offset + token_len as usize > data.len() {
                    return Err(Error::BufferTooShort);
                }

                token = Some(data[offset..offset + token_len as usize].to_vec());
                offset += token_len as usize;
            }
        }

        let (_length, length_size) = decode_varint(&data[offset..])?;
        offset += length_size;

        Ok(ProtectedLongHeaderPrefix {
            packet_type,
            version,
            dcid,
            scid,
            token,
            pn_offset: offset,
        })
    }

    pub fn parse_protected_short_prefix(data: &[u8]) -> Result<ProtectedShortHeaderPrefix> {
        const DCID_LEN: usize = 8;
        if data.len() < 1 + DCID_LEN {
            return Err(Error::BufferTooShort);
        }

        let dcid = ConnectionId::new(data[1..1 + DCID_LEN].to_vec());
        Ok(ProtectedShortHeaderPrefix {
            dcid,
            pn_offset: 1 + DCID_LEN,
        })
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::BufferTooShort);
        }

        let first = data[0];
        let is_long = (first & 0x80) != 0;
        if is_long {
            Self::parse_long_header(data)
        } else {
            Self::parse_short_header(data)
        }
    }

    fn parse_long_header(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 5 {
            return Err(Error::BufferTooShort);
        }

        let mut offset = 0;
        let first = data[offset];
        offset += 1;
        let version = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        offset += 4;
        if version == 0 {
            return Self::parse_version_negotiation(data);
        }

        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid_len = data[offset] as usize;
        offset += 1;
        if offset + dcid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid = ConnectionId::new(data[offset..offset + dcid_len].to_vec());
        offset += dcid_len;
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }

        let scid_len = data[offset] as usize;
        offset += 1;
        if offset + scid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let scid = ConnectionId::new(data[offset..offset + scid_len].to_vec());
        offset += scid_len;

        let type_bits = (first & 0x30) >> 4;
        let packet_type = PacketType::from_long_header_type(type_bits)?;
        let mut token = None;
        match packet_type {
            PacketType::Initial => {
                let (token_len, token_len_size) = decode_varint(&data[offset..])?;
                offset += token_len_size;
                if token_len > 0 {
                    if offset + token_len as usize > data.len() {
                        return Err(Error::BufferTooShort);
                    }

                    token = Some(data[offset..offset + token_len as usize].to_vec());
                    offset += token_len as usize;
                }
            }
            PacketType::Retry => {
                return Ok((
                    PacketHeader {
                        packet_type,
                        version,
                        dcid,
                        scid,
                        packet_number: 0,
                        token,
                        key_phase: false,
                        largest_acked: 0,
                    },
                    offset,
                ));
            }
            _ => {}
        }

        let (_length, length_size) = decode_varint(&data[offset..])?;
        offset += length_size;

        let pn_len = ((first & 0x03) + 1) as usize;
        if offset + pn_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let mut truncated_pn = 0u64;
        for i in 0..pn_len {
            truncated_pn = (truncated_pn << 8) | (data[offset + i] as u64);
        }

        offset += pn_len;
        let packet_number = PacketNumber::decode(truncated_pn, pn_len, 0);

        Ok((
            PacketHeader {
                packet_type,
                version,
                dcid,
                scid,
                packet_number,
                token,
                key_phase: false,
                largest_acked: 0,
            },
            offset,
        ))
    }

    fn parse_short_header(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::BufferTooShort);
        }

        let mut offset = 0;
        let first = data[offset];
        offset += 1;

        let key_phase = (first & 0x04) != 0;
        let dcid_len = 8;
        if offset + dcid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid = ConnectionId::new(data[offset..offset + dcid_len].to_vec());
        offset += dcid_len;

        let pn_len = ((first & 0x03) + 1) as usize;
        if offset + pn_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let mut truncated_pn = 0u64;
        for i in 0..pn_len {
            truncated_pn = (truncated_pn << 8) | (data[offset + i] as u64);
        }

        offset += pn_len;
        let packet_number = PacketNumber::decode(truncated_pn, pn_len, 0);

        Ok((
            PacketHeader {
                packet_type: PacketType::Short,
                version: 0,
                dcid,
                scid: ConnectionId::new(Vec::new()),
                packet_number,
                token: None,
                key_phase,
                largest_acked: 0,
            },
            offset,
        ))
    }

    fn parse_version_negotiation(data: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 1;
        offset += 4;
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid_len = data[offset] as usize;
        offset += 1;
        if offset + dcid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let dcid = ConnectionId::new(data[offset..offset + dcid_len].to_vec());
        offset += dcid_len;
        if offset >= data.len() {
            return Err(Error::BufferTooShort);
        }
        
        let scid_len = data[offset] as usize;
        offset += 1;
        if offset + scid_len > data.len() {
            return Err(Error::BufferTooShort);
        }

        let scid = ConnectionId::new(data[offset..offset + scid_len].to_vec());
        offset += scid_len;

        Ok((
            PacketHeader {
                packet_type: PacketType::VersionNegotiation,
                version: 0,
                dcid,
                scid,
                packet_number: 0,
                token: None,
                key_phase: false,
                largest_acked: 0,
            },
            offset,
        ))
    }

    pub fn encode(&self, buffer: &mut Vec<u8>, payload_len: usize) -> Result<(usize, usize)> {
        match self.packet_type {
            PacketType::Initial | PacketType::ZeroRtt | PacketType::Handshake | PacketType::Retry => {
                self.encode_long_header(buffer, payload_len)
            }
            PacketType::Short => self.encode_short_header(buffer),
            PacketType::VersionNegotiation => {
                self.encode_version_negotiation(buffer)?;
                Ok((0, 0))
            }
        }
    }

    fn encode_long_header(&self, buffer: &mut Vec<u8>, payload_len: usize) -> Result<(usize, usize)> {
        let type_bits = self.packet_type.to_long_header_type().ok_or(Error::InvalidPacket)?;
        let is_retry = self.packet_type == PacketType::Retry;
        let (pn_bytes, pn_len) = if is_retry {
            (Vec::new(), 0)
        } else {
            PacketNumber::encode(self.packet_number, self.largest_acked)
        };

        let pn_len_bits = if pn_len > 0 { (pn_len - 1) as u8 } else { 0x03 };
        let first = 0x80 | (type_bits << 4) | pn_len_bits;
        buffer.push(first);

        buffer.extend_from_slice(&self.version.to_be_bytes());

        buffer.push(self.dcid.len() as u8);
        buffer.extend_from_slice(self.dcid.as_bytes());

        buffer.push(self.scid.len() as u8);
        buffer.extend_from_slice(self.scid.as_bytes());
        if self.packet_type == PacketType::Initial {
            if let Some(ref token) = self.token {
                buffer.extend_from_slice(&encode_varint(token.len() as u64));
                buffer.extend_from_slice(token);
            } else {
                buffer.push(0);
            }
        }

        if is_retry {
            return Ok((0, 0));
        }

        buffer.extend_from_slice(&encode_varint((pn_len + payload_len) as u64));

        let pn_offset = buffer.len();
        buffer.extend_from_slice(&pn_bytes);

        Ok((pn_offset, pn_len))
    }

    fn encode_short_header(&self, buffer: &mut Vec<u8>) -> Result<(usize, usize)> {
        let (pn_bytes, pn_len) = PacketNumber::encode(self.packet_number, self.largest_acked);

        let mut first = 0x40;
        if self.key_phase {
            first |= 0x04;
        }

        first |= (pn_len - 1) as u8;
        buffer.push(first);

        buffer.extend_from_slice(self.dcid.as_bytes());

        let pn_offset = buffer.len();
        buffer.extend_from_slice(&pn_bytes);

        Ok((pn_offset, pn_len))
    }

    fn encode_version_negotiation(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let random_byte = random::generate_random(1).unwrap_or(vec![0])[0];
        buffer.push(0x80 | (random_byte & 0x7f));
        buffer.extend_from_slice(&0u32.to_be_bytes());

        buffer.push(self.dcid.len() as u8);
        buffer.extend_from_slice(self.dcid.as_bytes());

        buffer.push(self.scid.len() as u8);
        buffer.extend_from_slice(self.scid.as_bytes());

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

impl Packet {
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            encrypted: false,
        }
    }

    pub fn init(version: u32, dcid: ConnectionId, scid: ConnectionId, packet_number: u64, token: Option<Vec<u8>>, payload: Vec<u8>) -> Self {
        let mut header = PacketHeader::new(PacketType::Initial, version, dcid, scid, packet_number);
        header.token = token;
        Self::new(header, payload)
    }

    pub fn handshake(version: u32, dcid: ConnectionId, scid: ConnectionId, packet_number: u64, payload: Vec<u8>) -> Self {
        let header = PacketHeader::new(PacketType::Handshake, version, dcid, scid, packet_number);
        Self::new(header, payload)
    }

    pub fn short(dcid: ConnectionId, packet_number: u64, key_phase: bool, payload: Vec<u8>) -> Self {
        let mut header = PacketHeader::new(
            PacketType::Short,
            0,
            dcid,
            ConnectionId::new(Vec::new()),
            packet_number,
        );

        header.key_phase = key_phase;
        Self::new(header, payload)
    }

    pub fn retry(version: u32, dcid: ConnectionId, scid: ConnectionId, token: Vec<u8>, integrity_tag: [u8; 16]) -> Self {
        let mut payload = token;
        payload.extend_from_slice(&integrity_tag);
        let header = PacketHeader::new(PacketType::Retry, version, dcid, scid, 0);
        Self::new(header, payload)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, header_len) = PacketHeader::parse(data)?;
        if data.len() < header_len {
            return Err(Error::BufferTooShort);
        }

        let payload = data[header_len..].to_vec();
        Ok(Self {
            header,
            payload,
            encrypted: true,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.header.encode(&mut buffer, self.payload.len())?;
        buffer.extend_from_slice(&self.payload);
        Ok(buffer)
    }

    pub fn encode_with_pn_info(&self) -> Result<(Vec<u8>, usize, usize)> {
        let mut buffer = Vec::new();
        let (pn_offset, pn_len) = self.header.encode(&mut buffer, self.payload.len())?;
        buffer.extend_from_slice(&self.payload);
        Ok((buffer, pn_offset, pn_len))
    }

    pub fn packet_number_space(&self) -> PacketNumberSpace {
        PacketNumberSpace::from_packet_type(self.header.packet_type)
    }

    pub fn is_ack_eliciting(&self) -> bool {
        matches!(self.header.packet_type, PacketType::Initial | PacketType::Handshake | PacketType::Short)
    }

    pub fn wire_size(&self) -> usize {
        self.encode().map(|b| b.len()).unwrap_or(0)
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecurePacketBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_packet(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure packet nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_packet_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecurePacketBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        };

        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = PACKET_BLOB_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            issued_at = meta.issued_at_unix,
        );

        let mut blob = header.into_bytes();
        blob.extend_from_slice(&encoded_payload);

        Ok((meta, blob))
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecurePacketBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_packet_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecurePacketBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_packet_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure packet nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure packet digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure packet tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure packet digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_packet_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure packet tag verification failed",
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
                    "secure packet raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure packet digest verification failed",
            ));
        }

        let packet = deserialize_packet(&raw_payload)?;
        Ok((meta, packet))
    }
}

pub fn select_secure_packet_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_packet(packet: &Packet, algorithm: CompressionAlgorithm) -> io::Result<(SecurePacketBlobMeta, Vec<u8>)> {
    packet.to_secure_blob(algorithm)
}

pub fn encode_secure_packet_auto(packet: &Packet, accept_encoding: &str) -> io::Result<(SecurePacketBlobMeta, Vec<u8>)> {
    packet.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_packet(data: &[u8]) -> io::Result<(SecurePacketBlobMeta, Packet)> {
    Packet::from_secure_blob(data)
}

fn packet_type_label(packet_type: PacketType) -> &'static str {
    match packet_type {
        PacketType::Initial => "Initial",
        PacketType::ZeroRtt => "ZeroRtt",
        PacketType::Handshake => "Handshake",
        PacketType::Retry => "Retry",
        PacketType::Short => "Short",
        PacketType::VersionNegotiation => "VersionNegotiation",
    }
}

fn parse_packet_type(value: &str) -> io::Result<PacketType> {
    match value {
        "Initial" => Ok(PacketType::Initial),
        "ZeroRtt" | "0-RTT" => Ok(PacketType::ZeroRtt),
        "Handshake" => Ok(PacketType::Handshake),
        "Retry" => Ok(PacketType::Retry),
        "Short" => Ok(PacketType::Short),
        "VersionNegotiation" => Ok(PacketType::VersionNegotiation),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid packet-type '{}'", value),
        )),
    }
}

fn serialize_packet(packet: &Packet) -> Vec<u8> {
    let token_present = packet.header.token.is_some();
    let token_b64 = packet.header.token.as_ref().map(|t| pem::encode(t)).unwrap_or_default();
    format!(
        "packet-type={}\nversion={}\ndcid={}\nscid={}\ntoken-present={}\ntoken={}\npacket-number={}\nkey-phase={}\nencrypted={}\npayload={}\n",
        packet_type_label(packet.header.packet_type),
        packet.header.version,
        pem::encode(packet.header.dcid.as_bytes()),
        pem::encode(packet.header.scid.as_bytes()),
        token_present,
        token_b64,
        packet.header.packet_number,
        packet.header.key_phase,
        packet.encrypted,
        pem::encode(&packet.payload),
    )
    .into_bytes()
}

fn deserialize_packet(raw_payload: &[u8]) -> io::Result<Packet> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure packet payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    for line in payload.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure packet payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let packet_type = parse_packet_type(get_required_field(&map, "packet-type")?)?;
    let version = get_required_field(&map, "version")?.parse::<u32>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid packet version")
    })?;

    let dcid = pem::decode(get_required_field(&map, "dcid")?).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid dcid encoding: {}", e))
    })?;
    
    if dcid.len() > 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dcid too long in secure packet payload",
        ));
    }

    let scid = pem::decode(get_required_field(&map, "scid")?).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid scid encoding: {}", e))
    })?;
    
    if scid.len() > 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "scid too long in secure packet payload",
        ));
    }

    let token_present = parse_bool(get_required_field(&map, "token-present")?)?;
    let token_raw = get_required_field(&map, "token")?;
    let token = if token_present {
        Some(
            pem::decode(token_raw).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid token encoding: {}", e),
                )
            })?,
        )
    } else {
        None
    };

    let packet_number = get_required_field(&map, "packet-number")?.parse::<u64>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid packet-number")
    })?;

    let key_phase = parse_bool(get_required_field(&map, "key-phase")?)?;
    let encrypted = parse_bool(get_required_field(&map, "encrypted")?)?;
    let payload = pem::decode(get_required_field(&map, "payload")?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid packet payload encoding: {}", e),
        )
    })?;

    let mut header = PacketHeader::new(
        packet_type,
        version,
        ConnectionId::new(dcid),
        ConnectionId::new(scid),
        packet_number,
    );

    header.key_phase = key_phase;
    header.token = token;

    Ok(Packet {
        header,
        payload,
        encrypted,
    })
}

fn get_required_field<'a>(map: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    map.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing '{}' in secure packet payload", key),
        )
    })
}

fn parse_bool(value: &str) -> io::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean value '{}'", value),
        )),
    }
}

fn compute_packet_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(PACKET_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(PACKET_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "secure packet header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "secure packet header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "secure packet blob missing header/body separator",
    ))
}

fn parse_secure_packet_meta(header: &str, body_len: usize) -> io::Result<SecurePacketBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != PACKET_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure packet blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure packet header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", value.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(value.trim().to_string()),
            "digest" => {
                let parsed = value.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();

                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in secure packet blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size in secure packet blob")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(value.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in secure packet blob")
                })?);
            }
            _ => {}
        }
    }

    let meta = SecurePacketBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in secure packet blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in secure packet blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in secure packet blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in secure packet blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in secure packet blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in secure packet blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure packet encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
}

pub struct PacketNumber;

impl PacketNumber {
    pub fn encode(full_pn: u64, largest_acked: u64) -> (Vec<u8>, usize) {
        let num_unacked = if full_pn >= largest_acked {
            full_pn - largest_acked
        } else {
            0
        };

        let bytes_needed = if num_unacked < (1 << 7) {
            1
        } else if num_unacked < (1 << 15) {
            2
        } else if num_unacked < (1 << 23) {
            3
        } else {
            4
        };

        let mut encoded = Vec::new();
        for i in (0..bytes_needed).rev() {
            encoded.push(((full_pn >> (i * 8)) & 0xFF) as u8);
        }

        (encoded, bytes_needed)
    }

    pub fn decode(truncated_pn: u64, truncated_len: usize, largest_pn: u64) -> u64 {
        let expected_pn = largest_pn + 1;
        let pn_win = 1u64 << (truncated_len * 8);
        let pn_hwin = pn_win / 2;
        let pn_mask = pn_win - 1;
        let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;
        if candidate_pn <= expected_pn.saturating_sub(pn_hwin) && candidate_pn < (1u64 << 62) - pn_win {
            candidate_pn + pn_win
        } else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
            candidate_pn - pn_win
        } else {
            candidate_pn
        }
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::Initial => write!(f, "Initial"),
            PacketType::ZeroRtt => write!(f, "0-RTT"),
            PacketType::Handshake => write!(f, "Handshake"),
            PacketType::Retry => write!(f, "Retry"),
            PacketType::Short => write!(f, "Short"),
            PacketType::VersionNegotiation => write!(f, "VersionNegotiation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_conversion() {
        assert_eq!(PacketType::Initial.to_long_header_type(), Some(0x00));
        assert_eq!(PacketType::Handshake.to_long_header_type(), Some(0x02));
        assert_eq!(PacketType::Short.to_long_header_type(), None);

        assert_eq!(PacketType::from_long_header_type(0x00).unwrap(), PacketType::Initial);
        assert_eq!(PacketType::from_long_header_type(0x02).unwrap(), PacketType::Handshake);
    }

    #[test]
    fn test_packet_number_space() {
        assert_eq!(
            PacketNumberSpace::from_packet_type(PacketType::Initial),
            PacketNumberSpace::Initial
        );
        assert_eq!(
            PacketNumberSpace::from_packet_type(PacketType::Handshake),
            PacketNumberSpace::Handshake
        );
        assert_eq!(
            PacketNumberSpace::from_packet_type(PacketType::Short),
            PacketNumberSpace::ApplicationData
        );
    }

    #[test]
    fn test_packet_number_encoding() {
        let (encoded, len) = PacketNumber::encode(1000, 0);
        assert!(len <= 4);
        assert_eq!(encoded.len(), len);
    }

    #[test]
    fn test_packet_number_decoding() {
        let decoded = PacketNumber::decode(0x9b, 1, 0xa82f9b30);
        assert_eq!(decoded, 0xa82f9b9b);

        let decoded = PacketNumber::decode(0xac, 1, 0xa82f30ea);
        assert_eq!(decoded, 0xa82f30ac);
    }

    #[test]
    fn test_packet_creation() {
        let dcid = ConnectionId::generate().unwrap();
        let scid = ConnectionId::generate().unwrap();
        
        let packet = Packet::init(
            0x00000001,
            dcid.clone(),
            scid.clone(),
            0,
            None,
            vec![1, 2, 3, 4],
        );

        assert_eq!(packet.header.packet_type, PacketType::Initial);
        assert_eq!(packet.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_packet_encode_decode() {
        let dcid = ConnectionId::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let scid = ConnectionId::new(vec![8, 7, 6, 5, 4, 3, 2, 1]);
        
        let packet = Packet::handshake(
            0x00000001,
            dcid,
            scid,
            100,
            vec![0xff, 0xee, 0xdd],
        );

        let encoded = packet.encode().unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_packet_number_space_mapping() {
        let initial = Packet::init(
            1,
            ConnectionId::generate().unwrap(),
            ConnectionId::generate().unwrap(),
            0,
            None,
            vec![],
        );
        assert_eq!(initial.packet_number_space(), PacketNumberSpace::Initial);

        let handshake = Packet::handshake(
            1,
            ConnectionId::generate().unwrap(),
            ConnectionId::generate().unwrap(),
            0,
            vec![],
        );
        assert_eq!(handshake.packet_number_space(), PacketNumberSpace::Handshake);
    }

    #[test]
    fn test_secure_packet_roundtrip_identity() {
        let mut packet = Packet::short(
            ConnectionId::new(vec![11, 12, 13, 14, 15, 16, 17, 18]),
            42,
            true,
            vec![1, 3, 3, 7],
        );
        packet.encrypted = true;

        let (meta, blob) = encode_secure_packet(&packet, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_decoded_meta, decoded) = decode_secure_packet(&blob).unwrap();
        assert_eq!(decoded.header.packet_type, packet.header.packet_type);
        assert_eq!(decoded.header.packet_number, packet.header.packet_number);
        assert_eq!(decoded.header.key_phase, packet.header.key_phase);
        assert_eq!(decoded.header.dcid.as_bytes(), packet.header.dcid.as_bytes());
        assert_eq!(decoded.header.scid.as_bytes(), packet.header.scid.as_bytes());
        assert_eq!(decoded.payload, packet.payload);
        assert_eq!(decoded.encrypted, packet.encrypted);
    }

    #[test]
    fn test_secure_packet_roundtrip_compressed() {
        let mut packet = Packet::init(
            1,
            ConnectionId::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ConnectionId::new(vec![8, 7, 6, 5, 4, 3, 2, 1]),
            9,
            Some(vec![9, 9, 9]),
            vec![10, 20, 30, 40, 50, 60],
        );
        packet.encrypted = false;

        let (meta, blob) = encode_secure_packet(&packet, CompressionAlgorithm::Gzip).unwrap();
        assert_eq!(meta.raw_size > 0, true);

        let (_decoded_meta, decoded) = decode_secure_packet(&blob).unwrap();
        assert_eq!(decoded.header.packet_type, packet.header.packet_type);
        assert_eq!(decoded.header.version, packet.header.version);
        assert_eq!(decoded.header.packet_number, packet.header.packet_number);
        assert_eq!(decoded.header.dcid.as_bytes(), packet.header.dcid.as_bytes());
        assert_eq!(decoded.header.scid.as_bytes(), packet.header.scid.as_bytes());
        assert_eq!(decoded.header.token, packet.header.token);
        assert_eq!(decoded.payload, packet.payload);
        assert_eq!(decoded.encrypted, packet.encrypted);
    }

    #[test]
    fn test_secure_packet_tamper_detection() {
        let packet = Packet::handshake(
            1,
            ConnectionId::new(vec![1, 1, 1, 1, 1, 1, 1, 1]),
            ConnectionId::new(vec![2, 2, 2, 2, 2, 2, 2, 2]),
            12,
            vec![9, 8, 7, 6],
        );

        let (_meta, blob) = encode_secure_packet(&packet, CompressionAlgorithm::Identity).unwrap();
        let mut tampered = blob.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xAA;
        }

        assert!(decode_secure_packet(&tampered).is_err());
    }
}