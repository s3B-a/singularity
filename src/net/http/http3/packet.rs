use super::error::{Error, ErrorCode, Result};
use super::{ConnectionId, decode_varint, encode_varint};
use crate::crypto::random;
use std::fmt;

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
        }
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

        let version = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
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
                    },
                    offset,
                ));
            }
            _ => {}
        }

        let (length, length_size) = decode_varint(&data[offset..])?;
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
        let packet_number = 0;

        Ok((
            PacketHeader {
                packet_type: PacketType::Short,
                version: 0,
                dcid,
                scid: ConnectionId::new(Vec::new()),
                packet_number,
                token: None,
                key_phase,
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
            },
            offset,
        ))
    }

    pub fn encode(&self, buffer: &mut Vec<u8>) -> Result<()> {
        match self.packet_type {
            PacketType::Initial | PacketType::ZeroRtt | PacketType::Handshake | PacketType::Retry => {
                self.encode_long_header(buffer)
            }
            PacketType::Short => self.encode_short_header(buffer),
            PacketType::VersionNegotiation => self.encode_version_negotiation(buffer),
        }
    }

    fn encode_long_header(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let type_bits = self.packet_type.to_long_header_type().ok_or(Error::InvalidPacket)?;
        let first = 0x80 | (type_bits << 4) | 0x03;
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

        if self.packet_type != PacketType::Retry {
            buffer.extend_from_slice(&encode_varint(0));
            buffer.extend_from_slice(&self.packet_number.to_be_bytes());
        }

        Ok(())
    }

    fn encode_short_header(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut first = 0x40;
        if self.key_phase {
            first |= 0x04;
        }

        first |= 0x03;
        buffer.push(first);

        buffer.extend_from_slice(self.dcid.as_bytes());
        buffer.extend_from_slice(&self.packet_number.to_be_bytes());

        Ok(())
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
        let mut header = PacketHeader::new(PacketType::Short, 0, dcid, ConnectionId::new(Vec::new()), packet_number);
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
        self.header.encode(&mut buffer)?;
        buffer.extend_from_slice(&self.payload);
        Ok(buffer)
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
}