use super::error::{Error, ErrorCode, Result};
use super::{decode_varint, encode_varint, ConnectionId};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const FRAME_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_FRAME_BLOB_V1";
const FRAME_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_FRAME_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureFrameBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlocked = 0x16,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,
}

impl FrameType {
    pub fn from_u64(value: u64) -> Result<Self> {
        match value {
            0x00 => Ok(FrameType::Padding),
            0x01 => Ok(FrameType::Ping),
            0x02 => Ok(FrameType::Ack),
            0x03 => Ok(FrameType::AckEcn),
            0x04 => Ok(FrameType::ResetStream),
            0x05 => Ok(FrameType::StopSending),
            0x06 => Ok(FrameType::Crypto),
            0x07 => Ok(FrameType::NewToken),
            0x08..=0x0f => Ok(FrameType::Stream),
            0x10 => Ok(FrameType::MaxData),
            0x11 => Ok(FrameType::MaxStreamData),
            0x12 | 0x13 => Ok(FrameType::MaxStreams),
            0x14 => Ok(FrameType::DataBlocked),
            0x15 => Ok(FrameType::StreamDataBlocked),
            0x16 | 0x17 => Ok(FrameType::StreamsBlocked),
            0x18 => Ok(FrameType::NewConnectionId),
            0x19 => Ok(FrameType::RetireConnectionId),
            0x1a => Ok(FrameType::PathChallenge),
            0x1b => Ok(FrameType::PathResponse),
            0x1c => Ok(FrameType::ConnectionClose),
            0x1d => Ok(FrameType::ConnectionCloseApp),
            0x1e => Ok(FrameType::HandshakeDone),
            _ => Err(Error::InvalidFrame),
        }
    }

    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(self, FrameType::Ack | FrameType::AckEcn | FrameType::Padding | FrameType::ConnectionClose | FrameType::ConnectionCloseApp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub gap: u64,
    pub len: u64,
}

#[derive(Debug, Clone)]
pub enum Frame {
    Padding {
        length: usize,
    },

    Ping,

    Ack {
        largest_ack: u64,
        ack_delay: u64,
        ranges: Vec<AckRange>,
        ecn_counts: Option<(u64, u64, u64)>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        offset: u64,
        data: Vec<u8>,
    },

    NewToken {
        token: Vec<u8>,
    },

    Stream {
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
        fin: bool,
    },

    MaxData {
        max: u64,
    },

    MaxStreamData {
        stream_id: u64,
        max: u64,
    },

    MaxStreams {
        bidirectional: bool,
        max: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlocked {
        bidirectional: bool,
        limit: u64,
    },

    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    },

    RetireConnectionId {
        sequence: u64,
    },

    PathChallenge {
        data: [u8; 8],
    },

    PathResponse {
        data: [u8; 8],
    },

    ConnectionClose {
        error_code: ErrorCode,
        frame_type: Option<u64>,
        reason: Vec<u8>,
    },

    ConnectionCloseApp {
        error_code: u64,
        reason: Vec<u8>,
    },

    HandshakeDone,
}

impl Frame {
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::BufferTooShort);
        }

        let mut offset = 0;
        let (frame_type_val, type_len) = decode_varint(&data[offset..])?;
        offset += type_len;

        let frame_type = FrameType::from_u64(frame_type_val)?;
        match frame_type {
            FrameType::Padding => {
                let mut length = 1;
                while offset < data.len() && data[offset] == 0x00 {
                    length += 1;
                    offset += 1;
                }

                Ok((Frame::Padding { length }, offset))
            }
            FrameType::Ping => Ok((Frame::Ping, offset)),
            FrameType::Ack | FrameType::AckEcn => {
                let (largest_ack, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (ack_delay, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (range_count, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (first_range, len) = decode_varint(&data[offset..])?;
                offset += len;

                let mut ranges = vec![AckRange { gap: 0, len: first_range }];
                for _ in 0..range_count {
                    let (gap, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    let (range_len, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    ranges.push(AckRange { gap, len: range_len });
                }

                let ecn_counts = if frame_type == FrameType::AckEcn {
                    let (ect0, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    let (ect1, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    let (ce, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    Some((ect0, ect1, ce))
                } else {
                    None
                };

                Ok((
                    Frame::Ack {
                        largest_ack,
                        ack_delay,
                        ranges,
                        ecn_counts,
                    },
                    offset,
                ))
            }
            FrameType::ResetStream => {
                let (stream_id, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (error_code, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (final_size, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    },
                    offset,
                ))
            }
            FrameType::StopSending => {
                let (stream_id, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (error_code, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::StopSending { stream_id, error_code }, offset))
            }
            FrameType::Crypto => {
                let (crypto_offset, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (length, len) = decode_varint(&data[offset..])?;
                offset += len;
                if offset + length as usize > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let crypto_data = data[offset..offset + length as usize].to_vec();
                offset += length as usize;

                Ok((
                    Frame::Crypto {
                        offset: crypto_offset,
                        data: crypto_data,
                    },
                    offset,
                ))
            }
            FrameType::NewToken => {
                let (length, len) = decode_varint(&data[offset..])?;
                offset += len;
                if offset + length as usize > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let token = data[offset..offset + length as usize].to_vec();
                offset += length as usize;

                Ok((Frame::NewToken { token }, offset))
            }
            FrameType::Stream => {
                let flags = frame_type_val as u8;
                let has_offset = (flags & 0x04) != 0;
                let has_length = (flags & 0x02) != 0;
                let fin = (flags & 0x01) != 0;

                let (stream_id, len) = decode_varint(&data[offset..])?;
                offset += len;

                let stream_offset = if has_offset {
                    let (off, len) = decode_varint(&data[offset..])?;
                    offset += len;
                    off
                } else {
                    0
                };

                let stream_data = if has_length {
                    let (length, len) = decode_varint(&data[offset..])?;
                    offset += len;
                    if offset + length as usize > data.len() {
                        return Err(Error::BufferTooShort);
                    }

                    let data_slice = data[offset..offset + length as usize].to_vec();
                    offset += length as usize;
                    data_slice
                } else {
                    let data_slice = data[offset..].to_vec();
                    offset = data.len();
                    data_slice
                };

                Ok((
                    Frame::Stream {
                        stream_id,
                        offset: stream_offset,
                        data: stream_data,
                        fin,
                    },
                    offset,
                ))
            }
            FrameType::MaxData => {
                let (max, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::MaxData { max }, offset))
            }
            FrameType::MaxStreamData => {
                let (stream_id, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (max, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::MaxStreamData { stream_id, max }, offset))
            }
            FrameType::MaxStreams => {
                let bidirectional = (frame_type_val & 0x01) == 0;

                let (max, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::MaxStreams { max, bidirectional }, offset))
            }
            FrameType::DataBlocked => {
                let (limit, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::DataBlocked { limit }, offset))
            }
            FrameType::StreamDataBlocked => {
                let (stream_id, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (limit, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::StreamDataBlocked { stream_id, limit }, offset))
            }
            FrameType::StreamsBlocked => {
                let bidirectional = (frame_type_val & 0x01) == 0;

                let (limit, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::StreamsBlocked { limit, bidirectional }, offset))
            }
            FrameType::NewConnectionId => {
                let (sequence, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (retire_prior_to, len) = decode_varint(&data[offset..])?;
                offset += len;
                if offset >= data.len() {
                    return Err(Error::BufferTooShort);
                }

                let cid_len = data[offset] as usize;
                offset += 1;
                if cid_len > 20 || offset + cid_len > data.len() {
                    return Err(Error::InvalidFrame);
                }

                let connection_id = ConnectionId::new(data[offset..offset + cid_len].to_vec());
                offset += cid_len;
                if offset + 16 > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let mut token = [0u8; 16];
                token.copy_from_slice(&data[offset..offset + 16]);
                offset += 16;

                Ok((
                    Frame::NewConnectionId {
                        sequence,
                        retire_prior_to,
                        connection_id,
                        stateless_reset_token: token,
                    },
                    offset,
                ))
            }
            FrameType::RetireConnectionId => {
                let (sequence, len) = decode_varint(&data[offset..])?;
                offset += len;

                Ok((Frame::RetireConnectionId { sequence }, offset))
            }
            FrameType::PathChallenge => {
                if offset + 8 > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let mut challenge_data = [0u8; 8];
                challenge_data.copy_from_slice(&data[offset..offset + 8]);
                offset += 8;

                Ok((Frame::PathChallenge { data: challenge_data }, offset))
            }
            FrameType::PathResponse => {
                if offset + 8 > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let mut response_data = [0u8; 8];
                response_data.copy_from_slice(&data[offset..offset + 8]);
                offset += 8;

                Ok((Frame::PathResponse { data: response_data }, offset))
            }
            FrameType::ConnectionClose => {
                let (error_code_val, len) = decode_varint(&data[offset..])?;
                offset += len;

                let error_code = ErrorCode::from_wire(error_code_val);

                let (frame_type_val, len) = decode_varint(&data[offset..])?;
                offset += len;

                let frame_type = if frame_type_val == 0 {
                    None
                } else {
                    Some(frame_type_val)
                };

                let (reason_len, len) = decode_varint(&data[offset..])?;
                offset += len;
                if offset + reason_len as usize > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let reason = data[offset..offset + reason_len as usize].to_vec();
                offset += reason_len as usize;

                Ok((
                    Frame::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    },
                    offset,
                ))
            }
            FrameType::ConnectionCloseApp => {
                let (error_code, len) = decode_varint(&data[offset..])?;
                offset += len;

                let (reason_len, len) = decode_varint(&data[offset..])?;
                offset += len;
                if offset + reason_len as usize > data.len() {
                    return Err(Error::BufferTooShort);
                }

                let reason = data[offset..offset + reason_len as usize].to_vec();
                offset += reason_len as usize;

                Ok((Frame::ConnectionCloseApp { error_code, reason }, offset))
            }
            FrameType::HandshakeDone => Ok((Frame::HandshakeDone, offset)),
        }
    }

    pub fn encode(&self, buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Frame::Padding { length } => {
                buffer.extend(vec![0x00; *length]);
            }
            Frame::Ping => {
                buffer.push(0x01);
            }
            Frame::Ack {
                largest_ack,
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let frame_type = if ecn_counts.is_some() { 0x03 } else { 0x02 };
                buffer.push(frame_type);

                buffer.extend_from_slice(&encode_varint(*largest_ack));
                buffer.extend_from_slice(&encode_varint(*ack_delay));
                buffer.extend_from_slice(&encode_varint(ranges.len().saturating_sub(1) as u64));
                if let Some(first) = ranges.first() {
                    buffer.extend_from_slice(&encode_varint(first.len));
                }

                for range in ranges.iter().skip(1) {
                    buffer.extend_from_slice(&encode_varint(range.gap));
                    buffer.extend_from_slice(&encode_varint(range.len));
                }

                if let Some((ect0, ect1, ce)) = ecn_counts {
                    buffer.extend_from_slice(&encode_varint(*ect0));
                    buffer.extend_from_slice(&encode_varint(*ect1));
                    buffer.extend_from_slice(&encode_varint(*ce));
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                buffer.push(0x04);
                buffer.extend_from_slice(&encode_varint(*stream_id));
                buffer.extend_from_slice(&encode_varint(*error_code));
                buffer.extend_from_slice(&encode_varint(*final_size));
            }
            Frame::StopSending { stream_id, error_code } => {
                buffer.push(0x05);
                buffer.extend_from_slice(&encode_varint(*stream_id));
                buffer.extend_from_slice(&encode_varint(*error_code));
            }
            Frame::Crypto { offset, data } => {
                buffer.push(0x06);
                buffer.extend_from_slice(&encode_varint(*offset));
                buffer.extend_from_slice(&encode_varint(data.len() as u64));
                buffer.extend_from_slice(data);
            }
            Frame::NewToken { token } => {
                buffer.push(0x07);
                buffer.extend_from_slice(&encode_varint(token.len() as u64));
                buffer.extend_from_slice(token);
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => {
                let mut flags = 0x08u8;
                if *offset > 0 {
                    flags |= 0x04;
                }

                flags |= 0x02;
                if *fin {
                    flags |= 0x01;
                }

                buffer.push(flags);
                buffer.extend_from_slice(&encode_varint(*stream_id));
                if *offset > 0 {
                    buffer.extend_from_slice(&encode_varint(*offset));
                }

                buffer.extend_from_slice(&encode_varint(data.len() as u64));
                buffer.extend_from_slice(data);
            }
            Frame::MaxData { max } => {
                buffer.push(0x10);
                buffer.extend_from_slice(&encode_varint(*max));
            }
            Frame::MaxStreamData { stream_id, max } => {
                buffer.push(0x11);
                buffer.extend_from_slice(&encode_varint(*stream_id));
                buffer.extend_from_slice(&encode_varint(*max));
            }
            Frame::MaxStreams { max, bidirectional } => {
                buffer.push(if *bidirectional { 0x12 } else { 0x13 });
                buffer.extend_from_slice(&encode_varint(*max));
            }
            Frame::DataBlocked { limit } => {
                buffer.push(0x14);
                buffer.extend_from_slice(&encode_varint(*limit));
            }
            Frame::StreamDataBlocked { stream_id, limit } => {
                buffer.push(0x15);
                buffer.extend_from_slice(&encode_varint(*stream_id));
                buffer.extend_from_slice(&encode_varint(*limit));
            }
            Frame::StreamsBlocked { limit, bidirectional } => {
                buffer.push(if *bidirectional { 0x16 } else { 0x17 });
                buffer.extend_from_slice(&encode_varint(*limit));
            }
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            } => {
                buffer.push(0x18);
                buffer.extend_from_slice(&encode_varint(*sequence));
                buffer.extend_from_slice(&encode_varint(*retire_prior_to));
                buffer.push(connection_id.len() as u8);
                buffer.extend_from_slice(connection_id.as_bytes());
                buffer.extend_from_slice(stateless_reset_token);
            }
            Frame::RetireConnectionId { sequence } => {
                buffer.push(0x19);
                buffer.extend_from_slice(&encode_varint(*sequence));
            }
            Frame::PathChallenge { data } => {
                buffer.push(0x1a);
                buffer.extend_from_slice(data);
            }
            Frame::PathResponse { data } => {
                buffer.push(0x1b);
                buffer.extend_from_slice(data);
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                buffer.push(0x1c);
                buffer.extend_from_slice(&encode_varint(error_code.to_wire()));
                buffer.extend_from_slice(&encode_varint(frame_type.unwrap_or(0)));
                buffer.extend_from_slice(&encode_varint(reason.len() as u64));
                buffer.extend_from_slice(reason);
            }
            Frame::ConnectionCloseApp { error_code, reason } => {
                buffer.push(0x1d);
                buffer.extend_from_slice(&encode_varint(*error_code));
                buffer.extend_from_slice(&encode_varint(reason.len() as u64));
                buffer.extend_from_slice(reason);
            }
            Frame::HandshakeDone => {
                buffer.push(0x1e);
            }
        }

        Ok(())
    }

    pub fn frame_type(&self) -> FrameType {
        match self {
            Frame::Padding { .. } => FrameType::Padding,
            Frame::Ping => FrameType::Ping,
            Frame::Ack { ecn_counts, .. } => {
                if ecn_counts.is_some() {
                    FrameType::AckEcn
                } else {
                    FrameType::Ack
                }
            }
            Frame::ResetStream { .. } => FrameType::ResetStream,
            Frame::StopSending { .. } => FrameType::StopSending,
            Frame::Crypto { .. } => FrameType::Crypto,
            Frame::NewToken { .. } => FrameType::NewToken,
            Frame::Stream { .. } => FrameType::Stream,
            Frame::MaxData { .. } => FrameType::MaxData,
            Frame::MaxStreamData { .. } => FrameType::MaxStreamData,
            Frame::MaxStreams { .. } => FrameType::MaxStreams,
            Frame::DataBlocked { .. } => FrameType::DataBlocked,
            Frame::StreamDataBlocked { .. } => FrameType::StreamDataBlocked,
            Frame::StreamsBlocked { .. } => FrameType::StreamsBlocked,
            Frame::NewConnectionId { .. } => FrameType::NewConnectionId,
            Frame::RetireConnectionId { .. } => FrameType::RetireConnectionId,
            Frame::PathChallenge { .. } => FrameType::PathChallenge,
            Frame::PathResponse { .. } => FrameType::PathResponse,
            Frame::ConnectionClose { .. } => FrameType::ConnectionClose,
            Frame::ConnectionCloseApp { .. } => FrameType::ConnectionCloseApp,
            Frame::HandshakeDone => FrameType::HandshakeDone,
        }
    }

    pub fn is_ack_eliciting(&self) -> bool {
        self.frame_type().is_ack_eliciting()
    }

    pub fn wire_size(&self) -> usize {
        let mut buffer = Vec::new();
        self.encode(&mut buffer).ok();
        buffer.len()
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_frame(self)?;
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure frame nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_frame_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecureFrameBlobMeta {
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
            magic = FRAME_BLOB_MAGIC,
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

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_frame_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureFrameBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_frame_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_frame_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure frame blob tag verification failed",
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
                    "frame raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure frame blob digest verification failed",
            ));
        }

        let frame = deserialize_frame(&raw_payload)?;
        Ok((meta, frame))
    }
}

pub fn select_secure_frame_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_frame(frame: &Frame, algorithm: CompressionAlgorithm) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
    frame.to_secure_blob(algorithm)
}

pub fn encode_secure_frame_auto(frame: &Frame, accept_encoding: &str) -> io::Result<(SecureFrameBlobMeta, Vec<u8>)> {
    frame.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_frame(data: &[u8]) -> io::Result<(SecureFrameBlobMeta, Frame)> {
    Frame::from_secure_blob(data)
}

fn serialize_frame(frame: &Frame) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    frame.encode(&mut buffer).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("frame encode failed: {}", e))
    })?;
    
    Ok(buffer)
}

fn deserialize_frame(raw_payload: &[u8]) -> io::Result<Frame> {
    let (frame, consumed) = Frame::parse(raw_payload).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("frame parse failed: {}", e))
    })?;
    
    if consumed != raw_payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame payload has trailing data: consumed {}, total {}",
                consumed,
                raw_payload.len()
            ),
        ));
    }

    Ok(frame)
}

fn compute_frame_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(FRAME_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(FRAME_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "frame secure blob header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "frame secure blob header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "frame secure blob missing header/body separator",
    ))
}

fn parse_secure_frame_meta(header: &str, body_len: usize) -> io::Result<SecureFrameBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != FRAME_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame secure blob magic",
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

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame secure header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", v.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();
                
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in frame blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size in frame blob")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in frame blob")
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureFrameBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in frame secure blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in frame secure blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in frame secure blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in frame secure blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in frame secure blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in frame secure blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameType::Padding => write!(f, "PADDING"),
            FrameType::Ping => write!(f, "PING"),
            FrameType::Ack => write!(f, "ACK"),
            FrameType::AckEcn => write!(f, "ACK_ECN"),
            FrameType::ResetStream => write!(f, "RESET_STREAM"),
            FrameType::StopSending => write!(f, "STOP_SENDING"),
            FrameType::Crypto => write!(f, "CRYPTO"),
            FrameType::NewToken => write!(f, "NEW_TOKEN"),
            FrameType::Stream => write!(f, "STREAM"),
            FrameType::MaxData => write!(f, "MAX_DATA"),
            FrameType::MaxStreamData => write!(f, "MAX_STREAM_DATA"),
            FrameType::MaxStreams => write!(f, "MAX_STREAMS"),
            FrameType::DataBlocked => write!(f, "DATA_BLOCKED"),
            FrameType::StreamDataBlocked => write!(f, "STREAM_DATA_BLOCKED"),
            FrameType::StreamsBlocked => write!(f, "STREAMS_BLOCKED"),
            FrameType::NewConnectionId => write!(f, "NEW_CONNECTION_ID"),
            FrameType::RetireConnectionId => write!(f, "RETIRE_CONNECTION_ID"),
            FrameType::PathChallenge => write!(f, "PATH_CHALLENGE"),
            FrameType::PathResponse => write!(f, "PATH_RESPONSE"),
            FrameType::ConnectionClose => write!(f, "CONNECTION_CLOSE"),
            FrameType::ConnectionCloseApp => write!(f, "CONNECTION_CLOSE_APP"),
            FrameType::HandshakeDone => write!(f, "HANDSHAKE_DONE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_ack_eliciting() {
        assert!(FrameType::Ping.is_ack_eliciting());
        assert!(FrameType::Stream.is_ack_eliciting());
        assert!(!FrameType::Ack.is_ack_eliciting());
        assert!(!FrameType::Padding.is_ack_eliciting());
    }

    #[test]
    fn test_ping_frame() {
        let frame = Frame::Ping;
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        assert_eq!(buf, vec![0x01]);

        let (decoded, len) = Frame::parse(&buf).unwrap();
        assert_eq!(len, 1);
        assert!(matches!(decoded, Frame::Ping));
    }

    #[test]
    fn test_padding_frame() {
        let frame = Frame::Padding { length: 5 };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_stream_frame() {
        let frame = Frame::Stream {
            stream_id: 4,
            offset: 100,
            data: vec![1, 2, 3, 4, 5],
            fin: true,
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let (decoded, _) = Frame::parse(&buf).unwrap();
        match decoded {
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => {
                assert_eq!(stream_id, 4);
                assert_eq!(offset, 100);
                assert_eq!(data, vec![1, 2, 3, 4, 5]);
                assert!(fin);
            }
            _ => panic!("Expected Stream frame"),
        }
    }

    #[test]
    fn test_crypto_frame() {
        let frame = Frame::Crypto {
            offset: 0,
            data: vec![0xaa, 0xbb, 0xcc],
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let (decoded, _) = Frame::parse(&buf).unwrap();
        match decoded {
            Frame::Crypto { offset, data } => {
                assert_eq!(offset, 0);
                assert_eq!(data, vec![0xaa, 0xbb, 0xcc]);
            }
            _ => panic!("Expected Crypto frame"),
        }
    }

    #[test]
    fn test_ack_frame() {
        let frame = Frame::Ack {
            largest_ack: 100,
            ack_delay: 25,
            ranges: vec![AckRange { gap: 0, len: 10 }],
            ecn_counts: None,
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let (decoded, _) = Frame::parse(&buf).unwrap();
        match decoded {
            Frame::Ack {
                largest_ack,
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                assert_eq!(largest_ack, 100);
                assert_eq!(ack_delay, 25);
                assert_eq!(ranges.len(), 1);
                assert!(ecn_counts.is_none());
            }
            _ => panic!("Expected Ack frame"),
        }
    }

    #[test]
    fn test_connection_close_frame() {
        let frame = Frame::ConnectionClose {
            error_code: ErrorCode::NoError,
            frame_type: Some(0x01),
            reason: b"test".to_vec(),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let (decoded, _) = Frame::parse(&buf).unwrap();
        match decoded {
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                assert_eq!(error_code, ErrorCode::NoError);
                assert_eq!(frame_type, Some(0x01));
                assert_eq!(reason, b"test");
            }
            _ => panic!("Expected ConnectionClose frame"),
        }
    }

    #[test]
    fn test_max_data_frame() {
        let frame = Frame::MaxData { max: 1000000 };

        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();

        let (decoded, _) = Frame::parse(&buf).unwrap();
        match decoded {
            Frame::MaxData { max } => {
                assert_eq!(max, 1000000);
            }
            _ => panic!("Expected MaxData frame"),
        }
    }

    #[test]
    fn test_secure_frame_roundtrip_identity() {
        let frame = Frame::Ping;
        let raw = serialize_frame(&frame).unwrap();

        let (meta, blob) = encode_secure_frame(&frame, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_decoded_meta, decoded) = decode_secure_frame(&blob).unwrap();
        let decoded_raw = serialize_frame(&decoded).unwrap();
        assert_eq!(decoded_raw, raw);
    }

    #[test]
    fn test_secure_frame_roundtrip_compressed() {
        let frame = Frame::Stream {
            stream_id: 8,
            offset: 55,
            data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            fin: false,
        };
        let raw = serialize_frame(&frame).unwrap();

        let (_meta, blob) = encode_secure_frame(&frame, CompressionAlgorithm::Gzip).unwrap();
        let (_decoded_meta, decoded) = decode_secure_frame(&blob).unwrap();
        let decoded_raw = serialize_frame(&decoded).unwrap();
        assert_eq!(decoded_raw, raw);
    }

    #[test]
    fn test_secure_frame_tamper_detection() {
        let frame = Frame::MaxData { max: 424242 };
        let (_meta, blob) = encode_secure_frame(&frame, CompressionAlgorithm::Identity).unwrap();

        let mut tampered = blob.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xAA;
        }

        assert!(decode_secure_frame(&tampered).is_err());
    }
}