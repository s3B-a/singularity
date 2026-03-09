use super::error::{Error, ErrorCode, Result};
use super::{decode_varint, encode_varint, ConnectionId};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    Settings = 0x20,
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

    Settings {
        settings: Vec<(u64, u64)>,
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
            FrameType::Settings => {
                let mut settings = Vec::new();
                while offset < data.len() {
                    let (id, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    let (value, len) = decode_varint(&data[offset..])?;
                    offset += len;

                    settings.push((id, value));
                }

                Ok((Frame::Settings { settings }, offset))
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
            Frame::Settings { settings } => {
                buffer.push(0x20);
                for (id, value) in settings {
                    buffer.extend_from_slice(&encode_varint(*id));
                    buffer.extend_from_slice(&encode_varint(*value));
                }
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
            Frame::Settings { .. } => FrameType::Settings,
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
            FrameType::Settings => write!(f, "SETTINGS"),
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
}