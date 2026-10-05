use super::error::Result;
use super::{decode_varint, encode_varint};

pub const H3_FRAME_DATA: u64 = 0x00;
pub const H3_FRAME_HEADERS: u64 = 0x01;
pub const H3_FRAME_SETTINGS: u64 = 0x04;

pub const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
pub const H3_STREAM_TYPE_PUSH: u64 = 0x01;
pub const H3_STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const H3_STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

pub fn encode_stream_type(stream_type: u64) -> Vec<u8> {
    encode_varint(stream_type)
}

pub fn encode_settings_frame(settings: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (id, value) in settings {
        payload.extend_from_slice(&encode_varint(*id));
        payload.extend_from_slice(&encode_varint(*value));
    }

    let mut frame = Vec::new();
    frame.extend_from_slice(&encode_varint(H3_FRAME_SETTINGS));
    frame.extend_from_slice(&encode_varint(payload.len() as u64));
    frame.extend_from_slice(&payload);
    frame
}

pub fn parse_h3_frames(buf: &[u8]) -> Result<(Vec<(u64, Vec<u8>)>, usize)> {
    let mut offset = 0;
    let mut frames = Vec::new();
    loop {
        let (frame_type, type_len) = match decode_varint(&buf[offset..]) {
            Ok(v) => v,
            Err(_) => break,
        };

        let (length, length_len) = match decode_varint(&buf[offset + type_len..]) {
            Ok(v) => v,
            Err(_) => break,
        };

        let header_len = type_len + length_len;
        let total = header_len + length as usize;
        if offset + total > buf.len() {
            break;
        }

        let payload = buf[offset + header_len..offset + total].to_vec();
        frames.push((frame_type, payload));
        offset += total;
    }

    Ok((frames, offset))
}

pub fn parse_settings_payload(payload: &[u8]) -> Result<Vec<(u64, u64)>> {
    let mut offset = 0;
    let mut settings = Vec::new();
    while offset < payload.len() {
        let (id, id_len) = decode_varint(&payload[offset..])?;
        offset += id_len;

        let (value, value_len) = decode_varint(&payload[offset..])?;
        offset += value_len;

        settings.push((id, value));
    }

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_roundtrip() {
        let settings = vec![(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096), (SETTINGS_QPACK_BLOCKED_STREAMS, 100)];
        let encoded = encode_settings_frame(&settings);

        let (frames, consumed) = parse_h3_frames(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, H3_FRAME_SETTINGS);

        let decoded = parse_settings_payload(&frames[0].1).unwrap();
        assert_eq!(decoded, settings);
    }

    #[test]
    fn test_partial_frame_not_consumed() {
        let settings = vec![(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096)];
        let encoded = encode_settings_frame(&settings);

        let partial = &encoded[..encoded.len() - 1];
        let (frames, consumed) = parse_h3_frames(partial).unwrap();
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_stream_type_bytes() {
        assert_eq!(encode_stream_type(H3_STREAM_TYPE_CONTROL), vec![0x00]);
        assert_eq!(encode_stream_type(H3_STREAM_TYPE_QPACK_ENCODER), vec![0x02]);
        assert_eq!(encode_stream_type(H3_STREAM_TYPE_QPACK_DECODER), vec![0x03]);
    }
}
