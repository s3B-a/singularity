use std::io::{self, Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl FrameType {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x0 => Some(FrameType::Data),
            0x1 => Some(FrameType::Headers),
            0x2 => Some(FrameType::Priority),
            0x3 => Some(FrameType::RstStream),
            0x4 => Some(FrameType::Settings),
            0x5 => Some(FrameType::PushPromise),
            0x6 => Some(FrameType::Ping),
            0x7 => Some(FrameType::GoAway),
            0x8 => Some(FrameType::WindowUpdate),
            0x9 => Some(FrameType::Continuation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;

    pub fn new(flags: u8) -> Self {
        FrameFlags(flags)
    }

    pub fn empty() -> Self {
        FrameFlags(0)
    }

    pub fn has(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    pub fn value(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub stream_id: u32,
}

impl FrameHeader {
    pub const SIZE: usize = 9;
    pub const MAX_PAYLOAD_SIZE: u32 = 16777215; // 2^24 - 1

    pub fn new(frame_type: FrameType, flags: u8, stream_id: u32, length: u32) -> Self {
        Self {
            length,
            frame_type,
            flags: FrameFlags::new(flags),
            stream_id: stream_id & 0x7FFFFFFF,
        }
    }

    pub fn parse(bytes: &[u8; 9]) -> io::Result<Self> {
        let length = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        let frame_type = FrameType::from_u8(bytes[3])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown frame type"))?;
        let flags = FrameFlags::new(bytes[4]);
        let stream_id = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7FFFFFFF;

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    pub fn serialize(&self) -> [u8; 9] {
        let length_bytes = self.length.to_be_bytes();
        let stream_id_bytes = self.stream_id.to_be_bytes();

        [
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
            self.frame_type as u8,
            self.flags.0,
            stream_id_bytes[0],
            stream_id_bytes[1],
            stream_id_bytes[2],
            stream_id_bytes[3],
        ]
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: FrameType, flags: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        let length = payload.len() as u32;
        Self {
            header: FrameHeader::new(frame_type, flags, stream_id, length),
            payload,
        }
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header_bytes = [0u8; 9];
        reader.read_exact(&mut header_bytes)?;
        let header = FrameHeader::parse(&header_bytes)?;

        if header.length > FrameHeader::MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame payload too large",
            ));
        }

        let mut payload = vec![0u8; header.length as usize];
        reader.read_exact(&mut payload)?;

        Ok(Self { header, payload })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.header.serialize())?;
        writer.write_all(&self.payload)?;
        Ok(())
    }

    pub fn data(stream_id: u32, data: Vec<u8>, end_stream: bool) -> Self {
        let flags = if end_stream { FrameFlags::END_STREAM } else { 0 };
        Self::new(FrameType::Data, flags, stream_id, data)
    }

    pub fn headers(stream_id: u32, headers: Vec<u8>, end_headers: bool, end_stream: bool) -> Self {
        let mut flags = 0;
        if end_headers {
            flags |= FrameFlags::END_HEADERS;
        }
        if end_stream {
            flags |= FrameFlags::END_STREAM;
        }
        Self::new(FrameType::Headers, flags, stream_id, headers)
    }

    pub fn priority(stream_id: u32, exclusive: bool, dependency: u32, weight: u8) -> Self {
        let dep = if exclusive {
            dependency | 0x80000000
        } else {
            dependency
        };
        let mut payload = dep.to_be_bytes().to_vec();
        payload.push(weight);
        Self::new(FrameType::Priority, 0, stream_id, payload)
    }

    pub fn rst_stream(stream_id: u32, error_code: u32) -> Self {
        Self::new(FrameType::RstStream, 0, stream_id, error_code.to_be_bytes().to_vec())
    }

    pub fn settings(settings: Vec<(u16, u32)>) -> Self {
        let mut payload = Vec::new();
        for (id, value) in settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        Self::new(FrameType::Settings, 0, 0, payload)
    }

    pub fn settings_ack() -> Self {
        Self::new(FrameType::Settings, FrameFlags::ACK, 0, Vec::new())
    }

    pub fn push_promise(stream_id: u32, promised_stream_id: u32, headers: Vec<u8>, end_headers: bool) -> Self {
        let flags = if end_headers { FrameFlags::END_HEADERS } else { 0 };
        let mut payload = promised_stream_id.to_be_bytes().to_vec();
        payload.extend(headers);
        Self::new(FrameType::PushPromise, flags, stream_id, payload)
    }

    pub fn ping(data: [u8; 8], ack: bool) -> Self {
        let flags = if ack { FrameFlags::ACK } else { 0 };
        Self::new(FrameType::Ping, flags, 0, data.to_vec())
    }

    pub fn goaway(last_stream_id: u32, error_code: u32, debug_data: Vec<u8>) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&last_stream_id.to_be_bytes());
        payload.extend_from_slice(&error_code.to_be_bytes());
        payload.extend_from_slice(&debug_data);
        Self::new(FrameType::GoAway, 0, 0, payload)
    }

    pub fn window_update(stream_id: u32, increment: u32) -> Self {
        let payload = (increment & 0x7FFFFFFF).to_be_bytes().to_vec();
        Self::new(FrameType::WindowUpdate, 0, stream_id, payload)
    }

    pub fn continuation(stream_id: u32, headers: Vec<u8>, end_headers: bool) -> Self {
        let flags = if end_headers { FrameFlags::END_HEADERS } else { 0 };
        Self::new(FrameType::Continuation, flags, stream_id, headers)
    }
}