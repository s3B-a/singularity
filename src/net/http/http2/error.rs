use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

impl ErrorCode {
    pub fn from_u32(code: u32) -> Self {
        match code {
            0x0 => ErrorCode::NoError,
            0x1 => ErrorCode::ProtocolError,
            0x2 => ErrorCode::InternalError,
            0x3 => ErrorCode::FlowControlError,
            0x4 => ErrorCode::SettingsTimeout,
            0x5 => ErrorCode::StreamClosed,
            0x6 => ErrorCode::FrameSizeError,
            0x7 => ErrorCode::RefusedStream,
            0x8 => ErrorCode::Cancel,
            0x9 => ErrorCode::CompressionError,
            0xa => ErrorCode::ConnectError,
            0xb => ErrorCode::EnhanceYourCalm,
            0xc => ErrorCode::InadequateSecurity,
            0xd => ErrorCode::Http11Required,
            _ => ErrorCode::InternalError,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::NoError => "NO_ERROR",
            ErrorCode::ProtocolError => "PROTOCOL_ERROR",
            ErrorCode::InternalError => "INTERNAL_ERROR",
            ErrorCode::FlowControlError => "FLOW_CONTROL_ERROR",
            ErrorCode::SettingsTimeout => "SETTINGS_TIMEOUT",
            ErrorCode::StreamClosed => "STREAM_CLOSED",
            ErrorCode::FrameSizeError => "FRAME_SIZE_ERROR",
            ErrorCode::RefusedStream => "REFUSED_STREAM",
            ErrorCode::Cancel => "CANCEL",
            ErrorCode::CompressionError => "COMPRESSION_ERROR",
            ErrorCode::ConnectError => "CONNECT_ERROR",
            ErrorCode::EnhanceYourCalm => "ENHANCE_YOUR_CALM",
            ErrorCode::InadequateSecurity => "INADEQUATE_SECURITY",
            ErrorCode::Http11Required => "HTTP_1_1_REQUIRED",
        }
    }
}

#[derive(Debug)]
pub enum Http2Error {
    Protocol(ErrorCode, String),
    Io(io::Error),
    ConnectionClosed,
    StreamNotFound(u32),
    InvalidStreamId(u32),
    InvalidFrameSize,
    CompressionFailed,
    DecompressionFailed,
}

impl fmt::Display for Http2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http2Error::Protocol(code, msg) => write!(f, "{}: {}", code.as_str(), msg),
            Http2Error::Io(e) => write!(f, "IO error: {}", e),
            Http2Error::ConnectionClosed => write!(f, "Connection closed"),
            Http2Error::StreamNotFound(id) => write!(f, "Stream {} not found", id),
            Http2Error::InvalidStreamId(id) => write!(f, "Invalid stream ID: {}", id),
            Http2Error::InvalidFrameSize => write!(f, "Invalid frame size"),
            Http2Error::CompressionFailed => write!(f, "Header compression failed"),
            Http2Error::DecompressionFailed => write!(f, "Header decompression failed"),
        }
    }
}

impl std::error::Error for Http2Error {}

impl From<io::Error> for Http2Error {
    fn from(err: io::Error) -> Self {
        Http2Error::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, Http2Error>;