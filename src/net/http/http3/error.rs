use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http3Error {
    NoError,
    GeneralProtocolError,
    InternalError,
    StreamCreationError,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    ExcessiveLoad,
    IdError,
    SettingsError,
    MissingSettings,
    RequestRejected,
    RequestCancelled,
    RequestIncomplete,
    MessageError,
    ConnectError,
    VersionFallback,
    QpackDecompressionFailure,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
}

impl Http3Error {
    pub fn to_code(&self) -> u64 {
        match self {
            Http3Error::NoError => 0x100,
            Http3Error::GeneralProtocolError => 0x101,
            Http3Error::InternalError => 0x102,
            Http3Error::StreamCreationError => 0x103,
            Http3Error::ClosedCriticalStream => 0x104,
            Http3Error::FrameUnexpected => 0x105,
            Http3Error::FrameError => 0x106,
            Http3Error::ExcessiveLoad => 0x107,
            Http3Error::IdError => 0x108,
            Http3Error::SettingsError => 0x109,
            Http3Error::MissingSettings => 0x10a,
            Http3Error::RequestRejected => 0x10b,
            Http3Error::RequestCancelled => 0x10c,
            Http3Error::RequestIncomplete => 0x10d,
            Http3Error::MessageError => 0x10e,
            Http3Error::ConnectError => 0x10f,
            Http3Error::VersionFallback => 0x110,
            Http3Error::QpackDecompressionFailure => 0x200,
            Http3Error::QpackEncoderStreamError => 0x201,
            Http3Error::QpackDecoderStreamError => 0x202,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x100 => Some(Http3Error::NoError),
            0x101 => Some(Http3Error::GeneralProtocolError),
            0x102 => Some(Http3Error::InternalError),
            0x103 => Some(Http3Error::StreamCreationError),
            0x104 => Some(Http3Error::ClosedCriticalStream),
            0x105 => Some(Http3Error::FrameUnexpected),
            0x106 => Some(Http3Error::FrameError),
            0x107 => Some(Http3Error::ExcessiveLoad),
            0x108 => Some(Http3Error::IdError),
            0x109 => Some(Http3Error::SettingsError),
            0x10a => Some(Http3Error::MissingSettings),
            0x10b => Some(Http3Error::RequestRejected),
            0x10c => Some(Http3Error::RequestCancelled),
            0x10d => Some(Http3Error::RequestIncomplete),
            0x10e => Some(Http3Error::MessageError),
            0x10f => Some(Http3Error::ConnectError),
            0x110 => Some(Http3Error::VersionFallback),
            0x200 => Some(Http3Error::QpackDecompressionFailure),
            0x201 => Some(Http3Error::QpackEncoderStreamError),
            0x202 => Some(Http3Error::QpackDecoderStreamError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ErrorCode {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError(u8),
}

impl ErrorCode {
    pub fn to_wire(&self) -> u64 {
        match self {
            ErrorCode::NoError => 0x00,
            ErrorCode::InternalError => 0x01,
            ErrorCode::ConnectionRefused => 0x02,
            ErrorCode::FlowControlError => 0x03,
            ErrorCode::StreamLimitError => 0x04,
            ErrorCode::StreamStateError => 0x05,
            ErrorCode::FinalSizeError => 0x06,
            ErrorCode::FrameEncodingError => 0x07,
            ErrorCode::TransportParameterError => 0x08,
            ErrorCode::ConnectionIdLimitError => 0x09,
            ErrorCode::ProtocolViolation => 0x0a,
            ErrorCode::InvalidToken => 0x0b,
            ErrorCode::ApplicationError => 0x0c,
            ErrorCode::CryptoBufferExceeded => 0x0d,
            ErrorCode::KeyUpdateError => 0x0e,
            ErrorCode::AeadLimitReached => 0x0f,
            ErrorCode::NoViablePath => 0x10,
            ErrorCode::CryptoError(alert) => 0x0100 + (*alert as u64),
        }
    }

    pub fn from_wire(code: u64) -> Self {
        match code {
            0x00 => ErrorCode::NoError,
            0x01 => ErrorCode::InternalError,
            0x02 => ErrorCode::ConnectionRefused,
            0x03 => ErrorCode::FlowControlError,
            0x04 => ErrorCode::StreamLimitError,
            0x05 => ErrorCode::StreamStateError,
            0x06 => ErrorCode::FinalSizeError,
            0x07 => ErrorCode::FrameEncodingError,
            0x08 => ErrorCode::TransportParameterError,
            0x09 => ErrorCode::ConnectionIdLimitError,
            0x0a => ErrorCode::ProtocolViolation,
            0x0b => ErrorCode::InvalidToken,
            0x0c => ErrorCode::ApplicationError,
            0x0d => ErrorCode::CryptoBufferExceeded,
            0x0e => ErrorCode::KeyUpdateError,
            0x0f => ErrorCode::AeadLimitReached,
            0x10 => ErrorCode::NoViablePath,
            0x0100..=0x01ff => ErrorCode::CryptoError((code - 0x0100) as u8),
            _ => ErrorCode::InternalError,
        }
    }

    pub fn is_crypto_error(&self) -> bool {
        matches!(self, ErrorCode::CryptoError(_))
    }

    pub fn tls_alert(&self) -> Option<u8> {
        match self {
            ErrorCode::CryptoError(alert) => Some(*alert),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Transport(ErrorCode, String),
    Http3(Http3Error, String),
    BufferTooShort,
    InvalidPacket,
    InvalidFrame,
    InvalidStreamState,
    StreamNotFound,
    ConnectionClosed,
    Timeout,
    Tls(String),
    Crypto(String),
    FlowControl(String),
    StreamLimit,
    Done,
    WouldBlock,
    InvalidOperation(String),
    Config(String),
    ProtocolViolation(String),
    VersionNegotiation,
    StatelessReset,
    KeyUnavailable,
    UnknownConnectionId,
    Qpack(String),
    CryptoError,
}

impl Error {
    pub fn transport(code: ErrorCode, msg: impl Into<String>) -> Self {
        Error::Transport(code, msg.into())
    }

    pub fn http3(code: Http3Error, msg: impl Into<String>) -> Self {
        Error::Http3(code, msg.into())
    }

    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn flow_control(msg: impl Into<String>) -> Self {
        Error::FlowControl(msg.into())
    }

    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Error::Transport(_, _)
                | Error::ConnectionClosed
                | Error::Timeout
                | Error::Tls(_)
                | Error::ProtocolViolation(_)
                | Error::VersionNegotiation
                | Error::StatelessReset
        )
    }

    pub fn is_application_error(&self) -> bool {
        matches!(self, Error::Http3(_, _))
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(self, Error::WouldBlock | Error::Done)
    }
}

impl fmt::Display for Http3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http3Error::NoError => write!(f, "No error"),
            Http3Error::GeneralProtocolError => write!(f, "General protocol error"),
            Http3Error::InternalError => write!(f, "Internal error"),
            Http3Error::StreamCreationError => write!(f, "Stream creation error"),
            Http3Error::ClosedCriticalStream => write!(f, "Closed critical stream"),
            Http3Error::FrameUnexpected => write!(f, "Frame unexpected"),
            Http3Error::FrameError => write!(f, "Frame error"),
            Http3Error::ExcessiveLoad => write!(f, "Excessive load"),
            Http3Error::IdError => write!(f, "ID error"),
            Http3Error::SettingsError => write!(f, "Settings error"),
            Http3Error::MissingSettings => write!(f, "Missing settings"),
            Http3Error::RequestRejected => write!(f, "Request rejected"),
            Http3Error::RequestCancelled => write!(f, "Request cancelled"),
            Http3Error::RequestIncomplete => write!(f, "Request incomplete"),
            Http3Error::MessageError => write!(f, "Message error"),
            Http3Error::ConnectError => write!(f, "Connect error"),
            Http3Error::VersionFallback => write!(f, "Version fallback"),
            Http3Error::QpackDecompressionFailure => write!(f, "QPACK decompression failed"),
            Http3Error::QpackEncoderStreamError => write!(f, "QPACK encoder stream error"),
            Http3Error::QpackDecoderStreamError => write!(f, "QPACK decoder stream error"),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::NoError => write!(f, "No error"),
            ErrorCode::InternalError => write!(f, "Internal error"),
            ErrorCode::ConnectionRefused => write!(f, "Connection refused"),
            ErrorCode::FlowControlError => write!(f, "Flow control error"),
            ErrorCode::StreamLimitError => write!(f, "Stream limit error"),
            ErrorCode::StreamStateError => write!(f, "Stream state error"),
            ErrorCode::FinalSizeError => write!(f, "Final size error"),
            ErrorCode::FrameEncodingError => write!(f, "Frame encoding error"),
            ErrorCode::TransportParameterError => write!(f, "Transport parameter error"),
            ErrorCode::ConnectionIdLimitError => write!(f, "Connection ID limit error"),
            ErrorCode::ProtocolViolation => write!(f, "Protocol violation"),
            ErrorCode::InvalidToken => write!(f, "Invalid token"),
            ErrorCode::ApplicationError => write!(f, "Application error"),
            ErrorCode::CryptoBufferExceeded => write!(f, "Crypto buffer exceeded"),
            ErrorCode::KeyUpdateError => write!(f, "Key update error"),
            ErrorCode::AeadLimitReached => write!(f, "AEAD limit reached"),
            ErrorCode::NoViablePath => write!(f, "No viable path"),
            ErrorCode::CryptoError(alert) => write!(f, "Crypto error (TLS alert: {})", alert),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Transport(code, msg) => write!(f, "Transport error {}: {}", code, msg),
            Error::Http3(code, msg) => write!(f, "HTTP/3 error {}: {}", code, msg),
            Error::BufferTooShort => write!(f, "Buffer too short"),
            Error::InvalidPacket => write!(f, "Invalid packet"),
            Error::InvalidFrame => write!(f, "Invalid frame"),
            Error::InvalidStreamState => write!(f, "Invalid stream state"),
            Error::StreamNotFound => write!(f, "Stream not found"),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::Timeout => write!(f, "Connection timeout"),
            Error::Tls(msg) => write!(f, "TLS error: {}", msg),
            Error::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Error::FlowControl(msg) => write!(f, "Flow control error: {}", msg),
            Error::StreamLimit => write!(f, "Stream limit exceeded"),
            Error::Done => write!(f, "Done"),
            Error::WouldBlock => write!(f, "Would block"),
            Error::InvalidOperation(msg) => write!(f, "Invalid operation: {}", msg),
            Error::Config(msg) => write!(f, "Configuration error: {}", msg),
            Error::ProtocolViolation(msg) => write!(f, "Protocol violation: {}", msg),
            Error::VersionNegotiation => write!(f, "Version negotiation failed"),
            Error::StatelessReset => write!(f, "Stateless reset"),
            Error::KeyUnavailable => write!(f, "Encryption key unavailable"),
            Error::UnknownConnectionId => write!(f, "Unknown connection ID"),
            Error::Qpack(msg) => write!(f, "QPACK error: {}", msg),
            Error::CryptoError => write!(f, "Cryptographic error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_error_codes() {
        assert_eq!(Http3Error::NoError.to_code(), 0x100);
        assert_eq!(Http3Error::GeneralProtocolError.to_code(), 0x101);
        assert_eq!(Http3Error::QpackDecompressionFailure.to_code(), 0x200);
    }

    #[test]
    fn test_http3_error_from_code() {
        assert_eq!(Http3Error::from_code(0x100), Some(Http3Error::NoError));
        assert_eq!(
            Http3Error::from_code(0x101),
            Some(Http3Error::GeneralProtocolError)
        );
        assert_eq!(Http3Error::from_code(0x999), None);
    }

    #[test]
    fn test_error_code_wire_format() {
        assert_eq!(ErrorCode::NoError.to_wire(), 0x00);
        assert_eq!(ErrorCode::InternalError.to_wire(), 0x01);
        assert_eq!(ErrorCode::CryptoError(42).to_wire(), 0x0100 + 42);
    }

    #[test]
    fn test_error_code_from_wire() {
        assert_eq!(ErrorCode::from_wire(0x00), ErrorCode::NoError);
        assert_eq!(ErrorCode::from_wire(0x01), ErrorCode::InternalError);
        assert_eq!(ErrorCode::from_wire(0x012a), ErrorCode::CryptoError(42));
    }

    #[test]
    fn test_crypto_error_detection() {
        assert!(ErrorCode::CryptoError(1).is_crypto_error());
        assert!(!ErrorCode::NoError.is_crypto_error());
        assert_eq!(ErrorCode::CryptoError(42).tls_alert(), Some(42));
        assert_eq!(ErrorCode::NoError.tls_alert(), None);
    }

    #[test]
    fn test_error_classification() {
        let err = Error::Transport(ErrorCode::InternalError, "test".to_string());
        assert!(err.is_connection_error());
        assert!(!err.is_application_error());
        assert!(!err.is_recoverable());

        let err = Error::Http3(Http3Error::FrameError, "test".to_string());
        assert!(!err.is_connection_error());
        assert!(err.is_application_error());

        let err = Error::WouldBlock;
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = Error::Transport(ErrorCode::FlowControlError, "overflow".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Flow control error"));
        assert!(display.contains("overflow"));
    }
}