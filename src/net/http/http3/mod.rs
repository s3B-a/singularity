pub mod quic;
pub mod qpack;
pub mod connection;
pub mod frame;
pub mod stream;
pub mod congestion;
pub mod recovery;
pub mod crypto;
pub mod packet;
pub mod error;
pub mod quic_tls;

pub use connection::{Http3Connection, ConnectionStats};
pub use error::{Http3Error, Error, ErrorCode, Result};
pub use frame::{Frame, FrameType, AckRange};
pub use stream::{Stream, StreamType, StreamId, StreamState};
pub use packet::{Packet, PacketHeader, PacketType, PacketNumber, PacketNumberSpace};
pub use congestion::{CongestionController, CongestionAlgorithm, CongestionState};
pub use recovery::{RecoveryManager, RecoveryStatus, SentPacket};
pub use crypto::{CryptoState, EncryptionLevel, CryptoKeys};
pub use qpack::{QpackEncoder, QpackDecoder};
pub use quic::{QuicClient, QuicServer, QuicEndpoint, QuicConnectionManager, QuicStats, StreamEvent};
pub use quic_tls::{QuicTlsState, CryptoAction};

use std::net::SocketAddr;
use std::time::Duration;

pub const HTTP3_VERSION: u32 = 0x00000001;
pub const ALPN_H3: &[u8] = b"h3";
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_UDP_PAYLOAD_SIZE: usize = 1350;
pub const INITIAL_MAX_DATA: u64 = 10_000_000;
pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 1_000_000;
pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 1_000_000;
pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 1_000_000;
pub const INITIAL_MAX_STREAMS_BIDI: u64 = 100;
pub const INITIAL_MAX_STREAMS_UNI: u64 = 100;
pub const ACK_DELAY_EXPONENT: u8 = 3;
pub const MAX_ACK_DELAY: u64 = 25;
pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

#[derive(Debug, Clone)]
pub struct Config {
    pub max_idle_timeout: Duration,
    pub max_udp_payload_size: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u8,
    pub max_ack_delay: Duration,
    pub active_connection_id_limit: u64,
    pub enable_early_data: bool,
    pub enable_migration: bool,
    pub congestion_control_algorithm: CongestionAlgorithm,
    pub enable_ecn: bool,
    pub max_send_burst: usize,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_udp_payload_size: MAX_UDP_PAYLOAD_SIZE,
            initial_max_data: INITIAL_MAX_DATA,
            initial_max_stream_data_bidi_local: INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            initial_max_stream_data_bidi_remote: INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            initial_max_stream_data_uni: INITIAL_MAX_STREAM_DATA_UNI,
            initial_max_streams_bidi: INITIAL_MAX_STREAMS_BIDI,
            initial_max_streams_uni: INITIAL_MAX_STREAMS_UNI,
            ack_delay_exponent: ACK_DELAY_EXPONENT,
            max_ack_delay: Duration::from_millis(MAX_ACK_DELAY),
            active_connection_id_limit: ACTIVE_CONNECTION_ID_LIMIT,
            enable_early_data: false,
            enable_migration: true,
            congestion_control_algorithm: CongestionAlgorithm::Cubic,
            enable_ecn: true,
            max_send_burst: 10,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshake,
    Active,
    Closing,
    Draining,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    data: Vec<u8>,
}

impl ConnectionId {
    pub fn new(data: Vec<u8>) -> Self {
        assert!(data.len() <= 20, "Connection ID too long");
        Self { data }
    }
    
    pub fn generate() -> Result<Self> {
        use crate::crypto::random;
        let len = 8;
        let data = random::generate_random(len)
            .map_err(|_| Error::CryptoError)?;
        Ok(Self::new(data))
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.data {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TransportParams {
    pub original_destination_connection_id: Option<ConnectionId>,
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub preferred_address: Option<PreferredAddress>,
    pub active_conn_id_limit: u64,
    pub initial_source_connection_id: Option<ConnectionId>,
    pub retry_source_connection_id: Option<ConnectionId>,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: DEFAULT_IDLE_TIMEOUT.as_millis() as u64,
            stateless_reset_token: None,
            max_udp_payload_size: MAX_UDP_PAYLOAD_SIZE as u64,
            initial_max_data: INITIAL_MAX_DATA,
            initial_max_stream_data_bidi_local: INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            initial_max_stream_data_bidi_remote: INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            initial_max_stream_data_uni: INITIAL_MAX_STREAM_DATA_UNI,
            initial_max_streams_bidi: INITIAL_MAX_STREAMS_BIDI,
            initial_max_streams_uni: INITIAL_MAX_STREAMS_UNI,
            ack_delay_exponent: ACK_DELAY_EXPONENT as u64,
            max_ack_delay: MAX_ACK_DELAY,
            disable_active_migration: false,
            preferred_address: None,
            active_conn_id_limit: ACTIVE_CONNECTION_ID_LIMIT,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreferredAddress {
    pub ipv4_address: Option<SocketAddr>,
    pub ipv6_address: Option<SocketAddr>,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: [u8; 16],
}

pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        vec![
            (0x40 | (value >> 8)) as u8,
            (value & 0xFF) as u8,
        ]
    } else if value < 1073741824 {
        vec![
            (0x80 | (value >> 24)) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]
    } else {
        vec![
            (0xC0 | (value >> 56)) as u8,
            ((value >> 48) & 0xFF) as u8,
            ((value >> 40) & 0xFF) as u8,
            ((value >> 32) & 0xFF) as u8,
            ((value >> 24) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]
    }
}

pub fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Err(Error::BufferTooShort);
    }
    
    let first = data[0];
    let prefix = first >> 6;
    match prefix {
        0 => {
            Ok((first as u64, 1))
        }
        1 => {
            if data.len() < 2 {
                return Err(Error::BufferTooShort);
            }
            let value = (((first & 0x3F) as u64) << 8) | (data[1] as u64);
            Ok((value, 2))
        }
        2 => {
            if data.len() < 4 {
                return Err(Error::BufferTooShort);
            }
            let value = (((first & 0x3F) as u64) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | (data[3] as u64);
            Ok((value, 4))
        }
        3 => {
            if data.len() < 8 {
                return Err(Error::BufferTooShort);
            }
            let value = (((first & 0x3F) as u64) << 56)
                | ((data[1] as u64) << 48)
                | ((data[2] as u64) << 40)
                | ((data[3] as u64) << 32)
                | ((data[4] as u64) << 24)
                | ((data[5] as u64) << 16)
                | ((data[6] as u64) << 8)
                | (data[7] as u64);
            Ok((value, 8))
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.max_udp_payload_size, MAX_UDP_PAYLOAD_SIZE);
        assert_eq!(config.initial_max_data, INITIAL_MAX_DATA);
    }

    #[test]
    fn test_connection_id_generate() {
        let cid = ConnectionId::generate().unwrap();
        assert_eq!(cid.len(), 8);
        assert!(!cid.is_empty());
    }

    #[test]
    fn test_connection_id_display() {
        let cid = ConnectionId::new(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let display = format!("{}", cid);
        assert_eq!(display, "aabbccdd");
    }

    #[test]
    fn test_encode_varint_one_byte() {
        let encoded = encode_varint(42);
        assert_eq!(encoded, vec![42]);
    }

    #[test]
    fn test_encode_varint_two_bytes() {
        let encoded = encode_varint(1000);
        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0] & 0xC0, 0x40);
    }

    #[test]
    fn test_encode_varint_four_bytes() {
        let encoded = encode_varint(100000);
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0] & 0xC0, 0x80);
    }

    #[test]
    fn test_encode_varint_eight_bytes() {
        let encoded = encode_varint(2000000000);
        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[0] & 0xC0, 0xC0);
    }

    #[test]
    fn test_decode_varint_one_byte() {
        let data = vec![42];
        let (value, len) = decode_varint(&data).unwrap();
        assert_eq!(value, 42);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_decode_varint_two_bytes() {
        let encoded = encode_varint(1000);
        let (value, len) = decode_varint(&encoded).unwrap();
        assert_eq!(value, 1000);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_encode_decode_varint_roundtrip() {
        let test_values = vec![0, 63, 64, 16383, 16384, 1073741823, 1073741824, u64::MAX / 2];
        
        for original in test_values {
            let encoded = encode_varint(original);
            let (decoded, _) = decode_varint(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_decode_varint_buffer_too_short() {
        let data = vec![0x40];
        let result = decode_varint(&data);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::BufferTooShort)));
    }

    #[test]
    fn test_transport_params_default() {
        let params = TransportParams::default();
        assert_eq!(params.max_udp_payload_size, MAX_UDP_PAYLOAD_SIZE as u64);
        assert_eq!(params.initial_max_data, INITIAL_MAX_DATA);
    }

    #[test]
    fn test_role_enum() {
        let client = Role::Client;
        let server = Role::Server;
        assert_ne!(client, server);
    }

    #[test]
    fn test_connection_state_enum() {
        assert_eq!(ConnectionState::Handshake, ConnectionState::Handshake);
        assert_ne!(ConnectionState::Active, ConnectionState::Closed);
    }
}