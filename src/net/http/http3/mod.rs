pub mod quic;
pub mod qpack;
pub mod connection;
pub mod frame;
pub mod h3_frame;
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

use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

const HTTP3_CONFIG_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_CONFIG_BLOB_V1";
const HTTP3_CONFIG_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_CONFIG_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureHttp3ConfigBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

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
    pub enable_retry_validation: bool,
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
            enable_retry_validation: false,
        }
    }
}

impl Config {
    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp3ConfigBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_http3_config(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure http3-config nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_http3_config_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let nonce_b64 = pem::encode(&nonce);
        let digest_b64 = pem::encode(&digest);
        let tag_b64 = pem::encode(&tag);
        let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = HTTP3_CONFIG_BLOB_MAGIC,
            encoding = selected_algorithm.content_encoding(),
            nonce = nonce_b64,
            digest = digest_b64,
            tag = tag_b64,
            raw_size = raw_payload.len(),
            encoded_size = encoded_payload.len(),
            issued_at = issued_at_unix,
        );

        let mut blob = header.into_bytes();
        blob.extend_from_slice(&encoded_payload);

        Ok((
            SecureHttp3ConfigBlobMeta {
                algorithm: selected_algorithm,
                nonce_b64,
                digest_b64,
                tag_b64,
                raw_size: raw_payload.len(),
                encoded_size: encoded_payload.len(),
                issued_at_unix,
            },
            blob,
        ))
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureHttp3ConfigBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_http3_config_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureHttp3ConfigBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_http3_config_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid http3-config nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid http3-config digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid http3-config tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http3-config digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_http3_config_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure http3-config blob HMAC mismatch",
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
                    "http3-config raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure http3-config blob digest mismatch",
            ));
        }

        let config = deserialize_http3_config(&raw_payload)?;
        Ok((meta, config))
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
        let len = 8;
        let data = random::generate_random(len).map_err(|_| Error::CryptoError)?;
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

pub fn select_secure_http3_config_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_http3_config(config: &Config, algorithm: CompressionAlgorithm) -> io::Result<(SecureHttp3ConfigBlobMeta, Vec<u8>)> {
    config.to_secure_blob(algorithm)
}

pub fn encode_secure_http3_config_auto(config: &Config, accept_encoding: &str) -> io::Result<(SecureHttp3ConfigBlobMeta, Vec<u8>)> {
    config.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_http3_config(data: &[u8]) -> io::Result<(SecureHttp3ConfigBlobMeta, Config)> {
    Config::from_secure_blob(data)
}

fn serialize_http3_config(config: &Config) -> Vec<u8> {
    format!(
        "max-idle-timeout-ms={max_idle}\nmax-udp-payload-size={udp_payload}\ninitial-max-data={max_data}\ninitial-max-stream-data-bidi-local={bidi_local}\ninitial-max-stream-data-bidi-remote={bidi_remote}\ninitial-max-stream-data-uni={uni}\ninitial-max-streams-bidi={streams_bidi}\ninitial-max-streams-uni={streams_uni}\nack-delay-exponent={ack_exp}\nmax-ack-delay-ms={max_ack_delay}\nactive-connection-id-limit={active_cid_limit}\nenable-early-data={early_data}\nenable-migration={migration}\ncongestion-control-algorithm={congestion}\nenable-ecn={ecn}\nmax-send-burst={send_burst}\nqpack-max-table-capacity={qpack_cap}\nqpack-blocked-streams={qpack_blocked}\nenable-retry-validation={retry_validation}\n",
        max_idle = config.max_idle_timeout.as_millis(),
        udp_payload = config.max_udp_payload_size,
        max_data = config.initial_max_data,
        bidi_local = config.initial_max_stream_data_bidi_local,
        bidi_remote = config.initial_max_stream_data_bidi_remote,
        uni = config.initial_max_stream_data_uni,
        streams_bidi = config.initial_max_streams_bidi,
        streams_uni = config.initial_max_streams_uni,
        ack_exp = config.ack_delay_exponent,
        max_ack_delay = config.max_ack_delay.as_millis(),
        active_cid_limit = config.active_connection_id_limit,
        early_data = if config.enable_early_data { "1" } else { "0" },
        migration = if config.enable_migration { "1" } else { "0" },
        congestion = congestion_algorithm_as_str(config.congestion_control_algorithm),
        ecn = if config.enable_ecn { "1" } else { "0" },
        send_burst = config.max_send_burst,
        qpack_cap = config.qpack_max_table_capacity,
        qpack_blocked = config.qpack_blocked_streams,
        retry_validation = if config.enable_retry_validation { "1" } else { "0" },
    )
    .into_bytes()
}

fn deserialize_http3_config(raw_payload: &[u8]) -> io::Result<Config> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secure http3-config payload is not valid UTF-8",
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
                format!("invalid http3-config payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let get_required = |k: &str| -> io::Result<&str> {
        map.get(k).map(String::as_str).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing required config field '{}'", k),
            )
        })
    };

    let max_idle_timeout_ms = get_required("max-idle-timeout-ms")?.parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid max-idle-timeout-ms"))?;

    let max_ack_delay_ms = get_required("max-ack-delay-ms")?.parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid max-ack-delay-ms"))?;

    let config = Config {
        max_idle_timeout: Duration::from_millis(max_idle_timeout_ms),
        max_udp_payload_size: get_required("max-udp-payload-size")?.parse::<usize>().map_err(
            |_| io::Error::new(io::ErrorKind::InvalidData, "invalid max-udp-payload-size"),
        )?,
        initial_max_data: get_required("initial-max-data")?.parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid initial-max-data"))?,
        initial_max_stream_data_bidi_local: get_required("initial-max-stream-data-bidi-local")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid initial-max-stream-data-bidi-local",
                )
            })?,
        initial_max_stream_data_bidi_remote: get_required("initial-max-stream-data-bidi-remote")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid initial-max-stream-data-bidi-remote",
                )
            })?,
        initial_max_stream_data_uni: get_required("initial-max-stream-data-uni")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid initial-max-stream-data-uni")
            })?,
        initial_max_streams_bidi: get_required("initial-max-streams-bidi")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid initial-max-streams-bidi")
            })?,
        initial_max_streams_uni: get_required("initial-max-streams-uni")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid initial-max-streams-uni")
            })?,
        ack_delay_exponent: get_required("ack-delay-exponent")?.parse::<u8>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ack-delay-exponent"))?,
        max_ack_delay: Duration::from_millis(max_ack_delay_ms),
        active_connection_id_limit: get_required("active-connection-id-limit")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid active-connection-id-limit")
            })?,
        enable_early_data: parse_bool(get_required("enable-early-data")?)?,
        enable_migration: parse_bool(get_required("enable-migration")?)?,
        congestion_control_algorithm: parse_congestion_algorithm(
            get_required("congestion-control-algorithm")?,
        )?,
        enable_ecn: parse_bool(get_required("enable-ecn")?)?,
        max_send_burst: get_required("max-send-burst")?.parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid max-send-burst"))?,
        qpack_max_table_capacity: get_required("qpack-max-table-capacity")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid qpack-max-table-capacity")
            })?,
        qpack_blocked_streams: get_required("qpack-blocked-streams")?.parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid qpack-blocked-streams")
            })?,
        enable_retry_validation: parse_bool(map.get("enable-retry-validation").map(String::as_str).unwrap_or("0"))?,
    };

    Ok(config)
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v {
        "1" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean value: {}", v),
        )),
    }
}

fn congestion_algorithm_as_str(algorithm: CongestionAlgorithm) -> &'static str {
    match algorithm {
        CongestionAlgorithm::Cubic => "cubic",
        CongestionAlgorithm::Reno => "reno",
        CongestionAlgorithm::Bbr => "bbr",
    }
}

fn parse_congestion_algorithm(v: &str) -> io::Result<CongestionAlgorithm> {
    match v {
        "cubic" | "Cubic" => Ok(CongestionAlgorithm::Cubic),
        "reno" | "Reno" => Ok(CongestionAlgorithm::Reno),
        "bbr" | "Bbr" | "BBR" => Ok(CongestionAlgorithm::Bbr),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid congestion-control-algorithm: {}", v),
        )),
    }
}

fn compute_http3_config_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(HTTP3_CONFIG_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(HTTP3_CONFIG_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "http3-config header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "http3-config header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "http3-config blob missing header/body separator",
    ))
}

fn parse_secure_http3_config_meta(header: &str, body_len: usize) -> io::Result<SecureHttp3ConfigBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != HTTP3_CONFIG_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure http3-config blob magic",
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
                format!("invalid secure http3-config header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", v.trim()),
                        )
                    },
                )?;
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
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size in config blob")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in config blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at in config blob")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in secure config blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure config blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure config blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure config blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure config blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in secure config blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "secure config encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureHttp3ConfigBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
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
    fn test_secure_http3_config_roundtrip_identity() {
        let config = Config::default();

        let (meta, blob) = config
            .to_secure_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure http3-config");

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded) = Config::from_secure_blob(&blob)
            .expect("failed to decode secure http3-config");

        assert_eq!(decoded_meta.raw_size, meta.raw_size);
        assert_eq!(decoded.max_udp_payload_size, config.max_udp_payload_size);
        assert_eq!(decoded.initial_max_data, config.initial_max_data);
        assert_eq!(decoded.ack_delay_exponent, config.ack_delay_exponent);
        assert_eq!(decoded.enable_migration, config.enable_migration);
        assert_eq!(decoded.enable_ecn, config.enable_ecn);
    }

    #[test]
    fn test_secure_http3_config_roundtrip_compressed() {
        let mut config = Config::default();
        config.max_idle_timeout = Duration::from_millis(12345);
        config.max_ack_delay = Duration::from_millis(99);
        config.enable_early_data = true;
        config.enable_migration = false;
        config.congestion_control_algorithm = CongestionAlgorithm::Reno;
        config.max_send_burst = 42;
        config.qpack_max_table_capacity = 8192;
        config.qpack_blocked_streams = 321;

        let (_meta, blob) = config
            .to_secure_blob(CompressionAlgorithm::Gzip)
            .expect("failed to encode compressed secure http3-config");

        let (_decoded_meta, decoded) = Config::from_secure_blob(&blob)
            .expect("failed to decode compressed secure http3-config");

        assert_eq!(decoded.max_idle_timeout, Duration::from_millis(12345));
        assert_eq!(decoded.max_ack_delay, Duration::from_millis(99));
        assert!(decoded.enable_early_data);
        assert!(!decoded.enable_migration);
        assert_eq!(decoded.max_send_burst, 42);
        assert_eq!(decoded.qpack_max_table_capacity, 8192);
        assert_eq!(decoded.qpack_blocked_streams, 321);
        assert!(matches!(
            decoded.congestion_control_algorithm,
            CongestionAlgorithm::Reno
        ));
    }

    #[test]
    fn test_secure_http3_config_tamper_detected() {
        let config = Config::default();
        let (_meta, mut blob) = config
            .to_secure_blob(CompressionAlgorithm::Identity)
            .expect("failed to encode secure http3-config");

        let idx = blob
            .len()
            .checked_sub(1)
            .expect("blob should not be empty");
        blob[idx] ^= 0x01;

        let result = Config::from_secure_blob(&blob);
        assert!(result.is_err());
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
        let test_values = vec![0, 63, 64, 16383, 16384, 1073741823, 1073741824, (1u64 << 62) - 1];
        
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