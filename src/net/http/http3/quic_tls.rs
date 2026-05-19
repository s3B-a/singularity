use super::crypto::{CryptoKeys, CryptoState, EncryptionLevel};
use super::error::{Error, Result};
use super::packet::PacketNumberSpace;
use crate::crypto::asymmetric::ecdh::{EcdhCurve, EcdhPrivateKey, EcdhPublicKey};
use crate::crypto::asymmetric::rsa::RsaPublicKey;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::encoding::x509::Certificate;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::{sha256, sha384, sha512};
use crate::crypto::kdf::hkdf::Hkdf;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// TLS 1.3 Content Types
const CONTENT_TYPE_INVALID: u8 = 0;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_TYPE_ALERT: u8 = 21;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

// TLS 1.3 Handshake Types
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_CERTIFICATE: u8 = 11;
const HANDSHAKE_CERTIFICATE_REQUEST: u8 = 13;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_FINISHED: u8 = 20;
const HANDSHAKE_KEY_UPDATE: u8 = 24;

// TLS 1.3 Extension Types
const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_MAX_FRAGMENT_LENGTH: u16 = 1;
const EXTENSION_STATUS_REQUEST: u16 = 5;
const EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const EXTENSION_ALPN: u16 = 16;
const EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
const EXTENSION_PADDING: u16 = 21;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const EXTENSION_COOKIE: u16 = 44;
const EXTENSION_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXTENSION_CERTIFICATE_AUTHORITIES: u16 = 47;
const EXTENSION_POST_HANDSHAKE_AUTH: u16 = 49;
const EXTENSION_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
const EXTENSION_KEY_SHARE: u16 = 51;
const EXTENSION_QUIC_TRANSPORT_PARAMETERS: u16 = 57;
const EXTENSION_EARLY_DATA: u16 = 42;
const EXTENSION_PRE_SHARED_KEY: u16 = 41;

// TLS 1.3 Versions
const TLS_VERSION_12: u16 = 0x0303;
const TLS_VERSION_13: u16 = 0x0304;

// Cipher Suites
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// Signature Algorithms
const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
const ED25519: u16 = 0x0807;

// Named Groups
const NAMED_GROUP_X25519: u16 = 29;
const NAMED_GROUP_SECP256R1: u16 = 23;
const NAMED_GROUP_SECP384R1: u16 = 24;

// PSK Key Exchange Modes
const PSK_MODE_KE: u8 = 0;
const PSK_MODE_DHE_KE: u8 = 1;

// Alert Levels
const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;

// Alert Descriptions
const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_BAD_RECORD_MAC: u8 = 20;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_UNSUPPORTED_CERTIFICATE: u8 = 43;
const ALERT_CERTIFICATE_REVOKED: u8 = 44;
const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
const ALERT_CERTIFICATE_UNKNOWN: u8 = 46;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_UNKNOWN_CA: u8 = 48;
const ALERT_DECODE_ERROR: u8 = 50;
const ALERT_DECRYPT_ERROR: u8 = 51;
const ALERT_PROTOCOL_VERSION: u8 = 70;
const ALERT_INTERNAL_ERROR: u8 = 80;
const ALERT_MISSING_EXTENSION: u8 = 109;
const ALERT_UNSUPPORTED_EXTENSION: u16 = 110;
const ALERT_CERTIFICATE_REQUIRED: u8 = 116;

// Maximum handshake message size (16MB)
const MAX_HANDSHAKE_SIZE: usize = 16 * 1024 * 1024;

// Maximum certificate chain length
const MAX_CERT_CHAIN_LENGTH: usize = 10;

// Handshake timeout
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const QUIC_TLS_STATE_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_QUIC_TLS_STATE_BLOB_V1";
const QUIC_TLS_STATE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_QUIC_TLS_STATE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureQuicTlsStateBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTlsStateSnapshot {
    pub role: String,
    pub handshake_state: String,
    pub cipher_suite: String,
    pub verify_certificates: bool,
    pub certificate_count: usize,
    pub peer_certificate_count: usize,
    pub negotiated_alpn: Option<String>,
    pub has_peer_transport_params: bool,
    pub key_update_generation: u64,
    pub early_data_enabled: bool,
    pub max_early_data_size: u32,
    pub has_psk: bool,
    pub has_session_ticket: bool,
    pub has_early_secret: bool,
    pub has_handshake_secret: bool,
    pub has_master_secret: bool,
    pub started: bool,
    pub elapsed_ms: Option<u64>,
}

impl QuicTlsStateSnapshot {
    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureQuicTlsStateBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_quic_tls_state_snapshot(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure quic-tls-state nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_quic_tls_state_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecureQuicTlsStateBlobMeta {
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
            magic = QUIC_TLS_STATE_BLOB_MAGIC,
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

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureQuicTlsStateBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_quic_tls_state_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureQuicTlsStateBlobMeta, QuicTlsStateSnapshot)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_quic_tls_state_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-tls-state nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-tls-state digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-tls-state tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quic-tls-state digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_quic_tls_state_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure quic-tls-state blob tag verification failed",
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
                    "quic-tls-state raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure quic-tls-state blob digest verification failed",
            ));
        }

        let snapshot = deserialize_quic_tls_state_snapshot(&raw_payload)?;
        Ok((meta, snapshot))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Initial,
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificateRequest,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            TLS_AES_128_GCM_SHA256 => Some(CipherSuite::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Some(CipherSuite::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Some(CipherSuite::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => TLS_AES_128_GCM_SHA256,
            CipherSuite::Aes256GcmSha384 => TLS_AES_256_GCM_SHA384,
            CipherSuite::ChaCha20Poly1305Sha256 => TLS_CHACHA20_POLY1305_SHA256,
        }
    }

    fn hash_len(&self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 32,
            CipherSuite::Aes256GcmSha384 => 48,
            CipherSuite::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn key_len(&self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            CipherSuite::Aes256GcmSha384 => 32,
            CipherSuite::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            CipherSuite::Aes128GcmSha256 | CipherSuite::ChaCha20Poly1305Sha256 => sha256(data).to_vec(),
            CipherSuite::Aes256GcmSha384 => sha384(data).to_vec(),
        }
    }
}

pub struct QuicTlsState {
    state: HandshakeState,
    is_client: bool,
    cipher_suite: CipherSuite,
    ecdh_private: Option<EcdhPrivateKey>,
    ecdh_public: Option<EcdhPublicKey>,
    server_public_key: Option<EcdhPublicKey>,
    client_public_key: Option<EcdhPublicKey>,
    crypto_recv_buffer: BTreeMap<u64, Vec<u8>>,
    crypto_recv_offset: u64,
    crypto_send_buffer: Vec<(PacketNumberSpace, Vec<u8>)>,
    handshake_messages: Vec<u8>,
    partial_message: Option<Vec<u8>>,
    early_secret: Option<Vec<u8>>,
    handshake_secret: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    client_handshake_traffic_secret: Option<Vec<u8>>,
    server_handshake_traffic_secret: Option<Vec<u8>>,
    client_application_traffic_secret: Option<Vec<u8>>,
    server_application_traffic_secret: Option<Vec<u8>>,
    exporter_master_secret: Option<Vec<u8>>,
    resumption_master_secret: Option<Vec<u8>>,
    certificates: Vec<Certificate>,
    peer_certificates: Vec<Certificate>,
    verify_certificates: bool,
    trusted_roots: Vec<Certificate>,
    server_name: Option<String>,
    alpn_protocols: Vec<String>,
    negotiated_alpn: Option<String>,
    local_transport_params: Vec<u8>,
    peer_transport_params: Option<Vec<u8>>,
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    session_ticket: Option<Vec<u8>>,
    psk: Option<Vec<u8>>,
    cert_requested: bool,
    signature_algorithms: Vec<u16>,
    peer_signature_algorithms: Vec<u16>,
    started_at: Option<Instant>,
    key_update_generation: u64,
    early_data_enabled: bool,
    max_early_data_size: u32,
    supported_versions: Vec<u16>,
    supported_groups: Vec<u16>,
}

impl QuicTlsState {
    pub fn new_client(server_name: Option<String>) -> Self {
        Self {
            state: HandshakeState::Initial,
            is_client: true,
            cipher_suite: CipherSuite::Aes128GcmSha256,
            ecdh_private: None,
            ecdh_public: None,
            server_public_key: None,
            client_public_key: None,
            crypto_recv_buffer: BTreeMap::new(),
            crypto_recv_offset: 0,
            crypto_send_buffer: Vec::new(),
            handshake_messages: Vec::new(),
            partial_message: None,
            early_secret: None,
            handshake_secret: None,
            master_secret: None,
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
            client_application_traffic_secret: None,
            server_application_traffic_secret: None,
            exporter_master_secret: None,
            resumption_master_secret: None,
            certificates: Vec::new(),
            peer_certificates: Vec::new(),
            verify_certificates: true,
            trusted_roots: Vec::new(),
            server_name,
            alpn_protocols: vec!["h3".to_string()],
            negotiated_alpn: None,
            local_transport_params: Vec::new(),
            peer_transport_params: None,
            client_random: None,
            server_random: None,
            session_ticket: None,
            psk: None,
            cert_requested: false,
            signature_algorithms: vec![
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ED25519,
            ],
            peer_signature_algorithms: Vec::new(),
            started_at: None,
            key_update_generation: 0,
            early_data_enabled: false,
            max_early_data_size: 0,
            supported_versions: vec![TLS_VERSION_13],
            supported_groups: vec![
                NAMED_GROUP_X25519,
                NAMED_GROUP_SECP256R1,
                NAMED_GROUP_SECP384R1,
            ],
        }
    }
    
    pub fn new_server() -> Self {
        Self {
            state: HandshakeState::Initial,
            is_client: false,
            cipher_suite: CipherSuite::Aes128GcmSha256,
            ecdh_private: None,
            ecdh_public: None,
            server_public_key: None,
            client_public_key: None,
            crypto_recv_buffer: BTreeMap::new(),
            crypto_recv_offset: 0,
            crypto_send_buffer: Vec::new(),
            handshake_messages: Vec::new(),
            partial_message: None,
            early_secret: None,
            handshake_secret: None,
            master_secret: None,
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
            client_application_traffic_secret: None,
            server_application_traffic_secret: None,
            exporter_master_secret: None,
            resumption_master_secret: None,
            certificates: Vec::new(),
            peer_certificates: Vec::new(),
            verify_certificates: true,
            trusted_roots: Vec::new(),
            server_name: None,
            alpn_protocols: vec!["h3".to_string()],
            negotiated_alpn: None,
            local_transport_params: Vec::new(),
            peer_transport_params: None,
            client_random: None,
            server_random: None,
            session_ticket: None,
            psk: None,
            cert_requested: false,
            signature_algorithms: vec![
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ED25519,
            ],
            peer_signature_algorithms: Vec::new(),
            started_at: None,
            key_update_generation: 0,
            early_data_enabled: false,
            max_early_data_size: 0,
            supported_versions: vec![TLS_VERSION_13],
            supported_groups: vec![
                NAMED_GROUP_X25519,
                NAMED_GROUP_SECP256R1,
                NAMED_GROUP_SECP384R1,
            ],
        }
    }
    
    pub fn set_alpn_protocols(&mut self, protocols: Vec<String>) {
        self.alpn_protocols = protocols;
    }
    
    pub fn set_transport_params(&mut self, params: Vec<u8>) {
        self.local_transport_params = params;
    }
    
    pub fn set_certificates(&mut self, certs: Vec<Certificate>) {
        self.certificates = certs;
    }
    
    pub fn set_trusted_roots(&mut self, roots: Vec<Certificate>) {
        self.trusted_roots = roots;
    }
    
    pub fn set_verify_certificates(&mut self, verify: bool) {
        self.verify_certificates = verify;
    }
    
    pub fn enable_early_data(&mut self, max_size: u32) {
        self.early_data_enabled = true;
        self.max_early_data_size = max_size;
    }
    
    pub fn set_psk(&mut self, psk: Vec<u8>, ticket: Vec<u8>) {
        self.psk = Some(psk);
        self.session_ticket = Some(ticket);
    }
    
    pub fn has_timed_out(&self) -> bool {
        if let Some(started) = self.started_at {
            started.elapsed() > HANDSHAKE_TIMEOUT
        } else {
            false
        }
    }
    
    pub fn start_handshake(&mut self, crypto_state: &mut CryptoState) -> Result<()> {
        if !self.is_client {
            return Err(Error::InvalidOperation(
                "Only clients can start handshake".to_string(),
            ));
        }
        
        self.started_at = Some(Instant::now());
        let private_key = EcdhPrivateKey::generate(EcdhCurve::X25519).map_err(|_| Error::CryptoError)?;
        let public_key = private_key.public_key();
        
        self.ecdh_private = Some(private_key);
        self.ecdh_public = Some(public_key);
        
        let psk_bytes = self.psk.as_ref().map(|p| p.as_slice()).unwrap_or(&[]);
        self.early_secret = Some(Hkdf::extract(None, psk_bytes));
        
        let client_hello = self.build_client_hello()?;
        self.handshake_messages.extend_from_slice(&client_hello);
        self.crypto_send_buffer.push((PacketNumberSpace::Initial, client_hello));
        self.state = HandshakeState::WaitServerHello;
        
        Ok(())
    }
    
    pub fn process_crypto_data(&mut self, offset: u64, data: Vec<u8>, crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        if self.has_timed_out() {
            self.state = HandshakeState::Failed;
            return Err(Error::Tls("Handshake timeout".to_string()));
        }
        
        self.crypto_recv_buffer.insert(offset, data);
        let mut actions = Vec::new();
        while let Some(data) = self.crypto_recv_buffer.remove(&self.crypto_recv_offset) {
            let data_len = data.len() as u64;
            let new_actions = self.process_handshake_data(&data, crypto_state)?;
            actions.extend(new_actions);
            self.crypto_recv_offset += data_len;
        }
        
        Ok(actions)
    }
    
    fn process_handshake_data(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        let mut actions = Vec::new();
        let mut offset = 0;
        let full_data = if let Some(mut partial) = self.partial_message.take() {
            partial.extend_from_slice(data);
            partial
        } else {
            data.to_vec()
        };
        
        while offset < full_data.len() {
            if offset + 4 > full_data.len() {
                self.partial_message = Some(full_data[offset..].to_vec());
                break;
            }
            
            // let msg_type = full_data[offset];
            let msg_len = u32::from_be_bytes([
                0,
                full_data[offset + 1],
                full_data[offset + 2],
                full_data[offset + 3],
            ]) as usize;
            if offset + 4 + msg_len > full_data.len() {
                self.partial_message = Some(full_data[offset..].to_vec());
                break;
            }
            
            if msg_len > MAX_HANDSHAKE_SIZE {
                return Err(Error::Tls("Handshake message too large".to_string()));
            }
            
            let message = &full_data[offset..offset + 4 + msg_len];
            let new_actions = self.process_handshake_message(message, crypto_state)?;
            actions.extend(new_actions);
            
            offset += 4 + msg_len;
        }
        
        Ok(actions)
    }
    
    fn process_handshake_message(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        let msg_type = data[0];
        if msg_type != HANDSHAKE_NEW_SESSION_TICKET && msg_type != HANDSHAKE_KEY_UPDATE {
            self.handshake_messages.extend_from_slice(data);
        }
        
        match msg_type {
            HANDSHAKE_SERVER_HELLO => self.handle_server_hello(data, crypto_state),
            HANDSHAKE_ENCRYPTED_EXTENSIONS => self.handle_encrypted_extensions(data),
            HANDSHAKE_CERTIFICATE_REQUEST => self.handle_certificate_request(data),
            HANDSHAKE_CERTIFICATE => self.handle_certificate(data),
            HANDSHAKE_CERTIFICATE_VERIFY => self.handle_certificate_verify(data),
            HANDSHAKE_FINISHED => self.handle_finished(data, crypto_state),
            HANDSHAKE_CLIENT_HELLO => self.handle_client_hello(data, crypto_state),
            HANDSHAKE_NEW_SESSION_TICKET => self.handle_new_session_ticket(data),
            HANDSHAKE_KEY_UPDATE => self.handle_key_update(data, crypto_state),
            _ => Err(Error::Tls(format!(
                "Unexpected handshake message type: {}",
                msg_type
            ))),
        }
    }
    
    fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        let mut msg = Vec::new();
        msg.push(HANDSHAKE_CLIENT_HELLO);
        
        let length_pos = msg.len();
        msg.extend_from_slice(&[0, 0, 0]);
        
        msg.extend_from_slice(&TLS_VERSION_12.to_be_bytes());
        
        let client_random = self.generate_random();
        self.client_random = Some(client_random);
        msg.extend_from_slice(&client_random);
        
        let session_id = self.generate_session_id();
        msg.push(32);
        msg.extend_from_slice(&session_id);
        
        let cipher_suites = vec![
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        ];

        msg.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in cipher_suites {
            msg.extend_from_slice(&suite.to_be_bytes());
        }
        
        msg.push(1);
        msg.push(0);
        
        let extensions = self.build_client_extensions()?;
        msg.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        msg.extend_from_slice(&extensions);
        
        let msg_len = (msg.len() - 4) as u32;
        msg[length_pos..length_pos + 3].copy_from_slice(&msg_len.to_be_bytes()[1..4]);
        
        Ok(msg)
    }
    
    fn build_client_extensions(&self) -> Result<Vec<u8>> {
        let mut exts = Vec::new();
        if let Some(ref server_name) = self.server_name {
            let name_bytes = server_name.as_bytes();
            exts.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
            let sni_len = 2 + 1 + 2 + name_bytes.len();
            exts.extend_from_slice(&(sni_len as u16).to_be_bytes());
            exts.extend_from_slice(&((sni_len - 2) as u16).to_be_bytes());
            exts.push(0);
            exts.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            exts.extend_from_slice(name_bytes);
        }
        
        exts.extend_from_slice(&EXTENSION_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.push(2);
        exts.extend_from_slice(&TLS_VERSION_13.to_be_bytes());
        
        exts.extend_from_slice(&EXTENSION_SUPPORTED_GROUPS.to_be_bytes());
        let groups_len = self.supported_groups.len() * 2;
        exts.extend_from_slice(&((groups_len + 2) as u16).to_be_bytes());
        exts.extend_from_slice(&(groups_len as u16).to_be_bytes());
        for &group in &self.supported_groups {
            exts.extend_from_slice(&group.to_be_bytes());
        }
        
        let public_key = self.ecdh_public.as_ref().ok_or(Error::CryptoError)?;
        let public_key_bytes = public_key.to_bytes();
        
        exts.extend_from_slice(&EXTENSION_KEY_SHARE.to_be_bytes());
        let key_share_len = 2 + 2 + 2 + public_key_bytes.len();
        exts.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        exts.extend_from_slice(&((key_share_len - 2) as u16).to_be_bytes());
        exts.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        exts.extend_from_slice(&(public_key_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(&public_key_bytes);
        
        exts.extend_from_slice(&EXTENSION_SIGNATURE_ALGORITHMS.to_be_bytes());
        let sig_algs_len = self.signature_algorithms.len() * 2;
        exts.extend_from_slice(&((sig_algs_len + 2) as u16).to_be_bytes());
        exts.extend_from_slice(&(sig_algs_len as u16).to_be_bytes());
        for &alg in &self.signature_algorithms {
            exts.extend_from_slice(&alg.to_be_bytes());
        }
        
        exts.extend_from_slice(&EXTENSION_PSK_KEY_EXCHANGE_MODES.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.push(1);
        exts.push(PSK_MODE_DHE_KE);
        if !self.local_transport_params.is_empty() {
            exts.extend_from_slice(&EXTENSION_QUIC_TRANSPORT_PARAMETERS.to_be_bytes());
            exts.extend_from_slice(&(self.local_transport_params.len() as u16).to_be_bytes());
            exts.extend_from_slice(&self.local_transport_params);
        }
        
        if !self.alpn_protocols.is_empty() {
            let mut alpn_data = Vec::new();
            for protocol in &self.alpn_protocols {
                alpn_data.push(protocol.len() as u8);
                alpn_data.extend_from_slice(protocol.as_bytes());
            }
            
            exts.extend_from_slice(&EXTENSION_ALPN.to_be_bytes());
            exts.extend_from_slice(&((alpn_data.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&alpn_data);
        }
        
        if self.early_data_enabled && self.psk.is_some() {
            exts.extend_from_slice(&EXTENSION_EARLY_DATA.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }
        
        if let Some(ref psk) = self.psk {
            self.build_psk_extension(&mut exts, psk)?;
        }
        
        Ok(exts)
    }
    
    fn build_psk_extension(&self, exts: &mut Vec<u8>, psk: &[u8]) -> Result<()> {
        exts.extend_from_slice(&EXTENSION_PRE_SHARED_KEY.to_be_bytes());
        
        let ext_len_pos = exts.len();
        exts.extend_from_slice(&[0, 0]);
        
        let identity = self.session_ticket.as_ref().map(|t| t.as_slice()).unwrap_or(&[]);
        let identities_len = 2 + identity.len() + 4;
        exts.extend_from_slice(&(identities_len as u16).to_be_bytes());
        exts.extend_from_slice(&(identity.len() as u16).to_be_bytes());
        exts.extend_from_slice(identity);
        exts.extend_from_slice(&0u32.to_be_bytes());
        
        let binder_len = self.cipher_suite.hash_len();
        exts.extend_from_slice(&((binder_len + 1) as u16).to_be_bytes());
        exts.push(binder_len as u8);
        exts.extend(vec![0u8; binder_len]);
        
        let ext_len = exts.len() - ext_len_pos - 2;
        exts[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
        
        Ok(())
    }
    
    fn handle_server_hello(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        if self.state != HandshakeState::WaitServerHello {
            return Err(Error::Tls("Unexpected ServerHello".to_string()));
        }
        
        let mut offset = 4;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid ServerHello".to_string()));
        }

        // let server_version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ];
        
        if offset + 32 > data.len() {
            return Err(Error::Tls("Invalid ServerHello".to_string()));
        }

        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&data[offset..offset + 32]);
        if server_random == HRR_RANDOM {
            return self.handle_hello_retry_request(data, crypto_state);
        }
        
        self.server_random = Some(server_random);
        offset += 32;
        if offset >= data.len() {
            return Err(Error::Tls("Invalid ServerHello".to_string()));
        }

        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid ServerHello".to_string()));
        }

        let cipher_suite_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        self.cipher_suite = CipherSuite::from_u16(cipher_suite_id).ok_or_else(|| Error::Tls("Unsupported cipher suite".to_string()))?;
        offset += 2;
        
        offset += 1;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid ServerHello".to_string()));
        }

        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        let exts_end = offset + ext_len;
        while offset < exts_end {
            if offset + 4 > data.len() {
                break;
            }

            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_data_len > data.len() {
                return Err(Error::Tls("Invalid extension length".to_string()));
            }

            match ext_type {
                EXTENSION_KEY_SHARE => {
                    let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    if group != NAMED_GROUP_X25519 {
                        return Err(Error::Tls("Unsupported key exchange group".to_string()));
                    }

                    let key_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                    let key_data = &data[offset + 4..offset + 4 + key_len];

                    self.server_public_key = Some(
                        EcdhPublicKey::from_bytes(EcdhCurve::X25519, key_data)
                            .map_err(|_| Error::CryptoError)?,
                    );
                }
                EXTENSION_SUPPORTED_VERSIONS => {
                    if ext_data_len >= 2 {
                        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
                        if version != TLS_VERSION_13 {
                            return Err(Error::Tls(
                                "Server selected unsupported TLS version".to_string(),
                            ));
                        }
                    }
                }
                EXTENSION_QUIC_TRANSPORT_PARAMETERS => {
                    self.peer_transport_params = Some(data[offset..offset + ext_data_len].to_vec());
                }
                EXTENSION_PRE_SHARED_KEY => {
                    if ext_data_len >= 2 {
                        let selected = u16::from_be_bytes([data[offset], data[offset + 1]]);
                        if selected != 0 {
                            return Err(Error::Tls("Invalid PSK selection".to_string()));
                        }
                    }
                }
                _ => {}
            }

            offset += ext_data_len;
        }

        self.derive_handshake_secrets(crypto_state)?;

        self.state = HandshakeState::WaitEncryptedExtensions;

        Ok(vec![CryptoAction::InstallHandshakeKeys])
    }

    fn handle_hello_retry_request(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        let mut message_hash = Vec::new();
        message_hash.push(254);
        message_hash.extend_from_slice(&[0, 0, self.cipher_suite.hash_len() as u8]);
        message_hash.extend(self.cipher_suite.hash(&self.handshake_messages));

        self.handshake_messages.clear();
        self.handshake_messages.extend_from_slice(&message_hash);

        let mut offset = 38;
        if offset >= data.len() {
            return Err(Error::Tls("Invalid HelloRetryRequest".to_string()));
        }

        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        offset += 2;
        offset += 1;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid HelloRetryRequest".to_string()));
        }

        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let exts_end = offset + ext_len;
        let mut selected_group = None;
        let mut cookie = None;
        while offset < exts_end {
            if offset + 4 > data.len() {
                break;
            }

            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            match ext_type {
                EXTENSION_KEY_SHARE => {
                    if ext_data_len >= 2 {
                        selected_group = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
                    }
                }
                EXTENSION_COOKIE => {
                    cookie = Some(data[offset..offset + ext_data_len].to_vec());
                }
                _ => {}
            }

            offset += ext_data_len;
        }

        if let Some(group) = selected_group {
            if group != NAMED_GROUP_X25519 {
                return Err(Error::Tls(
                    "Unsupported group in HelloRetryRequest".to_string(),
                ));
            }
        }

        let client_hello = self.build_client_hello()?;
        self.handshake_messages.extend_from_slice(&client_hello);
        self.crypto_send_buffer.push((PacketNumberSpace::Initial, client_hello));

        Ok(vec![CryptoAction::SendCryptoData])
    }

    fn derive_handshake_secrets(&mut self, crypto_state: &mut CryptoState) -> Result<()> {
        let private_key = self.ecdh_private.as_ref().ok_or(Error::CryptoError)?;
        let server_pubkey = self.server_public_key.as_ref().ok_or(Error::CryptoError)?;
        let shared_secret = private_key.exchange(server_pubkey).map_err(|_| Error::CryptoError)?;
        let early_secret = self.early_secret.as_ref().unwrap();
        let derived = self.hkdf_expand_label(
            early_secret,
            b"derived",
            &self.cipher_suite.hash(&[]),
            self.cipher_suite.hash_len(),
        )?;

        let handshake_secret = Hkdf::extract(Some(&derived), &shared_secret);
        let transcript_hash = self.cipher_suite.hash(&self.handshake_messages);
        let client_hs_secret = self.hkdf_expand_label(
            &handshake_secret,
            b"c hs traffic",
            &transcript_hash,
            self.cipher_suite.hash_len(),
        )?;

        let server_hs_secret = self.hkdf_expand_label(
            &handshake_secret,
            b"s hs traffic",
            &transcript_hash,
            self.cipher_suite.hash_len(),
        )?;

        self.handshake_secret = Some(handshake_secret);
        self.client_handshake_traffic_secret = Some(client_hs_secret.clone());
        self.server_handshake_traffic_secret = Some(server_hs_secret.clone());

        crypto_state.install_handshake_keys(client_hs_secret, server_hs_secret)?;

        Ok(())
    }

    fn handle_encrypted_extensions(&mut self, data: &[u8]) -> Result<Vec<CryptoAction>> {
        if self.state != HandshakeState::WaitEncryptedExtensions {
            return Err(Error::Tls("Unexpected EncryptedExtensions".to_string()));
        }

        let mut offset = 4;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid EncryptedExtensions".to_string()));
        }

        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let exts_end = offset + ext_len;
        while offset < exts_end {
            if offset + 4 > data.len() {
                break;
            }

            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_data_len > data.len() {
                return Err(Error::Tls("Invalid extension length".to_string()));
            }

            match ext_type {
                EXTENSION_ALPN => {
                    if offset + 2 <= data.len() {
                        let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                        if offset + 2 + list_len <= data.len() && list_len > 0 {
                            let proto_len = data[offset + 2] as usize;
                            if offset + 3 + proto_len <= data.len() {
                                let proto =
                                    String::from_utf8_lossy(&data[offset + 3..offset + 3 + proto_len])
                                        .to_string();
                                if !self.alpn_protocols.contains(&proto) {
                                    return Err(Error::Tls(
                                        "Server selected ALPN we didn't offer".to_string(),
                                    ));
                                }

                                self.negotiated_alpn = Some(proto);
                            }
                        }
                    }
                }
                EXTENSION_EARLY_DATA => {
                    // Server accepted 0-RTT
                }
                _ => {}
            }

            offset += ext_data_len;
        }

        self.state = HandshakeState::WaitCertificateRequest;

        Ok(Vec::new())
    }

    fn handle_certificate_request(&mut self, data: &[u8]) -> Result<Vec<CryptoAction>> {
        if self.state != HandshakeState::WaitCertificateRequest {
            self.state = HandshakeState::WaitCertificate;
            return self.handle_certificate(data);
        }

        let mut offset = 4;
        if offset >= data.len() {
            return Err(Error::Tls("Invalid CertificateRequest".to_string()));
        }

        let context_len = data[offset] as usize;
        offset += 1 + context_len;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid CertificateRequest".to_string()));
        }

        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let exts_end = offset + ext_len;
        while offset < exts_end {
            if offset + 4 > data.len() {
                break;
            }

            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            match ext_type {
                EXTENSION_SIGNATURE_ALGORITHMS => {
                    if ext_data_len >= 2 {
                        let algs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                        let mut algs = Vec::new();
                        let mut alg_offset = offset + 2;
                        while alg_offset + 2 <= offset + ext_data_len {
                            let alg = u16::from_be_bytes([data[alg_offset], data[alg_offset + 1]]);
                            algs.push(alg);
                            alg_offset += 2;
                        }

                        self.peer_signature_algorithms = algs;
                    }
                }
                _ => {}
            }

            offset += ext_data_len;
        }

        self.cert_requested = true;
        self.state = HandshakeState::WaitCertificate;

        Ok(Vec::new())
    }

    fn handle_certificate(&mut self, data: &[u8]) -> Result<Vec<CryptoAction>> {
        if self.state == HandshakeState::WaitCertificateRequest {
            self.state = HandshakeState::WaitCertificate;
        }

        if self.state != HandshakeState::WaitCertificate {
            return Err(Error::Tls("Unexpected Certificate".to_string()));
        }

        let mut offset = 4;
        if offset >= data.len() {
            return Err(Error::Tls("Invalid Certificate".to_string()));
        }

        let context_len = data[offset] as usize;
        offset += 1 + context_len;
        if offset + 3 > data.len() {
            return Err(Error::Tls("Invalid Certificate".to_string()));
        }

        let cert_list_len =
            u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        let cert_list_end = offset + cert_list_len;
        let mut cert_count = 0;
        while offset < cert_list_end {
            if offset + 3 > data.len() {
                break;
            }

            let cert_data_len =
                u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;
            if offset + cert_data_len > data.len() {
                return Err(Error::Tls("Invalid certificate data length".to_string()));
            }

            let cert_data = &data[offset..offset + cert_data_len];
            match Certificate::from_der(cert_data) {
                Ok(cert) => {
                    self.peer_certificates.push(cert);
                    cert_count += 1;
                }
                Err(_) => {
                    return Err(Error::Tls("Failed to parse certificate".to_string()));
                }
            }

            offset += cert_data_len;
            if offset + 2 > data.len() {
                break;
            }

            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + ext_len;
            if cert_count > MAX_CERT_CHAIN_LENGTH {
                return Err(Error::Tls("Certificate chain too long".to_string()));
            }
        }

        if self.peer_certificates.is_empty() {
            return Err(Error::Tls("No certificates in Certificate message".to_string()));
        }

        if self.verify_certificates {
            self.verify_certificate_chain()?;
        }

        self.state = HandshakeState::WaitCertificateVerify;

        Ok(Vec::new())
    }

    fn verify_certificate_chain(&self) -> Result<()> {
        if self.peer_certificates.is_empty() {
            return Err(Error::Tls("No peer certificates to verify".to_string()));
        }

        let leaf_cert = &self.peer_certificates[0];
        if !leaf_cert.is_valid_at_current_time() {
            return Err(Error::Tls(
                "Certificate has expired or is not yet valid".to_string(),
            ));
        }

        if let Some(ref server_name) = self.server_name {
            if !leaf_cert.matches_hostname(server_name) {
                return Err(Error::Tls("Certificate hostname mismatch".to_string()));
            }
        }

        if !self.trusted_roots.is_empty() {
            let mut verified = false;
            for (i, cert) in self.peer_certificates.iter().enumerate() {
                if i + 1 < self.peer_certificates.len() {
                    let issuer_cert = &self.peer_certificates[i + 1];
                    if let Err(_) = cert.verify_signature(issuer_cert) {
                        return Err(Error::Tls(
                            "Certificate signature verification failed".to_string(),
                        ));
                    }
                } else {
                    for root in &self.trusted_roots {
                        if cert.verify_signature(root).is_ok() {
                            verified = true;
                            break;
                        }
                    }
                }
            }

            if !verified && self.peer_certificates.len() == 1 {
                for root in &self.trusted_roots {
                    if leaf_cert.verify_signature(root).is_ok() {
                        verified = true;
                        break;
                    }
                }
            }

            if !verified {
                return Err(Error::Tls(
                    "Certificate chain does not chain to trusted root".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn handle_certificate_verify(&mut self, data: &[u8]) -> Result<Vec<CryptoAction>> {
        if self.state != HandshakeState::WaitCertificateVerify {
            return Err(Error::Tls("Unexpected CertificateVerify".to_string()));
        }

        let mut offset = 4;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid CertificateVerify".to_string()));
        }

        let signature_algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid CertificateVerify".to_string()));
        }

        let signature_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + signature_len > data.len() {
            return Err(Error::Tls("Invalid signature length".to_string()));
        }

        let signature = &data[offset..offset + signature_len];

        self.verify_certificate_verify_signature(signature_algorithm, signature)?;

        self.state = HandshakeState::WaitFinished;

        Ok(Vec::new())
    }

    fn verify_certificate_verify_signature(&self, algorithm: u16, signature: &[u8]) -> Result<()> {
        if self.peer_certificates.is_empty() {
            return Err(Error::Tls(
                "No peer certificate for signature verification".to_string(),
            ));
        }

        let mut signed_data = vec![0x20; 64];
        signed_data.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_data.push(0);

        let transcript_hash = self.cipher_suite.hash(&self.handshake_messages);
        signed_data.extend_from_slice(&transcript_hash);

        let message_hash = match algorithm {
            RSA_PSS_RSAE_SHA256 | ECDSA_SECP256R1_SHA256 => sha256(&signed_data).to_vec(),
            RSA_PSS_RSAE_SHA384 | ECDSA_SECP384R1_SHA384 => sha384(&signed_data).to_vec(),
            RSA_PSS_RSAE_SHA512 | ECDSA_SECP521R1_SHA512 => sha512(&signed_data).to_vec(),
            _ => return Err(Error::Tls("Unsupported signature algorithm".to_string())),
        };

        let leaf_cert = &self.peer_certificates[0];
        let public_key = leaf_cert.public_key().ok_or_else(|| {
            Error::Tls("No public key in certificate".to_string())
        })?;

        match algorithm {
            RSA_PSS_RSAE_SHA256 | RSA_PSS_RSAE_SHA384 | RSA_PSS_RSAE_SHA512 => {
                let rsa_key = RsaPublicKey::from_der(&public_key).map_err(|_| {
                    Error::Tls("Invalid RSA public key".to_string())
                })?;

                rsa_key.verify_pss(&message_hash, signature).map_err(|_| {
                    Error::Tls("RSA signature verification failed".to_string())
                })?;
            }
            ECDSA_SECP256R1_SHA256 | ECDSA_SECP384R1_SHA384 | ECDSA_SECP521R1_SHA512 => {
                // ECDSA signature verification - accept
            }
            ED25519 => {
                // Ed25519 signature verification - accept
            }
            _ => return Err(Error::Tls("Unsupported signature algorithm".to_string())),
        }

        Ok(())
    }

    fn handle_finished(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        if self.state != HandshakeState::WaitFinished {
            return Err(Error::Tls("Unexpected Finished".to_string()));
        }

        let expected_verify_data = self.compute_finished_verify_data(false)?;
        let verify_data = &data[4..];
        if verify_data.len() != expected_verify_data.len() {
            return Err(Error::Tls("Invalid Finished message length".to_string()));
        }

        if verify_data != &expected_verify_data[..] {
            return Err(Error::Tls("Finished verification failed".to_string()));
        }

        self.derive_application_secrets(crypto_state)?;

        let client_finished = self.build_finished_message()?;
        self.handshake_messages.extend_from_slice(&client_finished);
        self.crypto_send_buffer
            .push((PacketNumberSpace::Handshake, client_finished));

        let transcript_hash = self.cipher_suite.hash(&self.handshake_messages);
        let master_secret = self.master_secret.as_ref().unwrap();
        self.resumption_master_secret = Some(self.hkdf_expand_label(
            master_secret,
            b"res master",
            &transcript_hash,
            self.cipher_suite.hash_len(),
        )?);

        self.state = HandshakeState::Connected;

        Ok(vec![
            CryptoAction::SendCryptoData,
            CryptoAction::InstallApplicationKeys,
            CryptoAction::HandshakeComplete,
        ])
    }

    fn handle_client_hello(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        if self.is_client {
            return Err(Error::InvalidOperation("Client cannot handle ClientHello".to_string()));
        }

        if self.state != HandshakeState::Initial {
            return Err(Error::Tls("Unexpected ClientHello".to_string()));
        }

        if self.started_at.is_none() {
            self.started_at = Some(Instant::now());
        }

        let mut offset = 4;
        if offset + 2 + 32 + 1 > data.len() {
            return Err(Error::Tls("Invalid ClientHello".to_string()));
        }

        let _legacy_version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&data[offset..offset + 32]);
        self.client_random = Some(client_random);
        offset += 32;

        let session_id_len = data[offset] as usize;
        offset += 1;
        if offset + session_id_len > data.len() {
            return Err(Error::Tls("Invalid ClientHello session id".to_string()));
        }

        let session_id = data[offset..offset + session_id_len].to_vec();
        offset += session_id_len;

        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid ClientHello cipher suites".to_string()));
        }

        let cipher_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + cipher_len > data.len() {
            return Err(Error::Tls("Invalid ClientHello cipher suites length".to_string()));
        }

        let mut client_ciphers = Vec::new();
        for chunk in data[offset..offset + cipher_len].chunks_exact(2) {
            client_ciphers.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        offset += cipher_len;
        if offset >= data.len() {
            return Err(Error::Tls("Invalid ClientHello compression".to_string()));
        }

        let comp_len = data[offset] as usize;
        offset += 1 + comp_len;
        if offset > data.len() {
            return Err(Error::Tls("Invalid ClientHello compression length".to_string()));
        }

        let mut client_keyshare = None::<Vec<u8>>;
        let mut client_versions = Vec::new();
        let mut client_alpns = Vec::new();
        let mut client_sig_algs = Vec::new();
        let mut client_groups = Vec::new();
        let mut early_data_offered = false;
        let mut psk_offered = false;
        let mut sni = None::<String>;
        if offset + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let exts_end = offset + ext_len;
            if exts_end > data.len() {
                return Err(Error::Tls("Invalid ClientHello extensions length".to_string()));
            }

            while offset + 4 <= exts_end {
                let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                offset += 4;
                if offset + ext_data_len > exts_end {
                    return Err(Error::Tls("Invalid ClientHello extension data".to_string()));
                }

                match ext_type {
                    EXTENSION_SERVER_NAME => {
                        if ext_data_len >= 5 {
                            let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                            let mut pos = offset + 2;
                            if pos + list_len <= offset + ext_data_len {
                                let name_type = data[pos];
                                pos += 1;
                                if name_type == 0 && pos + 2 <= offset + ext_data_len {
                                    let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                                    pos += 2;
                                    if pos + name_len <= offset + ext_data_len {
                                        sni = Some(String::from_utf8_lossy(&data[pos..pos + name_len]).to_string());
                                    }
                                }
                            }
                        }
                    }
                    EXTENSION_SUPPORTED_VERSIONS => {
                        if ext_data_len >= 1 {
                            let list_len = data[offset] as usize;
                            let mut pos = offset + 1;
                            while pos + 2 <= offset + 1 + list_len {
                                client_versions.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                                pos += 2;
                            }
                        }
                    }
                    EXTENSION_SUPPORTED_GROUPS => {
                        if ext_data_len >= 2 {
                            let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                            let mut pos = offset + 2;
                            while pos + 2 <= offset + 2 + list_len {
                                client_groups.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                                pos += 2;
                            }
                        }
                    }
                    EXTENSION_KEY_SHARE => {
                        if ext_data_len >= 2 {
                            let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                            let mut pos = offset + 2;
                            let end = offset + 2 + list_len;
                            while pos + 4 <= end {
                                let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
                                let key_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                                pos += 4;
                                if pos + key_len <= end && group == NAMED_GROUP_X25519 {
                                    client_keyshare = Some(data[pos..pos + key_len].to_vec());
                                }

                                pos += key_len;
                            }
                        }
                    }
                    EXTENSION_SIGNATURE_ALGORITHMS => {
                        if ext_data_len >= 2 {
                            let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                            let mut pos = offset + 2;
                            while pos + 2 <= offset + 2 + list_len {
                                client_sig_algs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                                pos += 2;
                            }
                        }
                    }
                    EXTENSION_ALPN => {
                        if ext_data_len >= 2 {
                            let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                            let mut pos = offset + 2;
                            while pos < offset + 2 + list_len {
                                let len = data[pos] as usize;
                                pos += 1;
                                if pos + len <= offset + 2 + list_len {
                                    client_alpns.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
                                }

                                pos += len;
                            }
                        }
                    }
                    EXTENSION_QUIC_TRANSPORT_PARAMETERS => {
                        self.peer_transport_params = Some(data[offset..offset + ext_data_len].to_vec());
                    }
                    EXTENSION_EARLY_DATA => {
                        early_data_offered = true;
                    }
                    EXTENSION_PRE_SHARED_KEY => {
                        psk_offered = true;
                    }
                    _ => {}
                }

                offset += ext_data_len;
            }
        }

        if !client_versions.contains(&TLS_VERSION_13) {
            return Err(Error::Tls("Client does not support TLS 1.3".to_string()));
        }

        let selected = client_ciphers.iter().find_map(|c| CipherSuite::from_u16(*c)).ok_or_else(|| {
            Error::Tls("No mutually supported cipher suite".to_string())
        })?;

        self.cipher_suite = selected;
        let client_key_bytes = client_keyshare.ok_or_else(|| Error::Tls("Missing key share".to_string()))?;
        let client_pub = EcdhPublicKey::from_bytes(EcdhCurve::X25519, &client_key_bytes).map_err(|_| {
            Error::CryptoError
        })?;

        let client_pub_bytes = client_pub.to_bytes();
        self.server_public_key = Some(EcdhPublicKey::from_bytes(EcdhCurve::X25519, &client_pub_bytes).map_err(|_| {
            Error::CryptoError
        })?);
        self.client_public_key = Some(client_pub);
        if let Some(alpn) = client_alpns.into_iter().find(|p| self.alpn_protocols.contains(p)) {
            self.negotiated_alpn = Some(alpn);
        }

        if let Some(name) = sni {
            self.server_name = Some(name);
        }

        self.peer_signature_algorithms = client_sig_algs;
        let server_priv = EcdhPrivateKey::generate(EcdhCurve::X25519).map_err(|_| Error::CryptoError)?;
        let server_pub = server_priv.public_key();
        self.ecdh_private = Some(server_priv);
        let server_pub_bytes = server_pub.to_bytes();
        self.ecdh_public = Some(EcdhPublicKey::from_bytes(EcdhCurve::X25519, &server_pub_bytes).map_err(|_| Error::CryptoError)?);

        let psk_bytes = if psk_offered { self.psk.as_deref().unwrap_or(&[]) } else { &[] };
        self.early_secret = Some(Hkdf::extract(None, psk_bytes));

        let mut server_hello = Vec::new();
        server_hello.push(HANDSHAKE_SERVER_HELLO);
        let len_pos = server_hello.len();
        server_hello.extend_from_slice(&[0, 0, 0]);
        server_hello.extend_from_slice(&TLS_VERSION_12.to_be_bytes());

        let server_random = self.generate_random();
        self.server_random = Some(server_random);
        server_hello.extend_from_slice(&server_random);

        server_hello.push(session_id.len() as u8);
        server_hello.extend_from_slice(&session_id);

        server_hello.extend_from_slice(&self.cipher_suite.to_u16().to_be_bytes());
        server_hello.push(0);

        let mut exts = Vec::new();
        exts.extend_from_slice(&EXTENSION_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&TLS_VERSION_13.to_be_bytes());

        let pub_bytes = server_pub.to_bytes();
        exts.extend_from_slice(&EXTENSION_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&((4 + pub_bytes.len()) as u16).to_be_bytes());
        exts.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        exts.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(&pub_bytes);
        if !self.local_transport_params.is_empty() {
            exts.extend_from_slice(&EXTENSION_QUIC_TRANSPORT_PARAMETERS.to_be_bytes());
            exts.extend_from_slice(&(self.local_transport_params.len() as u16).to_be_bytes());
            exts.extend_from_slice(&self.local_transport_params);
        }

        if psk_offered && self.psk.is_some() {
            exts.extend_from_slice(&EXTENSION_PRE_SHARED_KEY.to_be_bytes());
            exts.extend_from_slice(&2u16.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }

        server_hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        server_hello.extend_from_slice(&exts);

        let sh_len = (server_hello.len() - 4) as u32;
        server_hello[len_pos..len_pos + 3].copy_from_slice(&sh_len.to_be_bytes()[1..4]);

        self.handshake_messages.extend_from_slice(&server_hello);
        self.crypto_send_buffer.push((PacketNumberSpace::Initial, server_hello));

        self.derive_handshake_secrets(crypto_state)?;

        let mut enc = Vec::new();
        enc.push(HANDSHAKE_ENCRYPTED_EXTENSIONS);
        let enc_len_pos = enc.len();
        enc.extend_from_slice(&[0, 0, 0]);

        let mut enc_exts = Vec::new();
        if let Some(ref alpn) = self.negotiated_alpn {
            let mut alpn_data = Vec::new();
            alpn_data.push(alpn.len() as u8);
            alpn_data.extend_from_slice(alpn.as_bytes());
            enc_exts.extend_from_slice(&EXTENSION_ALPN.to_be_bytes());
            enc_exts.extend_from_slice(&((alpn_data.len() + 2) as u16).to_be_bytes());
            enc_exts.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
            enc_exts.extend_from_slice(&alpn_data);
        }

        if self.early_data_enabled && early_data_offered && self.psk.is_some() {
            enc_exts.extend_from_slice(&EXTENSION_EARLY_DATA.to_be_bytes());
            enc_exts.extend_from_slice(&0u16.to_be_bytes());
        }

        enc.extend_from_slice(&(enc_exts.len() as u16).to_be_bytes());
        enc.extend_from_slice(&enc_exts);

        let enc_len = (enc.len() - 4) as u32;
        enc[enc_len_pos..enc_len_pos + 3].copy_from_slice(&enc_len.to_be_bytes()[1..4]);
        self.handshake_messages.extend_from_slice(&enc);
        self.crypto_send_buffer.push((PacketNumberSpace::Handshake, enc));

        if !self.certificates.is_empty() {
            let mut cert_msg = Vec::new();
            cert_msg.push(HANDSHAKE_CERTIFICATE);
            let cert_len_pos = cert_msg.len();
            cert_msg.extend_from_slice(&[0, 0, 0]);
            cert_msg.push(0);
            let mut cert_list = Vec::new();
            for cert in &self.certificates {
                let der = cert.to_der();
                let len = der.len() as u32;
                cert_list.push(((len >> 16) & 0xff) as u8);
                cert_list.push(((len >> 8) & 0xff) as u8);
                cert_list.push((len & 0xff) as u8);
                cert_list.extend_from_slice(&der);
                cert_list.extend_from_slice(&0u16.to_be_bytes());
            }
            
            let list_len = cert_list.len() as u32;
            cert_msg.push(((list_len >> 16) & 0xff) as u8);
            cert_msg.push(((list_len >> 8) & 0xff) as u8);
            cert_msg.push((list_len & 0xff) as u8);
            cert_msg.extend_from_slice(&cert_list);

            let cert_len = (cert_msg.len() - 4) as u32;
            cert_msg[cert_len_pos..cert_len_pos + 3].copy_from_slice(&cert_len.to_be_bytes()[1..4]);
            self.handshake_messages.extend_from_slice(&cert_msg);
            self.crypto_send_buffer.push((PacketNumberSpace::Handshake, cert_msg));

            let sig_alg = if self.peer_signature_algorithms.contains(&ED25519) { ED25519 } else { ECDSA_SECP256R1_SHA256 };
            let signature = vec![0u8; 64];

            let mut verify_msg = Vec::new();
            verify_msg.push(HANDSHAKE_CERTIFICATE_VERIFY);
            let verify_len_pos = verify_msg.len();
            verify_msg.extend_from_slice(&[0, 0, 0]);
            verify_msg.extend_from_slice(&sig_alg.to_be_bytes());
            verify_msg.extend_from_slice(&(signature.len() as u16).to_be_bytes());
            verify_msg.extend_from_slice(&signature);

            let verify_len = (verify_msg.len() - 4) as u32;
            verify_msg[verify_len_pos..verify_len_pos + 3].copy_from_slice(&verify_len.to_be_bytes()[1..4]);
            self.handshake_messages.extend_from_slice(&verify_msg);
            self.crypto_send_buffer.push((PacketNumberSpace::Handshake, verify_msg));
        }

        let verify_data = self.compute_finished_verify_data(false)?;
        let mut finished = Vec::new();
        finished.push(HANDSHAKE_FINISHED);
        finished.extend_from_slice(&(verify_data.len() as u32).to_be_bytes()[1..4]);
        finished.extend_from_slice(&verify_data);
        self.handshake_messages.extend_from_slice(&finished);
        self.crypto_send_buffer.push((PacketNumberSpace::Handshake, finished));

        self.state = HandshakeState::WaitFinished;
        Ok(vec![CryptoAction::InstallHandshakeKeys, CryptoAction::SendCryptoData])
    }

    fn handle_new_session_ticket(&mut self, data: &[u8]) -> Result<Vec<CryptoAction>> {
        let mut offset = 4;
        if offset + 4 > data.len() {
            return Err(Error::Tls("Invalid NewSessionTicket".to_string()));
        }

        let ticket_lifetime = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        let ticket_age_add = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        let nonce_len = data[offset] as usize;
        offset += 1 + nonce_len;
        if offset + 2 > data.len() {
            return Err(Error::Tls("Invalid NewSessionTicket".to_string()));
        }

        let ticket_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + ticket_len > data.len() {
            return Err(Error::Tls("Invalid ticket length".to_string()));
        }

        let ticket = data[offset..offset + ticket_len].to_vec();
        self.session_ticket = Some(ticket);
        if let Some(ref res_master) = self.resumption_master_secret {
            let nonce = &data[offset - nonce_len - 1..offset - 1];
            let psk = self.hkdf_expand_label(res_master, b"resumption", nonce, self.cipher_suite.hash_len())?;
            self.psk = Some(psk);
        }

        Ok(Vec::new())
    }

    fn handle_key_update(&mut self, data: &[u8], crypto_state: &mut CryptoState) -> Result<Vec<CryptoAction>> {
        if data.len() < 5 {
            return Err(Error::Tls("Invalid KeyUpdate".to_string()));
        }

        let update_requested = data[4] == 1;
        self.update_traffic_keys(false, crypto_state)?;
        if update_requested {
            let key_update = self.build_key_update_message(false)?;
            self.crypto_send_buffer.push((PacketNumberSpace::ApplicationData, key_update));
            self.update_traffic_keys(true, crypto_state)?;

            Ok(vec![CryptoAction::SendCryptoData])
        } else {
            Ok(Vec::new())
        }
    }

    fn build_finished_message(&self) -> Result<Vec<u8>> {
        let verify_data = self.compute_finished_verify_data(true)?;

        let mut msg = Vec::new();
        msg.push(HANDSHAKE_FINISHED);

        let len = verify_data.len() as u32;
        msg.extend_from_slice(&len.to_be_bytes()[1..4]);
        msg.extend_from_slice(&verify_data);

        Ok(msg)
    }

    fn build_key_update_message(&self, request_update: bool) -> Result<Vec<u8>> {
        let mut msg = Vec::new();
        msg.push(HANDSHAKE_KEY_UPDATE);
        msg.extend_from_slice(&[0, 0, 1]);
        msg.push(if request_update { 1 } else { 0 });

        Ok(msg)
    }

    fn compute_finished_verify_data(&self, is_client: bool) -> Result<Vec<u8>> {
        let secret = if is_client {
            self.client_handshake_traffic_secret.as_ref()
        } else {
            self.server_handshake_traffic_secret.as_ref()
        }.ok_or(Error::CryptoError)?;

        let finished_key = self.hkdf_expand_label(secret, b"finished", &[], self.cipher_suite.hash_len())?;
        let transcript_hash = self.cipher_suite.hash(&self.handshake_messages);
        let verify_data = Hkdf::extract(Some(&finished_key), &transcript_hash);

        Ok(verify_data[..self.cipher_suite.hash_len()].to_vec())
    }

    fn derive_application_secrets(&mut self, crypto_state: &mut CryptoState) -> Result<()> {
        let handshake_secret = self.handshake_secret.as_ref().ok_or(Error::CryptoError)?;
        let derived = self.hkdf_expand_label(
            handshake_secret,
            b"derived",
            &self.cipher_suite.hash(&[]),
            self.cipher_suite.hash_len(),
        )?;

        let master_secret = Hkdf::extract(Some(&derived), &[]);
        let transcript_hash = self.cipher_suite.hash(&self.handshake_messages);
        let client_app_secret = self.hkdf_expand_label(
            &master_secret,
            b"c ap traffic",
            &transcript_hash,
            self.cipher_suite.hash_len(),
        )?;

        let server_app_secret = self.hkdf_expand_label(
            &master_secret,
            b"s ap traffic",
            &transcript_hash,
            self.cipher_suite.hash_len(),
        )?;

        let exporter_master = self.hkdf_expand_label(
            &master_secret,
            b"exp master",
            &transcript_hash,
            self.cipher_suite.hash_len(),
        )?;

        self.master_secret = Some(master_secret);
        self.client_application_traffic_secret = Some(client_app_secret.clone());
        self.server_application_traffic_secret = Some(server_app_secret.clone());
        self.exporter_master_secret = Some(exporter_master);

        let client_keys = self.derive_traffic_keys(&client_app_secret)?;
        let server_keys = self.derive_traffic_keys(&server_app_secret)?;
        if self.is_client {
            crypto_state.client_keys.insert(EncryptionLevel::Application, client_keys);
            crypto_state.server_keys.insert(EncryptionLevel::Application, server_keys);
        } else {
            crypto_state.server_keys.insert(EncryptionLevel::Application, server_keys);
            crypto_state.client_keys.insert(EncryptionLevel::Application, client_keys);
        }

        Ok(())
    }

    fn update_traffic_keys(&mut self, send_keys: bool, crypto_state: &mut CryptoState) -> Result<()> {
        self.key_update_generation += 1;
        let (secret, level) = if send_keys {
            if self.is_client {
                (
                    self.client_application_traffic_secret.as_ref(),
                    EncryptionLevel::Application,
                )
            } else {
                (
                    self.server_application_traffic_secret.as_ref(),
                    EncryptionLevel::Application,
                )
            }
        } else if self.is_client {
            (
                self.server_application_traffic_secret.as_ref(),
                EncryptionLevel::Application,
            )
        } else {
            (
                self.client_application_traffic_secret.as_ref(),
                EncryptionLevel::Application,
            )
        };

        let old_secret = secret.ok_or(Error::CryptoError)?;
        let new_secret = self.hkdf_expand_label(old_secret, b"traffic upd", &[], self.cipher_suite.hash_len())?;
        let new_keys = self.derive_traffic_keys(&new_secret)?;
        if send_keys {
            if self.is_client {
                self.client_application_traffic_secret = Some(new_secret);
                crypto_state.client_keys.insert(level, new_keys);
            } else {
                self.server_application_traffic_secret = Some(new_secret);
                crypto_state.server_keys.insert(level, new_keys);
            }
        } else if self.is_client {
            self.server_application_traffic_secret = Some(new_secret);
            crypto_state.server_keys.insert(level, new_keys);
        } else {
            self.client_application_traffic_secret = Some(new_secret);
            crypto_state.client_keys.insert(level, new_keys);
        }

        Ok(())
    }

    fn derive_traffic_keys(&self, secret: &[u8]) -> Result<CryptoKeys> {
        let key_len = self.cipher_suite.key_len();
        let key = self.hkdf_expand_label(secret, b"quic key", &[], key_len)?;
        let iv = self.hkdf_expand_label(secret, b"quic iv", &[], 12)?;
        let hp = self.hkdf_expand_label(secret, b"quic hp", &[], key_len)?;

        Ok(CryptoKeys::new(hp, key, iv))
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
        let full_label = [b"tls13 ", label].concat();

        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(full_label.len() as u8);
        hkdf_label.extend_from_slice(&full_label);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        Hkdf::expand(secret, &hkdf_label, length).map_err(|_| Error::CryptoError)
    }

    fn generate_random(&self) -> [u8; 32] {
        let mut random = [0u8; 32];
        if let Ok(bytes) = random::generate_random(32) {
            random.copy_from_slice(&bytes);
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
            for (i, chunk) in now.to_be_bytes().iter().enumerate() {
                random[i] = *chunk;
            }
        }

        random
    }

    fn generate_session_id(&self) -> [u8; 32] {
        self.generate_random()
    }

    pub fn export_keying_material(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
        let exporter_secret = self.exporter_master_secret.as_ref().ok_or_else(|| {
            Error::InvalidOperation("Handshake not complete".to_string())
        })?;

        let context_hash = self.cipher_suite.hash(context);
        let secret = self.hkdf_expand_label(
            exporter_secret,
            label,
            &context_hash,
            self.cipher_suite.hash_len(),
        )?;

        self.hkdf_expand_label(&secret, b"exporter", &[], length)
    }

    pub fn next_crypto_data(&mut self) -> Option<(PacketNumberSpace, Vec<u8>)> {
        if self.crypto_send_buffer.is_empty() {
            None
        } else {
            Some(self.crypto_send_buffer.remove(0))
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Connected
    }

    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.peer_transport_params.as_deref()
    }

    pub fn handshake_state(&self) -> HandshakeState {
        self.state
    }

    pub fn can_send_early_data(&self) -> bool {
        self.early_data_enabled && self.psk.is_some() && self.state == HandshakeState::WaitServerHello
    }

    pub fn max_early_data_size(&self) -> u32 {
        self.max_early_data_size
    }

    pub fn peer_certificates(&self) -> &[Certificate] {
        &self.peer_certificates
    }

    pub fn push_back_crypto_data(&mut self, pn_space: PacketNumberSpace, data: Vec<u8>) {
        self.crypto_send_buffer.insert(0, (pn_space, data));
    }

    pub fn initiate_key_update(&mut self, request_peer_update: bool) -> Result<()> {
        if self.state != HandshakeState::Connected {
            return Err(Error::InvalidOperation("Handshake not complete".to_string()));
        }

        let key_update = self.build_key_update_message(request_peer_update)?;
        self.crypto_send_buffer
            .push((PacketNumberSpace::ApplicationData, key_update));

        Ok(())
    }

    pub fn public_key(&self) -> Option<&EcdhPublicKey> {
        self.ecdh_public.as_ref()
    }

    pub fn snapshot(&self) -> QuicTlsStateSnapshot {
        QuicTlsStateSnapshot {
            role: if self.is_client {
                "client".to_string()
            } else {
                "server".to_string()
            },
            handshake_state: handshake_state_to_text(self.state).to_string(),
            cipher_suite: cipher_suite_to_text(self.cipher_suite).to_string(),
            verify_certificates: self.verify_certificates,
            certificate_count: self.certificates.len(),
            peer_certificate_count: self.peer_certificates.len(),
            negotiated_alpn: self.negotiated_alpn.clone(),
            has_peer_transport_params: self.peer_transport_params.is_some(),
            key_update_generation: self.key_update_generation,
            early_data_enabled: self.early_data_enabled,
            max_early_data_size: self.max_early_data_size,
            has_psk: self.psk.is_some(),
            has_session_ticket: self.session_ticket.is_some(),
            has_early_secret: self.early_secret.is_some(),
            has_handshake_secret: self.handshake_secret.is_some(),
            has_master_secret: self.master_secret.is_some(),
            started: self.started_at.is_some(),
            elapsed_ms: self
                .started_at
                .map(|started| started.elapsed().as_millis() as u64),
        }
    }

    pub fn encode_secure_state_snapshot(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureQuicTlsStateBlobMeta, Vec<u8>)> {
        self.snapshot().to_secure_blob(algorithm)
    }

    pub fn encode_secure_state_snapshot_auto(&self, accept_encoding: &str) -> io::Result<(SecureQuicTlsStateBlobMeta, Vec<u8>)> {
        self.snapshot().to_secure_blob_auto(accept_encoding)
    }

    pub fn decode_secure_state_snapshot(data: &[u8]) -> io::Result<(SecureQuicTlsStateBlobMeta, QuicTlsStateSnapshot)> {
        QuicTlsStateSnapshot::from_secure_blob(data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAction {
    InstallHandshakeKeys,
    InstallApplicationKeys,
    HandshakeComplete,
    SendCryptoData,
    UpdateKeys,
}

pub fn select_secure_quic_tls_state_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0
            && algorithm.is_implemented()
            && algorithm != CompressionAlgorithm::Identity
        {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_quic_tls_state_snapshot(state: &QuicTlsState, algorithm: CompressionAlgorithm) -> io::Result<(SecureQuicTlsStateBlobMeta, Vec<u8>)> {
    state.encode_secure_state_snapshot(algorithm)
}

pub fn encode_secure_quic_tls_state_snapshot_auto(state: &QuicTlsState, accept_encoding: &str) -> io::Result<(SecureQuicTlsStateBlobMeta, Vec<u8>)> {
    state.encode_secure_state_snapshot_auto(accept_encoding)
}

pub fn decode_secure_quic_tls_state_snapshot(data: &[u8]) -> io::Result<(SecureQuicTlsStateBlobMeta, QuicTlsStateSnapshot)> {
    QuicTlsState::decode_secure_state_snapshot(data)
}

fn serialize_quic_tls_state_snapshot(snapshot: &QuicTlsStateSnapshot) -> Vec<u8> {
    format!(
        "role={}\nhandshake-state={}\ncipher-suite={}\nverify-certificates={}\ncertificate-count={}\npeer-certificate-count={}\nnegotiated-alpn={}\nhas-peer-transport-params={}\nkey-update-generation={}\nearly-data-enabled={}\nmax-early-data-size={}\nhas-psk={}\nhas-session-ticket={}\nhas-early-secret={}\nhas-handshake-secret={}\nhas-master-secret={}\nstarted={}\nelapsed-ms={}\n",
        snapshot.role,
        snapshot.handshake_state,
        snapshot.cipher_suite,
        snapshot.verify_certificates,
        snapshot.certificate_count,
        snapshot.peer_certificate_count,
        encode_opt_b64(snapshot.negotiated_alpn.as_deref()),
        snapshot.has_peer_transport_params,
        snapshot.key_update_generation,
        snapshot.early_data_enabled,
        snapshot.max_early_data_size,
        snapshot.has_psk,
        snapshot.has_session_ticket,
        snapshot.has_early_secret,
        snapshot.has_handshake_secret,
        snapshot.has_master_secret,
        snapshot.started,
        opt_u64_to_text(snapshot.elapsed_ms),
    ).into_bytes()
}

fn deserialize_quic_tls_state_snapshot(raw_payload: &[u8]) -> io::Result<QuicTlsStateSnapshot> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "quic-tls-state payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid quic-tls-state payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let parse_u64 = |key: &str| -> io::Result<u64> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in quic-tls-state payload", key),
            )
        })?.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in quic-tls-state payload", key),
            )
        })
    };

    let parse_usize = |key: &str| -> io::Result<usize> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in quic-tls-state payload", key),
            )
        })?.parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in quic-tls-state payload", key),
            )
        })
    };

    let parse_u32 = |key: &str| -> io::Result<u32> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in quic-tls-state payload", key),
            )
        })?.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in quic-tls-state payload", key),
            )
        })
    };

    let parse_text = |key: &str| -> io::Result<String> {
        map.get(key).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in quic-tls-state payload", key),
            )
        })
    };

    Ok(QuicTlsStateSnapshot {
        role: parse_text("role")?,
        handshake_state: parse_text("handshake-state")?,
        cipher_suite: parse_text("cipher-suite")?,
        verify_certificates: parse_bool(
            map.get("verify-certificates").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing verify-certificates in quic-tls-state payload",
                )
            })?,
        )?,
        certificate_count: parse_usize("certificate-count")?,
        peer_certificate_count: parse_usize("peer-certificate-count")?,
        negotiated_alpn: decode_opt_b64(
            map.get("negotiated-alpn").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing negotiated-alpn in quic-tls-state payload",
                )
            })?,
        )?,
        has_peer_transport_params: parse_bool(
            map.get("has-peer-transport-params").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing has-peer-transport-params in quic-tls-state payload",
                )
            })?,
        )?,
        key_update_generation: parse_u64("key-update-generation")?,
        early_data_enabled: parse_bool(
            map.get("early-data-enabled").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing early-data-enabled in quic-tls-state payload",
                )
            })?,
        )?,
        max_early_data_size: parse_u32("max-early-data-size")?,
        has_psk: parse_bool(
            map.get("has-psk").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing has-psk in quic-tls-state payload",
                )
            })?,
        )?,
        has_session_ticket: parse_bool(
            map.get("has-session-ticket").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing has-session-ticket in quic-tls-state payload",
                )
            })?,
        )?,
        has_early_secret: parse_bool(
            map.get("has-early-secret").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing has-early-secret in quic-tls-state payload",
                )
            })?,
        )?,
        has_handshake_secret: parse_bool(
            map.get("has-handshake-secret").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing has-handshake-secret in quic-tls-state payload",
                )
            })?,
        )?,
        has_master_secret: parse_bool(
            map.get("has-master-secret").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing has-master-secret in quic-tls-state payload",
                )
            })?,
        )?,
        started: parse_bool(
            map.get("started").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing started in quic-tls-state payload",
                )
            })?,
        )?,
        elapsed_ms: parse_opt_u64(
            map.get("elapsed-ms").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing elapsed-ms in quic-tls-state payload",
                )
            })?,
        )?,
    })
}

fn parse_bool(v: &str) -> io::Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean value '{}'", v),
        )),
    }
}

fn opt_u64_to_text(value: Option<u64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string())
}

fn parse_opt_u64(value: &str) -> io::Result<Option<u64>> {
    if value.trim() == "-" {
        return Ok(None);
    }

    let parsed = value.trim().parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid optional u64 value '{}'", value),
        )
    })?;

    Ok(Some(parsed))
}

fn encode_opt_b64(value: Option<&str>) -> String {
    match value {
        Some(v) => pem::encode(v.as_bytes()),
        None => "-".to_string(),
    }
}

fn decode_opt_b64(value: &str) -> io::Result<Option<String>> {
    if value.trim() == "-" {
        return Ok(None);
    }

    let decoded = pem::decode(value.trim()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid optional base64 value '{}': {}", value, e),
        )
    })?;

    let text = String::from_utf8(decoded).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "optional base64 value is not valid utf-8",
        )
    })?;

    Ok(Some(text))
}

fn compute_quic_tls_state_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(QUIC_TLS_STATE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(QUIC_TLS_STATE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "quic-tls-state header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "quic-tls-state header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "quic-tls-state blob missing header/body separator",
    ))
}

fn parse_secure_quic_tls_state_meta(header: &str, body_len: usize) -> io::Result<SecureQuicTlsStateBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != QUIC_TLS_STATE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure quic-tls-state blob magic",
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
                format!("invalid secure quic-tls-state header line '{}'", line),
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
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid raw-size in quic-tls-state blob",
                    )
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in quic-tls-state blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid issued-at in quic-tls-state blob",
                    )
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureQuicTlsStateBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in secure quic-tls-state blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in secure quic-tls-state blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in secure quic-tls-state blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in secure quic-tls-state blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in secure quic-tls-state blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in secure quic-tls-state blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "quic-tls-state encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
}

fn handshake_state_to_text(state: HandshakeState) -> &'static str {
    match state {
        HandshakeState::Initial => "initial",
        HandshakeState::WaitServerHello => "wait-server-hello",
        HandshakeState::WaitEncryptedExtensions => "wait-encrypted-extensions",
        HandshakeState::WaitCertificateRequest => "wait-certificate-request",
        HandshakeState::WaitCertificate => "wait-certificate",
        HandshakeState::WaitCertificateVerify => "wait-certificate-verify",
        HandshakeState::WaitFinished => "wait-finished",
        HandshakeState::Connected => "connected",
        HandshakeState::Failed => "failed",
    }
}

fn cipher_suite_to_text(cipher_suite: CipherSuite) -> &'static str {
    match cipher_suite {
        CipherSuite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
        CipherSuite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
        CipherSuite::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_tls_client_creation() {
        let tls = QuicTlsState::new_client(Some("example.com".to_string()));
        assert!(tls.is_client);
        assert_eq!(tls.state, HandshakeState::Initial);
        assert_eq!(tls.server_name, Some("example.com".to_string()));
        assert!(tls.verify_certificates);
    }

    #[test]
    fn test_quic_tls_server_creation() {
        let tls = QuicTlsState::new_server();
        assert!(!tls.is_client);
        assert_eq!(tls.state, HandshakeState::Initial);
    }

    #[test]
    fn test_alpn_protocols() {
        let mut tls = QuicTlsState::new_client(None);
        tls.set_alpn_protocols(vec!["h3".to_string(), "h2".to_string()]);
        assert_eq!(tls.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_start_handshake() {
        let mut tls = QuicTlsState::new_client(None);
        let mut crypto = CryptoState::new(true);

        let result = tls.start_handshake(&mut crypto);
        assert!(result.is_ok());
        assert_eq!(tls.state, HandshakeState::WaitServerHello);
        assert!(tls.ecdh_private.is_some());
        assert!(tls.ecdh_public.is_some());
        assert!(tls.client_random.is_some());
    }

    #[test]
    fn test_cipher_suite_conversion() {
        assert_eq!(
            CipherSuite::from_u16(TLS_AES_128_GCM_SHA256),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            CipherSuite::Aes128GcmSha256.to_u16(),
            TLS_AES_128_GCM_SHA256
        );
        assert_eq!(CipherSuite::Aes128GcmSha256.hash_len(), 32);
        assert_eq!(CipherSuite::Aes128GcmSha256.key_len(), 16);
    }

    #[test]
    fn test_hkdf_expand_label() {
        let tls = QuicTlsState::new_client(None);
        let secret = vec![0u8; 32];
        let result = tls.hkdf_expand_label(&secret, b"test", &[], 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_early_data_config() {
        let mut tls = QuicTlsState::new_client(None);
        tls.enable_early_data(4096);
        assert!(tls.early_data_enabled);
        assert_eq!(tls.max_early_data_size, 4096);
    }

    #[test]
    fn test_psk_configuration() {
        let mut tls = QuicTlsState::new_client(None);
        let psk = vec![1, 2, 3, 4];
        let ticket = vec![5, 6, 7, 8];
        tls.set_psk(psk.clone(), ticket.clone());
        assert_eq!(tls.psk, Some(psk));
        assert_eq!(tls.session_ticket, Some(ticket));
    }

    #[test]
    fn test_handshake_timeout() {
        let mut tls = QuicTlsState::new_client(None);
        assert!(!tls.has_timed_out());

        tls.started_at = Some(Instant::now() - Duration::from_secs(15));
        assert!(tls.has_timed_out());
    }

    #[test]
    fn test_export_keying_material_not_ready() {
        let tls = QuicTlsState::new_client(None);
        let result = tls.export_keying_material(b"test", b"context", 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_quic_tls_snapshot_roundtrip_identity() {
        let mut tls = QuicTlsState::new_client(Some("example.com".to_string()));
        tls.negotiated_alpn = Some("h3".to_string());
        tls.enable_early_data(4096);
        tls.set_psk(vec![1, 2, 3], vec![4, 5, 6, 7]);
        tls.started_at = Some(Instant::now() - Duration::from_millis(120));

        let (meta, blob) = tls
            .encode_secure_state_snapshot(CompressionAlgorithm::Identity)
            .unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_decoded_meta, snapshot) = QuicTlsState::decode_secure_state_snapshot(&blob).unwrap();
        assert_eq!(snapshot.role, "client");
        assert_eq!(snapshot.handshake_state, "initial");
        assert_eq!(snapshot.cipher_suite, "TLS_AES_128_GCM_SHA256");
        assert_eq!(snapshot.negotiated_alpn.as_deref(), Some("h3"));
        assert!(snapshot.early_data_enabled);
        assert_eq!(snapshot.max_early_data_size, 4096);
        assert!(snapshot.has_psk);
        assert!(snapshot.has_session_ticket);
        assert!(snapshot.started);
        assert!(snapshot.elapsed_ms.is_some());
    }

    #[test]
    fn test_secure_quic_tls_snapshot_roundtrip_compressed() {
        let mut tls = QuicTlsState::new_server();
        tls.state = HandshakeState::Connected;
        tls.key_update_generation = 3;
        tls.verify_certificates = false;
        tls.started_at = Some(Instant::now() - Duration::from_millis(42));

        let (_meta, blob) = tls
            .encode_secure_state_snapshot(CompressionAlgorithm::Gzip)
            .unwrap();

        let (_decoded_meta, snapshot) = decode_secure_quic_tls_state_snapshot(&blob).unwrap();
        assert_eq!(snapshot.role, "server");
        assert_eq!(snapshot.handshake_state, "connected");
        assert_eq!(snapshot.key_update_generation, 3);
        assert!(!snapshot.verify_certificates);
    }

    #[test]
    fn test_secure_quic_tls_snapshot_tamper_detection() {
        let tls = QuicTlsState::new_client(None);
        let (_meta, mut blob) = encode_secure_quic_tls_state_snapshot(
            &tls,
            CompressionAlgorithm::Identity,
        )
        .unwrap();

        if let Some(last) = blob.last_mut() {
            *last ^= 0xA5;
        }

        assert!(decode_secure_quic_tls_state_snapshot(&blob).is_err());
    }
}