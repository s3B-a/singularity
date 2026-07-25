use crate::crypto::asymmetric::{ecdh, rsa};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::{pem, x509};
use crate::crypto::hash::sha2::{self, sha256};
use crate::crypto::kdf::hkdf;
use crate::crypto::random;
use crate::crypto::symmetric::chacha20::ChaCha20Poly1305;
use crate::crypto::symmetric::gcm::GcmOptimized;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::http::http2::alpn::{AlpnNegotiator, AlpnProtocol};
use crate::net::https::trust_store::TrustStore;
use crate::net::tcp::TcpStream;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_VERSION_1_2: u16 = 0x0303;

const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_TYPE_ALERT: u8 = 21;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_CERTIFICATE: u8 = 11;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_FINISHED: u8 = 20;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;

const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;

const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(7200);

const SECURE_RECORD_MAGIC: &[u8; 8] = b"STLSREC1";
const SECURE_RECORD_VERSION: u8 = 1;
const SECURE_RECORD_FLAG_COMPRESSED: u8 = 0x01;
const SECURE_RECORD_BASE_HEADER_LEN: usize = 8 + 1 + 1 + 1 + 1 + 4 + 4;
const SECURE_RECORD_DIGEST_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct TlsRecordSecurityCfg {
    pub enable_integrity: bool,
    pub nonce_len: usize,
    pub context: String,
}

#[derive(Debug, Clone)]
pub struct TlsRecordCompressionCfg {
    pub enabled: bool,
    pub min_size: usize,
    pub preferred_algorithm: CompressionAlgorithm,
    pub level: CompressionLevel,
    pub fallback_to_identity_on_error: bool,
}

#[derive(Debug, Clone)]
pub struct TlsCfg {
    pub cert_chain: Vec<x509::Certificate>,
    pub private_key: rsa::RsaPrivateKey,
    pub supported_ciphers: Vec<String>,
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    pub verify_peer: bool,
    pub trust_store: TrustStore,
    pub session_cache: Option<SessionCache>,
    pub enable_session_resumption: bool,
    pub record_security: TlsRecordSecurityCfg,
    pub record_compression: TlsRecordCompressionCfg,
}

#[derive(Debug, Clone)]
pub struct TlsSession {
    pub session_id: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub cipher_suite: u16,
    pub created_at: SystemTime,
    pub server_name: String,
    pub protocol_version: TlsVersion,
    pub ticket: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls1_2,
    Tls1_3,
}

#[derive(Debug)]
pub enum TlsError {
    Io(std::io::Error),
    HandshakeFailed(String),
    InvalidCertificate(String),
    AlertReceived(u8, u8),
    DecodeError(String),
    UnsupportedVersion,
    NoSharedCipher,
    VerificationFailed(String),
    CipherError(String),
    CompressionError(String),
    IntegrityError(String),
    ProtocolNegotiationFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Initial,
    Handshaking,
    Connected,
    Closed,
}

#[derive(Debug, Clone)]
struct TlsKeys {
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
    client_write_iv: Vec<u8>,
    server_write_iv: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionCache {
    sessions: Arc<Mutex<HashMap<String, TlsSession>>>,
}

#[derive(Debug)]
pub struct TlsStream {
    stream: TcpStream,
    config: TlsCfg,
    state: ConnectionState,
    version: TlsVersion,
    cipher_suite: u16,
    keys: Option<TlsKeys>,
    handshake_msg: Vec<u8>,
    client_seq: u64,
    server_seq: u64,
    is_client: bool,
    buffer: Vec<u8>,
    pub server_name: Option<String>,
    session_id: Vec<u8>,
    resuming_session: bool,
    alpn_negotiator: AlpnNegotiator,
    negotiated_protocol: Option<AlpnProtocol>,
    negotiated_record_compression: CompressionAlgorithm,
}

impl TlsSession {
    pub fn new(session_id: Vec<u8>, master_secret: Vec<u8>, cipher_suite: u16, server_name: String, protocol_version: TlsVersion) -> Self {
        Self {
            session_id,
            master_secret,
            cipher_suite,
            created_at: SystemTime::now(),
            server_name,
            protocol_version,
            ticket: None,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.created_at.elapsed().map(|elapsed| elapsed < MAX_SESSION_LIFETIME).unwrap_or(false)
    }

    pub fn age(&self) -> u32 {
        self.created_at.elapsed().map(|d| d.as_secs() as u32).unwrap_or(u32::MAX)
    }
}

impl SessionCache {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, key: String, session: TlsSession) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(key, session);
        }
    }

    pub fn get(&self, key: &str) -> Option<TlsSession> {
        self.sessions.lock().ok().and_then(|sessions| sessions.get(key).cloned())
    }

    pub fn remove(&self, key: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(key);
        }
    }

    pub fn cleanup_expired(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, session| session.is_valid());
        }
    }

    pub fn clear(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.clear();
        }
    }
}

impl TlsStream {
    pub fn new_client(stream: TcpStream, config: TlsCfg) -> Result<Self, TlsError> {
        Self::new_client_with_sni(stream, config, String::new())
    }

    pub fn new_client_with_sni(stream: TcpStream, config: TlsCfg, server_name: String) -> Result<Self, TlsError> {
        let mut tls_stream = TlsStream {
            stream,
            config,
            state: ConnectionState::Initial,
            version: TlsVersion::Tls1_3,
            cipher_suite: 0,
            keys: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: true,
            buffer: Vec::new(),
            server_name: Some(server_name),
            session_id: Vec::new(),
            resuming_session: false,
            alpn_negotiator: AlpnNegotiator::new(),
            negotiated_protocol: None,
            negotiated_record_compression: CompressionAlgorithm::Identity,
        };

        tls_stream.client_handshake()?;
        Ok(tls_stream)
    }

    pub fn new_server(stream: TcpStream, config: TlsCfg) -> Result<Self, TlsError> {
        let mut tls_stream = TlsStream {
            stream,
            config,
            state: ConnectionState::Initial,
            version: TlsVersion::Tls1_3,
            cipher_suite: 0,
            keys: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: false,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
            alpn_negotiator: AlpnNegotiator::new(),
            negotiated_protocol: None,
            negotiated_record_compression: CompressionAlgorithm::Identity,
        };

        tls_stream.server_handshake()?;
        Ok(tls_stream)
    }

    fn client_handshake(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;
        let client_random = self.generate_random();
        let ecdh_key = ecdh::EcdhPrivateKey::generate(ecdh::EcdhCurve::X25519).map_err(|e| {
            TlsError::HandshakeFailed(format!("Failed to generate ECDH key: {:?}", e))
        })?;

        let client_public = ecdh_key.public_key();
        let resumable_session = if self.config.enable_session_resumption {
            if let (Some(cache), Some(server_name)) = (&self.config.session_cache, &self.server_name) {
                cache.get(server_name).filter(|s| s.is_valid())
            } else {
                None
            }
        } else {
            None
        };

        let client_hello = if let Some(ref session) = resumable_session {
            self.resuming_session = true;
            self.session_id = session.session_id.clone();
            self.build_resumption_client_hello(&client_random, &client_public, session)?
        } else {
            self.build_client_hello(&client_random, &client_public)?
        };

        self.handshake_msg.extend_from_slice(&client_hello);
        self.send_handshake_message(HANDSHAKE_CLIENT_HELLO, &client_hello)?;
        let (server_hello_type, server_hello) = self.recieve_handshake_message()?;
        if server_hello_type != HANDSHAKE_SERVER_HELLO {
            return Err(TlsError::HandshakeFailed(
                "Expected ServerHello".to_string(),
            ));
        }

        let server_alpn_data = self.extract_alpn_from_handshake(&server_hello)?;
        let negotiated = self.alpn_negotiator.negotiate(&server_alpn_data).ok();
        self.negotiated_protocol = negotiated;
        self.handshake_msg.extend_from_slice(&server_hello);
        
        let (
            server_random,
            selected_cipher,
            peer_public_key,
            negotiated_version,
            session_resumed,
        ) = self.parse_server_hello(&server_hello)?;

        self.version = negotiated_version;
        self.cipher_suite = selected_cipher;
        if session_resumed && self.resuming_session {
            if let Some(session) = resumable_session {
                let shared_secret = session.master_secret;
                self.derive_keys(&client_random, &server_random, &shared_secret)?;
                self.state = ConnectionState::Connected;
                return Ok(());
            }
        }

        self.resuming_session = false;
        if peer_public_key.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "No peer public key received".to_string(),
            ));
        }

        let peer_public =
            ecdh::EcdhPublicKey::from_bytes(ecdh::EcdhCurve::X25519, &peer_public_key).map_err(
                |_| TlsError::CipherError("Invalid peer public key".to_string()),
            )?;

        let shared_secret = ecdh_key.exchange(&peer_public).map_err(|e| {
            TlsError::HandshakeFailed(format!("ECDH exchange failed: {:?}", e))
        })?;

        self.derive_keys(&client_random, &server_random, &shared_secret)?;
        loop {
            let (msg_type, msg_data) = self.recieve_handshake_message()?;
            match msg_type {
                HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                    self.handshake_msg.extend_from_slice(&msg_data);
                }
                HANDSHAKE_CERTIFICATE => {
                    self.handshake_msg.extend_from_slice(&msg_data);
                    self.verify_certificate(&msg_data)?;
                }
                HANDSHAKE_CERTIFICATE_VERIFY => {
                    self.handshake_msg.extend_from_slice(&msg_data);
                }
                HANDSHAKE_FINISHED => {
                    self.verify_finished(&msg_data, false)?;
                    break;
                }
                HANDSHAKE_NEW_SESSION_TICKET => {
                    self.handle_new_session_ticket(&msg_data)?;
                }
                _ => {
                    return Err(TlsError::HandshakeFailed(format!(
                        "Unexpected handshake message: {}",
                        msg_type
                    )));
                }
            }
        }

        let finished_msg = self.compute_finished(true)?;
        self.send_handshake_message(HANDSHAKE_FINISHED, &finished_msg)?;
        self.state = ConnectionState::Connected;
        self.save_session(&shared_secret)?;

        Ok(())
    }

    fn server_handshake(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;
        let (client_hello_type, client_hello) = self.recieve_handshake_message()?;
        if client_hello_type != HANDSHAKE_CLIENT_HELLO {
            return Err(TlsError::HandshakeFailed(
                "Expected ClientHello".to_string(),
            ));
        }

        self.handshake_msg.extend_from_slice(&client_hello);
        let (client_random, client_ciphers, client_public_key, client_versions) = self.parse_client_hello(&client_hello)?;
        self.version = self.negotiate_version(&client_versions)?;
        self.cipher_suite = self.select_cipher_suite(&client_ciphers)?;
        let ecdh_private = ecdh::EcdhPrivateKey::generate(ecdh::EcdhCurve::X25519).map_err(|e| {
            TlsError::HandshakeFailed(format!("Failed to generate ECDH key: {:?}", e))
        })?;

        let ecdh_public = ecdh_private.public_key();
        let server_random = self.generate_random();
        let server_hello = self.build_server_hello(&server_random, &ecdh_public)?;
        self.handshake_msg.extend_from_slice(&server_hello);
        self.send_handshake_message(HANDSHAKE_SERVER_HELLO, &server_hello)?;
        let peer_ecdh_public = ecdh::EcdhPublicKey::from_bytes(ecdh::EcdhCurve::X25519, &client_public_key).map_err(
            |e| TlsError::HandshakeFailed(format!("Invalid peer public key: {:?}", e)),
        )?;

        let shared_secret = ecdh_private.exchange(&peer_ecdh_public).map_err(|e| {
            TlsError::HandshakeFailed(format!("ECDH exchange failed: {:?}", e))
        })?;

        self.derive_handshake_keys(&shared_secret)?;
        let encrypted_extensions = self.build_encrypted_extensions()?;
        self.handshake_msg.extend_from_slice(&encrypted_extensions);
        self.send_handshake_message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &encrypted_extensions)?;
        if !self.config.cert_chain.is_empty() {
            let certificate = self.build_certificate()?;
            self.handshake_msg.extend_from_slice(&certificate);
            self.send_handshake_message(HANDSHAKE_CERTIFICATE, &certificate)?;

            let cert_verify = self.build_certificate_verify()?;
            self.handshake_msg.extend_from_slice(&cert_verify);
            self.send_handshake_message(HANDSHAKE_CERTIFICATE_VERIFY, &cert_verify)?;
        }

        let server_finished = self.compute_finished(false)?;
        self.handshake_msg.extend_from_slice(&server_finished);
        self.send_handshake_message(HANDSHAKE_FINISHED, &server_finished)?;
        self.derive_application_keys(&shared_secret)?;
        let (finished_type, client_finished) = self.recieve_handshake_message()?;
        if finished_type != HANDSHAKE_FINISHED {
            return Err(TlsError::HandshakeFailed("Expected Finished".to_string()));
        }

        self.verify_finished(&client_finished, true)?;
        self.state = ConnectionState::Connected;

        Ok(())
    }

    fn generate_random(&self) -> [u8; 32] {
        let mut random_bytes = [0u8; 32];
        let _ = random::fill_random(&mut random_bytes);
        random_bytes
    }

    fn parse_configured_cipher_suite(cipher: &str) -> Option<u16> {
        match cipher.trim() {
            "TLS_AES_128_GCM_SHA256" => Some(TLS_AES_128_GCM_SHA256),
            "TLS_AES_256_GCM_SHA384" => Some(TLS_AES_256_GCM_SHA384),
            "TLS_CHACHA20_POLY1305_SHA256" => Some(TLS_CHACHA20_POLY1305_SHA256),
            s if s.starts_with("0x") || s.starts_with("0X") => {
                u16::from_str_radix(&s[2..], 16).ok()
            }
            s => s.parse::<u16>().ok(),
        }
    }

    fn configured_cipher_suites(&self) -> Vec<u16> {
        let mut suites = Vec::new();
        for configured in &self.config.supported_ciphers {
            if let Some(suite) = Self::parse_configured_cipher_suite(configured) {
                suites.push(suite);
            }
        }

        if suites.is_empty() {
            suites.push(TLS_AES_256_GCM_SHA384);
            suites.push(TLS_AES_128_GCM_SHA256);
            suites.push(TLS_CHACHA20_POLY1305_SHA256);
        }

        suites
    }

    fn build_client_hello(&self, client_random: &[u8; 32], public_key: &ecdh::EcdhPublicKey) -> Result<Vec<u8>, TlsError> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        hello.extend_from_slice(client_random);
        hello.push(0);
        let suites = self.configured_cipher_suites();
        hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for suite in suites {
            hello.extend_from_slice(&suite.to_be_bytes());
        }

        hello.push(1);
        hello.push(0);
        let mut ext = Vec::new();
        if let Some(server_name) = &self.server_name {
            if !server_name.is_empty() {
                let host_bytes = server_name.as_bytes();
                let sni_list_len = 3 + host_bytes.len();
                let sni_ext_len = 2 + sni_list_len;

                ext.extend_from_slice(&0u16.to_be_bytes());
                ext.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
                ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
                ext.push(0);
                ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                ext.extend_from_slice(host_bytes);
            }
        }

        ext.extend_from_slice(&10u16.to_be_bytes());
        ext.extend_from_slice(&4u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&0x001du16.to_be_bytes());

        ext.extend_from_slice(&13u16.to_be_bytes());
        ext.extend_from_slice(&8u16.to_be_bytes());
        ext.extend_from_slice(&6u16.to_be_bytes());
        ext.extend_from_slice(&0x0804u16.to_be_bytes());
        ext.extend_from_slice(&0x0401u16.to_be_bytes());
        ext.extend_from_slice(&0x0403u16.to_be_bytes());
        if !self.alpn_negotiator.supported_protocols_wire().is_empty() {
            let protocols_wire = self.alpn_negotiator.supported_protocols_wire();
            let alpn_list_len = protocols_wire.len();
            ext.extend_from_slice(&16u16.to_be_bytes());
            ext.extend_from_slice(&((alpn_list_len + 2) as u16).to_be_bytes());
            ext.extend_from_slice(&(alpn_list_len as u16).to_be_bytes());
            ext.extend_from_slice(&protocols_wire);
        }

        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.push(2);
        ext.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());

        let key_bytes = public_key.to_bytes();
        let key_share_entry_len = 2 + 2 + key_bytes.len();
        let key_share_ext_len = 2 + key_share_entry_len;

        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&(key_share_ext_len as u16).to_be_bytes());
        ext.extend_from_slice(&(key_share_entry_len as u16).to_be_bytes());
        ext.extend_from_slice(&0x001du16.to_be_bytes());
        ext.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key_bytes);

        ext.extend_from_slice(&45u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.push(1);
        ext.push(1);

        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        Ok(hello)
    }

    fn build_resumption_client_hello(&self, client_random: &[u8; 32], public_key: &ecdh::EcdhPublicKey, session: &TlsSession) -> Result<Vec<u8>, TlsError> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        hello.extend_from_slice(client_random);
        hello.push(session.session_id.len() as u8);
        hello.extend_from_slice(&session.session_id);

        let suites = self.configured_cipher_suites();
        hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for suite in suites {
            hello.extend_from_slice(&suite.to_be_bytes());
        }

        hello.push(1);
        hello.push(0);

        let mut ext = Vec::new();
        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.push(2);
        ext.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());

        let public_key_bytes = public_key.to_bytes();
        let key_share_entry_len = 2 + 2 + public_key_bytes.len();
        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&((2 + key_share_entry_len) as u16).to_be_bytes());
        ext.extend_from_slice(&(key_share_entry_len as u16).to_be_bytes());
        ext.extend_from_slice(&0x001du16.to_be_bytes());
        ext.extend_from_slice(&(public_key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&public_key_bytes);

        ext.extend_from_slice(&45u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.push(1);
        ext.push(1);
        if let Some(ticket) = &session.ticket {
            ext.extend_from_slice(&41u16.to_be_bytes());

            let identities_len = 2 + ticket.len() + 4;
            let binders_len = 33;
            let psk_ext_len = 2 + identities_len + 2 + binders_len;

            ext.extend_from_slice(&(psk_ext_len as u16).to_be_bytes());

            ext.extend_from_slice(&(identities_len as u16).to_be_bytes());
            ext.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            ext.extend_from_slice(ticket);
            ext.extend_from_slice(&session.age().to_be_bytes());

            ext.extend_from_slice(&(binders_len as u16).to_be_bytes());
            ext.push(32);
            ext.extend_from_slice(&[0u8; 32]);
        }

        if let Some(host) = &self.server_name {
            if !host.is_empty() {
                let host_bytes = host.as_bytes();
                let sni_list_len = 3 + host_bytes.len();
                let sni_ext_len = 2 + sni_list_len;

                ext.extend_from_slice(&0u16.to_be_bytes());
                ext.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
                ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
                ext.push(0);
                ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                ext.extend_from_slice(host_bytes);
            }
        }

        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        Ok(hello)
    }

    fn build_server_hello(&self, server_random: &[u8; 32], public_key: &ecdh::EcdhPublicKey) -> Result<Vec<u8>, TlsError> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        hello.extend_from_slice(server_random);

        hello.push(0);
        hello.extend_from_slice(&self.cipher_suite.to_be_bytes());
        hello.push(0);

        let mut ext = Vec::new();
        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());

        let key_bytes = public_key.to_bytes();
        let key_share_len = 2 + 2 + key_bytes.len();
        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        ext.extend_from_slice(&0x001du16.to_be_bytes());
        ext.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key_bytes);
        if let Some(protocol) = self.negotiated_protocol {
            let proto_wire = protocol.wire_format();
            ext.extend_from_slice(&16u16.to_be_bytes());
            ext.extend_from_slice(&((2 + proto_wire.len()) as u16).to_be_bytes());
            ext.extend_from_slice(&(proto_wire.len() as u16).to_be_bytes());
            ext.extend_from_slice(proto_wire);
        }

        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        Ok(hello)
    }

    fn build_encrypted_extensions(&self) -> Result<Vec<u8>, TlsError> {
        let mut ext = Vec::new();
        if let Some(protocol) = self.negotiated_protocol {
            if !self.is_client {
                let proto_wire = protocol.wire_format();
                ext.extend_from_slice(&16u16.to_be_bytes());
                ext.extend_from_slice(&((2 + proto_wire.len()) as u16).to_be_bytes());
                ext.extend_from_slice(&(proto_wire.len() as u16).to_be_bytes());
                ext.extend_from_slice(proto_wire);
            }
        }

        if !self.is_client && self.server_name.is_some() {
            ext.extend_from_slice(&0u16.to_be_bytes());
            ext.extend_from_slice(&0u16.to_be_bytes());
        }

        let mut result = Vec::new();
        result.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        result.extend_from_slice(&ext);

        Ok(result)
    }

    fn build_certificate(&self) -> Result<Vec<u8>, TlsError> {
        let mut cert_msg = Vec::new();
        cert_msg.push(0);

        let mut cert_list = Vec::new();
        for cert in &self.config.cert_chain {
            let cert_der = cert.to_der();
            let cert_len = cert_der.len() as u32;
            cert_list.push(((cert_len >> 16) & 0xff) as u8);
            cert_list.push(((cert_len >> 8) & 0xff) as u8);
            cert_list.push((cert_len & 0xff) as u8);
            cert_list.extend_from_slice(&cert_der);
            cert_list.extend_from_slice(&0u16.to_be_bytes());
        }

        let list_len = cert_list.len() as u32;
        cert_msg.push(((list_len >> 16) & 0xff) as u8);
        cert_msg.push(((list_len >> 8) & 0xff) as u8);
        cert_msg.push((list_len & 0xff) as u8);
        cert_msg.extend_from_slice(&cert_list);

        Ok(cert_msg)
    }

    fn build_certificate_verify(&self) -> Result<Vec<u8>, TlsError> {
        let mut verify_msg = Vec::new();
        let transcript_hash = self.compute_transcript_hash();
        verify_msg.extend_from_slice(&0x0804u16.to_be_bytes());

        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&[0x20u8; 64]);
        if self.is_client {
            to_sign.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        } else {
            to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        }

        to_sign.push(0);
        to_sign.extend_from_slice(&transcript_hash);
        let signature = self.config.private_key.sign(&to_sign, rsa::RsaPadding::Pkcs1v15).map_err(|e| {
            TlsError::CipherError(format!(
                "Failed to sign CertificateVerify: {:?}",
                e
            ))
        })?;

        verify_msg.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        verify_msg.extend_from_slice(&signature);

        Ok(verify_msg)
    }

    fn compute_finished(&self, is_client: bool) -> Result<Vec<u8>, TlsError> {
        let transcript_hash = self.compute_transcript_hash();
        let finished_key = self.derive_finished_key(is_client)?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&finished_key);
        hasher.update(&transcript_hash);
        Ok(hasher.finalize().to_vec())
    }

    fn verify_finished(&self, finished_msg: &[u8], is_client: bool) -> Result<(), TlsError> {
        let expected = self.compute_finished(is_client)?;
        if !constant_time_eq(&expected, finished_msg) {
            return Err(TlsError::HandshakeFailed(
                "Finished verification failed".to_string(),
            ));
        }

        Ok(())
    }

    fn parse_client_hello(&self, data: &[u8]) -> Result<([u8; 32], Vec<u16>, Vec<u8>, Vec<u16>), TlsError> {
        if data.len() < 38 {
            return Err(TlsError::DecodeError("ClientHello too short".to_string()));
        }

        let mut pos = 2;
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError(
                "Invalid ClientHello format".to_string(),
            ));
        }

        let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut ciphers = Vec::new();
        for i in (0..cipher_len).step_by(2) {
            if pos + i + 1 >= data.len() {
                break;
            }

            ciphers.push(u16::from_be_bytes([data[pos + i], data[pos + i + 1]]));
        }

        pos += cipher_len;
        if pos >= data.len() {
            return Err(TlsError::DecodeError(
                "Invalid ClientHello format".to_string(),
            ));
        }

        let comp_len = data[pos] as usize;
        pos += 1 + comp_len;
        let mut public_key = Vec::new();
        let mut supported_versions = Vec::new();
        if pos + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let ext_end = pos.saturating_add(ext_len);
            while pos + 4 <= ext_end && pos + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                if pos + ext_data_len > data.len() {
                    break;
                }

                if ext_type == 51 {
                    let mut kpos = pos + 2;
                    if kpos + 4 <= pos + ext_data_len {
                        let _group = u16::from_be_bytes([data[kpos], data[kpos + 1]]);
                        let key_len = u16::from_be_bytes([data[kpos + 2], data[kpos + 3]]) as usize;
                        kpos += 4;
                        if kpos + key_len <= pos + ext_data_len {
                            public_key = data[kpos..kpos + key_len].to_vec();
                        }
                    }
                }

                if ext_type == 43 && ext_data_len >= 1 {
                    let versions_len = data[pos] as usize;
                    let mut vpos = pos + 1;
                    while vpos + 2 <= pos + 1 + versions_len && vpos + 2 <= data.len() {
                        supported_versions.push(u16::from_be_bytes([data[vpos], data[vpos + 1]]));
                        vpos += 2;
                    }
                }

                pos += ext_data_len;
            }
        }

        if supported_versions.is_empty() {
            supported_versions.push(u16::from_be_bytes([data[0], data[1]]));
        }

        Ok((client_random, ciphers, public_key, supported_versions))
    }

    fn parse_server_hello(&self, data: &[u8]) -> Result<([u8; 32], u16, Vec<u8>, TlsVersion, bool), TlsError> {
        if data.len() < 38 {
            return Err(TlsError::DecodeError("ServerHello too short".to_string()));
        }

        let mut pos = 2;
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let session_id_len = data[pos] as usize;
        pos += 1;

        let session_resumed = !self.session_id.is_empty()
            && session_id_len == self.session_id.len()
            && pos + session_id_len <= data.len()
            && &data[pos..pos + session_id_len] == &self.session_id[..];

        pos += session_id_len;
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError(
                "Invalid ServerHello format".to_string(),
            ));
        }

        let cipher = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        pos += 1;

        let mut public_key = Vec::new();
        let mut negotiated_version = TlsVersion::Tls1_2;
        if pos + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let ext_end = pos.saturating_add(ext_len);
            while pos + 4 <= ext_end && pos + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                if pos + ext_data_len > data.len() {
                    break;
                }

                if ext_type == 43 && ext_data_len >= 2 {
                    let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    negotiated_version = match version {
                        TLS_VERSION_1_3 => TlsVersion::Tls1_3,
                        TLS_VERSION_1_2 => TlsVersion::Tls1_2,
                        _ => return Err(TlsError::UnsupportedVersion),
                    };
                }

                if ext_type == 51 && ext_data_len >= 4 {
                    let mut kpos = pos + 2;
                    if kpos + 2 <= pos + ext_data_len {
                        let group = u16::from_be_bytes([data[kpos], data[kpos + 1]]);
                        kpos += 2;
                        if group == 0x001d && kpos + 2 <= pos + ext_data_len {
                            let key_len =
                                u16::from_be_bytes([data[kpos], data[kpos + 1]]) as usize;
                            kpos += 2;
                            if kpos + key_len <= pos + ext_data_len {
                                public_key = data[kpos..kpos + key_len].to_vec();
                            }
                        }
                    }
                }

                pos += ext_data_len;
            }
        }

        Ok((
            server_random,
            cipher,
            public_key,
            negotiated_version,
            session_resumed,
        ))
    }

    fn handle_new_session_ticket(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if data.len() < 8 {
            return Err(TlsError::DecodeError(
                "Session ticket too short".to_string(),
            ));
        }

        let mut pos = 0;
        let _lifetime = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let _age_add = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        if pos >= data.len() {
            return Ok(());
        }

        let nonce_len = data[pos] as usize;
        pos += 1 + nonce_len;
        if pos + 2 > data.len() {
            return Ok(());
        }

        let ticket_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + ticket_len > data.len() {
            return Ok(());
        }

        let ticket = data[pos..pos + ticket_len].to_vec();
        if let (Some(cache), Some(server_name)) = (&self.config.session_cache, &self.server_name) {
            if let Some(keys) = &self.keys {
                let mut session = TlsSession::new(
                    self.session_id.clone(),
                    keys.client_write_key.clone(),
                    self.cipher_suite,
                    server_name.clone(),
                    self.version,
                );

                session.ticket = Some(ticket);
                cache.insert(server_name.clone(), session);
            }
        }

        Ok(())
    }

    fn save_session(&mut self, shared_secret: &[u8]) -> Result<(), TlsError> {
        if !self.config.enable_session_resumption {
            return Ok(());
        }

        if let (Some(cache), Some(server_name)) = (&self.config.session_cache, &self.server_name) {
            if self.session_id.is_empty() {
                let mut sid = vec![0u8; 32];
                let _ = random::fill_random(&mut sid);
                self.session_id = sid;
            }

            let session = TlsSession::new(
                self.session_id.clone(),
                shared_secret.to_vec(),
                self.cipher_suite,
                server_name.clone(),
                self.version,
            );

            cache.insert(server_name.clone(), session);
        }

        Ok(())
    }

    fn select_cipher_suite(&self, client_ciphers: &[u16]) -> Result<u16, TlsError> {
        for configured in &self.config.supported_ciphers {
            if let Some(suite) = Self::parse_configured_cipher_suite(configured) {
                if client_ciphers.contains(&suite) {
                    return Ok(suite);
                }
            }
        }

        Err(TlsError::NoSharedCipher)
    }

    fn parse_certificate_chain(&self, cert_msg: &[u8]) -> Result<Vec<x509::Certificate>, TlsError> {
        if cert_msg.len() < 10 {
            return Err(TlsError::InvalidCertificate(
                "Certificate message too short".to_string(),
            ));
        }

        let mut pos = 1;
        if pos + 3 > cert_msg.len() {
            return Err(TlsError::InvalidCertificate(
                "Invalid certificate message format".to_string(),
            ));
        }

        let cert_list_len = ((cert_msg[pos] as usize) << 16)
            | ((cert_msg[pos + 1] as usize) << 8)
            | (cert_msg[pos + 2] as usize);
        
        pos += 3;
        if cert_list_len == 0 || pos + cert_list_len > cert_msg.len() {
            return Err(TlsError::InvalidCertificate(
                "Certificate list truncated".to_string(),
            ));
        }

        let list_end = pos + cert_list_len;
        let mut chain = Vec::new();
        while pos + 3 <= list_end {
            let cert_len = ((cert_msg[pos] as usize) << 16)
                | ((cert_msg[pos + 1] as usize) << 8)
                | (cert_msg[pos + 2] as usize);

            pos += 3;
            if pos + cert_len > list_end {
                return Err(TlsError::InvalidCertificate(
                    "Certificate data truncated".to_string(),
                ));
            }

            let cert_der = &cert_msg[pos..pos + cert_len];
            let cert = x509::Certificate::from_der(cert_der).map_err(|e| {
                TlsError::InvalidCertificate(format!("Failed to parse certificate: {:?}", e))
            })?;

            pos += cert_len;
            if pos + 2 > list_end {
                return Err(TlsError::InvalidCertificate(
                    "Certificate entry missing extensions length".to_string(),
                ));
            }

            let ext_len = u16::from_be_bytes([cert_msg[pos], cert_msg[pos + 1]]) as usize;
            pos += 2;
            if pos + ext_len > list_end {
                return Err(TlsError::InvalidCertificate(
                    "Certificate entry extensions truncated".to_string(),
                ));
            }

            pos += ext_len;
            chain.push(cert);
        }

        if chain.is_empty() {
            return Err(TlsError::InvalidCertificate(
                "Certificate chain is empty".to_string(),
            ));
        }

        Ok(chain)
    }

    fn validate_certificate_chain(&self, chain: &[x509::Certificate]) -> Result<(), TlsError> {
        if self.config.trust_store.is_empty() {
            return Err(TlsError::VerificationFailed(
                "No trust anchors configured; cannot verify certificate chain".to_string(),
            ));
        }

        for cert in chain {
            if !cert.is_valid_at_current_time() {
                return Err(TlsError::InvalidCertificate(
                    "Certificate in chain is expired or not yet valid".to_string(),
                ));
            }
        }

        if !chain[0].allows_server_auth() {
            return Err(TlsError::VerificationFailed(
                "Leaf certificate's extended key usage does not permit TLS server authentication"
                    .to_string(),
            ));
        }

        for i in 0..chain.len() - 1 {
            let subject = &chain[i];
            let issuer = &chain[i + 1];
            if subject.issuer_raw() != issuer.subject_raw() {
                return Err(TlsError::VerificationFailed(
                    "Certificate chain name mismatch: issuer/subject do not chain".to_string(),
                ));
            }

            subject.verify_signature(issuer).map_err(|_| {
                TlsError::VerificationFailed(
                    "Certificate chain signature verification failed".to_string(),
                )
            })?;

            let (is_ca, path_len) = issuer.get_basic_constraints().map_err(|e| {
                TlsError::InvalidCertificate(format!("Failed to read basicConstraints: {:?}", e))
            })?;

            if !is_ca {
                return Err(TlsError::VerificationFailed(
                    "Certificate chain contains a non-CA certificate acting as an issuer"
                        .to_string(),
                ));
            }

            if !issuer.can_sign_certificates() {
                return Err(TlsError::VerificationFailed(
                    "Issuer certificate's key usage does not permit certificate signing"
                        .to_string(),
                ));
            }

            if let Some(max_intermediates) = path_len {
                if (i as u32) > max_intermediates {
                    return Err(TlsError::VerificationFailed(
                        "Certificate chain exceeds issuer's path length constraint".to_string(),
                    ));
                }
            }
        }

        let top = chain.last().ok_or_else(|| {
            TlsError::VerificationFailed("Certificate chain is empty".to_string())
        })?;

        if self.config.trust_store.contains_exact(top) {
            return Ok(());
        }

        let anchor = self.config.trust_store.find_issuer(top).ok_or_else(|| {
            TlsError::VerificationFailed(
                "Certificate chain does not terminate at a trusted root".to_string(),
            )
        })?;

        if !anchor.is_valid_at_current_time() {
            return Err(TlsError::InvalidCertificate(
                "Trust anchor certificate is expired or not yet valid".to_string(),
            ));
        }

        top.verify_signature(anchor).map_err(|_| {
            TlsError::VerificationFailed(
                "Certificate chain signature verification against trust anchor failed"
                    .to_string(),
            )
        })?;

        if let (true, Some(max_intermediates)) = anchor.get_basic_constraints().unwrap_or((true, None)) {
            let total_intermediates = (chain.len() - 1) as u32;
            if total_intermediates > max_intermediates {
                return Err(TlsError::VerificationFailed(
                    "Certificate chain exceeds trust anchor's path length constraint".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn verify_certificate(&self, cert_msg: &[u8]) -> Result<(), TlsError> {
        let chain = self.parse_certificate_chain(cert_msg)?;
        let leaf = &chain[0];
        if !leaf.is_valid_at_current_time() {
            return Err(TlsError::InvalidCertificate(
                "Certificate expired or not yet valid".to_string(),
            ));
        }

        if let Some(server_name) = &self.server_name {
            if !server_name.is_empty() && !leaf.matches_hostname(server_name) {
                return Err(TlsError::InvalidCertificate(format!(
                    "Certificate hostname mismatch: expected {}",
                    server_name
                )));
            }
        }

        if self.config.verify_peer {
            self.validate_certificate_chain(&chain)?;
        }

        Ok(())
    }

    fn verify_certificate_verify(&self, verify_msg: &[u8]) -> Result<(), TlsError> {
        if verify_msg.len() < 4 {
            return Err(TlsError::VerificationFailed(
                "CertificateVerify message too short".to_string(),
            ));
        }

        for cert in &self.config.cert_chain {
            let public_key_bytes = cert.public_key()
                .ok_or_else(|| TlsError::InvalidCertificate("Missing public key".to_string()))?;

            let public_key = rsa::RsaPublicKey::from_bytes(&public_key_bytes).map_err(|_| {
                TlsError::InvalidCertificate("Failed to parse public key".to_string())
            })?;

            let signature_len = u16::from_be_bytes([verify_msg[2], verify_msg[3]]) as usize;
            if 4 + signature_len > verify_msg.len() {
                return Err(TlsError::VerificationFailed(
                    "CertificateVerify signature truncated".to_string(),
                ));
            }

            let signature = &verify_msg[4..4 + signature_len];
            let transcript_hash = self.compute_transcript_hash();
            let mut to_verify = Vec::new();
            to_verify.extend_from_slice(&[0x20u8; 64]);
            if self.is_client {
                to_verify.extend_from_slice(b"TLS 1.3, client CertificateVerify");
            } else {
                to_verify.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            }

            to_verify.push(0);
            to_verify.extend_from_slice(&transcript_hash);
            if public_key.verify(&to_verify, signature, rsa::RsaPadding::Pkcs1v15).unwrap_or(false) {
                return Ok(());
            }
        }

        Err(TlsError::VerificationFailed(
            "CertificateVerify verification failed".to_string(),
        ))
    }

    fn derive_handshake_keys(&mut self, shared_secret: &[u8]) -> Result<(), TlsError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"");
        let empty_hash = hasher.finalize();

        let early_secret = hkdf::Hkdf::extract(Some(&[0u8; 32]), &[0u8; 32]);
        let derived = self.hkdf_expand_label(&early_secret, b"derived", &empty_hash, 32)?;
        let handshake_secret = hkdf::Hkdf::extract(Some(&derived), shared_secret);
        let transcript_hash = self.compute_transcript_hash();
        let client_hs_secret =
            self.hkdf_expand_label(&handshake_secret, b"c hs traffic", &transcript_hash, 32)?;
        
        let server_hs_secret =
            self.hkdf_expand_label(&handshake_secret, b"s hs traffic", &transcript_hash, 32)?;

        let key_len = Self::aead_key_len(self.cipher_suite);
        let client_write_key = self.hkdf_expand_label(&client_hs_secret, b"key", b"", key_len)?;
        let client_write_iv = self.hkdf_expand_label(&client_hs_secret, b"iv", b"", 12)?;
        let server_write_key = self.hkdf_expand_label(&server_hs_secret, b"key", b"", key_len)?;
        let server_write_iv = self.hkdf_expand_label(&server_hs_secret, b"iv", b"", 12)?;
        self.keys = Some(TlsKeys {
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        });

        Ok(())
    }

    fn derive_keys(&mut self, _client_random: &[u8; 32], _server_random: &[u8; 32], shared_secret: &[u8]) -> Result<(), TlsError> {
        self.derive_application_keys(shared_secret)
    }

    fn derive_application_keys(&mut self, shared_secret: &[u8]) -> Result<(), TlsError> {
        let handshake_hash = self.compute_transcript_hash();
        let client_app_secret = self.hkdf_expand_label(shared_secret, b"c ap traffic", &handshake_hash, 32)?;
        let server_app_secret = self.hkdf_expand_label(shared_secret, b"s ap traffic", &handshake_hash, 32)?;
        let key_len = Self::aead_key_len(self.cipher_suite);
        let client_write_key = self.hkdf_expand_label(&client_app_secret, b"key", b"", key_len)?;
        let client_write_iv = self.hkdf_expand_label(&client_app_secret, b"iv", b"", 12)?;
        let server_write_key = self.hkdf_expand_label(&server_app_secret, b"key", b"", key_len)?;
        let server_write_iv = self.hkdf_expand_label(&server_app_secret, b"iv", b"", 12)?;

        self.keys = Some(TlsKeys {
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        });

        Ok(())
    }

    fn derive_finished_key(&self, is_client: bool) -> Result<Vec<u8>, TlsError> {
        let keys = self.keys.as_ref().ok_or_else(|| TlsError::HandshakeFailed("Keys not derived".to_string()))?;
        let base = if is_client {
            &keys.client_write_key
        } else {
            &keys.server_write_key
        };

        self.hkdf_expand_label(base, b"finished", b"", 32)
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, TlsError> {
        let mut hkdf_label = Vec::new();
        let full_label = [b"tls13 ", label].concat();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(full_label.len() as u8);
        hkdf_label.extend_from_slice(&full_label);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        hkdf::Hkdf::expand(secret, &hkdf_label, length)
            .map_err(|e| TlsError::CipherError(format!("HKDF expand failed: {:?}", e)))
    }

    fn compute_transcript_hash(&self) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.handshake_msg);

        hasher.finalize().to_vec()
    }

    fn send_handshake_message(&mut self, msg_type: u8, msg: &[u8]) -> Result<(), TlsError> {
        let mut message = Vec::new();
        let len = msg.len() as u32;
        message.push(msg_type);
        message.push(((len >> 16) & 0xff) as u8);
        message.push(((len >> 8) & 0xff) as u8);
        message.push((len & 0xff) as u8);
        message.extend_from_slice(msg);

        self.send_record(CONTENT_TYPE_HANDSHAKE, &message)
    }

    fn recieve_handshake_message(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        let record_data = self.receive_record()?;
        if record_data.len() < 4 {
            return Err(TlsError::DecodeError(
                "Handshake message too short".to_string(),
            ));
        }

        let msg_type = record_data[0];
        let msg_len = ((record_data[1] as usize) << 16)
            | ((record_data[2] as usize) << 8)
            | (record_data[3] as usize);

        if record_data.len() < 4 + msg_len {
            return Err(TlsError::DecodeError(
                "Incomplete handshake message".to_string(),
            ));
        }

        Ok((msg_type, record_data[4..4 + msg_len].to_vec()))
    }

    fn next_send_sequence(&mut self) -> u64 {
        if self.is_client {
            let current = self.client_seq;
            self.client_seq = self.client_seq.saturating_add(1);
            
            current
        } else {
            let current = self.server_seq;
            self.server_seq = self.server_seq.saturating_add(1);
            
            current
        }
    }

    fn next_receive_sequence(&mut self) -> u64 {
        if self.is_client {
            let current = self.server_seq;
            self.server_seq = self.server_seq.saturating_add(1);
            
            current
        } else {
            let current = self.client_seq;
            self.client_seq = self.client_seq.saturating_add(1);
            
            current
        }
    }

    fn should_secure_record_payload(&self, content_type: u8) -> bool {
        self.state == ConnectionState::Connected && content_type == CONTENT_TYPE_APPLICATION_DATA
    }

    fn choose_record_algorithm(&self, payload_len: usize) -> CompressionAlgorithm {
        let cfg = &self.config.record_compression;
        if !cfg.enabled || payload_len < cfg.min_size {
            return CompressionAlgorithm::Identity;
        }

        if cfg.preferred_algorithm.is_implemented() {
            cfg.preferred_algorithm
        } else {
            CompressionAlgorithm::Identity
        }
    }

    fn compression_algorithm_to_id(algorithm: CompressionAlgorithm) -> u8 {
        match algorithm {
            CompressionAlgorithm::Identity => 0,
            CompressionAlgorithm::Gzip => 1,
            CompressionAlgorithm::Deflate => 2,
            CompressionAlgorithm::Brotli => 3,
            CompressionAlgorithm::Zstd => 4,
        }
    }

    fn compression_algorithm_from_id(id: u8) -> Result<CompressionAlgorithm, TlsError> {
        match id {
            0 => Ok(CompressionAlgorithm::Identity),
            1 => Ok(CompressionAlgorithm::Gzip),
            2 => Ok(CompressionAlgorithm::Deflate),
            3 => Ok(CompressionAlgorithm::Brotli),
            4 => Ok(CompressionAlgorithm::Zstd),
            _ => Err(TlsError::DecodeError(format!(
                "Unknown compression algorithm id: {}",
                id
            ))),
        }
    }

    fn derive_record_integrity_key(&self, seq: u64, outbound: bool) -> Result<[u8; 32], TlsError> {
        let keys = self.keys.as_ref().ok_or_else(|| TlsError::IntegrityError("TLS keys not initialized".to_string()))?;
        let base_key: &[u8] = if outbound {
            if self.is_client {
                &keys.client_write_key
            } else {
                &keys.server_write_key
            }
        } else if self.is_client {
            &keys.server_write_key
        } else {
            &keys.client_write_key
        };

        let mut material = Vec::new();
        material.extend_from_slice(self.config.record_security.context.as_bytes());
        material.extend_from_slice(&seq.to_be_bytes());
        material.extend_from_slice(base_key);

        Ok(sha256(&material))
    }

    fn compute_secure_record_digest(&self, integrity_key: &[u8], content_type: u8, algorithm: CompressionAlgorithm, flags: u8, nonce: &[u8], raw_len: usize, wire_len: usize, wire_payload: &[u8]) -> [u8; 32] {
        let mut material = Vec::new();
        material.extend_from_slice(integrity_key);
        material.extend_from_slice(SECURE_RECORD_MAGIC);
        material.push(SECURE_RECORD_VERSION);
        material.push(content_type);
        material.push(Self::compression_algorithm_to_id(algorithm));
        material.push(flags);
        material.extend_from_slice(&(raw_len as u32).to_be_bytes());
        material.extend_from_slice(&(wire_len as u32).to_be_bytes());
        material.extend_from_slice(nonce);
        material.extend_from_slice(wire_payload);
        
        sha256(&material)
    }

    fn build_secure_record_payload(&self, plaintext: &[u8], content_type: u8, seq: u64, outbound: bool) -> Result<Vec<u8>, TlsError> {
        let mut algorithm = self.choose_record_algorithm(plaintext.len());
        if algorithm == CompressionAlgorithm::Identity {
            algorithm = self.negotiated_record_compression;
        }

        if !algorithm.is_implemented() {
            algorithm = CompressionAlgorithm::Identity;
        }

        let mut wire_payload = if algorithm == CompressionAlgorithm::Identity {
            plaintext.to_vec()
        } else {
            match compression::compress(algorithm, plaintext, self.config.record_compression.level) {
                Ok(out) => out,
                Err(e) if self.config.record_compression.fallback_to_identity_on_error => {
                    algorithm = CompressionAlgorithm::Identity;
                    plaintext.to_vec()
                }
                Err(e) => {
                    return Err(TlsError::CompressionError(format!(
                        "Failed to compress TLS record: {}",
                        e
                    )))
                }
            }
        };

        let mut flags = 0u8;
        if algorithm != CompressionAlgorithm::Identity {
            flags |= SECURE_RECORD_FLAG_COMPRESSED;
        }

        if wire_payload.is_empty() {
            wire_payload = Vec::new();
        }

        let nonce_len = self.config.record_security.nonce_len.max(8).min(64);
        let mut nonce = vec![0u8; nonce_len];
        random::fill_random(&mut nonce).map_err(|e| {
            TlsError::IntegrityError(format!(
                "Failed to generate record nonce: {:?}",
                e
            ))
        })?;

        let integrity_key = self.derive_record_integrity_key(seq, outbound)?;
        let digest = self.compute_secure_record_digest(
            &integrity_key,
            content_type,
            algorithm,
            flags,
            &nonce,
            plaintext.len(),
            wire_payload.len(),
            &wire_payload,
        );

        let mut blob = Vec::new();
        blob.extend_from_slice(SECURE_RECORD_MAGIC);
        blob.push(SECURE_RECORD_VERSION);
        blob.push(content_type);
        blob.push(Self::compression_algorithm_to_id(algorithm));
        blob.push(flags);
        blob.push(nonce_len as u8);
        blob.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(wire_payload.len() as u32).to_be_bytes());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&digest);
        blob.extend_from_slice(&wire_payload);

        Ok(blob)
    }

    fn parse_secure_record_payload(&self, payload: &[u8], seq: u64, outbound: bool, fallback_content_type: u8) -> Result<(Vec<u8>, u8), TlsError> {
        if payload.len() < SECURE_RECORD_BASE_HEADER_LEN {
            return Ok((payload.to_vec(), fallback_content_type));
        }

        if &payload[..8] != SECURE_RECORD_MAGIC {
            return Ok((payload.to_vec(), fallback_content_type));
        }

        let mut pos = 8;
        let version = payload[pos];
        pos += 1;
        if version != SECURE_RECORD_VERSION {
            return Err(TlsError::DecodeError(format!(
                "Unsupported secure record version: {}",
                version
            )));
        }

        let inner_content_type = payload[pos];
        pos += 1;

        let algorithm_id = payload[pos];
        pos += 1;

        let algorithm = Self::compression_algorithm_from_id(algorithm_id)?;
        let flags = payload[pos];
        pos += 1;

        let nonce_len = payload[pos] as usize;
        pos += 1;
        if payload.len() < SECURE_RECORD_BASE_HEADER_LEN + nonce_len + SECURE_RECORD_DIGEST_LEN {
            return Err(TlsError::DecodeError(
                "Secure record too short".to_string(),
            ));
        }

        let raw_len = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]) as usize;

        pos += 4;

        let wire_len = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]) as usize;

        pos += 4;
        if pos + nonce_len + SECURE_RECORD_DIGEST_LEN + wire_len != payload.len() {
            return Err(TlsError::DecodeError(
                "Secure record size mismatch".to_string(),
            ));
        }

        let nonce = &payload[pos..pos + nonce_len];
        pos += nonce_len;

        let expected_digest = &payload[pos..pos + SECURE_RECORD_DIGEST_LEN];
        pos += SECURE_RECORD_DIGEST_LEN;

        let wire_payload = &payload[pos..pos + wire_len];
        let integrity_key = self.derive_record_integrity_key(seq, outbound)?;
        let actual_digest = self.compute_secure_record_digest(
            &integrity_key,
            inner_content_type,
            algorithm,
            flags,
            nonce,
            raw_len,
            wire_len,
            wire_payload,
        );

        if self.config.record_security.enable_integrity && !constant_time_eq(expected_digest, &actual_digest) {
            return Err(TlsError::IntegrityError(
                "Secure record digest verification failed".to_string(),
            ));
        }

        let decoded = if flags & SECURE_RECORD_FLAG_COMPRESSED != 0 {
            compression::decompress(algorithm, wire_payload).map_err(|e| {
                TlsError::CompressionError(format!(
                    "Failed to decompress secure record: {}",
                    e
                ))
            })?
        } else {
            wire_payload.to_vec()
        };

        if decoded.len() != raw_len {
            return Err(TlsError::DecodeError(format!(
                "Secure record raw length mismatch: expected {}, got {}",
                raw_len,
                decoded.len()
            )));
        }

        Ok((decoded, inner_content_type))
    }

    fn send_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), TlsError> {
        let mut record = Vec::new();
        let (final_content_type, payload) = if self.should_secure_record_payload(content_type) && self.keys.is_some() {
            let seq = self.next_send_sequence();
            let secure_payload = self.build_secure_record_payload(data, content_type, seq, true)?;
            let encrypted = self.encrypt_record(&secure_payload, CONTENT_TYPE_APPLICATION_DATA, seq)?;
            (CONTENT_TYPE_APPLICATION_DATA, encrypted)
        } else if self.state == ConnectionState::Handshaking && self.keys.is_some() && (content_type == CONTENT_TYPE_HANDSHAKE || content_type == CONTENT_TYPE_APPLICATION_DATA) {
            let seq = self.next_send_sequence();
            let encrypted = self.encrypt_record(data, content_type, seq)?;
            (CONTENT_TYPE_APPLICATION_DATA, encrypted)
        } else {
            (content_type, data.to_vec())
        };

        record.push(final_content_type);
        record.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(&payload);

        self.stream.write_all(&record)?;
        self.stream.flush()?;
        Ok(())
    }

    fn receive_record(&mut self) -> Result<Vec<u8>, TlsError> {
        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header)?;
        let content_type = header[0];
        let _version = u16::from_be_bytes([header[1], header[2]]);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; length];
        self.stream.read_exact(&mut payload)?;
        if content_type == CONTENT_TYPE_ALERT {
            if payload.len() >= 2 {
                return Err(TlsError::AlertReceived(payload[0], payload[1]));
            }

            return Err(TlsError::AlertReceived(ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE));
        }

        if content_type == CONTENT_TYPE_APPLICATION_DATA && self.keys.is_some() {
            let seq = self.next_receive_sequence();
            let (decrypted, original_type) = self.decrypt_record(&payload, seq)?;
            if self.state == ConnectionState::Connected && original_type == CONTENT_TYPE_APPLICATION_DATA {
                let (decoded, _inner_type) = self.parse_secure_record_payload(&decrypted, seq, false, original_type)?;
                return Ok(decoded);
            }

            return Ok(decrypted);
        }

        Ok(payload)
    }

    fn aead_key_len(cipher_suite: u16) -> usize {
        match cipher_suite {
            TLS_AES_256_GCM_SHA384 => 32,
            TLS_CHACHA20_POLY1305_SHA256 => 32,
            _ => 16,
        }
    }

    fn compute_record_nonce(iv: &[u8], seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv[..12]);
        for i in 0..8 {
            nonce[4 + i] ^= ((seq >> (56 - i * 8)) & 0xff) as u8;
        }

        nonce
    }

    fn record_aad(record_len: usize) -> [u8; 5] {
        let len_bytes = (record_len as u16).to_be_bytes();
        let version_bytes = TLS_VERSION_1_2.to_be_bytes();
        [
            CONTENT_TYPE_APPLICATION_DATA,
            version_bytes[0],
            version_bytes[1],
            len_bytes[0],
            len_bytes[1],
        ]
    }

    fn aead_seal(cipher_suite: u16, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TlsError> {
        match cipher_suite {
            TLS_CHACHA20_POLY1305_SHA256 => {
                let cipher = ChaCha20Poly1305::new(key).map_err(|e| {
                    TlsError::CipherError(format!("Failed to initialize ChaCha20-Poly1305: {:?}", e))
                })?;

                cipher.encrypt(nonce, plaintext, aad).map_err(|e| {
                    TlsError::CipherError(format!("ChaCha20-Poly1305 encryption failed: {:?}", e))
                })
            }
            _ => {
                let cipher = GcmOptimized::new(key).map_err(|e| {
                    TlsError::CipherError(format!("Failed to initialize AES-GCM: {:?}", e))
                })?;

                cipher.encrypt(nonce, plaintext, aad).map_err(|e| {
                    TlsError::CipherError(format!("AES-GCM encryption failed: {:?}", e))
                })
            }
        }
    }

    fn aead_open(cipher_suite: u16, key: &[u8], nonce: &[u8], ciphertext_and_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>, TlsError> {
        match cipher_suite {
            TLS_CHACHA20_POLY1305_SHA256 => {
                let cipher = ChaCha20Poly1305::new(key).map_err(|e| {
                    TlsError::CipherError(format!("Failed to initialize ChaCha20-Poly1305: {:?}", e))
                })?;

                cipher.decrypt(nonce, ciphertext_and_tag, aad).map_err(|_| {
                    TlsError::CipherError("Authentication tag verification failed".to_string())
                })
            }
            _ => {
                let cipher = GcmOptimized::new(key).map_err(|e| {
                    TlsError::CipherError(format!("Failed to initialize AES-GCM: {:?}", e))
                })?;

                cipher.decrypt(nonce, ciphertext_and_tag, aad).map_err(|_| {
                    TlsError::CipherError("Authentication tag verification failed".to_string())
                })
            }
        }
    }

    fn encrypt_record(&mut self, plaintext: &[u8], content_type: u8, seq: u64) -> Result<Vec<u8>, TlsError> {
        let keys = self.keys.as_ref().ok_or_else(|| TlsError::CipherError("Keys not initialized".to_string()))?;
        let (write_key, iv) = if self.is_client {
            (&keys.client_write_key, &keys.client_write_iv)
        } else {
            (&keys.server_write_key, &keys.server_write_iv)
        };

        let nonce = Self::compute_record_nonce(iv, seq);

        let mut inner_plaintext = plaintext.to_vec();
        inner_plaintext.push(content_type);

        let record_len = inner_plaintext.len() + 16;
        let aad = Self::record_aad(record_len);

        Self::aead_seal(self.cipher_suite, write_key, &nonce, &inner_plaintext, &aad)
    }

    fn decrypt_record(&mut self, ciphertext: &[u8], seq: u64) -> Result<(Vec<u8>, u8), TlsError> {
        if ciphertext.len() < 16 {
            return Err(TlsError::CipherError("Ciphertext too short".to_string()));
        }

        let keys = self.keys.as_ref().ok_or_else(|| TlsError::CipherError("Keys not initialized".to_string()))?;
        let (read_key, iv) = if self.is_client {
            (&keys.server_write_key, &keys.server_write_iv)
        } else {
            (&keys.client_write_key, &keys.client_write_iv)
        };

        let nonce = Self::compute_record_nonce(iv, seq);
        let aad = Self::record_aad(ciphertext.len());

        let mut plaintext = Self::aead_open(self.cipher_suite, read_key, &nonce, ciphertext, &aad)?;
        let content_type = plaintext.pop().ok_or_else(|| {
            TlsError::CipherError("Decrypted data empty".to_string())
        })?;

        Ok((plaintext, content_type))
    }

    fn negotiate_version(&self, client_versions: &[u16]) -> Result<TlsVersion, TlsError> {
        if client_versions.contains(&TLS_VERSION_1_3) && self.config.max_version >= TlsVersion::Tls1_3 && self.config.min_version <= TlsVersion::Tls1_3 {
            return Ok(TlsVersion::Tls1_3);
        }

        if client_versions.contains(&TLS_VERSION_1_2) && self.config.max_version >= TlsVersion::Tls1_2 && self.config.min_version <= TlsVersion::Tls1_2 {
            return Ok(TlsVersion::Tls1_2);
        }

        Err(TlsError::UnsupportedVersion)
    }

    pub fn send_alert(&mut self, level: u8, description: u8) -> Result<(), TlsError> {
        let alert = vec![level, description];
        self.send_record(CONTENT_TYPE_ALERT, &alert)?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), TlsError> {
        if self.state != ConnectionState::Closed {
            let _ = self.send_alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
            self.state = ConnectionState::Closed;
        }

        Ok(())
    }

    pub fn stream_into_inner(self) -> Result<TcpStream, TlsError> {
        self.stream.try_clone().map_err(TlsError::Io)
    }

    pub fn stream_get_ref(&self) -> &TcpStream {
        &self.stream
    }

    pub fn stream_get_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), TlsError> {
        self.stream.set_read_timeout(dur)?;
        Ok(())
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<(), TlsError> {
        self.stream.set_write_timeout(dur)?;
        Ok(())
    }

    pub fn set_alpn_protocols(&mut self, protocols: Vec<AlpnProtocol>) {
        let mut new_negotiator = AlpnNegotiator::with_protocols(protocols);
        new_negotiator.set_server_preference(false);
        self.alpn_negotiator = new_negotiator;
    }

    pub fn get_negotiated_protocol(&self) -> Option<AlpnProtocol> {
        self.negotiated_protocol
    }

    pub fn negotiate_alpn(&mut self, server_alpn_data: &[u8]) -> Result<AlpnProtocol, TlsError> {
        self.alpn_negotiator.negotiate(server_alpn_data).map_err(|e| {
            TlsError::HandshakeFailed(format!("ALPN negotiation failed: {}", e))
        })
    }

    pub fn extract_alpn_from_handshake(&self, server_hello_data: &[u8]) -> Result<Vec<u8>, TlsError> {
        if server_hello_data.len() < 38 {
            return Err(TlsError::HandshakeFailed(
                "ServerHello too short".to_string(),
            ));
        }

        let mut pos = 34;
        let session_id_len = server_hello_data[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 4 > server_hello_data.len() {
            return Err(TlsError::HandshakeFailed(
                "ServerHello truncated before extensions".to_string(),
            ));
        }
        
        pos += 3;
        if pos + 2 > server_hello_data.len() {
            return Err(TlsError::HandshakeFailed(
                "ServerHello missing extensions length".to_string(),
            ));
        }

        let ext_len = u16::from_be_bytes([server_hello_data[pos], server_hello_data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos.saturating_add(ext_len);
        if ext_end > server_hello_data.len() {
            return Err(TlsError::HandshakeFailed(
                "ServerHello extensions truncated".to_string(),
            ));
        }
        
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([server_hello_data[pos], server_hello_data[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([
                server_hello_data[pos + 2],
                server_hello_data[pos + 3],
            ]) as usize;

            pos += 4;
            if pos + ext_data_len > ext_end {
                return Err(TlsError::HandshakeFailed(
                    "Extension data exceeds extensions boundary".to_string(),
                ));
            }

            if ext_type == 16 {
                return Ok(server_hello_data[pos..pos + ext_data_len].to_vec());
            }

            pos += ext_data_len;
        }
        
        Ok(Vec::new())
    }

    pub fn complete_alpn_negotiation(&mut self) -> Result<Option<AlpnProtocol>, TlsError> {
        if !self.alpn_negotiator.is_negotiated() {
            return Ok(None);
        }
        
        self.negotiated_protocol = self.alpn_negotiator.selected();
        Ok(self.negotiated_protocol)
    }

    pub fn init_alpn_client(&mut self, preferred: Vec<AlpnProtocol>) {
        self.alpn_negotiator = AlpnNegotiator::with_protocols(preferred);
        self.alpn_negotiator.set_server_preference(false);
    }

    pub fn build_alpn_extension(&self) -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend_from_slice(&16u16.to_be_bytes());

        let protocols_wire = self.alpn_negotiator.supported_protocols_wire();
        let ext_len = 2 + protocols_wire.len();

        extension.extend_from_slice(&(ext_len as u16).to_be_bytes());
        extension.extend_from_slice(&(protocols_wire.len() as u16).to_be_bytes());
        extension.extend_from_slice(&protocols_wire);
        extension
    }

    pub fn parse_alpn_extension(&mut self, extension_data: &[u8]) -> Result<(), TlsError> {
        if extension_data.len() < 3 {
            return Err(TlsError::HandshakeFailed(
                "ALPN extension too short".to_string(),
            ));
        }

        let list_len = u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
        if extension_data.len() < 2 + list_len {
            return Err(TlsError::HandshakeFailed(
                "ALPN extension data truncated".to_string(),
            ));
        }

        if list_len == 0 {
            return Err(TlsError::HandshakeFailed(
                "Server sent empty ALPN list".to_string(),
            ));
        }

        let proto_len = extension_data[2] as usize;
        if proto_len == 0 || 2 + 1 + proto_len > 2 + list_len {
            return Err(TlsError::HandshakeFailed(
                "Invalid ALPN protocol length".to_string(),
            ));
        }

        let proto_data = &extension_data[3..3 + proto_len];
        if let Some(protocol) = AlpnProtocol::from_wire(proto_data) {
            let protocol_wire = protocol.wire_format();
            let supported_wire = self.alpn_negotiator.supported_protocols_wire();
            let mut is_supported = false;
            let mut pos = 0;
            while pos < supported_wire.len() {
                let len = supported_wire[pos] as usize;
                pos += 1;
                if pos + len > supported_wire.len() {
                    break;
                }

                if &supported_wire[pos..pos + len] == protocol_wire {
                    is_supported = true;
                    break;
                }

                pos += len;
            }

            if !is_supported {
                return Err(TlsError::HandshakeFailed(format!(
                    "Server selected protocol '{}' not in client offer",
                    protocol.name()
                )));
            }

            self.negotiated_protocol = Some(protocol);
            return Ok(());
        }

        Err(TlsError::HandshakeFailed(format!(
            "Unknown ALPN protocol: {:?}",
            proto_data
        )))
    }

    pub fn validate_negotiated_protocol(&self, expected: &[AlpnProtocol]) -> Result<(), TlsError> {
        match self.negotiated_protocol {
            Some(proto) => {
                if expected.is_empty() || expected.contains(&proto) {
                    Ok(())
                } else {
                    Err(TlsError::ProtocolNegotiationFailed(format!(
                        "Server negotiated unexpected protocol: {}",
                        proto.name()
                    )))
                }
            }
            None => {
                if expected.is_empty() {
                    Ok(())
                } else {
                    Err(TlsError::ProtocolNegotiationFailed(
                        "Server did not negotiate ALPN protocol".to_string(),
                    ))
                }
            }
        }
    }

    pub fn try_clone(&self) -> Result<TlsStream, TlsError> {
        let cloned_stream = self.stream.try_clone()?;
        Ok(TlsStream {
            stream: cloned_stream,
            config: self.config.clone(),
            state: self.state,
            version: self.version,
            cipher_suite: self.cipher_suite,
            keys: self.keys.clone(),
            handshake_msg: self.handshake_msg.clone(),
            client_seq: self.client_seq,
            server_seq: self.server_seq,
            is_client: self.is_client,
            buffer: Vec::new(),
            server_name: self.server_name.clone(),
            session_id: self.session_id.clone(),
            resuming_session: self.resuming_session,
            alpn_negotiator: self.alpn_negotiator.clone(),
            negotiated_protocol: self.negotiated_protocol,
            negotiated_record_compression: self.negotiated_record_compression,
        })
    }
}

impl Default for TlsRecordSecurityCfg {
    fn default() -> Self {
        Self {
            enable_integrity: true,
            nonce_len: 16,
            context: "SINGULARITY_TLS_RECORD_CTX_V1".to_string(),
        }
    }
}

impl Default for TlsRecordCompressionCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size: 512,
            preferred_algorithm: CompressionAlgorithm::Zstd,
            level: CompressionLevel::Default,
            fallback_to_identity_on_error: true,
        }
    }
}

impl Default for TlsCfg {
    fn default() -> Self {
        TlsCfg {
            cert_chain: vec![],
            private_key: rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).expect("Failed to generate RSA key"),
            supported_ciphers: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            min_version: TlsVersion::Tls1_2,
            max_version: TlsVersion::Tls1_3,
            verify_peer: true,
            trust_store: TrustStore::bundled(),
            session_cache: Some(SessionCache::new()),
            enable_session_resumption: true,
            record_security: TlsRecordSecurityCfg::default(),
            record_compression: TlsRecordCompressionCfg::default(),
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.state != ConnectionState::Connected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS connection not established",
            ));
        }

        if !self.buffer.is_empty() {
            let to_copy = buf.len().min(self.buffer.len());
            buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            self.buffer.drain(..to_copy);
            return Ok(to_copy);
        }

        match self.receive_record() {
            Ok(data) => {
                let to_copy = buf.len().min(data.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);

                if data.len() > to_copy {
                    self.buffer.extend_from_slice(&data[to_copy..]);
                }

                Ok(to_copy)
            }
            Err(TlsError::Io(e)) => Err(e),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("TLS error: {}", e),
            )),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.state != ConnectionState::Connected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS connection not established",
            ));
        }

        match self.send_record(CONTENT_TYPE_APPLICATION_DATA, buf) {
            Ok(_) => Ok(buf.len()),
            Err(TlsError::Io(e)) => Err(e),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("TLS error: {}", e),
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl From<std::io::Error> for TlsError {
    fn from(err: std::io::Error) -> Self {
        TlsError::Io(err)
    }
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Io(e) => write!(f, "IO Error: {}", e),
            TlsError::HandshakeFailed(msg) => write!(f, "Handshake Failed: {}", msg),
            TlsError::InvalidCertificate(msg) => write!(f, "Invalid Certificate: {}", msg),
            TlsError::CipherError(msg) => write!(f, "Cipher Error: {}", msg),
            TlsError::CompressionError(msg) => write!(f, "Compression Error: {}", msg),
            TlsError::IntegrityError(msg) => write!(f, "Integrity Error: {}", msg),
            TlsError::AlertReceived(level, desc) => {
                write!(f, "Alert Received: level={}, description={}", level, desc)
            }
            TlsError::DecodeError(msg) => write!(f, "Decode Error: {}", msg),
            TlsError::UnsupportedVersion => write!(f, "Unsupported TLS Version"),
            TlsError::NoSharedCipher => write!(f, "No Shared Cipher Suite"),
            TlsError::VerificationFailed(msg) => write!(f, "Verification Failed: {}", msg),
            TlsError::ProtocolNegotiationFailed(msg) => {
                write!(f, "Protocol Negotiation Failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for TlsError {}

impl Drop for TlsStream {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use crate::net::tcp::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn start_test_server() -> (String, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
                let _ = tx.send(());
            }
        });

        (format!("127.0.0.1:{}", addr.port()), rx)
    }

    fn test_tls_stream_with_keys(is_client: bool) -> TlsStream {
        let (addr, _rx) = start_test_server();
        let stream = TcpStream::connect(&addr).expect("Failed to connect");

        TlsStream {
            stream,
            config: TlsCfg::default(),
            state: ConnectionState::Connected,
            version: TlsVersion::Tls1_3,
            cipher_suite: TLS_AES_128_GCM_SHA256,
            keys: Some(TlsKeys {
                client_write_key: vec![0x11; 16],
                server_write_key: vec![0x22; 16],
                client_write_iv: vec![0x33; 12],
                server_write_iv: vec![0x44; 12],
            }),
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
            alpn_negotiator: AlpnNegotiator::new(),
            negotiated_protocol: None,
            negotiated_record_compression: CompressionAlgorithm::Identity,
        }
    }

    fn test_tls_stream_with_config(config: TlsCfg, server_name: Option<String>) -> TlsStream {
        let (addr, _rx) = start_test_server();
        let stream = TcpStream::connect(&addr).expect("Failed to connect");

        TlsStream {
            stream,
            config,
            state: ConnectionState::Initial,
            version: TlsVersion::Tls1_3,
            cipher_suite: 0,
            keys: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: true,
            buffer: Vec::new(),
            server_name,
            session_id: Vec::new(),
            resuming_session: false,
            alpn_negotiator: AlpnNegotiator::new(),
            negotiated_protocol: None,
            negotiated_record_compression: CompressionAlgorithm::Identity,
        }
    }

    fn encode_test_name(seq: &mut crate::crypto::encoding::asn1::DerEncoder, cn: &str) {
        use crate::crypto::encoding::asn1::DerEncoder;

        let mut rdn = DerEncoder::new();
        rdn.sequence(|attr| {
            let _ = attr.object_identifier(&[2, 5, 4, 3]);
            attr.utf8_string(cn);
        });

        let rdn_bytes = rdn.finish();
        seq.write_tag(0x31, true);
        seq.write_length(rdn_bytes.len());
        seq.raw(&rdn_bytes);
    }

    #[allow(clippy::too_many_arguments)]
    fn build_test_tbs(subject_cn: &str, issuer_cn: &str, public_key_der: &[u8], is_ca: bool, path_len: Option<u32>, key_usage_cert_sign: bool, eku_oids: &[&[u64]]) -> Vec<u8> {
        use crate::crypto::encoding::asn1::DerEncoder;

        let mut tbs = DerEncoder::new();
        tbs.sequence(|s| {
            s.context_specific(0, |v| {
                v.integer_u64(2);
            });

            s.integer(&[1]);
            s.sequence(|alg| {
                let _ = alg.object_identifier(&[1, 2, 840, 113549, 1, 1, 11]);
                alg.null();
            });

            s.sequence(|iss| encode_test_name(iss, issuer_cn));
            s.sequence(|validity| {
                validity.utc_time("240101000000Z");
                validity.utc_time("340101000000Z");
            });

            s.sequence(|subj| encode_test_name(subj, subject_cn));
            s.sequence(|spki| {
                spki.sequence(|alg| {
                    let _ = alg.object_identifier(&[1, 2, 840, 113549, 1, 1, 1]);
                    alg.null();
                });

                spki.bit_string(public_key_der, 0);
            });

            s.context_specific(3, |ext_outer| {
                ext_outer.sequence(|exts| {
                    exts.sequence(|ext| {
                        let _ = ext.object_identifier(&[2, 5, 29, 19]);
                        ext.boolean(true);
                        let mut bc = DerEncoder::new();
                        bc.sequence(|bc_seq| {
                            if is_ca {
                                bc_seq.boolean(true);
                            }

                            if let Some(pl) = path_len {
                                bc_seq.integer_u64(pl as u64);
                            }
                        });

                        ext.octet_string(&bc.finish());
                    });

                    exts.sequence(|ext| {
                        let _ = ext.object_identifier(&[2, 5, 29, 15]);
                        ext.boolean(true);
                        let mut ku = DerEncoder::new();
                        let byte0: u8 = if key_usage_cert_sign { 0x04 } else { 0x80 };
                        ku.bit_string(&[byte0], 0);
                        ext.octet_string(&ku.finish());
                    });

                    if !eku_oids.is_empty() {
                        exts.sequence(|ext| {
                            let _ = ext.object_identifier(&[2, 5, 29, 37]);
                            let mut eku = DerEncoder::new();
                            eku.sequence(|eku_seq| {
                                for oid in eku_oids {
                                    let _ = eku_seq.object_identifier(oid);
                                }
                            });

                            ext.octet_string(&eku.finish());
                        });
                    }
                });
            });
        });

        tbs.finish()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_test_cert(subject_cn: &str, issuer_cn: &str, subject_key: &rsa::RsaPublicKey, signing_key: &rsa::RsaPrivateKey, is_ca: bool, path_len: Option<u32>, key_usage_cert_sign: bool, eku_oids: &[&[u64]]) -> x509::Certificate {
        let subject_key_der = subject_key.to_der();
        let tbs = build_test_tbs(
            subject_cn,
            issuer_cn,
            &subject_key_der,
            is_ca,
            path_len,
            key_usage_cert_sign,
            eku_oids,
        );

        let signature = signing_key.sign(&tbs, rsa::RsaPadding::Pkcs1v15).unwrap();

        x509::Certificate {
            tbs,
            signature_algorithm: vec![1, 2, 840, 113549, 1, 1, 11],
            signature,
            subject: x509::Name { common_name: Some(subject_cn.to_string()) },
            issuer: x509::Name { common_name: Some(issuer_cn.to_string()) },
            subject_public_key_info: x509::SubjectPublicKeyInfo {
                algorithm: vec![1, 2, 840, 113549, 1, 1, 1],
                param: None,
                public_key: subject_key_der,
            },
        }
    }

    const EKU_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
    const EKU_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];

    #[test]
    fn test_validate_certificate_chain_success() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Root CA", &leaf_key.public_key(), &root_key,
            false, None, false, &[EKU_SERVER_AUTH],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let mut config = TlsCfg::default();
        config.verify_peer = true;
        config.trust_store = trust_store;

        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[leaf, root]).is_ok());
    }

    #[test]
    fn test_validate_certificate_chain_intermediate_success() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let intermediate_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let intermediate = build_test_cert(
            "Test Intermediate CA", "Test Root CA", &intermediate_key.public_key(), &root_key,
            true, Some(0), true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Intermediate CA", &leaf_key.public_key(), &intermediate_key,
            false, None, false, &[EKU_SERVER_AUTH],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let mut config = TlsCfg::default();
        config.verify_peer = true;
        config.trust_store = trust_store;

        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[leaf, intermediate, root]).is_ok());
    }

    #[test]
    fn test_validate_certificate_chain_fails_with_empty_trust_store() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let config = TlsCfg { verify_peer: true, trust_store: TrustStore::empty(), ..TlsCfg::default() };
        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[root]).is_err());
    }

    #[test]
    fn test_validate_certificate_chain_fails_on_wrong_signer() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let other_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Root CA", &leaf_key.public_key(), &other_key,
            false, None, false, &[EKU_SERVER_AUTH],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let config = TlsCfg { verify_peer: true, trust_store, ..TlsCfg::default() };
        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[leaf, root]).is_err());
    }

    #[test]
    fn test_validate_certificate_chain_fails_when_issuer_not_ca() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            false, None, true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Root CA", &leaf_key.public_key(), &root_key,
            false, None, false, &[EKU_SERVER_AUTH],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let config = TlsCfg { verify_peer: true, trust_store, ..TlsCfg::default() };
        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[leaf, root]).is_err());
    }

    #[test]
    fn test_validate_certificate_chain_fails_on_eku_mismatch() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Root CA", &leaf_key.public_key(), &root_key,
            false, None, false, &[EKU_CODE_SIGNING],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let config = TlsCfg { verify_peer: true, trust_store, ..TlsCfg::default() };
        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[leaf, root]).is_err());
    }

    #[test]
    fn test_validate_certificate_chain_fails_on_path_len_violation() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let intermediate_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let intermediate = build_test_cert(
            "Test Intermediate CA", "Test Root CA", &intermediate_key.public_key(), &root_key,
            true, Some(0), true, &[],
        );

        let sub_intermediate_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let sub_intermediate = build_test_cert(
            "Test Sub Intermediate CA", "Test Intermediate CA", &sub_intermediate_key.public_key(), &intermediate_key,
            true, None, true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Sub Intermediate CA", &leaf_key.public_key(), &sub_intermediate_key,
            false, None, false, &[EKU_SERVER_AUTH],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let config = TlsCfg { verify_peer: true, trust_store, ..TlsCfg::default() };
        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));
        assert!(tls.validate_certificate_chain(&[leaf, sub_intermediate, intermediate, root]).is_err());
    }

    #[test]
    fn test_verify_certificate_end_to_end_via_certificate_message() {
        let root_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let root = build_test_cert(
            "Test Root CA", "Test Root CA", &root_key.public_key(), &root_key,
            true, None, true, &[],
        );

        let leaf = build_test_cert(
            "example.com", "Test Root CA", &leaf_key.public_key(), &root_key,
            false, None, false, &[EKU_SERVER_AUTH],
        );

        let mut trust_store = TrustStore::empty();
        trust_store.add_cert(root.clone());

        let config = TlsCfg { verify_peer: true, trust_store, ..TlsCfg::default() };
        let tls = test_tls_stream_with_config(config, Some("example.com".to_string()));

        let mut cert_msg = vec![0u8];
        let mut cert_list = Vec::new();
        for cert in [&leaf, &root] {
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

        let result = tls.verify_certificate(&cert_msg);
        assert!(result.is_ok(), "verify_certificate failed: {:?}", result);
    }

    #[test]
    fn test_tls_config_default() {
        let cfg = TlsCfg::default();
        assert_eq!(cfg.min_version, TlsVersion::Tls1_2);
        assert_eq!(cfg.max_version, TlsVersion::Tls1_3);
        assert!(cfg.verify_peer);
        assert!(!cfg.trust_store.is_empty());
        assert_eq!(cfg.supported_ciphers.len(), 3);
        assert!(cfg.record_compression.enabled);
        assert!(cfg.record_security.enable_integrity);
    }

    #[test]
    fn test_cipher_suite_selection() {
        let (addr, _rx) = start_test_server();
        let stream = TcpStream::connect(&addr).expect("Failed to connect");

        let tls = TlsStream {
            stream,
            config: TlsCfg::default(),
            state: ConnectionState::Initial,
            version: TlsVersion::Tls1_3,
            cipher_suite: 0,
            keys: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: true,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
            alpn_negotiator: AlpnNegotiator::new(),
            negotiated_protocol: None,
            negotiated_record_compression: CompressionAlgorithm::Identity,
        };

        let client_ciphers = vec![0x1301, 0x1302];
        let result = tls.select_cipher_suite(&client_ciphers);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_hello_parsing() {
        let (addr, _rx) = start_test_server();
        let stream = TcpStream::connect(&addr).expect("Failed to connect");

        let tls = TlsStream {
            stream,
            config: TlsCfg::default(),
            state: ConnectionState::Initial,
            version: TlsVersion::Tls1_3,
            cipher_suite: 0,
            keys: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: false,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
            alpn_negotiator: AlpnNegotiator::new(),
            negotiated_protocol: None,
            negotiated_record_compression: CompressionAlgorithm::Identity,
        };

        let client_hello = vec![
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x02, 0x13, 0x01,
            0x01, 0x00,
            0x00, 0x00,
        ];

        let result = tls.parse_client_hello(&client_hello);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_record_roundtrip_identity() {
        let tls = test_tls_stream_with_keys(true);
        let payload = b"secure tls payload";
        let blob = tls
            .build_secure_record_payload(payload, CONTENT_TYPE_APPLICATION_DATA, 7, true)
            .unwrap();

        let (decoded, inner_type) = tls
            .parse_secure_record_payload(
                &blob,
                7,
                true,
                CONTENT_TYPE_APPLICATION_DATA,
            )
            .unwrap();

        assert_eq!(inner_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_record_roundtrip_compressed() {
        let mut tls = test_tls_stream_with_keys(true);
        tls.config.record_compression.enabled = true;
        tls.config.record_compression.min_size = 1;
        tls.config.record_compression.preferred_algorithm = CompressionAlgorithm::Gzip;

        let payload = b"this is a compressible secure tls payload repeated repeated repeated";
        let blob = tls
            .build_secure_record_payload(payload, CONTENT_TYPE_APPLICATION_DATA, 12, true)
            .unwrap();

        let (decoded, inner_type) = tls
            .parse_secure_record_payload(
                &blob,
                12,
                true,
                CONTENT_TYPE_APPLICATION_DATA,
            )
            .unwrap();

        assert_eq!(inner_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_secure_record_tamper_detection() {
        let tls = test_tls_stream_with_keys(true);
        let payload = b"tamper me";
        let mut blob = tls
            .build_secure_record_payload(payload, CONTENT_TYPE_APPLICATION_DATA, 99, true)
            .unwrap();

        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let result = tls.parse_secure_record_payload(
            &blob,
            99,
            true,
            CONTENT_TYPE_APPLICATION_DATA,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_alert_encoding() {
        let alert = vec![ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE];
        assert_eq!(alert[0], ALERT_LEVEL_FATAL);
        assert_eq!(alert[1], ALERT_HANDSHAKE_FAILURE);
    }

    #[test]
    fn test_version_ordering() {
        assert!(TlsVersion::Tls1_2 < TlsVersion::Tls1_3);
        assert_eq!(TlsVersion::Tls1_3, TlsVersion::Tls1_3);
    }

    #[test]
    fn test_pem_for_debug_digest_only() {
        let digest = sha256(b"digest-example");
        let b64 = pem::encode(&digest);
        assert!(!b64.is_empty());
    }
}