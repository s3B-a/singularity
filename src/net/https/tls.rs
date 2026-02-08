use std::io::{Read, Write};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};
use crate::net::tcp::TcpStream;
use crate::crypto::asymmetric::{rsa, ecdh};
use crate::crypto::symmetric::aes;
use crate::crypto::hash::sha2;
use crate::crypto::encoding::x509;
use crate::crypto::kdf::hkdf;
use crate::crypto::random;

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
const HANDSHAKE_CERTIFICATE_REQUEST: u8 = 13;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_FINISHED: u8 = 20;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;

const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_BAD_RECORD_MAC: u8 = 20;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
const ALERT_CERTIFICATE_UNKNOWN: u8 = 46;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_DECODE_ERROR: u8 = 50;
const ALERT_DECRYPT_ERROR: u8 = 51;
const ALERT_PROTOCOL_VERSION: u8 = 70;
const ALERT_INTERNAL_ERROR: u8 = 80;

const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(7200);
const SESSION_TICKET_EXTENSION: u16 = 35;
const PRE_SHARED_KEY_EXTENSION: u16 = 41;
const PSK_KEY_EXCHANGE_MODES_EXTENSION: u16 = 45;

#[derive(Debug, Clone)]
pub struct TlsCfg {
    pub cert_chain: Vec<x509::Certificate>,
    pub private_key: rsa::RsaPrivateKey,
    pub supported_ciphers: Vec<String>,
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    pub verify_peer: bool,
    pub ca_certs: Vec<x509::Certificate>,
    pub session_cache: Option<SessionCache>,
    pub enable_session_resumption: bool,
}

#[derive(Debug, Clone)]
pub struct TlsSession {
    pub session_id: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub cipher_suite: u16,
    pub created_at: std::time::SystemTime,
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
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionState {
    Initial,
    Handshaking,
    Connected,
    Closed,
}

struct TlsKeys {
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
    client_write_iv: Vec<u8>,
    server_write_iv: Vec<u8>,
}

pub struct TlsStream {
    stream: TcpStream,
    config: TlsCfg,
    state: ConnectionState,
    version: TlsVersion,
    cipher_suite: u16,
    keys: Option<TlsKeys>,
    client_cipher: Option<aes::Aes>,
    server_cipher: Option<aes::Aes>,
    handshake_msg: Vec<u8>,
    client_seq: u64,
    server_seq: u64,
    is_client: bool,
    buffer: Vec<u8>,
    server_name: Option<String>,
    session_id: Vec<u8>,
    resuming_session: bool,
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
        if let Ok(elapsed) = self.created_at.elapsed() {
            elapsed < MAX_SESSION_LIFETIME
        } else {
            false
        }
    }

    pub fn age(&self) -> u32 {
        self.created_at.elapsed().map(|d| d.as_secs() as u32).unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct SessionCache {
    sessions: Arc<Mutex<HashMap<String, TlsSession>>>,
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
        if let Ok(sessions) = self.sessions.lock() {
            sessions.get(key).cloned()
        } else {
            None
        }
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
            client_cipher: None,
            server_cipher: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: true,
            buffer: Vec::new(),
            server_name: Some(server_name),
            session_id: Vec::new(),
            resuming_session: false,
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
            client_cipher: None,
            server_cipher: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: false,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
        };

        tls_stream.server_handshake()?;
        Ok(tls_stream)
    }

    fn client_handshake(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;
        let client_random = self.generate_random();
        let ecdh_key = ecdh::EcdhPrivateKey::generate(ecdh::EcdhCurve::X25519)
            .map_err(|e| TlsError::HandshakeFailed(format!("Failed to generate ECDH key: {:?}", e)))?;
        let client_public = ecdh_key.public_key();
        
        let resumable_session = if self.config.enable_session_resumption {
            if let Some(ref cache) = self.config.session_cache {
                if let Some(ref server_name) = self.server_name {
                    cache.get(server_name).filter(|s| s.is_valid()).clone()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let client_hello = if let Some(ref session) = resumable_session {
            self.resuming_session = true;
            self.session_id = session.session_id.clone();
            self.build_resumption_client_hello(&client_random, &client_public, &session)?
        } else {
            self.build_client_hello(&client_random, &client_public)?
        };

        self.handshake_msg.extend_from_slice(&client_hello);
        self.send_handshake_message(HANDSHAKE_CLIENT_HELLO, &client_hello)?;

        let (server_hello_type, server_hello) = self.recieve_handshake_message()?;
        if server_hello_type != HANDSHAKE_SERVER_HELLO {
            return Err(TlsError::HandshakeFailed("Expected ServerHello".to_string()));
        }

        self.handshake_msg.extend_from_slice(&server_hello);
        let (server_random, selected_cipher, peer_public_key, negotiated_version, session_resumed) =
            self.parse_server_hello(&server_hello)?;

        self.version = negotiated_version;
        self.cipher_suite = selected_cipher;
        if session_resumed && self.resuming_session {
            if let Some(ref session) = resumable_session {
                let shared_secret = session.master_secret.clone();
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

        let peer_public = ecdh::EcdhPublicKey::from_bytes(ecdh::EcdhCurve::X25519, &peer_public_key)
            .map_err(|_| TlsError::CipherError("Invalid peer public key".to_string()))?;

        let shared_secret = ecdh_key.exchange(&peer_public)
            .map_err(|e| TlsError::HandshakeFailed(format!("ECDH exchange failed: {:?}", e)))?;
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
        self.save_session(&client_random, &server_random, &shared_secret)?;

        Ok(())
    }

    fn server_handshake(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;
        let (client_hello_type, client_hello) = self.recieve_handshake_message()?;
        if client_hello_type != HANDSHAKE_CLIENT_HELLO {
            return Err(TlsError::HandshakeFailed("Expected ClientHello".to_string()));
        }

        self.handshake_msg.extend_from_slice(&client_hello);
        let (client_random, client_ciphers, client_public_key, client_versions) = self.parse_client_hello(&client_hello)?;
        
        self.version = self.negotiate_version(&client_versions)?;
        self.cipher_suite = self.select_cipher_suite(&client_ciphers)?;

        let ecdh_private = ecdh::EcdhPrivateKey::generate(ecdh::EcdhCurve::X25519)
            .map_err(|e| TlsError::HandshakeFailed(format!("Failed to generate ECDH key: {:?}", e)))?;
        let ecdh_public = ecdh_private.public_key();
        let server_random = self.generate_random();

        let server_hello = self.build_server_hello(&server_random, &ecdh_public)?;
        self.handshake_msg.extend_from_slice(&server_hello);
        self.send_handshake_message(HANDSHAKE_SERVER_HELLO, &server_hello)?;

        let peer_ecdh_public = ecdh::EcdhPublicKey::from_bytes(ecdh::EcdhCurve::X25519, &client_public_key)
            .map_err(|e| TlsError::HandshakeFailed(format!("Invalid peer public key: {:?}", e)))?;
        
        let shared_secret = ecdh_private.exchange(&peer_ecdh_public)
            .map_err(|e| TlsError::HandshakeFailed(format!("ECDH exchange failed: {:?}", e)))?;

        self.derive_handshake_keys(&shared_secret, &client_random, &server_random)?;
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
        self.derive_application_keys(&shared_secret, &client_random, &server_random)?;
        let (finished_type, client_finished) = self.recieve_handshake_message()?;
        if finished_type != HANDSHAKE_FINISHED {
            return Err(TlsError::HandshakeFailed("Expected Finished".to_string()));
        }
        
        self.verify_finished(&client_finished, true)?;
        self.state = ConnectionState::Connected;

        Ok(())
    }

    fn generate_random(&self) -> [u8; 32] {
        let mut random = [0u8; 32];
        random::fill_random(&mut random).expect("Failed to generate cryptographically secure random bytes");
        
        random
    }

    fn build_client_hello(&self, client_random: &[u8; 32], public_key: &ecdh::EcdhPublicKey) -> Result<Vec<u8>, TlsError> {
        let mut hello = vec![];
        hello.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        hello.extend_from_slice(client_random);
        hello.push(0);

        let cipher_count = self.config.supported_ciphers.len() as u16;
        hello.extend_from_slice(&(cipher_count * 2).to_be_bytes());
        for cipher in &self.config.supported_ciphers {
            hello.extend_from_slice(&cipher.parse::<u16>().unwrap_or(0).to_be_bytes());
        }

        hello.push(1);
        hello.push(0);

        let mut ext = Vec::new();

        // Extension: Server Name Indication (SNI) - Type 0
        if let Some(ref server_name) = self.server_name {
            if !server_name.is_empty() {
                ext.extend_from_slice(&0u16.to_be_bytes());
                let host_bytes = server_name.as_bytes();
                let sni_list_len = 3 + host_bytes.len();
                let sni_ext_len = 2 + sni_list_len;

                ext.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
                ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
                ext.push(0);
                ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                ext.extend_from_slice(host_bytes);
            }
        }

        // Extension: Supported Versions - Type 43
        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.push(2);
        ext.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());

        // Extension: Key Share - Type 51
        let key_bytes = public_key.to_bytes();
        let key_share_len = 2 + 2 + 2 + key_bytes.len();
        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        ext.extend_from_slice(&(4 + key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&29u16.to_be_bytes());
        ext.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key_bytes);

        // Extension: Signature Algorithms - Type 13
        ext.extend_from_slice(&13u16.to_be_bytes());
        ext.extend_from_slice(&8u16.to_be_bytes());
        ext.extend_from_slice(&6u16.to_be_bytes());
        ext.extend_from_slice(&0x0804u16.to_be_bytes());
        ext.extend_from_slice(&0x0401u16.to_be_bytes());
        ext.extend_from_slice(&0x0403u16.to_be_bytes());

        // Extension: Application-Layer Protocol Negotiation (ALPN) - Type 16
        ext.extend_from_slice(&16u16.to_be_bytes());
        let alpn_data: Vec<u8> = vec![
            2, b'h', b'2',       // HTTP/2
            8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // HTTP/1.1
        ];
        ext.extend_from_slice(&(alpn_data.len() as u16 + 2).to_be_bytes());
        ext.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_data);

        // Extension: status_request (OCSP Stapling) - Type 5
        ext.extend_from_slice(&5u16.to_be_bytes());
        ext.extend_from_slice(&5u16.to_be_bytes());
        ext.push(1);
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());

        // Extension: supported_groups - Type 10
        ext.extend_from_slice(&10u16.to_be_bytes());
        ext.extend_from_slice(&4u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&29u16.to_be_bytes());

        // Extension: ec_point_formats - Type 11
        ext.extend_from_slice(&11u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.push(1);
        ext.push(0);

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
        let ciphers = vec![
            TLS_AES_256_GCM_SHA384,
            TLS_AES_128_GCM_SHA256,
            TLS_CHACHA20_POLY1305_SHA256,
        ];
        hello.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for cipher in ciphers {
            hello.extend_from_slice(&cipher.to_be_bytes());
        }

        hello.push(1);
        hello.push(0);
        let mut ext = Vec::new();

        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.push(2);
        ext.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());

        let public_key_bytes = public_key.to_bytes();
        ext.extend_from_slice(&51u16.to_be_bytes());
        let key_share_len = 4 + public_key_bytes.len();
        ext.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        ext.extend_from_slice(&((key_share_len - 2) as u16).to_be_bytes());
        ext.extend_from_slice(&0x001du16.to_be_bytes());
        ext.extend_from_slice(&(public_key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&public_key_bytes);

        ext.extend_from_slice(&PSK_KEY_EXCHANGE_MODES_EXTENSION.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.push(1);
        ext.push(1);

        if let Some(ref ticket) = session.ticket {
            ext.extend_from_slice(&PRE_SHARED_KEY_EXTENSION.to_be_bytes());
            let psk_len = 2 + 2 + ticket.len() + 4 + 2 + 1 + 32;
            ext.extend_from_slice(&(psk_len as u16).to_be_bytes());
            
            let identities_len = 2 + ticket.len() + 4;
            ext.extend_from_slice(&(identities_len as u16).to_be_bytes());
            ext.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            ext.extend_from_slice(ticket);
            ext.extend_from_slice(&session.age().to_be_bytes());
            
            ext.extend_from_slice(&33u16.to_be_bytes());
            ext.push(32);
            ext.extend_from_slice(&[0u8; 32]);
        }

        if let Some(ref host) = self.server_name {
            ext.extend_from_slice(&0u16.to_be_bytes());
            let host_bytes = host.as_bytes();
            let sni_len = 5 + host_bytes.len();
            ext.extend_from_slice(&(sni_len as u16).to_be_bytes());
            ext.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            ext.extend_from_slice(host_bytes);
        }

        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        Ok(hello)
    }

    fn build_server_hello(&self, server_random: &[u8; 32], public_key: &ecdh::EcdhPublicKey) -> Result<Vec<u8>, TlsError> {
        let mut hello = vec![];
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
        ext.extend_from_slice(&29u16.to_be_bytes());
        ext.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key_bytes);

        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        Ok(hello)
    }

    fn build_encrypted_extensions(&self) -> Result<Vec<u8>, TlsError> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());

        Ok(ext)
    }

    fn build_certificate(&self) -> Result<Vec<u8>, TlsError> {
        let mut cert_msg = Vec::new();
        cert_msg.push(0);
        
        let mut cert_list = Vec::new();
        for cert in &self.config.cert_chain {
            let cert_der = cert.to_der();
            
            let cert_len = cert_der.len() as u32;
            cert_list.push(((cert_len >> 16) & 0xFF) as u8);
            cert_list.push(((cert_len >> 8) & 0xFF) as u8);
            cert_list.push((cert_len & 0xFF) as u8);
            cert_list.extend_from_slice(&cert_der);
            cert_list.extend_from_slice(&0u16.to_be_bytes());
        }

        let list_len = cert_list.len() as u32;
        cert_msg.push(((list_len >> 16) & 0xFF) as u8);
        cert_msg.push(((list_len >> 8) & 0xFF) as u8);
        cert_msg.push((list_len & 0xFF) as u8);
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
        let signature = self.config.private_key.sign(&to_sign, rsa::RsaPadding::Pkcs1v15)
            .map_err(|e| TlsError::CipherError(format!("Failed to sign CertificateVerify: {:?}", e)))?;

        verify_msg.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        verify_msg.extend_from_slice(&signature);

        Ok(verify_msg)
    }

    fn compute_finished(&self, is_client: bool) -> Result<Vec<u8>, TlsError> {
        let transcript_hash = self.compute_transcript_hash();
        let finished_key = if is_client {
            self.derive_finished_key(true)?
        } else {
            self.derive_finished_key(false)?
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(&finished_key);
        hasher.update(&transcript_hash);
        let verify_data = hasher.finalize();

        Ok(verify_data.to_vec())
    }

    fn verify_finished(&self, finished_msg: &[u8], is_client: bool) -> Result<(), TlsError> {
        let expected = self.compute_finished(is_client)?;
        if finished_msg != expected.as_slice() {
            return Err(TlsError::HandshakeFailed("Finished verification failed".to_string()));
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
            return Err(TlsError::DecodeError("Invalid ClientHello format".to_string()));
        }

        let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        
        let mut ciphers = Vec::new();
        for i in (0..cipher_len).step_by(2) {
            if pos + i + 2 > data.len() {
                break;
            }

            let cipher = u16::from_be_bytes([data[pos + i], data[pos + i + 1]]) as usize;
            ciphers.push(cipher as u16);
        }

        pos += cipher_len;
        if pos >= data.len() {
            return Err(TlsError::DecodeError("Invalid ClientHello format".to_string()));
        }

        let comp_len = data[pos] as usize;
        pos += 1 + comp_len;
        let mut public_key = Vec::new();
        let mut supported_versions = Vec::new();
        if pos + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let ext_end = pos + ext_len;
            while pos + 4 <= ext_end && pos + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                if ext_type == 51 && pos + ext_data_len <= data.len() {
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

                if ext_type == 43 && pos + ext_data_len <= data.len() {
                    let versions_len = data[pos] as usize;
                    let mut vpos = pos + 1;
                    
                    while vpos + 2 <= pos + 1 + versions_len {
                        let version = u16::from_be_bytes([data[vpos], data[vpos + 1]]);
                        supported_versions.push(version);
                        vpos += 2;
                    }
                }

                pos += ext_data_len;
            }
        }
        
        if supported_versions.is_empty() {
            let legacy_version = u16::from_be_bytes([data[0], data[1]]);
            supported_versions.push(legacy_version);
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
        
        let session_resumed = if !self.session_id.is_empty() 
            && session_id_len == self.session_id.len()
            && pos + session_id_len <= data.len() 
            && &data[pos..pos + session_id_len] == &self.session_id[..] {
            true
        } else {
            false
        };
        
        pos += session_id_len;
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError("Invalid ServerHello format".to_string()));
        }

        let cipher = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        pos += 1;

        let mut public_key = Vec::new();
        let mut negotiated_version = TlsVersion::Tls1_2;
        if pos + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let ext_end = pos + ext_len;
            while pos + 4 <= ext_end && pos + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                if ext_type == 43 && pos + ext_data_len <= data.len() {
                    if ext_data_len >= 2 {
                        let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
                        negotiated_version = match version {
                            TLS_VERSION_1_3 => TlsVersion::Tls1_3,
                            TLS_VERSION_1_2 => TlsVersion::Tls1_2,
                            _ => return Err(TlsError::UnsupportedVersion),
                        };
                    }
                }

                if ext_type == 51 && pos + ext_data_len <= data.len() {
                    let mut kpos = pos + 2;
                    if kpos + 2 <= pos + ext_data_len {
                        let group = u16::from_be_bytes([data[kpos], data[kpos + 1]]);
                        kpos += 2;

                        if group == 0x001d && kpos + 2 <= pos + ext_data_len {
                            let key_len =
                                u16::from_be_bytes([data[kpos], data[kpos + 1]]) as usize;
                            kpos += 2;

                            if kpos + key_len <= pos + ext_data_len {
                                public_key.extend_from_slice(&data[kpos..kpos + key_len]);
                            }
                        }
                    }
                }

                pos += ext_data_len;
            }
        }

        Ok((server_random, cipher, public_key, negotiated_version, session_resumed))
    }

    fn handle_new_session_ticket(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if data.len() < 8 {
            return Err(TlsError::DecodeError("Session ticket too short".to_string()));
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
        if let Some(ref mut cache) = self.config.session_cache {
            if let Some(ref server_name) = self.server_name {
                if let Some(ref keys) = self.keys {
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
        }

        Ok(())
    }

    fn save_session(&mut self, client_random: &[u8; 32], server_random: &[u8; 32], shared_secret: &[u8]) -> Result<(), TlsError> {
        if !self.config.enable_session_resumption {
            return Ok(());
        }

        if let Some(ref mut cache) = self.config.session_cache {
            if let Some(ref server_name) = self.server_name {
                if self.session_id.is_empty() {
                    let mut session_id = vec![0u8; 32];
                    random::fill_random(&mut session_id).expect("Failed to generate random session ID");
                    self.session_id = session_id;
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
        }

        Ok(())
    }

    fn select_cipher_suite(&self, client_ciphers: &[u16]) -> Result<u16, TlsError> {
        for cipher in &self.config.supported_ciphers {
            if client_ciphers.contains(&cipher.parse::<u16>().unwrap_or(0)) {
                return Ok(cipher.parse::<u16>().unwrap_or(0));
            }
        }

        Err(TlsError::NoSharedCipher)
    }

    fn verify_certificate(&self, cert_msg: &[u8]) -> Result<(), TlsError> {
        if cert_msg.len() < 10 {
            return Err(TlsError::InvalidCertificate("Certificate message too short".to_string()));
        }

        let mut pos = 1; // Skip context byte        
        if pos + 3 > cert_msg.len() {
            return Err(TlsError::InvalidCertificate("Invalid certificate message format".to_string()));
        }
        
        let cert_list_len = ((cert_msg[pos] as usize) << 16) 
            | ((cert_msg[pos + 1] as usize) << 8) 
            | (cert_msg[pos + 2] as usize);
        pos += 3;
        
        if pos + 3 > cert_msg.len() {
            return Err(TlsError::InvalidCertificate("Certificate list truncated".to_string()));
        }
        
        let cert_len = ((cert_msg[pos] as usize) << 16) 
            | ((cert_msg[pos + 1] as usize) << 8) 
            | (cert_msg[pos + 2] as usize);
        pos += 3;
        if pos + cert_len > cert_msg.len() {
            return Err(TlsError::InvalidCertificate("Certificate data truncated".to_string()));
        }
        
        let cert_der = &cert_msg[pos..pos + cert_len];
        let cert = x509::Certificate::from_der(cert_der)
            .map_err(|e| TlsError::InvalidCertificate(format!("Failed to parse certificate: {:?}", e)))?;
        
        if !cert.is_valid_at_current_time() {
            return Err(TlsError::InvalidCertificate("Certificate expired or not yet valid".to_string()));
        }
        
        if let Some(ref server_name) = self.server_name {
            if !server_name.is_empty() {
                if !cert.matches_hostname(server_name) {
                    return Err(TlsError::InvalidCertificate(format!(
                        "Certificate hostname mismatch: expected {}", server_name
                    )));
                }
            }
        }
        
        if !self.config.ca_certs.is_empty() {
            let mut verified = false;
            
            for ca_cert in &self.config.ca_certs {
                if cert.verify_signature(ca_cert).is_ok() {
                    verified = true;
                    break;
                }
            }
            
            if !verified {
                return Err(TlsError::VerificationFailed(
                    "Certificate chain verification failed: no trusted CA found".to_string()
                ));
            }
        } else if self.config.verify_peer {
            eprintln!("Warning: verify_peer is true but no CA certificates provided");
        }
        
        Ok(())
    }

    fn verify_certificate_verify(&self, verify_msg: &[u8]) -> Result<(), TlsError> {
        for ver in &self.config.cert_chain {
            let public_key_bytes = ver.public_key().ok_or(TlsError::InvalidCertificate("Missing public key".to_string()))?;
            let public_key = rsa::RsaPublicKey::from_bytes(&public_key_bytes)
                .map_err(|_| TlsError::InvalidCertificate("Failed to parse public key".to_string()))?;
            let signature_len = u16::from_be_bytes([verify_msg[2], verify_msg[3]]) as usize;
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
            if public_key.verify(&to_verify, signature, rsa::RsaPadding::Pkcs1v15).is_ok() {
                return Ok(());
            }
        }

        Err(TlsError::VerificationFailed("CertificateVerify verification failed".to_string()))
    }

    fn derive_handshake_keys(&mut self, shared_secret: &[u8], _client_random: &[u8; 32], _server_random: &[u8; 32]) -> Result<(), TlsError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"");
        let empty_hash = hasher.finalize();

        let early_secret = hkdf::Hkdf::extract(Some(&[0u8; 32]), &[0u8; 32]);
        let derived = self.hkdf_expand_label(&early_secret, b"derived", &empty_hash, 32)?;
        let handshake_secret = hkdf::Hkdf::extract(Some(&derived), shared_secret);
        let transcript_hash = self.compute_transcript_hash();
        let client_handshake_traffic_secret = self.hkdf_expand_label(&handshake_secret, b"c hs traffic", &transcript_hash, 32)?;
        let server_handshake_traffic_secret = self.hkdf_expand_label(&handshake_secret, b"s hs traffic", &transcript_hash, 32)?;
        
        let client_write_key = self.hkdf_expand_label(&client_handshake_traffic_secret, b"key", b"", 16)?;
        let client_write_iv = self.hkdf_expand_label(&client_handshake_traffic_secret, b"iv", b"", 12)?;
        let server_write_key = self.hkdf_expand_label(&server_handshake_traffic_secret, b"key", b"", 16)?;
        let server_write_iv = self.hkdf_expand_label(&server_handshake_traffic_secret, b"iv", b"", 12)?;
        
        self.keys = Some(TlsKeys {
            client_write_key: client_write_key.clone(),
            server_write_key: server_write_key.clone(),
            client_write_iv: client_write_iv.clone(),
            server_write_iv: server_write_iv.clone(),
        });

        self.client_cipher = Some(aes::Aes::new(&client_write_key).map_err(|e|
            TlsError::CipherError(format!("Failed to create client cipher: {:?}", e))
        )?);

        self.server_cipher = Some(aes::Aes::new(&server_write_key).map_err(|e|
            TlsError::CipherError(format!("Failed to create server cipher: {:?}", e))
        )?);
        
        Ok(())
    }

    fn derive_keys(&mut self, _client_random: &[u8; 32], _server_random: &[u8; 32], shared_secret: &[u8]) -> Result<(), TlsError> {
        self.derive_application_keys(shared_secret, _client_random, _server_random)
    }

    fn derive_application_keys(&mut self, shared_secret: &[u8], _client_random: &[u8; 32], _server_random: &[u8; 32]) -> Result<(), TlsError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"");
        let _empty_hash = hasher.finalize();

        let handshake_hash = self.compute_transcript_hash();
        let client_app_traffic_secret = self.hkdf_expand_label(shared_secret, b"c ap traffic", &handshake_hash, 32)?;
        let server_app_traffic_secret = self.hkdf_expand_label(shared_secret, b"s ap traffic", &handshake_hash, 32)?;

        let client_write_key = self.hkdf_expand_label(&client_app_traffic_secret, b"key", b"", 16)?;
        let client_write_iv = self.hkdf_expand_label(&client_app_traffic_secret, b"iv", b"", 12)?;
        let server_write_key = self.hkdf_expand_label(&server_app_traffic_secret, b"key", b"", 16)?;
        let server_write_iv = self.hkdf_expand_label(&server_app_traffic_secret, b"iv", b"", 12)?;
        
        self.keys = Some(TlsKeys {
            client_write_key: client_write_key.clone(),
            server_write_key: server_write_key.clone(),
            client_write_iv: client_write_iv.clone(),
            server_write_iv: server_write_iv.clone(),
        });

        self.client_cipher = Some(aes::Aes::new(&client_write_key).map_err(|e|
            TlsError::CipherError(format!("Failed to create client cipher: {:?}", e))
        )?);

        self.server_cipher = Some(aes::Aes::new(&server_write_key).map_err(|e|
            TlsError::CipherError(format!("Failed to create server cipher: {:?}", e))
        )?);
        
        Ok(())
    }

    fn derive_finished_key(&self, is_client: bool) -> Result<Vec<u8>, TlsError> {
        let keys = self.keys.as_ref().ok_or_else(|| TlsError::HandshakeFailed("Keys not derived".to_string()))?;
        let base_key = if is_client {
            &keys.client_write_key
        } else {
            &keys.server_write_key
        };

        self.hkdf_expand_label(base_key, b"finished", b"", 32)
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, TlsError> {
        let mut hkdf_label = Vec::new();
        let full_label = [b"tls13 ", label].concat();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(full_label.len() as u8);
        hkdf_label.extend_from_slice(&full_label);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);
        hkdf::Hkdf::expand(secret, &hkdf_label, length).map_err(|e| 
            TlsError::CipherError(format!("HKDF expand failed: {:?}", e))
        )
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
        message.push(((len >> 16) & 0xFF) as u8);
        message.push(((len >> 8) & 0xFF) as u8);
        message.push((len & 0xFF) as u8);
        message.extend_from_slice(msg);

        self.send_record(CONTENT_TYPE_HANDSHAKE, &message)
    }

    fn recieve_handshake_message(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        let record_data = self.receive_record()?;
        if record_data.len() < 4 {
            return Err(TlsError::DecodeError("Handshake message too short".to_string()));
        }

        let msg_type = record_data[0];
        let msg_len = ((record_data[1] as usize) << 16) | ((record_data[2] as usize) << 8) | (record_data[3] as usize);
        if record_data.len() < 4 + msg_len {
            return Err(TlsError::DecodeError("Incomplete handshake message".to_string()));
        }

        let msg_data = record_data[4..4 + msg_len].to_vec();
        
        Ok((msg_type, msg_data))
    }

    fn send_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), TlsError> {
        let mut record = Vec::new();
        let (final_content_type, payload) = if self.state == ConnectionState::Handshaking 
            && self.client_cipher.is_some()
            && (content_type == CONTENT_TYPE_HANDSHAKE || content_type == CONTENT_TYPE_APPLICATION_DATA) {
                let encrypted = self.encrypt_record(data, content_type)?;
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
                let level = payload[0];
                let description = payload[1];
                return Err(TlsError::AlertReceived(level, description));
            }
        }

        if content_type == CONTENT_TYPE_APPLICATION_DATA && self.server_cipher.is_some() {
            let (decrypted, _original_type) = self.decrypt_record(&payload)?;
            Ok(decrypted)
        } else {
            Ok(payload)
        }
    }

    fn encrypt_record(&mut self, plaintext: &[u8], content_type: u8) -> Result<Vec<u8>, TlsError> {
        let cipher = if self.is_client {
            self.client_cipher.as_ref()
        } else {
            self.server_cipher.as_ref()
        }.ok_or_else(|| TlsError::CipherError("Cipher not initialized".to_string()))?;

        let keys = self.keys.as_ref().ok_or_else(|| TlsError::CipherError("Keys not initialized".to_string()))?;
        let mut to_encrypt = plaintext.to_vec();
        to_encrypt.push(content_type);
        while to_encrypt.len() % 16 != 0 {
            to_encrypt.push(0);
        }

        let seq = if self.is_client {
            let s = self.client_seq;
            self.client_seq += 1;
            s
        } else {
            let s = self.server_seq;
            self.server_seq += 1;
            s
        };

        let iv = if self.is_client {
            &keys.client_write_iv
        } else {
            &keys.server_write_iv
        };

        let mut nonce = [0u8; 12];
        nonce[..12].copy_from_slice(&iv[..12]);
        for i in 0..8 {
            nonce[4 + i] ^= ((seq >> (56 - i * 8)) & 0xFF) as u8;
        }

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&nonce);
        for chunk in to_encrypt.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let encrypted_block = cipher.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted_block[..chunk.len()]);
        }

        let mut hasher = sha2::Sha256::new();
        hasher.update(&ciphertext);
        let tag = hasher.finalize();
        ciphertext.extend_from_slice(&tag[..16]);

        Ok(ciphertext)
    }

    fn decrypt_record(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, u8), TlsError> {
        if ciphertext.len() < 28 {
            return Err(TlsError::CipherError("Ciphertext too short".to_string()));
        }

        let cipher = if self.is_client {
            self.server_cipher.as_ref()
        } else {
            self.client_cipher.as_ref()
        }.ok_or_else(|| TlsError::CipherError("Cipher not initialized".to_string()))?;

        let nonce = &ciphertext[..12];
        let encrypted_data = &ciphertext[12..ciphertext.len() - 16];
        let received_tag = &ciphertext[ciphertext.len() - 16..];

        let mut hasher = sha2::Sha256::new();
        hasher.update(&ciphertext[..ciphertext.len() - 16]);
        let computed_tag = hasher.finalize();
        
        let mut tag_match = true;
        for i in 0..16 {
            if computed_tag[i] != received_tag[i] {
                tag_match = false;
            }
        }
        
        if !tag_match {
            return Err(TlsError::CipherError("Authentication tag verification failed".to_string()));
        }

        let mut plaintext = Vec::new();
        for chunk in encrypted_data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let decrypted_block = cipher.decrypt_block(&block);
            plaintext.extend_from_slice(&decrypted_block[..chunk.len()]);
        }

        while plaintext.last() == Some(&0) {
            plaintext.pop();
        }

        let content_type = plaintext.pop().ok_or_else(||
            TlsError::CipherError("Decrypted data empty".to_string())
        )?;

        Ok((plaintext, content_type))
    }

    fn negotiate_version(&self, client_versions: &[u16]) -> Result<TlsVersion, TlsError> {
        if client_versions.contains(&TLS_VERSION_1_3)
            && self.config.max_version >= TlsVersion::Tls1_3
            && self.config.min_version <= TlsVersion::Tls1_3
        {
            return Ok(TlsVersion::Tls1_3);
        }

        if client_versions.contains(&TLS_VERSION_1_2)
            && self.config.min_version <= TlsVersion::Tls1_2
            && self.config.max_version >= TlsVersion::Tls1_2
        {
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
}

impl Default for TlsCfg {
    fn default() -> Self {
        TlsCfg {
            cert_chain: vec![],
            private_key: rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048)
                .expect("Failed to generate RSA key"),
            supported_ciphers: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            min_version: TlsVersion::Tls1_3,
            max_version: TlsVersion::Tls1_3,
            verify_peer: true,
            ca_certs: vec![],
            session_cache: Some(SessionCache::new()),
            enable_session_resumption: true,
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
            TlsError::AlertReceived(level, desc) => {
                write!(f, "Alert Received: level={}, description={}", level, desc)
            }
            TlsError::DecodeError(msg) => write!(f, "Decode Error: {}", msg),
            TlsError::UnsupportedVersion => write!(f, "Unsupported TLS Version"),
            TlsError::NoSharedCipher => write!(f, "No Shared Cipher Suite"),
            TlsError::VerificationFailed(msg) => write!(f, "Verification Failed: {}", msg),
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
    use std::thread;
    use std::sync::mpsc;
    use crate::net::tcp::TcpListener;

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

    #[test]
    fn test_tls_config_default() {
        let cfg = TlsCfg::default();
        assert_eq!(cfg.min_version, TlsVersion::Tls1_2);
        assert_eq!(cfg.max_version, TlsVersion::Tls1_3);
        assert!(!cfg.verify_peer);
        assert_eq!(cfg.supported_ciphers.len(), 3);
        assert_eq!(cfg.supported_ciphers[0], "4865"); // TLS_AES_128_GCM_SHA256 as string
        assert_eq!(cfg.supported_ciphers[1], "4866"); // TLS_AES_256_GCM_SHA384 as string
        assert_eq!(cfg.supported_ciphers[2], "4867"); // TLS_CHACHA20_POLY1305_SHA256 as string
        assert!(cfg.cert_chain.is_empty());
        assert!(cfg.ca_certs.is_empty());
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
            client_cipher: None,
            server_cipher: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: true,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
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
            client_cipher: None,
            server_cipher: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: false,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
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
    fn test_server_hello_parsing() {
        let (addr, _rx) = start_test_server();
        let stream = TcpStream::connect(&addr).expect("Failed to connect");
        
        let tls = TlsStream {
            stream,
            config: TlsCfg::default(),
            state: ConnectionState::Initial,
            version: TlsVersion::Tls1_3,
            cipher_suite: 0,
            keys: None,
            client_cipher: None,
            server_cipher: None,
            handshake_msg: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_client: true,
            buffer: Vec::new(),
            server_name: None,
            session_id: Vec::new(),
            resuming_session: false,
        };

        let server_hello = vec![
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x13, 0x01,
            0x00,
            0x00, 0x00,
        ];

        let result = tls.parse_server_hello(&server_hello);
        assert!(result.is_ok());
        let (_, cipher, _, _, _) = result.unwrap();
        assert_eq!(cipher, 0x1301);
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
}