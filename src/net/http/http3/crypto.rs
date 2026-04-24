use super::error::{Error, Result};
use super::packet::{PacketNumberSpace, PacketType};
use super::quic_tls::{CryptoAction, QuicTlsState};
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::kdf::hkdf::Hkdf;
use crate::crypto::random;
use crate::crypto::symmetric::aes::Aes;
use crate::crypto::symmetric::gcm::Gcm;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use crate::net::https::tls::{TlsCfg, TlsStream};
use crate::net::tcp::TcpStream;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const CRYPTO_STATE_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_CRYPTO_STATE_BLOB_V1";
const CRYPTO_STATE_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_CRYPTO_STATE_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCryptoStateBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionLevel {
    Initial,
    ZeroRtt,
    Handshake,
    Application,
}

impl EncryptionLevel {
    pub fn from_packet_type(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::Initial => Self::Initial,
            PacketType::ZeroRtt => Self::ZeroRtt,
            PacketType::Handshake => Self::Handshake,
            PacketType::Short => Self::Application,
            _ => EncryptionLevel::Initial,
        }
    }

    pub fn to_packet_number_space(&self) -> PacketNumberSpace {
        match self {
            EncryptionLevel::Initial => PacketNumberSpace::Initial,
            EncryptionLevel::Handshake => PacketNumberSpace::Handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::Application => PacketNumberSpace::ApplicationData,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptionLevel::Initial => "initial",
            EncryptionLevel::ZeroRtt => "zero-rtt",
            EncryptionLevel::Handshake => "handshake",
            EncryptionLevel::Application => "application",
        }
    }

    pub fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "initial" => Ok(EncryptionLevel::Initial),
            "zero-rtt" => Ok(EncryptionLevel::ZeroRtt),
            "handshake" => Ok(EncryptionLevel::Handshake),
            "application" => Ok(EncryptionLevel::Application),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid encryption level '{}'", value),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CryptoKeys {
    pub header_key: Vec<u8>,
    pub packet_key: Vec<u8>,
    pub iv: Vec<u8>,
}

impl CryptoKeys {
    pub fn new(header_key: Vec<u8>, packet_key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self {
            header_key,
            packet_key,
            iv,
        }
    }
}

#[derive(Debug, Clone)]
struct TlsSecrets {
    client_handshake_secret: Option<Vec<u8>>,
    server_handshake_secret: Option<Vec<u8>>,
    client_application_secret: Option<Vec<u8>>,
    server_application_secret: Option<Vec<u8>>,
}

impl TlsSecrets {
    fn new() -> Self {
        Self {
            client_handshake_secret: None,
            server_handshake_secret: None,
            client_application_secret: None,
            server_application_secret: None,
        }
    }
}

pub struct CryptoState {
    pub client_keys: HashMap<EncryptionLevel, CryptoKeys>,
    pub server_keys: HashMap<EncryptionLevel, CryptoKeys>,
    send_level: EncryptionLevel,
    receive_level: EncryptionLevel,
    is_client: bool,
    tls_secret: TlsSecrets,
    tls_stream: Option<TlsStream>,
    handshake_complete: bool,
    quic_tls: Option<QuicTlsState>,
}

impl CryptoState {
    pub fn new(is_client: bool) -> Self {
        Self {
            client_keys: HashMap::new(),
            server_keys: HashMap::new(),
            send_level: EncryptionLevel::Initial,
            receive_level: EncryptionLevel::Initial,
            is_client,
            tls_secret: TlsSecrets::new(),
            tls_stream: None,
            handshake_complete: false,
            quic_tls: None,
        }
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureCryptoStateBlobMeta, Vec<u8>)> {
        encode_secure_crypto_state(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureCryptoStateBlobMeta, Vec<u8>)> {
        encode_secure_crypto_state_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureCryptoStateBlobMeta, Self)> {
        decode_secure_crypto_state(data)
    }

    pub fn with_tls_stream(mut self, tls_stream: TlsStream) -> Self {
        self.tls_stream = Some(tls_stream);
        self.handshake_complete = true;

        self
    }

    pub fn initialize_tls(&mut self, tcp_stream: TcpStream, config: TlsCfg, server_name: Option<String>) -> Result<()> {
        let tls_stream = if self.is_client {
            if let Some(sni) = server_name {
                TlsStream::new_client_with_sni(tcp_stream, config, sni)
                    .map_err(|e| Error::InvalidOperation(format!("TLS handshake failed: {}", e)))?
            } else {
                TlsStream::new_client(tcp_stream, config)
                    .map_err(|e| Error::InvalidOperation(format!("TLS handshake failed: {}", e)))?
            }
        } else {
            TlsStream::new_server(tcp_stream, config)
                .map_err(|e| Error::InvalidOperation(format!("TLS handshake failed: {}", e)))?
        };

        self.tls_stream = Some(tls_stream);
        self.handshake_complete = true;
        self.extract_tls_keys()?;
        
        Ok(())
    }

    fn extract_tls_keys(&mut self) -> Result<()> {
        if self.handshake_complete && self.tls_stream.is_some() {
            self.set_send_level(EncryptionLevel::Application);
            self.set_receive_level(EncryptionLevel::Application);
        }
        
        Ok(())
    }

    pub fn derive_initial_keys(&mut self, dcid: &[u8]) -> Result<()> {
        const INITIAL_SALT: &[u8] = &[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];

        let initial_secret = Hkdf::extract(Some(INITIAL_SALT), dcid);
        let client_initial_secret = self.derive_secret(&initial_secret, b"client in")?;
        let server_initial_secret = self.derive_secret(&initial_secret, b"server in")?;
        let client_keys = self.derive_keys_from_secret(&client_initial_secret)?;
        self.client_keys.insert(EncryptionLevel::Initial, client_keys);
        let server_keys = self.derive_keys_from_secret(&server_initial_secret)?;
        self.server_keys.insert(EncryptionLevel::Initial, server_keys);

        Ok(())
    }

    fn derive_secret(&self, secret: &[u8], label: &[u8]) -> Result<Vec<u8>> {
        let label_with_prefix = [b"tls13 ", label].concat();
        let info = self.build_hkdf_label(32, &label_with_prefix, &[]);

        Hkdf::expand(secret, &info, 32).map_err(|_| Error::CryptoError)
    }

    fn build_hkdf_label(&self, length: usize, label: &[u8], context: &[u8]) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&(length as u16).to_be_bytes());
        info.push(label.len() as u8);
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        info
    }

    fn derive_keys_from_secret(&self, secret: &[u8]) -> Result<CryptoKeys> {
        let key_label = b"tls13 quic key";
        let key_info = self.build_hkdf_label(16, key_label, &[]);
        let packet_key = Hkdf::expand(secret, &key_info, 16).map_err(|_| Error::CryptoError)?;

        let iv_label = b"tls13 quic iv";
        let iv_info = self.build_hkdf_label(12, iv_label, &[]);
        let iv = Hkdf::expand(secret, &iv_info, 12).map_err(|_| Error::CryptoError)?;

        let hp_label = b"tls13 quic hp";
        let hp_info = self.build_hkdf_label(16, hp_label, &[]);
        let header_key = Hkdf::expand(secret, &hp_info, 16).map_err(|_| Error::CryptoError)?;

        Ok(CryptoKeys::new(header_key, packet_key, iv))
    }

    pub fn install_handshake_keys(&mut self, client_secret: Vec<u8>, server_secret: Vec<u8>) -> Result<()> {
        self.tls_secret.client_handshake_secret = Some(client_secret.clone());
        self.tls_secret.server_handshake_secret = Some(server_secret.clone());

        let client_keys = self.derive_keys_from_secret(&client_secret)?;
        let server_keys = self.derive_keys_from_secret(&server_secret)?;

        self.client_keys.insert(EncryptionLevel::Handshake, client_keys);
        self.server_keys.insert(EncryptionLevel::Handshake, server_keys);

        Ok(())
    }

    pub fn initialize_quic_tls(&mut self, server_name: Option<String>, transport_params: Vec<u8>) -> Result<()> {
        let mut quic_tls = if self.is_client {
            QuicTlsState::new_client(server_name)
        } else {
            QuicTlsState::new_server()
        };
        
        quic_tls.set_transport_params(transport_params);
        self.quic_tls = Some(quic_tls);
        
        Ok(())
    }
    
    pub fn start_quic_handshake(&mut self) -> Result<()> {
        let mut quic_tls = self.quic_tls.take().ok_or_else(|| Error::InvalidOperation("QUIC TLS not initialized".to_string()))?;
        quic_tls.start_handshake(self)?;
        self.quic_tls = Some(quic_tls);

        Ok(())
    }
    
    pub fn process_quic_crypto(&mut self, offset: u64, data: Vec<u8>) -> Result<Vec<CryptoAction>> {
        if self.quic_tls.is_none() {
            return Err(Error::InvalidOperation(
                "QUIC TLS not initialized".to_string(),
            ));
        }

        let mut quic_tls = self.quic_tls.take().unwrap();
        let result = quic_tls.process_crypto_data(offset, data, self);
        self.quic_tls = Some(quic_tls);
        result
    }
    
    pub fn next_quic_crypto_data(&mut self) -> Option<(super::packet::PacketNumberSpace, Vec<u8>)> {
        self.quic_tls.as_mut().and_then(|tls| tls.next_crypto_data())
    }
    
    pub fn is_quic_handshake_complete(&self) -> bool {
        self.quic_tls.as_ref().map(|tls| tls.is_complete()).unwrap_or(false)
    }

    pub fn encrypt(&self, level: EncryptionLevel, packet_number: u64, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let keys = if self.is_client {
            self.client_keys.get(&level)
        } else {
            self.server_keys.get(&level)
        }.ok_or(Error::KeyUnavailable)?;

        let nonce = self.construct_nonce(&keys.iv, packet_number);
        let gcm = Gcm::new(&keys.packet_key).map_err(|_| Error::CryptoError)?;
        let ciphertext = gcm.encrypt(&nonce, plaintext, associated_data).map_err(|_| Error::CryptoError)?;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, level: EncryptionLevel, packet_number: u64, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let keys = if self.is_client {
            self.server_keys.get(&level)
        } else {
            self.client_keys.get(&level)
        }.ok_or(Error::KeyUnavailable)?;

        let nonce = self.construct_nonce(&keys.iv, packet_number);
        let gcm = Gcm::new(&keys.packet_key).map_err(|_| Error::CryptoError)?;
        let plaintext = gcm.decrypt(&nonce, ciphertext, associated_data).map_err(|_| Error::CryptoError)?;

        Ok(plaintext)
    }

    pub fn protect_header(&self, level: EncryptionLevel, header: &mut [u8], sample: &[u8]) -> Result<()> {
        let keys = if self.is_client {
            self.client_keys.get(&level)
        } else {
            self.server_keys.get(&level)
        }.ok_or(Error::KeyUnavailable)?;

        let aes = Aes::new(&keys.header_key).map_err(|_| Error::CryptoError)?;
        let mask = aes.encrypt_block(&sample[..16]);
        if header[0] & 0x80 == 0x80 {
            header[0] ^= mask[0] & 0x0f;
        } else {
            header[0] ^= mask[0] & 0x1f;
        }

        let pn_length = ((header[0] & 0x03) + 1) as usize;
        let pn_offset = header.len() - pn_length;
        for i in 0..pn_length {
            header[pn_offset + i] ^= mask[1 + i];
        }

        Ok(())
    }

    pub fn unprotect_header(&self, level: EncryptionLevel, header: &mut [u8], sample: &[u8]) -> Result<()> {
        let keys = if self.is_client {
            self.server_keys.get(&level)
        } else {
            self.client_keys.get(&level)
        }.ok_or(Error::KeyUnavailable)?;

        let aes = Aes::new(&keys.header_key).map_err(|_| Error::CryptoError)?;
        let mask = aes.encrypt_block(&sample[..16]);
        if header[0] & 0x80 == 0x80 {
            header[0] ^= mask[0] & 0x0f;
        } else {
            header[0] ^= mask[0] & 0x1f;
        }

        let pn_length = ((header[0] & 0x03) + 1) as usize;
        let pn_offset = header.len() - pn_length;
        for i in 0..pn_length {
            header[pn_offset + i] ^= mask[1 + i];
        }

        Ok(())
    }

    fn construct_nonce(&self, iv: &[u8], packet_number: u64) -> Vec<u8> {
        let mut nonce = iv.to_vec();
        let pn_bytes = packet_number.to_be_bytes();
        let offset = nonce.len() - 8;
        for i in 0..8 {
            nonce[offset + i] ^= pn_bytes[i];
        }

        nonce
    }
    
    pub fn set_send_level(&mut self, level: EncryptionLevel) {
        self.send_level = level;
    }

    pub fn set_receive_level(&mut self, level: EncryptionLevel) {
        self.receive_level = level;
    }

    pub fn send_level(&self) -> EncryptionLevel {
        self.send_level
    }

    pub fn receive_level(&self) -> EncryptionLevel {
        self.receive_level
    }

    pub fn discard_keys(&mut self, level: EncryptionLevel) {
        self.client_keys.remove(&level);
        self.server_keys.remove(&level);
    }

    pub fn has_keys(&self, level: EncryptionLevel) -> bool {
        let client_has = self.client_keys.contains_key(&level);
        let server_has = self.server_keys.contains_key(&level);
        client_has && server_has
    }

    pub fn update_application_keys(&mut self) -> Result<()> {
        if let Some(client_secret) = self.tls_secret.client_application_secret.clone() {
            let new_client_secret = self.derive_secret(&client_secret, b"quic ku")?;
            let client_keys = self.derive_keys_from_secret(&new_client_secret)?;
            self.client_keys.insert(EncryptionLevel::Application, client_keys);
            self.tls_secret.client_application_secret = Some(new_client_secret);
        }

        if let Some(server_secret) = self.tls_secret.server_application_secret.clone() {
            let new_server_secret = self.derive_secret(&server_secret, b"quic ku")?;
            let server_keys = self.derive_keys_from_secret(&new_server_secret)?;
            self.server_keys.insert(EncryptionLevel::Application, server_keys);
            self.tls_secret.server_application_secret = Some(new_server_secret);
        }

        Ok(())
    }

    pub fn handle_crypto_data(&mut self, data: &[u8]) -> Result<()> {
        let tls_stream = self.tls_stream.as_mut().ok_or_else(|| Error::InvalidOperation("TLS not initialized".to_string()))?;
        tls_stream.write_all(data).map_err(|e| Error::InvalidOperation(format!("TLS write failed: {}", e)))?;
        self.extract_tls_keys()?;

        Ok(())
    }

    pub fn read_crypto_data(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            tls_stream.read(buffer)
                .map_err(|e| Error::InvalidOperation(format!("Failed to read crypto data: {}", e)))
        } else {
            Ok(0)
        }
    }

    #[deprecated(note = "Use handle_crypto_data with TLS stream")]
    pub fn handle_frame(&mut self, _offset: u64, data: Vec<u8>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let msg_type = data[0];
        if self.is_client {
            match msg_type {
                0x02 => {
                    if data.len() > 1 {
                        if let Ok(handshake_secret) = self.derive_secret(&data[1..], b"handshake") {
                            self.tls_secret.server_handshake_secret = Some(handshake_secret.clone());
                            let client_secret = self.tls_secret.client_handshake_secret
                                .clone()
                                .unwrap_or_else(|| data[1..].to_vec());
                            
                            let _ = self.install_handshake_keys(client_secret, handshake_secret);
                            self.set_send_level(EncryptionLevel::Handshake);
                            self.set_receive_level(EncryptionLevel::Handshake);
                        }
                    }
                }
                0x08 => {
                    self.set_send_level(EncryptionLevel::Application);
                    self.set_receive_level(EncryptionLevel::Application);
                }
                0x0b => {
                    if data.len() > 4 {
                        let cert_len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
                        if data.len() >= cert_len + 4 {
                            let _cert_data = &data[4..cert_len + 4];
                        }
                    }
                }
                0x14 => {
                    if data.len() > 1 {
                        if let Ok(app_secret) = self.derive_secret(&data[1..], b"application") {
                            self.tls_secret.client_application_secret = Some(app_secret.clone());
                            self.tls_secret.server_application_secret = Some(app_secret.clone());
                            
                            let app_keys = self.derive_keys_from_secret(&app_secret)?;
                            self.client_keys.insert(EncryptionLevel::Application, app_keys.clone());
                            self.server_keys.insert(EncryptionLevel::Application, app_keys);
                            
                            self.set_send_level(EncryptionLevel::Application);
                            self.set_receive_level(EncryptionLevel::Application);
                            self.handshake_complete = true;
                        }
                    }
                }
                _ => {}
            }
        } else {
            match msg_type {
                0x01 => {
                    if data.len() > 1 {
                        if let Ok(handshake_secret) = self.derive_secret(&data[1..], b"handshake") {
                            self.tls_secret.client_handshake_secret = Some(handshake_secret.clone());
                            let server_secret = self.tls_secret.server_handshake_secret
                                .clone()
                                .unwrap_or_else(|| data[1..].to_vec());
                            
                            let _ = self.install_handshake_keys(handshake_secret, server_secret);
                            self.set_send_level(EncryptionLevel::Handshake);
                            self.set_receive_level(EncryptionLevel::Handshake);
                        }
                    }
                }
                0x14 => {
                    if data.len() > 1 {
                        if let Ok(app_secret) = self.derive_secret(&data[1..], b"application") {
                            self.tls_secret.client_application_secret = Some(app_secret.clone());
                            self.tls_secret.server_application_secret = Some(app_secret.clone());
                            
                            let app_keys = self.derive_keys_from_secret(&app_secret)?;
                            self.client_keys.insert(EncryptionLevel::Application, app_keys.clone());
                            self.server_keys.insert(EncryptionLevel::Application, app_keys);
                            
                            self.set_send_level(EncryptionLevel::Application);
                            self.set_receive_level(EncryptionLevel::Application);
                            self.handshake_complete = true;
                        }
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete || (self.tls_secret.client_application_secret.is_some() && self.tls_secret.server_application_secret.is_some())
    }

    pub fn get_tls_stream(&self) -> Option<&TlsStream> {
        self.tls_stream.as_ref()
    }

    pub fn get_tls_stream_mut(&mut self) -> Option<&mut TlsStream> {
        self.tls_stream.as_mut()
    }

    pub fn take_tls_stream(&mut self) -> Option<TlsStream> {
        self.tls_stream.take()
    }

    pub fn take_pending_frame(&mut self, pn_space: PacketNumberSpace) -> Option<super::frame::Frame> {
        let quic_tls = self.quic_tls.as_mut()?;
        if let Some((frame_pn_space, data)) = quic_tls.next_crypto_data() {
            if frame_pn_space == pn_space {
                return Some(super::frame::Frame::Crypto { offset: 0, data });
            }

            quic_tls.push_back_crypto_data(frame_pn_space, data);
        }

        None
    }
}

pub fn select_secure_crypto_state_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_crypto_state(state: &CryptoState, algorithm: CompressionAlgorithm) -> io::Result<(SecureCryptoStateBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_crypto_state(state);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate crypto-state blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_crypto_state_blob_tag(
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
        magic = CRYPTO_STATE_BLOB_MAGIC,
        encoding = selected_algorithm.content_encoding(),
        nonce = nonce_b64,
        digest = digest_b64,
        tag = tag_b64,
        raw_size = raw_payload.len(),
        encoded_size = encoded_payload.len(),
        issued_at = issued_at_unix
    );

    let mut blob = header.into_bytes();
    blob.extend_from_slice(&encoded_payload);

    Ok((SecureCryptoStateBlobMeta {
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

pub fn encode_secure_crypto_state_auto(state: &CryptoState, accept_encoding: &str) -> io::Result<(SecureCryptoStateBlobMeta, Vec<u8>)> {
    let selected = select_secure_crypto_state_algorithm(accept_encoding);
    encode_secure_crypto_state(state, selected)
}

pub fn decode_secure_crypto_state(data: &[u8]) -> io::Result<(SecureCryptoStateBlobMeta, CryptoState)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_crypto_state_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "digest or tag has invalid length",
        ));
    }

    let expected_tag = compute_crypto_state_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crypto-state blob HMAC mismatch",
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
                "raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crypto-state blob digest mismatch",
        ));
    }

    let state = deserialize_crypto_state(&raw_payload)?;
    Ok((meta, state))
}

fn serialize_crypto_state(state: &CryptoState) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!("is-client={}", state.is_client));
    lines.push(format!("send-level={}", state.send_level.as_str()));
    lines.push(format!("receive-level={}", state.receive_level.as_str()));
    lines.push(format!("handshake-complete={}", state.handshake_complete));
    lines.push(format!("tls-stream-present={}", state.tls_stream.is_some()));
    lines.push(format!("quic-tls-present={}", state.quic_tls.is_some()));
    lines.push(format!(
        "tls-client-handshake-present={}",
        state.tls_secret.client_handshake_secret.is_some()
    ));

    if let Some(secret) = &state.tls_secret.client_handshake_secret {
        lines.push(format!(
            "tls-client-handshake={}",
            pem::encode(secret.as_slice())
        ));
    }

    lines.push(format!(
        "tls-server-handshake-present={}",
        state.tls_secret.server_handshake_secret.is_some()
    ));

    if let Some(secret) = &state.tls_secret.server_handshake_secret {
        lines.push(format!(
            "tls-server-handshake={}",
            pem::encode(secret.as_slice())
        ));
    }

    lines.push(format!(
        "tls-client-application-present={}",
        state.tls_secret.client_application_secret.is_some()
    ));

    if let Some(secret) = &state.tls_secret.client_application_secret {
        lines.push(format!(
            "tls-client-application={}",
            pem::encode(secret.as_slice())
        ));
    }

    lines.push(format!(
        "tls-server-application-present={}",
        state.tls_secret.server_application_secret.is_some()
    ));

    if let Some(secret) = &state.tls_secret.server_application_secret {
        lines.push(format!(
            "tls-server-application={}",
            pem::encode(secret.as_slice())
        ));
    }

    let mut client_levels: Vec<EncryptionLevel> = state.client_keys.keys().copied().collect();
    client_levels.sort_by_key(|lvl| encryption_level_rank(*lvl));
    lines.push(format!("client-key-count={}", client_levels.len()));
    for (idx, level) in client_levels.iter().enumerate() {
        if let Some(keys) = state.client_keys.get(level) {
            lines.push(format!("client-key-{}-level={}", idx, level.as_str()));
            lines.push(format!(
                "client-key-{}-header-key={}",
                idx,
                pem::encode(&keys.header_key)
            ));

            lines.push(format!(
                "client-key-{}-packet-key={}",
                idx,
                pem::encode(&keys.packet_key)
            ));

            lines.push(format!("client-key-{}-iv={}", idx, pem::encode(&keys.iv)));
        }
    }

    let mut server_levels: Vec<EncryptionLevel> = state.server_keys.keys().copied().collect();
    server_levels.sort_by_key(|lvl| encryption_level_rank(*lvl));
    lines.push(format!("server-key-count={}", server_levels.len()));
    for (idx, level) in server_levels.iter().enumerate() {
        if let Some(keys) = state.server_keys.get(level) {
            lines.push(format!("server-key-{}-level={}", idx, level.as_str()));
            lines.push(format!(
                "server-key-{}-header-key={}",
                idx,
                pem::encode(&keys.header_key)
            ));

            lines.push(format!(
                "server-key-{}-packet-key={}",
                idx,
                pem::encode(&keys.packet_key)
            ));

            lines.push(format!("server-key-{}-iv={}", idx, pem::encode(&keys.iv)));
        }
    }

    lines.join("\n").into_bytes()
}

fn deserialize_crypto_state(raw_payload: &[u8]) -> io::Result<CryptoState> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "crypto-state payload is not valid UTF-8",
        )
    })?;

    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid crypto-state payload line '{}'", trimmed),
            )
        })?;

        kv.insert(key.to_string(), value.to_string());
    }

    let is_client = parse_bool(required_field(&kv, "is-client")?, "is-client")?;
    let send_level = EncryptionLevel::from_str(required_field(&kv, "send-level")?)?;
    let receive_level = EncryptionLevel::from_str(required_field(&kv, "receive-level")?)?;
    let handshake_complete = parse_bool(
        required_field(&kv, "handshake-complete")?,
        "handshake-complete",
    )?;

    let _tls_stream_present = parse_bool(
        required_field(&kv, "tls-stream-present")?,
        "tls-stream-present",
    )?;

    let _quic_tls_present = parse_bool(required_field(&kv, "quic-tls-present")?, "quic-tls-present")?;
    let client_handshake_secret = decode_optional_blob_field(
        &kv,
        "tls-client-handshake-present",
        "tls-client-handshake",
    )?;

    let server_handshake_secret = decode_optional_blob_field(
        &kv,
        "tls-server-handshake-present",
        "tls-server-handshake",
    )?;

    let client_application_secret = decode_optional_blob_field(
        &kv,
        "tls-client-application-present",
        "tls-client-application",
    )?;

    let server_application_secret = decode_optional_blob_field(
        &kv,
        "tls-server-application-present",
        "tls-server-application",
    )?;

    let client_count = parse_usize(required_field(&kv, "client-key-count")?, "client-key-count")?;
    let mut client_keys = HashMap::new();
    for idx in 0..client_count {
        let level = EncryptionLevel::from_str(required_field(&kv, &format!("client-key-{}-level", idx))?)?;
        let header_key = decode_blob_field(
            required_field(&kv, &format!("client-key-{}-header-key", idx))?,
            &format!("client-key-{}-header-key", idx),
        )?;

        let packet_key = decode_blob_field(
            required_field(&kv, &format!("client-key-{}-packet-key", idx))?,
            &format!("client-key-{}-packet-key", idx),
        )?;

        let iv = decode_blob_field(
            required_field(&kv, &format!("client-key-{}-iv", idx))?,
            &format!("client-key-{}-iv", idx),
        )?;

        client_keys.insert(level, CryptoKeys::new(header_key, packet_key, iv));
    }

    let server_count = parse_usize(required_field(&kv, "server-key-count")?, "server-key-count")?;
    let mut server_keys = HashMap::new();
    for idx in 0..server_count {
        let level = EncryptionLevel::from_str(required_field(&kv, &format!("server-key-{}-level", idx))?)?;
        let header_key = decode_blob_field(
            required_field(&kv, &format!("server-key-{}-header-key", idx))?,
            &format!("server-key-{}-header-key", idx),
        )?;

        let packet_key = decode_blob_field(
            required_field(&kv, &format!("server-key-{}-packet-key", idx))?,
            &format!("server-key-{}-packet-key", idx),
        )?;

        let iv = decode_blob_field(
            required_field(&kv, &format!("server-key-{}-iv", idx))?,
            &format!("server-key-{}-iv", idx),
        )?;

        server_keys.insert(level, CryptoKeys::new(header_key, packet_key, iv));
    }

    let mut state = CryptoState::new(is_client);
    state.client_keys = client_keys;
    state.server_keys = server_keys;
    state.send_level = send_level;
    state.receive_level = receive_level;
    state.handshake_complete = handshake_complete;
    state.tls_secret = TlsSecrets {
        client_handshake_secret,
        server_handshake_secret,
        client_application_secret,
        server_application_secret,
    };

    state.tls_stream = None;
    state.quic_tls = None;

    Ok(state)
}

fn encryption_level_rank(level: EncryptionLevel) -> u8 {
    match level {
        EncryptionLevel::Initial => 0,
        EncryptionLevel::ZeroRtt => 1,
        EncryptionLevel::Handshake => 2,
        EncryptionLevel::Application => 3,
    }
}

fn decode_optional_blob_field(kv: &HashMap<String, String>, present_key: &str, value_key: &str) -> io::Result<Option<Vec<u8>>> {
    let present = parse_bool(required_field(kv, present_key)?, present_key)?;
    if !present {
        return Ok(None);
    }

    let encoded = required_field(kv, value_key)?;
    Ok(Some(decode_blob_field(encoded, value_key)?))
}

fn decode_blob_field(value: &str, field: &str) -> io::Result<Vec<u8>> {
    pem::decode(value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {} encoding: {}", field, e),
        )
    })
}

fn required_field<'a>(kv: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    kv.get(key).map(|v| v.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {} in crypto-state payload", key),
        )
    })
}

fn parse_bool(v: &str, field: &str) -> io::Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {}", field),
        )),
    }
}

fn parse_usize(v: &str, field: &str) -> io::Result<usize> {
    v.parse::<usize>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", field))
    })
}

fn compute_crypto_state_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(CRYPTO_STATE_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(CRYPTO_STATE_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "header is not valid UTF-8")
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing blob header/body separator",
    ))
}

fn parse_secure_crypto_state_meta(header: &str, body_len: usize) -> io::Result<SecureCryptoStateBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != CRYPTO_STATE_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secure crypto-state blob magic mismatch",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None::<String>;
    let mut digest_b64 = None::<String>;
    let mut tag_b64 = None::<String>;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure crypto-state header line '{}'", line),
            )
        })?;

        match key.trim() {
            "content-encoding" => {
                algorithm =
                    CompressionAlgorithm::from_content_encoding(value.trim()).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", value.trim()),
                        )
                    })?;
            }
            "nonce" => nonce_b64 = Some(value.trim().to_string()),
            "digest" => {
                let parsed = value.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = value.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();

                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid raw-size")
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encoded-size")
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(value.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid issued-at")
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in secure crypto-state blob",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in secure crypto-state blob",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in secure crypto-state blob",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in secure crypto-state blob",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in secure crypto-state blob",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encoded-size mismatch: metadata {}, actual {}",
                encoded_size, body_len
            ),
        ));
    }

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in secure crypto-state blob",
        )
    })?;

    Ok(SecureCryptoStateBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_level_conversion() {
        assert_eq!(
            EncryptionLevel::from_packet_type(PacketType::Initial),
            EncryptionLevel::Initial
        );
        assert_eq!(
            EncryptionLevel::from_packet_type(PacketType::Handshake),
            EncryptionLevel::Handshake
        );
        assert_eq!(
            EncryptionLevel::from_packet_type(PacketType::Short),
            EncryptionLevel::Application
        );
    }

    #[test]
    fn test_crypto_state_creation() {
        let state = CryptoState::new(true);
        assert_eq!(state.send_level, EncryptionLevel::Initial);
        assert_eq!(state.receive_level, EncryptionLevel::Initial);
        assert!(state.is_client);
        assert!(!state.handshake_complete);
    }

    #[test]
    fn test_derive_initial_keys() {
        let mut state = CryptoState::new(true);
        let dcid = vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        
        let result = state.derive_initial_keys(&dcid);
        assert!(result.is_ok());
        assert!(state.has_keys(EncryptionLevel::Initial));
    }

    #[test]
    fn test_nonce_construction() {
        let state = CryptoState::new(true);
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let packet_number = 0x1234567890abcdef;
        
        let nonce = state.construct_nonce(&iv, packet_number);
        assert_eq!(nonce.len(), 12);
        assert_ne!(nonce, iv);
    }

    #[test]
    fn test_encryption_level_ordering() {
        let mut state = CryptoState::new(true);
        
        state.set_send_level(EncryptionLevel::Handshake);
        assert_eq!(state.send_level(), EncryptionLevel::Handshake);
        
        state.set_receive_level(EncryptionLevel::Application);
        assert_eq!(state.receive_level(), EncryptionLevel::Application);
    }

    #[test]
    fn test_discard_keys() {
        let mut state = CryptoState::new(true);
        let dcid = vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        
        state.derive_initial_keys(&dcid).unwrap();
        assert!(state.has_keys(EncryptionLevel::Initial));
        
        state.discard_keys(EncryptionLevel::Initial);
        assert!(!state.has_keys(EncryptionLevel::Initial));
    }

    #[test]
    fn test_handshake_completion() {
        let mut state = CryptoState::new(true);
        assert!(!state.is_handshake_complete());
        
        state.handshake_complete = true;
        assert!(state.is_handshake_complete());
    }

    #[test]
    fn test_key_availability() {
        let state = CryptoState::new(true);
        
        assert!(!state.has_keys(EncryptionLevel::Initial));
        assert!(!state.has_keys(EncryptionLevel::Handshake));
        assert!(!state.has_keys(EncryptionLevel::Application));
    }

    #[test]
    fn test_secure_crypto_state_roundtrip() {
        let mut state = CryptoState::new(true);
        state.send_level = EncryptionLevel::Handshake;
        state.receive_level = EncryptionLevel::Application;
        state.handshake_complete = true;

        state.client_keys.insert(
            EncryptionLevel::Initial,
            CryptoKeys::new(vec![1u8; 16], vec![2u8; 16], vec![3u8; 12]),
        );
        state.server_keys.insert(
            EncryptionLevel::Handshake,
            CryptoKeys::new(vec![4u8; 16], vec![5u8; 16], vec![6u8; 12]),
        );

        state.tls_secret.client_handshake_secret = Some(vec![10, 11, 12]);
        state.tls_secret.server_application_secret = Some(vec![13, 14, 15]);

        let (meta, blob) = encode_secure_crypto_state(&state, CompressionAlgorithm::Identity)
            .expect("encode secure crypto-state");
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, decoded) =
            decode_secure_crypto_state(&blob).expect("decode secure crypto-state");
        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);

        assert!(decoded.is_client);
        assert_eq!(decoded.send_level, EncryptionLevel::Handshake);
        assert_eq!(decoded.receive_level, EncryptionLevel::Application);
        assert!(decoded.handshake_complete);

        assert_eq!(
            decoded
                .client_keys
                .get(&EncryptionLevel::Initial)
                .unwrap()
                .packet_key,
            vec![2u8; 16]
        );
        assert_eq!(
            decoded
                .server_keys
                .get(&EncryptionLevel::Handshake)
                .unwrap()
                .header_key,
            vec![4u8; 16]
        );

        assert_eq!(
            decoded.tls_secret.client_handshake_secret,
            Some(vec![10, 11, 12])
        );
        assert_eq!(
            decoded.tls_secret.server_application_secret,
            Some(vec![13, 14, 15])
        );

        assert!(decoded.tls_stream.is_none());
        assert!(decoded.quic_tls.is_none());
    }

    #[test]
    fn test_secure_crypto_state_tamper_detection() {
        let state = CryptoState::new(false);
        let (_, mut blob) = encode_secure_crypto_state(&state, CompressionAlgorithm::Identity)
            .expect("encode secure crypto-state");

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let result = decode_secure_crypto_state(&blob);
        assert!(result.is_err());
    }
}