use super::error::{Error, Result};
use super::packet::{PacketNumberSpace, PacketType};
use crate::crypto::symmetric::aes::Aes;
use crate::crypto::symmetric::gcm::Gcm;
use crate::crypto::kdf::hkdf::Hkdf;
use crate::net::https::tls::{TlsStream, TlsCfg};
use super::quic_tls::{QuicTlsState, CryptoAction};
use crate::net::tcp::TcpStream;
use std::collections::HashMap;
use std::io::{Read, Write};

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
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
            0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
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
}