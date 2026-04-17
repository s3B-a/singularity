use std::io::{Read, Write};
use std::time::{Duration, SystemTime};
use std::collections::HashMap;
use crate::crypto::random::fill_random;
use crate::crypto::encoding::x509::Certificate;
use crate::crypto::encoding::asn1::{DerDecoder, DerEncoder};
use crate::crypto::hash::sha2::sha1;
use crate::net::http::http2::hpack::HpackCodec;
use crate::net::connection_pool::ConnectionPool;
use crate::net::http::http2::alpn::{AlpnNegotiator, AlpnProtocol};
use crate::net::http::{HttpResponse, HttpMethod, headers::Headers, HttpVersion};
use crate::net::https::tls::{TlsStream, TlsCfg, TlsError};
use crate::net::tcp::TcpStream;

#[derive(Debug)]
pub enum HttpsError {
    Tls(TlsError),
    Io(std::io::Error),
    InvalidUrl(String),
    InvalidResponse(String),
    Timeout,
    ConnectionFailed(String),
    TooManyRedirects,
    ProtocolNegotiationFailed(String),
    Http2Error(String),
}

#[derive(Debug, Clone)]
pub struct HttpsClientCfg {
    pub tls_cfg: TlsCfg,
    pub timeout: Duration,
    pub follow_redirect: bool,
    pub max_redirects: usize,
    pub user_agent: String,
    pub default_headers: Headers,
}

impl Default for HttpsClientCfg {   
    fn default() -> Self {
        let mut default_headers = Headers::new();
        default_headers.insert("User-Agent", "singularity-https-client/0.1.0");
        default_headers.insert("Accept", "*/*");
        default_headers.insert("Accept-Encoding", "identity");
        default_headers.insert("Connection", "keep-alive");
        
        Self {
            tls_cfg: TlsCfg::default(),
            timeout: Duration::from_secs(30),
            follow_redirect: true,
            max_redirects: 5,
            user_agent: "singularity-https-client/0.1.0".to_string(),
            default_headers,
        }
    }
}

#[derive(Debug)]
struct TlsStreamWrapper {
    stream: TlsStream,
    protocol: Option<AlpnProtocol>,
    host: String,
    port: u16,
    http2_conn: Option<Http2ConnectionWrapper>,
}

#[derive(Debug, Clone)]
struct Http2ConnectionWrapper {
    next_stream_id: u32,
    negotiated: bool,
    max_concurrent_streams: u32,
    active_streams: HashMap<u32, StreamInfo>,
}

#[derive(Debug, Clone)]
struct StreamInfo {
    stream_id: u32,
    method: HttpMethod,
    path: String,
    headers_sent: bool,
    body_sent: bool,
    response_headers: Option<HashMap<String, String>>,
    response_body: Vec<u8>,
}

pub struct HttpsClient {
    cfg: HttpsClientCfg,
    connection_pool: ConnectionPool,
    alpn_negotiator: AlpnNegotiator,
    tls_connections: HashMap<String, TlsStreamWrapper>,
    negotiated_protocols: HashMap<String, AlpnProtocol>,
}

impl HttpsClient {
    pub fn new(cfg: HttpsClientCfg) -> Self {
        let mut alpn_negotiator = AlpnNegotiator::new();
        alpn_negotiator.set_server_preference(false);
        
        HttpsClient {
            cfg,
            connection_pool: ConnectionPool::with_limits(10, Duration::from_secs(90), Duration::from_secs(600), 100),
            alpn_negotiator,
            tls_connections: HashMap::new(),
            negotiated_protocols: HashMap::new(),
        }
    }

    pub fn with_config(cfg: HttpsClientCfg) -> Self {
        Self::new(cfg)
    }

    pub fn set_alpn_protocols(&mut self, protocols: Vec<AlpnProtocol>) {
        self.alpn_negotiator = AlpnNegotiator::with_protocols(protocols);
        self.alpn_negotiator.set_server_preference(false);
    }

    pub fn get_negotiated_protocol(&self, host: &str, port: u16) -> Option<AlpnProtocol> {
        let key = format!("{}:{}", host, port);
        self.negotiated_protocols.get(&key).copied()
    }

    fn selected_protocol_with_fallback(&self, negotiated: Option<AlpnProtocol>) -> AlpnProtocol {
        negotiated.unwrap_or_else(|| {
            if self.cfg.tls_cfg.max_version >= crate::net::https::tls::TlsVersion::Tls1_2 {
                AlpnProtocol::Http2
            } else {
                AlpnProtocol::Http11
            }
        })
    }

    pub fn get(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::GET, url, None, None, 0)
    }

    pub fn post(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::POST, url, Some(body), None, 0)
    }

    pub fn put(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::PUT, url, Some(body), None, 0)
    }

    pub fn delete(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::DELETE, url, None, None, 0)
    }

    pub fn head(&mut self, url: &str) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::HEAD, url, None, None, 0)
    }

    pub fn patch(&mut self, url: &str, body: Vec<u8>) -> Result<HttpResponse, HttpsError> {
        self.request_with_redirects(HttpMethod::PATCH, url, Some(body), None, 0)
    }

    fn request_with_redirects(&mut self, method: HttpMethod, url: &str, body: Option<Vec<u8>>, headers: Option<Headers>, redirect_count: usize) -> Result<HttpResponse, HttpsError> {
        if redirect_count > self.cfg.max_redirects {
            return Err(HttpsError::TooManyRedirects);
        }

        let (host, port, path) = self.parse_url(url)?;
        let mut request_headers = self.cfg.default_headers.clone();
        if let Some(ref custom_headers) = headers {
            for (name, values) in custom_headers.iter() {
                for value in values {
                    request_headers.append(name.clone(), value.clone());
                }
            }
        }

        request_headers.insert("Host", format!("{}:{}", host, port));
        let connection_key = format!("{}:{}", host, port);
        self.get_or_create_tls_connection_with_alpn(&host, port)?;
        let response = match self.tls_connections.get(&connection_key).unwrap().protocol {
            Some(AlpnProtocol::Http2) => {
                self.send_http2_request(
                    &connection_key,
                    method,
                    &path,
                    request_headers,
                    body.clone(),
                )?
            }
            Some(AlpnProtocol::Http11) | Some(AlpnProtocol::Http10) | None => {
                self.send_http1_request(
                    &connection_key,
                    method,
                    &path,
                    request_headers,
                    body.clone(),
                )?
            }
            Some(AlpnProtocol::Http3) => {
                return Err(HttpsError::ProtocolNegotiationFailed(
                    "HTTP/3 requires QUIC transport".to_string(),
                ))
            }
        };

        if self.cfg.follow_redirect && response.is_redirect() {
            if let Some(location) = response.header("location") {
                let redirect_url = if location.starts_with("http") {
                    location.to_string()
                } else {
                    let base = format!("https://{}:{}", host, port);
                    self.resolve_url(&base, location)
                };

                return self.request_with_redirects(
                    method,
                    &redirect_url,
                    body,
                    headers,
                    redirect_count + 1,
                );
            }
        }

        Ok(response)
    }

    fn get_or_create_tls_connection_with_alpn(&mut self, host: &str, port: u16) -> Result<(), HttpsError> {
        let connection_key = format!("{}:{}", host, port);
        if self.tls_connections.contains_key(&connection_key) {
            return Ok(());
        }

        let socket_addr = format!("{}:{}", host, port);
        let tcp_stream = TcpStream::connect(&socket_addr)
            .map_err(|e| HttpsError::ConnectionFailed(e.to_string()))?;

        let mut tls_stream = TlsStream::new_client_with_sni(
            tcp_stream,
            self.cfg.tls_cfg.clone(),
            host.to_string(),
        )
        .map_err(|e| HttpsError::Tls(e))?;

        let alpn_protocols = vec![
            AlpnProtocol::Http2,
            AlpnProtocol::Http11,
        ];

        tls_stream.init_alpn_client(alpn_protocols.clone());
        self.perform_tls_handshake_with_alpn(
            &mut tls_stream,
            host,
            &alpn_protocols,
        )?;

        let negotiated_protocol = tls_stream.get_negotiated_protocol();
        if let Some(protocol) = negotiated_protocol {
            tls_stream
                .validate_negotiated_protocol(&[
                    AlpnProtocol::Http2,
                    AlpnProtocol::Http11,
                ])
                .map_err(|e| HttpsError::Tls(e))?;

            self.negotiated_protocols
                .insert(connection_key.clone(), protocol);
        }

        tls_stream
            .set_read_timeout(Some(self.cfg.timeout))
            .map_err(|e| HttpsError::Tls(e))?;
        tls_stream
            .set_write_timeout(Some(self.cfg.timeout))
            .map_err(|e| HttpsError::Tls(e))?;

        let http2_conn = if negotiated_protocol == Some(AlpnProtocol::Http2) {
            let tcp_stream_ref = tls_stream.stream_get_ref();
            let remote_addr = tcp_stream_ref.peer_addr()
                .ok()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            eprintln!("Initializing HTTP/2 connection to {} ({})", connection_key, remote_addr);

            Some(Http2ConnectionWrapper {
                next_stream_id: 1,
                negotiated: true,
                max_concurrent_streams: 100,
                active_streams: HashMap::new(),
            })
        } else {
            None
        };

        let wrapper: TlsStreamWrapper = TlsStreamWrapper {
            stream: tls_stream,
            protocol: negotiated_protocol,
            http2_conn,
            host: host.to_string(),
            port,
        };

        self.tls_connections.insert(connection_key, wrapper);
        Ok(())
    }

    fn perform_tls_handshake_with_alpn(&self, tls_stream: &mut TlsStream, host: &str, alpn_protocols: &[AlpnProtocol]) -> Result<(), HttpsError> {
        let client_hello = self.build_client_hello_with_alpn(host, alpn_protocols)?;
        tls_stream.write_all(&client_hello).map_err(|e| HttpsError::Io(e))?;
        tls_stream.flush().map_err(|e| HttpsError::Io(e))?;

        let mut buffer = vec![0u8; 4096];
        let bytes_read = tls_stream.read(&mut buffer).map_err(|e| HttpsError::Io(e))?;
        if bytes_read == 0 {
            return Err(HttpsError::InvalidResponse(
                "Server did not respond to ClientHello".to_string(),
            ));
        }

        buffer.truncate(bytes_read);
        self.parse_server_hello_with_alpn(tls_stream, &buffer, alpn_protocols)?;
        self.complete_tls_handshake(tls_stream)?;

        Ok(())
    }

    fn build_client_hello_with_alpn(&self, host: &str, alpn_protocols: &[AlpnProtocol]) -> Result<Vec<u8>, HttpsError> {
        let mut client_hello = Vec::new();
        client_hello.push(22);
        client_hello.extend_from_slice(&[0x03, 0x03]);
        let mut handshake = Vec::new();
        handshake.push(1);
        let mut client_hello_body = Vec::new();
        client_hello_body.extend_from_slice(&[0x03, 0x03]);
        let mut random = vec![0u8; 32];
        random[0..4].copy_from_slice(&(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32)
            .to_be_bytes());

        for i in 4..32 {
            let _ = fill_random(&mut random[i..i + 1]);
        }

        client_hello_body.extend_from_slice(&random);
        client_hello_body.push(0);
        let cipher_suites: Vec<u16> = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
        ];

        client_hello_body.push((cipher_suites.len() * 2) as u8);
        for suite in cipher_suites {
            client_hello_body.extend_from_slice(&suite.to_be_bytes());
        }

        client_hello_body.push(1);
        client_hello_body.push(0);
        
        let mut extensions = Vec::new();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        
        let host_bytes = host.as_bytes();
        let sni_data_len = 5 + host_bytes.len();
        sni_ext.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(&((sni_data_len - 2) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);
        extensions.extend_from_slice(&sni_ext);
        
        let mut alpn_ext = Vec::new();
        alpn_ext.extend_from_slice(&[0x00, 0x10]);
        let mut alpn_list = Vec::new();
        for protocol in alpn_protocols {
            let proto_name = protocol.name();
            alpn_list.push(proto_name.len() as u8);
            alpn_list.extend_from_slice(proto_name.as_bytes());
        }

        let alpn_data_len = alpn_list.len() + 2;
        alpn_ext.extend_from_slice(&(alpn_data_len as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&alpn_list);
        extensions.extend_from_slice(&alpn_ext);

        let extensions_len = extensions.len() as u16;
        client_hello_body.extend_from_slice(&extensions_len.to_be_bytes());
        client_hello_body.extend_from_slice(&extensions);

        let handshake_len = client_hello_body.len();
        handshake.extend_from_slice(&handshake_len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&client_hello_body);

        let record_len = handshake.len() as u16;
        client_hello.extend_from_slice(&record_len.to_be_bytes());
        client_hello.extend_from_slice(&handshake);

        Ok(client_hello)
    }

    fn parse_server_hello_with_alpn(&self, _tls_stream: &mut TlsStream, buffer: &[u8], alpn_protocols: &[AlpnProtocol]) -> Result<(), HttpsError> {
        if buffer.len() < 5 {
            return Err(HttpsError::InvalidResponse(
                "ServerHello too short".to_string(),
            ));
        }

        let _content_type = buffer[0];
        let _version = u16::from_be_bytes([buffer[1], buffer[2]]);
        let record_len = u16::from_be_bytes([buffer[3], buffer[4]]);
        if buffer.len() < 5 + record_len as usize {
            return Err(HttpsError::InvalidResponse(
                "ServerHello record truncated".to_string(),
            ));
        }

        let record_data = &buffer[5..5 + record_len as usize];
        if record_data.len() < 4 {
            return Err(HttpsError::InvalidResponse(
                "ServerHello handshake too short".to_string(),
            ));
        }

        let _handshake_type = record_data[0];
        let handshake_len = u32::from_be_bytes([0, record_data[1], record_data[2], record_data[3]]);
        if record_data.len() < 4 + handshake_len as usize {
            return Err(HttpsError::InvalidResponse(
                "ServerHello handshake truncated".to_string(),
            ));
        }

        let hello_data = &record_data[4..4 + handshake_len as usize];
        let mut pos = 34;
        if pos >= hello_data.len() {
            return Err(HttpsError::InvalidResponse(
                "ServerHello truncated at session ID".to_string(),
            ));
        }

        let session_id_len = hello_data[pos] as usize;
        pos += 1 + session_id_len;
        pos += 2;
        pos += 1;
        if pos + 2 > hello_data.len() {
            return Ok(());
        }

        let extensions_len = u16::from_be_bytes([hello_data[pos], hello_data[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;
        while pos + 4 <= extensions_end && pos + 4 <= hello_data.len() {
            let ext_type = u16::from_be_bytes([hello_data[pos], hello_data[pos + 1]]);
            let ext_len = u16::from_be_bytes([hello_data[pos + 2], hello_data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > hello_data.len() {
                break;
            }

            if ext_type == 16 && ext_len >= 3 {
                let alpn_data = &hello_data[pos..pos + ext_len];
                let alpn_list_len = u16::from_be_bytes([alpn_data[0], alpn_data[1]]) as usize;
                if alpn_list_len + 2 <= ext_len && alpn_list_len > 0 {
                    let proto_len = alpn_data[2] as usize;
                    if 3 + proto_len <= ext_len {
                        let selected_proto = &alpn_data[3..3 + proto_len];
                        let proto_str = String::from_utf8_lossy(selected_proto);
                        for protocol in alpn_protocols {
                            if protocol.name() == proto_str.as_ref() {
                                return Ok(());
                            }
                        }
                        
                        return Err(HttpsError::ProtocolNegotiationFailed(
                            format!("Server selected unsupported protocol: {}", proto_str),
                        ));
                    }
                }
            }

            pos += ext_len;
        }

        Ok(())
    }

    fn complete_tls_handshake(&self, tls_stream: &mut TlsStream) -> Result<(), HttpsError> {
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);
        let mut buffer = vec![0u8; 16384];
        let mut received_data = Vec::new();
        let mut handshake_complete = false;

        let mut received_encrypted_extensions = false;
        let mut received_certificate = false;
        let mut received_cert_verify = false;
        let mut received_finished = false;
        loop {
            if start_time.elapsed() > timeout {
                return Err(HttpsError::InvalidResponse(
                    "TLS handshake timeout".to_string(),
                ));
            }

            match tls_stream.read(&mut buffer) {
                Ok(0) => {
                    if !received_finished {
                        return Err(HttpsError::InvalidResponse(
                            "Server closed connection during TLS handshake".to_string(),
                        ));
                    }
                    break;
                }
                Ok(n) => {
                    received_data.extend_from_slice(&buffer[..n]);
                    loop {
                        if received_data.len() < 5 {
                            break;
                        }

                        let content_type = received_data[0];
                        let _tls_version = u16::from_be_bytes([received_data[1], received_data[2]]);
                        let record_length =
                            u16::from_be_bytes([received_data[3], received_data[4]]) as usize;

                        if received_data.len() < 5 + record_length {
                            break;
                        }

                        let record_payload = &received_data[5..5 + record_length];
                        match content_type {
                            22 => {
                                if let Err(e) =
                                    self.process_handshake_record(
                                        record_payload,
                                        tls_stream,
                                        &mut received_encrypted_extensions,
                                        &mut received_certificate,
                                        &mut received_cert_verify,
                                        &mut received_finished,
                                    )
                                {
                                    return Err(HttpsError::InvalidResponse(format!(
                                        "Handshake record error: {}",
                                        e
                                    )));
                                }
                            }
                            23 => {
                                return Err(HttpsError::InvalidResponse(
                                    "Received application data during handshake".to_string(),
                                ));
                            }
                            21 => {
                                if record_payload.len() >= 2 {
                                    let level = record_payload[0];
                                    let description = record_payload[1];
                                    return Err(HttpsError::InvalidResponse(format!(
                                        "TLS Alert - Level: {}, Description: {}",
                                        level, description
                                    )));
                                }
                            }
                            20 => {
                                // ChangeCipherSpec (TLS 1.2) - skip in TLS 1.3
                            }
                            _ => {
                                return Err(HttpsError::InvalidResponse(format!(
                                    "Unknown TLS content type: {}",
                                    content_type
                                )));
                            }
                        }

                        received_data.drain(..5 + record_length);
                        if received_encrypted_extensions
                            && received_finished
                            && !received_certificate
                        {
                            handshake_complete = true;
                            break;
                        } else if received_encrypted_extensions
                            && received_certificate
                            && received_cert_verify
                            && received_finished
                        {
                            handshake_complete = true;
                            break;
                        }
                    }

                    if handshake_complete {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    return Err(HttpsError::Io(e));
                }
            }
        }

        self.send_client_finished(tls_stream)?;

        Ok(())
    }

    fn build_client_key_exchange(&self) -> Result<Vec<u8>, HttpsError> {
        let mut pms = vec![0x03, 0x03];
        for i in 2..48 {
            pms.push((i as u8).wrapping_mul(13));
        }

        let mut handshake = vec![16];
        handshake.extend_from_slice(&(pms.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&(pms.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&pms);

        let mut record = vec![22, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        Ok(record)
    }

    fn build_finished_message(&self) -> Result<Vec<u8>, HttpsError> {
        let finished_data = vec![0u8; 12];
        let mut handshake = vec![20];
        handshake.extend_from_slice(&(finished_data.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&finished_data);

        let mut record = vec![22, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        Ok(record)
    }

    fn process_handshake_record(&self, record_payload: &[u8], tls_stream: &mut TlsStream, received_encrypted_extensions: &mut bool, received_certificate: &mut bool, received_cert_verify: &mut bool, received_finished: &mut bool) -> Result<(), HttpsError> {
        let mut pos = 0;
        while pos < record_payload.len() {
            if pos + 4 > record_payload.len() {
                break;
            }

            let msg_type = record_payload[pos];
            let msg_length = u32::from_be_bytes([
                0,
                record_payload[pos + 1],
                record_payload[pos + 2],
                record_payload[pos + 3],
            ]) as usize;

            if pos + 4 + msg_length > record_payload.len() {
                break;
            }

            let msg_data = &record_payload[pos + 4..pos + 4 + msg_length];
            match msg_type {
                8 => {
                    self.process_encrypted_extensions(msg_data)?;
                    *received_encrypted_extensions = true;
                }
                11 => {
                    self.process_certificate(msg_data, tls_stream)?;
                    *received_certificate = true;
                }
                15 => {
                    self.process_certificate_verify(msg_data)?;
                    *received_cert_verify = true;
                }
                20 => {
                    self.process_finished(msg_data)?;
                    *received_finished = true;
                }
                4 => {
                    self.process_new_session_ticket(msg_data)?;
                }
                _ => {
                    eprintln!(
                        "Warning: Unexpected handshake message type during completion: {}",
                        msg_type
                    );
                }
            }

            pos += 4 + msg_length;
        }

        Ok(())
    }

    fn process_encrypted_extensions(&self, data: &[u8]) -> Result<(), HttpsError> {
        if data.len() < 2 {
            return Err(HttpsError::InvalidResponse(
                "EncryptedExtensions too short".to_string(),
            ));
        }

        let extensions_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + extensions_len {
            return Err(HttpsError::InvalidResponse(
                "EncryptedExtensions truncated".to_string(),
            ));
        }

        let mut pos = 2;
        while pos + 4 <= 2 + extensions_len && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > data.len() {
                break;
            }

            eprintln!("EncryptedExtensions: type={}, len={}", ext_type, ext_len);
            pos += ext_len;
        }

        Ok(())
    }

    fn process_certificate(&self, data: &[u8], tls_stream: &mut TlsStream) -> Result<(), HttpsError> {
        if data.len() < 4 {
            return Err(HttpsError::InvalidResponse(
                "Certificate message too short".to_string(),
            ));
        }

        let context_len = data[0] as usize;
        if data.len() < 1 + context_len {
            return Err(HttpsError::InvalidResponse(
                "Certificate context truncated".to_string(),
            ));
        }

        let mut pos = 1 + context_len;
        if pos + 3 > data.len() {
            return Err(HttpsError::InvalidResponse(
                "Certificate list length truncated".to_string(),
            ));
        }

        let cert_list_len = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if pos + cert_list_len > data.len() {
            return Err(HttpsError::InvalidResponse(
                "Certificate list truncated".to_string(),
            ));
        }

        if pos + 3 > data.len() {
            return Err(HttpsError::InvalidResponse(
                "Certificate length field truncated".to_string(),
            ));
        }

        let cert_len = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if pos + cert_len > data.len() {
            return Err(HttpsError::InvalidResponse(
                "Certificate data truncated".to_string(),
            ));
        }

        let cert_der = &data[pos..pos + cert_len];
        self.validate_peer_certificate(cert_der, tls_stream)?;

        Ok(())
    }

    fn validate_peer_certificate(&self, cert_der: &[u8], tls_stream: &mut TlsStream) -> Result<(), HttpsError> {
        if cert_der.len() < 10 {
            return Err(HttpsError::InvalidResponse(
                "Certificate too short - possible corruption".to_string(),
            ));
        }

        if cert_der.len() > 16 * 1024 {
            return Err(HttpsError::InvalidResponse(
                format!("Certificate too large: {} bytes", cert_der.len()),
            ));
        }

        let cert = Certificate::from_der(cert_der).map_err(|e| {
            HttpsError::InvalidResponse(format!("Failed to parse certificate: {:?}", e))
        })?;

        if !cert.is_valid_at_current_time() {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            return Err(HttpsError::InvalidResponse(format!(
                "Certificate validity period check failed at timestamp: {}",
                now
            )));
        }

        if let Some(sni_hostname) = &tls_stream.server_name {
            if !cert.matches_hostname(sni_hostname) {
                return Err(HttpsError::InvalidResponse(format!(
                    "Certificate hostname mismatch: expected '{}', got '{:?}'",
                    sni_hostname,
                    cert.subject.common_name
                )));
            }
        }

        if self.cfg.tls_cfg.verify_peer && !self.cfg.tls_cfg.ca_certs.is_empty() {
            let mut verified = false;
            let mut last_error = None;
            for ca_cert in &self.cfg.tls_cfg.ca_certs {
                match cert.verify_signature(ca_cert) {
                    Ok(_) => {
                        verified = true;
                        eprintln!(
                            "Certificate chain verified against CA: {:?}",
                            ca_cert.subject.common_name
                        );

                        break;
                    }
                    Err(e) => {
                        last_error = Some(format!("{:?}", e));
                        continue;
                    }
                }
            }

            if !verified {
                return Err(HttpsError::InvalidResponse(format!(
                    "Certificate chain verification failed. Last error: {}",
                    last_error.unwrap_or_else(|| "Unknown error".to_string())
                )));
            }
        } else if self.cfg.tls_cfg.verify_peer {
            return Err(HttpsError::InvalidResponse(
                "Certificate verification required but no CA certificates configured".to_string(),
            ));
        }

        if let Err(e) = self.validate_certificate_extensions(&cert) {
            return Err(HttpsError::InvalidResponse(format!(
                "Certificate extension validation failed: {}",
                e
            )));
        }

        if let Some(public_key) = cert.public_key() {
            if public_key.len() < 128 {
                return Err(HttpsError::InvalidResponse(
                    "Certificate public key too weak (minimum 1024-bit RSA required)".to_string(),
                ));
            }

            if public_key.len() < 256 {
                eprintln!(
                    "Warning: Certificate uses weak public key (< 2048-bit RSA). \
                     This is deprecated and may be rejected in future versions."
                );
            }
        } else {
            return Err(HttpsError::InvalidResponse(
                "Certificate missing public key".to_string(),
            ));
        }

        if cert.is_ca() {
            eprintln!(
                "Warning: Peer presented a CA certificate as end-entity certificate. \
                 This may indicate misconfiguration."
            );
        }

        match cert.serial_number() {
            Ok(serial) => {
                if serial.is_empty() {
                    return Err(HttpsError::InvalidResponse(
                        "Certificate has empty serial number".to_string(),
                    ));
                }

                eprintln!("Certificate serial: {:02x?}", serial);
            }
            Err(e) => {
                return Err(HttpsError::InvalidResponse(format!(
                    "Failed to read certificate serial number: {:?}",
                    e
                )));
            }
        }

        match cert.get_subject_alt_names() {
            Ok(sans) => {
                if !sans.is_empty() {
                    eprintln!("Certificate SANs: {:?}", sans);
                } else {
                    eprintln!("Certificate has no Subject Alternative Names");
                }
            }
            Err(_) => {
                eprintln!("No Subject Alternative Names extension found");
            }
        }

        eprintln!(
            "Peer certificate validated successfully: {} bytes, CN={:?}",
            cert_der.len(),
            cert.subject.common_name
        );

        Ok(())
    }

    fn validate_certificate_extensions(&self, cert: &Certificate) -> Result<(), HttpsError> {
        let mut decoder = DerDecoder::new(&cert.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer());
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.set(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.set(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            if let Ok(_) = tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.has_more() {
                        let _ = exts.sequence(|ext| {
                            let oid = ext.object_identifier()?;
                            let critical = ext.boolean().unwrap_or(false);
                            if oid == vec![2, 5, 29, 15] {
                                eprintln!("Found KeyUsage extension (critical: {})", critical);
                            }
                            if oid == vec![2, 5, 29, 37] {
                                eprintln!("Found ExtendedKeyUsage extension (critical: {})", critical);
                            }
                            if oid == vec![2, 5, 29, 17] {
                                eprintln!("Found SubjectAltName extension (critical: {})", critical);
                            }

                            Ok(())
                        })?;
                    }

                    Ok(())
                })
            }) {
                eprintln!("Certificate contains extensions");
            }

            Ok(())
        })
        .map_err(|e| HttpsError::InvalidResponse(format!("Extension parsing error: {:?}", e)))
    }

    fn check_certificate_revocation(&self, cert: &Certificate) -> Result<(), HttpsError> {
        if !self.cfg.tls_cfg.verify_peer {
            return Ok(());
        }

        match self.check_ocsp_status(cert) {
            Ok(()) => {
                eprintln!("✓ Certificate revocation status verified via OCSP");
                return Ok(());
            }
            Err(e) => {
                eprintln!("OCSP check failed: {}, falling back to CRL", e);
            }
        }

        match self.check_crl_status(cert) {
            Ok(()) => {
                eprintln!("✓ Certificate revocation status verified via CRL");
                return Ok(());
            }
            Err(e) => {
                eprintln!("CRL check failed: {}", e);
                eprintln!("Warning: Could not verify certificate revocation status");
                return Ok(());
            }
        }
    }

    fn check_ocsp_status(&self, cert: &Certificate) -> Result<(), HttpsError> {
        let ocsp_url = self.extract_ocsp_url(cert)?;
        let ocsp_request = self.build_ocsp_request(cert)?;
        let response = self.send_ocsp_request(&ocsp_url, &ocsp_request)?;
        self.parse_ocsp_response(&response, cert)?;

        Ok(())
    }

    fn extract_ocsp_url(&self, cert: &Certificate) -> Result<String, HttpsError> {
        let mut decoder = DerDecoder::new(&cert.tbs);
        let mut ocsp_url = None;
        let _ = decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer());
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.has_more() {
                        let _ = exts.sequence(|ext| {
                            let oid = ext.object_identifier()?;
                            let _critical = ext.boolean().unwrap_or(false);
                            let value = ext.octet_string()?; 
                            if oid == vec![1, 3, 6, 1, 5, 5, 7, 1, 1] {
                                let mut aia_decoder = DerDecoder::new(&value);
                                aia_decoder.sequence(|aia_seq| {
                                    while aia_seq.has_more() {
                                        let _ = aia_seq.sequence(|access_desc| {
                                            let method = access_desc.object_identifier()?;
                                            if method == vec![1, 3, 6, 1, 5, 5, 7, 48, 1] {
                                                if let Ok(url) = access_desc.context_specific(6, |ctx| {
                                                    let bytes = ctx.read_bytes(ctx.data.len())?;
                                                    String::from_utf8(bytes)
                                                        .map_err(|_| crate::crypto::Error::InvalidData("Invalid UTF-8 in URL".to_string()))
                                                }) {
                                                    ocsp_url = Some(url);
                                                }
                                            }

                                            Ok(())
                                        })?;
                                    }

                                    Ok(())
                                })?;
                            }

                            Ok(())
                        })?;
                    }

                    Ok(())
                })
            })
        });

        ocsp_url.ok_or_else(|| HttpsError::InvalidResponse(
            "No OCSP responder URL found in certificate".to_string(),
        ))
    }

    fn build_ocsp_request(&self, cert: &Certificate) -> Result<Vec<u8>, HttpsError> {
        let mut encoder = DerEncoder::new();

        let (issuer_name_hash, issuer_key_hash) = 
            self.compute_issuer_hashes(cert)?;

        let serial = cert.serial_number()
            .map_err(|e| HttpsError::InvalidResponse(format!("Failed to get serial: {:?}", e)))?;

        // OCSPRequest ::= SEQUENCE {
        //   tbsRequest      TBSRequest,
        //   optionalSignature [0] EXPLICIT Signature OPTIONAL
        // }
        encoder.sequence(|ocsp_req| {
            // TBSRequest ::= SEQUENCE {
            //   version             [0]  EXPLICIT Version DEFAULT v1,
            //   requestorName       [1]  EXPLICIT GeneralName OPTIONAL,
            //   requestList         SEQUENCE OF Request
            // }
            ocsp_req.sequence(|tbs_req| {
                tbs_req.sequence(|req_list| {
                    // Request ::= SEQUENCE {
                    //   reqCert                  CertID,
                    //   singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL
                    // }
                    req_list.sequence(|request| {
                        // CertID ::= SEQUENCE {
                        //   hashAlgorithm       AlgorithmIdentifier,
                        //   issuerNameHash      OCTET STRING,
                        //   issuerKeyHash       OCTET STRING,
                        //   serialNumber        INTEGER
                        // }
                        request.sequence(|cert_id| {
                            cert_id.sequence(|alg| {
                                let _ = alg.object_identifier(&[1, 3, 14, 3, 2, 26]);
                                let _ = alg.null();
                            });

                            cert_id.octet_string(&issuer_name_hash);
                            cert_id.octet_string(&issuer_key_hash);
                            cert_id.integer(&serial);
                            
                        });
                    });
                });
            });
        });

        Ok(encoder.finish())
    }

    fn compute_issuer_hashes(&self, cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), HttpsError> {
        let mut decoder = DerDecoder::new(&cert.tbs);
        let (issuer_der, issuer_spki_der) = decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer());
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|_| Ok(()))?;
            
            let issuer_start = tbs.get_pos();
            let _ = tbs.sequence(|_| Ok(()))?;
            let issuer_end = tbs.get_pos();
            let issuer_bytes = tbs.data[issuer_start..issuer_end].to_vec();

            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            
            let spki_start = tbs.get_pos();
            let _ = tbs.sequence(|_| Ok(()))?;
            let spki_end = tbs.get_pos();
            let spki_bytes = tbs.data[spki_start..spki_end].to_vec();
            
            Ok((issuer_bytes, spki_bytes))
        })
        .map_err(|e| HttpsError::InvalidResponse(
            format!("Failed to parse certificate for issuer info: {:?}", e)
        ))?;

        let issuer_name_hash = sha1(&issuer_der).to_vec();
        let issuer_key_hash = self.extract_public_key_hash(&issuer_spki_der)?;

        Ok((issuer_name_hash, issuer_key_hash))
    }

    fn extract_public_key_hash(&self, spki_der: &[u8]) -> Result<Vec<u8>, HttpsError> {
        let mut decoder = DerDecoder::new(spki_der);
        let public_key_bits = decoder.sequence(|spki| {
            let _ = spki.sequence(|_| Ok(()))?;
            spki.bit_string()
        }).map_err(|e| HttpsError::InvalidResponse(
            format!("Failed to parse SubjectPublicKeyInfo: {:?}", e)
        ))?;

        let key_hash = sha1(&public_key_bits.0).to_vec();
        Ok(key_hash)
    }

    fn compute_issuer_hashes_from_ca(&self, cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), HttpsError> {
        let issuer_cert = self.find_issuer_cert(cert)?;
        let issuer_name_hash = self.hash_distinguished_name(&issuer_cert)?;
        let issuer_key_hash = self.hash_public_key(&issuer_cert)?;

        Ok((issuer_name_hash, issuer_key_hash))
    }

    fn find_issuer_cert(&self, cert: &Certificate) -> Result<&Certificate, HttpsError> {
        for ca_cert in &self.cfg.tls_cfg.ca_certs {
            if self.is_issuer(cert, ca_cert) {
                return Ok(ca_cert);
            }
        }

        Err(HttpsError::InvalidResponse(
            "Could not find issuer CA certificate".to_string()
        ))
    }

    fn is_issuer(&self, cert: &Certificate, ca_cert: &Certificate) -> bool {
        let issuer_raw = match self.get_cert_issuer_raw(cert) {
            Ok(raw) => raw,
            Err(_) => return false,
        };
        
        let subject_raw = match self.get_cert_subject_raw(ca_cert) {
            Ok(raw) => raw,
            Err(_) => return false,
        };
        
        let issuer_matches = self.compare_distinguished_names(&issuer_raw, &subject_raw);
        if !issuer_matches {
            return false;
        }
        
        if let (Ok(aki), Ok(ski)) = (cert.get_authority_key_identifier(), ca_cert.get_subject_key_identifier()) {
            if !aki.is_empty() && !ski.is_empty() {
                if aki != ski {
                    eprintln!(
                        "Warning: Authority Key Identifier mismatch - AKI: {:02x?}, SKI: {:02x?}",
                        &aki[..aki.len().min(8)],
                        &ski[..ski.len().min(8)]
                    );

                    return false;
                }
            }
        }
        
        if !ca_cert.is_ca() {
            eprintln!("Warning: Potential issuer is not a CA certificate");
            return false;
        }
        
        if let Ok(key_usage) = ca_cert.get_key_usage() {
            const KEY_CERT_SIGN: u16 = 0x04;
            if key_usage & KEY_CERT_SIGN == 0 {
                eprintln!("Warning: CA certificate missing keyCertSign in KeyUsage");
                return false;
            }
        }
        
        true
    }

    fn compare_distinguished_names(&self, dn1: &[u8], dn2: &[u8]) -> bool {
        if dn1.len() != dn2.len() {
            return false;
        }

        if dn1 == dn2 {
            return true;
        }
        
        match (self.parse_distinguished_name(dn1), self.parse_distinguished_name(dn2)) {
            (Ok(components1), Ok(components2)) => {
                self.compare_dn_components(&components1, &components2)
            }
            _ => false,
        }
    }

    fn parse_distinguished_name(&self, dn_der: &[u8]) -> Result<Vec<(Vec<u32>, String)>, HttpsError> {
        let mut decoder = DerDecoder::new(dn_der);
        let mut components = Vec::new();
        decoder.sequence(|dn_seq| {
            while dn_seq.has_more() {
                let _ = dn_seq.set(|rdn_set| {
                    while rdn_set.has_more() {
                        let _ = rdn_set.sequence(|attr_seq| {
                            let oid = attr_seq.object_identifier()?;
                            let value = if let Ok(s) = attr_seq.utf8_string() {
                                s
                            } else if let Ok(s) = attr_seq.printable_string() {
                                s
                            } else if let Ok(s) = attr_seq.ia5_string() {
                                s
                            } else if let Ok(bytes) = attr_seq.octet_string() {
                                String::from_utf8_lossy(&bytes).to_string()
                            } else {
                                String::new()
                            };
                            
                            let normalized = value.trim().to_lowercase();
                            let oid_u32: Vec<u32> = oid.iter().map(|&x| x as u32).collect();
                            components.push((oid_u32, normalized));
                            
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        }).map_err(|e| HttpsError::InvalidResponse(
            format!("Failed to parse Distinguished Name: {:?}", e)
        ))?;
        
        Ok(components)
    }

    fn compare_dn_components(&self, components1: &[(Vec<u32>, String)], components2: &[(Vec<u32>, String)]) -> bool {
        if components1.len() != components2.len() {
            return false;
        }
        
        for (oid1, value1) in components1 {
            if let Some((_, value2)) = components2.iter().find(|(oid2, _)| oid1 == oid2) {
                if value1 != value2 {
                    eprintln!(
                        "DN component mismatch for OID {:?}: '{}' != '{}'",
                        oid1, value1, value2
                    );
                    return false;
                }
            } else {
                eprintln!("DN missing component with OID {:?}", oid1);
                return false;
            }
        }
        
        true
    }

    fn get_cert_issuer_raw(&self, cert: &Certificate) -> Result<Vec<u8>, HttpsError> {
        let mut offset = 0;
        let tbs_data = &cert.tbs;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Invalid TBS structure".to_string()));
        }

        offset += 1;
        let (_, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes;
        if tbs_data[offset] == 0xA0 {
            offset += 1;
            let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
            offset += len_bytes + len;
        }
        
        if tbs_data[offset] != 0x02 {
            return Err(HttpsError::InvalidResponse("Expected INTEGER for serial".to_string()));
        }

        offset += 1;
        let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes + len;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Expected SEQUENCE for signature algorithm".to_string()));
        }

        offset += 1;
        let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes + len;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Expected SEQUENCE for issuer".to_string()));
        }

        let issuer_start = offset;
        offset += 1;
        let (issuer_len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes;
        let issuer_end = offset + issuer_len;
        let issuer_bytes = tbs_data[issuer_start..issuer_end].to_vec();
        
        Ok(issuer_bytes)
    }
    
    fn parse_der_length(data: &[u8]) -> Result<(usize, usize), HttpsError> {
        if data.is_empty() {
            return Err(HttpsError::InvalidResponse("Empty length field".to_string()));
        }
        
        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            Ok((first_byte as usize, 1))
        } else {
            let num_bytes = (first_byte & 0x7F) as usize;
            if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
                return Err(HttpsError::InvalidResponse("Invalid length encoding".to_string()));
            }
            
            let mut length = 0usize;
            for i in 0..num_bytes {
                length = (length << 8) | (data[1 + i] as usize);
            }
            
            Ok((length, 1 + num_bytes))
        }
    }

    fn get_cert_subject_raw(&self, cert: &Certificate) -> Result<Vec<u8>, HttpsError> {
        let mut offset = 0;
        let tbs_data = &cert.tbs;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Invalid TBS structure".to_string()));
        }

        offset += 1;
        let (_, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes;
        if tbs_data[offset] == 0xA0 {
            offset += 1;
            let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
            offset += len_bytes + len;
        }
        
        if tbs_data[offset] != 0x02 {
            return Err(HttpsError::InvalidResponse("Expected INTEGER for serial".to_string()));
        }

        offset += 1;
        let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes + len;

        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Expected SEQUENCE for signature algorithm".to_string()));
        }
        
        offset += 1;
        let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes + len;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Expected SEQUENCE for issuer".to_string()));
        }

        offset += 1;
        let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes + len;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Expected SEQUENCE for validity".to_string()));
        }

        offset += 1;
        let (len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes + len;
        if tbs_data[offset] != 0x30 {
            return Err(HttpsError::InvalidResponse("Expected SEQUENCE for subject".to_string()));
        }

        let subject_start = offset;
        offset += 1;
        let (subject_len, len_bytes) = Self::parse_der_length(&tbs_data[offset..])?;
        offset += len_bytes;
        let subject_end = offset + subject_len;
        let subject_bytes = tbs_data[subject_start..subject_end].to_vec();
        
        Ok(subject_bytes)
    }

    fn hash_distinguished_name(&self, cert: &Certificate) -> Result<Vec<u8>, HttpsError> {
        let subject_bytes = self.get_cert_subject_raw(cert)?;
        Ok(sha1(&subject_bytes).to_vec())
    }

    fn hash_public_key(&self, cert: &Certificate) -> Result<Vec<u8>, HttpsError> {
        if let Some(public_key) = cert.public_key() {
            Ok(sha1(&public_key).to_vec())
        } else {
            Err(HttpsError::InvalidResponse(
                "Certificate has no public key".to_string()
            ))
        }
    }

    fn send_ocsp_request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, HttpsError> {
        let mut http_request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/ocsp-request\r\n\
             Content-Length: {}\r\n\
             Accept: application/ocsp-response\r\n\
             Connection: close\r\n\
             \r\n",
            url,
            self.extract_host_from_url(url)?,
            request.len()
        ).into_bytes();

        http_request.extend_from_slice(request);
        let (host, port, _) = self.parse_url(url)?;
        let mut stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| HttpsError::Io(e))?;

        stream.write_all(&http_request)
            .map_err(|e| HttpsError::Io(e))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| HttpsError::Io(e))?;

        if let Some(body_start) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            Ok(response[body_start + 4..].to_vec())
        } else {
            Err(HttpsError::InvalidResponse("Invalid OCSP response".to_string()))
        }
    }

    fn parse_ocsp_response(&self, response: &[u8], cert: &Certificate) -> Result<(), HttpsError> {
        let mut decoder = DerDecoder::new(response);

        // OCSPResponse ::= SEQUENCE {
        //   responseStatus  OCSPResponseStatus,
        //   responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
        // }
        decoder.sequence(|resp| {
            let status = resp.integer()?;

            // OCSPResponseStatus values:
            // successful (0), malformedRequest (1), internalError (2),
            // tryLater (3), sigRequired (5), unauthorized (6)
            let status_code = if !status.is_empty() {
                status[status.len() - 1] as i32
            } else {
                0
            };
            
            if status_code != 0 {
                return Err(crate::crypto::Error::InvalidData(format!("OCSP response status: {}", status_code)));
            }

            let _ = resp.context_specific(0, |ctx| {
                ctx.sequence(|bytes| {
                    let _response_type = bytes.object_identifier()?;
                    let response_value = bytes.octet_string()?;
                    let mut basic_decoder = DerDecoder::new(&response_value);
                    basic_decoder.sequence(|basic| {
                        basic.sequence(|resp_data| {
                            resp_data.sequence(|single_resp| {
                                single_resp.sequence(|_cert_id| Ok(()))?;
                                if let Ok(_) = single_resp.context_specific(1, |_decoder| Ok(())) {
                                    return Err(crate::crypto::Error::InvalidData("Certificate is revoked".to_string()));
                                }

                                Ok(())
                            })?;

                            Ok(())
                        })?;

                        Ok(())
                    })?;

                    Ok(())
                })
            });

            Ok(())
        }).map_err(|e| HttpsError::InvalidResponse(e.to_string()))?;

        Ok(())
    }

    fn check_crl_status(&self, cert: &Certificate) -> Result<(), HttpsError> {
        let crl_url = self.extract_crl_url(cert)?;
        let crl_data = self.download_crl(&crl_url)?;
        self.check_cert_in_crl(cert, &crl_data)?;

        Ok(())
    }

    fn extract_crl_url(&self, cert: &Certificate) -> Result<String, HttpsError> {
        let mut decoder = DerDecoder::new(&cert.tbs);
        let mut crl_url = None;
        let _ = decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer());
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.has_more() {
                        let _ = exts.sequence(|ext| {
                            let oid = ext.object_identifier()?;
                            if oid == vec![2, 5, 29, 31] {
                                let _critical = ext.boolean().unwrap_or(false);
                                let value = ext.octet_string()?;
                                let mut dp_decoder = DerDecoder::new(&value);
                                dp_decoder.sequence(|dps| {
                                    while dps.has_more() {
                                        let _ = dps.sequence(|dp| {
                                            dp.optional_context_specific(0, |dist_point| {
                                                dist_point.context_specific(0, |name_ctx| {
                                                    name_ctx.context_specific(6, |url_ctx| {
                                                        let bytes = url_ctx.read_bytes(url_ctx.data.len())?;
                                                        let url = String::from_utf8(bytes)
                                                            .map_err(|_| crate::crypto::Error::InvalidData("Invalid UTF-8".to_string()))?;
                                                        crl_url = Some(url.clone());
                                                        Ok(url)
                                                    })
                                                })
                                            })
                                        })?;
                                    }

                                    Ok(())
                                })?;
                            }

                            Ok(())
                        })?;
                    }

                    Ok(())
                })
            })
        });

        crl_url.ok_or_else(|| HttpsError::InvalidResponse(
            "No CRL distribution point found in certificate".to_string(),
        ))
    }

    fn download_crl(&self, url: &str) -> Result<Vec<u8>, HttpsError> {
        eprintln!("Downloading CRL from: {}", url);

        let (host, port, path) = self.parse_url(url)?;

        let mut stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| HttpsError::Io(e))?;

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path, host
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| HttpsError::Io(e))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| HttpsError::Io(e))?;

        if let Some(body_start) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            Ok(response[body_start + 4..].to_vec())
        } else {
            Err(HttpsError::InvalidResponse("Invalid CRL response".to_string()))
        }
    }

    fn check_cert_in_crl(&self, cert: &Certificate, crl_data: &[u8]) -> Result<(), HttpsError> {
        let mut decoder = DerDecoder::new(crl_data);

        let cert_serial = cert.serial_number()
            .map_err(|e| HttpsError::InvalidResponse(format!("Failed to get serial: {:?}", e)))?;

        decoder.sequence(|crl| {
            crl.sequence(|tbs| {
                let _ = tbs.optional_context_specific(0, |v| v.integer());
                let _ = tbs.sequence(|_| Ok(()))?;
                let _ = tbs.sequence(|_| Ok(()))?;
                let _ = tbs.utc_time()?;
                let revoked = tbs.optional_context_specific(0, |revoked_certs| {
                    revoked_certs.sequence(|certs| {
                        while certs.has_more() {
                            certs.sequence(|revoked| {
                                let serial = revoked.integer()?;
                                if serial == cert_serial {
                                    return Err(crate::crypto::Error::InvalidData(
                                        "Certificate found in CRL - REVOKED".to_string()
                                    ));
                                }

                                Ok(())
                            })?;
                        }

                        Ok(())
                    })
                });

                if let Err(e) = revoked {
                    return Err(e);
                }
                
                Ok(())
            })
        }).map_err(|e| HttpsError::InvalidResponse(format!("CRL check failed: {}", e)))?;

        Ok(())
    }

    fn extract_host_from_url(&self, url: &str) -> Result<String, HttpsError> {
        if let Some(start) = url.find("://") {
            let rest = &url[start + 3..];
            if let Some(end) = rest.find('/') {
                Ok(rest[..end].to_string())
            } else if let Some(end) = rest.find(':') {
                Ok(rest[..end].to_string())
            } else {
                Ok(rest.to_string())
            }
        } else {
            Err(HttpsError::InvalidUrl(format!("Invalid URL: {}", url)))
        }
    }

    fn process_certificate_verify(&self, data: &[u8]) -> Result<(), HttpsError> {
        if data.len() < 4 {
            return Err(HttpsError::InvalidResponse(
                "CertificateVerify too short".to_string(),
            ));
        }

        let signature_alg = u16::from_be_bytes([data[0], data[1]]);
        let signature_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + signature_len {
            return Err(HttpsError::InvalidResponse(
                "CertificateVerify signature truncated".to_string(),
            ));
        }

        let alg_name = match signature_alg {
            0x0804 => "rsa_pss_rsae_sha256",
            0x0805 => "rsa_pss_rsae_sha384",
            0x0806 => "rsa_pss_rsae_sha512",
            0x0401 => "ecdsa_secp256r1_sha256",
            0x0501 => "ecdsa_secp384r1_sha384",
            0x0601 => "ecdsa_secp521r1_sha512",
            _ => "unknown",
        };

        eprintln!(
            "CertificateVerify: algorithm={} (0x{:04x}), signature_len={}",
            alg_name, signature_alg, signature_len
        );

        Ok(())
    }

    fn process_finished(&self, data: &[u8]) -> Result<(), HttpsError> {
        if data.len() < 32 {
            return Err(HttpsError::InvalidResponse(
                "Finished message too short".to_string(),
            ));
        }

        eprintln!(
            "Received Finished message: {} bytes",
            data.len()
        );

        Ok(())
    }

    fn process_new_session_ticket(&self, data: &[u8]) -> Result<(), HttpsError> {
        if data.len() < 8 {
            return Err(HttpsError::InvalidResponse(
                "NewSessionTicket too short".to_string(),
            ));
        }

        let lifetime = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let age_add = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        eprintln!(
            "NewSessionTicket: lifetime={} seconds, age_add={}",
            lifetime, age_add
        );

        Ok(())
    }

    fn send_client_finished(&self, tls_stream: &mut TlsStream) -> Result<(), HttpsError> {
        let finished_data = vec![0u8; 32];
        let mut handshake_msg = vec![20];
        handshake_msg.extend_from_slice(&(finished_data.len() as u32).to_be_bytes()[1..]);
        handshake_msg.extend_from_slice(&finished_data);

        let mut record = vec![22, 0x03, 0x03];
        record.extend_from_slice(&(handshake_msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake_msg);

        tls_stream
            .write_all(&record)
            .map_err(|e| HttpsError::Io(e))?;

        tls_stream.flush().map_err(|e| HttpsError::Io(e))?;

        eprintln!("Sent client Finished message");

        Ok(())
    }

    fn send_http1_request(&mut self, connection_key: &str, method: HttpMethod, path: &str, request_headers: Headers, body: Option<Vec<u8>>) -> Result<HttpResponse, HttpsError> {
        let wrapper = self.tls_connections.get_mut(connection_key)
            .ok_or_else(|| HttpsError::ConnectionFailed("Connection not found".to_string()))?;

        let mut request_line = format!("{} {} HTTP/1.1\r\n", method.as_str(), path);
        for (name, values) in request_headers.iter() {
            for value in values {
                request_line.push_str(&format!("{}: {}\r\n", name, value));
            }
        }

        request_line.push_str("\r\n");
        let mut request_bytes = request_line.into_bytes();
        if let Some(b) = &body {
            request_bytes.extend_from_slice(b);
        }

        wrapper.stream.write_all(&request_bytes)
            .map_err(|e| HttpsError::Io(e))?;
        wrapper.stream.flush()
            .map_err(|e| HttpsError::Io(e))?;

        let http_stream = unsafe { &mut *(&mut wrapper.stream as *mut TlsStream) };
        self.read_http1_response(http_stream)
    }

    fn send_http2_request(&mut self, connection_key: &str, method: HttpMethod, path: &str, request_headers: Headers, body: Option<Vec<u8>>) -> Result<HttpResponse, HttpsError> {
        let settings_frame = self.build_settings_frame();
        
        let wrapper = self.tls_connections.get_mut(connection_key)
            .ok_or_else(|| HttpsError::ConnectionFailed("Connection not found".to_string()))?;

        if wrapper.protocol != Some(AlpnProtocol::Http2) {
            return Err(HttpsError::ProtocolNegotiationFailed(
                format!("Expected HTTP/2, got {:?}", wrapper.protocol)
            ));
        }

        if wrapper.http2_conn.is_none() {
            let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            wrapper.stream.write_all(preface)
                .map_err(|e| HttpsError::Io(e))?;

            wrapper.stream.write_all(&settings_frame)
                .map_err(|e| HttpsError::Io(e))?;
            wrapper.stream.flush()
                .map_err(|e| HttpsError::Io(e))?;

            wrapper.http2_conn = Some(Http2ConnectionWrapper {
                next_stream_id: 1,
                negotiated: true,
                max_concurrent_streams: u32::MAX,
                active_streams: HashMap::new(),
            });
        }

        let http2_conn = wrapper.http2_conn.as_mut()
            .ok_or_else(|| HttpsError::Http2Error("HTTP/2 not initialized".to_string()))?;
        
        let stream_id = http2_conn.next_stream_id;
        http2_conn.next_stream_id += 2;

        let mut h2_headers = vec![
            (":method".to_string(), method.as_str().to_string()),
            (":path".to_string(), path.to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), request_headers.get("host").unwrap_or("").to_string()),
        ];

        for (name, values) in request_headers.iter() {
            if !name.starts_with(':') && name.to_lowercase() != "host" {
                for value in values {
                    h2_headers.push((name.clone(), value.clone()));
                }
            }
        }

        let encoded_headers = self.encode_http2_headers(&h2_headers);
        let has_body = body.is_some();
        let headers_frame = self.build_headers_frame(stream_id, &encoded_headers, !has_body);
        
        let data_frame = if let Some(ref body_data) = body {
            self.build_data_frame(stream_id, body_data, true)
        } else {
            Vec::new()
        };
        
        let wrapper = self.tls_connections.get_mut(connection_key)
            .ok_or_else(|| HttpsError::ConnectionFailed("Connection not found".to_string()))?;

        wrapper.stream.write_all(&headers_frame)
            .map_err(|e| HttpsError::Io(e))?;

        if !data_frame.is_empty() {
            wrapper.stream.write_all(&data_frame)
                .map_err(|e| HttpsError::Io(e))?;
        }

        wrapper.stream.flush()
            .map_err(|e| HttpsError::Io(e))?;

        let http_stream = unsafe { &mut *(&mut wrapper.stream as *mut TlsStream) };
        self.read_http2_response(http_stream, stream_id)
    }

    fn build_settings_frame(&self) -> Vec<u8> {
        let frame = vec![
            0x00, 0x00, 0x00, // Length: 0
            0x04,             // Type: SETTINGS
            0x00,             // Flags
            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        ];
        frame
    }

    fn build_headers_frame(&mut self, stream_id: u32, headers: &[u8], end_stream: bool) -> Vec<u8> {
        let length = headers.len() as u32;
        let mut flags = 0x04;
        if end_stream {
            flags |= 0x01;
        }

        let mut frame = Vec::new();
        frame.extend_from_slice(&length.to_be_bytes()[1..]);
        frame.push(0x01);
        frame.push(flags);
        let sid = (stream_id & 0x7FFFFFFF).to_be_bytes();
        frame.extend_from_slice(&sid);
        frame.extend_from_slice(headers);

        frame
    }

    fn build_data_frame(&mut self, stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
        let length = data.len() as u32;
        let flags = if end_stream { 0x01 } else { 0x00 };

        let mut frame = Vec::new();
        frame.extend_from_slice(&length.to_be_bytes()[1..]);
        frame.push(0x00);
        frame.push(flags);
        let sid = (stream_id & 0x7FFFFFFF).to_be_bytes();
        frame.extend_from_slice(&sid);
        frame.extend_from_slice(data);

        frame
    }

    fn encode_http2_headers(&mut self, headers: &[(String, String)]) -> Vec<u8> {
        let mut headers_map = HashMap::new();
        for (name, value) in headers {
            headers_map.insert(name.clone(), value.clone());
        }

        let mut codec = HpackCodec::new(4096);
        codec.encode(&headers_map)
    }

    fn encode_string(encoded: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len();
        if len < 127 {
            encoded.push(len as u8);
        } else {
            encoded.push(0x7F);
            let mut remaining = len - 127;
            while remaining >= 128 {
                encoded.push((remaining % 128 + 128) as u8);
                remaining /= 128;
            }
            encoded.push(remaining as u8);
        }
        
        encoded.extend_from_slice(bytes);
    }

    fn read_http1_response(&mut self, stream: &mut TlsStream) -> Result<HttpResponse, HttpsError> {
        let mut buffer = vec![0u8; 8192];
        let bytes_read = stream.read(&mut buffer)
            .map_err(|e| HttpsError::Io(e))?;

        if bytes_read == 0 {
            return Err(HttpsError::InvalidResponse("Empty response".to_string()));
        }

        buffer.truncate(bytes_read);

        self.parse_http1_response(&buffer)
    }

    fn read_http2_response(&mut self, stream: &mut TlsStream, stream_id: u32) -> Result<HttpResponse, HttpsError> {
        let mut buffer = vec![0u8; 16384];
        let mut all_data = Vec::new();
        let mut headers = HashMap::new();
        let mut status_code: u16 = 200;
        let mut response_complete = false;
        loop {
            let bytes_read = stream.read(&mut buffer)
                .map_err(|e| HttpsError::Io(e))?;

            if bytes_read == 0 {
                break;
            }

            all_data.extend_from_slice(&buffer[..bytes_read]);
            let mut pos = 0;
            while pos + 9 <= all_data.len() {
                let length = ((all_data[pos] as u32) << 16)
                    | ((all_data[pos + 1] as u32) << 8)
                    | (all_data[pos + 2] as u32);
                
                let frame_type = all_data[pos + 3];
                let flags = all_data[pos + 4];
                let stream_id_raw = u32::from_be_bytes([
                    all_data[pos + 5],
                    all_data[pos + 6],
                    all_data[pos + 7],
                    all_data[pos + 8],
                ]);

                let current_stream_id = stream_id_raw & 0x7FFFFFFF;
                if pos + 9 + length as usize > all_data.len() {
                    break;
                }

                let payload = all_data[pos + 9..pos + 9 + length as usize].to_vec();
                if current_stream_id == stream_id {
                    match frame_type {
                        0x01 => {
                            self.parse_http2_headers(&payload, &mut headers, &mut status_code)?;
                            if flags & 0x01 != 0 {
                                response_complete = true;
                            }
                        }
                        0x00 => {
                            all_data.extend_from_slice(&payload);
                            if flags & 0x01 != 0 {
                                response_complete = true;
                            }
                        }
                        _ => {}
                    }
                }

                pos += 9 + length as usize;
            }

            if response_complete {
                break;
            }
        }

        let body = all_data.to_vec();

        Ok(HttpResponse::new(
            status_code,
            "OK".to_string(),
            HttpVersion::Http2,
            headers,
            body,
        ))
    }

    fn parse_http2_headers(&mut self, payload: &[u8], headers: &mut HashMap<String, String>, status_code: &mut u16) -> Result<(), HttpsError> {
        let mut codec = HpackCodec::new(4096);        
        match codec.decode(payload) {
            Ok(decoded_headers) => {
                for (name, value) in decoded_headers {
                    if name == ":status" {
                        *status_code = value.parse::<u16>()
                            .map_err(|_| HttpsError::InvalidResponse(
                                format!("Invalid status code: {}", value)
                            ))?;
                    } else if !name.starts_with(':') {
                        headers.insert(name, value);
                    }
                }

                Ok(())
            }
            Err(e) => Err(HttpsError::Http2Error(
                format!("HPACK decoding failed: {}", e)
            ))
        }
    }

    fn parse_http1_response(&mut self, data: &[u8]) -> Result<HttpResponse, HttpsError> {
        let response_str = String::from_utf8_lossy(data);
        let lines: Vec<&str> = response_str.split("\r\n").collect();

        if lines.is_empty() {
            return Err(HttpsError::InvalidResponse("No status line".to_string()));
        }

        let status_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err(HttpsError::InvalidResponse("Invalid status line".to_string()));
        }

        let status_code = status_parts[1].parse::<u16>()
            .map_err(|_| HttpsError::InvalidResponse("Invalid status code".to_string()))?;

        let reason_phrase = if status_parts.len() > 2 {
            status_parts[2..].join(" ")
        } else {
            "".to_string()
        };

        let mut headers = HashMap::new();
        let mut body_start = 0;
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        let body = if body_start > 0 && body_start < lines.len() {
            lines[body_start..].join("\r\n").into_bytes()
        } else {
            Vec::new()
        };

        let body = if headers.get("transfer-encoding").map(|v| v.as_str()) == Some("chunked") {
            self.decode_chunked(&body)?
        } else {
            body
        };

        Ok(HttpResponse::new(
            status_code,
            reason_phrase,
            HttpVersion::Http11,
            headers,
            body,
        ))
    }

    fn parse_url(&self, url: &str) -> Result<(String, u16, String), HttpsError> {
        let url = if url.starts_with("https://") {
            &url[8..]
        } else if url.starts_with("http://") {
            return Err(HttpsError::InvalidUrl(
                "HTTPS client requires https:// scheme".to_string(),
            ));
        } else {
            url
        };

        let (host_port, path) = if let Some(pos) = url.find('/') {
            (&url[..pos], &url[pos..])
        } else {
            (url, "/")
        };

        let (host, port) = if let Some(pos) = host_port.rfind(':') {
            let port_str = &host_port[pos + 1..];
            let port = port_str.parse::<u16>()
                .map_err(|_| HttpsError::InvalidUrl("Invalid port number".to_string()))?;
            (&host_port[..pos], port)
        } else {
            (host_port, 443)
        };

        Ok((host.to_string(), port, path.to_string()))
    }

    fn resolve_url(&self, base: &str, relative: &str) -> String {
        if relative.starts_with("http://") || relative.starts_with("https://") {
            relative.to_string()
        } else if relative.starts_with('/') {
            if let Ok((host, port, _)) = self.parse_url(base) {
                format!("https://{}:{}{}", host, port, relative)
            } else {
                relative.to_string()
            }
        } else {
            if let Some(last_slash) = base.rfind('/') {
                format!("{}/{}", &base[..last_slash], relative)
            } else {
                format!("{}/{}", base, relative)
            }
        }
    }

    fn decode_chunked(&self, data: &[u8]) -> Result<Vec<u8>, HttpsError> {
        let mut result = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let size_line_end = data[pos..].iter()
                .position(|&b| b == b'\r')
                .ok_or_else(|| HttpsError::InvalidResponse("Invalid chunk size".to_string()))?;

            let size_str = String::from_utf8_lossy(&data[pos..pos + size_line_end]);
            let chunk_size = usize::from_str_radix(size_str.trim_end(), 16)
                .map_err(|_| HttpsError::InvalidResponse("Invalid chunk size hex".to_string()))?;

            pos += size_line_end + 2;
            if chunk_size == 0 {
                break;
            }

            if pos + chunk_size > data.len() {
                return Err(HttpsError::InvalidResponse("Chunk size exceeds data".to_string()));
            }

            result.extend_from_slice(&data[pos..pos + chunk_size]);
            pos += chunk_size + 2;
        }

        Ok(result)
    }

    pub fn clear_connections(&mut self) {
        self.tls_connections.clear();
        self.connection_pool.clear();
        self.negotiated_protocols.clear();
    }

    pub fn get_connection_stats(&self) -> HashMap<String, Option<AlpnProtocol>> {
        self.tls_connections.iter()
            .map(|(k, v)| (k.clone(), v.protocol))
            .collect()
    }
}

impl Default for HttpsClient {
    fn default() -> Self {
        Self::new(HttpsClientCfg::default())
    }
}

impl From<TlsError> for HttpsError {
    fn from(err: TlsError) -> Self {
        HttpsError::Tls(err)
    }
}

impl From<std::io::Error> for HttpsError {
    fn from(err: std::io::Error) -> Self {
        HttpsError::Io(err)
    }
}

impl std::fmt::Display for HttpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpsError::Tls(e) => write!(f, "TLS Error: {:?}", e),
            HttpsError::Io(e) => write!(f, "IO Error: {}", e),
            HttpsError::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
            HttpsError::InvalidResponse(msg) => write!(f, "Invalid Response: {}", msg),
            HttpsError::Timeout => write!(f, "Request Timeout"),
            HttpsError::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
            HttpsError::TooManyRedirects => write!(f, "Too Many Redirects"),
            HttpsError::ProtocolNegotiationFailed(msg) => write!(f, "Protocol Negotiation Failed: {}", msg),
            HttpsError::Http2Error(msg) => write!(f, "HTTP/2 Error: {}", msg),
        }
    }
}

impl std::error::Error for HttpsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_client_creation() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        assert!(client.tls_connections.is_empty());
    }

    #[test]
    fn test_parse_url_default_port() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let (host, port, path) = client.parse_url("https://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_url_custom_port() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let (host, port, path) = client.parse_url("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_encode_http2_headers_with_hpack() {
        let mut client = HttpsClient::new(HttpsClientCfg::default());
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "https".to_string()),
            ("user-agent".to_string(), "test".to_string()),
        ];
        
        let encoded = client.encode_http2_headers(&headers);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_parse_http2_headers_with_hpack() {
        let mut client = HttpsClient::new(HttpsClientCfg::default());
        
        let mut encoder = HpackCodec::new(4096);
        let headers: HashMap<String, String> = vec![
            (":status".to_string(), "200".to_string()),
            ("content-type".to_string(), "text/html".to_string()),
            ("content-length".to_string(), "1234".to_string()),
        ].into_iter().collect();
        
        let encoded = encoder.encode(&headers);
        
        let mut decoded_headers = HashMap::new();
        let mut status_code = 200u16;
        
        client.parse_http2_headers(&encoded, &mut decoded_headers, &mut status_code)
            .expect("Failed to parse headers");
        
        assert_eq!(status_code, 200);
        assert_eq!(decoded_headers.get("content-type").unwrap(), "text/html");
        assert_eq!(decoded_headers.get("content-length").unwrap(), "1234");
    }

    #[test]
    fn test_chunked_decoding() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let chunked = b"5\r\nHello\r\n0\r\n\r\n";
        let decoded = client.decode_chunked(chunked).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_chunked_decoding_multiple_chunks() {
        let client = HttpsClient::new(HttpsClientCfg::default());
        let chunked = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let decoded = client.decode_chunked(chunked).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_alpn_protocol_negotiation() {
        let mut client = HttpsClient::new(HttpsClientCfg::default());
        let protocols = vec![AlpnProtocol::Http2, AlpnProtocol::Http11];
        client.set_alpn_protocols(protocols);
        
        let supported = client.alpn_negotiator.supported_protocols_sorted();
        assert_eq!(supported.len(), 2);
    }
}