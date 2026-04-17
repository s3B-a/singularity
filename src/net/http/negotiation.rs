use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::cmp::Ordering;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTENT_NEGOTIATION_BLOB_MAGIC: &str = "SINGULARITY_HTTP_NEGOTIATION_BLOB_V1";
const CONTENT_NEGOTIATION_BLOB_CONTEXT: &str = "SINGULARITY_HTTP_NEGOTIATION_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureContentNegotiationBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentNegotiationProfile {
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaType {
    pub type_: String,
    pub subtype: String,
    pub quality: f32,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct LanguageTag {
    pub language: String,
    pub region: Option<String>,
    pub quality: f32,
}

#[derive(Debug, Clone)]
pub struct EncodingPreference {
    pub encoding: String,
    pub quality: f32,
}

pub struct ContentNegotiator;

impl ContentNegotiationProfile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_headers(accept: Option<&str>, accept_language: Option<&str>, accept_encoding: Option<&str>) -> Self {
        Self {
            accept: accept.map(ToOwned::to_owned),
            accept_language: accept_language.map(ToOwned::to_owned),
            accept_encoding: accept_encoding.map(ToOwned::to_owned),
        }
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureContentNegotiationBlobMeta, Vec<u8>)> {
        encode_secure_content_negotiation_profile(self, algorithm)
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureContentNegotiationBlobMeta, Vec<u8>)> {
        encode_secure_content_negotiation_profile_auto(self, accept_encoding)
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureContentNegotiationBlobMeta, Self)> {
        decode_secure_content_negotiation_profile(data)
    }

    pub fn negotiate_media_type(&self, available: &[&str]) -> Option<String> {
        self.accept.as_deref().and_then(|accept| ContentNegotiator::negotiate_media_type(accept, available))
    }

    pub fn negotiate_language(&self, available: &[&str]) -> Option<String> {
        self.accept_language.as_deref().and_then(|accept_language| {
            ContentNegotiator::negotiate_language(accept_language, available)
        })
    }

    pub fn negotiate_encoding(&self, available: &[&str]) -> Option<String> {
        self.accept_encoding.as_deref().and_then(|accept_encoding| {
            ContentNegotiator::negotiate_encoding(accept_encoding, available)
        }).or_else(|| {
            if available.iter().any(|e| e.eq_ignore_ascii_case("identity")) {
                Some("identity".to_string())
            } else {
                None
            }
        })
    }
}

impl MediaType {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
        if parts.is_empty() || parts[0].is_empty() {
            return None;
        }

        let media_parts: Vec<&str> = parts[0].split('/').collect();
        if media_parts.len() != 2 {
            return None;
        }

        let mut quality = 1.0_f32;
        let mut params = Vec::new();
        for param in &parts[1..] {
            if let Some((key, value)) = param.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if key.eq_ignore_ascii_case("q") {
                    quality = Self::parse_q(value);
                } else {
                    params.push((key.to_string(), value.to_string()));
                }
            }
        }

        Some(MediaType {
            type_: media_parts[0].to_ascii_lowercase(),
            subtype: media_parts[1].to_ascii_lowercase(),
            quality,
            params,
        })
    }

    pub fn matches(&self, other: &MediaType) -> bool {
        (self.type_ == "*" || other.type_ == "*" || self.type_ == other.type_) && (self.subtype == "*" || other.subtype == "*" || self.subtype == other.subtype)
    }

    pub fn specificity(&self) -> u8 {
        if self.type_ == "*" {
            0
        } else if self.subtype == "*" {
            1
        } else {
            2
        }
    }

    fn parse_q(q: &str) -> f32 {
        q.parse::<f32>().ok().map(|v| v.clamp(0.0, 1.0)).unwrap_or(1.0)
    }

    pub fn to_string(&self) -> String {
        let mut result = format!("{}/{}", self.type_, self.subtype);
        for (key, value) in &self.params {
            result.push_str(&format!("; {}={}", key, value));
        }

        result
    }
}

impl LanguageTag {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
        if parts.is_empty() || parts[0].is_empty() {
            return None;
        }

        let lang_parts: Vec<&str> = parts[0].split('-').collect();
        let language = lang_parts[0].to_ascii_lowercase();
        let region = if lang_parts.len() > 1 {
            Some(lang_parts[1].to_ascii_uppercase())
        } else {
            None
        };

        let mut quality = 1.0_f32;
        for param in &parts[1..] {
            if let Some((key, value)) = param.split_once('=') {
                if key.trim().eq_ignore_ascii_case("q") {
                    quality = value.trim().parse::<f32>().ok().map(|v| v.clamp(0.0, 1.0)).unwrap_or(1.0);
                }
            }
        }

        Some(LanguageTag {
            language,
            region,
            quality,
        })
    }

    pub fn matches(&self, other: &LanguageTag) -> bool {
        if self.language == "*" || other.language == "*" {
            return true;
        }

        if self.language != other.language {
            return false;
        }

        match (&self.region, &other.region) {
            (None, _) | (_, None) => true,
            (Some(r1), Some(r2)) => r1 == r2,
        }
    }

    pub fn to_string(&self) -> String {
        if let Some(ref region) = self.region {
            format!("{}-{}", self.language, region)
        } else {
            self.language.clone()
        }
    }
}

impl EncodingPreference {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').map(|p| p.trim()).collect();
        if parts.is_empty() || parts[0].is_empty() {
            return None;
        }

        let encoding = parts[0].to_ascii_lowercase();
        let mut quality = 1.0_f32;
        for param in &parts[1..] {
            if let Some((key, value)) = param.split_once('=') {
                if key.trim().eq_ignore_ascii_case("q") {
                    quality = value.trim().parse::<f32>().ok().map(|v| v.clamp(0.0, 1.0)).unwrap_or(1.0);
                }
            }
        }

        Some(EncodingPreference { encoding, quality })
    }

    fn specificity(&self) -> u8 {
        if self.encoding == "*" { 0 } else { 1 }
    }
}

impl ContentNegotiator {
    pub fn negotiate_media_type(accept: &str, available: &[&str]) -> Option<String> {
        let mut client_prefs: Vec<MediaType> = accept.split(',').filter_map(|s| MediaType::parse(s.trim())).filter(|m| m.quality > 0.0).collect();

        client_prefs.sort();

        let server_types: Vec<MediaType> = available.iter().filter_map(|s| MediaType::parse(s)).collect();
        for client_type in &client_prefs {
            for server_type in &server_types {
                if client_type.matches(server_type) {
                    return Some(server_type.to_string());
                }
            }
        }

        None
    }

    pub fn negotiate_language(accept_language: &str, available: &[&str]) -> Option<String> {
        let mut client_prefs: Vec<LanguageTag> = accept_language.split(',').filter_map(|s| LanguageTag::parse(s.trim())).filter(|l| l.quality > 0.0).collect();
        client_prefs.sort();
        let server_langs: Vec<LanguageTag> = available.iter().filter_map(|s| LanguageTag::parse(s)).collect();
        for client_lang in &client_prefs {
            for server_lang in &server_langs {
                if client_lang.matches(server_lang) {
                    return Some(server_lang.to_string());
                }
            }
        }

        None
    }

    pub fn negotiate_encoding(accept_encoding: &str, available: &[&str]) -> Option<String> {
        let mut client_prefs: Vec<EncodingPreference> = accept_encoding.split(',').filter_map(|s| EncodingPreference::parse(s.trim())).filter(|e| e.quality > 0.0).collect();
        if client_prefs.is_empty() {
            return Some("identity".to_string());
        }

        client_prefs.sort();
        let available_lc: Vec<String> = available.iter().map(|s| s.to_ascii_lowercase()).collect();
        for pref in &client_prefs {
            if pref.encoding == "*" {
                if let Some(first_non_identity) = available_lc.iter().find(|e| e.as_str() != "identity") {
                    return Some(first_non_identity.clone());
                }

                return Some("identity".to_string());
            }

            if available_lc.iter().any(|e| e == &pref.encoding) {
                return Some(pref.encoding.clone());
            }
        }

        if available_lc.iter().any(|e| e == "identity") {
            return Some("identity".to_string());
        }

        None
    }

    pub fn parse_accept(accept: &str) -> Vec<MediaType> {
        let mut types: Vec<MediaType> = accept.split(',').filter_map(|s| MediaType::parse(s.trim())).filter(|m| m.quality > 0.0).collect();
        types.sort();

        types
    }

    pub fn parse_accept_language(accept_language: &str) -> Vec<LanguageTag> {
        let mut langs: Vec<LanguageTag> = accept_language.split(',').filter_map(|s| LanguageTag::parse(s.trim())).filter(|l| l.quality > 0.0).collect();
        langs.sort();

        langs
    }

    pub fn parse_accept_encoding(accept_encoding: &str) -> Vec<EncodingPreference> {
        let mut encodings: Vec<EncodingPreference> = accept_encoding.split(',').filter_map(|s| EncodingPreference::parse(s.trim())).filter(|e| e.quality > 0.0).collect();
        encodings.sort();

        encodings
    }
}

pub fn select_secure_content_negotiation_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    compression::parse_accept_encoding(accept_encoding).into_iter().find_map(|(algorithm, quality)| {
        if quality > 0.0 && algorithm.is_implemented() {
            Some(algorithm)
        } else {
            None
        }
    }).unwrap_or(CompressionAlgorithm::Identity)
}

pub fn encode_secure_content_negotiation_profile(profile: &ContentNegotiationProfile, algorithm: CompressionAlgorithm) -> io::Result<(SecureContentNegotiationBlobMeta, Vec<u8>)> {
    let mut selected_algorithm = algorithm;
    if !selected_algorithm.is_implemented() {
        selected_algorithm = CompressionAlgorithm::Identity;
    }

    let raw_payload = serialize_content_negotiation_profile(profile);
    let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
        raw_payload.clone()
    } else {
        compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
    };

    let nonce = random::generate_random(24).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to generate negotiation blob nonce: {}", e),
        )
    })?;

    let digest = sha256(&raw_payload);
    let tag = compute_content_negotiation_blob_tag(
        &nonce,
        selected_algorithm,
        raw_payload.len(),
        &encoded_payload,
    );

    let digest_b64 = pem::encode(&digest);
    let tag_b64 = pem::encode(&tag);
    let nonce_b64 = pem::encode(&nonce);
    let issued_at_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let header = format!(
        "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
        magic = CONTENT_NEGOTIATION_BLOB_MAGIC,
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

    Ok((
        SecureContentNegotiationBlobMeta {
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

pub fn encode_secure_content_negotiation_profile_auto(profile: &ContentNegotiationProfile,accept_encoding: &str) -> io::Result<(SecureContentNegotiationBlobMeta, Vec<u8>)> {
    let selected = select_secure_content_negotiation_algorithm(accept_encoding);
    encode_secure_content_negotiation_profile(profile, selected)
}

pub fn decode_secure_content_negotiation_profile(data: &[u8]) -> io::Result<(SecureContentNegotiationBlobMeta, ContentNegotiationProfile)> {
    let (header, body) = split_header_body(data)?;
    let meta = parse_secure_content_negotiation_meta(&header, body.len())?;
    let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid negotiation nonce encoding: {}", e),
        )
    })?;

    let expected_digest = pem::decode(&meta.digest_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid negotiation digest encoding: {}", e),
        )
    })?;

    let provided_tag = pem::decode(&meta.tag_b64).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid negotiation tag encoding: {}", e),
        )
    })?;

    if expected_digest.len() != 32 || provided_tag.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negotiation digest or tag has invalid length",
        ));
    }

    let expected_tag =compute_content_negotiation_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
    if !constant_time_eq(&expected_tag, &provided_tag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "content-negotiation blob HMAC mismatch",
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
                "negotiation raw-size mismatch: expected {}, got {}",
                meta.raw_size,
                raw_payload.len()
            ),
        ));
    }

    let actual_digest = sha256(&raw_payload);
    if !constant_time_eq(&actual_digest, &expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "content-negotiation blob digest mismatch",
        ));
    }

    let profile = deserialize_content_negotiation_profile(&raw_payload)?;
    Ok((meta, profile))
}

fn serialize_content_negotiation_profile(profile: &ContentNegotiationProfile) -> Vec<u8> {
    let mut lines = Vec::new();
    if let Some(accept) = &profile.accept {
        lines.push(format!("accept={}", pem::encode(accept.as_bytes())));
    }

    if let Some(accept_language) = &profile.accept_language {
        lines.push(format!(
            "accept-language={}",
            pem::encode(accept_language.as_bytes())
        ));
    }

    if let Some(accept_encoding) = &profile.accept_encoding {
        lines.push(format!(
            "accept-encoding={}",
            pem::encode(accept_encoding.as_bytes())
        ));
    }

    lines.join("\n").into_bytes()
}

fn deserialize_content_negotiation_profile(raw_payload: &[u8]) -> io::Result<ContentNegotiationProfile> {
    let text = String::from_utf8(raw_payload.to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "content-negotiation payload is not valid UTF-8",
        )
    })?;

    let mut profile = ContentNegotiationProfile::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid content-negotiation line '{}'", trimmed),
            )
        })?;

        let decoded = String::from_utf8(pem::decode(value.trim()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid content-negotiation value encoding: {}", e),
            )
        })?).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "content-negotiation value is not valid UTF-8",
            )
        })?;

        match key.trim() {
            "accept" => profile.accept = Some(decoded),
            "accept-language" => profile.accept_language = Some(decoded),
            "accept-encoding" => profile.accept_encoding = Some(decoded),
            _ => {}
        }
    }

    Ok(profile)
}

fn compute_content_negotiation_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(CONTENT_NEGOTIATION_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(CONTENT_NEGOTIATION_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "content-negotiation header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "content-negotiation header is not valid UTF-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "content-negotiation blob missing header/body separator",
    ))
}

fn parse_secure_content_negotiation_meta(header: &str, body_len: usize) -> io::Result<SecureContentNegotiationBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != CONTENT_NEGOTIATION_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid content-negotiation blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None::<usize>;
    let mut encoded_size = None::<usize>;
    let mut issued_at_unix = None::<u64>;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid content-negotiation header line '{}'", line),
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
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid digest header"))?.to_string();
                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid tag header"))?.to_string();
                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid raw-size in negotiation blob",
                    )
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in negotiation blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid issued-at in negotiation blob",
                    )
                })?);
            }
            _ => {}
        }
    }

    let nonce_b64 = nonce_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nonce in negotiation blob header",
        )
    })?;

    let digest_b64 = digest_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing digest in negotiation blob header",
        )
    })?;

    let tag_b64 = tag_b64.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing tag in negotiation blob header",
        )
    })?;

    let raw_size = raw_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing raw-size in negotiation blob header",
        )
    })?;

    let encoded_size = encoded_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing encoded-size in negotiation blob header",
        )
    })?;

    let issued_at_unix = issued_at_unix.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing issued-at in negotiation blob header",
        )
    })?;

    if encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "negotiation encoded-size mismatch: expected {}, got {}",
                encoded_size, body_len
            ),
        ));
    }

    Ok(SecureContentNegotiationBlobMeta {
        algorithm,
        nonce_b64,
        digest_b64,
        tag_b64,
        raw_size,
        encoded_size,
        issued_at_unix,
    })
}

impl PartialEq for MediaType {
    fn eq(&self, other: &Self) -> bool {
        self.type_ == other.type_ && self.subtype == other.subtype
    }
}

impl Eq for MediaType {}

impl PartialOrd for MediaType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MediaType {
    fn cmp(&self, other: &Self) -> Ordering {
        let quality_cmp = other.quality.partial_cmp(&self.quality).unwrap_or(Ordering::Equal);
        if quality_cmp != Ordering::Equal {
            return quality_cmp;
        }

        other.specificity().cmp(&self.specificity())
    }
}

impl PartialEq for LanguageTag {
    fn eq(&self, other: &Self) -> bool {
        self.language == other.language && self.region == other.region
    }
}

impl Eq for LanguageTag {}

impl PartialOrd for LanguageTag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanguageTag {
    fn cmp(&self, other: &Self) -> Ordering {
        other.quality.partial_cmp(&self.quality).unwrap_or(Ordering::Equal)
    }
}

impl PartialEq for EncodingPreference {
    fn eq(&self, other: &Self) -> bool {
        self.encoding.eq_ignore_ascii_case(&other.encoding)
    }
}

impl Eq for EncodingPreference {}

impl PartialOrd for EncodingPreference {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EncodingPreference {
    fn cmp(&self, other: &Self) -> Ordering {
        let quality_cmp = other.quality.partial_cmp(&self.quality).unwrap_or(Ordering::Equal);
        if quality_cmp != Ordering::Equal {
            return quality_cmp;
        }

        other.specificity().cmp(&self.specificity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_type_parse() {
        let mt = MediaType::parse("text/html; q=0.8").unwrap();
        assert_eq!(mt.type_, "text");
        assert_eq!(mt.subtype, "html");
        assert_eq!(mt.quality, 0.8);
    }

    #[test]
    fn test_media_type_wildcard() {
        let mt1 = MediaType::parse("text/*").unwrap();
        let mt2 = MediaType::parse("text/html").unwrap();
        assert!(mt1.matches(&mt2));
    }

    #[test]
    fn test_negotiate_media_type() {
        let result = ContentNegotiator::negotiate_media_type(
            "text/html, application/json; q=0.9, */*; q=0.1",
            &["application/json", "text/plain"],
        );

        assert_eq!(result, Some("application/json".to_string()));
    }

    #[test]
    fn test_language_tag_parse() {
        let lang = LanguageTag::parse("en-US; q=0.9").unwrap();
        assert_eq!(lang.language, "en");
        assert_eq!(lang.region, Some("US".to_string()));
        assert_eq!(lang.quality, 0.9);
    }

    #[test]
    fn test_negotiate_language() {
        let result = ContentNegotiator::negotiate_language(
            "en-US, en; q=0.9, fr; q=0.8",
            &["en", "de"],
        );

        assert_eq!(result, Some("en".to_string()));
    }

    #[test]
    fn test_negotiate_encoding() {
        let result = ContentNegotiator::negotiate_encoding(
            "gzip, deflate; q=0.8, identity; q=0.1",
            &["deflate", "identity"],
        );

        assert_eq!(result, Some("deflate".to_string()));
    }

    #[test]
    fn test_negotiate_encoding_wildcard() {
        let result =
            ContentNegotiator::negotiate_encoding("*; q=0.5", &["br", "gzip", "identity"]);
        assert_eq!(result, Some("br".to_string()));
    }

    #[test]
    fn test_secure_negotiation_profile_roundtrip_identity() {
        let profile = ContentNegotiationProfile {
            accept: Some("application/json, text/plain; q=0.8".to_string()),
            accept_language: Some("en-US, en; q=0.9".to_string()),
            accept_encoding: Some("br, gzip; q=0.9, identity; q=0.1".to_string()),
        };

        let (meta, blob) = profile
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();

        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (decoded_meta, restored) = ContentNegotiationProfile::from_secure_blob(&blob).unwrap();

        assert_eq!(decoded_meta.algorithm, CompressionAlgorithm::Identity);
        assert_eq!(restored, profile);
    }

    #[test]
    fn test_secure_negotiation_profile_tamper_detection() {
        let profile = ContentNegotiationProfile {
            accept: Some("text/html".to_string()),
            accept_language: None,
            accept_encoding: Some("gzip".to_string()),
        };

        let (_, mut blob) = profile
            .to_secure_blob(CompressionAlgorithm::Identity)
            .unwrap();

        let idx = blob.len() - 1;
        blob[idx] ^= 0x01;

        let err = ContentNegotiationProfile::from_secure_blob(&blob).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}