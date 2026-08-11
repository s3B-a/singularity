use super::record::{DnsRecord, RecordData, RecordType};
use crate::crypto::asymmetric::{ecdsa, rsa};
use crate::crypto::constant_time_eq;
use crate::crypto::hash::sha2::{sha1, sha256, sha384, sha512};
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecError {
    WrongRecordType,
    UnsupportedAlgorithm(u8),
    UnsupportedDigestType(u8),
    KeyTagMismatch,
    AlgorithmMismatch,
    SignatureExpired,
    SignatureNotYetValid,
    BadSignature,
    Malformed(String),
}

impl fmt::Display for DnssecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnssecError::WrongRecordType => write!(f, "record is not the expected DNSSEC record type"),
            DnssecError::UnsupportedAlgorithm(a) => write!(f, "unsupported DNSSEC algorithm: {}", a),
            DnssecError::UnsupportedDigestType(d) => write!(f, "unsupported DS digest type: {}", d),
            DnssecError::KeyTagMismatch => write!(f, "RRSIG/DS key tag does not match the DNSKEY"),
            DnssecError::AlgorithmMismatch => write!(f, "algorithm mismatch between RRSIG/DS and DNSKEY"),
            DnssecError::SignatureExpired => write!(f, "RRSIG signature has expired"),
            DnssecError::SignatureNotYetValid => write!(f, "RRSIG signature is not yet valid"),
            DnssecError::BadSignature => write!(f, "signature verification failed"),
            DnssecError::Malformed(msg) => write!(f, "malformed DNSSEC data: {}", msg),
        }
    }
}

impl std::error::Error for DnssecError {}

impl From<DnssecError> for io::Error {
    fn from(e: DnssecError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    }
}

fn dnskey_fields(record: &DnsRecord) -> Result<(u16, u8, u8, &[u8]), DnssecError> {
    match &record.data {
        RecordData::DNSKEY { flags, protocol, algorithm, public_key } => Ok((*flags, *protocol, *algorithm, public_key.as_slice())),
        _ => Err(DnssecError::WrongRecordType),
    }
}

fn dnskey_rdata_bytes(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + public_key.len());
    out.extend_from_slice(&flags.to_be_bytes());
    out.push(protocol);
    out.push(algorithm);
    out.extend_from_slice(public_key);
    out
}

pub fn compute_key_tag(dnskey: &DnsRecord) -> Result<u16, DnssecError> {
    let (flags, protocol, algorithm, public_key) = dnskey_fields(dnskey)?;
    let rdata = dnskey_rdata_bytes(flags, protocol, algorithm, public_key);
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }

    ac += (ac >> 16) & 0xFFFF;
    Ok((ac & 0xFFFF) as u16)
}

fn write_canonical_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }

        let lower = label.to_ascii_lowercase();
        out.push(lower.len() as u8);
        out.extend_from_slice(lower.as_bytes());
    }

    out.push(0);
}

fn canonical_rdata(data: &RecordData) -> Result<Vec<u8>, DnssecError> {
    let mut out = Vec::new();
    match data {
        RecordData::A(ip) => out.extend_from_slice(&ip.octets()),
        RecordData::AAAA(ip) => out.extend_from_slice(&ip.octets()),
        RecordData::NS(name) | RecordData::CNAME(name) | RecordData::PTR(name) => {
            write_canonical_name(&mut out, name);
        }
        RecordData::MX { preference, exchange } => {
            out.extend_from_slice(&preference.to_be_bytes());
            write_canonical_name(&mut out, exchange);
        }
        RecordData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
            write_canonical_name(&mut out, mname);
            write_canonical_name(&mut out, rname);
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        RecordData::SRV { priority, weight, port, target } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            write_canonical_name(&mut out, target);
        }
        RecordData::TXT(texts) => {
            for text in texts {
                if text.len() > 255 {
                    return Err(DnssecError::Malformed("TXT segment exceeds 255 bytes".to_string()));
                }

                out.push(text.len() as u8);
                out.extend_from_slice(text.as_bytes());
            }
        }
        RecordData::DS { key_tag, algorithm, digest_type, digest } => {
            out.extend_from_slice(&key_tag.to_be_bytes());
            out.push(*algorithm);
            out.push(*digest_type);
            out.extend_from_slice(digest);
        }
        RecordData::DNSKEY { flags, protocol, algorithm, public_key } => {
            out = dnskey_rdata_bytes(*flags, *protocol, *algorithm, public_key);
        }
        RecordData::NSEC { next_domain_name, type_bit_maps } => {
            write_canonical_name(&mut out, next_domain_name);
            out.extend_from_slice(type_bit_maps);
        }
        RecordData::NSEC3 { hash_algorithm, flags, iterations, salt, next_hashed_owner_name, type_bit_maps } => {
            out.push(*hash_algorithm);
            out.push(*flags);
            out.extend_from_slice(&iterations.to_be_bytes());
            out.push(salt.len() as u8);
            out.extend_from_slice(salt);
            out.push(next_hashed_owner_name.len() as u8);
            out.extend_from_slice(next_hashed_owner_name);
            out.extend_from_slice(type_bit_maps);
        }
        RecordData::Unknown(bytes) => out.extend_from_slice(bytes),
        RecordData::RRSIG { .. } => {
            return Err(DnssecError::Malformed("signing an RRSIG-covered RRSIG is not supported".to_string()));
        }
    }

    Ok(out)
}

fn canonical_rr_bytes(record: &DnsRecord, ttl_override: u32) -> Result<Vec<u8>, DnssecError> {
    let mut out = Vec::new();
    write_canonical_name(&mut out, &record.name);
    out.extend_from_slice(&record.record_type.to_u16().to_be_bytes());
    out.extend_from_slice(&record.record_class.to_u16().to_be_bytes());
    out.extend_from_slice(&ttl_override.to_be_bytes());
    let rdata = canonical_rdata(&record.data)?;
    if rdata.len() > u16::MAX as usize {
        return Err(DnssecError::Malformed("RDATA too large".to_string()));
    }

    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    Ok(out)
}

struct RrsigFields<'a> {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: &'a str,
    signature: &'a [u8],
}

fn rrsig_fields(record: &DnsRecord) -> Result<RrsigFields<'_>, DnssecError> {
    match &record.data {
        RecordData::RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } => Ok(RrsigFields {
            type_covered: *type_covered,
            algorithm: *algorithm,
            labels: *labels,
            original_ttl: *original_ttl,
            signature_expiration: *signature_expiration,
            signature_inception: *signature_inception,
            key_tag: *key_tag,
            signer_name,
            signature,
        }),
        _ => Err(DnssecError::WrongRecordType),
    }
}

fn parse_rsa_public_key(raw: &[u8]) -> Result<rsa::RsaPublicKeyComponents, DnssecError> {
    if raw.is_empty() {
        return Err(DnssecError::Malformed("empty RSA public key".to_string()));
    }

    let (exp_len, offset) = if raw[0] == 0 {
        if raw.len() < 3 {
            return Err(DnssecError::Malformed("truncated RSA exponent length".to_string()));
        }

        (u16::from_be_bytes([raw[1], raw[2]]) as usize, 3)
    } else {
        (raw[0] as usize, 1)
    };

    if offset + exp_len > raw.len() {
        return Err(DnssecError::Malformed("truncated RSA exponent".to_string()));
    }

    let e = raw[offset..offset + exp_len].to_vec();
    let n = raw[offset + exp_len..].to_vec();
    if n.is_empty() {
        return Err(DnssecError::Malformed("empty RSA modulus".to_string()));
    }

    Ok(rsa::RsaPublicKeyComponents { n, e })
}

fn rsa_verify_digest(raw_public_key: &[u8], digest_info: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool, DnssecError> {
    use crate::crypto::bignum::BigNum;

    let components = parse_rsa_public_key(raw_public_key)?;
    let modulus_len = components.n.len();
    if signature.is_empty() || signature.len() > modulus_len {
        return Ok(false);
    }

    let n = BigNum::from_bytes_be(&components.n);
    let e = BigNum::from_bytes_be(&components.e);
    let s = BigNum::from_bytes_be(signature);
    let m = s.mod_exp_montgomery(&e, &n).map_err(|err| DnssecError::Malformed(err.to_string()))?;

    let mut m_bytes = m.to_bytes_be();
    if m_bytes.len() > modulus_len {
        return Ok(false);
    }

    if m_bytes.len() < modulus_len {
        let mut padded = vec![0u8; modulus_len - m_bytes.len()];
        padded.extend_from_slice(&m_bytes);
        m_bytes = padded;
    }

    let encoded_len = digest_info.len() + digest.len();
    if encoded_len + 11 > modulus_len {
        return Ok(false);
    }

    let padding_len = modulus_len - encoded_len - 3;
    let mut expected = Vec::with_capacity(modulus_len);
    expected.push(0x00);
    expected.push(0x01);
    expected.extend(std::iter::repeat(0xFFu8).take(padding_len));
    expected.push(0x00);
    expected.extend_from_slice(digest_info);
    expected.extend_from_slice(digest);

    Ok(constant_time_eq(&m_bytes, &expected))
}

fn verify_signature(algorithm: u8, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, DnssecError> {
    match algorithm {
        5 | 7 => rsa_verify_digest(public_key, &rsa::DIGEST_INFO_SHA1, &sha1(message), signature),
        8 => rsa_verify_digest(public_key, &rsa::DIGEST_INFO_SHA256, &sha256(message), signature),
        10 => rsa_verify_digest(public_key, &rsa::DIGEST_INFO_SHA512, &sha512(message), signature),
        13 => {
            if public_key.len() != 64 {
                return Err(DnssecError::Malformed("ECDSA P-256 public key must be 64 bytes".to_string()));
            }

            let mut prefixed = Vec::with_capacity(65);
            prefixed.push(0x04);
            prefixed.extend_from_slice(public_key);
            ecdsa::verify(ecdsa::SignatureCurve::P256, &prefixed, message, signature)
                .map_err(|e| DnssecError::Malformed(e.to_string()))
        }
        15 => ecdsa::verify(ecdsa::SignatureCurve::Ed25519, public_key, message, signature)
            .map_err(|e| DnssecError::Malformed(e.to_string())),
        other => Err(DnssecError::UnsupportedAlgorithm(other)),
    }
}

pub fn verify_rrsig(records: &[DnsRecord], rrsig: &DnsRecord, dnskey: &DnsRecord) -> Result<(), DnssecError> {
    if records.is_empty() {
        return Err(DnssecError::Malformed("no records to verify".to_string()));
    }

    let sig = rrsig_fields(rrsig)?;
    let (_flags, _protocol, dnskey_algorithm, dnskey_public_key) = dnskey_fields(dnskey)?;

    if sig.algorithm != dnskey_algorithm {
        return Err(DnssecError::AlgorithmMismatch);
    }

    let computed_tag = compute_key_tag(dnskey)?;
    if computed_tag != sig.key_tag {
        return Err(DnssecError::KeyTagMismatch);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
    if now > sig.signature_expiration {
        return Err(DnssecError::SignatureExpired);
    }

    if now < sig.signature_inception {
        return Err(DnssecError::SignatureNotYetValid);
    }

    let owner = records[0].name.trim_end_matches('.').to_ascii_lowercase();
    for record in records {
        if record.record_type.to_u16() != sig.type_covered {
            return Err(DnssecError::Malformed("record does not match RRSIG type-covered".to_string()));
        }

        if record.name.trim_end_matches('.').to_ascii_lowercase() != owner {
            return Err(DnssecError::Malformed("RRset contains mixed owner names".to_string()));
        }
    }

    let owner_label_count = owner.split('.').filter(|l| !l.is_empty()).count() as u8;
    if sig.labels > owner_label_count {
        return Err(DnssecError::Malformed(format!(
            "RRSIG labels field ({}) exceeds owner name's actual label count ({})",
            sig.labels, owner_label_count
        )));
    }

    let mut sorted: Vec<&DnsRecord> = records.iter().collect();
    let mut sort_err = None;
    sorted.sort_by(|a, b| match (canonical_rdata(&a.data), canonical_rdata(&b.data)) {
        (Ok(ra), Ok(rb)) => ra.cmp(&rb),
        (Err(e), _) | (_, Err(e)) => {
            sort_err = Some(e);
            std::cmp::Ordering::Equal
        }
    });

    if let Some(e) = sort_err {
        return Err(e);
    }

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&sig.type_covered.to_be_bytes());
    signed_data.push(sig.algorithm);
    signed_data.push(sig.labels);
    signed_data.extend_from_slice(&sig.original_ttl.to_be_bytes());
    signed_data.extend_from_slice(&sig.signature_expiration.to_be_bytes());
    signed_data.extend_from_slice(&sig.signature_inception.to_be_bytes());
    signed_data.extend_from_slice(&sig.key_tag.to_be_bytes());
    write_canonical_name(&mut signed_data, sig.signer_name);

    for record in &sorted {
        signed_data.extend_from_slice(&canonical_rr_bytes(record, sig.original_ttl)?);
    }

    let ok = verify_signature(dnskey_algorithm, dnskey_public_key, &signed_data, sig.signature)?;
    if ok {
        Ok(())
    } else {
        Err(DnssecError::BadSignature)
    }
}

pub fn verify_ds(dnskey: &DnsRecord, ds: &DnsRecord) -> Result<bool, DnssecError> {
    let (ds_key_tag, ds_algorithm, digest_type, ds_digest) = match &ds.data {
        RecordData::DS { key_tag, algorithm, digest_type, digest } => (*key_tag, *algorithm, *digest_type, digest.as_slice()),
        _ => return Err(DnssecError::WrongRecordType),
    };

    let (flags, protocol, algorithm, public_key) = dnskey_fields(dnskey)?;
    if algorithm != ds_algorithm {
        return Ok(false);
    }

    let computed_tag = compute_key_tag(dnskey)?;
    if computed_tag != ds_key_tag {
        return Ok(false);
    }

    let mut material = Vec::new();
    write_canonical_name(&mut material, &dnskey.name);
    material.extend_from_slice(&dnskey_rdata_bytes(flags, protocol, algorithm, public_key));

    let computed_digest: Vec<u8> = match digest_type {
        1 => sha1(&material).to_vec(),
        2 => sha256(&material).to_vec(),
        4 => sha384(&material).to_vec(),
        other => return Err(DnssecError::UnsupportedDigestType(other)),
    };

    Ok(constant_time_eq(&computed_digest, ds_digest))
}

pub fn validate_rrset<'a>(records: &[DnsRecord], rrsigs: &[DnsRecord], dnskeys: &'a [DnsRecord]) -> Result<&'a DnsRecord, DnssecError> {
    let mut last_err = DnssecError::Malformed("no RRSIG/DNSKEY pair available".to_string());
    for rrsig in rrsigs {
        let sig = match rrsig_fields(rrsig) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                continue;
            }
        };

        for dnskey in dnskeys {
            let dnskey_algorithm = match dnskey_fields(dnskey) {
                Ok((_, _, algorithm, _)) => algorithm,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };

            if dnskey_algorithm != sig.algorithm {
                continue;
            }

            match verify_rrsig(records, rrsig, dnskey) {
                Ok(()) => return Ok(dnskey),
                Err(e) => last_err = e,
            }
        }
    }

    Err(last_err)
}

pub fn compare_canonical_names(a: &str, b: &str) -> std::cmp::Ordering {
    let a_labels: Vec<String> = a.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).map(|l| l.to_ascii_lowercase()).collect();
    let b_labels: Vec<String> = b.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).map(|l| l.to_ascii_lowercase()).collect();

    let mut ai = a_labels.len();
    let mut bi = b_labels.len();
    loop {
        match (ai, bi) {
            (0, 0) => return std::cmp::Ordering::Equal,
            (0, _) => return std::cmp::Ordering::Less,
            (_, 0) => return std::cmp::Ordering::Greater,
            _ => {
                ai -= 1;
                bi -= 1;
                let cmp = a_labels[ai].as_bytes().cmp(b_labels[bi].as_bytes());
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
        }
    }
}

fn nsec_covers(owner: &str, next: &str, name: &str) -> bool {
    let owner_before_name = compare_canonical_names(owner, name) == std::cmp::Ordering::Less;
    let name_before_next = compare_canonical_names(name, next) == std::cmp::Ordering::Less;
    if compare_canonical_names(owner, next) == std::cmp::Ordering::Less {
        owner_before_name && name_before_next
    } else {
        owner_before_name || name_before_next
    }
}

fn nsec_has_type(type_bit_maps: &[u8], record_type: u16) -> bool {
    let target_window = (record_type >> 8) as u8;
    let target_byte = ((record_type & 0xFF) / 8) as usize;
    let target_bit = 7 - ((record_type & 0xFF) % 8) as u8;

    let mut offset = 0;
    while offset + 2 <= type_bit_maps.len() {
        let window = type_bit_maps[offset];
        let bitmap_len = type_bit_maps[offset + 1] as usize;
        offset += 2;
        if offset + bitmap_len > type_bit_maps.len() {
            break;
        }

        if window == target_window && target_byte < bitmap_len && (type_bit_maps[offset + target_byte] >> target_bit) & 1 == 1 {
            return true;
        }

        offset += bitmap_len;
    }

    false
}

pub fn verify_nsec_nodata(name: &str, record_type: RecordType, nsec: &DnsRecord) -> Result<(), DnssecError> {
    if !nsec.name.trim_end_matches('.').eq_ignore_ascii_case(name.trim_end_matches('.')) {
        return Err(DnssecError::Malformed(
            "NSEC owner name does not match the queried name for a NODATA proof".to_string(),
        ));
    }

    let type_bit_maps = match &nsec.data {
        RecordData::NSEC { type_bit_maps, .. } => type_bit_maps,
        _ => return Err(DnssecError::WrongRecordType),
    };

    if nsec_has_type(type_bit_maps, record_type.to_u16()) {
        return Err(DnssecError::Malformed(format!(
            "NSEC record indicates {:?} exists at {} -- not a valid NODATA proof",
            record_type, name
        )));
    }

    Ok(())
}

pub fn verify_nsec_name_error(name: &str, nsec_records: &[DnsRecord]) -> Result<(), DnssecError> {
    let covered = nsec_records.iter().any(|record| match &record.data {
        RecordData::NSEC { next_domain_name, .. } => nsec_covers(&record.name, next_domain_name, name),
        _ => false,
    });

    if !covered {
        return Err(DnssecError::Malformed(format!("no NSEC record covers {} -- not a valid name-error proof", name)));
    }

    let closest_encloser = find_closest_encloser(name, nsec_records)
        .ok_or_else(|| DnssecError::Malformed("no closest encloser found among NSEC records".to_string()))?;

    let wildcard = format!("*.{}", closest_encloser);
    let wildcard_covered = nsec_records.iter().any(|record| match &record.data {
        RecordData::NSEC { next_domain_name, .. } => nsec_covers(&record.name, next_domain_name, &wildcard),
        _ => false,
    });

    if wildcard_covered {
        Ok(())
    } else {
        Err(DnssecError::Malformed(format!("no NSEC covers the wildcard {} -- incomplete name-error proof", wildcard)))
    }
}

fn find_closest_encloser(name: &str, nsec_records: &[DnsRecord]) -> Option<String> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    for i in 0..labels.len() {
        let candidate = labels[i..].join(".");
        if nsec_records.iter().any(|r| r.name.trim_end_matches('.').eq_ignore_ascii_case(&candidate)) {
            return Some(candidate);
        }
    }

    None
}

pub fn rrsig_indicates_wildcard(rrsig: &DnsRecord, owner_name: &str) -> Result<bool, DnssecError> {
    let sig = rrsig_fields(rrsig)?;
    let owner_label_count = owner_name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).count() as u8;
    Ok(sig.labels < owner_label_count)
}

pub fn nsec_covers_name(name: &str, nsec_records: &[DnsRecord]) -> bool {
    nsec_records.iter().any(|record| match &record.data {
        RecordData::NSEC { next_domain_name, .. } => nsec_covers(&record.name, next_domain_name, name),
        _ => false,
    })
}

fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = (bits >> bit_count) & 0x1F;
            out.push(BASE32HEX_ALPHABET[idx as usize] as char);
        }
    }

    if bit_count > 0 {
        let idx = (bits << (5 - bit_count)) & 0x1F;
        out.push(BASE32HEX_ALPHABET[idx as usize] as char);
    }

    out
}

fn base32hex_decode(s: &str) -> Result<Vec<u8>, DnssecError> {
    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for c in s.chars() {
        let upper = c.to_ascii_uppercase();
        let val = BASE32HEX_ALPHABET
            .iter()
            .position(|&b| b == upper as u8)
            .ok_or_else(|| DnssecError::Malformed(format!("invalid base32hex character '{}'", c)))? as u32;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }

    Ok(out)
}

fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut wire_name = Vec::new();
    write_canonical_name(&mut wire_name, name);

    let mut material = wire_name;
    material.extend_from_slice(salt);
    let mut current = sha1(&material).to_vec();

    for _ in 0..iterations {
        let mut material = current;
        material.extend_from_slice(salt);
        current = sha1(&material).to_vec();
    }

    current
}

fn nsec3_fields(record: &DnsRecord) -> Result<(u8, u8, u16, &[u8], &[u8], &[u8]), DnssecError> {
    match &record.data {
        RecordData::NSEC3 { hash_algorithm, flags, iterations, salt, next_hashed_owner_name, type_bit_maps } => {
            Ok((*hash_algorithm, *flags, *iterations, salt.as_slice(), next_hashed_owner_name.as_slice(), type_bit_maps.as_slice()))
        }
        _ => Err(DnssecError::WrongRecordType),
    }
}

fn nsec3_owner_hash(record: &DnsRecord) -> Result<Vec<u8>, DnssecError> {
    let first_label = record.name.split('.').next().unwrap_or("");
    base32hex_decode(first_label)
}

fn nsec3_covers(owner: &[u8], next: &[u8], target: &[u8]) -> bool {
    let owner_before_target = owner < target;
    let target_before_next = target < next;
    if owner < next {
        owner_before_target && target_before_next
    } else {
        owner_before_target || target_before_next
    }
}

fn nsec3_params(nsec3_records: &[DnsRecord]) -> Option<(u8, u16, &[u8])> {
    nsec3_records.iter().find_map(|r| nsec3_fields(r).ok().map(|(alg, _, iterations, salt, _, _)| (alg, iterations, salt)))
}

pub fn verify_nsec3_nodata(name: &str, record_type: RecordType, nsec3: &DnsRecord) -> Result<(), DnssecError> {
    let (hash_algorithm, _flags, iterations, salt, _next, type_bit_maps) = nsec3_fields(nsec3)?;
    if hash_algorithm != 1 {
        return Err(DnssecError::UnsupportedAlgorithm(hash_algorithm));
    }

    let owner_hash = nsec3_owner_hash(nsec3)?;
    let target_hash = nsec3_hash(name, salt, iterations);
    if owner_hash != target_hash {
        return Err(DnssecError::Malformed(
            "NSEC3 owner hash does not match the queried name for a NODATA proof".to_string(),
        ));
    }

    if nsec_has_type(type_bit_maps, record_type.to_u16()) {
        return Err(DnssecError::Malformed(format!(
            "NSEC3 record indicates {:?} exists at {} -- not a valid NODATA proof",
            record_type, name
        )));
    }

    Ok(())
}

pub fn nsec3_covers_name(name: &str, nsec3_records: &[DnsRecord]) -> bool {
    let Some((hash_algorithm, iterations, salt)) = nsec3_params(nsec3_records) else {
        return false;
    };

    if hash_algorithm != 1 {
        return false;
    }

    let target_hash = nsec3_hash(name, salt, iterations);
    nsec3_records.iter().any(|r| match nsec3_fields(r) {
        Ok((_, _, _, _, next, _)) => nsec3_owner_hash(r).map(|owner| nsec3_covers(&owner, next, &target_hash)).unwrap_or(false),
        Err(_) => false,
    })
}

pub fn verify_nsec3_name_error(name: &str, nsec3_records: &[DnsRecord]) -> Result<(), DnssecError> {
    let (hash_algorithm, iterations, salt) =
        nsec3_params(nsec3_records).ok_or_else(|| DnssecError::Malformed("no NSEC3 records provided".to_string()))?;
    if hash_algorithm != 1 {
        return Err(DnssecError::UnsupportedAlgorithm(hash_algorithm));
    }

    let labels: Vec<&str> = name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    let mut closest_encloser: Option<(String, usize)> = None;
    for i in 0..labels.len() {
        let candidate = labels[i..].join(".");
        let candidate_hash = nsec3_hash(&candidate, salt, iterations);
        let matches = nsec3_records.iter().any(|r| nsec3_owner_hash(r).map(|h| h == candidate_hash).unwrap_or(false));
        if matches {
            closest_encloser = Some((candidate, i));
            break;
        }
    }

    let (closest_encloser, ce_index) =
        closest_encloser.ok_or_else(|| DnssecError::Malformed("no closest encloser found among NSEC3 records".to_string()))?;

    if ce_index == 0 {
        return Err(DnssecError::Malformed(format!(
            "NSEC3 records indicate {} exists -- not a valid name-error proof",
            name
        )));
    }

    let next_closer = labels[ce_index - 1..].join(".");
    if !nsec3_covers_name(&next_closer, nsec3_records) {
        return Err(DnssecError::Malformed(format!(
            "no NSEC3 covers the next-closer name for {} -- incomplete name-error proof",
            name
        )));
    }

    let wildcard = format!("*.{}", closest_encloser);
    if nsec3_covers_name(&wildcard, nsec3_records) {
        Ok(())
    } else {
        Err(DnssecError::Malformed(format!("no NSEC3 covers the wildcard {} -- incomplete name-error proof", wildcard)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::asymmetric::rsa::{RsaKeySize, RsaPadding, RsaPrivateKey};
    use crate::net::dns::record::{RecordClass, RecordType};
    use std::net::Ipv4Addr;

    fn a_record(name: &str, ttl: u32, ip: Ipv4Addr) -> DnsRecord {
        DnsRecord::a(name.to_string(), ttl, ip)
    }

    fn dnskey_record(name: &str, algorithm: u8, public_key: Vec<u8>) -> DnsRecord {
        DnsRecord::new(
            name.to_string(),
            RecordType::DNSKEY,
            RecordClass::IN,
            3600,
            RecordData::DNSKEY { flags: 257, protocol: 3, algorithm, public_key },
        )
    }

    fn rrsig_for(records: &[DnsRecord], algorithm: u8, key_tag: u16, signer_name: &str, signature: Vec<u8>) -> DnsRecord {
        let type_covered = records[0].record_type.to_u16();
        DnsRecord::new(
            records[0].name.clone(),
            RecordType::RRSIG,
            RecordClass::IN,
            records[0].ttl,
            RecordData::RRSIG {
                type_covered,
                algorithm,
                labels: signer_name.split('.').filter(|l| !l.is_empty()).count() as u8,
                original_ttl: records[0].ttl,
                signature_expiration: u32::MAX,
                signature_inception: 0,
                key_tag,
                signer_name: signer_name.to_string(),
                signature,
            },
        )
    }

    fn build_signed_data(records: &[DnsRecord], rrsig: &DnsRecord) -> Vec<u8> {
        let sig = rrsig_fields(rrsig).unwrap();
        let mut sorted: Vec<&DnsRecord> = records.iter().collect();
        sorted.sort_by(|a, b| canonical_rdata(&a.data).unwrap().cmp(&canonical_rdata(&b.data).unwrap()));

        let mut out = Vec::new();
        out.extend_from_slice(&sig.type_covered.to_be_bytes());
        out.push(sig.algorithm);
        out.push(match &rrsig.data {
            RecordData::RRSIG { labels, .. } => *labels,
            _ => unreachable!(),
        });
        out.extend_from_slice(&sig.original_ttl.to_be_bytes());
        out.extend_from_slice(&sig.signature_expiration.to_be_bytes());
        out.extend_from_slice(&sig.signature_inception.to_be_bytes());
        out.extend_from_slice(&sig.key_tag.to_be_bytes());
        write_canonical_name(&mut out, sig.signer_name);
        for record in &sorted {
            out.extend_from_slice(&canonical_rr_bytes(record, sig.original_ttl).unwrap());
        }

        out
    }

    #[test]
    fn test_rsa_sha256_rrsig_roundtrip() {
        let private_key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public_components = private_key.to_components();
        let dnskey_pubkey = {
            let mut out = Vec::new();
            assert!(public_components.e.len() <= 255);
            out.push(public_components.e.len() as u8);
            out.extend_from_slice(&public_components.e);
            out.extend_from_slice(&public_components.n);
            out
        };

        let dnskey = dnskey_record("example.com", 8, dnskey_pubkey);
        let key_tag = compute_key_tag(&dnskey).unwrap();

        let records = vec![a_record("example.com", 300, Ipv4Addr::new(93, 184, 216, 34))];
        let unsigned_rrsig = rrsig_for(&records, 8, key_tag, "example.com", Vec::new());
        let signed_data = build_signed_data(&records, &unsigned_rrsig);
        let signature = private_key.sign(&signed_data, RsaPadding::Pkcs1v15).unwrap();
        let rrsig = rrsig_for(&records, 8, key_tag, "example.com", signature);

        assert!(verify_rrsig(&records, &rrsig, &dnskey).is_ok());

        let tampered = vec![a_record("example.com", 300, Ipv4Addr::new(1, 2, 3, 4))];
        assert!(verify_rrsig(&tampered, &rrsig, &dnskey).is_err());

        let mut bad_labels_rrsig = rrsig.clone();
        if let RecordData::RRSIG { labels, .. } = &mut bad_labels_rrsig.data {
            *labels = 10;
        }

        assert_eq!(
            verify_rrsig(&records, &bad_labels_rrsig, &dnskey),
            Err(DnssecError::Malformed(
                "RRSIG labels field (10) exceeds owner name's actual label count (2)".to_string()
            ))
        );
    }

    #[test]
    fn test_rsa_verify_digest_rejects_malformed_signature_lengths() {
        let private_key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let components = private_key.to_components();
        let mut raw_public_key = Vec::new();
        raw_public_key.push(components.e.len() as u8);
        raw_public_key.extend_from_slice(&components.e);
        raw_public_key.extend_from_slice(&components.n);

        let digest = sha256(b"hello");
        assert_eq!(rsa_verify_digest(&raw_public_key, &rsa::DIGEST_INFO_SHA256, &digest, &[]), Ok(false));

        let too_long_signature = vec![0u8; components.n.len() + 1];
        assert_eq!(rsa_verify_digest(&raw_public_key, &rsa::DIGEST_INFO_SHA256, &digest, &too_long_signature), Ok(false));

        let mut tiny_public_key = Vec::new();
        tiny_public_key.push(1u8);
        tiny_public_key.push(3u8);
        tiny_public_key.extend_from_slice(&[0xFFu8; 16]);
        let tiny_signature = vec![0u8; 16];
        assert_eq!(rsa_verify_digest(&tiny_public_key, &rsa::DIGEST_INFO_SHA256, &digest, &tiny_signature), Ok(false));
    }

    #[test]
    fn test_ecdsa_p256_rrsig_roundtrip() {
        let (signing_key, verifying_key) = ecdsa::generate_keypair(ecdsa::SignatureCurve::P256).unwrap();
        let raw_pubkey = verifying_key.to_bytes();
        let dnskey_pubkey = raw_pubkey[1..].to_vec();

        let dnskey = dnskey_record("example.org", 13, dnskey_pubkey);
        let key_tag = compute_key_tag(&dnskey).unwrap();

        let records = vec![a_record("example.org", 300, Ipv4Addr::new(93, 184, 216, 34))];
        let unsigned_rrsig = rrsig_for(&records, 13, key_tag, "example.org", Vec::new());
        let signed_data = build_signed_data(&records, &unsigned_rrsig);
        let signature = signing_key.sign(&signed_data).unwrap().to_bytes();
        let rrsig = rrsig_for(&records, 13, key_tag, "example.org", signature);

        assert!(verify_rrsig(&records, &rrsig, &dnskey).is_ok());
    }

    #[test]
    fn test_ed25519_rrsig_roundtrip() {
        let (signing_key, verifying_key) = ecdsa::generate_keypair(ecdsa::SignatureCurve::Ed25519).unwrap();
        let dnskey_pubkey = verifying_key.to_bytes();

        let dnskey = dnskey_record("example.net", 15, dnskey_pubkey);
        let key_tag = compute_key_tag(&dnskey).unwrap();

        let records = vec![a_record("example.net", 300, Ipv4Addr::new(93, 184, 216, 34))];
        let unsigned_rrsig = rrsig_for(&records, 15, key_tag, "example.net", Vec::new());
        let signed_data = build_signed_data(&records, &unsigned_rrsig);
        let signature = signing_key.sign(&signed_data).unwrap().to_bytes();
        let rrsig = rrsig_for(&records, 15, key_tag, "example.net", signature);

        assert!(verify_rrsig(&records, &rrsig, &dnskey).is_ok());
    }

    #[test]
    fn test_verify_ds_matches_dnskey() {
        let private_key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public_components = private_key.to_components();
        let mut dnskey_pubkey = Vec::new();
        dnskey_pubkey.push(public_components.e.len() as u8);
        dnskey_pubkey.extend_from_slice(&public_components.e);
        dnskey_pubkey.extend_from_slice(&public_components.n);

        let dnskey = dnskey_record("example.com", 8, dnskey_pubkey.clone());
        let key_tag = compute_key_tag(&dnskey).unwrap();

        let rdata = dnskey_rdata_bytes(257, 3, 8, &dnskey_pubkey);
        let mut material = Vec::new();
        write_canonical_name(&mut material, "example.com");
        material.extend_from_slice(&rdata);
        let digest = sha256(&material).to_vec();

        let ds = DnsRecord::new(
            "example.com".to_string(),
            RecordType::DS,
            RecordClass::IN,
            3600,
            RecordData::DS { key_tag, algorithm: 8, digest_type: 2, digest },
        );

        assert!(verify_ds(&dnskey, &ds).unwrap());

        let mut bad_ds = ds.clone();
        if let RecordData::DS { digest, .. } = &mut bad_ds.data {
            digest[0] ^= 0xFF;
        }

        assert!(!verify_ds(&dnskey, &bad_ds).unwrap());
    }

    fn nsec_record(owner: &str, next_domain_name: &str, types: &[u16]) -> DnsRecord {
        DnsRecord::new(
            owner.to_string(),
            RecordType::NSEC,
            RecordClass::IN,
            3600,
            RecordData::NSEC { next_domain_name: next_domain_name.to_string(), type_bit_maps: build_type_bitmap(types) },
        )
    }

    fn build_type_bitmap(types: &[u16]) -> Vec<u8> {
        use std::collections::BTreeMap;
        let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
        for &t in types {
            let window = (t >> 8) as u8;
            let byte_idx = ((t & 0xFF) / 8) as usize;
            let bit = 7 - ((t & 0xFF) % 8) as u8;
            let entry = windows.entry(window).or_insert([0u8; 32]);
            entry[byte_idx] |= 1 << bit;
        }

        let mut out = Vec::new();
        for (window, bitmap) in windows {
            let mut len = 32;
            while len > 0 && bitmap[len - 1] == 0 {
                len -= 1;
            }

            if len == 0 {
                continue;
            }

            out.push(window);
            out.push(len as u8);
            out.extend_from_slice(&bitmap[..len]);
        }

        out
    }

    #[test]
    fn test_compare_canonical_names_ordering() {
        assert_eq!(compare_canonical_names("example.com", "www.example.com"), std::cmp::Ordering::Less);
        assert_eq!(compare_canonical_names("a.example.com", "b.example.com"), std::cmp::Ordering::Less);
        assert_eq!(compare_canonical_names("b.example.com", "c.example.com"), std::cmp::Ordering::Less);
        assert_eq!(compare_canonical_names("EXAMPLE.com", "example.com"), std::cmp::Ordering::Equal);
        assert_eq!(compare_canonical_names("example.com", "example.com"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_nsec_covers_normal_and_wraparound_ranges() {
        assert!(nsec_covers("a.example.com", "c.example.com", "b.example.com"));
        assert!(!nsec_covers("a.example.com", "c.example.com", "example.com"));
        assert!(!nsec_covers("a.example.com", "c.example.com", "z.example.com"));

        assert!(nsec_covers("y.example.com", "a.example.com", "z.example.com"));
        assert!(nsec_covers("y.example.com", "a.example.com", "0.example.com"));
        assert!(!nsec_covers("y.example.com", "a.example.com", "m.example.com"));
    }

    #[test]
    fn test_nsec_has_type_bitmap() {
        let bitmap = build_type_bitmap(&[1, 28, 46]);
        assert!(nsec_has_type(&bitmap, 1));
        assert!(nsec_has_type(&bitmap, 28));
        assert!(nsec_has_type(&bitmap, 46));
        assert!(!nsec_has_type(&bitmap, 15));
        assert!(!nsec_has_type(&bitmap, 47));
    }

    #[test]
    fn test_verify_nsec_nodata() {
        let nsec_without_aaaa = nsec_record("www.example.com", "zzz.example.com", &[1, 46]);
        assert!(verify_nsec_nodata("www.example.com", RecordType::AAAA, &nsec_without_aaaa).is_ok());
        assert!(verify_nsec_nodata("www.example.com", RecordType::A, &nsec_without_aaaa).is_err());

        let wrong_owner = nsec_record("other.example.com", "zzz.example.com", &[1]);
        assert!(verify_nsec_nodata("www.example.com", RecordType::AAAA, &wrong_owner).is_err());
    }

    #[test]
    fn test_verify_nsec_name_error() {
        let nsec_records = vec![
            nsec_record("example.com", "a.example.com", &[1, 46]),
            nsec_record("a.example.com", "z.example.com", &[1, 46]),
            nsec_record("z.example.com", "example.com", &[1, 46]),
        ];

        assert!(verify_nsec_name_error("b.example.com", &nsec_records).is_ok());

        assert!(verify_nsec_name_error("sub.other.org", &nsec_records).is_err());
    }

    #[test]
    fn test_base32hex_roundtrip() {
        for data in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"abcde", b"the quick brown fox"] {
            let encoded = base32hex_encode(data);
            let decoded = base32hex_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for {:?}", data);
        }
    }

    #[test]
    fn test_nsec3_covers_normal_and_wraparound_ranges() {
        assert!(nsec3_covers(&[0x10], &[0x30], &[0x20]));
        assert!(!nsec3_covers(&[0x10], &[0x30], &[0x05]));
        assert!(!nsec3_covers(&[0x10], &[0x30], &[0x40]));

        assert!(nsec3_covers(&[0x30], &[0x10], &[0x40]));
        assert!(nsec3_covers(&[0x30], &[0x10], &[0x05]));
        assert!(!nsec3_covers(&[0x30], &[0x10], &[0x20]));
    }

    fn nsec3_record(owner_hash: &[u8], next_hash: &[u8], salt: &[u8], iterations: u16, types: &[u16]) -> DnsRecord {
        let owner_label = base32hex_encode(owner_hash).to_ascii_lowercase();
        DnsRecord::new(
            format!("{}.example.com", owner_label),
            RecordType::NSEC3,
            RecordClass::IN,
            3600,
            RecordData::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations,
                salt: salt.to_vec(),
                next_hashed_owner_name: next_hash.to_vec(),
                type_bit_maps: build_type_bitmap(types),
            },
        )
    }

    #[test]
    fn test_verify_nsec3_nodata() {
        let salt = b"abcd";
        let name = "www.example.com";
        let hash = nsec3_hash(name, salt, 3);
        let next = nsec3_hash("zzz.example.com", salt, 3);

        let nsec3 = nsec3_record(&hash, &next, salt, 3, &[1, 46]);
        assert!(verify_nsec3_nodata(name, RecordType::AAAA, &nsec3).is_ok());
        assert!(verify_nsec3_nodata(name, RecordType::A, &nsec3).is_err());

        let wrong_hash_nsec3 = nsec3_record(&nsec3_hash("other.example.com", salt, 3), &next, salt, 3, &[1]);
        assert!(verify_nsec3_nodata(name, RecordType::AAAA, &wrong_hash_nsec3).is_err());
    }

    #[test]
    fn test_verify_nsec3_name_error() {
        let salt = b"abcd";
        let iterations = 3u16;

        let h_apex = nsec3_hash("example.com", salt, iterations);
        let h_a = nsec3_hash("a.example.com", salt, iterations);
        let h_z = nsec3_hash("z.example.com", salt, iterations);

        let nsec3_records = vec![
            nsec3_record(&h_apex, &h_a, salt, iterations, &[1, 46]),
            nsec3_record(&h_a, &h_z, salt, iterations, &[1, 46]),
            nsec3_record(&h_z, &h_apex, salt, iterations, &[1, 46]),
        ];

        let b_hash = nsec3_hash("b.example.com", salt, iterations);
        let wildcard_hash = nsec3_hash("*.example.com", salt, iterations);
        let b_covered = nsec3_covers(&h_a, &h_z, &b_hash) || nsec3_covers(&h_z, &h_apex, &b_hash) || nsec3_covers(&h_apex, &h_a, &b_hash);
        let wildcard_covered = nsec3_covers(&h_a, &h_z, &wildcard_hash) || nsec3_covers(&h_z, &h_apex, &wildcard_hash) || nsec3_covers(&h_apex, &h_a, &wildcard_hash);
        assert!(b_covered, "test setup invariant: b.example.com's hash must fall in some range of this 3-record chain");
        assert!(wildcard_covered, "test setup invariant: *.example.com's hash must fall in some range of this 3-record chain");

        assert!(verify_nsec3_name_error("b.example.com", &nsec3_records).is_ok());
        assert!(verify_nsec3_name_error("sub.other.org", &nsec3_records).is_err());
    }
}
