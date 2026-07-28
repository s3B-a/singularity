use crate::crypto::asymmetric::{ecc_generic, ecdsa};
use crate::crypto::encoding::asn1::{decode_oid_content, DerDecoder, DerEncoder, Tag};
use crate::crypto::encoding::pem;
use crate::crypto::encoding::x509::{Certificate, SubjectPublicKeyInfo};
use crate::crypto::hash::sha2::sha256;
use std::collections::HashMap;

const BUNDLED_CT_LOGS: &str = include_str!("data/ct_logs.txt");

const RSA_ENCRYPTION_OID: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
const EC_PUBLIC_KEY_OID: [u64; 6] = [1, 2, 840, 10045, 2, 1];

#[derive(Debug, Clone)]
struct CtLog {
    operator: String,
    description: String,
    public_key_der: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct CtLogBundle {
    logs_by_id: HashMap<[u8; 32], CtLog>,
}

impl CtLogBundle {
    pub fn bundled() -> Self {
        let mut logs_by_id = HashMap::new();
        for line in BUNDLED_CT_LOGS.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.splitn(3, '|');
            let operator = parts.next();
            let description = parts.next();
            let key_b64 = parts.next();
            let (operator, description, key_b64) = match (operator, description, key_b64) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => continue,
            };

            let public_key_der = match pem::decode(key_b64) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            let log_id = sha256(&public_key_der);
            logs_by_id.insert(
                log_id,
                CtLog {
                    operator: operator.to_string(),
                    description: description.to_string(),
                    public_key_der,
                },
            );
        }

        Self { logs_by_id }
    }

    pub fn is_empty(&self) -> bool {
        self.logs_by_id.is_empty()
    }

    pub fn len(&self) -> usize {
        self.logs_by_id.len()
    }

    fn find(&self, log_id: &[u8]) -> Option<&CtLog> {
        if log_id.len() != 32 {
            return None;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(log_id);
        self.logs_by_id.get(&key)
    }
}

struct Sct {
    version: u8,
    log_id: [u8; 32],
    timestamp: u64,
    extensions: Vec<u8>,
    signature: Vec<u8>,
}

fn parse_sct_list(raw: &[u8]) -> Vec<Sct> {
    let mut scts = Vec::new();
    if raw.len() < 2 {
        return scts;
    }

    let total_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    let end = (2 + total_len).min(raw.len());
    let mut pos = 2;
    while pos + 2 <= end {
        let sct_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
        pos += 2;
        if pos + sct_len > end {
            break;
        }

        if let Some(sct) = parse_single_sct(&raw[pos..pos + sct_len]) {
            scts.push(sct);
        }

        pos += sct_len;
    }

    scts
}

fn parse_single_sct(data: &[u8]) -> Option<Sct> {
    if data.len() < 1 + 32 + 8 + 2 {
        return None;
    }

    let version = data[0];
    let mut log_id = [0u8; 32];
    log_id.copy_from_slice(&data[1..33]);
    let timestamp = u64::from_be_bytes(data[33..41].try_into().ok()?);

    let mut pos = 41;
    let ext_len = u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
    pos += 2;
    if pos + ext_len > data.len() {
        return None;
    }

    let extensions = data[pos..pos + ext_len].to_vec();
    pos += ext_len;
    if pos + 2 > data.len() {
        return None;
    }

    pos += 2;
    let sig_len = u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
    pos += 2;
    if pos + sig_len > data.len() {
        return None;
    }

    let signature = data[pos..pos + sig_len].to_vec();
    Some(Sct { version, log_id, timestamp, extensions, signature })
}

fn precert_signed_data(sct: &Sct, issuer_key_hash: &[u8; 32], precert_tbs: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(sct.version);
    out.push(0);
    out.extend_from_slice(&sct.timestamp.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(issuer_key_hash);

    let len = precert_tbs.len() as u32;
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(precert_tbs);

    out.extend_from_slice(&(sct.extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    out
}

fn encode_spki_der(spki: &SubjectPublicKeyInfo) -> Result<Vec<u8>, String> {
    let mut alg = DerEncoder::new();
    alg.object_identifier(&spki.algorithm).map_err(|e| format!("{:?}", e))?;
    if spki.algorithm == RSA_ENCRYPTION_OID {
        alg.null();
    } else if spki.algorithm == EC_PUBLIC_KEY_OID {
        let curve_oid = spki.param.as_ref()
            .ok_or_else(|| "EC public key missing curve parameters".to_string())
            .and_then(|bytes| decode_oid_content(bytes).map_err(|e| format!("{:?}", e)))?;
        
        alg.object_identifier(&curve_oid).map_err(|e| format!("{:?}", e))?;
    } else {
        alg.null();
    }

    let alg_bytes = alg.finish();
    let mut alg_seq = DerEncoder::new();
    alg_seq.write_tag(Tag::Sequence as u8, true);
    alg_seq.write_length(alg_bytes.len());
    alg_seq.raw(&alg_bytes);

    let mut body = alg_seq.finish();
    let mut bit_string = DerEncoder::new();
    bit_string.bit_string(&spki.public_key, 0);
    body.extend_from_slice(&bit_string.finish());

    let mut wrapped = DerEncoder::new();
    wrapped.write_tag(Tag::Sequence as u8, true);
    wrapped.write_length(body.len());
    wrapped.raw(&body);
    Ok(wrapped.finish())
}

fn extract_spki_point(spki_der: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = DerDecoder::new(spki_der);
    decoder
        .sequence(|spki| {
            let _ = spki.sequence(|_| Ok(()))?;
            let (point, _) = spki.bit_string()?;
            Ok(point)
        })
        .ok()
}

pub fn verify_embedded_scts(leaf: &Certificate, issuer: &Certificate, bundle: &CtLogBundle) -> Result<(), String> {
    if bundle.is_empty() {
        return Err("no CT log bundle loaded".to_string());
    }

    let raw_list = leaf.get_sct_list().map_err(|e| format!("failed to read SCT list extension: {:?}", e))?;
    if raw_list.is_empty() {
        return Err("certificate has no embedded SCTs".to_string());
    }

    let scts = parse_sct_list(&raw_list);
    if scts.is_empty() {
        return Err("SCT list extension present but no SCT entries could be parsed".to_string());
    }

    let precert_tbs = leaf.tbs_for_precert().map_err(|e| format!("failed to reconstruct precertificate TBS: {:?}", e))?;
    let issuer_spki_der = encode_spki_der(&issuer.subject_public_key_info)?;
    let issuer_key_hash = sha256(&issuer_spki_der);
    for sct in &scts {
        let log = match bundle.find(&sct.log_id) {
            Some(log) => log,
            None => continue,
        };

        let point = match extract_spki_point(&log.public_key_der) {
            Some(p) => p,
            None => continue,
        };

        let fixed_sig = match ecc_generic::der_signature_to_fixed(&sct.signature, 32) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let to_sign = precert_signed_data(sct, &issuer_key_hash, &precert_tbs);
        if ecdsa::verify(ecdsa::SignatureCurve::P256, &point, &to_sign, &fixed_sig).unwrap_or(false) {
            return Ok(());
        }
    }

    Err("no embedded SCT verified against a known CT log".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::asymmetric::rsa;
    use crate::crypto::encoding::x509::Name;

    fn der_seq(content: &[u8]) -> Vec<u8> {
        let mut enc = DerEncoder::new();
        enc.write_tag(Tag::Sequence as u8, true);
        enc.write_length(content.len());
        enc.raw(content);
        enc.finish()
    }

    fn fixed_sig_to_der(sig: &[u8]) -> Vec<u8> {
        let (r, s) = sig.split_at(sig.len() / 2);
        let mut enc = DerEncoder::new();
        enc.integer(r);
        enc.integer(s);
        der_seq(&enc.finish())
    }

    fn build_cert_with_extensions(key: &rsa::RsaPrivateKey, serial: u8, extensions: &[Vec<u8>]) -> Certificate {
        let mut body = vec![
            0xA0, 0x03, 0x02, 0x01, 0x02,
            0x02, 0x01, serial,
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
        ];
        body.extend_from_slice(&der_seq(&[0x31, 0x00]));
        body.extend_from_slice(&der_seq(&[0x17, 0x01, 0x30, 0x17, 0x01, 0x30]));
        body.extend_from_slice(&der_seq(&[0x31, 0x00]));

        let mut spki_alg = DerEncoder::new();
        let _ = spki_alg.object_identifier(&RSA_ENCRYPTION_OID);
        spki_alg.null();
        let mut spki = DerEncoder::new();
        spki.raw(&der_seq(&spki_alg.finish()));
        spki.bit_string(&key.public_key().to_der(), 0);
        body.extend_from_slice(&der_seq(&spki.finish()));
        if !extensions.is_empty() {
            let mut exts_concat = Vec::new();
            for e in extensions {
                exts_concat.extend_from_slice(e);
            }
            let exts_seq = der_seq(&exts_concat);
            let mut ctx3 = DerEncoder::new();
            ctx3.write_tag(0x80 | 3, true);
            ctx3.write_length(exts_seq.len());
            ctx3.raw(&exts_seq);
            body.extend_from_slice(&ctx3.finish());
        }

        let tbs = der_seq(&body);
        let signature = key.sign(&tbs, rsa::RsaPadding::Pkcs1v15).unwrap();

        Certificate {
            tbs,
            signature_algorithm: vec![1, 2, 840, 113549, 1, 1, 11],
            signature,
            subject: Name { common_name: None },
            issuer: Name { common_name: None },
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: RSA_ENCRYPTION_OID.to_vec(),
                param: None,
                public_key: key.public_key().to_der(),
            },
        }
    }

    fn der_extension(oid: &[u64], extn_value: &[u8]) -> Vec<u8> {
        let mut enc = DerEncoder::new();
        enc.object_identifier(oid).unwrap();
        enc.octet_string(extn_value);
        der_seq(&enc.finish())
    }

    #[test]
    fn test_bundled_ct_logs_load_and_parse() {
        let bundle = CtLogBundle::bundled();
        assert!(bundle.len() > 20, "expected a sizable bundle of real CT logs, got {}", bundle.len());
    }

    #[test]
    fn test_verify_embedded_scts_accepts_valid_signature_and_rejects_tampering() {
        let (log_signing_key, log_verifying_key) = ecdsa::generate_keypair(ecdsa::SignatureCurve::P256).unwrap();
        let log_point = log_verifying_key.to_bytes();

        let mut log_spki_alg = DerEncoder::new();
        let _ = log_spki_alg.object_identifier(&EC_PUBLIC_KEY_OID);
        let _ = log_spki_alg.object_identifier(&[1, 2, 840, 10045, 3, 1, 7]); // prime256v1
        let mut log_spki = DerEncoder::new();
        log_spki.raw(&der_seq(&log_spki_alg.finish()));
        log_spki.bit_string(&log_point, 0);
        let log_spki_der = der_seq(&log_spki.finish());

        let mut bundle = CtLogBundle::default();
        let log_id = sha256(&log_spki_der);
        bundle.logs_by_id.insert(log_id, CtLog {
            operator: "Test".to_string(),
            description: "Test Log".to_string(),
            public_key_der: log_spki_der,
        });

        let issuer_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let issuer_cert = build_cert_with_extensions(&issuer_key, 1, &[]);
        let issuer_spki_der = encode_spki_der(&issuer_cert.subject_public_key_info).unwrap();
        let issuer_key_hash = sha256(&issuer_spki_der);

        let leaf_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        fn build_sct_extension(log_id: &[u8; 32], timestamp: u64, der_sig: &[u8]) -> Vec<u8> {
            let mut sct_bytes = Vec::new();
            sct_bytes.push(0);
            sct_bytes.extend_from_slice(log_id);
            sct_bytes.extend_from_slice(&timestamp.to_be_bytes());
            sct_bytes.extend_from_slice(&0u16.to_be_bytes());
            sct_bytes.push(4);
            sct_bytes.push(3);
            sct_bytes.extend_from_slice(&(der_sig.len() as u16).to_be_bytes());
            sct_bytes.extend_from_slice(der_sig);

            let mut sct_list = Vec::new();
            sct_list.extend_from_slice(&(sct_bytes.len() as u16).to_be_bytes());
            sct_list.extend_from_slice(&sct_bytes);

            let mut list_len_prefixed = Vec::new();
            list_len_prefixed.extend_from_slice(&(sct_list.len() as u16).to_be_bytes());
            list_len_prefixed.extend_from_slice(&sct_list);

            let mut inner_octet = DerEncoder::new();
            inner_octet.octet_string(&list_len_prefixed);
            der_extension(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2], &inner_octet.finish())
        }

        let timestamp = 1_700_000_000_000u64;
        let placeholder_ext = build_sct_extension(&log_id, timestamp, &[]);
        let leaf_draft = build_cert_with_extensions(&leaf_key, 1, &[placeholder_ext]);
        let precert_tbs = leaf_draft.tbs_for_precert().unwrap();

        let sct = Sct { version: 0, log_id, timestamp, extensions: Vec::new(), signature: Vec::new() };
        let to_sign = precert_signed_data(&sct, &issuer_key_hash, &precert_tbs);
        let raw_sig = ecdsa::sign(ecdsa::SignatureCurve::P256, &log_signing_key.to_bytes(), &to_sign).unwrap();
        let der_sig = fixed_sig_to_der(&raw_sig);

        let sct_ext = build_sct_extension(&log_id, timestamp, &der_sig);
        let leaf = build_cert_with_extensions(&leaf_key, 1, &[sct_ext.clone()]);

        assert!(verify_embedded_scts(&leaf, &issuer_cert, &bundle).is_ok());
        let tampered_leaf = build_cert_with_extensions(&leaf_key, 2, &[sct_ext]);
        assert!(verify_embedded_scts(&tampered_leaf, &issuer_cert, &bundle).is_err());
    }
}