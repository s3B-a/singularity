use crate::crypto::encoding::x509::Certificate;
use crate::crypto::encoding::x509_crl::CertificateList;
use crate::net::http::client::HttpClient;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_CRL_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const CRL_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationPolicy {
    SoftFail,
    HardFail,
}

impl Default for RevocationPolicy {
    fn default() -> Self {
        RevocationPolicy::SoftFail
    }
}

#[derive(Debug)]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown(String),
}

#[derive(Debug, Clone)]
struct CachedCrl {
    list: CertificateList,
}

#[derive(Debug, Clone, Default)]
pub struct CrlCache {
    entries: Arc<Mutex<HashMap<String, CachedCrl>>>,
}

impl CrlCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &str, now: i64) -> Option<CertificateList> {
        self.entries.lock().ok().and_then(|entries| {
            entries.get(key).filter(|c| c.list.is_valid_at(now)).map(|c| c.list.clone())
        })
    }

    fn insert(&self, key: String, list: CertificateList) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(key, CachedCrl { list });
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }

    s
}

pub fn check_revocation(cert: &Certificate, issuer: &Certificate, cache: &CrlCache) -> RevocationStatus {
    let urls = match cert.get_crl_distribution_points() {
        Ok(urls) if !urls.is_empty() => urls,
        Ok(_) => return RevocationStatus::Unknown("certificate has no CRL distribution points".to_string()),
        Err(e) => return RevocationStatus::Unknown(format!("failed to read CRL distribution points: {:?}", e)),
    };

    let serial = match cert.serial_number() {
        Ok(s) => s,
        Err(e) => return RevocationStatus::Unknown(format!("failed to read certificate serial number: {:?}", e)),
    };

    let now = unix_now();
    let issuer_key = hex_encode(&issuer.subject_raw());
    let mut last_error = "no usable CRL distribution point".to_string();
    for url in urls {
        let cache_key = format!("{}|{}", issuer_key, url);
        let list = match cache.get(&cache_key, now) {
            Some(cached) => cached,
            None => match fetch_and_verify_crl(&url, issuer, now) {
                Ok(list) => {
                    cache.insert(cache_key, list.clone());
                    list
                }

                Err(e) => {
                    last_error = e;
                    continue;
                }
            },
        };

        return if list.contains_serial(&serial) {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Good
        };
    }

    RevocationStatus::Unknown(last_error)
}

fn fetch_and_verify_crl(url: &str, issuer: &Certificate, now: i64) -> Result<CertificateList, String> {
    let mut client = HttpClient::new();
    client.set_timeout(CRL_FETCH_TIMEOUT);
    let response = client.get(url).map_err(|e| format!("CRL fetch failed: {}", e))?;
    if response.status_code() != 200 {
        return Err(format!("CRL fetch returned HTTP {}", response.status_code()));
    }

    if response.body().len() > MAX_CRL_RESPONSE_BYTES {
        return Err(format!(
            "CRL response too large ({} bytes, cap is {})",
            response.body().len(),
            MAX_CRL_RESPONSE_BYTES
        ));
    }

    let list = CertificateList::from_der(response.body()).map_err(|e| format!("failed to parse CRL: {:?}", e))?;
    list.verify_signature(issuer).map_err(|e| format!("CRL signature verification failed: {:?}", e))?;
    if !list.is_valid_at(now) {
        return Err("CRL is expired or not yet valid".to_string());
    }

    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::asymmetric::rsa;
    use crate::crypto::encoding::asn1::{DerEncoder, Tag};

    fn der_seq(content: &[u8]) -> Vec<u8> {
        let mut enc = DerEncoder::new();
        enc.write_tag(Tag::Sequence as u8, true);
        enc.write_length(content.len());
        enc.raw(content);
        enc.finish()
    }

    fn empty_name() -> Vec<u8> {
        der_seq(&[0x31, 0x00])
    }

    fn build_cert(key: &rsa::RsaPrivateKey, serial: u8) -> Certificate {
        let mut body = vec![
            0xA0, 0x03, 0x02, 0x01, 0x02,
            0x02, 0x01, serial,
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
        ];
        body.extend_from_slice(&empty_name());
        body.extend_from_slice(&der_seq(&[0x17, 0x01, 0x30, 0x17, 0x01, 0x30]));
        body.extend_from_slice(&empty_name());
        body.extend_from_slice(&der_seq(&[
            0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x01, 0x00,
        ]));

        let tbs = der_seq(&body);
        let signature = key.sign(&tbs, rsa::RsaPadding::Pkcs1v15).unwrap();

        Certificate {
            tbs,
            signature_algorithm: vec![1, 2, 840, 113549, 1, 1, 11],
            signature,
            subject: crate::crypto::encoding::x509::Name { common_name: None },
            issuer: crate::crypto::encoding::x509::Name { common_name: None },
            subject_public_key_info: crate::crypto::encoding::x509::SubjectPublicKeyInfo {
                algorithm: vec![1, 2, 840, 113549, 1, 1, 1],
                param: None,
                public_key: key.public_key().to_der(),
            },
        }
    }

    fn build_crl(issuer_key: &rsa::RsaPrivateKey, this_update: &str, next_update: &str, revoked: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut alg = DerEncoder::new();
        let _ = alg.object_identifier(&[1, 2, 840, 113549, 1, 1, 11]);
        alg.null();
        body.extend_from_slice(&der_seq(&alg.finish()));
        body.extend_from_slice(&empty_name());

        let mut utc = DerEncoder::new();
        utc.utc_time(this_update);
        body.extend_from_slice(&utc.finish());
        let mut utc2 = DerEncoder::new();
        utc2.utc_time(next_update);
        body.extend_from_slice(&utc2.finish());
        if !revoked.is_empty() {
            let mut entries = Vec::new();
            for serial in revoked {
                let mut entry = Vec::new();
                let mut enc = DerEncoder::new();
                enc.integer(&[*serial]);
                entry.extend_from_slice(&enc.finish());
                let mut date = DerEncoder::new();
                date.utc_time(this_update);
                entry.extend_from_slice(&date.finish());
                entries.extend_from_slice(&der_seq(&entry));
            }
            body.extend_from_slice(&der_seq(&entries));
        }

        let tbs = der_seq(&body);
        let signature = issuer_key.sign(&tbs, rsa::RsaPadding::Pkcs1v15).unwrap();

        let mut full = tbs.clone();
        let mut sig_alg = DerEncoder::new();
        let _ = sig_alg.object_identifier(&[1, 2, 840, 113549, 1, 1, 11]);
        sig_alg.null();
        full.extend_from_slice(&der_seq(&sig_alg.finish()));
        let mut sig_enc = DerEncoder::new();
        sig_enc.bit_string(&signature, 0);
        full.extend_from_slice(&sig_enc.finish());

        der_seq(&full)
    }

    #[test]
    fn test_crl_cache_round_trip_and_expiry_filter() {
        let issuer_key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let der = build_crl(&issuer_key, "240101000000Z", "240201000000Z", &[0x07]);
        let list = CertificateList::from_der(&der).unwrap();

        let cache = CrlCache::new();
        cache.insert("issuer|http://example/ca.crl".to_string(), list.clone());
        
        assert!(cache.get("issuer|http://example/ca.crl", list.this_update + 10).is_some());
        assert!(cache.get("issuer|http://example/ca.crl", list.next_update.unwrap() + 10).is_none());
    }

    #[test]
    fn test_check_revocation_unknown_when_no_distribution_points() {
        let key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();
        let cert = build_cert(&key, 1);
        let cache = CrlCache::new();

        match check_revocation(&cert, &cert, &cache) {
            RevocationStatus::Unknown(_) => {}
            other => panic!("expected Unknown, got {:?}", other),
        }
    }
}
