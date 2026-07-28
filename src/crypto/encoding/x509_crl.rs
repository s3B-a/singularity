// crypto/encoding/x509_crl.rs - Certificate Revocation List (CRL) parsing and verification
// https://tools.ietf.org/html/rfc5280#section-5

use crate::crypto::encoding::asn1::{DerDecoder, Tag};
use crate::crypto::encoding::x509::{parse_time, verify_tbs_signature, Certificate};
use crate::crypto::{Error, Result};

// A CRL is a list of revoked certificate serial numbers issued by a CA
// This struct represents a parsed X.509 CertificateList (CRL)
#[derive(Clone, Debug)]
pub struct CertificateList {
    pub tbs: Vec<u8>,
    pub signature_algorithm: Vec<u64>,
    pub signature: Vec<u8>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    revoked_serials: Vec<Vec<u8>>,
}

impl CertificateList {

    /**
     * Parses a DER-encoded CRL into a CertificateList struct
     * Args:
     *    der: &[u8] - The DER-encoded bytes of the CRL
     * 
     * Returns:
     *    Result<CertificateList> - The parsed CRL or an error if parsing fails
     */
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let mut decoder = DerDecoder::new(der);
        decoder.sequence(|cert_list| {
            let tbs_start = cert_list.pos;
            let (this_update, next_update, revoked_serials) = cert_list.sequence(|tbs| {
                if tbs.has_more() && tbs.peek_tag()? == Tag::Integer as u8 {
                    let _version = tbs.integer()?;
                }

                let _signature_alg = tbs.sequence(|alg| alg.object_identifier())?;
                let _issuer = tbs.sequence(|_| Ok(()))?;
                let this_update = parse_time(tbs)?;
                let next_update = if tbs.has_more() {
                    let tag = tbs.peek_tag()?;
                    if tag == Tag::UtcTime as u8 || tag == Tag::GeneralizedTime as u8 {
                        Some(parse_time(tbs)?)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut revoked_serials = Vec::new();
                if tbs.has_more() {
                    let tag = tbs.peek_tag()?;
                    if tag == (Tag::Sequence as u8 | 0x20) {
                        tbs.sequence(|revoked| {
                            while revoked.has_more() {
                                revoked.sequence(|entry| {
                                    let serial = entry.integer()?;
                                    let _revocation_date = parse_time(entry)?;
                                    while entry.has_more() {
                                        let _ = entry.read_element()?;
                                    }

                                    revoked_serials.push(serial);

                                    Ok(())
                                })?;
                            }

                            Ok(())
                        })?;
                    }
                }

                while tbs.has_more() {
                    let _ = tbs.read_element()?;
                }

                Ok((this_update, next_update, revoked_serials))
            })?;

            let tbs_end = cert_list.pos;
            let tbs_bytes = cert_list.data[tbs_start..tbs_end].to_vec();

            let signature_algorithm = cert_list.sequence(|alg| alg.object_identifier())?;
            let (signature, _) = cert_list.bit_string()?;

            Ok(CertificateList {
                tbs: tbs_bytes,
                signature_algorithm,
                signature,
                this_update,
                next_update,
                revoked_serials,
            })
        })
    }

    /**
     * Returns the raw DER bytes of the issuer's Name field from the CRL's TBSCertList
     * Args:
     *    &self - The CertificateList instance
     * 
     * Returns:
     *    Vec<u8> - The raw DER bytes of the issuer's Name
     */
    pub fn issuer_raw(&self) -> Vec<u8> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            if tbs.has_more() && tbs.peek_tag()? == Tag::Integer as u8 {
                let _ = tbs.integer()?;
            }

            let _ = tbs.sequence(|_| Ok(()))?;
            let start = tbs.pos;
            tbs.sequence(|_| Ok(()))?;
            let end = tbs.pos;

            Ok(tbs.data[start..end].to_vec())
        }).unwrap_or_default()
    }

    /**
     * Checks if the CRL is valid at a given timestamp
     * Args:
     *    &self - The CertificateList instance
     *    now: i64 - The current timestamp (seconds since epoch)
     * 
     * Returns:
     *    bool - True if the CRL is valid at the given time, false otherwise
     */
    pub fn is_valid_at(&self, now: i64) -> bool {
        now >= self.this_update && self.next_update.map(|next| now < next).unwrap_or(true)
    }

    /**
     * Checks if a given serial number is listed as revoked in the CRL
     * Args:
     *    &self - The CertificateList instance
     *    serial: &[u8] - The serial number to check
     * 
     * Returns:
     *    bool - True if the serial number is revoked, false otherwise
     */
    pub fn contains_serial(&self, serial: &[u8]) -> bool {
        let trimmed = trim_leading_zeros(serial);
        self.revoked_serials.iter().any(|s| trim_leading_zeros(s) == trimmed)
    }

    /**
     * Verifies the CRL's signature against the issuer's public key
     * Args:
     *    &self - The CertificateList instance
     *    issuer: &Certificate - The issuer's certificate containing the public key
     * 
     * Returns:
     *    Result<()> - Ok if the signature is valid, Err otherwise
     */
    pub fn verify_signature(&self, issuer: &Certificate) -> Result<()> {
        if self.issuer_raw() != issuer.subject_raw() {
            return Err(Error::InvalidData(
                "CRL issuer does not match the given certificate's subject".to_string(),
            ));
        }

        verify_tbs_signature(&self.tbs, &self.signature_algorithm, &self.signature, &issuer.subject_public_key_info)
    }
}

/**
 * Trims leading zero bytes from a byte slice
 * Args:
 *    bytes: &[u8] - The byte slice to trim
 * 
 * Returns:
 *    &[u8] - A subslice without leading zeros
 */
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::asymmetric::rsa;
    use crate::crypto::encoding::asn1::DerEncoder;

    fn der_seq(content: &[u8]) -> Vec<u8> {
        let mut enc = DerEncoder::new();
        enc.write_tag(Tag::Sequence as u8, true);
        enc.write_length(content.len());
        enc.raw(content);
        enc.finish()
    }

    fn utc_time(s: &str) -> Vec<u8> {
        let mut enc = DerEncoder::new();
        enc.utc_time(s);
        enc.finish()
    }

    fn build_crl_tbs(issuer_name_der: &[u8], this_update: &str, next_update: Option<&str>, revoked: &[(u8, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut alg = DerEncoder::new();
        let _ = alg.object_identifier(&[1, 2, 840, 113549, 1, 1, 11]);
        alg.null();
        body.extend_from_slice(&der_seq(&alg.finish()));
        body.extend_from_slice(&der_seq(issuer_name_der));
        body.extend_from_slice(&utc_time(this_update));
        if let Some(next) = next_update {
            body.extend_from_slice(&utc_time(next));
        }

        if !revoked.is_empty() {
            let mut entries = Vec::new();
            for (serial, date) in revoked {
                let mut entry = Vec::new();
                let mut enc = DerEncoder::new();
                enc.integer(&[*serial]);
                entry.extend_from_slice(&enc.finish());
                entry.extend_from_slice(&utc_time(date));
                entries.extend_from_slice(&der_seq(&entry));
            }
            body.extend_from_slice(&der_seq(&entries));
        }

        der_seq(&body)
    }

    fn build_crl_der(tbs: &[u8], signature_algorithm: &[u64], signature: &[u8]) -> Vec<u8> {
        let mut body = tbs.to_vec();
        let mut alg = DerEncoder::new();
        let _ = alg.object_identifier(signature_algorithm);
        alg.null();
        body.extend_from_slice(&der_seq(&alg.finish()));

        let mut sig_enc = DerEncoder::new();
        sig_enc.bit_string(signature, 0);
        body.extend_from_slice(&sig_enc.finish());

        der_seq(&body)
    }

    fn empty_issuer() -> Vec<u8> {
        vec![0x31, 0x00]
    }

    fn minimal_cert_tbs_with_subject(subject_name_der: &[u8]) -> Vec<u8> {
        let mut body = vec![
            0xA0, 0x03, 0x02, 0x01, 0x02,
            0x02, 0x01, 0x01,
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
        ];
        body.extend_from_slice(&der_seq(&empty_issuer()));
        body.extend_from_slice(&der_seq(&[0x17, 0x01, 0x30, 0x17, 0x01, 0x30]));
        body.extend_from_slice(&der_seq(subject_name_der));
        body.extend_from_slice(&der_seq(&[
            0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x01, 0x00,
        ]));

        der_seq(&body)
    }

    #[test]
    fn test_parse_crl_this_update_next_update_and_revoked_serials() {
        let issuer = empty_issuer();
        let tbs = build_crl_tbs(&issuer, "240101000000Z", Some("240201000000Z"), &[(0x05, "240102000000Z")]);
        let der = build_crl_der(&tbs, &[1, 2, 840, 113549, 1, 1, 11], &[0u8; 4]);

        let crl = CertificateList::from_der(&der).unwrap();
        assert!(crl.next_update.is_some());
        assert!(crl.this_update < crl.next_update.unwrap());
        assert!(crl.contains_serial(&[0x05]));
        assert!(!crl.contains_serial(&[0x06]));
    }

    #[test]
    fn test_parse_crl_with_no_revocations() {
        let issuer = empty_issuer();
        let tbs = build_crl_tbs(&issuer, "240101000000Z", Some("240201000000Z"), &[]);
        let der = build_crl_der(&tbs, &[1, 2, 840, 113549, 1, 1, 11], &[0u8; 4]);

        let crl = CertificateList::from_der(&der).unwrap();
        assert!(!crl.contains_serial(&[0x01]));
    }

    #[test]
    fn test_crl_is_valid_at_window() {
        let issuer = empty_issuer();
        let tbs = build_crl_tbs(&issuer, "240101000000Z", Some("240201000000Z"), &[]);
        let der = build_crl_der(&tbs, &[1, 2, 840, 113549, 1, 1, 11], &[0u8; 4]);
        let crl = CertificateList::from_der(&der).unwrap();

        assert!(crl.is_valid_at(crl.this_update + 1));
        assert!(!crl.is_valid_at(crl.this_update - 1));
        assert!(!crl.is_valid_at(crl.next_update.unwrap()));
    }

    #[test]
    fn test_crl_signature_verifies_against_issuer() {
        let key = rsa::RsaPrivateKey::generate(rsa::RsaKeySize::Rsa2048).unwrap();

        let issuer = empty_issuer();
        let tbs = build_crl_tbs(&issuer, "240101000000Z", Some("240201000000Z"), &[]);
        let signature = key.sign(&tbs, rsa::RsaPadding::Pkcs1v15).unwrap();
        let der = build_crl_der(&tbs, &[1, 2, 840, 113549, 1, 1, 11], &signature);
        let crl = CertificateList::from_der(&der).unwrap();

        let issuer_cert = Certificate {
            tbs: minimal_cert_tbs_with_subject(&empty_issuer()),
            signature_algorithm: vec![1, 2, 840, 113549, 1, 1, 11],
            signature: vec![0u8],
            subject: crate::crypto::encoding::x509::Name { common_name: None },
            issuer: crate::crypto::encoding::x509::Name { common_name: None },
            subject_public_key_info: crate::crypto::encoding::x509::SubjectPublicKeyInfo {
                algorithm: vec![1, 2, 840, 113549, 1, 1, 1],
                param: None,
                public_key: key.public_key().to_der(),
            },
        };

        assert!(crl.verify_signature(&issuer_cert).is_ok());

        let mut tampered = der.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let tampered_crl = CertificateList::from_der(&tampered).unwrap();
        assert!(tampered_crl.verify_signature(&issuer_cert).is_err());
    }
}
