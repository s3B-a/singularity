// crypto/encoding/x509.rs - X.509 Certificate parsing and encoding
// https://tools.ietf.org/html/rfc5280

use crate::crypto::Result;
use crate::crypto::encoding::asn1::DerDecoder;
use crate::crypto::encoding::pem;

// X.509 Name and Certificate structures
#[derive(Clone, Debug)]
pub struct Name {
    pub common_name: Option<String>,
}

// Subject Public Key Info structure
#[derive(Clone, Debug)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: Vec<u64>,
    pub param: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
}

// X.509 Certificate structure
#[derive(Clone, Debug)]
pub struct Certificate {
    pub tbs: Vec<u8>,
    pub signature_algorithm: Vec<u64>,
    pub signature: Vec<u8>,
    pub subject: Name,
    pub issuer: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
}

impl Certificate {

    /**
     * Parses a DER-encoded X.509 certificate using ASN.1 DerDecoder
     * Args:
     *    der - &[u8]: The DER-encoded certificate bytes
     * 
     * Returns:
     *    Result<Self>: The parsed Certificate or an error if parsing fails
     */
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let mut decoder = DerDecoder::new(der);
        decoder.sequence(|cert| {
            let tbs_bytes = {
                let start = cert.pos;
                cert.sequence(|tbs| {
                    let _version = tbs.optional_context_specific(0, |v| v.integer_u64())?;
                    let _serial = tbs.integer()?;
                    let sig_alg = tbs.sequence(|alg| alg.object_identifier())?;
                    let issuer = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
                    tbs.sequence(|validity| {
                        validity.read_element()?;
                        validity.read_element()?;
                        Ok(())
                    })?;

                    let subject = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
                    let spki = tbs.sequence(|spki_seq| parse_spki(spki_seq))?;
                    
                    Ok((sig_alg, issuer, subject, spki))
                })?;

                let end = cert.pos;
                der[start..end].to_vec()
            };

            let signature_algorithm = cert.sequence(|alg| alg.object_identifier())?;
            let (sig_bytes, _) = cert.bit_string()?;

            let mut tbs_decoder = DerDecoder::new(&tbs_bytes);
            tbs_decoder.sequence(|tbs| {
                let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
                let _ = tbs.integer()?;
                let _ = tbs.sequence(|alg| alg.object_identifier())?;
                let issuer = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
                let _ = tbs.sequence(|validity| {
                    validity.read_element()?;
                    validity.read_element()?;

                    Ok(())
                })?;

                let subject = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
                let spki = tbs.sequence(|spki| parse_spki(spki))?;

                Ok(Self {
                    tbs: tbs_bytes.clone(),
                    signature_algorithm : signature_algorithm.clone(),
                    signature: sig_bytes,
                    subject,
                    issuer,
                    subject_public_key_info: spki,
                })
            })
        })
    }

    /**
     * Parses a PEM-encoded X.509 certificate
     * Args:
     *    pem_str - &str: The PEM-encoded certificate string
     * 
     * Returns
     *    Result<Self>: The parsed Certificate or an error if parsing fails
     */
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let pem = pem::decode(pem_str)?;

        Self::from_der(&pem)
    }

    /**
     * Encodes the certificate to PEM format
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    String: The PEM-encoded certificate string
     */
    pub fn to_pem(&self) -> String {
        pem::encode(&self.tbs)
    }
}

/**
 * Parses an X.509 Name from a DerDecoder
 * Args:
 *    decoder - &mut DerDecoder: The DerDecoder positioned at the Name
 * 
 * Returns:
 *    Result<Name>: The parsed Name or an error if parsing fails
 */
fn parse_name(decoder: &mut DerDecoder) -> Result<Name> {
    let mut common_name = None;
    decoder.set(|set| {
        set.sequence(|attr| {
            let oid = attr.object_identifier()?;
            let value = attr.read_element()?;
            if oid == [2, 5, 4, 3] {
                let mut val_decoder = DerDecoder::new(&value.data);
                common_name = Some(val_decoder.utf8_string().unwrap_or_default());
            }
            Ok(())
        })
    })?;
    Ok(Name { common_name })
}

/**
 * Parses a SubjectPublicKeyInfo from a DerDecoder
 * Args:
 *    decoder - &mut DerDecoder: The DerDecoder positioned at the SubjectPublicKeyInfo
 * 
 * Returns:
 *    Result<SubjectPublicKeyInfo>: The parsed SubjectPublicKeyInfo or an error if parsing fails
 */
fn parse_spki(decoder: &mut DerDecoder) -> Result<SubjectPublicKeyInfo> {
    let algorithm = decoder.sequence(|alg| alg.object_identifier())?;
    let param = decoder.optional_context_specific(0, |p| p.octet_string()).ok().flatten();
    let (public_key, _) = decoder.bit_string()?;
    Ok(SubjectPublicKeyInfo {
        algorithm,
        param,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal DER-encoded self-signed certificate (not valid, just for testing structure)
    // This is a dummy, minimal ASN.1 DER-encoded X.509 certificate for test purposes.
    // In a real test, use a real certificate or a properly generated one.
    const MINIMAL_DER: &[u8] = &[
        0x30, 0x82, 0x00, 0x22, // SEQUENCE, length 34
        0x30, 0x1F, // SEQUENCE, length 31 (tbsCertificate)
        0xA0, 0x03, 0x02, 0x01, 0x02, // [0] Version: v3
        0x02, 0x01, 0x01, // Serial Number: 1
        0x30, 0x0D, // SEQUENCE (signature algorithm)
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, // OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption)
        0x05, 0x00, // NULL
        0x30, 0x03, // SEQUENCE (issuer)
        0x31, 0x01, // SET
        0x30, 0x00, // SEQUENCE (empty)
        0x30, 0x03, // SEQUENCE (validity)
        0x17, 0x01, 0x30, // UTCTime
        0x17, 0x01, 0x30, // UTCTime
        0x30, 0x03, // SEQUENCE (subject)
        0x31, 0x01, // SET
        0x30, 0x00, // SEQUENCE (empty)
        0x30, 0x0A, // SEQUENCE (subjectPublicKeyInfo)
        0x30, 0x08, // SEQUENCE (algorithm)
        0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, // OID 1.2.840.113549.1.1.1 (rsaEncryption)
        0x03, 0x00, // BIT STRING (empty)
        0x30, 0x0D, // SEQUENCE (signatureAlgorithm)
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, // OID 1.2.840.113549.1.1.5
        0x05, 0x00, // NULL
        0x03, 0x01, 0x00, // BIT STRING (signature)
    ];

    #[test]
    fn test_parse_self_signed_cert() {
        let cert = Certificate::from_der(MINIMAL_DER);
        assert!(cert.is_ok());
    }

    #[test]
    fn test_parse_invalid_der() {
        let cert = Certificate::from_der(&[]);
        assert!(cert.is_err());
    }

    #[test]
    fn test_parse_pem() {
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            pem::encode(MINIMAL_DER)
        );
        let cert = Certificate::from_pem(&pem);
        assert!(cert.is_ok());
    }

    #[test]
    fn test_to_pem_roundtrip() {
        let cert = Certificate::from_der(MINIMAL_DER).unwrap();
        let pem = cert.to_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_parse_name_empty() {
        let mut decoder = DerDecoder::new(&[0x31, 0x00]); // SET, length 0
        let name = super::parse_name(&mut decoder);
        assert!(name.is_ok());
        assert!(name.unwrap().common_name.is_none());
    }
}