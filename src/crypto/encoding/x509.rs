// crypto/encoding/x509.rs - X.509 Certificate parsing and encoding
// https://tools.ietf.org/html/rfc5280

use crate::crypto::Result;
use crate::crypto::encoding::asn1::{DerDecoder, DerEncoder, Tag};
use crate::crypto::encoding::pem;

const KEY_USAGE_KEY_CERT_SIGN: u16 = 0x0400;

mod ext_oid {
    pub const SUBJECT_ALT_NAME: [u64; 4] = [2, 5, 29, 17];
    pub const BASIC_CONSTRAINTS: [u64; 4] = [2, 5, 29, 19];
    pub const KEY_USAGE: [u64; 4] = [2, 5, 29, 15];
    pub const SUBJECT_KEY_IDENTIFIER: [u64; 4] = [2, 5, 29, 14];
    pub const AUTHORITY_KEY_IDENTIFIER: [u64; 4] = [2, 5, 29, 35];
    pub const EXTENDED_KEY_USAGE: [u64; 4] = [2, 5, 29, 37];
    pub const EKU_SERVER_AUTH: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 3, 1];
    pub const EKU_ANY: [u64; 5] = [2, 5, 29, 37, 0];
}

/**
 * Reads an Extension's `extnID` and skips its OPTIONAL `critical` BOOLEAN (DEFAULT FALSE)
 * without touching the following `extnValue` OCTET STRING
 * Args:
 *    ext - &mut DerDecoder: The decoder positioned at the start of an Extension SEQUENCE
 *
 * Returns:
 *    Result<Vec<u64>>: The extension's OID
 */
fn read_extension_header(ext: &mut DerDecoder) -> Result<Vec<u64>> {
    let oid = ext.object_identifier()?;
    if ext.has_more() && ext.peek_tag().map(|t| t == Tag::Boolean as u8).unwrap_or(false) {
        let _critical = ext.boolean()?;
    }

    Ok(oid)
}

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
                cert.data[start..end].to_vec()
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
     * Encodes the certificate to DER format
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Vec<u8>: The DER-encoded certificate bytes
     */
    pub fn to_der(&self) -> Vec<u8> {
        let mut sig_alg = DerEncoder::new();
        sig_alg.sequence(|alg| {
            let _ = alg.object_identifier(&self.signature_algorithm);
            alg.null();
        });

        let mut cert = DerEncoder::new();
        cert.sequence(|c| {
            c.raw(&self.tbs);
            c.raw(&sig_alg.finish());
            c.bit_string(&self.signature, 0);
        });

        cert.finish()
    }

    /**
     * Returns the public key bytes from the certificate
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Option<Vec<u8>>: The public key bytes if available
     */
    pub fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.subject_public_key_info.public_key.clone())
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
        let body: String = pem_str.lines().filter(|line| !line.starts_with("-----")).collect::<Vec<_>>().join("");
        let der = pem::decode(&body)?;
        
        Self::from_der(&der)
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
        let der = self.to_der();
        
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", pem::encode(&der))
    }

    /**
     * Checks if the certificate is valid at the current time
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    bool: True if the certificate is currently valid
     */
    pub fn is_valid_at_current_time(&self) -> bool {
        let mut decoder = DerDecoder::new(&self.tbs);
        match decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?;
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
            
            tbs.sequence(|validity| {
                let not_before = parse_time(validity)?;                
                let not_after = parse_time(validity)?;
                let now = match std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs() as i64,
                    Err(_) => {
                        return Ok(false);
                    }
                };
                
                if not_before >= not_after {
                    return Ok(false);
                }
                
                Ok(now >= not_before && now <= not_after)
            })
        }) {
            Ok(is_valid) => is_valid,
            Err(_) => {
                false
            }
        }
    }

    /**
     * Checks if the certificate's subject matches the given hostname
     * Args:
     *    &self: The Certificate instance
     *    hostname: &str - The hostname to match
     * 
     * Returns:
     *    bool: True if the hostname matches
     */
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        if let Some(ref cn) = self.subject.common_name {
            if hostname_matches(cn, hostname) {
                return true;
            }
        }

        if let Ok(sans) = self.get_subject_alt_names() {
            for san in sans {
                if hostname_matches(&san, hostname) {
                    return true;
                }
            }
        }

        false
    }

    /**
     * Verifies the certificate signature using a CA certificate
     * Args:
     *    &self: The Certificate instance
     *    ca_cert: &Certificate - The CA certificate to verify against
     * 
     * Returns:
     *    Result<()>: Ok if verification succeeds, Err otherwise
     */
    pub fn verify_signature(&self, ca_cert: &Certificate) -> Result<()> {
        use crate::crypto::Error;
        use crate::crypto::asymmetric::{ecc_generic, ecdsa, rsa};
        use crate::crypto::encoding::asn1::oid;
        use crate::crypto::hash::sha2::{sha1, sha256, sha384, sha512};

        let alg = ca_cert.subject_public_key_info.algorithm.as_slice();
        let is_valid = if alg == oid::RSA_ENCRYPTION {
            let ca_public_key_bytes = ca_cert.public_key().ok_or_else(|| Error::InvalidData("CA has no public key".to_string()))?;

            let ca_public_key = rsa::RsaPublicKey::from_bytes(&ca_public_key_bytes)
                .map_err(|_| Error::InvalidData("Invalid CA public key".to_string()))?;

            let sig_alg = self.signature_algorithm.as_slice();
            let (digest_info, digest): (&[u8], Vec<u8>) = if sig_alg == oid::SHA256_WITH_RSA_ENCRYPTION {
                (&rsa::DIGEST_INFO_SHA256, sha256(&self.tbs).to_vec())
            } else if sig_alg == oid::SHA384_WITH_RSA_ENCRYPTION {
                (&rsa::DIGEST_INFO_SHA384, sha384(&self.tbs).to_vec())
            } else if sig_alg == oid::SHA512_WITH_RSA_ENCRYPTION {
                (&rsa::DIGEST_INFO_SHA512, sha512(&self.tbs).to_vec())
            } else if sig_alg == oid::SHA1_WITH_RSA_ENCRYPTION {
                (&rsa::DIGEST_INFO_SHA1, sha1(&self.tbs).to_vec())
            } else {
                return Err(Error::InvalidData(
                    "Unsupported signature hash algorithm for RSA certificate".to_string(),
                ));
            };

            ca_public_key.verify_pkcs1v15_digest(digest_info, &digest, &self.signature)?
        } else if alg == oid::EC_PUBLIC_KEY {
            let curve_oid = ca_cert.subject_public_key_info.param.as_ref()
                .ok_or_else(|| Error::InvalidData("EC public key missing curve parameters".to_string()))
                .and_then(|bytes| crate::crypto::encoding::asn1::decode_oid_content(bytes))?;

            if curve_oid.as_slice() == oid::SECP256R1 {
                let fixed_sig = ecc_generic::der_signature_to_fixed(&self.signature, 32)?;
                ecdsa::verify(ecdsa::SignatureCurve::P256, &ca_cert.subject_public_key_info.public_key, &self.tbs, &fixed_sig)?
            } else {
                let curve = if curve_oid.as_slice() == oid::SECP384R1 {
                    ecc_generic::NistCurve::P384
                } else if curve_oid.as_slice() == oid::SECP521R1 {
                    ecc_generic::NistCurve::P521
                } else {
                    return Err(Error::InvalidData(
                        "Unsupported EC curve for signature verification".to_string(),
                    ));
                };

                let sig_alg = self.signature_algorithm.as_slice();
                let digest: Vec<u8> = if sig_alg == oid::ECDSA_WITH_SHA384 {
                    sha384(&self.tbs).to_vec()
                } else if sig_alg == oid::ECDSA_WITH_SHA512 {
                    sha512(&self.tbs).to_vec()
                } else if sig_alg == oid::ECDSA_WITH_SHA256 {
                    sha256(&self.tbs).to_vec()
                } else {
                    return Err(Error::InvalidData(
                        "Unsupported signature hash algorithm for EC certificate".to_string(),
                    ));
                };

                ecc_generic::verify_prehashed(curve, &ca_cert.subject_public_key_info.public_key, &digest, &self.signature)?
            }
        } else {
            return Err(Error::InvalidData(
                "Unsupported public key algorithm for signature verification".to_string(),
            ));
        };

        if is_valid {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    /**
     * Extracts Subject Alternative Names from certificate extensions
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Result<Vec<String>>: List of SANs or error
     */
    pub fn get_subject_alt_names(&self) -> Result<Vec<String>> {
        let mut decoder = DerDecoder::new(&self.tbs);
        let mut sans = Vec::new();

        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?; // version
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?; // sig alg
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?; // issuer
            let _ = tbs.sequence(|validity| {
                validity.read_element()?;
                validity.read_element()?;
                Ok(())
            })?;
            let _ = tbs.sequence(|subject_seq| parse_name(subject_seq))?; // subject
            let _ = tbs.sequence(|spki| parse_spki(spki))?; // spki
            if let Ok(_) = tbs.context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.pos < exts.data.len() {
                        if let Ok(_) = exts.sequence(|ext| {
                            let oid = read_extension_header(ext)?;
                            if oid == ext_oid::SUBJECT_ALT_NAME {
                                let san_data = ext.octet_string()?;
                                let mut san_decoder = DerDecoder::new(&san_data);
                                if let Ok(_) = san_decoder.sequence(|san_seq| {
                                    while san_seq.pos < san_seq.data.len() {
                                        if let Ok(dns_name) = san_seq.context_specific(2, |dns| {
                                            Ok(String::from_utf8_lossy(dns.data).to_string())
                                        }) {
                                            sans.push(dns_name);
                                        }
                                    }
                                    Ok(())
                                }) {}
                            }
                            Ok(())
                        }) {
                            continue;
                        } else {
                            break;
                        }
                    }
                    Ok(())
                })
            }) {}

            Ok(())
        })?;

        Ok(sans)
    }

    /**
     * Gets the certificate's serial number
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The serial number bytes
     */
    pub fn serial_number(&self) -> Result<Vec<u8>> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?; // version
            tbs.integer()
        })
    }

    /**
     * Reads the basicConstraints extension (RFC 5280 4.2.1.9): whether this certificate is a CA, and its pathLenConstraint if present
     * Args:
     *    &self: The Certificate instance
     *
     * Returns:
     *    Result<(bool, Option<u32>)>: (is_ca, path_len_constraint)
     */
    pub fn get_basic_constraints(&self) -> Result<(bool, Option<u32>)> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?;
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
            let _ = tbs.sequence(|validity| {
                validity.read_element()?;
                validity.read_element()?;
                Ok(())
            })?;

            let _ = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
            let _ = tbs.sequence(|spki| parse_spki(spki))?;
            let result = tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.pos < exts.data.len() {
                        if let Ok(found) = exts.sequence(|ext| {
                            let oid = read_extension_header(ext)?;
                            let value = ext.octet_string()?;
                            if oid == ext_oid::BASIC_CONSTRAINTS {
                                let mut bc_decoder = DerDecoder::new(&value);
                                return bc_decoder.sequence(|bc| {
                                    let is_ca = if bc.has_more() && bc.peek_tag().map(|t| t == Tag::Boolean as u8).unwrap_or(false) {
                                        bc.boolean()?
                                    } else {
                                        false
                                    };

                                    let path_len = if bc.has_more() {
                                        Some(bc.integer_u64()? as u32)
                                    } else {
                                        None
                                    };

                                    Ok(Some((is_ca, path_len)))
                                });
                            }
                            Ok(None)
                        }) {
                            if let Some(bc) = found {
                                return Ok(bc);
                            }
                        }
                    }

                    Ok((false, None))
                })
            })?;

            Ok(result.unwrap_or((false, None)))
        })
    }

    /**
     * Checks if this is a CA certificate
     * Args:
     *    &self: The Certificate instance
     *
     * Returns:
     *    bool: True if this is a CA certificate
     */
    pub fn is_ca(&self) -> bool {
        self.get_basic_constraints().map(|(is_ca, _)| is_ca).unwrap_or(false)
    }

    /**
     * Reads the extendedKeyUsage extension as a list of KeyPurposeId OIDs
     * Args:
     *    &self: The Certificate instance
     *
     * Returns:
     *    Result<Vec<Vec<u64>>>: The list of extended key usage OIDs, empty if not present
     */
    pub fn get_extended_key_usage(&self) -> Result<Vec<Vec<u64>>> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?;
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
            let _ = tbs.sequence(|validity| {
                validity.read_element()?;
                validity.read_element()?;
                Ok(())
            })?;

            let _ = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
            let _ = tbs.sequence(|spki| parse_spki(spki))?;
            let result = tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.pos < exts.data.len() {
                        if let Ok(found) = exts.sequence(|ext| {
                            let oid = read_extension_header(ext)?;
                            let value = ext.octet_string()?;
                            if oid == ext_oid::EXTENDED_KEY_USAGE {
                                let mut eku_decoder = DerDecoder::new(&value);
                                let oids = eku_decoder.sequence(|seq| {
                                    let mut out = Vec::new();
                                    while seq.has_more() {
                                        out.push(seq.object_identifier()?);
                                    }
                                    Ok(out)
                                })?;

                                return Ok(Some(oids));
                            }
                            Ok(None)
                        }) {
                            if let Some(oids) = found {
                                return Ok(oids);
                            }
                        }
                    }

                    Ok(Vec::new())
                })
            })?;

            Ok(result.unwrap_or_default())
        })
    }

    /**
     * Checks whether this certificate's extendedKeyUsage extension (if present) permits TLS
     * server authentication
     * Args:
     *    &self: The Certificate instance
     *
     * Returns:
     *    bool: True if EKU is absent, or present and includes serverAuth/anyExtendedKeyUsage
     */
    pub fn allows_server_auth(&self) -> bool {
        match self.get_extended_key_usage() {
            Ok(ekus) if ekus.is_empty() => true,
            Ok(ekus) => ekus.iter().any(|oid| {
                oid == &ext_oid::EKU_SERVER_AUTH || oid == &ext_oid::EKU_ANY
            }),
            Err(_) => true,
        }
    }

    /**
     * Gets the raw issuer bytes from the TBS certificate for signature verification
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Vec<u8>: The raw issuer bytes from the TBS certificate
     */
    pub fn issuer_raw(&self) -> Vec<u8> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer());
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let start = tbs.pos;
            tbs.sequence(|_| Ok(()))?;
            let end = tbs.pos;
            Ok(tbs.data[start..end].to_vec())
        }).unwrap_or_default()
    }
    
    /**
     * Gets the raw subject bytes from the TBS certificate for signature verification
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Vec<u8>: The raw subject bytes from the TBS certificate
     */
    pub fn subject_raw(&self) -> Vec<u8> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer());
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let _ = tbs.sequence(|_| Ok(()))?;
            let start = tbs.pos;
            tbs.sequence(|_| Ok(()))?;
            let end = tbs.pos;
            Ok(tbs.data[start..end].to_vec())
        }).unwrap_or_default()
    }
    
    /**
     * Gets the Authority Key Identifier from the certificate extensions, if present
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The Authority Key Identifier bytes if present, or an empty vector if not present
     */
    pub fn get_authority_key_identifier(&self) -> Result<Vec<u8>> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?;
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
            let _ = tbs.sequence(|validity| {
                validity.read_element()?;
                validity.read_element()?;
                Ok(())
            })?;

            let _ = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
            let _ = tbs.sequence(|spki| parse_spki(spki))?;
            let result = tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.has_more() {
                        if let Ok(found) = exts.sequence(|ext| {
                            let oid = read_extension_header(ext)?;
                            let value = ext.octet_string()?;
                            if oid == ext_oid::AUTHORITY_KEY_IDENTIFIER {
                                let mut aki_decoder = DerDecoder::new(&value);
                                let key_id = aki_decoder.sequence(|aki_seq| {
                                    aki_seq.optional_context_specific(0, |key_id| Ok(key_id.data.to_vec()))
                                })?;

                                return Ok(Some(key_id.unwrap_or_default()));
                            }

                            Ok(None)
                        }) {
                            if let Some(key_id) = found {
                                if !key_id.is_empty() {
                                    return Ok(key_id);
                                }
                            }
                        }
                    }

                    Ok(Vec::new())
                })
            })?;

            Ok(result.unwrap_or_default())
        })
    }
    
    /**
     * Gets the Subject Key Identifier from the certificate extensions, if present
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The Subject Key Identifier bytes if present, or an empty vector if not present
     */
    pub fn get_subject_key_identifier(&self) -> Result<Vec<u8>> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?;
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
            let _ = tbs.sequence(|validity| {
                validity.read_element()?;
                validity.read_element()?;
                Ok(())
            })?;

            let _ = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
            let _ = tbs.sequence(|spki| parse_spki(spki))?;
            let result = tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.has_more() {
                        if let Ok(found) = exts.sequence(|ext| {
                            let oid = read_extension_header(ext)?;
                            let value = ext.octet_string()?;
                            if oid == ext_oid::SUBJECT_KEY_IDENTIFIER {
                                let mut val_decoder = DerDecoder::new(&value);
                                return Ok(Some(val_decoder.octet_string()?));
                            }

                            Ok(None)
                        }) {
                            if let Some(key_id) = found {
                                if !key_id.is_empty() {
                                    return Ok(key_id);
                                }
                            }
                        }
                    }

                    Ok(Vec::new())
                })
            })?;

            Ok(result.unwrap_or_default())
        })
    }
    
    /**
     * Gets the Key Usage bits from the certificate extensions, if present
     * Args:
     *    &self: The Certificate instance
     * 
     * Returns:
     *    Result<u16>: The Key Usage bits as a u16, or 0 if not present
     */
    pub fn get_key_usage(&self) -> Result<u16> {
        let mut decoder = DerDecoder::new(&self.tbs);
        decoder.sequence(|tbs| {
            let _ = tbs.optional_context_specific(0, |v| v.integer_u64())?;
            let _ = tbs.integer()?;
            let _ = tbs.sequence(|alg| alg.object_identifier())?;
            let _ = tbs.sequence(|issuer_seq| parse_name(issuer_seq))?;
            let _ = tbs.sequence(|validity| {
                validity.read_element()?;
                validity.read_element()?;
                Ok(())
            })?;

            let _ = tbs.sequence(|subject_seq| parse_name(subject_seq))?;
            let _ = tbs.sequence(|spki| parse_spki(spki))?;
            let result = tbs.optional_context_specific(3, |ext_seq| {
                ext_seq.sequence(|exts| {
                    while exts.has_more() {
                        if let Ok(found) = exts.sequence(|ext| {
                            let oid = read_extension_header(ext)?;
                            let value = ext.octet_string()?;
                            if oid == ext_oid::KEY_USAGE {
                                let mut val_decoder = DerDecoder::new(&value);
                                let (bits, _unused) = val_decoder.bit_string()?;
                                let mut usage: u16 = 0;
                                for (i, &byte) in bits.iter().take(2).enumerate() {
                                    usage |= (byte as u16) << (8 * (1 - i));
                                }

                                return Ok(Some(usage));
                            }

                            Ok(None)
                        }) {
                            if let Some(usage) = found {
                                return Ok(usage);
                            }
                        }
                    }

                    Ok(0)
                })
            })?;

            Ok(result.unwrap_or(0))
        })
    }

    /**
     * Checks whether this certificate's KeyUsage extension (if present) asserts keyCertSign
     * i.e. that the key may be used to verify signatures on other certificates
     * Args:
     *    &self: The Certificate instance
     *
     * Returns:
     *    bool: True if KeyUsage is absent, or present with the keyCertSign bit set
     */
    pub fn can_sign_certificates(&self) -> bool {
        match self.get_key_usage() {
            Ok(0) => true,
            Ok(usage) => usage & KEY_USAGE_KEY_CERT_SIGN != 0,
            Err(_) => true,
        }
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
    while decoder.has_more() {
        decoder.set(|set| {
            while set.has_more() {
                set.sequence(|attr| {
                    let oid = attr.object_identifier()?;
                    let value = attr.read_element()?;
                    if oid == [2, 5, 4, 3] {
                        common_name = Some(String::from_utf8_lossy(&value.data).to_string());
                    }

                    Ok(())
                })?;
            }

            Ok(())
        })?;
    }
    
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
    let (algorithm, param) = decoder.sequence(|alg| {
        let oid = alg.object_identifier()?;
        let param = if alg.has_more() {
            Some(alg.read_element()?.data)
        } else {
            None
        };

        Ok((oid, param))
    })?;

    let (public_key, _) = decoder.bit_string()?;
    Ok(SubjectPublicKeyInfo {
        algorithm,
        param,
        public_key,
    })
}

/**
 * Parses ASN.1 time (UTCTime or GeneralizedTime) to Unix timestamp
 * Args:
 *    decoder: &mut DerDecoder - The decoder positioned at a time value
 * 
 * Returns:
 *    Result<i64>: Unix timestamp (seconds since epoch) or error
 */
fn parse_time(decoder: &mut DerDecoder) -> Result<i64> {
    let elem = decoder.read_element()?;
    
    match elem.tag {
        0x17 => parse_utc_time(&elem.data),
        0x18 => parse_generalized_time(&elem.data),
        _ => Err(crate::crypto::Error::InvalidData(
            format!("Expected time type, got tag: 0x{:02X}", elem.tag)
        )),
    }
}

/**
 * Parses UTCTime (YYMMDDhhmmssZ or YYMMDDhhmmss+hhmm)
 * Args:
 *    data: &[u8] - The UTCTime bytes
 * 
 * Returns:
 *    Result<i64>: Unix timestamp or error
 */
fn parse_utc_time(data: &[u8]) -> Result<i64> {
    let time_str = std::str::from_utf8(data)
        .map_err(|_| crate::crypto::Error::InvalidData("Invalid UTF-8 in UTCTime".to_string()))?;
    
    // UTCTime format: YYMMDDhhmmssZ (13 chars) or YYMMDDhhmmss+hhmm (17 chars)
    if time_str.len() < 13 {
        return Err(crate::crypto::Error::InvalidData(
            "UTCTime too short".to_string()
        ));
    }
    
    let year_2digit = parse_digits(&time_str[0..2])?;
    let month = parse_digits(&time_str[2..4])?;
    let day = parse_digits(&time_str[4..6])?;
    let hour = parse_digits(&time_str[6..8])?;
    let minute = parse_digits(&time_str[8..10])?;
    let second = parse_digits(&time_str[10..12])?;
    
    // Convert 2-digit year to 4-digit year (RFC 5280 section 4.1.2.5.1)
    // If YY >= 50, then YYYY = 1900 + YY
    // If YY < 50, then YYYY = 2000 + YY
    let year = if year_2digit >= 50 {
        1900 + year_2digit
    } else {
        2000 + year_2digit
    };
    
    if month < 1 || month > 12 {
        return Err(crate::crypto::Error::InvalidData("Invalid month".to_string()));
    }

    if day < 1 || day > 31 {
        return Err(crate::crypto::Error::InvalidData("Invalid day".to_string()));
    }

    if hour > 23 {
        return Err(crate::crypto::Error::InvalidData("Invalid hour".to_string()));
    }

    if minute > 59 {
        return Err(crate::crypto::Error::InvalidData("Invalid minute".to_string()));
    }

    if second > 59 {
        return Err(crate::crypto::Error::InvalidData("Invalid second".to_string()));
    }

    let timestamp = calculate_unix_timestamp(year, month, day, hour, minute, second)?;
    if time_str.len() > 13 && !time_str.ends_with('Z') {
        let tz_offset = parse_timezone_offset(&time_str[12..])?;
        Ok(timestamp - tz_offset)
    } else {
        Ok(timestamp)
    }
}

/**
 * Parses GeneralizedTime (YYYYMMDDhhmmssZ)
 * Args:
 *    data: &[u8] - The GeneralizedTime bytes
 * 
 * Returns:
 *    Result<i64>: Unix timestamp or error
 */
fn parse_generalized_time(data: &[u8]) -> Result<i64> {
    let time_str = std::str::from_utf8(data)
        .map_err(|_| crate::crypto::Error::InvalidData("Invalid UTF-8 in GeneralizedTime".to_string()))?;
    
    // GeneralizedTime format: YYYYMMDDhhmmssZ (15 chars minimum)
    if time_str.len() < 15 {
        return Err(crate::crypto::Error::InvalidData(
            "GeneralizedTime too short".to_string()
        ));
    }
    
    let year = parse_digits(&time_str[0..4])? as i64;
    let month = parse_digits(&time_str[4..6])?;
    let day = parse_digits(&time_str[6..8])?;
    let hour = parse_digits(&time_str[8..10])?;
    let minute = parse_digits(&time_str[10..12])?;
    let second = parse_digits(&time_str[12..14])?;
    
    if year < 1970 {
        return Err(crate::crypto::Error::InvalidData("Year before Unix epoch".to_string()));
    }

    if month < 1 || month > 12 {
        return Err(crate::crypto::Error::InvalidData("Invalid month".to_string()));
    }

    if day < 1 || day > 31 {
        return Err(crate::crypto::Error::InvalidData("Invalid day".to_string()));
    }

    if hour > 23 {
        return Err(crate::crypto::Error::InvalidData("Invalid hour".to_string()));
    }

    if minute > 59 {
        return Err(crate::crypto::Error::InvalidData("Invalid minute".to_string()));
    }

    if second > 59 {
        return Err(crate::crypto::Error::InvalidData("Invalid second".to_string()));
    }
    
    let timestamp = calculate_unix_timestamp(year, month, day, hour, minute, second)?;
    if time_str.len() > 15 && !time_str.ends_with('Z') {
        let tz_offset = parse_timezone_offset(&time_str[15..])?;
        Ok(timestamp - tz_offset)
    } else {
        Ok(timestamp)
    }
}

/**
 * Parses digits from a string slice
 * Args:
 *    s: &str - String containing only digits
 * 
 * Returns:
 *    Result<i64>: Parsed number or error
 */
fn parse_digits(s: &str) -> Result<i64> {
    s.parse::<i64>().map_err(|_| crate::crypto::Error::InvalidData(
            format!("Failed to parse digits: {}", s)
        ))
}

/**
 * Parses timezone offset (+hhmm or -hhmm)
 * Args:
 *    tz_str: &str - Timezone offset string
 * 
 * Returns:
 *    Result<i64>: Offset in seconds or error
 */
fn parse_timezone_offset(tz_str: &str) -> Result<i64> {
    if tz_str.len() != 5 {
        return Err(crate::crypto::Error::InvalidData(
            "Invalid timezone offset format".to_string()
        ));
    }
    
    let sign = match &tz_str[0..1] {
        "+" => 1,
        "-" => -1,
        _ => return Err(crate::crypto::Error::InvalidData(
            "Invalid timezone sign".to_string()
        )),
    };
    
    let hours = parse_digits(&tz_str[1..3])?;
    let minutes = parse_digits(&tz_str[3..5])?;
    
    if hours > 23 || minutes > 59 {
        return Err(crate::crypto::Error::InvalidData(
            "Invalid timezone offset".to_string()
        ));
    }
    
    Ok(sign * (hours * 3600 + minutes * 60))
}

/**
 * Calculates Unix timestamp from date/time components
 * Args:
 *    year, month, day, hour, minute, second: Date/time components
 * 
 * Returns:
 *    Result<i64>: Unix timestamp or error
 */
fn calculate_unix_timestamp(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> Result<i64> {
    const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    
    let mut days = 0i64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    
    for m in 1..month {
        days += DAYS_IN_MONTH[(m - 1) as usize];
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    
    days += day - 1;
    
    let timestamp = days * 86400 + hour * 3600 + minute * 60 + second;
    
    Ok(timestamp)
}

/**
 * Checks if a year is a leap year
 * Args:
 *    year: i64 - The year to check
 * 
 * Returns:
 *    bool: True if leap year
 */
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/**
 * Helper function to match hostname with wildcards
 * Args:
 *    pattern: &str - The pattern (may contain wildcards)
 *    hostname: &str - The hostname to match
 * 
 * Returns:
 *    bool: True if hostname matches pattern
 */
fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    let pattern_lower = pattern.to_lowercase();
    let hostname_lower = hostname.to_lowercase();
    if pattern_lower == hostname_lower {
        return true;
    }

    if pattern_lower.starts_with("*.") {
        let pattern_domain = &pattern_lower[2..];
        if let Some(dot_pos) = hostname_lower.find('.') {
            let hostname_domain = &hostname_lower[dot_pos + 1..];
            return hostname_domain == pattern_domain;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal DER-encoded self-signed certificate (not valid, just for testing structure)
    // This is a dummy, minimal ASN.1 DER-encoded X.509 certificate for test purposes.
    const MINIMAL_DER: &[u8] = &[
        // Certificate SEQUENCE, length 74 = 0x4A
        0x30, 0x4A,
        // TBSCertificate SEQUENCE, length 54 = 0x36
        0x30, 0x36,
        // [0] Version: v3
        0xA0, 0x03, 0x02, 0x01, 0x02,
        // Serial Number: 1
        0x02, 0x01, 0x01,
        // Signature algorithm SEQUENCE (sha1WithRSAEncryption), length 13
        0x30, 0x0D,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
        0x05, 0x00,
        // Issuer SEQUENCE, length 2: empty SET
        0x30, 0x02, 0x31, 0x00,
        // Validity SEQUENCE, length 6: two UTCTime values
        0x30, 0x06, 0x17, 0x01, 0x30, 0x17, 0x01, 0x30,
        // Subject SEQUENCE, length 2: empty SET
        0x30, 0x02, 0x31, 0x00,
        // SubjectPublicKeyInfo SEQUENCE, length 13
        0x30, 0x0D,
        // Algorithm SEQUENCE, length 8
        0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        // Public key BIT STRING: 1 byte content (0 unused bits, empty key)
        0x03, 0x01, 0x00,
        // Signature algorithm SEQUENCE (sha1WithRSAEncryption), length 13
        0x30, 0x0D,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
        0x05, 0x00,
        // Signature BIT STRING: 1 byte content (0 unused bits, empty signature)
        0x03, 0x01, 0x00,
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

    #[test]
    fn test_parse_name_common_name_utf8() {
        // SET { SEQUENCE { OID commonName, UTF8String "example.com" } }
        let mut rdn = crate::crypto::encoding::asn1::DerEncoder::new();
        rdn.sequence(|attr| {
            let _ = attr.object_identifier(&[2, 5, 4, 3]);
            attr.utf8_string("example.com");
        });
        let rdn_bytes = rdn.finish();

        let mut name_bytes = vec![0x31];
        name_bytes.push(rdn_bytes.len() as u8);
        name_bytes.extend_from_slice(&rdn_bytes);

        let mut decoder = DerDecoder::new(&name_bytes);
        let name = super::parse_name(&mut decoder).unwrap();
        assert_eq!(name.common_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_utc_time() {
        // "240101120000Z" = Jan 1, 2024, 12:00:00 UTC
        let timestamp = parse_utc_time(b"240101120000Z").unwrap();
        assert!(timestamp >= 1704110400); // Unix timestamp for 2024-01-01 12:00:00
    }

    #[test]
    fn test_parse_generalized_time() {
        // "20240101120000Z" = Jan 1, 2024, 12:00:00 UTC
        let timestamp = parse_generalized_time(b"20240101120000Z").unwrap();
        assert!(timestamp >= 1704110400);
    }

    #[test]
    fn test_parse_utc_time_with_offset() {
        // "240101120000+0100" = Jan 1, 2024, 12:00:00 +01:00
        let timestamp = parse_utc_time(b"240101120000+0100").unwrap();
        let expected_base = parse_utc_time(b"240101120000Z").unwrap();
        assert_eq!(timestamp, expected_base - 3600); // 1 hour offset
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn test_calculate_unix_timestamp() {
        // Jan 1, 1970, 00:00:00 should be 0
        let ts = calculate_unix_timestamp(1970, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(ts, 0);
        
        // Jan 2, 1970, 00:00:00 should be 86400 (1 day)
        let ts = calculate_unix_timestamp(1970, 1, 2, 0, 0, 0).unwrap();
        assert_eq!(ts, 86400);
    }

    #[test]
    fn test_parse_timezone_offset() {
        assert_eq!(parse_timezone_offset("+0000").unwrap(), 0);
        assert_eq!(parse_timezone_offset("+0100").unwrap(), 3600);
        assert_eq!(parse_timezone_offset("-0500").unwrap(), -18000);
        assert!(parse_timezone_offset("+2400").is_err()); // Invalid
    }

    #[test]
    fn test_hostname_matches_exact() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("Example.COM", "example.com"));
        assert!(!hostname_matches("example.com", "other.com"));
    }

    #[test]
    fn test_hostname_matches_wildcard() {
        assert!(hostname_matches("*.example.com", "foo.example.com"));
        assert!(hostname_matches("*.example.com", "bar.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("*.example.com", "foo.bar.example.com"));
    }
}