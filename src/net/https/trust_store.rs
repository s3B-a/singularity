use crate::crypto::encoding::x509::Certificate;
use std::fs;
use std::path::Path;

// A self-contained bundle of root CA certificates extracted from Mozilla's root program
const BUNDLED_MOZILLA_ROOTS_PEM: &str = include_str!("data/mozilla_roots.pem");

#[derive(Debug)]
pub enum TrustStoreError {
    Io(std::io::Error),
    Parse(String),
}

impl std::fmt::Display for TrustStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustStoreError::Io(e) => write!(f, "Trust store IO error: {}", e),
            TrustStoreError::Parse(msg) => write!(f, "Trust store parse error: {}", msg),
        }
    }
}

impl std::error::Error for TrustStoreError {}

impl From<std::io::Error> for TrustStoreError {
    fn from(err: std::io::Error) -> Self {
        TrustStoreError::Io(err)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    anchors: Vec<Certificate>,
}

impl TrustStore {
    pub fn empty() -> Self {
        Self { anchors: Vec::new() }
    }

    pub fn bundled() -> Self {
        let mut store = Self::empty();
        store.add_pem_bundle(BUNDLED_MOZILLA_ROOTS_PEM);

        store
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn anchors(&self) -> &[Certificate] {
        &self.anchors
    }

    pub fn add_cert(&mut self, cert: Certificate) {
        self.anchors.push(cert);
    }

    pub fn add_der(&mut self, der: &[u8]) -> Result<(), TrustStoreError> {
        let cert = Certificate::from_der(der).map_err(|e| TrustStoreError::Parse(format!("{:?}", e)))?;
        self.anchors.push(cert);

        Ok(())
    }

    pub fn add_pem_bundle(&mut self, pem_data: &str) -> usize {
        let mut added = 0;
        for block in split_pem_certificates(pem_data) {
            if let Ok(cert) = Certificate::from_pem(&block) {
                self.anchors.push(cert);
                added += 1;
            }
        }

        added
    }

    pub fn load_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, TrustStoreError> {
        let data = fs::read_to_string(path)?;
        let mut store = Self::empty();
        store.add_pem_bundle(&data);
        Ok(store)
    }

    pub fn add_pem_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, TrustStoreError> {
        let data = fs::read_to_string(path)?;
        Ok(self.add_pem_bundle(&data))
    }

    pub fn load_system_default() -> Self {
        let mut candidates: Vec<String> = Vec::new();
        if let Ok(path) = std::env::var("SSL_CERT_FILE") {
            candidates.push(path);
        }

        if let Ok(path) = std::env::var("SINGULARITY_CA_BUNDLE") {
            candidates.push(path);
        }

        candidates.extend(
            [
                "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo/Arch
                "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL/CentOS
                "/etc/ssl/ca-bundle.pem",             // openSUSE
                "/etc/pki/tls/cacert.pem",            // OpenELEC
                "/etc/ssl/cert.pem",                  // Alpine/macOS
                "/usr/local/etc/openssl/cert.pem",    // Homebrew OpenSSL on macOS
            ].iter().map(|s| s.to_string()),
        );

        let mut store = Self::empty();
        for candidate in candidates {
            if let Ok(data) = fs::read_to_string(&candidate) {
                store.add_pem_bundle(&data);
                if !store.is_empty() {
                    break;
                }
            }
        }

        store
    }

    pub fn find_issuer(&self, cert: &Certificate) -> Option<&Certificate> {
        let issuer_name = cert.issuer_raw();
        let aki = cert.get_authority_key_identifier().unwrap_or_default();
        self.anchors.iter().find(|anchor| {
            if anchor.subject_raw() != issuer_name {
                return false;
            }

            if !aki.is_empty() {
                let ski = anchor.get_subject_key_identifier().unwrap_or_default();
                if !ski.is_empty() && ski != aki {
                    return false;
                }
            }

            true
        })
    }

    pub fn contains_exact(&self, cert: &Certificate) -> bool {
        let der = cert.to_der();
        self.anchors.iter().any(|anchor| anchor.to_der() == der)
    }
}

fn split_pem_certificates(data: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut in_block = false;
    for line in data.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_block = true;
            current.clear();
        }

        if in_block {
            current.push_str(line);
            current.push('\n');
        }

        if line.contains("-----END CERTIFICATE-----") {
            if in_block {
                blocks.push(std::mem::take(&mut current));
            }

            in_block = false;
        }
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_store() {
        let store = TrustStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_split_pem_certificates_ignores_comments() {
        let data = "\
## some header text\n\
## more header\n\
Friendly Name\n\
=============\n\
-----BEGIN CERTIFICATE-----\n\
AAAA\n\
BBBB\n\
-----END CERTIFICATE-----\n\
\n\
Another Name\n\
============\n\
-----BEGIN CERTIFICATE-----\n\
CCCC\n\
-----END CERTIFICATE-----\n\
";

        let blocks = split_pem_certificates(data);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAAA"));
        assert!(blocks[0].contains("BBBB"));
        assert!(blocks[1].contains("CCCC"));
    }

    #[test]
    fn test_bundled_store_parses_most_mozilla_roots() {
        let store = TrustStore::bundled();
        let total_blocks = split_pem_certificates(BUNDLED_MOZILLA_ROOTS_PEM).len();

        assert!(total_blocks > 50, "expected a sizable bundle, found {} blocks", total_blocks);
        assert!(
            store.len() * 10 >= total_blocks * 9,
            "expected at least 90% of {} bundled certs to parse, got {}",
            total_blocks,
            store.len()
        );
    }

    #[test]
    fn test_find_issuer_none_when_empty() {
        let store = TrustStore::empty();
        let bundled = TrustStore::bundled();
        if let Some(anchor) = bundled.anchors().first() {
            assert!(store.find_issuer(anchor).is_none());
        }
    }

    #[test]
    fn test_bundled_root_to_der_roundtrip() {
        let store = TrustStore::bundled();
        let anchor = store.anchors().first().expect("bundle should be non-empty");

        let der = anchor.to_der();
        assert!(der.len() > 300, "expected a realistically-sized certificate, got {} bytes", der.len());

        let reparsed = Certificate::from_der(&der).expect("re-encoded certificate should parse");
        assert_eq!(reparsed.signature, anchor.signature);
        assert_eq!(reparsed.tbs, anchor.tbs);
        assert_eq!(reparsed.to_der(), der, "to_der() should be stable across a round trip");

        assert!(store.contains_exact(anchor));
    }

    #[test]
    fn test_bundled_rsa_anchors_have_usable_public_keys() {
        use crate::crypto::asymmetric::rsa::RsaPublicKey;

        const RSA_ENCRYPTION_OID: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
        let store = TrustStore::bundled();
        let rsa_anchors: Vec<_> = store
            .anchors()
            .iter()
            .filter(|c| c.subject_public_key_info.algorithm == RSA_ENCRYPTION_OID)
            .collect();

        assert!(!rsa_anchors.is_empty(), "expected at least one RSA trust anchor in the bundle");
        for anchor in rsa_anchors {
            RsaPublicKey::from_bytes(&anchor.subject_public_key_info.public_key)
                .expect("RSA trust anchor public key should parse as valid DER");
        }
    }

    #[test]
    fn test_all_bundled_roots_verify_their_own_self_signature() {
        let store = TrustStore::bundled();
        assert_eq!(store.len(), 119, "bundled root count changed - re-check curve/hash coverage");

        let mut failures = Vec::new();
        for anchor in store.anchors() {
            if let Err(e) = anchor.verify_signature(anchor) {
                failures.push(format!("{:?}: {:?}", anchor.subject.common_name, e));
            }
        }

        assert!(failures.is_empty(), "self-signature verification failed for: {:#?}", failures);
    }
}
