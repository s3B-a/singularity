use crate::crypto::{Error, Result};
use crate::crypto::hash::{HmacSha256, HmacSha512};

pub struct Hkdf {
    prk: Vec<u8>,
}

pub struct HkdfSha512;

impl Hkdf {
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let mut hmac = HmacSha256::new(salt);
        hmac.update(ikm);
        
        hmac.finalize().to_vec()
    }

    pub fn expand(prk: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>> {
        let hash_len = 32;
        if prk.len() < hash_len {
            return Err(Error::InvalidKeySize);
        }

        let mut okm = Vec::with_capacity(okm_len);
        let mut previous = Vec::new();
        let mut counter = 1u8;
        while okm.len() < okm_len {
            let mut hmac = HmacSha256::new(prk);
            hmac.update(&previous);
            hmac.update(info);
            hmac.update(&[counter]);
            previous = hmac.finalize().to_vec();

            let to_copy = std::cmp::min(okm_len - okm.len(), hash_len);
            okm.extend_from_slice(&previous[..to_copy]);
            counter = counter.checked_add(1).ok_or(Error::InvalidLength)?;
        }
        
        Ok(okm)
    }

    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>> {
        let prk = Self::extract(salt, ikm);
        
        Self::expand(&prk, info, okm_len)
    }
}

impl HkdfSha512 {
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let salt = salt.unwrap_or(&[0u8; 64]);
        let mut hmac = HmacSha512::new(salt);
        hmac.update(ikm);
        hmac.finalize().to_vec()
    }

    pub fn expand(prk: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>> {
        let hash_len = 64;
        if prk.len() < hash_len {
            return Err(Error::InvalidKeySize);
        }
        let mut okm = Vec::with_capacity(okm_len);
        let mut previous = Vec::new();
        let mut counter = 1u8;

        while okm.len() < okm_len {
            let mut hmac = HmacSha512::new(prk);
            hmac.update(&previous);
            hmac.update(info);
            hmac.update(&[counter]);
            previous = hmac.finalize().to_vec();

            let to_copy = std::cmp::min(okm_len - okm.len(), hash_len);
            okm.extend_from_slice(&previous[..to_copy]);
            counter = counter.checked_add(1).ok_or(Error::InvalidLength)?;
        }

        Ok(okm)
    }

    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, okm_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let okm = Hkdf::derive(Some(salt), ikm, info, 42).unwrap();
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn test_hkdf_sha512() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let okm = HkdfSha512::derive(Some(salt), ikm, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_expand_multiple_blocks() {
        let ikm = b"key";
        let okm = Hkdf::derive(None, ikm, b"", 100).unwrap();
        assert_eq!(okm.len(), 100);
    }
}