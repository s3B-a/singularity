// crypto/hash/mod.rs - Hashing Module
// This module provides various hashing algorithms and HMAC implementations
// including SHA-2, SHA-3, and HMAC.

pub mod sha2;
pub mod sha3;
pub mod hmac;

pub use sha2::{Sha224, Sha256, Sha384, Sha512, sha224, sha256, sha384, sha512};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, sha3_224, sha3_256, sha3_384, sha3_512};
pub use sha3::{Keccak256, keccak256, Shake128, Shake256};
pub use hmac::{Hmac, HmacSha256, HmacSha512};

// Trait defining common interface for hash functions
pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>;
    fn reset(&mut self);
    fn output_size(&self) -> usize;
    fn block_size(&self) -> usize;
}

/**
 * Convenience function to hash data using a specified Digest implementation
 * Args:
 *    D - Digest + Default: The hash function to use
 *    data: &[u8]: The data to hash
 * 
 * Returns:
 *    Vec<u8>: The resulting hash
 */
pub fn hash<D: Digest + Default>(data: &[u8]) -> Vec<u8> {
    let mut hasher = D::default();
    hasher.update(data);

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_convenience() {
        let result = sha256(b"test");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha512_convenience() {
        let result = sha512(b"test");
        assert_eq!(result.len(), 64);
    }
}