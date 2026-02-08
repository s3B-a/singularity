// crypto/mod.rs - Cryptographic Export Module
// This module re-exports all cryptographic functionalities provided
// by the Singularity library for easy access.

pub mod random;
pub mod bignum;
pub mod hash;
pub mod symmetric;
pub mod asymmetric;
pub mod kdf;
pub mod encoding;

pub use random::{CryptoRng, SystemRng};

// Common error type for cryptographic operations
pub type Result<T> = std::result::Result<T, Error>;

// Common error enumeration for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // Used for invalid key sizes
    InvalidKeySize,
    // Used for invalid input lengths
    InvalidLength,
    // Used for invalid padding in asymmetric and symmetric operations
    InvalidPadding,
    // Used when verification of signatures or MACs fails
    VerificationFailed,
    // Used for invalid signatures
    InvalidSignature,
    // Used for invalid certificates
    InvalidCertificate,
    // Used when there is insufficient entropy for random number generation
    InsufficientEntropy,
    // Generic cryptographic error with a message
    CryptoError(String),
    // Used for invalid data formats or values
    InvalidData(String),
}

/**
 * Constant-time comparison of two byte slices to prevent timing attacks
 * Args:
 *    a - &[u8]: First byte slice
 *    b - &[u8]: Second byte slice
 * 
 * Returns:
 *    bool: true if slices are equal, false otherwise
 */
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/**
 * Securely zero out a byte slice to prevent sensitive data from lingering in memory
 * Args:
 *    data - &mut [u8]: The byte slice to zero out
 * 
 * Returns:
 *    (): Nothing
 */
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKeySize => write!(f, "Invalid key size"),
            Error::InvalidLength => write!(f, "Invalid input length"),
            Error::InvalidPadding => write!(f, "Invalid padding"),
            Error::VerificationFailed => write!(f, "Verification failed"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::InvalidCertificate => write!(f, "Invalid certificate"),
            Error::InsufficientEntropy => write!(f, "Insufficient entropy"),
            Error::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Error::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xff; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}