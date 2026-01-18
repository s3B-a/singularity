pub mod random;
pub mod bignum;
pub mod hash;
pub mod symmetric;
pub mod asymmetric;
pub mod kdf;
pub mod encoding;

pub use random::{CryptoRng, SystemRng};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidKeySize,
    InvalidLength,
    InvalidPadding,
    VerificationFailed,
    InvalidSignature,
    InvalidCertificate,
    InsufficientEntropy,
    CryptoError(String),
}

// Constant-time equality check
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

// Zero out memory
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