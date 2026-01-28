// crypto/kdf/pbkdf2.rs - Password-Based Key Derivation Function 2 (PBKDF2) implementation
// https://datatracker.ietf.org/doc/html/rfc8018#section-5.2

use crate::crypto::{Error, Result};
use crate::crypto::hash::{HmacSha256, HmacSha512};

// Minimum recommended iterations for PBKDF2
const MIN_ITERATIONS: u32 = 100_000;

// Recommended iterations for PBKDF2
const RECOMMENDED_ITERATIONS: u32 = 600_000;

// Maximum derived key length in bytes
const MAX_DK_LEN: usize = 1024 * 1024;

/**
 * Derives a key using PBKDF2 with HMAC-SHA256
 * Args:
 *    password - &[u8]: The input password
 *    salt - &[u8]: The cryptographic salt
 *    iterations - u32: Number of iterations
 *    dk_len - usize: Desired length of the derived key in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived key or an error if parameters are invalid
 */
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Result<Vec<u8>> {
    pbkdf2_sha256_impl(password, salt, iterations, dk_len, false)
}

/**
 * Derives a key using PBKDF2 with HMAC-SHA256 in strict mode
 * Strict mode enforces minimum security parameters
 * Args:
 *    password - &[u8]: The input password
 *    salt - &[u8]: The cryptographic salt
 *    iterations - u32: Number of iterations
 *    dk_len - usize: Desired length of the derived key in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived key or an error if parameters are invalid
 */
pub fn pbkdf2_sha256_strict(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Result<Vec<u8>> {
    pbkdf2_sha256_impl(password, salt, iterations, dk_len, true)
}

/**
 * Internal implementation of PBKDF2 with HMAC-SHA256
 * Args:
 *    password - &[u8]: The input password
 *    salt - &[u8]: The cryptographic salt
 *    iterations - u32: Number of iterations
 *    dk_len - usize: Desired length of the derived key in bytes
 *    strict - bool: Whether to enforce strict security parameters
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived key or an error if parameters are invalid
 */
fn pbkdf2_sha256_impl(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize, strict: bool) -> Result<Vec<u8>> {
    if iterations == 0 {
        return Err(Error::InvalidLength);
    }
    
    if strict && iterations < MIN_ITERATIONS {
        return Err(Error::InvalidLength);
    }
    
    if password.is_empty() {
        return Err(Error::InvalidLength);
    }
    
    if salt.len() < 16 {
        return Err(Error::InvalidLength);
    }
    
    if dk_len == 0 || dk_len > MAX_DK_LEN {
        return Err(Error::InvalidLength);
    }
    
    let hash_len = 32usize;
    let blocks = dk_len.checked_add(hash_len - 1).and_then(|v| v.checked_div(hash_len)).ok_or(Error::InvalidLength)?;
    if blocks > u32::MAX as usize {
        return Err(Error::InvalidLength);
    }
    
    let mut dk = vec![0u8; dk_len];
    for block_num in 1..=blocks {
        let mut hmac = HmacSha256::new(password);
        hmac.update(salt);
        hmac.update(&(block_num as u32).to_be_bytes());
        let mut u = hmac.finalize().to_vec();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut hmac = HmacSha256::new(password);
            hmac.update(&u);
            u = hmac.finalize().to_vec();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= ui;
            }
        }
        
        let offset = (block_num - 1) * hash_len;
        let to_copy = std::cmp::min(hash_len, dk_len - offset);
        dk[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        
        u.iter_mut().for_each(|b| *b = 0);
        t.iter_mut().for_each(|b| *b = 0);
    }
    
    Ok(dk)
}

/**
 * Derives a key using PBKDF2 with HMAC-SHA512
 * Args:
 *    password - &[u8]: The input password
 *    salt - &[u8]: The cryptographic salt
 *    iterations - u32: Number of iterations
 *    dk_len - usize: Desired length of the derived key in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived key or an error if parameters are invalid
 */
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Result<Vec<u8>> {
    pbkdf2_sha512_impl(password, salt, iterations, dk_len, false)
}

/**
 * Derives a key using PBKDF2 with HMAC-SHA512 in strict mode
 * Strict mode enforces minimum security parameters
 * Args:
 *    password - &[u8]: The input password
 *    salt - &[u8]: The cryptographic salt
 *    iterations - u32: Number of iterations
 *    dk_len - usize: Desired length of the derived key in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived key or an error if parameters are invalid
 */
pub fn pbkdf2_sha512_strict(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Result<Vec<u8>> {
    pbkdf2_sha512_impl(password, salt, iterations, dk_len, true)
}

/**
 * Internal implementation of PBKDF2 with HMAC-SHA512
 * Args:
 *    password - &[u8]: The input password
 *    salt - &[u8]: The cryptographic salt
 *    iterations - u32: Number of iterations
 *    dk_len - usize: Desired length of the derived key in bytes
 *    strict - bool: Whether to enforce strict security parameters
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived key or an error if parameters are invalid
 */
fn pbkdf2_sha512_impl(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize, strict: bool) -> Result<Vec<u8>> {
    if iterations == 0 {
        return Err(Error::InvalidLength);
    }
    
    if strict && iterations < MIN_ITERATIONS {
        return Err(Error::InvalidLength);
    }
    
    if password.is_empty() {
        return Err(Error::InvalidLength);
    }
    
    if salt.len() < 16 {
        return Err(Error::InvalidLength);
    }
    
    if dk_len == 0 || dk_len > MAX_DK_LEN {
        return Err(Error::InvalidLength);
    }
    
    let hash_len = 64usize;
    let blocks = dk_len.checked_add(hash_len - 1).and_then(|v| v.checked_div(hash_len)).ok_or(Error::InvalidLength)?;
    if blocks > u32::MAX as usize {
        return Err(Error::InvalidLength);
    }
    
    let mut dk = vec![0u8; dk_len];
    for block_num in 1..=blocks {
        let mut hmac = HmacSha512::new(password);
        hmac.update(salt);
        hmac.update(&(block_num as u32).to_be_bytes());
        let mut u = hmac.finalize().to_vec();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut hmac = HmacSha512::new(password);
            hmac.update(&u);
            u = hmac.finalize().to_vec();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= ui;
            }
        }
        
        let offset = (block_num - 1) * hash_len;
        let to_copy = std::cmp::min(hash_len, dk_len - offset);
        dk[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        
        u.iter_mut().for_each(|b| *b = 0);
        t.iter_mut().for_each(|b| *b = 0);
    }
    
    Ok(dk)
}

/**
 * Securely compares two byte slices in constant times
 * Args:
 *    a - &[u8]: First byte slice
 *    b - &[u8]: Second byte slice
 * 
 * Returns:
 *    bool: True if slices are equal, false otherwise
 */
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (ai, bi) in a.iter().zip(b.iter()) {
        result |= ai ^ bi;
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pbkdf2_sha256_basic() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let dk = pbkdf2_sha256(password, salt, 1000, 32).unwrap();
        assert_eq!(dk.len(), 32);
    }
    
    #[test]
    fn test_pbkdf2_sha512_basic() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let dk = pbkdf2_sha512(password, salt, 1000, 64).unwrap();
        assert_eq!(dk.len(), 64);
    }
    
    #[test]
    fn test_pbkdf2_sha256_multiple_blocks() {
        let password = b"pass";
        let salt = b"saltsaltsaltsalt";
        let dk = pbkdf2_sha256(password, salt, 1000, 100).unwrap();
        assert_eq!(dk.len(), 100);
    }
    
    #[test]
    fn test_pbkdf2_sha512_multiple_blocks() {
        let password = b"pass";
        let salt = b"saltsaltsaltsalt";
        let dk = pbkdf2_sha512(password, salt, 1000, 128).unwrap();
        assert_eq!(dk.len(), 128);
    }
    
    #[test]
    fn test_empty_password_rejected() {
        let salt = b"saltsaltsaltsalt";
        assert!(pbkdf2_sha256(b"", salt, 1000, 32).is_err());
    }
    
    #[test]
    fn test_short_salt_rejected() {
        let password = b"password";
        let salt = b"short";
        assert!(pbkdf2_sha256(password, salt, 1000, 32).is_err());
    }
    
    #[test]
    fn test_zero_iterations_rejected() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        assert!(pbkdf2_sha256(password, salt, 0, 32).is_err());
    }
    
    #[test]
    fn test_strict_mode_low_iterations() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        assert!(pbkdf2_sha256_strict(password, salt, 1000, 32).is_err());
        assert!(pbkdf2_sha256_strict(password, salt, RECOMMENDED_ITERATIONS, 32).is_ok());
    }
    
    #[test]
    fn test_excessive_dk_len_rejected() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        assert!(pbkdf2_sha256(password, salt, 1000, MAX_DK_LEN + 1).is_err());
    }
    
    #[test]
    fn test_secure_compare() {
        let a = b"test";
        let b = b"test";
        let c = b"rest";
        
        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
        assert!(!secure_compare(a, b"short"));
    }
}