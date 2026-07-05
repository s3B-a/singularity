// crypto/hash/hmac.rs - HMAC implementation using SHA-256 and SHA-512
// Supports incremental updates and verification of HMAC values.
// Based on RFC 2104 and RFC 4231 test vectors
// https://tools.ietf.org/html/rfc2104
// https://tools.ietf.org/html/rfc4231

use super::sha2::{Sha256, Sha512};

// Trait for hash functions used in HMAC
pub trait HashFunction: Clone {
    fn update(&mut self, data: &[u8]);
    fn finalize_clone(&mut self) -> Vec<u8>;
    fn reset(&mut self);
}

// Generic HMAC struct
#[derive(Clone)]
pub struct Hmac<H> {
    hasher: H,
    outer_hasher: H,
    block_size: usize,
}

// HMAC using SHA-256
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Hmac<Sha256>,
}

// HMAC using SHA-512
#[derive(Clone)]
pub struct HmacSha512 {
    inner: Hmac<Sha512>,
}

// Implementation of HMAC for any hash function H that implements the HashFunction trait
impl<H: Clone> Hmac<H> {

    /**
     * Create a new HMAC instance with a given key
     * Args:
     *    key - &[u8]: The secret key for HMAC
     * 
     * Returns:
     *    Self where H: HashFunction + Default: New HMAC instance in accordance with the hash
     *    function H and the default block size for that hash function
     */
    pub fn new(key: &[u8]) -> Self where H: HashFunction + Default {
        let hasher = H::default();
        let block_size = match std::any::type_name::<H>() {
            name if name.contains("Sha256") => 64,
            name if name.contains("Sha512") => 128,
            _ => 64,
        };

        Self::new_with_hasher(hasher, key, block_size)
    }

    /**
     * Create a new HMAC instance with a given hasher and key
     * Args:
     *    mut hasher - H: The hash function instance
     *    key - &[u8]: The secret key for HMAC
     *    block_size - usize: The block size of the hash function
     * 
     * Returns:
     *    Self where H: HashFunction: New HMAC instance in accordance with the hash function H
     */
    fn new_with_hasher(mut hasher: H, key: &[u8], block_size: usize) -> Self where H: HashFunction {
        let mut key_buffer = vec![0u8; block_size];
        if key.len() > block_size {
            hasher.update(key);
            let hashed_key = hasher.finalize_clone();
            key_buffer[..hashed_key.len()].copy_from_slice(&hashed_key);
            hasher.reset();
        } else {
            key_buffer[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = vec![0u8; block_size];
        let mut outer_key = vec![0u8; block_size];
        for i in 0..block_size {
            inner_key[i] = key_buffer[i] ^ 0x36;
            outer_key[i] = key_buffer[i] ^ 0x5c;
        }

        hasher.update(&inner_key);

        let mut outer_hasher = hasher.clone();
        outer_hasher.reset();
        outer_hasher.update(&outer_key);

        Hmac {
            hasher,
            outer_hasher,
            block_size,
        }
    }

    /**
     * Update the HMAC with data
     * Args:
     *    &mut self: Mutable reference to the HMAC instance
     *    data - &[u8]: The data to update the HMAC with
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) where H: HashFunction {
        self.hasher.update(data);
    }

    /**
     * Finalize the HMAC computation and return the HMAC value
     * Args:
     *    mut self: Mutable HMAC instance
     * 
     * Returns:
     *    Vec<u8> where H: HashFunction: The computed HMAC value in accordance with the hash function H
     */
    pub fn finalize(mut self) -> Vec<u8> where H: HashFunction {
        let inner_hash = self.hasher.finalize_clone();
        self.outer_hasher.update(&inner_hash);
        self.outer_hasher.finalize_clone()
    }

    pub fn verify(self, expected: &[u8]) -> bool where H: HashFunction {
        let computed = self.finalize();
        crate::crypto::constant_time_eq(&computed, expected)
    }
}

// Implementation of HashFunction trait for Sha256
impl HashFunction for Sha256 {
    
    /**
     * Update the Sha256 hash with data
     * Args:
     *    &mut self: Mutable reference to the Sha256 instance
     *    data - &[u8]: The data to update the hash with
     * 
     * Returns:
     *    (): Nothing
     */
    fn update(&mut self, data: &[u8]) {
        Sha256::update(self, data);
    }

    /**
     * Finalize the Sha256 hash computation and return the hash value
     * Args:
     *    &mut self: Mutable reference to the Sha256 instance
     * 
     * Returns:
     *    Vec<u8>: The computed hash value
     */
    fn finalize_clone(&mut self) -> Vec<u8> {
        self.clone().finalize().to_vec()
    }

    /**
     * Reset the Sha256 instance to its initial state
     * Args:
     *    &mut self: Mutable reference to the Sha256 instance
     * 
     * Returns:
     *    (): Nothing
     */
    fn reset(&mut self) {
        *self = Sha256::new();
    }
}

// Implementation of HashFunction trait for Sha512
impl HashFunction for Sha512 {

    /**
     * Update the Sha512 hash with data
     * Args:
     *    &mut self: Mutable reference to the Sha512 instance
     *    data - &[u8]: The data to update the hash with
     * 
     * Returns:
     *    (): Nothing
     */
    fn update(&mut self, data: &[u8]) {
        Sha512::update(self, data);
    }

    /**
     * Finalize the Sha512 hash computation and return the hash value
     * Args:
     *    &mut self: Mutable reference to the Sha512 instance
     * 
     * Returns:
     *    Vec<u8>: The computed hash value
     */
    fn finalize_clone(&mut self) -> Vec<u8> {
        self.clone().finalize().to_vec()
    }

    /**
     * Reset the Sha512 instance to its initial state
     * Args:
     *    &mut self: Mutable reference to the Sha512 instance
     * 
     * Returns:
     *    (): Nothing
     */
    fn reset(&mut self) {
        *self = Sha512::new();
    }
}

// HMAC-SHA256 convenience functions
impl HmacSha256 {
    
    /**
     * Create a new HMAC-SHA256 instance with a given key
     * Args:
     *    key - &[u8]: The secret key for HMAC
     * 
     * Returns:
     *    Self: New HMAC-SHA256 instance
     */
    pub fn new(key: &[u8]) -> Self {
        HmacSha256 {
            inner: Hmac::new_with_hasher(Sha256::new(), key, 64),
        }
    }

    /**
     * Update the HMAC-SHA256 with data
     * Args:
     *    &mut self: Mutable reference to the HMAC-SHA256 instance
     *    data - &[u8]: The data to update the HMAC with
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the HMAC-SHA256 computation and return the HMAC value
     * Args:
     *    self: HMAC-SHA256 instance
     * 
     * Returns:
     *    [u8; 32]: The computed HMAC-SHA256 value
     */
    pub fn finalize(self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);

        output
    }

    /**
     * Verify the HMAC-SHA256 against an expected value
     * Args:
     *    self: HMAC-SHA256 instance
     *    expected - &[u8]: The expected HMAC value to verify against
     * 
     * Returns:
     *    bool: True if the computed HMAC matches the expected value, false otherwise
     */
    pub fn verify(self, expected: &[u8]) -> bool {
        self.inner.verify(expected)
    }
}

/**
 * Compute HMAC-SHA256 for given key and data
 * Args:
 *    key - &[u8]: The secret key for HMAC
 *    data - &[u8]: The data to compute HMAC over
 * 
 * Returns:
 *    [u8; 32]: The computed HMAC-SHA256 value
 */
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new(key);
    hmac.update(data);

    hmac.finalize()
}

// HMAC-SHA512 convenience functions
impl HmacSha512 {

    /**
     * Create a new HMAC-SHA512 instance with a given key
     * Args:
     *    key - &[u8]: The secret key for HMAC
     * 
     * Returns:
     *    Self: new HMAC-SHA512 instance
     */
    pub fn new(key: &[u8]) -> Self {
        HmacSha512 {
            inner: Hmac::new_with_hasher(Sha512::new(), key, 128),
        }
    }

    /**
     * Update the HMAC-SHA512 with data
     * Args:
     *    &mut self: Mutable reference to the HMAC-SHA512 instance
     *    data - &[u8]: The data to update the HMAC with
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the HMAC-SHA512 computation and return the HMAC value
     * Args:
     *    self: HMAC-SHA512 instance
     * 
     * Returns:
     *    [u8; 64]: The computed HMAC-SHA512 value
     */
    pub fn finalize(self) -> [u8; 64] {
        let result = self.inner.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);

        output
    }

    /**
     * Verify the HMAC-SHA512 against an expected value
     * Args:
     *    self: HMAC-SHA512 instance
     *    expected - &[u8]: The expected HMAC value to verify against
     * 
     * Returns:
     *    bool: True if the computed HMAC matches the expected value, false otherwise
     */
    pub fn verify(self, expected: &[u8]) -> bool {
        self.inner.verify(expected)
    }
}

/**
 * Compute HMAC-SHA512 for given key and data
 * Args:
 *    key - &[u8]: The secret key for HMAC
 *    data - &[u8]: The data to compute HMAC over
 * 
 * Returns:
 *    [u8; 64]: The computed HMAC-SHA512 value
 */
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut hmac = HmacSha512::new(key);
    hmac.update(data);
    
    hmac.finalize()
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }

        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_test1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
        
        let result = hmac_sha256(&key, data);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();
        
        let result = hmac_sha256(key, data);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hmac_sha256_incremental() {
        let key = b"key";
        let data1 = b"The quick brown fox ";
        let data2 = b"jumps over the lazy dog";
        
        let mut full_data = Vec::new();
        full_data.extend_from_slice(data1);
        full_data.extend_from_slice(data2);
        let expected = hmac_sha256(key, &full_data);
        
        let mut hmac = HmacSha256::new(key);
        hmac.update(data1);
        hmac.update(data2);
        let result = hmac.finalize();
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha512_rfc4231_test1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = hex::decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854").unwrap();
        
        let result = hmac_sha512(&key, data);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hmac_verify() {
        let key = b"secret_key";
        let data = b"message";
        
        let mut hmac1 = HmacSha256::new(key);
        hmac1.update(data);
        let mac = hmac1.clone().finalize();
        
        let mut hmac2 = HmacSha256::new(key);
        hmac2.update(data);
        assert!(hmac2.verify(&mac));
        
        let mut hmac3 = HmacSha256::new(key);
        hmac3.update(data);
        let mut wrong_mac = mac;
        wrong_mac[0] ^= 1;
        assert!(!hmac3.verify(&wrong_mac));
    }

    #[test]
    fn test_hmac_long_key() {
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key";
        
        let result = hmac_sha256(&key, data);
        assert_eq!(result.len(), 32);
    }
}