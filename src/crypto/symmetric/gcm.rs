// crypto/symmetric/gcm.rs - Galois/Counter Mode (GCM) implementation
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

use crate::crypto::{Error, Result};
use super::aes::Aes;

// GCM structure
#[derive(Clone)]
pub struct Gcm {
    cipher: Aes,
    h: [u64; 2],
}

impl Gcm {

    /**
     * Creates a new Gcm instance with the given AES key
     * Args:
     *    key - &[u8]: The AES encryption key (16, 24, or 32 bytes)
     * 
     * Returns:
     *    Result<Self>: The Gcm instance or an error if the key size is invalid
     */
    pub fn new(key: &[u8]) -> Result<Self> {
        let cipher = Aes::new(key)?;
        let h_block = cipher.encrypt_block(&[0u8; 16]);
        let h = [
            u64::from_be_bytes([
                h_block[0], h_block[1], h_block[2], h_block[3],
                h_block[4], h_block[5], h_block[6], h_block[7],
            ]),
            u64::from_be_bytes([
                h_block[8], h_block[9], h_block[10], h_block[11],
                h_block[12], h_block[13], h_block[14], h_block[15],
            ]),
        ];

        Ok(Gcm { cipher, h })
    }

    /**
     * Encrypts plaintext using GCM mode with the given nonce and additional authenticated data (AAD)
     * Args:
     *    &self: The Gcm instance
     *    nonce - &[u8]: The nonce (IV) for encryption
     *    plaintext - &[u8]: The plaintext to encrypt
     *    aad - &[u8]: Additional authenticated data
     * 
     * Returns:
     *    Result<Vec<u8>>: The resulting ciphertext with authentication tag or an error
     *    if parameters are invalid
     */
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.is_empty() {
            return Err(Error::InvalidLength);
        }

        let j0 = self.compute_j0(nonce);
        let mut ghash_state = [0u64; 2];
        self.ghash_update(&mut ghash_state, aad);

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter = j0;
        for chunk in plaintext.chunks(16) {
            increment_counter(&mut counter);
            let keystream = self.cipher.encrypt_block(&counter);
            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
        }

        self.ghash_update(&mut ghash_state, &ciphertext);

        let mut length_block = [0u8; 16];
        length_block[0..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        length_block[8..16].copy_from_slice(&((ciphertext.len() * 8) as u64).to_be_bytes());
        let length_ghash = [
            u64::from_be_bytes([
                length_block[0], length_block[1], length_block[2], length_block[3],
                length_block[4], length_block[5], length_block[6], length_block[7],
            ]),
            u64::from_be_bytes([
                length_block[8], length_block[9], length_block[10], length_block[11],
                length_block[12], length_block[13], length_block[14], length_block[15],
            ]),
        ];
        
        ghash_state = self.ghash_mul(ghash_state, self.h);
        ghash_state[0] ^= length_ghash[0];
        ghash_state[1] ^= length_ghash[1];
        ghash_state = self.ghash_mul(ghash_state, self.h);

        let s = self.cipher.encrypt_block(&j0);
        let mut tag = [0u8; 16];
        for i in 0..8 {
            tag[i] = ((ghash_state[0] >> (56 - i * 8)) & 0xff) as u8 ^ s[i];
        }

        for i in 0..8 {
            tag[i + 8] = ((ghash_state[1] >> (56 - i * 8)) & 0xff) as u8 ^ s[i + 8];
        }

        ciphertext.extend_from_slice(&tag);

        Ok(ciphertext)
    }

    /**
     * Decrypts ciphertext using GCM mode with the given nonce and additional authenticated data (AAD)
     * Args:
     *    &self: The Gcm instance
     *    nonce - &[u8]: The nonce (IV) for decryption
     *    ciphertext_and_tag - &[u8]: The ciphertext with authentication tag
     *    aad - &[u8]: Additional authenticated data
     * 
     * Returns:
     *    Result<Vec<u8>>: The resulting plaintext or an error if authentication fails
     *    or parameters are invalid
     */
    pub fn decrypt(&self, nonce: &[u8], ciphertext_and_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.is_empty() {
            return Err(Error::InvalidLength);
        }

        if ciphertext_and_tag.len() < 16 {
            return Err(Error::InvalidLength);
        }

        let ciphertext_len = ciphertext_and_tag.len() - 16;
        let ciphertext = &ciphertext_and_tag[..ciphertext_len];
        let received_tag = &ciphertext_and_tag[ciphertext_len..];

        let j0 = self.compute_j0(nonce);
        let mut ghash_state = [0u64; 2];
        self.ghash_update(&mut ghash_state, aad);
        self.ghash_update(&mut ghash_state, ciphertext);

        let mut length_block = [0u8; 16];
        length_block[0..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        length_block[8..16].copy_from_slice(&((ciphertext.len() * 8) as u64).to_be_bytes());
        let length_ghash = [
            u64::from_be_bytes([
                length_block[0], length_block[1], length_block[2], length_block[3],
                length_block[4], length_block[5], length_block[6], length_block[7],
            ]),
            u64::from_be_bytes([
                length_block[8], length_block[9], length_block[10], length_block[11],
                length_block[12], length_block[13], length_block[14], length_block[15],
            ]),
        ];
        
        ghash_state = self.ghash_mul(ghash_state, self.h);
        ghash_state[0] ^= length_ghash[0];
        ghash_state[1] ^= length_ghash[1];
        ghash_state = self.ghash_mul(ghash_state, self.h);

        let s = self.cipher.encrypt_block(&j0);
        let mut computed_tag = [0u8; 16];
        for i in 0..8 {
            computed_tag[i] = ((ghash_state[0] >> (56 - i * 8)) & 0xff) as u8 ^ s[i];
        }

        for i in 0..8 {
            computed_tag[i + 8] = ((ghash_state[1] >> (56 - i * 8)) & 0xff) as u8 ^ s[i + 8];
        }

        if !crate::crypto::constant_time_eq(&computed_tag, received_tag) {
            return Err(Error::VerificationFailed);
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter = j0;
        for chunk in ciphertext.chunks(16) {
            increment_counter(&mut counter);
            let keystream = self.cipher.encrypt_block(&counter);
            for (i, &byte) in chunk.iter().enumerate() {
                plaintext.push(byte ^ keystream[i]);
            }
        }

        Ok(plaintext)
    }

    /**
     * Computes the initial counter block J0 based on the nonce
     * Args:
     *    &self: The Gcm instance
     *    nonce - &[u8]: The nonce (IV) for which to compute the initial counter block
     * 
     * Returns:
     *    [u8; 16]: The computed J0 block
     */
    fn compute_j0(&self, nonce: &[u8]) -> [u8; 16] {
        if nonce.len() == 12 {
            let mut j0 = [0u8; 16];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;

            j0
        } else {
            let mut ghash_state = [0u64; 2];
            self.ghash_update(&mut ghash_state, nonce);
            
            let mut length_block = [0u8; 16];
            length_block[8..16].copy_from_slice(&((nonce.len() * 8) as u64).to_be_bytes());
            let length_ghash = [
                u64::from_be_bytes([
                    length_block[0], length_block[1], length_block[2], length_block[3],
                    length_block[4], length_block[5], length_block[6], length_block[7],
                ]),
                u64::from_be_bytes([
                    length_block[8], length_block[9], length_block[10], length_block[11],
                    length_block[12], length_block[13], length_block[14], length_block[15],
                ]),
            ];
            
            ghash_state = self.ghash_mul(ghash_state, self.h);
            ghash_state[0] ^= length_ghash[0];
            ghash_state[1] ^= length_ghash[1];
            ghash_state = self.ghash_mul(ghash_state, self.h);
            
            let mut j0 = [0u8; 16];
            for i in 0..8 {
                j0[i] = (ghash_state[0] >> (56 - i * 8)) as u8;
                j0[i + 8] = (ghash_state[1] >> (56 - i * 8)) as u8;
            }

            j0
        }
    }

    /**
     * Updates the GHASH state with the given data
     * Args:
     *    &self: The Gcm instance
     *    state - &mut [u64; 2]: The current GHASH state to update
     *    data - &[u8]: The data to process
     * 
     * Returns:
     *    (): Nothing
     */
    fn ghash_update(&self, state: &mut [u64; 2], data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let block_u64 = [
                u64::from_be_bytes([
                    block[0], block[1], block[2], block[3],
                    block[4], block[5], block[6], block[7],
                ]),
                u64::from_be_bytes([
                    block[8], block[9], block[10], block[11],
                    block[12], block[13], block[14], block[15],
                ]),
            ];
            
            state[0] ^= block_u64[0];
            state[1] ^= block_u64[1];
            *state = self.ghash_mul(*state, self.h);
        }
    }

    /**
     * Performs GHASH multiplication in GF(2^128)
     * Args:
     *    &self: The Gcm instance
     *    x - [u64; 2]: The first operand
     *    y - [u64; 2]: The second operand
     * 
     * Returns:
     *    [u64; 2]: The result of the multiplication
     */
    fn ghash_mul(&self, x: [u64; 2], y: [u64; 2]) -> [u64; 2] {
        let mut z = [0u64; 2];
        let mut v = y;
        for i in 0..128 {
            let word = i / 64;
            let bit = 63 - (i % 64);
            if (x[word] >> bit) & 1 == 1 {
                z[0] ^= v[0];
                z[1] ^= v[1];
            }

            let lsb = v[1] & 1;
            v[1] = (v[1] >> 1) | (v[0] << 63);
            v[0] >>= 1;
            if lsb == 1 {
                v[0] ^= 0xe100000000000000;
            }
        }

        z
    }
}

/**
 * Increments the rightmost 32 bits of the counter block
 * Args:
 *    counter - &mut [u8; 16]: The counter block to increment
 * 
 * Returns:
 *    (): Nothing
 */
fn increment_counter(counter: &mut [u8; 16]) {
    let mut val = u32::from_be_bytes([
        counter[12],
        counter[13],
        counter[14],
        counter[15],
    ]);
    
    val = val.wrapping_add(1);
    let bytes = val.to_be_bytes();

    counter[12] = bytes[0];
    counter[13] = bytes[1];
    counter[14] = bytes[2];
    counter[15] = bytes[3];
}

/**
 * Convenience function to encrypt data using AES-GCM
 * Args:
 *    key - &[u8]: The AES encryption key (16, 24, or 32 bytes)
 *    nonce - &[u8]: The nonce (IV) for encryption
 *    plaintext - &[u8]: The plaintext to encrypt
 *    aad - &[u8]: Additional authenticated data
 * 
 * Returns:
 *    Result<Vec<u8>>: The resulting ciphertext with authentication tag or an error
 *    if parameters are invalid
 */
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let gcm = Gcm::new(key)?;

    gcm.encrypt(nonce, plaintext, aad)
}

/**
 * Convenience function to decrypt data using AES-GCM
 * Args:
 *    key - &[u8]: The AES encryption key (16, 24, or 32 bytes)
 *    nonce - &[u8]: The nonce (IV) for decryption
 *    ciphertext_and_tag - &[u8]: The ciphertext with authentication tag
 *    aad - &[u8]: Additional authenticated data
 * 
 * Returns:
 *    Result<Vec<u8>>: The resulting plaintext or an error if authentication fails
 *    or parameters are invalid
 */
pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext_and_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let gcm = Gcm::new(key)?;

    gcm.decrypt(nonce, ciphertext_and_tag, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcm_encrypt_decrypt() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, GCM!";
        let aad = b"Additional data";

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_tamper_detection() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        let gcm = Gcm::new(&key).unwrap();
        let mut ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        let result = gcm.decrypt(&nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_gcm_empty_plaintext() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let plaintext = b"";
        let aad = b"Just AAD";

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        
        // Should have only the tag (16 bytes)
        assert_eq!(ciphertext.len(), 16);
        
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_no_aad() {
        let key = [5u8; 16];
        let nonce = [6u8; 12];
        let plaintext = b"Message without AAD";
        let aad = b"";

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_long_plaintext() {
        let key = [7u8; 24];
        let nonce = [8u8; 12];
        let plaintext = [9u8; 1000];
        let aad = b"Some AAD";

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, &plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(&plaintext[..], &decrypted[..]);
    }

    #[test]
    fn test_gcm_different_nonce() {
        let key = [10u8; 16];
        let nonce1 = [11u8; 12];
        let nonce2 = [12u8; 12];
        let plaintext = b"Same plaintext";
        let aad = b"Same AAD";

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext1 = gcm.encrypt(&nonce1, plaintext, aad).unwrap();
        let ciphertext2 = gcm.encrypt(&nonce2, plaintext, aad).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }
}