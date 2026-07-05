// crypto/symmetric/gcm.rs - Galois/Counter Mode (GCM) implementation
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

use crate::crypto::{Error, Result};
use super::aes::Aes;

// GCM structure
#[deprecated(note = "Gcm is now optimized and should use GcmOptimized for better performance, Gcm will still exist but may be removed in the future")]
#[derive(Clone)]
pub struct Gcm {
    cipher: Aes,
    h: [u64; 2],
}

pub struct GcmOptimized {
    cipher: Aes,
    h: [u64; 2],
    h_powers: Vec<[u64; 2]>,
    h_karatsuba: KaratsubaTable,
}

struct KaratsubaTable {
    h_high: u64,
    h_low: u64,
    h_mid: u64,
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

impl GcmOptimized {

    /**
     * Creates a new GcmOptimized instance with the given AES key 
     * and precomputes the necessary tables for faster GHASH multiplication
     * Args:
     *    key - &[u8]: The AES encryption key (16, 24, or 32 bytes)
     * 
     * Returns:
     *    Result<Self>: The GcmOptimized instance or an error if the key size is invalid
     */
    pub fn new(key: &[u8]) -> Result<Self> {
        let cipher = Aes::new(key)?;
        let h_block = [0u8; 16];
        let h_encrypted = cipher.encrypt_block(&h_block);
        
        let h = [
            u64::from_be_bytes([
                h_encrypted[0], h_encrypted[1], h_encrypted[2], h_encrypted[3],
                h_encrypted[4], h_encrypted[5], h_encrypted[6], h_encrypted[7],
            ]),
            u64::from_be_bytes([
                h_encrypted[8], h_encrypted[9], h_encrypted[10], h_encrypted[11],
                h_encrypted[12], h_encrypted[13], h_encrypted[14], h_encrypted[15],
            ]),
        ];

        let h_karatsuba = KaratsubaTable {
            h_high: h[0],
            h_low: h[1],
            h_mid: ((h[0] ^ h[1]).wrapping_mul(h[0] ^ h[1])),
        };

        let mut h_powers = vec![];
        let mut h_power = h;
        for _ in 0..8 {
            h_powers.push(h_power);
            h_power = Self::ghash_mul_karatsuba(&h_power, &h);
        }

        Ok(GcmOptimized {
            cipher,
            h,
            h_powers,
            h_karatsuba,
        })
    }

    /**
     * Performs GHASH multiplication using Karatsuba's method for faster computation
     * Karatsuba: (a*2^64 + b)(c*2^64 + d) = ac*2^128 + ((a+b)(c+d) - ac - bd)*2^64 + bd
     * Args:
     *    x: &[u64; 2]: The first operand
     *    y: &[u64; 2]: The second operand
     * 
     * Returns:
     *    [u64; 2]: The result of the multiplication
     */
    fn ghash_mul_karatsuba(x: &[u64; 2], y: &[u64; 2]) -> [u64; 2] {
        let x_high = x[0];
        let x_low = x[1];
        let y_high = y[0];
        let y_low = y[1];

        let z0 = Self::gf128_mul_64(x_low, y_low);
        let z2 = Self::gf128_mul_64(x_high, y_high);
        let z1 = Self::gf128_mul_64(x_low ^ x_high, y_low ^ y_high);

        let mut result = z2;
        
        result[0] ^= z1[0] ^ z0[0];
        result[1] ^= z1[1] ^ z0[1];

        Self::gf128_reduce(&[z2[0], z2[1] ^ z1[0] ^ z0[0], z1[1] ^ z0[1], z0[0], z0[1]])
    }

    /**
     * Performs multiplication of two 64-bit values in GF(2^128)
     * using the method of shifting and conditional XORs
     * Args:
     *    a: u64 - The first operand
     *    b: u64 - The second operand
     * 
     * Returns:
     *    [u64; 2]: The result of the multiplication, represented 
     *        as a 128 bit value split into two 64-bit parts
     */
    fn gf128_mul_64(a: u64, b: u64) -> [u64; 2] {
        let mut z0 = 0u64;
        let mut z1 = 0u64;
        let mut v = b;
        for i in 0..64 {
            if (a >> i) & 1 == 1 {
                z0 ^= v;
                if i > 0 {
                    z1 ^= (v >> (64 - i));
                }
            }

            let lsb = v & 1;
            v >>= 1;
            if lsb == 1 {
                v ^= 0xe100000000000000;
            }
        }

        [z0, z1]
    }

    /**
     * Reduces a 256-bit product down to 128 bits using the GCM polynomial
     * x^128 + x^7 + x^2 + x + 1
     * Args:
     *    p: &[u64; 5] - The 256-bit product represented as 5 64-bit parts
     * 
     * Retruns:
     *    [u64; 2]: The reduced 128-bit result represented as two 64-bit parts
     */
    fn gf128_reduce(p: &[u64; 5]) -> [u64; 2] {
        let mut result = [p[3], p[4]];
        for i in 0..3 {
            result[0] ^= p[i] >> (64 - (i + 1) * 8);
            result[1] ^= (p[i] << ((i + 1) * 8)) & 0xffffffffffffffff;
        }

        result
    }

    /**
     * Updates the GHASH state with the given data using the optimized Karatsuba multiplication
     * This method processes data in 16-byte blocks and uses precomputed tables for faster multiplication
     * Args:
     *    &self: The GcmOptimized instance
     *    state - &mut [u64; 2]: The current GHASH state
     *    data - &[u8]: The data to process
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn ghash_update_fast(&self, state: &mut [u64; 2], data: &[u8]) {
        for block in data.chunks(16) {
            let mut x = [0u64; 2];
            if block.len() == 16 {
                x[0] = u64::from_be_bytes([
                    block[0], block[1], block[2], block[3],
                    block[4], block[5], block[6], block[7],
                ]);
                x[1] = u64::from_be_bytes([
                    block[8], block[9], block[10], block[11],
                    block[12], block[13], block[14], block[15],
                ]);
            }

            *state = Self::ghash_mul_karatsuba(&[state[0] ^ x[0], state[1] ^ x[1]], &self.h);
        }
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