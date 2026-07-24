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
        self.ghash_update(&mut ghash_state, &length_block);

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
        self.ghash_update(&mut ghash_state, &length_block);

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
            self.ghash_update(&mut ghash_state, &length_block);

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
        let (x_lo, x_hi) = (x[0].reverse_bits(), x[1].reverse_bits());
        let (y_lo, y_hi) = (y[0].reverse_bits(), y[1].reverse_bits());

        let (z0_hi, z0_lo) = Self::clmul64(x_lo, y_lo);
        let (z2_hi, z2_lo) = Self::clmul64(x_hi, y_hi);
        let (z1_hi, z1_lo) = Self::clmul64(x_lo ^ x_hi, y_lo ^ y_hi);

        let cross_hi = z1_hi ^ z2_hi ^ z0_hi;
        let cross_lo = z1_lo ^ z2_lo ^ z0_lo;

        let p0 = z0_lo;
        let p1 = z0_hi ^ cross_lo;
        let p2 = cross_hi ^ z2_lo;
        let p3 = z2_hi;

        let (r_hi, r_lo) = Self::reduce256(p3, p2, p1, p0);

        [r_lo.reverse_bits(), r_hi.reverse_bits()]
    }

    /**
     * Plain (unreduced) carryless multiplication of two 64-bit values, treating
     * bit i of each operand as the coefficient of x^i (schoolbook shift-and-xor)
     * Args:
     *    a: u64 - The first operand
     *    b: u64 - The second operand
     * 
     * Returns:
     *    (u64, u64): The 128-bit product as (high, low), no modular reduction applied
     */
    fn clmul64(a: u64, b: u64) -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for i in 0..64 {
            if (a >> i) & 1 == 1 {
                lo ^= b << i;
                if i > 0 {
                    hi ^= b >> (64 - i);
                }
            }
        }

        (hi, lo)
    }

    /**
     * Shifts a 128-bit value (hi:lo) left by a small amount (1 <= n <= 63)
     * returning the bits pushed out past bit 127 separately
     * Args:
     *    hi: u64 - High 64 bits of the value
     *    lo: u64 - Low 64 bits of the value
     *    n: u32 - Shift amount, must be in 1..=63
     *
     * Returns:
     *    (u64, u64, u64): (overflow bits beyond bit 127, new high word, new low word)
     */
    fn shl128_small(hi: u64, lo: u64, n: u32) -> (u64, u64, u64) {
        let overflow = hi >> (64 - n);
        let new_hi = (hi << n) | (lo >> (64 - n));
        let new_lo = lo << n;

        (overflow, new_hi, new_lo)
    }

    /**
     * Reduces an unreduced 256-bit carryless product modulo the GCM field
     * polynomial x^128 + x^7 + x^2 + x + 1 (i.e. x^128 = x^7 + x^2 + x + 1)
     * using plain "bit i = coefficient of x^i" order throughout
     * Args:
     *    x3, x2, x1, x0: u64 - The 256-bit product, most-significant word first
     *
     * Returns:
     *    (u64, u64): The reduced 128-bit result as (high, low)
     */
    fn reduce256(x3: u64, x2: u64, x1: u64, x0: u64) -> (u64, u64) {
        let (ov1, h1, l1) = Self::shl128_small(x3, x2, 1);
        let (ov2, h2, l2) = Self::shl128_small(x3, x2, 2);
        let (ov7, h7, l7) = Self::shl128_small(x3, x2, 7);

        let reduction_hi = x3 ^ h1 ^ h2 ^ h7;
        let reduction_lo = x2 ^ l1 ^ l2 ^ l7;
        let overflow = ov1 ^ ov2 ^ ov7;

        let r1 = x1 ^ reduction_hi;
        let mut r0 = x0 ^ reduction_lo;

        r0 ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);

        (r1, r0)
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
            } else {
                let mut padded = [0u8; 16];
                padded[..block.len()].copy_from_slice(block);
                x[0] = u64::from_be_bytes([
                    padded[0], padded[1], padded[2], padded[3],
                    padded[4], padded[5], padded[6], padded[7],
                ]);
                x[1] = u64::from_be_bytes([
                    padded[8], padded[9], padded[10], padded[11],
                    padded[12], padded[13], padded[14], padded[15],
                ]);
            }

            *state = Self::ghash_mul_karatsuba(&[state[0] ^ x[0], state[1] ^ x[1]], &self.h);
        }
    }

    /**
     * Computes the initial counter block J0 based on the nonce, using the
     * Karatsuba-accelerated GHASH for non-standard (non-96-bit) nonce lengths
     * Args:
     *    &self: The GcmOptimized instance
     *    nonce - &[u8]: The nonce for which to compute the initial counter block
     *
     * Returns:
     *    [u8; 16]: The computed J0 block
     */
    fn compute_j0(&self, nonce: &[u8]) -> [u8; 16] {
        if nonce.len() == 12 {
            let mut j0 = [0u8; 16];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;

            return j0;
        }

        let mut ghash_state = [0u64; 2];
        self.ghash_update_fast(&mut ghash_state, nonce);

        let mut length_block = [0u8; 16];
        length_block[8..16].copy_from_slice(&((nonce.len() * 8) as u64).to_be_bytes());
        self.ghash_update_fast(&mut ghash_state, &length_block);

        let mut j0 = [0u8; 16];
        for i in 0..8 {
            j0[i] = (ghash_state[0] >> (56 - i * 8)) as u8;
            j0[i + 8] = (ghash_state[1] >> (56 - i * 8)) as u8;
        }

        j0
    }

    /**
     * Encrypts plaintext using GCM mode (Karatsuba-accelerated GHASH) with the
     * given nonce and additional authenticated data (AAD)
     * Args:
     *    &self: The GcmOptimized instance
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
        self.ghash_update_fast(&mut ghash_state, aad);

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter = j0;
        for chunk in plaintext.chunks(16) {
            increment_counter(&mut counter);
            let keystream = self.cipher.encrypt_block(&counter);
            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
        }

        self.ghash_update_fast(&mut ghash_state, &ciphertext);

        let mut length_block = [0u8; 16];
        length_block[0..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        length_block[8..16].copy_from_slice(&((ciphertext.len() * 8) as u64).to_be_bytes());
        self.ghash_update_fast(&mut ghash_state, &length_block);

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
     * Decrypts ciphertext using GCM mode (Karatsuba-accelerated GHASH) with the
     * given nonce and additional authenticated data (AAD)
     * Args:
     *    &self: The GcmOptimized instance
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
        self.ghash_update_fast(&mut ghash_state, aad);
        self.ghash_update_fast(&mut ghash_state, ciphertext);

        let mut length_block = [0u8; 16];
        length_block[0..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        length_block[8..16].copy_from_slice(&((ciphertext.len() * 8) as u64).to_be_bytes());
        self.ghash_update_fast(&mut ghash_state, &length_block);

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
    fn test_ghash_mul_matches_authoritative_nist_vector() {
        let c1 = [0x0388dace60b6a392u64, 0xf328c2b971b2fe78u64];
        let h = [0x66e94bd4ef8a2c3bu64, 0x884cfa59ca342b2eu64];
        let expected_x1 = [0x5e2ec74691706288u64, 0x2c85b0685353deb7u64];

        let gcm = Gcm::new(&[0u8; 16]).unwrap();
        assert_eq!(gcm.ghash_mul(c1, h), expected_x1, "ghash_mul does not match the authoritative NIST vector");
        assert_eq!(GcmOptimized::ghash_mul_karatsuba(&c1, &h), expected_x1, "ghash_mul_karatsuba does not match the authoritative NIST vector");
    }

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

    #[test]
    fn test_gcm_nist_test_case_1() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let expected_tag: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
        ];

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, b"", b"").unwrap();

        assert_eq!(&ciphertext[..], &expected_tag[..]);
    }

    #[test]
    fn test_gcm_nist_test_case_2() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let expected_ciphertext: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        ];
        let expected_tag: [u8; 16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
            0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
        ];

        let gcm = Gcm::new(&key).unwrap();
        let out = gcm.encrypt(&nonce, &plaintext, b"").unwrap();

        assert_eq!(&out[..16], &expected_ciphertext[..]);
        assert_eq!(&out[16..], &expected_tag[..]);
    }

    #[test]
    fn test_gcm_non_standard_nonce_length() {
        let key = [13u8; 16];
        let nonce = [14u8; 16];
        let plaintext = b"Non-standard nonce length test";
        let aad = b"aad";

        let gcm = Gcm::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_optimized_encrypt_decrypt() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, GCM!";
        let aad = b"Additional data";

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_optimized_tamper_detection() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        let gcm = GcmOptimized::new(&key).unwrap();
        let mut ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();

        ciphertext[0] ^= 1;

        let result = gcm.decrypt(&nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_gcm_optimized_empty_plaintext() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let plaintext = b"";
        let aad = b"Just AAD";

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();

        assert_eq!(ciphertext.len(), 16);

        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_optimized_no_aad() {
        let key = [5u8; 16];
        let nonce = [6u8; 12];
        let plaintext = b"Message without AAD";
        let aad = b"";

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_optimized_long_plaintext() {
        let key = [7u8; 24];
        let nonce = [8u8; 12];
        let plaintext = [9u8; 1000];
        let aad = b"Some AAD";

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, &plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(&plaintext[..], &decrypted[..]);
    }

    #[test]
    fn test_gcm_optimized_different_nonce() {
        let key = [10u8; 16];
        let nonce1 = [11u8; 12];
        let nonce2 = [12u8; 12];
        let plaintext = b"Same plaintext";
        let aad = b"Same AAD";

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext1 = gcm.encrypt(&nonce1, plaintext, aad).unwrap();
        let ciphertext2 = gcm.encrypt(&nonce2, plaintext, aad).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_gcm_optimized_non_standard_nonce_length() {
        let key = [13u8; 16];
        let nonce = [14u8; 16];
        let plaintext = b"Non-standard nonce length test";
        let aad = b"aad";

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_gcm_optimized_matches_gcm_ciphertext() {
        let cases: &[(&[u8], &[u8], &[u8], &[u8])] = &[
            (&[0u8; 16], &[0u8; 12], b"", b""),
            (&[1u8; 16], &[2u8; 12], b"Hello, GCM!", b"Additional data"),
            (&[7u8; 24], &[8u8; 12], &[9u8; 1000], b"Some AAD"),
            (&[0xABu8; 32], &[0xCDu8; 12], b"variable length plaintext data", b""),
        ];

        for (key, nonce, plaintext, aad) in cases {
            let gcm = Gcm::new(key).unwrap();
            let gcm_opt = GcmOptimized::new(key).unwrap();

            let ct1 = gcm.encrypt(nonce, plaintext, aad).unwrap();
            let ct2 = gcm_opt.encrypt(nonce, plaintext, aad).unwrap();

            let ct1_body = &ct1[..ct1.len() - 16];
            let ct2_body = &ct2[..ct2.len() - 16];
            assert_eq!(ct1_body, ct2_body, "CTR keystream mismatch between Gcm and GcmOptimized");
        }
    }

    #[test]
    fn test_ghash_mul_karatsuba_matches_bitwise_ghash_mul() {
        let gcm = Gcm::new(&[0u8; 16]).unwrap();

        let values: &[[u64; 2]] = &[
            [0, 0],
            [u64::MAX, u64::MAX],
            [1, 0],
            [0, 1],
            [0x0102030405060708, 0x090a0b0c0d0e0f10],
            [0xdeadbeefdeadbeef, 0xcafebabecafebabe],
            [0xffffffff00000000, 0x00000000ffffffff],
        ];

        for &x in values {
            for &y in values {
                let expected = gcm.ghash_mul(x, y);
                let actual = GcmOptimized::ghash_mul_karatsuba(&x, &y);
                assert_eq!(actual, expected, "mismatch for x={:x?} y={:x?}", x, y);
            }
        }
    }

    #[test]
    fn test_gcm_optimized_nist_test_case_1() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let expected_tag: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
        ];

        let gcm = GcmOptimized::new(&key).unwrap();
        let ciphertext = gcm.encrypt(&nonce, b"", b"").unwrap();

        assert_eq!(ciphertext.len(), 16);
        assert_eq!(&ciphertext[..], &expected_tag[..]);
    }

    #[test]
    fn test_gcm_optimized_nist_test_case_2() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let expected_ciphertext: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        ];
        let expected_tag: [u8; 16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
            0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
        ];

        let gcm = GcmOptimized::new(&key).unwrap();
        let out = gcm.encrypt(&nonce, &plaintext, b"").unwrap();

        assert_eq!(&out[..16], &expected_ciphertext[..]);
        assert_eq!(&out[16..], &expected_tag[..]);
    }
}