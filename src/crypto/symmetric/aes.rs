// crypto/symmetric/aes.rs - Advanced Encryption Standard (AES) implementation
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

use crate::crypto::{Error, Result};

// AES S-box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// AES Inverse S-box
const INVERSE_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// AES Round Constants
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

// Key expansion for AES-128
#[derive(Clone)]
pub struct Aes {
    round_keys: Vec<[u8; 16]>,
    num_rounds: usize,
}

impl Aes {

    /**
     * Creates a new AES instance with the given key
     * Args:
     *    key - &[u8]: The encryption key (16, 24, or 32 bytes for AES 128, 192, or 256)
     * 
     * Returns:
     *    Result<Self>: The AES instance or an error if the key size is invalid
     */
    pub fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Self::new_128(key)),
            24 => Ok(Self::new_192(key)),
            32 => Ok(Self::new_256(key)),
            _ => Err(Error::InvalidKeySize),
        }
    }

    /**
     * Encrypts a single 16-byte block
     * Args:
     *    &self: The AES instance
     *    block - &[u8]: The 16-byte block to encrypt
     * 
     * Returns:
     *    [u8; 16]: The encrypted block
     */
    pub fn encrypt_block(&self, block: &[u8]) -> [u8; 16] {
        assert_eq!(block.len(), 16);
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        add_round_key(&mut state, &self.round_keys[0]);
        for round in 1..self.num_rounds {
            shift_rows(&mut state);
            sub_bytes(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[self.num_rounds]);

        state
    }

    /**
     * Decrypts a single 16-byte block
     * Args:
     *    &self: The AES instance
     *    block - &[u8]: The 16-byte block to decrypt
     * 
     * Returns:
     *    [u8; 16]: The decrypted block
     */
    pub fn decrypt_block(&self, block: &[u8]) -> [u8; 16] {
        assert_eq!(block.len(), 16);
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        add_round_key(&mut state, &self.round_keys[self.num_rounds]);
        for round in (1..self.num_rounds).rev() {
            inverse_shift_rows(&mut state);
            inverse_sub_bytes(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
            inverse_mix_columns(&mut state);
        }

        inverse_shift_rows(&mut state);
        inverse_sub_bytes(&mut state);
        add_round_key(&mut state, &self.round_keys[0]);

        state
    }

    /**
     * Creates a new AES-128 instance
     * Args:
     *    key - &[u8]: The 16-byte encryption key
     * 
     * Returns:
     *    Self: The AES-128 instance
     */
    pub fn new_128(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        let round_keys = key_expansion_128(key);
        Aes {
            round_keys,
            num_rounds: 10,
        }
    }

    /**
     * Creates a new AES-192 instance
     * Args:
     *    key - &[u8]: The 24-byte encryption key
     * 
     * Returns:
     *    Self: The AES-192 instance
     */
    pub fn new_192(key: &[u8]) -> Self {
        assert_eq!(key.len(), 24);
        let round_keys = key_expansion_192(key);
        Aes {
            round_keys,
            num_rounds: 12,
        }
    }

    /**
     * Creates a new AES-256 instance
     * Args:
     *    key - &[u8]: The 32-byte encryption key
     * 
     * Returns:
     *    Self: The AES-256 instance
     */
    pub fn new_256(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let round_keys = key_expansion_256(key);
        Aes {
            round_keys,
            num_rounds: 14,
        }
    }
}

/**
 * Byte substitution using the AES S-box
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 * 
 * Returns:
 *    (): Nothing
 */
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

/**
 * Inverse byte substitution using the AES Inverse S-box
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 * 
 * Returns:
 *    (): Nothing
 */
fn inverse_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INVERSE_SBOX[*byte as usize];
    }
}

/**
 * Shift the rows of the state array to the left
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 * 
 * Returns:
 *    (): Nothing
 */
fn shift_rows(state: &mut [u8; 16]) {
    state.swap(1, 5);
    state.swap(5, 9);
    state.swap(9, 13);

    state.swap(2, 10);
    state.swap(6, 14);

    state.swap(3, 15);
    state.swap(15, 11);
    state.swap(11, 7);
}

/**
 * Inverse shift the rows of the state array to the right
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 * 
 * Returns:
 *    (): Nothing
 */
fn inverse_shift_rows(state: &mut [u8; 16]) {
    state.swap(13, 9);
    state.swap(9, 5);
    state.swap(5, 1);

    state.swap(2, 10);
    state.swap(6, 14);

    state.swap(7, 11);
    state.swap(11, 15);
    state.swap(15, 3);
}

/**
 * Galois field multiplication
 * Args:
 *    a - u8: First byte
 *    b - u8: Second byte
 * 
 * Returns:
 *    u8: The result of the multiplication
 */
fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }

        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b;
        }

        b >>= 1;
    }

    p
}

/**
 * Mixes the columns of the state array
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 * 
 * Returns:
 *    (): Nothing
 */
fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[i * 4];
        let s1 = state[i * 4 + 1];
        let s2 = state[i * 4 + 2];
        let s3 = state[i * 4 + 3];

        state[i * 4] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[i * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

/**
 * Inverse mixes the columns of the state array
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 * 
 * Returns:
 *    (): Nothing
 */
fn inverse_mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[i * 4];
        let s1 = state[i * 4 + 1];
        let s2 = state[i * 4 + 2];
        let s3 = state[i * 4 + 3];

        state[i * 4] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9);
        state[i * 4 + 1] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
        state[i * 4 + 2] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11);
        state[i * 4 + 3] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14);
    }
}

/**
 * Adds the round key to the state array
 * Args:
 *    state - &mut [u8; 16]: The state array to transform
 *    round_key - &[u8; 16]: The round key to add
 * 
 * Returns:
 *    (): Nothing
 */
fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

/**
 * Key expansion for AES-128
 * Args:
 *    key - &[u8]: The 16-byte encryption key
 * 
 * Returns:
 *    Vec<[u8; 16]>: The expanded round keys
 */
fn key_expansion_128(key: &[u8]) -> Vec<[u8; 16]> {
    let mut round_keys = vec![[0u8; 16]; 11];
    round_keys[0].copy_from_slice(key);
    for i in 1..11 {
        let mut temp = [0u8; 4];
        temp.copy_from_slice(&round_keys[i - 1][12..16]);
        temp.rotate_left(1);
        for byte in temp.iter_mut() {
            *byte = SBOX[*byte as usize];
        }

        temp[0] ^= RCON[i];
        for j in 0..4 {
            round_keys[i][j] = round_keys[i - 1][j] ^ temp[j];
        }

        for j in 4..16 {
            round_keys[i][j] = round_keys[i - 1][j] ^ round_keys[i][j - 4];
        }
    }

    round_keys
}

/**
 * Key expansion for AES-192
 * Args:
 *    key - &[u8]: The 24-byte encryption key
 * 
 * Returns:
 *    Vec<[u8; 16]>: The expanded round keys
 */
fn key_expansion_192(key: &[u8]) -> Vec<[u8; 16]> {
    let mut round_keys = vec![[0u8; 16]; 13];
    let mut temp = [0u8; 24];
    temp.copy_from_slice(key);
    for i in 0..13 {
        if i * 16 < 24 {
            let available = 24 - i * 16;
            let to_copy = available.min(16);
            round_keys[i][..to_copy].copy_from_slice(&temp[i * 16..i * 16 + to_copy]);
        }

        if i < 12 {
            let round_offset = (i * 16 + 24) / 24;
            if round_offset < 8 {
                let mut word = [0u8; 4];
                word.copy_from_slice(&temp[20..24]);
                word.rotate_left(1);
                for byte in word.iter_mut() {
                    *byte = SBOX[*byte as usize];
                }

                word[0] ^= RCON[round_offset + 1];
                for j in 0..4 {
                    temp[j] ^= word[j];
                }

                for j in 4..24 {
                    temp[j] ^= temp[j - 4];
                }
            }
        }
    }

    round_keys
}

/**
 * Key expansion for AES-256
 * Args:
 *    key - &[u8]: The 32-byte encryption key
 * 
 * Returns:
 *    Vec<[u8; 16]>: The expanded round keys
 */
fn key_expansion_256(key: &[u8]) -> Vec<[u8; 16]> {
    let mut round_keys = vec![[0u8; 16]; 15];
    round_keys[0].copy_from_slice(&key[0..16]);
    round_keys[1].copy_from_slice(&key[16..32]);
    for i in 2..15 {
        let mut temp = [0u8; 4];
        temp.copy_from_slice(&round_keys[i - 1][12..16]);
        if i % 2 == 0 {
            temp.rotate_left(1);
            for byte in temp.iter_mut() {
                *byte = SBOX[*byte as usize];
            }

            temp[0] ^= RCON[i / 2];
        } else {
            for byte in temp.iter_mut() {
                *byte = SBOX[*byte as usize];
            }
        }

        for j in 0..4 {
            round_keys[i][j] = round_keys[i - 2][j] ^ temp[j];
        }

        for j in 4..16 {
            round_keys[i][j] = round_keys[i - 2][j] ^ round_keys[i][j - 4];
        }
    }

    round_keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_encrypt() {
        let key = [0u8; 16];
        let plaintext = [0u8; 16];
        let aes = Aes::new_128(&key);
        let ciphertext = aes.encrypt_block(&plaintext);

        let expected = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        ];

        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_aes128_decrypt() {
        let key = [0u8; 16];
        let ciphertext = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        ];

        let aes = Aes::new_128(&key);
        let plaintext = aes.decrypt_block(&ciphertext);

        assert_eq!(plaintext, [0u8; 16]);
    }

    #[test]
    fn test_aes_round_trip() {
        let key = b"0123456789abcdef";
        let plaintext = b"Hello, World!!!!";

        let aes = Aes::new(key).unwrap();
        let ciphertext = aes.encrypt_block(plaintext);
        let decrypted = aes.decrypt_block(&ciphertext);

        assert_eq!(&decrypted[..], plaintext);
    }
}