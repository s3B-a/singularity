// ChaCha20 stream cipher implementation
// https://tools.ietf.org/html/rfc8439

use crate::crypto::{Error, Result};

// ChaCha20 constant words
const CONSTANTS: [u32; 4] = [
    0x61707865, // "expa"
    0x3320646e, // "nd 3"
    0x79622d32, // "2-by"
    0x6b206574, // "te k"
];

// Quarter round function
#[derive(Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
    keystream: [u8; 64],
    ks_index: usize,
}

impl ChaCha20 {

    /**
     * Creates a new ChaCha20 cipher instance
     * Args:
     *    key - &[u8]: The 32-byte encryption key
     *    nonce - &[u8]: The 12-byte nonce
     * 
     * Returns:
     *    Result<ChaCha20>: The ChaCha20 cipher instance or an error if parameters are invalid
     */
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        if nonce.len() != 12 {
            return Err(Error::InvalidLength);
        }

        let mut state = [0u32; 16];

        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];

        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        state[12] = 0; // Counter
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        Ok(ChaCha20 {
            state,
            keystream: [0u8; 64],
            ks_index: 64, // Force generation
        })
    }

    /**
     * Generates the next 64-byte keystream block
     * Args:
     *    &mut self: The ChaCha20 instance
     * 
     * Returns:
     *    (): Nothing
     */
    fn generate_keystream(&mut self) {
        let mut working_state = self.state;
        for _ in 0..10 {
            quarter_round(&mut working_state, 0, 4, 8, 12);
            quarter_round(&mut working_state, 1, 5, 9, 13);
            quarter_round(&mut working_state, 2, 6, 10, 14);
            quarter_round(&mut working_state, 3, 7, 11, 15);

            quarter_round(&mut working_state, 0, 5, 10, 15);
            quarter_round(&mut working_state, 1, 6, 11, 12);
            quarter_round(&mut working_state, 2, 7, 8, 13);
            quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }

        for i in 0..16 {
            let bytes = working_state[i].to_le_bytes();
            self.keystream[i * 4] = bytes[0];
            self.keystream[i * 4 + 1] = bytes[1];
            self.keystream[i * 4 + 2] = bytes[2];
            self.keystream[i * 4 + 3] = bytes[3];
        }

        self.state[12] = self.state[12].wrapping_add(1);
    }

    /**
     * Applies the keystream to the given data in place
     * Args:
     *    &mut self: The ChaCha20 instance
     *    data - &mut [u8]: The data to encrypt/decrypt
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.ks_index >= 64 {
                self.generate_keystream();
                self.ks_index = 0;
            }

            *byte ^= self.keystream[self.ks_index];
            self.ks_index += 1;
        }
    }

    /**
     * Encrypts the given plaintext and returns the ciphertext
     * Args:
     *    &mut self: The ChaCha20 instance
     *    plaintext - &mut [u8]: The plaintext to encrypt
     * 
     * Returns:
     *    Vec<u8>: The resulting ciphertext
     */
    pub fn encrypt(&mut self, plaintext: &mut [u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        self.apply_keystream(&mut ciphertext);
        
        ciphertext
    }

    /**
     * Decrypts the given ciphertext and returns the plaintext
     * Args:
     *    &mut self: The ChaCha20 instance
     *    ciphertext - &mut [u8]: The ciphertext to decrypt
     * 
     * Returns:
     *    Vec<u8>: The resulting plaintext
     */
    pub fn decrypt(&mut self, ciphertext: &mut [u8]) -> Vec<u8> {
        let mut plaintext = ciphertext.to_vec();
        self.apply_keystream(&mut plaintext);

        plaintext
    }

    /**
     * Creates a new ChaCha20 cipher instance using Internet Engineering Task Force (IETF) variant
     * Args:
     *    key - &[u8]: The 32-byte encryption key
     *    nonce - &[u8]: The 12-byte nonce
     *    counter - u32: The initial block counter
     * 
     * Returns:
     *    Result<Self>: The ChaCha20 cipher instance or an error if parameters are invalid
     */
    pub fn new_ietf(key: &[u8], nonce: &[u8], counter: u32) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        if nonce.len() != 12 {
            return Err(Error::InvalidLength);
        }

        let mut chacha = Self::new(key, nonce)?;
        chacha.state[12] = counter;

        Ok(chacha)
    }

    /**
     * Seeks to the specified block counter
     * Args:
     *    &mut self: The ChaCha20 instance
     *    counter - u64: The block counter to seek to
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn seek(&mut self, counter: u64) {
        self.state[12] = counter as u32;
        self.ks_index = 64;
    }
}

/**
 * Performs the quarter round operation on the state
 * Args:
 *    state - &mut [u32; 16]: The state array
 *    a - usize: Index a
 *    b - usize: Index b
 *    c - usize: Index c
 *    d - usize: Index d
 * 
 * Returns:
 *    (): Nothing
 */
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

// ChaCha20 Poly1305 AEAD construction
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {

    /**
     * Creates a new ChaCha20Poly1305 instance
     * Args:
     *    key - &[u8]: The 32-byte encryption key
     * 
     * Returns:
     *    Result<Self>: The ChaCha20Poly1305 instance or an error if the key size is invalid
     */
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        Ok(ChaCha20Poly1305 {
            key: key_array,
        })
    }

    /**
     * Encrypts the given platintext with associated data and returns the ciphertext with a tag
     * Args:
     *    &self: The ChaCha20Poly1305 instance
     *    nonce - &[u8]: The 12-byte nonce
     *    plaintext - &[u8]: The plaintext to encrypt
     *    aad - &[u8]: The associated additional data (AAD)
     * 
     * Returns:
     *    Result<Vec<u8>>: The resulting ciphertext with authentication tag or an error
     *    if parameters are invalid
     */
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(Error::InvalidLength);
        }

        let mut poly_key_cipher = ChaCha20::new_ietf(&self.key, nonce, 0)?;
        let mut poly_key = vec![0u8; 32];
        poly_key_cipher.apply_keystream(&mut poly_key);

        let mut cipher = ChaCha20::new_ietf(&self.key, nonce, 1)?;
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        use super::poly1305::Poly1305;
        let mut poly = Poly1305::new(&poly_key)?;

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let padding = vec![0u8; 16 - (aad.len() % 16)];
            poly.update(&padding);
        }

        poly.update(&ciphertext);
        if ciphertext.len() % 16 != 0 {
            let padding = vec![0u8; 16 - (ciphertext.len() % 16)];
            poly.update(&padding);
        }

        let mut lengths = Vec::new();
        lengths.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly.update(&lengths);

        let tag = poly.finalize()?;
        let mut result = ciphertext;
        result.extend_from_slice(&tag);

        Ok(result)
    }

    /**
     * Decrypts the given ciphertext with associated data and verifies the tag
     * Args:
     *    &self: The ChaCha20Poly1305 instance
     *    nonce - &[u8]: The 12-byte nonce
     *    ciphertext_and_tag - &[u8]: The ciphertext with authentication tag
     *    aad - &[u8]: The associated additional data (AAD)
     * 
     * Result:
     *    Result<Vec<u8>>: The resulting plaintext or an error if verification fails
     */
    pub fn decrypt(&self, nonce: &[u8], ciphertext_and_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(Error::InvalidLength);
        }

        if ciphertext_and_tag.len() < 16 {
            return Err(Error::InvalidLength);
        }

        let ciphertext_len = ciphertext_and_tag.len() - 16;
        let ciphertext = &ciphertext_and_tag[..ciphertext_len];
        let received_tag = &ciphertext_and_tag[ciphertext_len..];

        let mut poly_key_cipher = ChaCha20::new_ietf(&self.key, nonce, 0)?;
        let mut poly_key = vec![0u8; 32];
        poly_key_cipher.apply_keystream(&mut poly_key);

        use super::poly1305::Poly1305;
        let mut poly = Poly1305::new(&poly_key)?;

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let padding = vec![0u8; 16 - (aad.len() % 16)];
            poly.update(&padding);
        }

        poly.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            let padding = vec![0u8; 16 - (ciphertext.len() % 16)];
            poly.update(&padding);
        }

        let mut lengths = Vec::new();
        lengths.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        lengths.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly.update(&lengths);

        let computed_tag = poly.finalize()?;
        if !crate::crypto::constant_time_eq(&computed_tag, received_tag) {
            return Err(Error::VerificationFailed);
        }

        let mut cipher = ChaCha20::new_ietf(&self.key, nonce, 1)?;
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

/**
 * Convenience function to encrypt data using ChaCha20
 * Args:
 *    key - &[u8]: The 32-byte encryption key
 *    nonce - &[u8]: The 12-byte nonce
 *    plaintext - &[u8]: The plaintext to encrypt
 * 
 * Returns:
 *    Result<Vec<u8>>: The resulting ciphertext or an error if parameters are invalid
 */
pub fn chacha20_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20::new(key, nonce)?;
    let mut data = plaintext.to_vec();

    Ok(cipher.encrypt(&mut data))
}

/**
 * Convenience function to decrypt data using ChaCha20
 * Args:
 *    key - &[u8]: The 32-byte encryption key
 *    nonce - &[u8]: The 12-byte nonce
 *    ciphertext - &[u8]: The ciphertext to decrypt
 * 
 * Returns:
 *    Result<Vec<u8>>: The resulting plaintext or an error if parameters are invalid
 */
pub fn chacha20_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20::new(key, nonce)?;
    let mut data = ciphertext.to_vec();

    Ok(cipher.decrypt(&mut data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_quarter_round() {
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;

        quarter_round(&mut state, 0, 1, 2, 3);

        assert_eq!(state[0], 0xea2a92f4);
        assert_eq!(state[1], 0xcb1cf8ce);
        assert_eq!(state[2], 0x4581472e);
        assert_eq!(state[3], 0x5881c4bb);
    }

    #[test]
    fn test_chacha20_block() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let mut cipher = ChaCha20::new(&key, &nonce).unwrap();
        cipher.generate_keystream();

        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        ];

        assert_eq!(&cipher.keystream[..16], &expected);
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, ChaCha20!";

        let mut cipher1 = ChaCha20::new(&key, &nonce).unwrap();
        let mut plaintext_mut = plaintext.to_vec();
        let ciphertext = cipher1.encrypt(&mut plaintext_mut);

        let mut cipher2 = ChaCha20::new(&key, &nonce).unwrap();
        let mut ciphertext_mut = ciphertext.clone();
        let decrypted = cipher2.decrypt(&mut ciphertext_mut);

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_chacha20_rfc7539() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let mut cipher = ChaCha20::new_ietf(&key, &nonce, 1).unwrap();
        let mut plaintext_mut = plaintext.to_vec();
        let ciphertext = cipher.encrypt(&mut plaintext_mut);

        let expected = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        ];

        assert_eq!(&ciphertext[..16], &expected);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        let encrypted = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_chacha20_poly1305_tamper() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        let mut encrypted = cipher.encrypt(&nonce, plaintext, aad).unwrap();

        // Tamper with ciphertext
        encrypted[0] ^= 1;

        let result = cipher.decrypt(&nonce, &encrypted, aad);
        assert!(result.is_err());
    }
}