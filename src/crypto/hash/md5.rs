// crypto/hash/md5.rs
// Implementation of the MD5 hashing algorithm
// https://www.ietf.org/rfc/rfc1321.txt

// Constant tables for MD5 algorithm
const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

// Constant shift amounts for each round
const S: [[u32; 4]; 4] = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
];

// MD5 struct
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

// MD5 implementation
impl Md5 {

    /**
     * Creates a new MD5 hasher with initial state
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: A new MD5 instance
     */
    pub fn new() -> Self {
        Self {
            state: [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /**
     * Updates the hasher with new data
     * Args:
     *    &mut self: The MD5 instance to update
     *    data - &[u8]: The data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;
        if self.buffer_len > 0 {
            let space_left = 64 - self.buffer_len;
            let to_copy = std::cmp::min(space_left, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
            if self.buffer_len == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.process_block(&block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /**
     * Finalizes the hash and returns the result
     * Args:
     *    mut self: The MD5 hash instance
     * 
     * Returns:
     *    [u8; 16]: The finalized hash
     */
    pub fn finalize(mut self) -> [u8; 16] {
        let msg_len_bits = self.total_len * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }

            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }
        
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        
        self.buffer[56..64].copy_from_slice(&msg_len_bits.to_le_bytes());
        self.process_block(&self.buffer.clone());
        
        let mut result = [0u8; 16];
        for (i, &val) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
        
        result
    }
    
    /**
     * Processes a single 512-bit block of data
     * Args:
     *    &mut self: The MD5 instance
     *    block - &[u8; 64]: The block to process
     * 
     * Returns:
     *    (): Nothing
     */
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        
        // Main loop
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => {
                    let f = (b & c) | ((!b) & d);
                    (f, i)
                },
                16..=31 => {
                    let f = (b & d) | (c & (!d));
                    let g = (5 * i + 1) % 16;
                    (f, g)
                },
                32..=47 => {
                    let f = b ^ c ^ d;
                    let g = (3 * i + 5) % 16;
                    (f, g)
                },
                48..=63 => {
                    let f = c ^ (b | (!d));
                    let g = (7 * i) % 16;
                    (f, g)
                },
                _ => unreachable!(),
            };
            
            let temp = d;
            d = c;
            c = b;
            
            let round = i / 16;
            let shift = S[round][i % 4];
            
            b = b.wrapping_add(
                a.wrapping_add(f).wrapping_add(T[i]).wrapping_add(x[g]).rotate_left(shift)
            );
            
            a = temp;
        }
        
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
    
    /**
     * Resets the hasher to its initial state
     * Args:
     *    &mut self: The current MD5 instance
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn reset(&mut self) {
        self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        self.buffer = [0u8; 64];
        self.buffer_len = 0;
        self.total_len = 0;
    }
}

// Default implementation for Md5
impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

/**
 * Convenience function to hash data using MD5
 * Args:
 *    data - &[u8]: The data to hash
 * 
 * Returns:
 *    [u8; 16]: The resulting MD5 hash
 */
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize()
}

/**
 * Convenience function to hash data using MD5 and return hex string
 * Args:
 *    data - &[u8]: The data to hash
 * 
 * Returns:
 *    String: The resulting MD5 hash as a hexadecimal string
 */
pub fn md5_hex(data: &[u8]) -> String {
    let hash = md5(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/**
 * Convenience function to hash a string using MD5
 * Args:
 *    s - &str: The string to hash
 * 
 * Returns:
 *    [u8; 16]: The resulting MD5 hash
 */
pub fn md5_str(s: &str) -> [u8; 16] {
    md5(s.as_bytes())
}

/**
 * Convenience function to hash a string using MD5 and return hex string
 * Args:
 *    s - &str: The string to hash
 * 
 * Returns:
 *    String: The resulting MD5 hash as a hexadecimal string
 */
pub fn md5_str_hex(s: &str) -> String {
    md5_hex(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_md5_empty() {
        let hash = md5(b"");
        let expected = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
            0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
        ];
        assert_eq!(hash, expected);
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }
    
    #[test]
    fn test_md5_a() {
        let hash = md5(b"a");
        let expected = [
            0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
            0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,
        ];
        assert_eq!(hash, expected);
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
    }
    
    #[test]
    fn test_md5_abc() {
        let hash = md5(b"abc");
        let expected = [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
            0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
        ];
        assert_eq!(hash, expected);
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }
    
    #[test]
    fn test_md5_message_digest() {
        assert_eq!(md5_hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
    }
    
    #[test]
    fn test_md5_alphabet() {
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }
    
    #[test]
    fn test_md5_alphanumeric() {
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }
    
    #[test]
    fn test_md5_long() {
        let input = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        assert_eq!(
            md5_hex(input),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }
    
    #[test]
    fn test_md5_incremental() {
        let mut hasher = Md5::new();
        hasher.update(b"The quick brown fox ");
        hasher.update(b"jumps over ");
        hasher.update(b"the lazy dog");
        
        let result = hasher.finalize();
        let expected = md5(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_md5_reset() {
        let mut hasher = Md5::new();
        hasher.update(b"test");
        hasher.reset();
        hasher.update(b"abc");
        
        let result = hasher.finalize();
        let expected = md5(b"abc");
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_md5_multiple_blocks() {
        let data = b"a".repeat(1000);
        let hash = md5(&data);
        
        let mut hasher = Md5::new();
        for _ in 0..1000 {
            hasher.update(b"a");
        }

        let incremental_hash = hasher.finalize();
        
        assert_eq!(hash, incremental_hash);
    }
    
    #[test]
    fn test_md5_corner_cases() {
        let data55 = b"a".repeat(55);
        let hash55 = md5(&data55);
        assert_eq!(hash55.len(), 16);
        
        let data56 = b"a".repeat(56);
        let hash56 = md5(&data56);
        assert_eq!(hash56.len(), 16);
        
        let data64 = b"a".repeat(64);
        let hash64 = md5(&data64);
        assert_eq!(hash64.len(), 16);
    }
    
    #[test]
    fn test_md5_str_functions() {
        assert_eq!(md5_str_hex("hello"), md5_hex(b"hello"));
        assert_eq!(md5_str("test"), md5(b"test"));
    }
}