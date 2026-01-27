// crypto/hash/sha2.rs
// Implementations of SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

// SHA-256 round constants
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// SHA-512 round constants
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// SHA-256
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {

    /**
     * Create a new SHA-256 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    self: New SHA-256 instance
     */
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /**
     * Update the SHA-256 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA-256 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing   
     */
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let remaining = 64 - self.buffer_len;
            let to_copy = remaining.min(data.len() - pos);

            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[pos..pos + to_copy]);
            
            self.buffer_len += to_copy;
            pos += to_copy;
            if self.buffer_len == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        self.total_len += data.len() as u64;
    }

    /**
     * Finalize the SHA-256 hash and return the digest
     * Args:
     *    mut self: Mutable SHA-256 instance
     * 
     * Returns:
     *    [u8; 32]: The resulting SHA-256 hash digest
     */
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

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

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let buffer_copy = self.buffer;
        self.process_block(&buffer_copy);

        let mut output = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        output
    }

    /**
     * Process a single 512-bit block
     * Args:
     *    &mut self: Mutable reference to SHA-256 instance
     *    block - &[u8; 64]: 512-bit block to process
     * 
     * Returns:
     *    (): Nothing
     */
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/**
 * Hash data using SHA-256
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 32]: The resulting SHA-256 hash digest
 */
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);

    hasher.finalize()
}

// Implement Default trait for Sha256
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA-224
#[derive(Clone)]
pub struct Sha224 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha224 {

    /**
     * Create a new SHA-224 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New SHA-224 instance
     */
    pub fn new() -> Self {
        Sha224 {
            state: [
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /**
     * Update the SHA-224 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA-224 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let remaining = 64 - self.buffer_len;
            let to_copy = remaining.min(data.len() - pos);

            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[pos..pos + to_copy]);
            
            self.buffer_len += to_copy;
            pos += to_copy;
            if self.buffer_len == 64 {
                process_sha256_block(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }

        self.total_len += data.len() as u64;
    }

    /**
     * Finalize the SHA-224 hash and return the digest
     * Args:
     *    mut self: Mutable SHA-224 instance
     * 
     * Returns:
     *    [u8; 28]: The resulting SHA-224 hash digest
     */
    pub fn finalize(mut self) -> [u8; 28] {
        finalize_sha256_state(&mut self.state, &mut self.buffer, self.buffer_len, self.total_len);

        let mut output = [0u8; 28];
        for i in 0..7 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }

        output
    }
}

/**
 * Hash data using SHA-224
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 28]: The resulting SHA-224 hash digest
 */
pub fn sha224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(data);

    hasher.finalize()
}

// Implement Default trait for Sha224
impl Default for Sha224 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA-512
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    total_len: u128,
}

impl Sha512 {

    /**
     * Create a new SHA-512 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New SHA-512 instance
     */
    pub fn new() -> Self {
        Sha512 {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /**
     * Update the SHA-512 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA-512 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let remaining = 128 - self.buffer_len;
            let to_copy = remaining.min(data.len() - pos);

            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[pos..pos + to_copy]);
            
            self.buffer_len += to_copy;
            pos += to_copy;
            if self.buffer_len == 128 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        self.total_len += data.len() as u128;
    }

    /**
     * Finalize the SHA-512 hash and return the digest
     * Args:
     *    mut self: Mutable SHA-512 instance
     * 
     * Returns:
     *    [u8; 64]: The resulting SHA-512 hash digest
     */
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 112 {
            while self.buffer_len < 128 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }

        while self.buffer_len < 112 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let buffer_copy = self.buffer;
        self.process_block(&buffer_copy);

        let mut output = [0u8; 64];
        for (i, &word) in self.state.iter().enumerate() {
            output[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }

        output
    }

    /**
     * Process a single 1024-bit block
     * Args:
     *    &mut self: Mutable reference to SHA-512 instance
     *    block - &[u8; 128]: 1024-bit block to process
     * 
     * Returns:
     *    (): Nothing
     */
    fn process_block(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Main loop
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/**
 * Hash data using SHA-512
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 64]: The resulting SHA-512 hash digest
 */
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);

    hasher.finalize()
}

// Implement Default trait for Sha512
impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA-384
#[derive(Clone)]
pub struct Sha384 {
    inner: Sha512,
}

impl Sha384 {

    /**
     * Create a new SHA-384 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New SHA-384 instance
     */
    pub fn new() -> Self {
        let mut hasher = Sha512::new();
        hasher.state = [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ];

        Sha384 { inner: hasher }
    }

    /**
     * Update the SHA-384 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA-384 instance
     *    data - &[u8]: Input data to hash
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the SHA-384 hash and return the digest
     * Args:
     *    self: SHA-384 instance
     * 
     * Returns:
     *    [u8; 48]: The resulting SHA-384 hash digest
     */
    pub fn finalize(self) -> [u8; 48] {
        let full_hash = self.inner.finalize();
        let mut output = [0u8; 48];
        output.copy_from_slice(&full_hash[..48]);

        output
    }
}

/**
 * Hash data using SHA-384
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 48]: The resulting SHA-384 hash digest
 */
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);

    hasher.finalize()
}

// Implement Default trait for Sha384
impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

/**
 * Helper for processing SHA-224/256 blocks
 * Args:
 *    state - &mut [u32; 8]: Current hash state
 *    block - &[u8; 64]: 512-bit block to process
 * 
 * Returns:
 *    (): Nothing
 */
fn process_sha256_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/**
 * Helper for finalizing SHA-224/256 state
 * Args:
 *    state - &mut [u32, 8]: Current hash state
 *    buffer - &mut [u8; 64]: Buffer containing remaining data
 *    buffer_len - usize: Length of data in the buffer
 *    total_len - u64: Total length of input data in bytes
 * 
 * Returns:
 *    (): Nothing
 */
fn finalize_sha256_state(state: &mut [u32; 8], buffer: &mut [u8; 64], buffer_len: usize, total_len: u64) {
    let bit_len = total_len * 8;
    let mut temp_buffer_len = buffer_len;

    buffer[temp_buffer_len] = 0x80;
    temp_buffer_len += 1;
    if temp_buffer_len > 56 {
        while temp_buffer_len < 64 {
            buffer[temp_buffer_len] = 0;
            temp_buffer_len += 1;
        }
        process_sha256_block(state, buffer);
        temp_buffer_len = 0;
    }

    while temp_buffer_len < 56 {
        buffer[temp_buffer_len] = 0;
        temp_buffer_len += 1;
    }

    buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
    process_sha256_block(state, buffer);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha256_long() {
        let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected = hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha224_empty() {
        let hash = sha224(b"");
        let expected = hex::decode("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha512_empty() {
        let hash = sha512(b"");
        let expected = hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha512_abc() {
        let hash = sha512(b"abc");
        let expected = hex::decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha384_empty() {
        let hash = sha384(b"");
        let expected = hex::decode("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}