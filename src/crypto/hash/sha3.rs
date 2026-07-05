// crypto/hash/sha3.rs
// Implementations for SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

// Keccak-f[1600] constants
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// Rho offsets
const ROTATIONS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

// Keccak state
#[derive(Clone)]
struct KeccakState {
    state: [u64; 25],
}

impl KeccakState {

    /**
     * Create a new Keccak state initialized to zero
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New KeccakState instance
     */
    fn new() -> Self {
        KeccakState { state: [0u64; 25] }
    }

    /**
     * Perform the Keccak-f[1600] permutation on the state by applying 24 rounds of transformations
     * These transformations include the Theta, Rho, Pi, Chi, and Iota steps
     * 
     * Theta step: Mixes columns of the state
     * Rho step: Rotates bits within lanes
     * Pi step: Permutes the positions of the lanes
     * Chi step: Non-linear mixing of bits within rows
     * Iota step: Adds round constants to the state
     * 
     * Args:
     *    &mut self: Mutable reference to KeccakState instance
     * 
     * Returns:
     *    (): Nothing
     */
    fn permute(&mut self) {
        for round in 0..24 {
            // Theta step
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = self.state[x] ^ self.state[x + 5] ^ self.state[x + 10] 
                     ^ self.state[x + 15] ^ self.state[x + 20];
            }

            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }

            for x in 0..5 {
                for y in 0..5 {
                    self.state[x + 5 * y] ^= d[x];
                }
            }

            // Rho and Pi steps
            let mut b = [0u64; 25];
            b[0] = self.state[0];
            
            let mut x = 1;
            let mut y = 0;
            for i in 0..24 {
                let src = self.state[x + 5 * y].rotate_left(ROTATIONS[i]);
                let tmp = y;
                y = (2 * x + 3 * y) % 5;
                x = tmp;
                b[x + 5 * y] = src;
            }

            // Chi step
            for y in 0..5 {
                let mut t = [0u64; 5];
                for x in 0..5 {
                    t[x] = b[x + 5 * y];
                }
                for x in 0..5 {
                    self.state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
                }
            }

            // Iota step
            self.state[0] ^= RC[round];
        }
    }

    /**
     * Absorb input data into the Keccak state
     * Args:
     *    &mut self: Mutable reference to KeccakState instance
     *    rate_bytes - usize: Rate in bytes
     *    data - &[u8]: Input data to absorb
     * 
     * Returns:
     *    (): Nothing
     */
    fn absorb(&mut self, rate_bytes: usize, data: &[u8]) {
        let rate_words = rate_bytes / 8;
        for chunk in data.chunks(rate_bytes) {
            for (i, block) in chunk.chunks(8).enumerate() {
                if i >= rate_words {
                    break;
                }
                
                let mut word = [0u8; 8];
                word[..block.len()].copy_from_slice(block);
                self.state[i] ^= u64::from_le_bytes(word);
            }
            
            self.permute();
        }
    }

    /**
     * Squeeze output data from the Keccak State
     * Args:
     *    &mut self: Mutable reference to KeccakState instance
     *    rate_bytes - usize: Rate in bytes
     *    output - &mut [u8]: Output buffer to fill with squeezed data
     * 
     * Returns:
     *    (): Nothing
     */
    fn squeeze(&mut self, rate_bytes: usize, output: &mut [u8]) {
        let rate_words = rate_bytes / 8;
        let mut output_pos = 0;
        while output_pos < output.len() {
            for i in 0..rate_words {
                if output_pos >= output.len() {
                    break;
                }

                let word_bytes = self.state[i].to_le_bytes();
                let to_copy = (output.len() - output_pos).min(8);
                output[output_pos..output_pos + to_copy].copy_from_slice(&word_bytes[..to_copy]);
                output_pos += to_copy;
            }

            if output_pos < output.len() {
                self.permute();
            }
        }
    }
}

// Keccak sponge construction
#[derive(Clone)]
struct Keccak {
    state: KeccakState,
    buffer: Vec<u8>,
    rate: usize,
    output_len: usize,
    delim: u8,
}

impl Keccak {

    /**
     * Create a new Keccak sponge instance
     * Args:
     *    rate - usize: Rate in bytes
     *    output_len - usize: Desired output length in bytes
     *    delim - u8: Delimiter byte for padding
     * 
     * Returns:
     *    Self: New Keccak instance
     */
    fn new(rate: usize, output_len: usize, delim: u8) -> Self {
        Keccak {
            state: KeccakState::new(),
            buffer: Vec::new(),
            rate,
            output_len,
            delim,
        }
    }

    /**
     * Update the Keccak state with input data
     * Args:
     *    &mut self: Mutable reference to Keccak instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= self.rate {
            let block: Vec<u8> = self.buffer.drain(..self.rate).collect();
            self.state.absorb(self.rate, &block);
        }
    }

    /**
     * Finalize the Keccak hash and return the digest
     * Args:
     *    &mut self: Mutable reference to Keccak instance
     * 
     * Returns:
     *    Vec<u8>: The resulting hash digest
     */
    fn finalize(&mut self) -> Vec<u8> {
        self.buffer.push(self.delim);
        while self.buffer.len() < self.rate {
            self.buffer.push(0);
        }
        
        let last_idx = self.buffer.len() - 1;
        self.buffer[last_idx] |= 0x80;
        self.state.absorb(self.rate, &self.buffer);

        let mut output = vec![0u8; self.output_len];
        self.state.squeeze(self.rate, &mut output);

        output
    }
}

// SHA3-256
#[derive(Clone)]
pub struct Sha3_256 {
    inner: Keccak,
}

impl Sha3_256 {

    /**
     * Create a new SHA3_256 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Sha3_256 instance
     */
    pub fn new() -> Self {
        Sha3_256 {
            inner: Keccak::new(136, 32, 0x06),
        }
    }

    /**
     * Update the SHA3_256 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA3_256 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the SHA3_256 hash and return the digest
     * Args:
     *    mut self: Mutable reference to SHA3_256 instance
     * 
     * Returns:
     *    [u8; 32]: The resulting SHA3-256 hash digest
     */
    pub fn finalize(mut self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
}

/**
 * Hash data using SHA3-256
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 32]: The resulting SHA3-256 hash digest
 */
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize()
}

// Implement Default trait for Sha3_256
impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA3-224
#[derive(Clone)]
pub struct Sha3_224 {
    inner: Keccak,
}

impl Sha3_224 {
    
    /**
     * Create a new SHA3_224 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Sha3_224 instance
     */
    pub fn new() -> Self {
        Sha3_224 {
            inner: Keccak::new(144, 28, 0x06),
        }
    }

    /**
     * Update the SHA3_224 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA3_224 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the SHA3_224 hash and return the digest
     * Args:
     *    mut self: Mutable reference to SHA3_224 instance
     * 
     * Returns:
     *    [u8; 28]: The resulting SHA3-224 hash digest
     */
    pub fn finalize(mut self) -> [u8; 28] {
        let result = self.inner.finalize();
        let mut output = [0u8; 28];
        output.copy_from_slice(&result);
        output
    }
}

/**
 * Hash data using SHA3-224
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 28]: The resulting SHA3-224 hash digest
 */
pub fn sha3_224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha3_224::new();
    hasher.update(data);
    hasher.finalize()
}

// Implement Default trait for Sha3_224
impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA3-384
#[derive(Clone)]
pub struct Sha3_384 {
    inner: Keccak,
}

impl Sha3_384 {

    /**
     * Create a new SHA3_384 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Sha3_384 instance
     */
    pub fn new() -> Self {
        Sha3_384 {
            inner: Keccak::new(104, 48, 0x06),
        }
    }

    /**
     * Update the SHA3_384 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA3_384 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the SHA3_384 hash and return the digest
     * Args:
     *    mut self: Mutable reference to SHA3_384 instance
     * 
     * Returns:
     *    [u8; 48]: The resulting SHA3-384 hash digest
     */
    pub fn finalize(mut self) -> [u8; 48] {
        let result = self.inner.finalize();
        let mut output = [0u8; 48];
        output.copy_from_slice(&result);
        output
    }
}

/**
 * Hash data using SHA3-384
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 48]: The resulting SHA3-384 hash digest
 */
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    hasher.update(data);
    hasher.finalize()
}

// Implement Default trait for Sha3_384
impl Default for Sha3_384 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA3-512
#[derive(Clone)]
pub struct Sha3_512 {
    inner: Keccak,
}

impl Sha3_512 {

    /**
     * Create a new Sha3_512 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Sha3_512 instance
     */
    pub fn new() -> Self {
        Sha3_512 {
            inner: Keccak::new(72, 64, 0x06),
        }
    }

    /**
     * Update the SHA3_512 state with input data
     * Args:
     *    &mut self: Mutable reference to SHA3_512 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the SHA3_512 hash and return the digest
     * Args:
     *    mut self: Mutable reference to SHA3_512 instance
     * 
     * Returns:
     *    [u8; 64]: The resulting SHA3-512 hash digest
     */
    pub fn finalize(mut self) -> [u8; 64] {
        let result = self.inner.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        output
    }
}

/**
 * Hash data using SHA3-512
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 64]: The resulting SHA3-512 hash digest
 */
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize()
}

// Implement Default trait for Sha3_512
impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

// Keccak-256
#[derive(Clone)]
pub struct Keccak256 {
    inner: Keccak,
}

impl Keccak256 {
    
    /**
     * Create a new Keccak256 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Keccak256 instance
     */
    pub fn new() -> Self {
        Keccak256 {
            inner: Keccak::new(136, 32, 0x01),
        }
    }

    /**
     * Update the Keccak256 state with input data
     * Args:
     *    &mut self: Mutable reference to Keccak256 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the Keccak256 hash and return the digest
     * Args:
     *    mut self: Mutable reference to Keccak256 instance
     * 
     * Returns:
     *    [u8; 32]: The resulting Keccak256 hash digest
     */
    pub fn finalize(mut self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }
}

/**
 * Hash data using Keccak256
 * Args:
 *    data - &[u8]: Input data to hash
 * 
 * Returns:
 *    [u8; 32]: The resulting Keccak256 hash digest
 */
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize()
}

// Implement Default trait for Keccak256
impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}

// SHAKE128
#[derive(Clone)]
pub struct Shake128 {
    inner: Keccak,
}

impl Shake128 {

    /**
     * Create a new Shake128 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Shake128 instance
     */
    pub fn new() -> Self {
        Shake128 {
            inner: Keccak::new(168, 0, 0x1f),
        }
    }

    /**
     * Update the Shake128 state with input data
     * Args:
     *    &mut self: Mutable reference to Shake128 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the Shake128 hash and return the digest
     * Args:
     *    mut self: Mutable reference to Shake128 instance
     *    output_len - usize: Desired output length in bytes
     * 
     * Returns:
     *    Vec<u8>: The resulting hash digest
     */
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.inner.output_len = output_len;
        self.inner.finalize()
    }
}

/**
 * Hash data using SHAKE128
 * Args:
 *    data - &[u8]: Input data to hash
 *    output_len - usize: Desired output length in bytes
 * 
 * Returns:
 *    Vec<u8>: The resulting hash digest
 */
pub fn shake128(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::new();
    hasher.update(data);
    hasher.finalize(output_len)
}

// Implement Default trait for Shake128
impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

// SHAKE256
#[derive(Clone)]
pub struct Shake256 {
    inner: Keccak,
}

impl Shake256 {

    /**
     * Create a new Shake256 instance
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Self: New Shake256 instance
     */
    pub fn new() -> Self {
        Shake256 {
            inner: Keccak::new(136, 0, 0x1f),
        }
    }

    /**
     * Update the Shake256 state with input data
     * Args:
     *    &mut self: Mutable reference to Shake256 instance
     *    data - &[u8]: Input data to hash
     * 
     * Returns:
     *    (): Nothing
     */
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /**
     * Finalize the Shake256 hash and return the digest
     * Args:
     *    mut self: Mutable reference to Shake256 instance
     *    output_len - usize: Desired output length in bytes
     * 
     * Returns:
     *    Vec<u8>: The resulting hash digest
     */
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.inner.output_len = output_len;
        self.inner.finalize()
    }
}

/**
 * Hash data using SHAKE256
 * Args:
 *    data - &[u8]: Input data to hash
 *    output_len - usize: Desired output length in bytes
 * 
 * Returns:
 *    Vec<u8>: The resulting hash digest
 */
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::new();
    hasher.update(data);
    hasher.finalize(output_len)
}

// Implement Default trait for Shake256
impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
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
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        let expected = hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha3_256_abc() {
        let hash = sha3_256(b"abc");
        let expected = hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha3_512_empty() {
        let hash = sha3_512(b"");
        let expected = hex::decode("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha3_224_abc() {
        let hash = sha3_224(b"abc");
        let expected = hex::decode("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha3_384_abc() {
        let hash = sha3_384(b"abc");
        let expected = hex::decode("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        let expected = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_keccak256_vs_sha3_256() {
        let data = b"test";
        let keccak = keccak256(data);
        let sha3 = sha3_256(data);
        assert_ne!(keccak, sha3);
    }

    #[test]
    fn test_shake128() {
        let output = shake128(b"abc", 32);
        assert_eq!(output.len(), 32);
        
        let output_short = shake128(b"abc", 16);
        let output_long = shake128(b"abc", 64);
        assert_eq!(output_short.len(), 16);
        assert_eq!(output_long.len(), 64);
    }

    #[test]
    fn test_shake256() {
        let output = shake256(b"abc", 32);
        assert_eq!(output.len(), 32);
        
        let output_long = shake256(b"abc", 128);
        assert_eq!(output_long.len(), 128);
    }

    #[test]
    fn test_sha3_256_incremental() {
        let data = b"The quick brown fox jumps over the lazy dog";
        
        let hash1 = sha3_256(data);
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"The quick brown fox ");
        hasher.update(b"jumps over the lazy dog");
        let hash2 = hasher.finalize();
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha3_long_input() {
        let data = vec![0xa3; 1_000_000]; // 1 million 'a' characters (0xa3 = 'a' repeated)
        let hash = sha3_256(&data);
        
        assert_eq!(hash.len(), 32);
    }
}