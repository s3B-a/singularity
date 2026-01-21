use super::sha2::{Sha256, Sha512};

#[derive(Clone)]
pub struct Hmac<H> {
    hasher: H,
    outer_hasher: H,
    block_size: usize,
}

impl<H: Clone> Hmac<H> {
    pub fn new(key: &[u8]) -> Self where H: HashFunction + Default {
        let hasher = H::default();
        let block_size = match std::any::type_name::<H>() {
            name if name.contains("Sha256") => 64,
            name if name.contains("Sha512") => 128,
            _ => 64,
        };

        Self::new_with_hasher(hasher, key, block_size)
    }

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

    pub fn update(&mut self, data: &[u8]) where H: HashFunction {
        self.hasher.update(data);
    }

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

pub trait HashFunction: Clone {
    fn update(&mut self, data: &[u8]);
    fn finalize_clone(&mut self) -> Vec<u8>;
    fn reset(&mut self);
}

impl HashFunction for Sha256 {
    fn update(&mut self, data: &[u8]) {
        Sha256::update(self, data);
    }

    fn finalize_clone(&mut self) -> Vec<u8> {
        self.clone().finalize().to_vec()
    }

    fn reset(&mut self) {
        *self = Sha256::new();
    }
}

impl HashFunction for Sha512 {
    fn update(&mut self, data: &[u8]) {
        Sha512::update(self, data);
    }

    fn finalize_clone(&mut self) -> Vec<u8> {
        self.clone().finalize().to_vec()
    }

    fn reset(&mut self) {
        *self = Sha512::new();
    }
}

#[derive(Clone)]
pub struct HmacSha256 {
    inner: Hmac<Sha256>,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        HmacSha256 {
            inner: Hmac::new_with_hasher(Sha256::new(), key, 64),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);

        output
    }

    pub fn verify(self, expected: &[u8]) -> bool {
        self.inner.verify(expected)
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new(key);
    hmac.update(data);

    hmac.finalize()
}

#[derive(Clone)]
pub struct HmacSha512 {
    inner: Hmac<Sha512>,
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        HmacSha512 {
            inner: Hmac::new_with_hasher(Sha512::new(), key, 128),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 64] {
        let result = self.inner.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);

        output
    }

    pub fn verify(self, expected: &[u8]) -> bool {
        self.inner.verify(expected)
    }
}

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
        
        let hmac1 = HmacSha256::new(key);
        hmac1.clone().update(data);
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