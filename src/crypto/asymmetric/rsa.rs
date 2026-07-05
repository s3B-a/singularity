// crypto/asymmetric/rsa.rs - RSA Asymmetric Cryptography Implemenetation
// https://tools.ietf.org/html/rfc8017

use crate::crypto::{Error, Result};
use crate::crypto::encoding::pem;
use crate::crypto::bignum::{BigNum, MontgomeryContext};
use crate::crypto::hash::sha2::Sha256;
use crate::crypto::random;
use std::cmp::Ordering;
use std::ops::{Add, Sub, Mul, Div};

// RSA Key Sizes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaKeySize {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

// RSA Padding Schemes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaPadding {
    Pkcs1v15,
    OaepSha256,
    PssSha256,
    NoPadding,
}

// RSA Private Key Structure
#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    n: BigNum,
    e: BigNum,
    d: BigNum,
    p: BigNum,
    q: BigNum,
    dp: BigNum,
    dq: BigNum,
    qinv: BigNum,
    size: RsaKeySize,
}

// RSA Public Key Structure
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    n: BigNum,
    e: BigNum,
    size: RsaKeySize,
}

// RSA Private Key Components for serialization and deserialization
#[derive(Clone, Debug)]
pub struct RsaPrivateKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qinv: Vec<u8>,
}

// RSA Public Key Components for serialization and deserialization
#[derive(Clone, Debug)]
pub struct RsaPublicKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl RsaKeySize {

    /**
     * Returns the bit length of the RSA key size
     * Args:
     *    &self: The RsaKeySize instance
     * 
     * Returns:
     *    usize: The bit length of the RSA key size
     */
    pub fn bits(&self) -> usize {
        match self {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        }
    }

    /**
     * Returns the byte length of the RSA key size
     * Args:
     *    &self: The RsaKeySize instance
     * 
     * Returns:
     *    usize: The byte length of the RSA key size
     */
    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }
}

impl RsaPrivateKey {

    /**
     * Generates a new RSA private key with the specified key size
     * Args:
     *    size - RsaKeySize: The desired RSA key size
     * 
     * Returns:
     *    Result<Self>: The generated RsaPrivateKey or an error if generation fails
     */
    pub fn generate(size: RsaKeySize) -> Result<Self> {
        let bits = size.bits();
        let e = BigNum::from_u64(65537);
        
        let (p, q) = generate_rsa_primes(bits / 2, &e)?;
        let n = p.clone().mul(q.clone());
        
        let p_minus_1 = p.clone().sub(BigNum::from_u64(1));
        let q_minus_1 = q.clone().sub(BigNum::from_u64(1));
        
        let phi_n = p_minus_1.clone().mul(q_minus_1.clone());        
        let d = e.mod_inverse(&phi_n)?;
        
        let dp = d.clone().modulo(&p_minus_1);
        let dq = d.clone().modulo(&q_minus_1);
        let qinv = q.mod_inverse(&p)?;
        
        Ok(Self {
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
            size,
        })
    }
    
    /**
     * Returns the corresponding RSA public key
     * Args:
     *    &self: The RsaPrivateKey instance
     * 
     * Returns:
     *    RsaPublicKey: The corresponding RSA public key
     */
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            size: self.size,
        }
    }
    
    /**
     * Decrypts ciphertext using the RSA private key and specified padding
     * Args:
     *    &self: The RsaPrivateKey instance
     *    ciphertext - &[u8]: The ciphertext to decrypt
     *    padding - RsaPadding: The padding scheme to use
     * 
     * Returns:
     *    Result<Vec<u8>>: The decrypted plaintext or an error if decryption fails
     */
    pub fn decrypt(&self, ciphertext: &[u8], padding: RsaPadding) -> Result<Vec<u8>> {
        let c = BigNum::from_bytes_be(ciphertext);
        if c.cmp(&self.n) != Ordering::Less {
            return Err(Error::CryptoError("Ciphertext too large".to_string()));
        }

        let m = rsa_decrypt_crt(&c, &self.p, &self.q, &self.dp, &self.dq, &self.qinv, &self.n)?;
        let key_size = self.size.bytes();
        let m_bytes = big_num_to_fixed_bytes(&m, key_size);
        
        match padding {
            RsaPadding::Pkcs1v15 => unpad_pkcs1v15(&m_bytes, false),
            RsaPadding::OaepSha256 => unpad_oaep_sha256(&m_bytes),
            RsaPadding::NoPadding => Ok(m_bytes),
            _ => Err(Error::CryptoError("Unsupported padding for decryption".to_string())),
        }
    }
    
    /**
     * Signs a message using the RSA private key and specified padding
     * Args:
     *    &self: The RsaPrivateKey instance
     *    message - &[u8]: The message to sign
     *    padding - RsaPadding: The padding scheme to use
     * 
     * Returns:
     *    Result<Vec<u8>>: The signature or an error if signing fails
     */
    pub fn sign(&self, message: &[u8], padding: RsaPadding) -> Result<Vec<u8>> {
        let message_hash = match padding {
            RsaPadding::Pkcs1v15 | RsaPadding::PssSha256 => {
                let mut hasher = Sha256::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            RsaPadding::NoPadding => message.to_vec(),
            _ => return Err(Error::CryptoError("Unsupported padding for signing".to_string())),
        };
        
        let padded = match padding {
            RsaPadding::Pkcs1v15 => {
                pad_pkcs1v15_sign(&message_hash, self.size.bytes())?
            }
            RsaPadding::PssSha256 => {
                pad_pss_sha256(&message_hash, self.size.bytes())?
            }
            RsaPadding::NoPadding => {
                if message.len() > self.size.bytes() {
                    return Err(Error::CryptoError("Message too long".to_string()));
                }
                message.to_vec()
            }
            _ => return Err(Error::CryptoError("Unsupported padding for signing".to_string())),
        };
        
        let m = BigNum::from_bytes_be(&padded);
        let s = rsa_decrypt_crt(&m, &self.p, &self.q, &self.dp, &self.dq, &self.qinv, &self.n)?;
        
        let mut s_bytes = s.to_bytes_be();
        let target_len = self.size.bytes();
        if s_bytes.len() < target_len {
            let mut padded = vec![0u8; target_len - s_bytes.len()];
            padded.extend_from_slice(&s_bytes);
            s_bytes = padded;
        }
        Ok(s_bytes)
    }
    
    /**
     * Converts the RSA private key to its components for serialization
     * Args:
     *    &self: The RsaPrivateKey instance
     * 
     * Returns:
     *    RsaPrivateKeyComponents: The RSA private key components
     */
    pub fn to_components(&self) -> RsaPrivateKeyComponents {
        RsaPrivateKeyComponents {
            n: self.n.to_bytes_be(),
            e: self.e.to_bytes_be(),
            d: self.d.to_bytes_be(),
            p: self.p.to_bytes_be(),
            q: self.q.to_bytes_be(),
            dp: self.dp.to_bytes_be(),
            dq: self.dq.to_bytes_be(),
            qinv: self.qinv.to_bytes_be(),
        }
    }
    
    /**
     * Constructs an RSA private key from its components
     * Args:
     *    components - &RsaPrivateKeyComponents: The RSA private key components
     *    size - RsaKeySize: The RSA key size
     * 
     * Returns:
     *    Result<Self>: The constructed RsaPrivateKey or an error if construction fails
     */
    pub fn from_components(components: &RsaPrivateKeyComponents, size: RsaKeySize) -> Result<Self> {
        Ok(Self {
            n: BigNum::from_bytes_be(&components.n),
            e: BigNum::from_bytes_be(&components.e),
            d: BigNum::from_bytes_be(&components.d),
            p: BigNum::from_bytes_be(&components.p),
            q: BigNum::from_bytes_be(&components.q),
            dp: BigNum::from_bytes_be(&components.dp),
            dq: BigNum::from_bytes_be(&components.dq),
            qinv: BigNum::from_bytes_be(&components.qinv),
            size,
        })
    }
}

impl RsaPublicKey {

    /**
     * Encrypts plaintext using the RSA public key and specified padding
     * Args:
     *    &self: The RsaPublicKey instance
     *    plaintext - &[u8]: The plaintext to encrypt
     *    padding - RsaPadding: The padding scheme to use
     * 
     * Returns:
     *    Result<Vec<u8>>: The encrypted ciphertext or an error if encryption fails
     */
    pub fn encrypt(&self, plaintext: &[u8], padding: RsaPadding) -> Result<Vec<u8>> {
        let padded = match padding {
            RsaPadding::Pkcs1v15 => pad_pkcs1v15_encrypt(plaintext, self.size.bytes())?,
            RsaPadding::OaepSha256 => pad_oaep_sha256(plaintext, self.size.bytes())?,
            RsaPadding::NoPadding => {
                if plaintext.len() > self.size.bytes() {
                    return Err(Error::CryptoError("Plaintext too long".to_string()));
                }
                plaintext.to_vec()
            }
            _ => return Err(Error::CryptoError("Unsupported padding for encryption".to_string())),
        };
        
        let m = BigNum::from_bytes_be(&padded);
        if m.cmp(&self.n) != Ordering::Less {
            return Err(Error::CryptoError("Message too large".to_string()));
        }
        
        let c = m.mod_exp_montgomery(&self.e, &self.n)?;
        Ok(big_num_to_fixed_bytes(&c, self.size.bytes()))
    }
    
    /**
     * Verifies a signature using the RSA public key and specified padding
     * Args:
     *    &self: The RsaPublicKey instance
     *    message - &[u8]: The original message
     *    signature - &[u8]: The signature to verify
     *    padding - RsaPadding: The padding scheme to use
     * 
     * Returns:
     *    Result<bool>: True if the signature is valid, false otherwise
     */
    pub fn verify(&self, message: &[u8], signature: &[u8], padding: RsaPadding) -> Result<bool> {
        if signature.len() != self.size.bytes() {
            return Ok(false);
        }
        
        let message_hash = match padding {
            RsaPadding::Pkcs1v15 | RsaPadding::PssSha256 => {
                let mut hasher = Sha256::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            RsaPadding::NoPadding => message.to_vec(),
            _ => return Err(Error::CryptoError("Unsupported padding for verification".to_string())),
        };
        
        let s = BigNum::from_bytes_be(signature);
        if s.cmp(&self.n) != Ordering::Less {
            return Ok(false);
        }
        
        let m = s.mod_exp_montgomery(&self.e, &self.n)?;
        let mut m_bytes = m.to_bytes_be();
        let target_len = self.size.bytes();
        if m_bytes.len() < target_len {
            let mut padded = vec![0u8; target_len - m_bytes.len()];
            padded.extend_from_slice(&m_bytes);
            m_bytes = padded;
        }
        match padding {
            RsaPadding::Pkcs1v15 => {
                verify_pkcs1v15_sign(&m_bytes, &message_hash)
            }
            RsaPadding::PssSha256 => {
                verify_pss_sha256(&m_bytes, &message_hash)
            }
            RsaPadding::NoPadding => {
                Ok(m_bytes == message)
            }
            _ => Err(Error::CryptoError("Unsupported padding for verification".to_string())),
        }
    }
    
    /**
     * Converts the RSA public key to its components for serialization
     * Args:
     *    &self: The RsaPublicKey instance
     * 
     * Returns:
     *    RsaPublicKeyComponents: The RSA public key components
     */
    pub fn to_components(&self) -> RsaPublicKeyComponents {
        RsaPublicKeyComponents {
            n: self.n.to_bytes_be(),
            e: self.e.to_bytes_be(),
        }
    }
    
    /**
     * Constructs an RSA public key from its components
     * Args:
     *    components - &RsaPublicKeyComponents: The RSA public key components
     *    size - RsaKeySize: The RSA key size
     * 
     * Returns:
     *    Result<Self>: The constructed RsaPublicKey or an error if construction fails
     */
    pub fn from_components(components: &RsaPublicKeyComponents, size: RsaKeySize) -> Result<Self> {
        Ok(Self {
            n: BigNum::from_bytes_be(&components.n),
            e: BigNum::from_bytes_be(&components.e),
            size,
        })
    }

    /**
     * Constructs an RSA public key from DER-encoded bytes
     * Args:
     *    der - &[u8]: The DER-encoded public key bytes
     * 
     * Returns:
     *    Result<Self>: The constructed RsaPublicKey or an error if construction fails
     */
    pub fn from_bytes(der: &[u8]) -> Result<Self> {
        let mut index = 0;
        if der[index] != 0x30 {
            return Err(Error::CryptoError("Invalid DER format".to_string()));
        }

        index += 1;
        let _len = der[index] as usize;
        index += 1;
        if der[index] != 0x02 {
            return Err(Error::CryptoError("Invalid DER format".to_string()));
        }

        index += 1;
        let n_len = der[index] as usize;
        index += 1;
        let n_bytes = &der[index..index + n_len];
        index += n_len;
        if der[index] != 0x02 {
            return Err(Error::CryptoError("Invalid DER format".to_string()));
        }
        
        index += 1;
        let e_len = der[index] as usize;
        index += 1;
        let e_bytes = &der[index..index + e_len];

        let n = BigNum::from_bytes_be(n_bytes);
        let e = BigNum::from_bytes_be(e_bytes);
        let size = match n.bit_length() {
            2048 => RsaKeySize::Rsa2048,
            3072 => RsaKeySize::Rsa3072,
            4096 => RsaKeySize::Rsa4096,
            _ => return Err(Error::CryptoError("Unsupported RSA key size".to_string())),
        };

        Ok(Self { n, e, size })
    }

    /**
     * Converts the RSA public key to DER-encoded bytes
     * Args:
     *    &self: The RsaPublicKey instance
     * 
     * Returns:
     *    Vec<u8>: The DER-encoded public key bytes
     */
    pub fn to_der(&self) -> Vec<u8> {
        let n_bytes = self.n.to_bytes_be();
        let e_bytes = self.e.to_bytes_be();
        
        let mut der = Vec::new();
        der.push(0x30);
        der.push((2 + n_bytes.len() + 2 + e_bytes.len()) as u8);
        der.push(0x02);
        der.push(n_bytes.len() as u8);
        der.extend_from_slice(&n_bytes);
        der.push(0x02);
        der.push(e_bytes.len() as u8);
        der.extend_from_slice(&e_bytes);
        
        der
    }

    /**
     * Constructs an RSA public key from DER-encoded bytes
     * Args:
     *    der - &[u8]: The DER-encoded public key bytes
     * 
     * Returns:
     *    Result<Self>: The constructed RsaPublicKey or an error if construction fails
     */
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_bytes(der)
    }

    /**
     * Converts the RSA public key to a PEM-encoded string
     * Args:
     *    &self: The RsaPublicKey instance
     * 
     * Returns:
     *    String: The PEM-encoded public key string
     */
    pub fn to_pem(&self) -> String {
        let der = self.to_der();
        let b64 = pem::encode(&der);
        let mut pem = String::new();
        pem.push_str("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }

        pem.push_str("-----END PUBLIC KEY-----\n");
        
        pem
    }

    /**
     * Constructs an RSA public key from a PEM-encoded string
     * Args:
     *    pem_str - &str: The PEM-encoded public key string
     * 
     * Returns:
     *    Result<Self>: The constructed RsaPublicKey or an error if construction fails
     */
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let b64 = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let der = pem::decode(&b64)?;
        Self::from_bytes(&der)
    }

    /**
     * Verifies a PSS signature using the RSA public key and SHA-256 hash
     * Args:
     *    &self: The RsaPublicKey instance
     *    message_hash - &[u8]: The SHA-256 hash of the original message
     *    signature - &[u8]: The PSS signature to verify
     * 
     * Returns:
     *    Result<bool>: True if the signature is valid, false otherwise
     */
    pub fn verify_pss(&self, message_hash: &[u8], signature: &[u8]) -> Result<bool> {
        let s = BigNum::from_bytes_be(signature);
        if s.cmp(&self.n) != Ordering::Less {
            return Ok(false);
        }
        
        let m = s.mod_exp_montgomery(&self.e, &self.n)?;
        let mut m_bytes = m.to_bytes_be();
        let target_len = self.size.bytes();
        if m_bytes.len() < target_len {
            let mut padded = vec![0u8; target_len - m_bytes.len()];
            padded.extend_from_slice(&m_bytes);
            m_bytes = padded;
        }
        
        verify_pss_sha256(&m_bytes, message_hash)
    }
}

/**
 * Computes the greatest common divisor (GCD) of two BigNums
 * Args:
 *    a - &BigNum: The first BigNum
 *    b - &BigNum: The second BigNum
 * 
 * Returns:
 *    BigNum: The GCD of a and b
 */
pub fn generate_rsa_primes(bits: usize, e: &BigNum) -> Result<(BigNum, BigNum)> {
    let p = generate_prime(bits, e)?;
    let q = loop {
        let candidate = generate_prime(bits, e)?;
        if p.cmp(&candidate) != Ordering::Equal {
            break candidate;
        }
    };
    
    Ok((p, q))
}

/**
 * Generates a prime number of specified bit length
 * Args:
 *    bits - usize: The bit length of the prime to generate
 *    e - &BigNum: The public exponent
 * 
 * Returns:
 *    Result<BigNum>: The generated prime number or an error if generation fails
 */
fn generate_prime(bits: usize, e: &BigNum) -> Result<BigNum> {
    let bytes = (bits + 7) / 8;
    let prime_rounds = if bits < 512 { 6 } else if bits < 1024 { 8 } else { 8 };
    let two = BigNum::from_u64(2);
    const SMALL_PRIMES: [u64; 232] = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
        479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
        557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
        613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
        673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
        743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
        821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
        881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
        953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
        1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
        1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
        1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
        1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297,
        1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381,
        1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453,
        1459, 1471,
    ];

    let mut candidate_bytes = vec![0u8; bytes];
    random::fill_random(&mut candidate_bytes)?;
    candidate_bytes[0] |= 0x80;
    candidate_bytes[bytes - 1] |= 0x01;
    let mut candidate = BigNum::from_bytes_be(&candidate_bytes);
    if candidate.is_even() {
        candidate = candidate + &two;
    }

    loop {
        let mut composite = false;
        for &p in &SMALL_PRIMES {
            if mod_u64(&candidate, p) == 0 {
                composite = true;
                break;
            }
        }

        if !composite {
            let candidate_minus_1 = candidate.clone() - BigNum::one();
            if gcd(&candidate_minus_1, e) == BigNum::one() {
                if is_probably_prime(&candidate, prime_rounds)? {
                    return Ok(candidate);
                }
            }
        }

        candidate = candidate + &two;
        if candidate.bit_length() > bits {
            random::fill_random(&mut candidate_bytes)?;
            candidate_bytes[0] |= 0x80;
            candidate_bytes[bytes - 1] |= 0x01;
            candidate = BigNum::from_bytes_be(&candidate_bytes);
            if candidate.is_even() {
                candidate = candidate + &two;
            }
        }
    }

    Err(Error::CryptoError("Prime generation failed".to_string()))
}

/**
 * Performs a test to determine if a BigNum is probably prime 
 * using a combination of trial division and Miller-Rabin tests
 * Args:
 *    n - &BigNum: The number to test for primality
 *    rounds - usize: The number of Miller-Rabin rounds to perform for larger numbers
 * 
 * Returns:
 *    Result<bool>: True if n is probably prime, false if composite or an error if the test fails
 */
fn is_probably_prime(n: &BigNum, rounds: usize) -> Result<bool> {
    if n <= &BigNum::one() {
        return Ok(false);
    }

    if n == &BigNum::from_u64(2) || n == &BigNum::from_u64(3) {
        return Ok(true);
    }

    if n.is_even() {
        return Ok(false);
    }

    const SMALL_PRIMES: [u64; 49] = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229,
    ];

    for &p in &SMALL_PRIMES {
        if n == &BigNum::from_u64(p) {
            return Ok(true);
        }
    }

    if n.limbs.len() == 1 {
        return Ok(is_probably_prime_deterministic_64bit(n.limbs[0]));
    }

    if n.limbs.len() <= 2 {
        return Ok(miller_rabin_deterministic(n));
    }

    let bit_length = n.bit_length();
    let adaptive_rounds = if bit_length < 512 { 
        6
    } else if bit_length < 1024 { 
        8
    } else {
        8
    };

    let effective_rounds = if rounds == 0 { adaptive_rounds } else { rounds };

    Ok(miller_rabin_probabilistic(n, effective_rounds))
}

/**
 * Computes the modulus of a BigNum with a u64 integer
 * Args:
 *    n - &BigNum: The BigNum to compute the modulus of
 *    m - u64: The modulus
 * 
 * Returns:
 *    u64: The result of n mod m
 */
fn mod_u64(n: &BigNum, m: u64) -> u64 {
    if m == 0 {
        return 0;
    }

    let mut rem: u128 = 0;
    for &limb in n.limbs.iter().rev() {
        rem = ((rem << 64) + limb as u128) % (m as u128);
    }

    rem as u64
}

/**
 * Computes the greatest common divisor (GCD) of two u64 integers
 * Args:
 *    a - u64: The first integer
 *    b - u64: The second integer
 * 
 * Returns:
 *    u64: The GCD of a and b
 */
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }

    a
}

/**
 * Performs a deterministic Miller-Rabin primality test for 64-bit integers
 * Args:
 *    n - u64: The number to test for primality
 * 
 * Returns:
 *    bool: True if n is probably prime, false if composite
 */
fn is_probably_prime_deterministic_64bit(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }

    let witnesses: &[u64] = &[2, 3, 5, 7, 11, 13, 17];
    let n_minus_1 = n - 1;
    let mut r = 0;
    let mut d = n_minus_1;
    while d % 2 == 0 {
        d /= 2;
        r += 1;
    }

    'witness_loop: for &witness in witnesses {
        if witness >= n {
            continue;
        }

        let witness_bn = BigNum::from_u64(witness);
        let n_bn = BigNum::from_u64(n);
        let d_bn = BigNum::from_u64(d);

        let mut x = witness_bn.mod_exp(&d_bn, &n_bn).unwrap_or(BigNum::one());
        if x.is_one() || x == (n_bn.clone() - BigNum::one()) {
            continue 'witness_loop;
        }

        let mut composite = true;
        for _ in 0..(r - 1) {
            x = (&x * &x).modulo(&n_bn);
            if x == (n_bn.clone() - BigNum::one()) {
                composite = false;
                break;
            }
        }

        if composite {
            return false;
        }
    }

    true
}

/**
 * Performs the Miller-Rabin primality test, this is done by checking whether n is probably prime
 * Args:
 *    n - &BigNum: The number to test for primality
 *    rounds - usize: The number of rounds to perform
 * 
 * Returns:
 *    bool: True if n is probably prime, false if composite
 */
fn miller_rabin(n: &BigNum, rounds: usize) -> bool {
    if n.is_zero() || n.cmp(&BigNum::from_u64(1)) == Ordering::Equal {
        return false;
    }

    if n.cmp(&BigNum::from_u64(2)) == Ordering::Equal {
        return true;
    }
    
    let one = BigNum::from_u64(1);
    let n_minus_1 = n.sub(&one);
    let (r, d) = factor_power_of_two(&n_minus_1);
    'witness: for _ in 0..rounds {
        let a = random_range(&BigNum::from_u64(2), &n_minus_1).unwrap_or(BigNum::from_u64(2));
        let mut x = match a.mod_exp_montgomery(&d, n) {
            Ok(val) => val,
            Err(_) => return false,
        };
        
        if x.cmp(&one) == Ordering::Equal || x.cmp(&n_minus_1) == Ordering::Equal {
            continue 'witness;
        }
        
        for _ in 0..r {
            x = (&x * &x).modulo(n);
            if x.cmp(&n_minus_1) == Ordering::Equal {
                continue 'witness;
            }
        }
        
        return false;
    }
    
    true
}

/**
 * Performs modular exponentiation using Montgomery multiplication with a given context
 * Args:
 *    base - &BigNum: The base for exponentiation
 *    exp - &BigNum: The exponent for exponentiation
 *    ctx - &MontgomeryContext: The Montgomery context for modular arithmetic
 * 
 * Returns:
 *    BigNum: The result of (base^exp) mod n, where n is the modulus in the Montgomery context
 */
fn mod_exp_montgomery_ctx(base: &BigNum, exp: &BigNum, ctx: &MontgomeryContext) -> BigNum {
    let bit_length = exp.bit_length();
    if bit_length == 0 {
        return BigNum::one();
    }
    
    let base_mont = ctx.to_montgomery(base);
    let mut result = ctx.to_montgomery(&BigNum::one());
    for i in (0..bit_length).rev() {
        result = ctx.multiply(&result, &result);
        if exp.get_bit(i) {
            result = ctx.multiply(&result, &base_mont);
        }
    }
    
    ctx.from_montgomery(&result)
}

/**
 * Performs a deterministic Miller-Rabin primality test for BigNums up to 64 bits
 * Args:
 *    n - &BigNum: The number to test for primality
 * 
 * Returns:
 *    bool: True if n is probably prime, false if composite
 */
fn miller_rabin_deterministic(n: &BigNum) -> bool {
    if n <= &BigNum::one() { return false; }

    let witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    let n_minus_1 = n - &BigNum::one();
    let (r, d) = factor_power_of_two(&n_minus_1);
    if r == 0 { return false; }

    let ctx = match MontgomeryContext::new(n) {
        Ok(ctx) => ctx,
        Err(_) => return false,
    };
    let one_mont = ctx.to_montgomery(&BigNum::one());
    let n_minus_1_mont = ctx.to_montgomery(&n_minus_1);

    'witness_loop: for &witness in &witnesses {
        if BigNum::from_u64(witness) >= *n { continue; }

        let a = BigNum::from_u64(witness);
        let mut x = mod_exp_montgomery_ctx_mont(&a, &d, &ctx);

        if x == one_mont || x == n_minus_1_mont {
            continue 'witness_loop;
        }

        let mut found = false;
        for _ in 0..(r - 1) {
            x = ctx.multiply(&x, &x);
            if x == n_minus_1_mont {
                found = true;
                break;
            }
        }

        if !found {
            return false;
        }
    }

    true
}

/**
 * Performs a probabilistic Miller-Rabin primality test for BigNums larger than 64 bits
 * Args:
 *    n - &BigNum: The number to test for primality
 *    rounds - usize: The number of rounds to perform
 * 
 * Returns:
 *    bool: True if n is probably prime, false if composite
 */
fn miller_rabin_probabilistic(n: &BigNum, rounds: usize) -> bool {
    let one = BigNum::one();
    let n_minus_1 = n - &one;
    let (r, d) = factor_power_of_two(&n_minus_1);
    if r == 0 {
        return false;
    }

    let ctx = match MontgomeryContext::new(n) {
        Ok(ctx) => ctx,
        Err(_) => return false,
    };

    let one_mont = ctx.to_montgomery(&one);
    let n_minus_1_mont = ctx.to_montgomery(&n_minus_1);
    let two = BigNum::from_u64(2);
    for _ in 0..rounds {
        let a = match random_range(&two, &n_minus_1) {
            Ok(val) => val,
            Err(_) => return false,
        };

        let mut x = mod_exp_montgomery_ctx_mont(&a, &d, &ctx);
        if x == one_mont || x == n_minus_1_mont {
            continue;
        }

        let mut found_n_minus_1 = false;
        for _ in 0..(r - 1) {
            x = ctx.multiply(&x, &x);
            if x == n_minus_1_mont {
                found_n_minus_1 = true;
                break;
            }
        }

        if !found_n_minus_1 {
            return false;
        }
    }

    true
}

fn mod_exp_montgomery_ctx_mont(base: &BigNum, exp: &BigNum, ctx: &MontgomeryContext) -> BigNum {
    let bit_length = exp.bit_length();
    if bit_length == 0 {
        return ctx.to_montgomery(&BigNum::one());
    }
    
    let base_mont = ctx.to_montgomery(base);
    let mut result = ctx.to_montgomery(&BigNum::one());
    for i in (0..bit_length).rev() {
        result = ctx.multiply(&result, &result);
        if exp.get_bit(i) {
            result = ctx.multiply(&result, &base_mont);
        }
    }
    
    result
}

/**
 * Factors out powers of two from a BigNum
 * Args:
 *    n - &BigNum: The BigNum to factor
 * 
 * Returns:
 *    (usize, BigNum): A tuple containing the exponent of the power of two and the odd component
 */
fn factor_power_of_two(n: &BigNum) -> (usize, BigNum) {
    let r = n.trailing_zeros();
    if r == 0 {
        return (0, n.clone());
    }

    let d = n >> r;
    (r, d)
}

/**
 * Generates a random BigNum in the range [min, max)
 * Args:
 *    min - &BigNum: The minimum value (inclusive)
 *    max - &BigNum: The maximum value (exclusive)
 * 
 * Returns:
 *    Result<BigNum>: A random BigNum in the specified range or an error if generation fails
 */
fn random_range(min: &BigNum, max: &BigNum) -> Result<BigNum> {
    let range = max - min;
    let num_bytes = range.to_bytes_be().len();
    loop {
        let mut random_bytes = vec![0u8; num_bytes];
        random::fill_random(&mut random_bytes)?;
        let r = BigNum::from_bytes_be(&random_bytes);
        if r < range {
            return Ok(r + min);
        }
    }
}

/**
 * Decrypts ciphertext using RSA CRT optimization
 * Args:
 *    c - &BigNum: The ciphertext
 *    p - &BigNum: The prime p
 *    q - &BigNum: The prime q
 *    dp - &BigNum: d mod (p-1)
 *    dq - &BigNum: d mod (q-1)
 *    qinv - &BigNum: q^(-1) mod p
 *    n - &BigNum: The modulus n
 * 
 * Returns:
 *    Result<BigNum>: The decrypted plaintext or an error if decryption fails
 */
fn rsa_decrypt_crt(c: &BigNum, p: &BigNum, q: &BigNum, dp: &BigNum, dq: &BigNum, qinv: &BigNum, n: &BigNum) -> Result<BigNum> {
    let m1 = c.mod_exp_montgomery(dp, p)?;
    let m2 = c.mod_exp_montgomery(dq, q)?;
    
    let diff = if m1 >= m2 {
        &m1 - &m2
    } else {
        p + &m1 - &m2
    };
    let h = (&diff * qinv).modulo(p);
    let mut m = &m2 + &(&h * q);
    
    if m >= *n {
        m = &m - n;
    }
    
    Ok(m)
}

/**
 * Pads data using PKCS#1 v1.5 for encryption
 * Args:
 *    data - &[u8]: The data to pad
 *    key_size - usize: The RSA key size in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The padded data or an error if padding fails
 */
fn pad_pkcs1v15_encrypt(data: &[u8], key_size: usize) -> Result<Vec<u8>> {
    if data.len() > key_size - 11 {
        return Err(Error::CryptoError("Data too long for PKCS#1 v1.5 padding".to_string()));
    }
    
    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x02;
    let ps_len = key_size - data.len() - 3;
    let ps = &mut padded[2..2 + ps_len];
    for _ in 0..100 {
        random::fill_random(ps)?;
        if !ps.iter().any(|&b| b == 0) {
            break;
        }
    }

    for b in ps.iter_mut() {
        if *b == 0 { *b = 0x01; }
    }

    padded[2 + ps_len] = 0x00;
    padded[2 + ps_len + 1..].copy_from_slice(data);
    Ok(padded)
}

/**
 * Unpads data using PKCS#1 v1.5
 * Args:
 *    data - &[u8]: The padded data
 *    is_sign - bool: True if unpadding for signature, false for encryption
 * 
 * Returns:
 *    Result<Vec<u8>>: The unpadded data or an error if unpadding fails
 */
fn unpad_pkcs1v15(data: &[u8], is_sign: bool) -> Result<Vec<u8>> {
    if data.len() < 11 {
        return Err(Error::CryptoError("Invalid PKCS#1 v1.5 padding".to_string()));
    }
    
    if data[0] != 0x00 {
        return Err(Error::CryptoError("Invalid PKCS#1 v1.5 padding".to_string()));
    }
    
    let expected_type = if is_sign { 0x01 } else { 0x02 };
    if data[1] != expected_type {
        return Err(Error::CryptoError("Invalid PKCS#1 v1.5 padding type".to_string()));
    }
    
    let mut separator_idx = None;
    for i in 2..data.len() {
        if data[i] == 0x00 {
            separator_idx = Some(i);
            break;
        }
    }
    
    let separator_idx = separator_idx
        .ok_or_else(|| Error::CryptoError("Invalid PKCS#1 v1.5 padding".to_string()))?;
    
    if separator_idx < 10 {
        return Err(Error::CryptoError("Invalid PKCS#1 v1.5 padding length".to_string()));
    }
    
    Ok(data[separator_idx + 1..].to_vec())
}

/**
 * Pads a hash using PKCS#1 v1.5 for signing
 * Args:
 *    hash - &[u8]: The hash to pad
 *    key_size - usize: The RSA key size in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The padded hash or an error if padding fails
 */
fn pad_pkcs1v15_sign(hash: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let digest_info = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    ];
    
    let t_len = digest_info.len() + hash.len();
    if t_len > key_size - 11 {
        return Err(Error::CryptoError("Hash too long for key size".to_string()));
    }
    
    let ps_len = key_size - t_len - 3;
    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x01;
    for i in 0..ps_len {
        padded[2 + i] = 0xff;
    }
    
    padded[2 + ps_len] = 0x00;
    padded[3 + ps_len..3 + ps_len + digest_info.len()].copy_from_slice(&digest_info);
    padded[3 + ps_len + digest_info.len()..].copy_from_slice(hash);
    
    Ok(padded)
}

/**
 * Verifies a PKCS#1 v1.5 signed hash
 * Args:
 *    padded - &[u8]: The padded signature
 *    hash - &[u8]: The original hash
 * 
 * Returns:
 *    Result<bool>: True if the signature is valid, false otherwise
 */
fn verify_pkcs1v15_sign(padded: &[u8], hash: &[u8]) -> Result<bool> {
    let digest_info = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    ];
    
    if padded.len() < digest_info.len() + hash.len() + 11 {
        return Ok(false);
    }
    
    if padded[0] != 0x00 || padded[1] != 0x01 {
        return Ok(false);
    }
    
    let mut separator_idx = None;
    for i in 2..padded.len() {
        if padded[i] == 0x00 {
            separator_idx = Some(i);
            break;
        } else if padded[i] != 0xff {
            return Ok(false);
        }
    }
    
    let separator_idx = match separator_idx {
        Some(idx) => idx,
        None => return Ok(false),
    };
    
    if separator_idx < 10 {
        return Ok(false);
    }
    
    let start = separator_idx + 1;
    if start + digest_info.len() + hash.len() != padded.len() {
        return Ok(false);
    }
    
    Ok(&padded[start..start + digest_info.len()] == &digest_info[..]
        && &padded[start + digest_info.len()..] == hash)
}

/**
 * Mask Generation Function 1 (MGF1) using SHA-256
 * Args:
 *    seed - &[u8]: The seed for MGF1
 *    mask_len - usize: The desired length of the mask
 * 
 * Returns:
 *    Vec<u8>: The generated mask
 */
fn pad_oaep_sha256(data: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let hash_len = 32;
    let max_data_len = key_size - 2 * hash_len - 2;
    if data.len() > max_data_len {
        return Err(Error::CryptoError("Data too long for OAEP".to_string()));
    }

    let l_hash = Sha256::new().finalize();
    let ps_len = key_size - data.len() - 2 * hash_len - 2;
    let mut db = Vec::with_capacity(hash_len + ps_len + 1 + data.len());
    db.extend_from_slice(&l_hash);
    db.extend(vec![0u8; ps_len]);
    db.push(0x01);
    db.extend_from_slice(data);

    let mut seed = vec![0u8; hash_len];
    random::fill_random(&mut seed)?;

    let db_mask = mgf1_sha256(&seed, db.len());
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    let seed_mask = mgf1_sha256(&masked_db, hash_len);
    let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    let mut em = vec![0u8; key_size];
    em[0] = 0x00;
    em[1..1 + hash_len].copy_from_slice(&masked_seed);
    em[1 + hash_len..].copy_from_slice(&masked_db);

    Ok(em)
}

/**
 * Mask Generation Function 1 (MGF1) using SHA-256
 * Args:
 *    seed - &[u8]: The seed for MGF1
 *    mask_len - usize: The desired length of the mask
 * 
 * Returns:
 *    Vec<u8>: The generated mask
 */
fn unpad_oaep_sha256(data: &[u8]) -> Result<Vec<u8>> {
    let hash_len = 32;
    if data.len() < 2 * hash_len + 2 || data[0] != 0x00 {
        return Err(Error::CryptoError("Invalid OAEP padding".to_string()));
    }

    let masked_seed = &data[1..1 + hash_len];
    let masked_db = &data[1 + hash_len..];
    let seed_mask = mgf1_sha256(masked_db, hash_len);
    let seed: Vec<u8> = masked_seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    let db_mask = mgf1_sha256(&seed, masked_db.len());
    let db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    let l_hash = Sha256::new().finalize();
    if &db[..hash_len] != &l_hash[..] {
        return Err(Error::CryptoError("Invalid OAEP padding".to_string()));
    }

    let mut sep = None;
    for i in hash_len..db.len() {
        if db[i] == 0x01 {
            sep = Some(i);
            break;
        } else if db[i] != 0x00 {
            return Err(Error::CryptoError("Invalid OAEP padding".to_string()));
        }
    }

    let sep = sep.ok_or_else(|| Error::CryptoError("Invalid OAEP padding".to_string()))?;

    Ok(db[sep + 1..].to_vec())
}

/**
 * Pads a hash using PSS with SHA-256
 * Args:
 *    hash - &[u8]: The hash to pad
 *    key_size - usize: The RSA key size in bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The padded hash or an error if padding fails
 */
fn pad_pss_sha256(hash: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let hash_len = 32;
    let s_len = hash_len;
    if key_size < hash_len + s_len + 2 {
        return Err(Error::CryptoError("Key too short for PSS".to_string()));
    }
    
    let mut salt = vec![0u8; s_len];
    random::fill_random(&mut salt)?;
    
    let mut m_prime = vec![0u8; 8 + hash_len + s_len];
    m_prime[8..8 + hash_len].copy_from_slice(hash);
    m_prime[8 + hash_len..].copy_from_slice(&salt);
    
    let mut hasher = Sha256::new();
    hasher.update(&m_prime);
    let h = hasher.finalize();
    
    let ps_len = key_size - s_len - hash_len - 2;
    let mut db = vec![0u8; ps_len + 1 + s_len];
    db[ps_len] = 0x01;
    db[ps_len + 1..].copy_from_slice(&salt);
    
    let db_mask = mgf1_sha256(&h, db.len());
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    
    let mut masked_db = masked_db;
    let bits_to_clear = 8 * key_size - (key_size * 8 - 1);
    if bits_to_clear > 0 {
        masked_db[0] &= 0xff >> bits_to_clear;
    }
    
    let mut em = Vec::with_capacity(key_size);
    em.extend_from_slice(&masked_db);
    em.extend_from_slice(&h);
    em.push(0xbc);
    
    Ok(em)
}

/**
 * Verifies a PSS signed hash using SHA-256
 * Args:
 *    em - &[u8]: The encoded message (signature)
 *    hash - &[u8]: The original hash
 * 
 * Returns:
 *    Result<bool>: True if the signature is valid, false otherwise
 */
fn verify_pss_sha256(em: &[u8], hash: &[u8]) -> Result<bool> {
    let hash_len = 32;
    let s_len = hash_len;
    if em.len() < hash_len + s_len + 2 {
        return Ok(false);
    }
    
    if em[em.len() - 1] != 0xbc {
        return Ok(false);
    }
    
    let masked_db = &em[..em.len() - hash_len - 1];
    let h = &em[em.len() - hash_len - 1..em.len() - 1];
    let db_mask = mgf1_sha256(h, masked_db.len());
    
    let mut db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    let bits_to_clear = 8 * em.len() - (em.len() * 8 - 1);
    if bits_to_clear > 0 {
        db[0] &= 0xff >> bits_to_clear;
    }
    
    let ps_len = db.len() - s_len - 1;
    for i in 0..ps_len {
        if db[i] != 0x00 {
            return Ok(false);
        }
    }
    
    if db[ps_len] != 0x01 {
        return Ok(false);
    }
    
    let salt = &db[ps_len + 1..];
    let mut m_prime = vec![0u8; 8 + hash_len + s_len];
    m_prime[8..8 + hash_len].copy_from_slice(hash);
    m_prime[8 + hash_len..].copy_from_slice(salt);
    
    let mut hasher = Sha256::new();
    hasher.update(&m_prime);
    let h_prime = hasher.finalize();
    
    Ok(&h_prime[..] == h)
}

/**
 * Mask Generation Function 1 (MGF1) using SHA-256
 * Args:
 *    seed - &[u8]: The seed for MGF1
 *    mask_len - usize: The desired length of the mask
 * 
 * Returns:
 *    Vec<u8>: The generated mask
 */
fn mgf1_sha256(seed: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 32;
    let mut output = Vec::with_capacity(length);
    let iterations = (length + hash_len - 1) / hash_len;
    for counter in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&(counter as u32).to_be_bytes());
        output.extend_from_slice(&hasher.finalize());
    }

    output.truncate(length);

    output
}

/**
 * Computes the greatest common divisor (GCD) of two BigNums
 * Args:
 *    a - &BigNum: The first BigNum
 *    b - &BigNum: The second BigNum
 * 
 * Returns:
 *    BigNum: The GCD of a and b
 */
fn gcd(a: &BigNum, b: &BigNum) -> BigNum {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let temp = b.clone();
        b = a.modulo(&b);
        a = temp;
    }
    
    a
}

/**
 * Computes the least common multiple (LCM) of two BigNums
 * Args:
 *    a - &BigNum: The first BigNum
 *    b - &BigNum: The second BigNum
 * 
 * Returns:
 *    BigNum: The LCM of a and b
 */
fn lcm(a: &BigNum, b: &BigNum) -> BigNum {
    let g = gcd(a, b);
    a.clone().mul(b.clone()).div(g)
}

fn big_num_to_fixed_bytes(num: &BigNum, length: usize) -> Vec<u8> {
    let mut bytes = num.to_bytes_be();
    if bytes.len() > length {
        bytes = bytes[bytes.len() - length..].to_vec();
    }

    if bytes.len() < length {
        let mut padded = vec![0u8; length - bytes.len()];
        padded.extend_from_slice(&bytes);

        padded
    } else {
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rsa_2048_keygen() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public = key.public_key();
        
        assert_eq!(key.size, RsaKeySize::Rsa2048);
        assert_eq!(public.size, RsaKeySize::Rsa2048);
    }
    
    #[test]
    fn test_rsa_encrypt_decrypt_pkcs1() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public = key.public_key();
        let message = b"Hello, RSA!";
        
        let ciphertext = public.encrypt(message, RsaPadding::Pkcs1v15).unwrap();
        let decrypted = key.decrypt(&ciphertext, RsaPadding::Pkcs1v15).unwrap();
        
        assert_eq!(decrypted, message);
    }
    
    #[test]
    fn test_rsa_encrypt_decrypt_oaep() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public = key.public_key();
        let message = b"Hello, RSA with OAEP!";
        
        let ciphertext = public.encrypt(message, RsaPadding::OaepSha256).unwrap();
        let decrypted = key.decrypt(&ciphertext, RsaPadding::OaepSha256).unwrap();
        
        assert_eq!(decrypted, message);
    }
    
    #[test]
    fn test_rsa_sign_verify_pkcs1() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public = key.public_key();
        let message = b"Message to sign";
        
        let signature = key.sign(message, RsaPadding::Pkcs1v15).unwrap();
        assert!(public.verify(message, &signature, RsaPadding::Pkcs1v15).unwrap());
        
        assert!(!public.verify(b"Different message", &signature, RsaPadding::Pkcs1v15).unwrap());
    }
    
    #[test]
    fn test_rsa_sign_verify_pss() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public = key.public_key();
        let message = b"Message to sign with PSS";
        
        let signature = key.sign(message, RsaPadding::PssSha256).unwrap();
        assert!(public.verify(message, &signature, RsaPadding::PssSha256).unwrap());
        
        assert!(!public.verify(b"Different message", &signature, RsaPadding::PssSha256).unwrap());
    }
    
    #[test]
    fn test_rsa_key_components() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let components = key.to_components();
        
        let restored = RsaPrivateKey::from_components(&components, RsaKeySize::Rsa2048).unwrap();
        
        let message = b"Test serialization";
        let signature1 = key.sign(message, RsaPadding::Pkcs1v15).unwrap();
        let signature2 = restored.sign(message, RsaPadding::Pkcs1v15).unwrap();
        
        assert_eq!(signature1.len(), signature2.len());
    }


        #[test]
    fn test_is_probably_prime_small_primes() {
        let small_primes = [
            BigNum::from_u64(2),
            BigNum::from_u64(3),
            BigNum::from_u64(5),
            BigNum::from_u64(7),
            BigNum::from_u64(11),
            BigNum::from_u64(101),
            BigNum::from_u64(1009),
            BigNum::from_u64(10007),
        ];
        
        println!("\n=== Testing is_probably_prime on small primes ===");
        for prime in small_primes.iter() {
            match is_probably_prime(prime, 16) {
                Ok(result) => println!("is_probably_prime({}) = {}", prime, result),
                Err(e) => println!("is_probably_prime({}) ERROR: {:?}", prime, e),
            }
        }
    }

    #[test]
    fn test_oaep_padding_only() {
        let msg = b"Hello OAEP";
        let key_size = 256;
        let padded = pad_oaep_sha256(msg, key_size).unwrap();
        let unpadded = unpad_oaep_sha256(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn test_rsa_core_raw() {
        let key = RsaPrivateKey::generate(RsaKeySize::Rsa2048).unwrap();
        let public = key.public_key();
        let mut msg = vec![0u8; key.size.bytes()];
        msg[key.size.bytes() - 1] = 0x42; // just some data
        let cipher = public.encrypt(&msg, RsaPadding::NoPadding).unwrap();
        let plain = key.decrypt(&cipher, RsaPadding::NoPadding).unwrap();
        assert_eq!(plain, msg);
    }
}