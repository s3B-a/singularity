use crate::crypto::{Error, Result};
use crate::crypto::bignum::BigNum;
use crate::crypto::hash::sha2::Sha256;
use crate::crypto::random;
use std::cmp::Ordering;
use std::ops::{Add, Sub, Mul, Div};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaKeySize {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaPadding {
    Pkcs1v15,
    OaepSha256,
    PssSha256,
    NoPadding,
}

#[derive(Clone)]
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

#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    n: BigNum,
    e: BigNum,
    size: RsaKeySize,


}

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

#[derive(Clone, Debug)]
pub struct RsaPublicKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl RsaKeySize {
    pub fn bits(&self) -> usize {
        match self {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }
}

impl RsaPrivateKey {
    pub fn generate(size: RsaKeySize) -> Result<Self> {
        let bits = size.bits();
        let e = BigNum::from_u64(65537);
        
        let (p, q) = generate_rsa_primes(bits / 2, &e)?;
        let n = p.clone().mul(q.clone());
        
        let p_minus_1 = p.clone().sub(BigNum::from_u64(1));
        let q_minus_1 = q.clone().sub(BigNum::from_u64(1));
        let lambda_n = lcm(&p_minus_1, &q_minus_1);
        
        let d = e.mod_inverse(&lambda_n)?;
        
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
    
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            size: self.size,
        }
    }
    
    pub fn decrypt(&self, ciphertext: &[u8], padding: RsaPadding) -> Result<Vec<u8>> {
        let c = BigNum::from_bytes_be(ciphertext);
        if c.cmp(&self.n) != Ordering::Less {
            return Err(Error::CryptoError("Ciphertext too large".to_string()));
        }
        
        let m = rsa_decrypt_crt(&c, &self.p, &self.q, &self.dp, &self.dq, &self.qinv, &self.n)?;
        let mut m_bytes = m.to_bytes_be();
        let target_len = self.size.bytes();
        if m_bytes.len() < target_len {
            let mut padded = vec![0u8; target_len - m_bytes.len()];
            padded.extend_from_slice(&m_bytes);
            m_bytes = padded;
        }
        
        match padding {
            RsaPadding::Pkcs1v15 => unpad_pkcs1v15(&m_bytes, false),
            RsaPadding::OaepSha256 => unpad_oaep_sha256(&m_bytes),
            RsaPadding::NoPadding => Ok(m_bytes),
            _ => Err(Error::CryptoError("Unsupported padding for decryption".to_string())),
        }
    }
    
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
    pub fn encrypt(&self, plaintext: &[u8], padding: RsaPadding) -> Result<Vec<u8>> {
        let padded = match padding {
            RsaPadding::Pkcs1v15 => {
                pad_pkcs1v15_encrypt(plaintext, self.size.bytes())?
            }
            RsaPadding::OaepSha256 => {
                pad_oaep_sha256(plaintext, self.size.bytes())?
            }
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
        
        let c = m.mod_exp(&self.e, &self.n)?;
        
        let mut c_bytes = c.to_bytes_be();
        let target_len = self.size.bytes();
        if c_bytes.len() < target_len {
            let mut padded = vec![0u8; target_len - c_bytes.len()];
            padded.extend_from_slice(&c_bytes);
            c_bytes = padded;
        }
        Ok(c_bytes)
    }
    
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
        
        let m = s.mod_exp(&self.e, &self.n)?;
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
    
    pub fn to_components(&self) -> RsaPublicKeyComponents {
        RsaPublicKeyComponents {
            n: self.n.to_bytes_be(),
            e: self.e.to_bytes_be(),
        }
    }
    
    pub fn from_components(components: &RsaPublicKeyComponents, size: RsaKeySize) -> Result<Self> {
        Ok(Self {
            n: BigNum::from_bytes_be(&components.n),
            e: BigNum::from_bytes_be(&components.e),
            size,
        })
    }
}

fn generate_rsa_primes(bits: usize, e: &BigNum) -> Result<(BigNum, BigNum)> {
    let p = generate_prime(bits, e)?;
    let q = loop {
        let candidate = generate_prime(bits, e)?;
        if p.cmp(&candidate) != Ordering::Equal {
            break candidate;
        }
    };
    
    Ok((p, q))
}

fn generate_prime(bits: usize, e: &BigNum) -> Result<BigNum> {
    let bytes = (bits + 7) / 8;
    loop {
        let mut candidate_bytes = vec![0u8; bytes];
        random::fill_random(&mut candidate_bytes)?;
        
        candidate_bytes[0] |= 0x80;
        candidate_bytes[bytes - 1] |= 0x01;
        
        let candidate = BigNum::from_bytes_be(&candidate_bytes);
        let candidate_minus_1 = candidate.clone().sub(BigNum::from_u64(1));
        if gcd(&candidate_minus_1, e).cmp(&BigNum::from_u64(1)) != Ordering::Equal {
            continue;
        }
        
        if is_probably_prime(&candidate, 64) {
            return Ok(candidate);
        }
    }
}

fn is_probably_prime(n: &BigNum, rounds: usize) -> bool {
    let small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
    for &p in &small_primes {
        let prime = BigNum::from_u64(p);
        if n.cmp(&prime) == Ordering::Equal {
            return true;
        }

        if n.clone().modulo(&prime).is_zero() {
            return false;
        }
    }
    
    miller_rabin(n, rounds)
}

fn miller_rabin(n: &BigNum, rounds: usize) -> bool {
    if n.is_zero() || n.cmp(&BigNum::from_u64(1)) == Ordering::Equal {
        return false;
    }

    if n.cmp(&BigNum::from_u64(2)) == Ordering::Equal {
        return true;
    }
    
    let n_minus_1 = n.clone().sub(BigNum::from_u64(1));
    let (r, d) = factor_power_of_two(&n_minus_1);
    'witness: for _ in 0..rounds {
        let a = random_range(&BigNum::from_u64(2), &n_minus_1).unwrap_or(BigNum::from_u64(2));
        let mut x = match a.mod_exp(&d, n) {
            Ok(val) => val,
            Err(_) => return false,
        };
        if x.cmp(&BigNum::from_u64(1)) == Ordering::Equal || x.cmp(&n_minus_1) == Ordering::Equal {
            continue 'witness;
        }
        
        for _ in 0..r {
            x = x.clone().mul(x.clone()).modulo(n);
            if x.cmp(&n_minus_1) == Ordering::Equal {
                continue 'witness;
            }
        }
        
        return false;
    }
    
    true
}

fn factor_power_of_two(n: &BigNum) -> (usize, BigNum) {
    let mut d = n.clone();
    let mut r = 0;
    while d.clone().modulo(&BigNum::from_u64(2)).is_zero() {
        d = d.div(BigNum::from_u64(2));
        r += 1;
    }
    
    (r, d)
}

fn random_range(min: &BigNum, max: &BigNum) -> Result<BigNum> {
    let range = max.clone().sub(min.clone());
    let range_bytes = range.to_bytes_be();
    loop {
        let mut random_bytes = vec![0u8; range_bytes.len()];
        random::fill_random(&mut random_bytes)?;
        
        let r = BigNum::from_bytes_be(&random_bytes);
        if r.cmp(&range) == Ordering::Less {
            return Ok(r.add(min.clone()));
        }
    }
}

fn rsa_decrypt_crt(c: &BigNum, p: &BigNum, q: &BigNum, dp: &BigNum, dq: &BigNum, qinv: &BigNum, n: &BigNum) -> Result<BigNum> {
    let m1 = c.mod_exp(dp, p)?;
    let m2 = c.mod_exp(dq, q)?;
    let h = if m1.cmp(&m2) != Ordering::Less {
        qinv.clone().mul(m1.sub(m2.clone())).modulo(p)
    } else {
        let diff = p.clone().add(m1).sub(m2.clone());
        qinv.clone().mul(diff).modulo(p)
    };
    
    let m = m2.add(h.mul(q.clone())).modulo(n);
    
    Ok(m)
}

fn pad_pkcs1v15_encrypt(data: &[u8], key_size: usize) -> Result<Vec<u8>> {
    if data.len() > key_size - 11 {
        return Err(Error::CryptoError("Data too long for PKCS#1 v1.5 padding".to_string()));
    }
    
    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x02;
    
    let ps_len = key_size - data.len() - 3;
    let mut ps = vec![0u8; ps_len];
    random::fill_random(&mut ps)?;
    for byte in ps.iter_mut() {
        if *byte == 0 {
            *byte = 1;
        }
    }
    
    padded[2..2 + ps_len].copy_from_slice(&ps);
    padded[2 + ps_len] = 0x00;
    padded[3 + ps_len..].copy_from_slice(data);
    
    Ok(padded)
}

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

fn pad_oaep_sha256(data: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let hash_len = 32;
    if data.len() > key_size - 2 * hash_len - 2 {
        return Err(Error::CryptoError("Data too long for OAEP".to_string()));
    }
    
    let hasher = Sha256::new();
    let l_hash = hasher.finalize();
    
    let ps_len = key_size - data.len() - 2 * hash_len - 2;
    let mut db = Vec::with_capacity(key_size - hash_len - 1);
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
    
    let hasher = Sha256::new();
    let l_hash = hasher.finalize();
    if &db[..hash_len] != &l_hash[..] {
        return Err(Error::CryptoError("Invalid OAEP padding".to_string()));
    }
    
    let mut separator_idx = None;
    for i in hash_len..db.len() {
        if db[i] == 0x01 {
            separator_idx = Some(i);
            break;
        } else if db[i] != 0x00 {
            return Err(Error::CryptoError("Invalid OAEP padding".to_string()));
        }
    }
    
    let separator_idx = separator_idx.ok_or_else(|| Error::CryptoError("Invalid OAEP padding".to_string()))?;
    
    Ok(db[separator_idx + 1..].to_vec())
}

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

fn lcm(a: &BigNum, b: &BigNum) -> BigNum {
    let g = gcd(a, b);
    a.clone().mul(b.clone()).div(g)
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
}