use crate::crypto::{Error, Result};
use super::x25519::{fe_from_bytes, fe_to_bytes, fe_add, fe_sub, fe_mul, fe_square, fe_invert, fe_reduce};
use crate::crypto::hash::sha2::Sha512;

type ExtendedPoint = ([i64; 10], [i64; 10], [i64; 10], [i64; 10]);
type Fe = [i64; 10];

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
    public_key: Ed25519PublicKey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519PublicKey {
    point: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signature {
    bytes: [u8; 64],
}

impl Ed25519PrivateKey {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        crate::crypto::random::fill_random(&mut seed)?;
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);

        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        let point = ed25519_scalar_mult_base(&scalar);
        
        Ok(Self {
            seed: *seed,
            public_key: Ed25519PublicKey { point },
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let mut hasher = Sha512::new();
        hasher.update(&self.seed);
        let hash = hasher.finalize();

        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        let prefix = &hash[32..64];

        let mut r_hasher = Sha512::new();
        r_hasher.update(prefix);
        r_hasher.update(message);
        let r_hash = r_hasher.finalize();
        let r = sc_reduce(&r_hash);

        let capital_r = ed25519_scalar_mult_base(&r);

        let mut k_hasher = Sha512::new();
        k_hasher.update(&capital_r);
        k_hasher.update(&self.public_key.point);
        k_hasher.update(message);
        let k_hash = k_hasher.finalize();
        let k = sc_reduce(&k_hash);

        let s = sc_muladd(&k, &scalar, &r);

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&capital_r);
        sig_bytes[32..64].copy_from_slice(&s);

        Ed25519Signature { bytes: sig_bytes }
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let mut point = [0u8; 32];
        point.copy_from_slice(bytes);

        Ok(Self { point })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.point
    }

    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        let capital_r: &[u8; 32] = signature.bytes[..32].try_into().unwrap();
        let s: &[u8; 32] = signature.bytes[32..64].try_into().unwrap();
        if !sc_is_conanical(s) {
            return false;
        }

        let mut k_hasher = Sha512::new();
        k_hasher.update(capital_r);
        k_hasher.update(&self.point);
        k_hasher.update(message);
        let k_hash = k_hasher.finalize();
        let k = sc_reduce(&k_hash);

        let sb = ed25519_scalar_mult_base(s);
        let ka = ed25519_scalar_mult(&k, &self.point);
        let r_plus_ka = ed25519_point_add(capital_r, &ka);

        sb == r_plus_ka
    }
}

impl Ed25519Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: sig_bytes })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }
}

fn ed25519_base_point() -> ExtendedPoint {
    // Base point in extended coordinates
    // x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    // y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
    let x = fe_from_bytes(&[
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
        0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
        0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
        0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
    ]);
    
    let y = fe_from_bytes(&[
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ]);
    
    let z = fe_one();
    let t = fe_mul(&x, &y);
    
    (x, y, z, t)
}

fn ed25519_scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut result = extended_identity();
    let base = ed25519_base_point();
    for i in 0..256 {
        if (scalar[i >> 3] >> (i & 7)) & 1 == 1 {
            result = extended_add(&result, &base);
        }

        if i < 255 {
            // Double for next iteration
        }
    }

    result = extended_identity();
    let mut temp = base;
    for i in 0..256 {
        if (scalar[i >> 3] >> (i & 7)) & 1 == 1 {
            result = extended_add(&result, &temp);
        }

        temp = extended_double(&temp);
    }

    extended_to_bytes(&result)
}

fn ed25519_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let p = extended_from_bytes(point);
    let mut result = extended_identity();
    let mut temp = p;
    for i in 0..256 {
        if (scalar[i >> 3] >> (i & 7)) & 1 == 1 {
            result = extended_add(&result, &temp);
        }

        temp = extended_double(&temp);
    }

    extended_to_bytes(&result)
}

fn ed25519_point_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let pa = extended_from_bytes(a);
    let pb = extended_from_bytes(b);
    let pc = extended_add(&pa, &pb);
    
    extended_to_bytes(&pc)
}

fn extended_identity() -> ExtendedPoint {
    (fe_zero(), fe_one(), fe_one(), fe_zero())
}

fn extended_from_bytes(bytes: &[u8; 32]) -> ExtendedPoint {
    let y = fe_from_bytes(bytes);
    let z = fe_one();
    
    let y2 = fe_square(&y);
    let u = fe_sub(&y2, &fe_one());
    let v = fe_add(&fe_mul(&fe_d(), &y2), &fe_one());
    let x = fe_sqrt(&fe_mul(&u, &fe_invert(&v)));
    let t = fe_mul(&x, &y);

    (x, y, z, t)
}

fn extended_to_bytes(p: &ExtendedPoint) -> [u8; 32] {
    let (x, y, z, _t) = p;
    let zinv = fe_invert(z);
    let x_final = fe_mul(x, &zinv);
    let y_final = fe_mul(y, &zinv);
    let mut bytes = fe_to_bytes(&y_final);

    bytes[31] ^= ((x_final[0] & 1) << 7) as u8;

    bytes
}

fn extended_add(p: &ExtendedPoint, q: &ExtendedPoint) -> ExtendedPoint {
    let (x1, y1, z1, t1) = p;
    let (x2, y2, z2, t2) = q;
    
    let a = fe_mul(&fe_sub(y1, x1), &fe_sub(y2, x2));
    let b = fe_mul(&fe_add(y1, x1), &fe_add(y2, x2));
    let c = fe_mul(&fe_mul(t1, t2), &fe_d2());
    let d = fe_mul(&fe_mul(z1, z2), &fe_two());
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    
    let x3 = fe_mul(&e, &f);
    let y3 = fe_mul(&g, &h);
    let t3 = fe_mul(&e, &h);
    let z3 = fe_mul(&f, &g);
    
    (x3, y3, z3, t3)
}

fn extended_double(p: &ExtendedPoint) -> ExtendedPoint {
    let (x1, y1, z1, _t1) = p;
    
    let a = fe_square(x1);
    let b = fe_square(y1);
    let c = fe_mul(&fe_two(), &fe_square(z1));
    let d = fe_neg(&a);
    let e = fe_sub(&fe_square(&fe_add(x1, y1)), &fe_add(&a, &b));
    let g = fe_add(&d, &b);
    let f = fe_sub(&g, &c);
    let h = fe_sub(&d, &b);
    
    let x3 = fe_mul(&e, &f);
    let y3 = fe_mul(&g, &h);
    let t3 = fe_mul(&e, &h);
    let z3 = fe_mul(&f, &g);
    
    (x3, y3, z3, t3)
}

fn fe_zero() -> Fe { [0; 10] }
fn fe_one() -> Fe { [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
fn fe_two() -> Fe { [2, 0, 0, 0, 0, 0, 0, 0, 0, 0] }

fn fe_d() -> Fe {
    [
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    ]
}

fn fe_d2() -> Fe {
    [
        -21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199
    ]
}

fn fe_neg(a: &Fe) -> Fe {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = -a[i];
    }

    h
}

fn fe_sqrt(a: &Fe) -> Fe {
    let mut t0 = fe_square(a);
    let mut t1 = fe_square(&t0);
    t1 = fe_square(&t1);
    t1 = fe_mul(a, &t1);
    t0 = fe_mul(&t0, &t1);

    for _ in 0..252 {
        t0 = fe_square(&t0);
    }

    t0
}

fn sc_reduce(s: &[u8; 64]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut s64 = [0i64; 64];
    for i in 0..64 {
        s64[i] = s[i] as i64;
    }

    for i in (32..64).rev() {
        let mut carry: i64 = 0;
        for j in (i - 32)..i {
            let x = s64[j] + carry - 16 * s64[i] * L[j - (i - 32)] as i64;
            carry = (x + 128) >> 8;
            s64[j] = x - carry * 256;
        }
    }

    for i in 0..32 {
        result[i] = s64[i] as u8;
    }

    result
}

fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut s = [0i64; 64];
    for i in 0..32 {
        for j in 0..32 {
            s[i + j] += (a[i] as i64) * (b[j] as i64);
        }
    }

    for i in 0..32 {
        s[i] += c[i] as i64;
    }

    let mut result = [0u8; 64];
    for i in 0..64 {
        result[i] = s[i] as u8;
    }

    sc_reduce(&result)
}

fn sc_is_conanical(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] < L[i] {
            return true;
        }

        if s[i] > L[i] {
            return false;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let key = Ed25519PrivateKey::generate().unwrap();
        let message = b"test message";
        
        let signature = key.sign(message);
        assert!(key.public_key().verify(message, &signature));
        
        assert!(!key.public_key().verify(b"wrong message", &signature));
    }
}