// crypto/asymmetric/ed25519.rs - Ed25519 Digital Signature Algorithm
// https://datatracker.ietf.org/doc/html/rfc8032#section-5.1

use crate::crypto::{Error, Result};
use super::x25519::{fe_from_bytes, fe_to_bytes, fe_add, fe_sub, fe_mul, fe_square, fe_invert};
use crate::crypto::hash::sha2::Sha512;

// Extended coordinates representation
type ExtendedPoint = ([i64; 10], [i64; 10], [i64; 10], [i64; 10]);

// Field element representation
type Fe = [i64; 10];

// Order of the Ed25519 curve
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

// Ed25519 Private Key structure
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
    public_key: Ed25519PublicKey,
}

// Ed25519 Public Key structure
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519PublicKey {
    point: [u8; 32],
}

// Ed25519 Signature structure
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signature {
    bytes: [u8; 64],
}

impl Ed25519PrivateKey {

    /**
     * Generates a new Ed25519 private key with a random seed
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Result<Self>: The generated Ed25519PrivateKey or an error if generation fails
     */
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        crate::crypto::random::fill_random(&mut seed)?;
        Self::from_seed(&seed)
    }

    /**
     * Creates an Ed25519 private key from a given seed
     * Args:
     *    seed - &[u8; 32]: The seed bytes
     * 
     * Returns:
     *    Result<Self>: The created Ed25519PrivateKey or an error if creation fails
     */
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

    /**
     * Retrieves the private key seed bytes
     * Args:
     *    &self: The Ed25519PrivateKey instance
     * 
     * Returns:
     *    [u8; 32]: The seed bytes
     */
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /**
     * Retrieves the associated public key
     * Args:
     *    &self: The Ed25519PrivateKey instance
     * 
     * Returns:
     *    &Ed25519PublicKey: The associated public key
     */
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /**
     * Signs a message using the Ed25519 private key
     * Args:
     *    &self: The Ed25519PrivateKey instance
     *    message - &[u8]: The message bytes to sign
     * 
     * Returns:
     *    Ed25519Signature: The generated signature
     */
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

    /**
     * Creates an Ed25519 public key from given bytes
     * Args:
     *    bytes - &[u8]: The public key bytes
     * 
     * Returns:
     *    Result<Self>: The created Ed25519PublicKey or an error if creation fails
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let mut point = [0u8; 32];
        point.copy_from_slice(bytes);

        Ok(Self { point })
    }

    /**
     * Retrieves the public key bytes
     * Args:
     *    &self: The Ed25519PublicKey instance
     * 
     * Returns:
     *    [u8; 32]: The public key bytes
     */
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point
    }

    /**
     * Verifies a signature for a given message using the Ed25519 public key
     * Args:
     *    &self: The Ed25519PublicKey instance
     *    message - &[u8]: The message bytes to verify
     *    signature - &Ed25519Signature: The signature to verify
     * 
     * Returns:
     *    bool: True if the signature is valid, false otherwise
     */
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

    /**
     * Creates an Ed25519 signature from given bytes
     * Args:
     *    bytes - &[u8]: The signature bytes
     * 
     * Returns
     *    Result<Self>: The created Ed25519Signature or an error if creation fails
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: sig_bytes })
    }

    /**
     * Retrieves the signature bytes
     * Args:
     *    &self: The Ed25519Signature instance
     * 
     * Returns:
     *    [u8; 64]: The signature bytes
     */
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }
}

/**
 * Returns the Ed25519 base point in extended coordinates
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    ExtendedPoint: The base point in extended coordinates
 */
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

/**
 * Performs scalar multiplication of the base point G by a scalar k
 * Args:
 *    scalar - &[u8; 32]: The scalar multiplier
 * 
 * Returns:
 *    [u8; 32]: The resulting point in byte representation after multiplication
 */
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

/**
 * Performs scalar multiplication of a point by a scalar k
 * Args:
 *    scalar - &[u8; 32]: The scalar multiplier
 *    point - &[u8; 32]: The point to be multiplied
 * 
 * Returns:
 *    [u8; 32]: The resulting point in byte representation after multiplication
 */
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

/**
 * Adds two points in byte representation
 * Args:
 *    a - &[u8; 32]: The first point in byte representation
 *    b - &[u8; 32]: The second point in byte representation
 * 
 * Returns:
 *    [u8; 32]: The resulting point in byte representation after addition
 */
fn ed25519_point_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let pa = extended_from_bytes(a);
    let pb = extended_from_bytes(b);
    let pc = extended_add(&pa, &pb);
    
    extended_to_bytes(&pc)
}

/**
 * Returns the identity point in extended coordinates
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    ExtendedPoint: The identity point in extended coordinates
 */
fn extended_identity() -> ExtendedPoint {
    (fe_zero(), fe_one(), fe_one(), fe_zero())
}

/**
 * Converts bytes to an ExtendedPoint
 * Args:
 *    bytes - &[u8; 32]: The point in byte representation
 * 
 * Returns:
 *    ExtendedPoint: The point in extended coordinates
 */
fn extended_from_bytes(bytes: &[u8; 32]) -> ExtendedPoint {
    let mut y_bytes = *bytes;
    let x_sign = (y_bytes[31] >> 7) & 1;
    y_bytes[31] &= 0x7F;

    let y = fe_from_bytes(&y_bytes);
    let z = fe_one();

    let y2 = fe_square(&y);
    let u = fe_sub(&y2, &fe_one());
    let v = fe_add(&fe_mul(&fe_d(), &y2), &fe_one());
    let uv = fe_mul(&u, &fe_invert(&v));
    let mut x = fe_sqrt(&uv);
    if fe_to_bytes(&x)[0] & 1 != x_sign {
        x = fe_neg(&x);
    }

    let t = fe_mul(&x, &y);
    (x, y, z, t)
}

/**
 * Converts an ExtendedPoint to bytes
 * Args:
 *    p - &ExtendedPoint: The point in extended coordinates
 * 
 * Returns:
 *    [u8; 32]: The point in byte representation
 */
fn extended_to_bytes(p: &ExtendedPoint) -> [u8; 32] {
    let (x, y, z, _t) = p;
    let zinv = fe_invert(z);
    let x_final = fe_mul(x, &zinv);
    let y_final = fe_mul(y, &zinv);
    let mut bytes = fe_to_bytes(&y_final);

    bytes[31] |= (fe_to_bytes(&x_final)[0] & 1) << 7;

    bytes
}

/**
 * Adds two points in extended coordinates
 * Args:
 *    p - &ExtendedPoint: The first point
 *    q - &ExtendedPoint: The second point
 * 
 * Returns:
 *    ExtendedPoint: The resulting point after addition
 */
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

/**
 * Doubles a point in extended coordinates
 * Args:
 *    p - &ExtendedPoint: The point to be doubled
 * 
 * Returns:
 *    ExtendedPoint: The resulting point after doubling
 */
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

/**
 * constant 0
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing 0
 */
fn fe_zero() -> Fe { [0; 10] }

/**
 * constant 1
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing 1
 */
fn fe_one() -> Fe { [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] }

/**
 * constant 2
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing 2
 */
fn fe_two() -> Fe { [2, 0, 0, 0, 0, 0, 0, 0, 0, 0] }

/**
 * constant d
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing d
 */
fn fe_d() -> Fe {
    [
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    ]
}

/**
 * constant 2*d
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing 2*d
 */
fn fe_d2() -> Fe {
    [
        -21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199
    ]
}

/**
 * Computes the negation of a field element
 * Args:
 *    a - &Fe: The field element
 * 
 * Returns:
 *    Fe: The negated field element
 */
fn fe_neg(a: &Fe) -> Fe {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = -a[i];
    }

    h
}

/**
 * Computes z^(2^252 - 3) in the field
 * Args:
 *    z - &Fe: The field element
 * 
 * Returns:
 *    Fe: The result of the exponentiation
 */
fn fe_pow22523(z: &Fe) -> Fe {
    let mut t0 = fe_square(z);
    let mut t1 = fe_square(&t0);
    t1 = fe_square(&t1);
    t1 = fe_mul(z, &t1);
    t0 = fe_mul(&t0, &t1);
    t0 = fe_square(&t0);
    t0 = fe_mul(&t1, &t0);
    t1 = fe_square(&t0);
    for _ in 0..4 {
        t1 = fe_square(&t1);
    }

    t0 = fe_mul(&t1, &t0);
    t1 = fe_square(&t0);
    for _ in 0..9 {
        t1 = fe_square(&t1);
    }

    t1 = fe_mul(&t1, &t0);
    let mut t2 = fe_square(&t1);
    for _ in 0..19 {
        t2 = fe_square(&t2);
    }

    t1 = fe_mul(&t2, &t1);
    t1 = fe_square(&t1);
    for _ in 0..9 {
        t1 = fe_square(&t1);
    }

    t0 = fe_mul(&t1, &t0);
    t1 = fe_square(&t0);
    for _ in 0..49 {
        t1 = fe_square(&t1);
    }
    
    t1 = fe_mul(&t1, &t0);
    t2 = fe_square(&t1);
    for _ in 0..99 {
        t2 = fe_square(&t2);
    }

    t1 = fe_mul(&t2, &t1);
    t1 = fe_square(&t1);
    for _ in 0..49 {
        t1 = fe_square(&t1);
    }

    t0 = fe_mul(&t1, &t0);
    t0 = fe_square(&t0);
    t0 = fe_square(&t0);
    fe_mul(&t0, z)
}

/**
 * Computes the square root of a field element, returning the positive root
 * Args:
 *    a - &Fe: The field element
 * 
 * Returns:
 *    Fe: The square root of the field element
 */
fn fe_sqrt(a: &Fe) -> Fe {
    const SQRT_M1: Fe = [
        -32595792, -7943725,  9377950,  3500415, 12389472,
        -272473, -25146209, -2005654,  326686, 11406482,
    ];

    let t = fe_pow22523(a);
    let mut x = fe_mul(&t, a);
    let x2 = fe_square(&x);
    let diff = fe_sub(&x2, a);
    if fe_to_bytes(&diff) != [0u8; 32] {
        x = fe_mul(&x, &SQRT_M1);
    }

    x
}

/**
 * Loads 3 little-endian bytes into an integer
 * Args:
 *    b - &[u8]: The byte slice containing at least 3 bytes
 * 
 * Returns:
 *    i128: The integer representation of the 3 bytes
 */
fn sc_load3(b: &[u8]) -> i128 {
    (b[0] as i128) | ((b[1] as i128) << 8) | ((b[2] as i128) << 16)
}

/**
 * Loads 4 little-endian bytes into an integer
 * Args:
 *    b - &[u8]: The byte slice containing at least 4 bytes
 * 
 * Returns:
 *    i128: The integer representation of the 4 bytes
 */
fn sc_load4(b: &[u8]) -> i128 {
    (b[0] as i128) | ((b[1] as i128) << 8) | ((b[2] as i128) << 16) | ((b[3] as i128) << 24)
}

/**
 * Splits a 32-byte little-endian scalar into twelve 21-bit limbs
 * Args:
 *    s - &[u8]: The scalar bytes
 * 
 * Returns:
 *    [i128; 12]: The array of 12 limbs representing the scalar
 */
fn sc_limbs32(s: &[u8]) -> [i128; 12] {
    [
        2097151 & sc_load3(&s[0..]),
        2097151 & (sc_load4(&s[2..]) >> 5),
        2097151 & (sc_load3(&s[5..]) >> 2),
        2097151 & (sc_load4(&s[7..]) >> 7),
        2097151 & (sc_load4(&s[10..]) >> 4),
        2097151 & (sc_load3(&s[13..]) >> 1),
        2097151 & (sc_load4(&s[15..]) >> 6),
        2097151 & (sc_load3(&s[18..]) >> 3),
        2097151 & sc_load3(&s[21..]),
        2097151 & (sc_load4(&s[23..]) >> 5),
        2097151 & (sc_load3(&s[26..]) >> 2),
        sc_load4(&s[28..]) >> 7,
    ]
}

/**
 * Splits a 64-byte little-endian scalar into 24 21-bit limbs
 * Args:
 *    s - &[u8; 64]: The scalar bytes
 * 
 * Returns:
 *   [i128; 24]: The array of 24 limbs representing the scalar
 */
fn sc_limbs64(s: &[u8; 64]) -> [i128; 24] {
    [
        2097151 & sc_load3(&s[0..]),
        2097151 & (sc_load4(&s[2..]) >> 5),
        2097151 & (sc_load3(&s[5..]) >> 2),
        2097151 & (sc_load4(&s[7..]) >> 7),
        2097151 & (sc_load4(&s[10..]) >> 4),
        2097151 & (sc_load3(&s[13..]) >> 1),
        2097151 & (sc_load4(&s[15..]) >> 6),
        2097151 & (sc_load3(&s[18..]) >> 3),
        2097151 & sc_load3(&s[21..]),
        2097151 & (sc_load4(&s[23..]) >> 5),
        2097151 & (sc_load3(&s[26..]) >> 2),
        2097151 & (sc_load4(&s[28..]) >> 7),
        2097151 & (sc_load4(&s[31..]) >> 4),
        2097151 & (sc_load3(&s[34..]) >> 1),
        2097151 & (sc_load4(&s[36..]) >> 6),
        2097151 & (sc_load3(&s[39..]) >> 3),
        2097151 & sc_load3(&s[42..]),
        2097151 & (sc_load4(&s[44..]) >> 5),
        2097151 & (sc_load3(&s[47..]) >> 2),
        2097151 & (sc_load4(&s[49..]) >> 7),
        2097151 & (sc_load4(&s[52..]) >> 4),
        2097151 & (sc_load3(&s[55..]) >> 1),
        2097151 & (sc_load4(&s[57..]) >> 6),
        sc_load4(&s[60..]) >> 3,
    ]
}

/**
 * Carries the value of limb `i` into limb `i+1`, optionally rounding it
 * Args:
 *    s - &mut [i128; 24]: The array of limbs
 *    i - usize: The index of the limb to carry
 *    round - bool: Whether to round the carry
 * 
 * Returns:
 *    (): No return value, modifies `s` in place
 */
fn sc_carry(s: &mut [i128; 24], i: usize, round: bool) {
    let carry = if round { (s[i] + (1 << 20)) >> 21 } else { s[i] >> 21 };
    s[i + 1] += carry;
    s[i] -= carry << 21;
}

/**
 * Folds the top limb into the lower limbs using the Ed25519 curve order
 * Args:
 *    s - &mut [i128; 24]: The array of limbs
 *    top - usize: The index of the top limb to fold
 * 
 * Returns:
 *    (): No return value, modifies `s` in place
 */
fn sc_fold(s: &mut [i128; 24], top: usize) {
    let v = s[top];
    s[top - 12] += v * 666643;
    s[top - 11] += v * 470296;
    s[top - 10] += v * 654183;
    s[top - 9] -= v * 997805;
    s[top - 8] += v * 136657;
    s[top - 7] -= v * 683901;
    s[top] = 0;
}

/**
 * Reduces a 24-limb scalar to a 32-byte scalar modulo the Ed25519 curve order
 * Args:
 *    s - [i128; 24]: The array of 24 limbs representing the scalar
 * 
 * Returns:
 *    [u8; 32]: The reduced 32-byte scalar
 */
fn sc_reduce_limbs(mut s: [i128; 24]) -> [u8; 32] {
    for top in (18..=23).rev() { sc_fold(&mut s, top); }
    for &i in &[6, 8, 10, 12, 14, 16] { sc_carry(&mut s, i, true); }
    for &i in &[7, 9, 11, 13, 15] { sc_carry(&mut s, i, true); }

    for top in (12..=17).rev() { sc_fold(&mut s, top); }
    for &i in &[0, 2, 4, 6, 8, 10] { sc_carry(&mut s, i, true); }
    for &i in &[1, 3, 5, 7, 9, 11] { sc_carry(&mut s, i, true); }

    sc_fold(&mut s, 12);
    for i in 0..=11 { sc_carry(&mut s, i, false); }

    sc_fold(&mut s, 12);
    for i in 0..=10 { sc_carry(&mut s, i, false); }

    let l = &s[..12];
    [
        (l[0] >> 0) as u8,
        (l[0] >> 8) as u8,
        ((l[0] >> 16) | (l[1] << 5)) as u8,
        (l[1] >> 3) as u8,
        (l[1] >> 11) as u8,
        ((l[1] >> 19) | (l[2] << 2)) as u8,
        (l[2] >> 6) as u8,
        ((l[2] >> 14) | (l[3] << 7)) as u8,
        (l[3] >> 1) as u8,
        (l[3] >> 9) as u8,
        ((l[3] >> 17) | (l[4] << 4)) as u8,
        (l[4] >> 4) as u8,
        (l[4] >> 12) as u8,
        ((l[4] >> 20) | (l[5] << 1)) as u8,
        (l[5] >> 7) as u8,
        ((l[5] >> 15) | (l[6] << 6)) as u8,
        (l[6] >> 2) as u8,
        (l[6] >> 10) as u8,
        ((l[6] >> 18) | (l[7] << 3)) as u8,
        (l[7] >> 5) as u8,
        (l[7] >> 13) as u8,
        (l[8] >> 0) as u8,
        (l[8] >> 8) as u8,
        ((l[8] >> 16) | (l[9] << 5)) as u8,
        (l[9] >> 3) as u8,
        (l[9] >> 11) as u8,
        ((l[9] >> 19) | (l[10] << 2)) as u8,
        (l[10] >> 6) as u8,
        ((l[10] >> 14) | (l[11] << 7)) as u8,
        (l[11] >> 1) as u8,
        (l[11] >> 9) as u8,
        (l[11] >> 17) as u8,
    ]
}

/**
 * Reduces a 64-byte scalar to a 32-byte scalar modulo the Ed25519 curve order
 * Args:
 *    s - &[u8; 64]: The 64-byte scalar
 *
 * Returns:
 *    [u8; 32]: The reduced 32-byte scalar
 */
fn sc_reduce(s: &[u8; 64]) -> [u8; 32] {
    sc_reduce_limbs(sc_limbs64(s))
}

/**
 * Computes (a * b + c) mod L
 * Args:
 *    a - &[u8; 32]: The first scalar
 *    b - &[u8; 32]: The second scalar
 *    c - &[u8; 32]: The third scalar
 * 
 * Returns:
 *    [u8; 32]: The resulting scalar after computation
 */
fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let a = sc_limbs32(a);
    let b = sc_limbs32(b);
    let c = sc_limbs32(c);
    let mut s = [0i128; 24];
    for i in 0..12 {
        for j in 0..12 {
            s[i + j] += a[i] * b[j];
        }
    }

    for i in 0..12 {
        s[i] += c[i];
    }

    for &i in &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22] { sc_carry(&mut s, i, true); }
    for &i in &[1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21] { sc_carry(&mut s, i, true); }

    sc_reduce_limbs(s)
}

/**
 * Checks if a scalar is in canonical form
 * Args:
 *    s - &[u8; 32]: The scalar to check
 * 
 * Returns:
 *    bool: True if the scalar is canonical, false otherwise
 */
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
    fn test_sign_verify_equation_small() {
        let a_s = [5u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let r_s = [3u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let k_s = [7u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let s38= [38u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

        let s = sc_muladd(&k_s, &a_s, &r_s);
        assert_eq!(s, s38, "sc_muladd(7,5,3) should be 38");

        let a_point = ed25519_scalar_mult_base(&a_s);
        let r_point = ed25519_scalar_mult_base(&r_s);
        let s_b = ed25519_scalar_mult_base(&s);
        let ka = ed25519_scalar_mult(&k_s, &a_point);
        let r_plus_ka = ed25519_point_add(&r_point, &ka);
        assert_eq!(s_b, r_plus_ka, "38*B != 7*(5*B) + 3*B");

        let a_l = [200u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let r_l = [150u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let k_l = [100u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

        let s_expected = [182u8, 78, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let s_l = sc_muladd(&k_l, &a_l, &r_l);
        assert_eq!(s_l, s_expected, "sc_muladd(100,200,150) should be 20150=[182,78,...]");

        let a_pt_l = ed25519_scalar_mult_base(&a_l);
        let r_pt_l = ed25519_scalar_mult_base(&r_l);
        let s_b_l = ed25519_scalar_mult_base(&s_l);
        let ka_l = ed25519_scalar_mult(&k_l, &a_pt_l);
        let rka_l = ed25519_point_add(&r_pt_l, &ka_l);
        assert_eq!(s_b_l, rka_l, "small-value sign/verify equation failed");
        eprintln!("Small-value sign/verify equation: PASS");

        let seed = [1u8,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8];
        let mut hasher = Sha512::new();
        hasher.update(&seed);
        let hash = hasher.finalize();
        let mut scalar_val = [0u8; 32];
        scalar_val.copy_from_slice(&hash[..32]);
        scalar_val[0] &= 248; scalar_val[31] &= 127; scalar_val[31] |= 64;
        let pubkey_a = ed25519_scalar_mult_base(&scalar_val);

        let k1 = [1u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let r1 = [1u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let base_bytes = [0x58u8,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
                          0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66];
        let s_k1 = sc_muladd(&k1, &scalar_val, &r1);
        let s_k1_b = ed25519_scalar_mult_base(&s_k1);
        let pubkey_plus_b = ed25519_point_add(&pubkey_a, &base_bytes);

        let mut sv_plus_1 = scalar_val;
        let mut carry = 1u16;
        for b in sv_plus_1.iter_mut() {
            let v = *b as u16 + carry;
            *b = v as u8;
            carry = v >> 8;
        }

        let sv1_b = ed25519_scalar_mult_base(&sv_plus_1);

        eprintln!("sv+1 bytes  [0..4]: {:?}", &sv_plus_1[..4]);
        eprintln!("muladd bytes[0..4]: {:?}", &s_k1[..4]);
        eprintln!("sv+1 bytes  [28..]: {:?}", &sv_plus_1[28..]);
        eprintln!("muladd bytes[28..]: {:?}", &s_k1[28..]);
        eprintln!("scalar_mult_base(sv+1)   [0..4]: {:?}", &sv1_b[..4]);
        eprintln!("scalar_mult_base(muladd) [0..4]: {:?}", &s_k1_b[..4]);
        eprintln!("pubkey_a + B             [0..4]: {:?}", &pubkey_plus_b[..4]);
        eprintln!("sv1_b == pubkey_plus_b: {}", sv1_b == pubkey_plus_b);
        eprintln!("s_k1_b == pubkey_plus_b: {}", s_k1_b == pubkey_plus_b);
        assert_eq!(sv1_b, pubkey_plus_b, "scalar_mult_base(sv+1) != point_add(A, B)");

        let mut naive_mod = sv_plus_1;
        for _ in 0..10 {
            let mut ge = false;
            for byte_idx in (0..32).rev() {
                if naive_mod[byte_idx] > L[byte_idx] { ge = true; break; }
                if naive_mod[byte_idx] < L[byte_idx] { break; }
                if byte_idx == 0 { ge = true; }
            }

            if !ge { break; }
            let mut borrow = 0i16;
            for byte_idx in 0..32 {
                let diff = naive_mod[byte_idx] as i16 - L[byte_idx] as i16 - borrow;
                if diff < 0 { naive_mod[byte_idx] = (diff + 256) as u8; borrow = 1; }
                else { naive_mod[byte_idx] = diff as u8; borrow = 0; }
            }
        }

        eprintln!("naive_mod bytes[28..]: {:?}", &naive_mod[28..]);
        eprintln!("sc_muladd bytes[28..]: {:?}", &s_k1[28..]);
        eprintln!("naive_mod[31]: {} (must be <=15), sc_muladd[31]: {}", naive_mod[31], s_k1[31]);
        assert!(naive_mod[31] <= 15, "naive reduction incomplete: byte[31]={}", naive_mod[31]);
        assert_eq!(naive_mod, s_k1, "sc_muladd gives wrong reduction of sv+1");
        eprintln!("Real scalar_val equation test: PASS");
    }

    #[test]
    fn test_sc_muladd_basic() {
        let a = [5u8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let b = [7u8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let c = [3u8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let s = sc_muladd(&a, &b, &c);
        assert_eq!(s[0], 38, "5*7+3 should be 38, got {}", s[0]);
        assert_eq!(&s[1..], &[0u8; 31], "high bytes should be 0");

        let ff = [255u8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let s2 = sc_muladd(&ff, &ff, &ff);
        eprintln!("255*255+255 = {:?}", &s2[..4]);
        assert_eq!(s2[0], 0, "byte 0: expected 0, got {}", s2[0]);
        assert_eq!(s2[1], 255, "byte 1: expected 255, got {}", s2[1]);
        assert_eq!(&s2[2..], &[0u8; 30], "high bytes should be 0");

        let mut l_minus_1 = L; l_minus_1[0] -= 1;
        let one = [1u8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let s3 = sc_muladd(&l_minus_1, &one, &one);
        eprintln!("(L-1)*1 + 1 = {:?}", &s3[..8]);
        assert_eq!(s3, [0u8; 32], "(L-1)*1+1 should be 0 mod L");

        let s4 = sc_muladd(&one, &l_minus_1, &one);
        assert_eq!(s4, [0u8; 32], "1*(L-1)+1 should be 0 mod L");

        let s5 = sc_muladd(&one, &one, &L);
        eprintln!("1*1+L = {:?}", &s5[..8]);
        assert_eq!(s5[0], 1, "1*1+L should be 1 (L≡0 mod L)");
        assert_eq!(&s5[1..], &[0u8; 31], "high bytes of 1*1+L should be 0");
    }

    #[test]
    fn test_ed25519_base_point() {
        let one = [1u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let result = ed25519_scalar_mult_base(&one);
        let expected_base: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ];

        assert_eq!(result, expected_base, "1*B != base point");

        let two = [2u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let three = [3u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let two_b = ed25519_scalar_mult_base(&two);
        let three_b = ed25519_scalar_mult_base(&three);
        let two_b_plus_b = ed25519_point_add(&two_b, &result);
        assert_eq!(two_b_plus_b, three_b, "2*B + B != 3*B");

        let base = ed25519_base_point();
        let two_b_direct = extended_to_bytes(&extended_double(&base));
        assert_eq!(two_b, two_b_direct, "scalar_mult_base(2) != double(base)");
    }

    #[test]
    fn test_ed25519_rfc8032_vector1() {
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];

        let expected_pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
            0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];

        let expected_sig: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let mut hasher = Sha512::new();
        hasher.update(&seed);
        let hash = hasher.finalize();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        eprintln!("scalar: {:?}", &scalar[..]);
        let computed_pubkey = ed25519_scalar_mult_base(&scalar);
        eprintln!("computed: {:?}", computed_pubkey);
        eprintln!("expected: {:?}", expected_pubkey);

        let key = Ed25519PrivateKey::from_seed(&seed).unwrap();
        assert_eq!(key.public_key().point, expected_pubkey, "public key mismatch");

        let sig = key.sign(b"");
        assert_eq!(sig.bytes, expected_sig, "signature mismatch");

        assert!(key.public_key().verify(b"", &sig), "verify failed");
    }

    #[test]
    fn test_scalar_prefix_bisect() {
        let full: [u8; 32] = [0x30, 0x7c, 0x83, 0x86, 0x4f, 0x28, 0x33, 0xcb,
                               0x42, 0x7a, 0x2e, 0xf1, 0xc0, 0x0a, 0x01, 0x3c,
                               0xfd, 0xff, 0x27, 0x68, 0xd9, 0x80, 0xc0, 0xa3,
                               0xa5, 0x20, 0xf0, 0x06, 0x90, 0x4d, 0xe9, 0x4f];

        let expected: [u8; 32] = [0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
                                   0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
                                   0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
                                   0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a];

        for k in 1..=32usize {
            let mut partial = [0u8; 32];
            partial[..k].copy_from_slice(&full[..k]);
            let r = ed25519_scalar_mult_base(&partial);
            let mut expected_k = extended_identity();
            let mut pw = ed25519_base_point();
            for i in 0..256usize {
                if (partial[i >> 3] >> (i & 7)) & 1 == 1 {
                    expected_k = extended_add(&expected_k, &pw);
                }

                pw = extended_double(&pw);
            }

            let expected_k_bytes = extended_to_bytes(&expected_k);
            eprintln!("k={:2}: result={:x?}", k, r);
            eprintln!("       expected={:x?}", expected_k_bytes);
            eprintln!("       match={}", r == expected_k_bytes);
            assert_eq!(r, expected_k_bytes, "mismatch at k={}", k);
        }

        let full_r = ed25519_scalar_mult_base(&full);
        eprintln!("full result:   {:x?}", full_r);
        eprintln!("full expected: {:x?}", expected);
        assert_eq!(full_r, expected, "full scalar mismatch");
    }

    #[test]
    fn test_rfc8032_seed_sha512() {
        let seed: [u8; 32] = [0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
                               0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60];
        
        let mut hasher = crate::crypto::hash::sha2::Sha512::new();
        hasher.update(&seed);
        let hash = hasher.finalize();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        eprintln!("SHA-512(seed)[0..32]: {:x?}", &hash[..32]);
        eprintln!("clamped scalar:       {:x?}", scalar);
        let pubkey = ed25519_scalar_mult_base(&scalar);
        let expected: [u8; 32] = [0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
                                   0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a];
        
        eprintln!("computed pubkey:      {:x?}", pubkey);
        eprintln!("expected pubkey:      {:x?}", expected);
        assert_eq!(pubkey, expected, "from_seed should produce correct public key");
    }

    #[test]
    fn test_scalar_one_gives_base_point() {
        let mut scalar_one = [0u8; 32];
        scalar_one[0] = 1;
        let result = ed25519_scalar_mult_base(&scalar_one);
        let expected_g: [u8; 32] = [0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66];
        
        eprintln!("scalar_mult_base(1) = {:x?}", result);
        eprintln!("expected G          = {:x?}", expected_g);
        assert_eq!(result, expected_g, "1*B should equal the base point G");
    }

    #[test]
    fn test_scalar_high_low_combine() {
        let rfc_scalar: [u8; 32] = [152, 183, 102, 223, 97, 9, 53, 179, 108, 89, 206, 211, 125, 105, 1, 125, 22, 198, 10, 21, 142, 193, 132, 42, 193, 170, 80, 60, 140, 222, 104, 81];
        let mut low_part = rfc_scalar;
        for i in 16..32 { low_part[i] = 0; }
        let mut high_part = rfc_scalar;
        for i in 0..16 { high_part[i] = 0; }

        let low_pt = ed25519_scalar_mult_base(&low_part);
        let high_pt = ed25519_scalar_mult_base(&high_part);
        let full_pt = ed25519_scalar_mult_base(&rfc_scalar);

        let low_ext = extended_from_bytes(&low_pt);
        let high_ext = extended_from_bytes(&high_pt);
        let sum_pt = extended_to_bytes(&extended_add(&low_ext, &high_ext));

        eprintln!("low part result:   {:?}", low_pt);
        eprintln!("high part result:  {:?}", high_pt);
        eprintln!("sum (low+high):    {:?}", sum_pt);
        eprintln!("scalar_mult_base:  {:?}", full_pt);
        eprintln!("sum==full: {}", sum_pt == full_pt);

        assert_eq!(sum_pt, full_pt, "low*B + high*B should equal (low+high)*B");
    }

    #[test]
    fn test_group_ops_fundamental() {
        let B = ed25519_base_point();
        let one: [u8; 32] = {let mut s = [0u8;32]; s[0]=1; s};
        let two: [u8; 32] = {let mut s = [0u8;32]; s[0]=2; s};
        let three: [u8; 32] = {let mut s = [0u8;32]; s[0]=3; s};

        let bb = extended_to_bytes(&extended_add(&B, &B));
        let dbl = extended_to_bytes(&extended_double(&B));
        let sb2 = ed25519_scalar_mult_base(&two);
        eprintln!("B+B:    {:?}", bb);
        eprintln!("2B dbl: {:?}", dbl);
        eprintln!("2B sc:  {:?}", sb2);
        assert_eq!(bb, dbl, "B+B should equal 2*B via double");
        assert_eq!(bb, sb2, "B+B should equal scalar_mult_base(2)");

        let bbb = extended_to_bytes(&extended_add(&extended_add(&B, &B), &B));
        let sb3 = ed25519_scalar_mult_base(&three);
        eprintln!("B+B+B: {:?}", bbb);
        eprintln!("3B sc: {:?}", sb3);
        assert_eq!(bbb, sb3, "B+B+B should equal scalar_mult_base(3)");

        let b_bytes = extended_to_bytes(&B);
        let scalar_128: [u8; 32] = {let mut s = [0u8;32]; s[16]=1; s};
        let pow128 = ed25519_scalar_mult_base(&scalar_128);
        let pow128_pt = extended_from_bytes(&pow128);
        let b_plus_128 = extended_to_bytes(&extended_add(&B, &pow128_pt));
        let scalar_1_128: [u8; 32] = {let mut s = [0u8;32]; s[0]=1; s[16]=1; s};
        let result_1_128 = ed25519_scalar_mult_base(&scalar_1_128);
        eprintln!("B + 2^128*B (manual): {:?}", b_plus_128);
        eprintln!("scalar(1+2^128)*B:     {:?}", result_1_128);
        assert_eq!(b_plus_128, result_1_128, "B + 2^128*B should equal scalar_mult_base with bits 0,128 set");
    }

    #[test]
    fn test_lm1_direct() {
        let base_bytes: [u8; 32] = [0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66];
        let mut minus_b = base_bytes;
        minus_b[31] ^= 0x80;
        let mut lm1 = L; lm1[0] -= 1;
        let result = ed25519_scalar_mult_base(&lm1);
        eprintln!("(L-1)*B:   {:?}", result);
        eprintln!("-B:        {:?}", minus_b);
        eprintln!("match: {}", result == minus_b);

        let base = ed25519_base_point();
        let two_b = extended_double(&base);
        let two_b_bytes = extended_to_bytes(&two_b);
        let scalar_2: [u8; 32] = [2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let result_2 = ed25519_scalar_mult_base(&scalar_2);
        eprintln!("2*B (double): {:?}", two_b_bytes);
        eprintln!("2*B (scalar): {:?}", result_2);
        eprintln!("2*B match: {}", two_b_bytes == result_2);
    }

    #[test]
    fn test_rfc8032_reduced_scalar() {
        let scalar: [u8; 32] = [48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104, 217, 128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79];
        let base_bytes: [u8; 32] = [0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66];
        let expected: [u8; 32] = [0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a];
        let via_base = ed25519_scalar_mult_base(&scalar);
        let via_mult = ed25519_scalar_mult(&scalar, &base_bytes);
        eprintln!("scalar_mult_base(rfc8032): {:?}", via_base);
        eprintln!("scalar_mult(rfc8032, B):   {:?}", via_mult);
        eprintln!("expected:                  {:?}", expected);
        eprintln!("base==mult: {}", via_base == via_mult);

        let scalar128: [u8; 32] = {let mut s = [0u8;32]; s[16] = 1; s};
        let via_base_128 = ed25519_scalar_mult_base(&scalar128);
        let via_mult_128 = ed25519_scalar_mult(&scalar128, &base_bytes);
        eprintln!("2^128*B via base: {:?}", via_base_128);
        eprintln!("2^128*B via mult: {:?}", via_mult_128);
        eprintln!("2^128 match: {}", via_base_128 == via_mult_128);
        assert_eq!(via_base, via_mult, "scalar_mult_base and scalar_mult should agree");
        assert_eq!(via_base, expected, "scalar*B should equal expected pubkey");
    }

    #[test]
    fn test_ed25519_sign_verify_debug() {
        let seed: [u8; 32] = [1u8,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8, 1,2,3,4,5,6,7,8];
        let key = Ed25519PrivateKey::from_seed(&seed).unwrap();
        let message = b"test";

        let signature = key.sign(message);
        let r: &[u8; 32] = signature.bytes[..32].try_into().unwrap();
        let s: &[u8; 32] = signature.bytes[32..64].try_into().unwrap();

        let pubkey = key.public_key();
        let is_canonical = sc_is_conanical(s);
        eprintln!("s is canonical: {}", is_canonical);

        let mut k_hasher = Sha512::new();
        k_hasher.update(r);
        k_hasher.update(&pubkey.point);
        k_hasher.update(message);
        let k_hash = k_hasher.finalize();
        let k = sc_reduce(&k_hash);

        let sb = ed25519_scalar_mult_base(s);
        let ka = ed25519_scalar_mult(&k, &pubkey.point);
        let r_plus_ka = ed25519_point_add(r, &ka);
        let matches = sb == r_plus_ka;
        eprintln!("s*B == R + k*A: {}", matches);
        eprintln!("s*B:       {:?}", &sb[..8]);
        eprintln!("R+k*A:     {:?}", &r_plus_ka[..8]);
        eprintln!("R:         {:?}", &r[..8]);
        eprintln!("k*A:       {:?}", &ka[..8]);

        let one = [1u8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let one_times_pubkey = ed25519_scalar_mult(&one, &pubkey.point);
        let pubkey_direct = pubkey.point;
        eprintln!("1*pubkey == pubkey: {}", one_times_pubkey == pubkey_direct);

        let base_bytes: [u8; 32] = [
            0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
            0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        ];

        let one_times_base = ed25519_scalar_mult(&one, &base_bytes);
        eprintln!("scalar_mult(1,B) == B: {}", one_times_base == base_bytes);

        let mut hasher2 = Sha512::new();
        hasher2.update(&seed);
        let hash2 = hasher2.finalize();
        let mut scalar_val = [0u8; 32];
        scalar_val.copy_from_slice(&hash2[..32]);
        scalar_val[0] &= 248; scalar_val[31] &= 127; scalar_val[31] |= 64;

        let prefix = &hash2[32..64];
        let mut r_hasher = Sha512::new();
        r_hasher.update(prefix);
        r_hasher.update(message);
        let r_hash = r_hasher.finalize();
        let r_scalar = sc_reduce(&r_hash);
        let r_capital = ed25519_scalar_mult_base(&r_scalar);

        let a_point = pubkey.point;
        let k_times_a = ed25519_scalar_mult(&k, &a_point);
        let r_times_b = ed25519_scalar_mult_base(&r_scalar);
        let combined = ed25519_point_add(&k_times_a, &r_times_b);

        let s_actual = sc_muladd(&k, &scalar_val, &r_scalar);
        let sb_actual = ed25519_scalar_mult_base(&s_actual);

        eprintln!("s (sc_muladd):  {:?}", &s_actual[..8]);
        eprintln!("s*B:           {:?}", &sb_actual[..8]);
        eprintln!("k*A + r*B:     {:?}", &combined[..8]);
        eprintln!("sc_muladd correct: {}", sb_actual == combined);
        eprintln!("k[..8]:        {:?}", &k[..8]);
        eprintln!("scalar_val[..8]: {:?}", &scalar_val[..8]);
        eprintln!("r_scalar[..8]: {:?}", &r_scalar[..8]);
        eprintln!("sig s[..8]:    {:?}", &s[..8]);
        eprintln!("sig_s == sc_muladd: {}", s == &s_actual);

        let sb_from_sig = ed25519_scalar_mult_base(s);
        eprintln!("sig_s*B:       {:?}", &sb_from_sig[..8]);
        eprintln!("sig_s*B==k*A+r*B: {}", sb_from_sig == combined);

        let zero32 = [0u8; 32];
        let ka_via_muladd = sc_muladd(&k, &scalar_val, &zero32);
        let ka_via_muladd_b = ed25519_scalar_mult_base(&ka_via_muladd);
        let ka_via_scalar_mult = ed25519_scalar_mult(&k, &a_point);
        eprintln!("sc_muladd(k,a,0)*B: {:?}", &ka_via_muladd_b[..8]);
        eprintln!("scalar_mult(k,A):   {:?}", &ka_via_scalar_mult[..8]);
        eprintln!("sc_muladd(k,a,0)*B == k*A: {}", ka_via_muladd_b == ka_via_scalar_mult);

        let one32 = [1u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let sc1_a0 = sc_muladd(&one32, &scalar_val, &zero32);
        eprintln!("sc_muladd(1,a,0): {:?}", &sc1_a0[..8]);
        eprintln!("scalar_val[..8]:  {:?}", &scalar_val[..8]);
        eprintln!("sc_muladd(1,a,0)==a: {}", sc1_a0 == scalar_val);

        let a_reduced_b = ed25519_scalar_mult_base(&sc1_a0);
        eprintln!("scalar_mult_base(a mod L): {:?}", &a_reduced_b[..8]);
        eprintln!("pubkey:                    {:?}", &a_point[..8]);
        eprintln!("a mod L gives correct pubkey: {}", a_reduced_b == a_point);

        let sc_l = sc_muladd(&one32, &L, &zero32);
        eprintln!("sc_muladd(1,L,0) == 0: {}", sc_l == zero32);

        let mut l_plus_1 = L;
        l_plus_1[0] = l_plus_1[0].wrapping_add(1);
        let lp1_b = ed25519_scalar_mult_base(&l_plus_1);
        let base_bytes_b: [u8; 32] = [
            0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
            0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        ];

        eprintln!("scalar_mult_base(L+1) == B: {}", lp1_b == base_bytes_b);

        let pubkey_direct = ed25519_scalar_mult_base(&scalar_val);
        eprintln!("pubkey via scalar_val: {:?}", &pubkey_direct[..8]);
        eprintln!("stored pubkey:         {:?}", &a_point[..8]);
        eprintln!("they match:            {}", pubkey_direct == a_point);

        assert!(is_canonical, "S is not canonical!");
        assert!(matches, "s*B != R + k*A");
    }

    #[test]
    fn test_scalar_mult_consistency() {
        let base_bytes: [u8; 32] = [
            0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
            0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        ];

        let base_pt = ed25519_base_point();
        let mut pt = base_pt;
        for k in 1..=16u32 {
            pt = extended_double(&pt);
            let expected = extended_to_bytes(&pt);

            let mut scalar = [0u8; 32];
            let byte_idx = (k / 8) as usize;
            let bit_idx = (k % 8) as u32;
            scalar[byte_idx] = 1u8 << bit_idx;

            let computed = ed25519_scalar_mult_base(&scalar);
            assert_eq!(computed, expected, "2^{} * B mismatch: scalar={:?}", k, scalar);
        }
        eprintln!("All 2^k * B tests passed for k=1..16");

        let mut pt2 = base_pt;
        for k in 1..=64u32 {
            pt2 = extended_double(&pt2);
            let expected = extended_to_bytes(&pt2);
            let mut scalar = [0u8; 32];
            let byte_idx = (k / 8) as usize;
            let bit_idx = (k % 8) as u32;
            scalar[byte_idx] = 1u8 << bit_idx;
            let computed = ed25519_scalar_mult_base(&scalar);
            assert_eq!(computed, expected, "2^{} * B mismatch", k);
        }

        eprintln!("All 2^k * B tests passed for k=1..64");

        let identity_bytes = [1u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let l_times_b = ed25519_scalar_mult_base(&L);
        assert_eq!(l_times_b, identity_bytes, "L*B != identity");
        eprintln!("L*B == identity: PASS");

        let mut minus_b = base_bytes;
        minus_b[31] ^= 0x80;
        let mut l_minus_1 = L;

        l_minus_1[0] -= 1;
        let l_minus_1_b = ed25519_scalar_mult_base(&l_minus_1);
        assert_eq!(l_minus_1_b, minus_b, "(L-1)*B != -B");
        eprintln!("(L-1)*B == -B: PASS");
        for k in 1u8..=20 {
            let mut s = [0u8; 32];
            s[0] = k;
            let via_base = ed25519_scalar_mult_base(&s);
            let via_general = ed25519_scalar_mult(&s, &base_bytes);
            assert_eq!(via_base, via_general, "scalar_mult({}, B) != scalar_mult_base({})", k, k);
        }

        let mut s256 = [0u8; 32]; s256[1] = 1;
        assert_eq!(ed25519_scalar_mult_base(&s256), ed25519_scalar_mult(&s256, &base_bytes), "scalar_mult(256, B) mismatch");

        let mut lm1 = L; lm1[0] -= 1;
        assert_eq!(ed25519_scalar_mult_base(&lm1), ed25519_scalar_mult(&lm1, &base_bytes), "scalar_mult(L-1, B) mismatch");
        eprintln!("scalar_mult(k,B) == scalar_mult_base(k) for k=1..20, 256, L-1: PASS");

        let a2 = [2u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let k3 = [3u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let k6 = [6u8, 0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
        let two_b = ed25519_scalar_mult_base(&a2);
        let three_times_two_b = ed25519_scalar_mult(&k3, &two_b);
        let six_b = ed25519_scalar_mult_base(&k6);
        assert_eq!(three_times_two_b, six_b, "scalar_mult(3, 2*B) != 6*B");
        eprintln!("scalar_mult(3, 2*B) == 6*B: PASS");

        let mut l_minus_2 = L; l_minus_2[0] -= 2;
        let res1 = ed25519_scalar_mult(&lm1, &two_b);
        let res2 = ed25519_scalar_mult_base(&l_minus_2);
        assert_eq!(res1, res2, "scalar_mult(L-1, 2*B) != (L-2)*B");
        eprintln!("scalar_mult(L-1, 2*B) == (L-2)*B: PASS");
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let key = Ed25519PrivateKey::generate().unwrap();
        let message = b"test message";

        let signature = key.sign(message);
        assert!(key.public_key().verify(message, &signature));

        assert!(!key.public_key().verify(b"wrong message", &signature));
    }
}