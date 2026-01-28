// crypto/asymmetric/x25519.rs - X25519 Key Exchange Implementation
// https://datatracker.ietf.org/doc/html/rfc7748#section-5

use crate::crypto::{Error, Result};

// Field Element type for X25519
type Fe = [i64; 10];

// Base point for X25519 key exchange
const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

// X25519 Private Key structure
#[derive(Clone)]
pub struct X25519PrivateKey {
    scalar: [u8; 32],
}

// X25519 Public Key structure
#[derive(Clone, Debug, PartialEq)]
pub struct X25519PublicKey {
    point: [u8; 32],
}

impl X25519PrivateKey {

    /**
     * Generates a new X25519 private key
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *    Result<Self>: The generated X25519PrivateKey or an error if generation fails
     */
    pub fn generate() -> Result<Self> {
        let mut scalar = [0u8; 32];
        crate::crypto::random::fill_random(&mut scalar)?;

        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        Ok(Self {
            scalar
        })
    }

    /**
     * Creates an X25519 private key from raw bytes
     * Args:
     *    bytes - &[u8]: The byte slice representing the private key
     * 
     * Returns:
     *    Result<Self>: The created X25519PrivateKey or an error if the byte slice is invalid
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(bytes);

        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        Ok(Self {
            scalar
        })
    }

    /**
     * Returns the raw bytes of the X25519 private key
     * Args:
     *    &self: The X25519PrivateKey instance
     * 
     * Returns:
     *    [u8; 32]: The byte array representing the private key
     */
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar
    }

    /**
     * Derives the corresponding X25519 public key from the private key
     * Args:
     *    &self: The X25519PrivateKey instance
     * 
     * Returns:
     *    X25519PublicKey: The derived X25519 public key
     */
    pub fn public_key(&self) -> X25519PublicKey {
        let point = x25519_base(&self.scalar);
        X25519PublicKey { point }
    }

    /**
     * Performs the Diffie-Hellman key exchange to compute the shared secret
     * Args:
     *    &self: The X25519PrivateKey instance
     *    their_public - &X25519PublicKey: The other party's X25519 public key
     * 
     * Returns:
     *    Result<[u8; 32]>: The computed shared secret or an error if the computation fails
     */
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> Result<[u8; 32]> {
        let shared = x25519_scalar_mult(&self.scalar, &their_public.point);
        if shared.iter().all(|&b| b == 0) {
            return Err(Error::CryptoError("Invalid X25519 shared secret".to_string()));
        }

        Ok(shared)
    }
}

impl X25519PublicKey {

    /**
     * Creates an X25519 public key from raw bytes
     * Args:
     *    bytes - &[u8]: The byte slice representing the public key
     * 
     * Returns:
     *    Result<Self>: The created X25519PublicKey or an error if the byte slice is invalid
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
     * Returns the raw bytes of the X25519 public key
     * Args:
     *    &self: The X25519PublicKey instance
     * 
     * Returns:
     *    [u8; 32]: The byte array representing the public key
     */
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point
    }
}

/**
 * Computes the X25519 public key point from a given scalar
 * Args:
 *    scalar - &[u8; 32]: The private key scalar
 * 
 * Returns:
 *    [u8; 32]: The resulting public key point
 */
fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519_scalar_mult(scalar, &BASE_POINT)
}

/**
 * Performs X25519 scalar multiplication
 * Args:
 *    scalar - &[u8; 32]: The private key scalar
 *    point - &[u8; 32]: The public key point
 * 
 * Returns:
 *    [u8; 32]: The resulting shared secret point
 */
fn x25519_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let x1 = fe_from_bytes(point);
    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = x1;
    let mut z3 = fe_one();
    let mut swap = 0u8;
    for t in (0..255).rev() {
        let bit = (scalar[t >> 3] >> (t & 7)) & 1;
        swap ^= bit;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let aa = fe_square(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_square(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        x3 = fe_square(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_square(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul_121666(&e)));
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let result = fe_mul(&x2, &fe_invert(&z2));
    fe_to_bytes(&result)
}

/**
 * Creates a field element representing zero
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing zero
 */
fn fe_zero() -> Fe {
    [0; 10]
}

/**
 * Creates a field element representing one
 * Args:
 *    (): No arguments
 * 
 * Returns:
 *    Fe: The field element representing one
 */
fn fe_one() -> Fe {
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/**
 * Converts a byte array to a field element (never make me type this again)
 * Args:
 *    bytes - &[u8; 32]: The byte array to convert
 * 
 * Returns:
 *    Fe: The resulting field element
 */
pub fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    let mut h = [0i64; 10];
    h[0] = (bytes[0] as i64) | ((bytes[1] as i64) << 8) | ((bytes[2] as i64) << 16) | ((bytes[3] as i64 & 3) << 24);
    h[1] = ((bytes[3] as i64) >> 2) | ((bytes[4] as i64) << 6) | ((bytes[5] as i64) << 14) | ((bytes[6] as i64 & 7) << 22);
    h[2] = ((bytes[6] as i64) >> 3) | ((bytes[7] as i64) << 5) | ((bytes[8] as i64) << 13) | ((bytes[9] as i64 & 31) << 21);
    h[3] = ((bytes[9] as i64) >> 5) | ((bytes[10] as i64) << 3) | ((bytes[11] as i64) << 11) | ((bytes[12] as i64 & 63) << 19);
    h[4] = ((bytes[12] as i64) >> 6) | ((bytes[13] as i64) << 2) | ((bytes[14] as i64) << 10) | ((bytes[15] as i64) << 18);
    h[5] = (bytes[16] as i64) | ((bytes[17] as i64) << 8) | ((bytes[18] as i64) << 16) | ((bytes[19] as i64 & 1) << 24);
    h[6] = ((bytes[19] as i64) >> 1) | ((bytes[20] as i64) << 7) | ((bytes[21] as i64) << 15) | ((bytes[22] as i64 & 7) << 23);
    h[7] = ((bytes[22] as i64) >> 3) | ((bytes[23] as i64) << 5) | ((bytes[24] as i64) << 13) | ((bytes[25] as i64 & 15) << 21);
    h[8] = ((bytes[25] as i64) >> 4) | ((bytes[26] as i64) << 4) | ((bytes[27] as i64) << 12) | ((bytes[28] as i64 & 63) << 20);
    h[9] = ((bytes[28] as i64) >> 6) | ((bytes[29] as i64) << 2) | ((bytes[30] as i64) << 10) | ((bytes[31] as i64) << 18);
    
    h
}

/**
 * Converts a field element to a byte array (i hate this)
 * Args:
 *    h - &Fe: The field element to convert
 * 
 * Returns:
 *    [u8; 32]: The resulting byte array
 */
pub fn fe_to_bytes(h: &Fe) -> [u8; 32] {
    let mut s = [0u8; 32];
    let mut h = *h;
    
    fe_reduce(&mut h);
    
    s[0] = h[0] as u8;
    s[1] = (h[0] >> 8) as u8;
    s[2] = (h[0] >> 16) as u8;
    s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
    s[4] = (h[1] >> 6) as u8;
    s[5] = (h[1] >> 14) as u8;
    s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
    s[7] = (h[2] >> 5) as u8;
    s[8] = (h[2] >> 13) as u8;
    s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
    s[10] = (h[3] >> 3) as u8;
    s[11] = (h[3] >> 11) as u8;
    s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
    s[13] = (h[4] >> 2) as u8;
    s[14] = (h[4] >> 10) as u8;
    s[15] = (h[4] >> 18) as u8;
    s[16] = h[5] as u8;
    s[17] = (h[5] >> 8) as u8;
    s[18] = (h[5] >> 16) as u8;
    s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
    s[20] = (h[6] >> 7) as u8;
    s[21] = (h[6] >> 15) as u8;
    s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
    s[23] = (h[7] >> 5) as u8;
    s[24] = (h[7] >> 13) as u8;
    s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
    s[26] = (h[8] >> 4) as u8;
    s[27] = (h[8] >> 12) as u8;
    s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
    s[29] = (h[9] >> 2) as u8;
    s[30] = (h[9] >> 10) as u8;
    s[31] = (h[9] >> 18) as u8;
    
    s
}

/**
 * Adds two field elements
 * Args:
 *    a - &Fe: The first field element
 *    b - &Fe: The second field element
 * 
 * Returns:
 *    Fe: The resulting field element after addition
 */
pub fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = a[i] + b[i];
    }

    h
}

/**
 * Subtracts two field elements
 * Args:
 *    a - &Fe: The first field element
 *    b - &Fe: The second field element
 * 
 * Returns:
 *    Fe: the resulting field element after subtraction
 */
pub fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = a[i] - b[i];
    }

    h
}

/**
 * Multiplies two field elements (writing this made me want to explode)
 * Args:
 *    a - &Fe: The first field element
 *    b - &Fe: The second field element
 * 
 * Returns:
 *    Fe: The resulting field element after multiplication
 */
pub fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a[0];
    let a1 = a[1];
    let a2 = a[2];
    let a3 = a[3];
    let a4 = a[4];
    let a5 = a[5];
    let a6 = a[6];
    let a7 = a[7];
    let a8 = a[8];
    let a9 = a[9];
    
    let b0 = b[0];
    let b1 = b[1];
    let b2 = b[2];
    let b3 = b[3];
    let b4 = b[4];
    let b5 = b[5];
    let b6 = b[6];
    let b7 = b[7];
    let b8 = b[8];
    let b9 = b[9];
    
    let mut h = [0i64; 10];
    h[0] = a0*b0 + 38*(a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1);
    h[1] = a0*b1 + a1*b0 + 38*(a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2);
    h[2] = a0*b2 + a1*b1 + a2*b0 + 38*(a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3);
    h[3] = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 38*(a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4);
    h[4] = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 + 38*(a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5);
    h[5] = a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0 + 38*(a6*b9 + a7*b8 + a8*b7 + a9*b6);
    h[6] = a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0 + 38*(a7*b9 + a8*b8 + a9*b7);
    h[7] = a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0 + 38*(a8*b9 + a9*b8);
    h[8] = a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0 + 38*(a9*b9);
    h[9] = a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
    
    fe_reduce(&mut h);

    h
}

/**
 * Squares a field element
 * Args:
 *    a - &Fe: The field element to square
 * 
 * Returns:
 *    Fe: The resulting field element after squaring
 */
pub fn fe_square(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/**
 * Multiplies a field element by 121666
 * Args:
 *    a - &Fe: The field element to multiply
 * 
 * Returns:
 *    Fe: The resulting field element after multiplication
 */
pub fn fe_mul_121666(a: &Fe) -> Fe {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = a[i] * 121666;
    }

    fe_reduce(&mut h);

    h
}

/**
 * Computes the multiplicative inverse of a field element
 * Args:
 *    z - &Fe: The field element to invert
 * 
 * Returns:
 *    Fe: The resulting field element after inversion
 */
pub fn fe_invert(z: &Fe) -> Fe {
    let mut t0 = fe_square(z);
    let mut t1 = fe_square(&t0);
    t1 = fe_square(&t1);
    t1 = fe_mul(z, &t1);
    t0 = fe_mul(&t0, &t1);

    let mut t2 = fe_square(&t0);
    t1 = fe_mul(&t1, &t2);
    t2 = fe_square(&t1);
    for _ in 0..4 {
        t2 = fe_square(&t2);
    }

    t1 = fe_mul(&t2, &t1);
    t2 = fe_square(&t1);
    for _ in 0..9 {
        t2 = fe_square(&t2);
    }

    t2 = fe_mul(&t2, &t1);
    let mut t3 = fe_square(&t2);
    for _ in 0..19 {
        t3 = fe_square(&t3);
    }

    t2 = fe_mul(&t3, &t2);
    t2 = fe_square(&t2);
    for _ in 0..9 {
        t2 = fe_square(&t2);
    }

    t1 = fe_mul(&t2, &t1);
    t2 = fe_square(&t1);
    for _ in 0..49 {
        t2 = fe_square(&t2);
    }

    t2 = fe_mul(&t2, &t1);
    t3 = fe_square(&t2);
    for _ in 0..99 {
        t3 = fe_square(&t3);
    }

    t2 = fe_mul(&t3, &t2);
    t2 = fe_square(&t2);
    for _ in 0..49 {
        t2 = fe_square(&t2);
    }

    t1 = fe_mul(&t2, &t1);
    t1 = fe_square(&t1);
    for _ in 0..4 {
        t1 = fe_square(&t1);
    }

    fe_mul(&t1, &t0)
}

/**
 * Reduces a field element modulo the prime
 * Args:
 *    h - &mut Fe: The field element to reduce
 * 
 * Returns:
 *    (): Nothing
 */
pub fn fe_reduce(h: &mut Fe) {
    let mut carry: i64;
    
    carry = (h[9] + (1 << 24)) >> 25; h[0] += carry * 19; h[9] -= carry << 25;
    carry = (h[1] + (1 << 24)) >> 25; h[2] += carry; h[1] -= carry << 25;
    carry = (h[3] + (1 << 24)) >> 25; h[4] += carry; h[3] -= carry << 25;
    carry = (h[5] + (1 << 24)) >> 25; h[6] += carry; h[5] -= carry << 25;
    carry = (h[7] + (1 << 24)) >> 25; h[8] += carry; h[7] -= carry << 25;
    
    carry = (h[0] + (1 << 25)) >> 26; h[1] += carry; h[0] -= carry << 26;
    carry = (h[2] + (1 << 25)) >> 26; h[3] += carry; h[2] -= carry << 26;
    carry = (h[4] + (1 << 25)) >> 26; h[5] += carry; h[4] -= carry << 26;
    carry = (h[6] + (1 << 25)) >> 26; h[7] += carry; h[6] -= carry << 26;
    carry = (h[8] + (1 << 25)) >> 26; h[9] += carry; h[8] -= carry << 26;
}

/**
 * Conditionally swaps two field elements
 * Args:
 *    a - &mut Fe: The first field element
 *    b - &mut Fe: The second field element
 *    swap - u8: The swap condition (0 or 1)
 * 
 * Returns:
 *    (): Nothing
 */
pub fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u8) {
    let mask = -(swap as i64);
    for i in 0..10 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_x25519_exchange() {
        let alice = X25519PrivateKey::generate().unwrap();
        let bob = X25519PrivateKey::generate().unwrap();
        
        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();
        
        let alice_shared = alice.diffie_hellman(&bob_pub).unwrap();
        let bob_shared = bob.diffie_hellman(&alice_pub).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
}