// crypto/asymmetric/p256.rs - P-256 Elliptic Curve Cryptography
// https://www.ietf.org/rfc/rfc5480

use crate::crypto::{Error, Result};
use crate::crypto::random;

// Field element represented as 4 u64 limbs (256 bits)
type FieldElement = [u64; 4];

// P-256 curve parameters
const P: FieldElement = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

// Order of the base point G
const N: FieldElement = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

// Curve coefficients
const A: FieldElement = [
    0xFFFFFFFFFFFFFFFC,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

// Coefficient B
const B: FieldElement = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

// Base point G
const GX: FieldElement = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

// Y coordinate of base point G
const GY: FieldElement = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

// P-256 Private Key structure
#[derive(Clone)]
pub struct P256PrivateKey {
    scalar: [u8; 32],
}

// P-256 Public Key structure
#[derive(Clone, Debug, PartialEq)]
pub struct P256PublicKey {
    point: AffinePoint,
}

// P-256 Signature structure
#[derive(Clone, Debug, PartialEq)]
pub struct P256Signature {
    r: [u8; 32],
    s: [u8; 32],
}

// Affine point on the curve
#[derive(Clone, Debug, PartialEq)]
struct AffinePoint {
    x: FieldElement,
    y: FieldElement,
    inf: bool,
}

// Jacobian point on the curve
#[derive(Clone)]
struct JacobianPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    inf: bool,
}

impl P256PrivateKey {

    /**
     * Generates a new random P-256 private key
     * Args:
     *    (): No arguments
     * 
     * Returns:
     *   Result<Self>: The generated P256PrivateKey or an error if generation fails
     */
    pub fn generate() -> Result<Self> {
        let mut scalar = [0u8; 32];
        loop {
            random::fill_random(&mut scalar)?;

            let scalar_fe = bytes_to_field(&scalar);
            if !fe_is_zero(&scalar_fe) && fe_cmp(&scalar_fe, &N) < 0 {
                break;
            }
        }

        Ok(Self { scalar })
    }

    /**
     * Creates a P-256 private key from raw bytes
     * Args:
     *    bytes - &[u8]: The byte slice representing the private key
     * 
     * Returns:
     *    Result<Self>: The P256PrivateKey or an error if the bytes are invalid
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(bytes);

        let scalar_fe = bytes_to_field(&scalar);
        if fe_is_zero(&scalar_fe) || fe_cmp(&scalar_fe, &N) >= 0 {
            return Err(Error::CryptoError("Invalid private key".to_string()));
        }

        Ok(Self { scalar })
    }

    /**
     * Returns the private key as bytes
     * Args:
     *    &self: The P256PrivateKey instance
     * 
     * Returns:
     *    [u8; 32]: The byte array representing the private key
     */
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar
    }

    /**
     * Derives the corresponding public key from the private key
     * Args:
     *    &self: The P256PrivateKey instance
     * 
     * Returns:
     *    P256PublicKey: The derived public key
     */
    pub fn public_key(&self) -> P256PublicKey {
        let scalar_fe = bytes_to_field(&self.scalar);
        let point = scalar_mult_base(&scalar_fe);

        P256PublicKey { point: jacobian_to_affine(&point) }
    }

    /**
     * Performs ECDH key exchange to derive a shared secret via the private key and a peer's public key
     * The shared secret is the x-coordinate of the resulting point, allowing both parties to compute the
     * same secret independently.
     * 
     * Args:
     *    &self: The P256PrivateKey instance
     *    their_public - &P256PublicKey: The peer's public key
     * 
     * Returns:
     *    Result<[u8; 32]>: The derived shared secret as a byte array or an error if the operation fails
     */
    pub fn diffie_hellman(&self, their_public: &P256PublicKey) -> Result<[u8; 32]> {
        if their_public.point.inf {
            return Err(Error::CryptoError("Invalid public key".to_string()));
        }

        let scalar_fe = bytes_to_field(&self.scalar);
        let their_jacobian = affine_to_jacobian(&their_public.point);
        let shared = scalar_mult(&scalar_fe, &their_jacobian);
        if shared.inf {
            return Err(Error::CryptoError("Invalid shared secret".to_string()));
        }

        let shared_affine = jacobian_to_affine(&shared);
        
        Ok(field_to_bytes(&shared_affine.x))
    }
}

impl P256PublicKey {

    /**
     * Creates a P-256 public key from uncompressed point bytes
     * Args:
     *    bytes - &[u8]: The byte slice representing the uncompressed public key
     * 
     * Returns:
     *    Result<Self>: The P256PublicKey or an error if the bytes are invalid
     */
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(Error::InvalidKeySize);
        }

        let x = bytes_to_field(&bytes[1..33].try_into().unwrap());
        let y = bytes_to_field(&bytes[33..65].try_into().unwrap());
        let point = AffinePoint {
            x,
            y,
            inf: false,
        };
        
        if !point_on_curve(&point) {
            return Err(Error::CryptoError("Point not on curve".to_string()));
        }
        
        Ok(Self { point })
    }

    /**
     * Creates a P-256 public key from compressed point bytes
     * Args:
     *    bytes - &[u8]: The byte slice representing the compressed public key
     * 
     * Returns:
     *    Result<Self>: The P256PublicKey or an error if the bytes are invalid
     */
    pub fn from_compressed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
            return Err(Error::InvalidKeySize);
        }
        
        let x = bytes_to_field(&bytes[1..33].try_into().unwrap());
        let y_is_odd = bytes[0] == 0x03;
        let y = decompress_y(&x, y_is_odd)?;
        let point = AffinePoint {
            x,
            y,
            inf: false,
        };
        
        Ok(Self { point })
    }
    
    /**
     * Returns the public key as uncompressed point bytes
     * Args:
     *    &self: The P256PublicKey instance
     * 
     * Returns:
     *    [u8; 65]: The byte array representing the uncompressed public key, the reason why it's 65 is
     *    because it includes a leading byte (0x04) followed by 32 bytes for the x-coordinate and 32 bytes
     *    for the y-coordinate. This format is defined by the SEC1 standard for representing elliptic curve
     *    public keys
     */
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[1..33].copy_from_slice(&field_to_bytes(&self.point.x));
        bytes[33..65].copy_from_slice(&field_to_bytes(&self.point.y));
        
        bytes
    }
    
    /**
     * Returns the public key as compressed point bytes
     * Args:
     *    &self: The P256PublicKey instance
     * 
     * Returns:
     *    [u8; 33]: The byte array representing the compressed public key, which includes a leading byte
     *    (0x02 or 0x03) indicating the parity of the y-coordinate, followed by 32 bytes for the x-coordinate
     */
    pub fn to_compressed(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = if self.point.y[0] & 1 == 1 { 0x03 } else { 0x02 };
        bytes[1..33].copy_from_slice(&field_to_bytes(&self.point.x));
        
        bytes
    }
}

impl P256Signature {
    
    /**
     * Creates a P-256 signature from raw bytes
     * Args:
     *    bytes - &[u8]: The byte slice representing the signature
     * 
     * Returns:
     *    Result<Self>: The P256Signature or an error if the bytes are invalid
     */
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);

        Ok(Self { r, s })
    }

    /**
     * Returns the signature as bytes
     * Args:
     *    &self: The P256Signature instance
     * 
     * Returns:
     *    [u8; 64]: The byte array representing the signature
     */
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);

        bytes
    }
}

/**
 * Checks if a field element is zero
 * Args:
 *    a - &FieldElement: The field element to check
 * 
 * Returns:
 *    bool: True if the field element is zero, false otherwise
 */
fn fe_is_zero(a: &FieldElement) -> bool {
    a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0
}

/**
 * Compares two field elements
 * Args:
 *    a - &FieldElement: The first field element
 *    b - &FieldElement: The second field element
 * 
 * Returns:
 *    i32: -1 if a < b, 0 if a == b, 1 if a > b
 */
fn fe_cmp(a: &FieldElement, b: &FieldElement) -> i32 {
    for i in (0..4).rev() {
        if a[i] < b[i] {
            return 1;
        }

        if a[i] > b[i] {
            return -1;
        }
    }

    0
}

/**
 * Adds two field elements
 * Args:
 *    a - &FieldElement: The first field element
 *    b - &FieldElement: The second field element
 * 
 * Returns:
 *    FieldElement: The result of a + b mod P (where P is the field prime)
 */
fn fe_add(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut result = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let sum = a[i] as u128 + b[i] as u128 + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }

    fe_reduce(&result)
}

/**
 * Subtracts two field elements
 * Args:
 *    a - &FieldElement: The first field element
 *    b - &FieldElement: The second field element
 * 
 * Returns:
 *    FieldElement: The result of a - b mod P (where P is the field prime)
 */
fn fe_sub(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut result = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = a[i] as i128 - b[i] as i128 - borrow;
        if diff < 0 {
            result[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }

    if borrow != 0 {
        fe_add(&result, &P)
    } else {
        result
    }
}

/**
 * Multiplies two field elements
 * Args:
 *    a - &FieldElement: The first field element
 *    b - &FieldElement: The second field element
 * 
 * Returns:
 *    FieldElement: The result of a * b mod P (where P is the field prime)
 */
fn fe_mul(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut result = [0u128; 8];
    for i in 0..4 {
        for j in 0..4 {
            result[i + j] += (a[i] as u128) * (b[j] as u128);
        }
    }

    for i in 0..7 {
        result[i + 1] += result[i] >> 64;
        result[i] &= 0xFFFFFFFFFFFFFFFF;
    }

    let mut r = [0u64; 4];
    for i in 0..4 {
        r[i] = result[i] as u64;
    }

    fe_reduce(&r)
}

/**
 * Squares a field element
 * Args:
 *    a - &FieldElement: The field element to square
 * 
 * Returns:
 *    FieldElement: The result of a^2 mod P (where P is the field prime)
 */
fn fe_square(a: &FieldElement) -> FieldElement {
    fe_mul(a, a)
}

/**
 * Reduces a field element modulo P
 * Args:
 *    a - &FieldElement: The field element to reduce
 * 
 * Returns:
 *    FieldElement: The reduced field element
 */
fn fe_reduce(a: &FieldElement) -> FieldElement {
    let mut result = *a;
    while fe_cmp(&result, &P) >= 0 {
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = result[i] as i128 - P[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
    }

    result
}

/**
 * Inverts a field element
 * Args:
 *    a - &FieldElement: The field element to invert
 * 
 * Returns:
 *    FieldElement: The multiplicative inverse of a mod P (where P is the field prime)
 */
fn fe_invert(a: &FieldElement) -> FieldElement {
    let mut result = [1, 0, 0, 0];
    let mut base = *a;
    let exp = [
        0xFFFFFFFFFFFFFFFFu64,
        0xFFFFFFFFFFFFFFFFu64,
        0xFFFFFFFFFFFFFFFFu64,
        0xFFFFFFFF00000000u64,
    ];

    for i in (0..256).rev() {
        if (exp[i / 64] >> (i % 64)) & 1 == 1 {
            result = fe_mul(&result, &base);
        }
        base = fe_square(&base);
    }

    result
}

/**
 * Decompresses a y-coordinate from an x-coordinate and a parity bit
 * Args:
 *    x - &FieldElement: The x-coordinate of the point
 *    y_is_odd - bool: The parity bit indicating if y is odd
 * 
 * Returns:
 *    Result<FieldElement>: The decompressed y-coordinate or an error if no valid y exists
 */
fn decompress_y(x: &FieldElement, y_is_odd: bool) -> Result<FieldElement> {
    let x2 = fe_square(x);
    let x3 = fe_mul(&x2, x);
    let ax = fe_mul(&A, x);
    let rhs = fe_add(&fe_add(&x3, &ax), &B);
    
    let y = fe_sqrt(&rhs)?;
    let y_odd = y[0] & 1 == 1;
    if y_odd != y_is_odd {
        Ok(fe_sub(&P, &y))
    } else {
        Ok(y)
    }
}

/**
 * Computes the square root of a field element
 * Args:
 *    a - &FieldElement: The field element to compute the square root of
 * 
 * Returns:
 *    Result<FieldElement>: The square root of a mod P (where P is the field prime) or an error if
 *    no square root exists
 */
fn fe_sqrt(a: &FieldElement) -> Result<FieldElement> {
    let mut result = [1, 0, 0, 0];
    let mut base = *a;
    let exp = [
        0x3FFFFFFFFFFFFFFFu64,
        0xFFFFFFFFFFFFFFFFu64,
        0xFFFFFFFFFFFFFFFFu64,
        0x3FFFFFFFFFFFFFFFu64,
    ];

    for i in (0..256).rev() {
        if (exp[i / 64] >> (i % 64)) & 1 == 1 {
            result = fe_mul(&result, &base);
        }
        base = fe_square(&base);
    }

    if fe_square(&result) != *a {
        return Err(Error::CryptoError("No square root exists".to_string()));
    }

    Ok(result)
}

/**
 * Checks if a point is on the curve
 * Args:
 *    p - &AffinePoint: The point to check
 * 
 * Returns:
 *    bool: True if the point is on the curve, false otherwise
 */
fn point_on_curve(p: &AffinePoint) -> bool {
    if p.inf {
        return true;
    }

    let y2 = fe_square(&p.y);
    let x2 = fe_square(&p.x);
    let x3 = fe_mul(&x2, &p.x);
    let ax = fe_mul(&A, &p.x);
    let rhs = fe_add(&fe_add(&x3, &ax), &B);

    fe_cmp(&y2, &rhs) == 0
}

/**
 * Converts an affine point to a Jacobian point
 * This is done by setting the z-coordinate to 1 for non-infinite points and 0 for infinite points
 * 
 * Args:
 *    p - &AffinePoint: The affine point to convert
 * 
 * Returns:
 *    JacobianPoint: The converted Jacobian point
 */
fn affine_to_jacobian(p: &AffinePoint) -> JacobianPoint {
    if p.inf {
        return JacobianPoint {
            x: [0; 4],
            y: [0; 4],
            z: [0; 4],
            inf: true,
        };
    }

    JacobianPoint {
        x: p.x,
        y: p.y,
        z: [1, 0, 0, 0],
        inf: false,
    }
}

/**
 * Converts a Jacobian point to an affine point
 * This involves computing the inverse of the z-coordinate and adjusting the x and y coordinates accordingly
 * 
 * Args:
 *    p - &JacobianPoint: The Jacobian point to convert
 * 
 * Returns:
 *    AffinePoint: The converted affine point
 */
fn jacobian_to_affine(p: &JacobianPoint) -> AffinePoint {
    if p.inf {
        return AffinePoint {
            x: [0; 4],
            y: [0; 4],
            inf: true,
        };
    }

    let z_inv = fe_invert(&p.z);
    let z_inv2 = fe_square(&z_inv);
    let z_inv3 = fe_mul(&z_inv2, &z_inv);

    AffinePoint {
        x: fe_mul(&p.x, &z_inv2),
        y: fe_mul(&p.y, &z_inv3),
        inf: false,
    }
}

/**
 * Doubles a Jacobian point
 * This is done by using the standard point doubling formula for 
 * elliptic curves (https://www.secg.org/sec1-v2.pdf pg. 3-8) in Jacobian coordinates
 * 
 * Args:
 *    p - &JacobianPoint: The Jacobian point to double
 * 
 * Returns:
 *    JacobianPoint: The double Jacobian point
 */
fn jacobian_double(p: &JacobianPoint) -> JacobianPoint {
    if p.inf {
        return p.clone();
    }
    
    let s = fe_mul(&fe_mul(&[4, 0, 0, 0], &p.x), &fe_square(&p.y));
    let m = fe_add(&fe_mul(&[3, 0, 0, 0], &fe_square(&p.x)), &fe_mul(&A, &fe_square(&fe_square(&p.z))));
    let x3 = fe_sub(&fe_square(&m), &fe_mul(&[2, 0, 0, 0], &s));
    let y3 = fe_sub(&fe_mul(&m, &fe_sub(&s, &x3)), &fe_mul(&[8, 0, 0, 0], &fe_square(&fe_square(&p.y))));
    let z3 = fe_mul(&fe_mul(&[2, 0, 0, 0], &p.y), &p.z);
    
    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        inf: false,
    }
}

/**
 * Adds two Jacobian points
 * This is done by using the standard point addition formula for elliptic curves
 * 
 * Args:
 *    p - &JacobianPoint: The first Jacobian point
 *    q - &JacobianPoint: The second Jacobian point
 * 
 * Returns:
 *    JacobianPoint: The resulting Jacobian point after addition
 */
fn jacobian_add(p: &JacobianPoint, q: &JacobianPoint) -> JacobianPoint {
    if p.inf {
        return q.clone();
    }

    if q.inf {
        return p.clone();
    }
    
    let z1z1 = fe_square(&p.z);
    let z2z2 = fe_square(&q.z);
    let u1 = fe_mul(&p.x, &z2z2);
    let u2 = fe_mul(&q.x, &z1z1);
    let s1 = fe_mul(&p.y, &fe_mul(&q.z, &z2z2));
    let s2 = fe_mul(&q.y, &fe_mul(&p.z, &z1z1));
    if fe_cmp(&u1, &u2) == 0 {
        if fe_cmp(&s1, &s2) == 0 {
            return jacobian_double(p);
        } else {
            return JacobianPoint {
                x: [0; 4],
                y: [1; 4],
                z: [0; 4],
                inf: true,
            };
        }
    }
    
    let h = fe_sub(&u2, &u1);
    let r = fe_sub(&s2, &s1);
    let hh = fe_square(&h);
    let hhh = fe_mul(&h, &hh);
    let v = fe_mul(&u1, &hh);
    
    let x3 = fe_sub(&fe_sub(&fe_square(&r), &hhh), &fe_mul(&[2, 0, 0, 0], &v));
    let y3 = fe_sub(&fe_mul(&r, &fe_sub(&v, &x3)), &fe_mul(&s1, &hhh));
    let z3 = fe_mul(&fe_mul(&p.z, &q.z), &h);
    
    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        inf: false,
    }
}

/**
 * Performs scalar multiplication of the base point G by a scalar
 * Args:
 *    scalar - &FieldElement: The scalar to multiply by
 * 
 * Returns:
 *    JacobianPoint: The resulting Jacobian point after multiplication
 */
fn scalar_mult_base(scalar: &FieldElement) -> JacobianPoint {
    let base = affine_to_jacobian(&AffinePoint {
        x: GX,
        y: GY,
        inf: false,
    });
    
    scalar_mult(scalar, &base)
}

/**
 * Performs scalar multiplication of a point by a scalar
 * Args:
 *    scalar - &FieldElement: The scalar to multiply by
 *    point - &JacobianPoint: The point to multiply
 * 
 * Returns:
 *    JacobianPoint: The resulting Jacobian point after multiplication
 */
fn scalar_mult(scalar: &FieldElement, point: &JacobianPoint) -> JacobianPoint {
    let mut result = JacobianPoint {
        x: [0; 4],
        y: [1; 4],
        z: [0; 4],
        inf: true,
    };
    
    let mut temp = point.clone();
    for i in 0..4 {
        let mut k = scalar[i];
        for _ in 0..64 {
            if k & 1 == 1 {
                result = jacobian_add(&result, &temp);
            }
            temp = jacobian_double(&temp);
            k >>= 1;
        }
    }
    
    result
}

/**
 * Converts a byte array to a field element
 * Args:
 *    bytes - &[u8; 32]: The byte array to convert
 * 
 * Returns:
 *    FieldElement: The resulting field element
 */
fn bytes_to_field(bytes: &[u8; 32]) -> FieldElement {
    let mut result = [0u64; 4];
    for i in 0..4 {
        result[i] = u64::from_be_bytes([
            bytes[i * 8],
            bytes[i * 8 + 1],
            bytes[i * 8 + 2],
            bytes[i * 8 + 3],
            bytes[i * 8 + 4],
            bytes[i * 8 + 5],
            bytes[i * 8 + 6],
            bytes[i * 8 + 7],
        ]);
    }

    result
}

/**
 * Converts a field element to a byte array
 * Args:
 *    fe - &FieldElement: The field element to convert
 * 
 * Returns:
 *    [u8; 32]: The resulting byte array
 */
fn field_to_bytes(fe: &FieldElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&fe[i].to_be_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_p256_key_generation() {
        let key = P256PrivateKey::generate().unwrap();
        let _pubkey = key.public_key();
    }
    
    #[test]
    fn test_p256_dh() {
        let alice = P256PrivateKey::generate().unwrap();
        let bob = P256PrivateKey::generate().unwrap();
        
        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();
        
        let alice_shared = alice.diffie_hellman(&bob_pub).unwrap();
        let bob_shared = bob.diffie_hellman(&alice_pub).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
}