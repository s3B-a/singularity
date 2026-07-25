// crypto/asymmetric/ecc_generic.rs - Elliptic Curve Cryptography (Generic Implementation)
// This module provides a generic implementation of elliptic curve operations for NIST curves

use crate::crypto::bignum::BigNum;
use crate::crypto::encoding::asn1::DerDecoder;
use crate::crypto::{Error, Result};
use std::cmp::Ordering;
use std::ops::{Add, Mul, Shr, Sub};

// Represents the supported NIST curves for ECDSA and ECDH operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NistCurve {
    P384,
    P521,
}

// Represents a point on an elliptic curve in affine coordinates (x, y)
#[derive(Clone, Debug)]
struct AffinePoint {
    x: BigNum,
    y: BigNum,
    infinity: bool,
}

impl AffinePoint {

    /**
     * Returns the point at infinity.
     * Args:
     *    () - None
     * 
     * Returns:
     *    Self: The point at infinity, represented as (0, 0) with the infinity flag set to true
     */
    fn infinity() -> Self {
        Self { x: BigNum::zero(), y: BigNum::zero(), infinity: true }
    }
}

// Represents the parameters of an elliptic curve, including the prime field, coefficients, order, generator point, and field size
struct CurveParams {
    p: BigNum,
    a: BigNum,
    b: BigNum,
    n: BigNum,
    g: AffinePoint,
    field_bytes: usize,
}

/**
 * Converts a hexadecimal string to a vector of bytes
 * Args:
 *    hex - &str: The hexadecimal string to convert
 * 
 * Returns:
 *    Vec<u8>: The resulting vector of bytes
 */
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = if clean.len() % 2 == 1 { format!("0{}", clean) } else { clean };
    (0..padded.len()).step_by(2).map(|i| {
        u8::from_str_radix(&padded[i..i + 2], 16
        ).expect("invalid hex constant")
    }).collect()
}

/**
 * Converts a hexadecimal string to a BigNum
 * Args:
 *    hex - &str: The hexadecimal string to convert
 * 
 * Returns:
 *    BigNum: The resulting BigNum representation of the hexadecimal string
 */
fn bignum_from_hex(hex: &str) -> BigNum {
    BigNum::from_bytes_be(&hex_to_bytes(hex))
}

/**
 * Converts a decimal string to a BigNum
 * Args:
 *    decimal - &str: The decimal string to convert
 * 
 * Returns:
 *    BigNum: The resulting BigNum representation of the decimal string
 */
fn bignum_from_decimal(decimal: &str) -> BigNum {
    let mut n = BigNum::zero();
    let ten = BigNum::from_u64(10);
    for c in decimal.chars() {
        if c.is_whitespace() {
            continue;
        }

        let digit = c.to_digit(10).expect("invalid decimal constant") as u64;
        n = n.mul(ten.clone()).add(BigNum::from_u64(digit));
    }

    n
}

/**
 * Returns the parameters for the specified NIST curve
 * Args:
 *    curve - NistCurve: The NIST curve for which to retrieve parameters
 * 
 * Returns:
 *    CurveParams: The parameters of the specified NIST curve, including the prime field, coefficients, order, generator point, and field size
 */
fn curve_params(curve: NistCurve) -> CurveParams {
    match curve {
        NistCurve::P384 => {
            let p = bignum_from_decimal(
                "39402006196394479212279040100143613805079739270465446667948293404245721771496\
                 870329047266088258938001861606973112319",
            );
            let n = bignum_from_decimal(
                "39402006196394479212279040100143613805079739270465446667946905279627659399113\
                 263569398956308152294913554433653942643",
            );
            let a = p.clone().sub(BigNum::from_u64(3));
            let b = bignum_from_hex(
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            );
            let gx = bignum_from_hex(
                "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            );
            let gy = bignum_from_hex(
                "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            );

            CurveParams {
                p,
                a,
                b,
                n,
                g: AffinePoint { x: gx, y: gy, infinity: false },
                field_bytes: 48,
            }
        }
        NistCurve::P521 => {
            let p = bignum_from_decimal(
                "68647976601306097149819007990813932172694353001433054093944634591855431833976\
                 56052122559640661454554977296311391480858037121987999716643812574028291115057151",
            );
            let n = bignum_from_decimal(
                "68647976601306097149819007990813932172694353001433054093944634591855431833976\
                 55394245057746333217197532963996371363321113864768612440380340372808892707005449",
            );
            let a = p.clone().sub(BigNum::from_u64(3));
            let b = bignum_from_hex(
                "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            );
            let gx = bignum_from_hex(
                "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
            );
            let gy = bignum_from_hex(
                "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            );

            CurveParams {
                p,
                a,
                b,
                n,
                g: AffinePoint { x: gx, y: gy, infinity: false },
                field_bytes: 66,
            }
        }
    }
}

/**
 * Performs modular addition of two BigNums under a given modulus
 * Args:
 *    a - &BigNum: The first operand
 *    b - &BigNum: The second operand
 *    m - &BigNum: The modulus
 * 
 * Returns:
 *    BigNum: The result of (a + b) mod m
 */
fn mod_add(a: &BigNum, b: &BigNum, m: &BigNum) -> BigNum {
    a.clone().add(b.clone()).modulo(m)
}

/**
 * Performs modular subtraction of two BigNums under a given modulus
 * Args:
 *    a - &BigNum: The first operand
 *    b - &BigNum: The second operand
 *    m - &BigNum: The modulus
 * 
 * Returns:
 *   BigNum: The result of (a - b) mod m
 */
fn mod_sub(a: &BigNum, b: &BigNum, m: &BigNum) -> BigNum {
    a.clone().add(m.clone()).sub(b.clone()).modulo(m)
}

/**
 * Performs modular multiplication of two BigNums under a given modulus
 * Args:
 *   a - &BigNum: The first operand
 *   b - &BigNum: The second operand
 *   m - &BigNum: The modulus
 * 
 * Returns:
 *   BigNum: The result of (a * b) mod m
 */
fn mod_mul(a: &BigNum, b: &BigNum, m: &BigNum) -> BigNum {
    a.clone().mul(b.clone()).modulo(m)
}

/**
 * Computes the modular inverse of a BigNum under a given modulus
 * Args:
 *    a - &BigNum: The number to invert
 *    m - &BigNum: The modulus
 * 
 * Returns:
 *    Result<BigNum>: The modular inverse of a mod m, or an error if it does not exist
 */
fn mod_inv(a: &BigNum, m: &BigNum) -> Result<BigNum> {
    a.clone().modulo(m).mod_inverse(m)
}

/**
 * Doubles a point on the elliptic curve using the curve's parameters
 * Args:
 *    p - &AffinePoint: The point to double
 *    curve - &CurveParams: The parameters of the elliptic curve
 * 
 * Returns:
 *    Result<AffinePoint>: The resulting point after doubling, or an error if the operation fails
 */
fn point_double(p: &AffinePoint, curve: &CurveParams) -> Result<AffinePoint> {
    if p.infinity || p.y.is_zero() {
        return Ok(AffinePoint::infinity());
    }

    let x2 = mod_mul(&p.x, &p.x, &curve.p);
    let three_x2 = mod_mul(&BigNum::from_u64(3), &x2, &curve.p);
    let numerator = mod_add(&three_x2, &curve.a, &curve.p);
    let two_y = mod_add(&p.y, &p.y, &curve.p);
    let inv_two_y = mod_inv(&two_y, &curve.p)?;
    let lambda = mod_mul(&numerator, &inv_two_y, &curve.p);

    let lambda_sq = mod_mul(&lambda, &lambda, &curve.p);
    let two_x = mod_add(&p.x, &p.x, &curve.p);
    let x3 = mod_sub(&lambda_sq, &two_x, &curve.p);
    let x_diff = mod_sub(&p.x, &x3, &curve.p);
    let y3 = mod_sub(&mod_mul(&lambda, &x_diff, &curve.p), &p.y, &curve.p);

    Ok(AffinePoint { x: x3, y: y3, infinity: false })
}

/**
 * Adds two points on the elliptic curve using the curve's parameters
 * Args:
 *    p - &AffinePoint: The first point
 *    q - &AffinePoint: The second point
 *    curve - &CurveParams: The parameters of the elliptic curve
 *
 * Returns:
 *    Result<AffinePoint>: The resulting point after addition, or an error if the operation fails
 */
fn point_add(p: &AffinePoint, q: &AffinePoint, curve: &CurveParams) -> Result<AffinePoint> {
    if p.infinity {
        return Ok(q.clone());
    }

    if q.infinity {
        return Ok(p.clone());
    }

    if p.x == q.x {
        if mod_add(&p.y, &q.y, &curve.p).is_zero() {
            return Ok(AffinePoint::infinity());
        }

        return point_double(p, curve);
    }

    let numerator = mod_sub(&q.y, &p.y, &curve.p);
    let denominator = mod_sub(&q.x, &p.x, &curve.p);
    let inv_denominator = mod_inv(&denominator, &curve.p)?;
    let lambda = mod_mul(&numerator, &inv_denominator, &curve.p);

    let lambda_sq = mod_mul(&lambda, &lambda, &curve.p);
    let x3 = mod_sub(&mod_sub(&lambda_sq, &p.x, &curve.p), &q.x, &curve.p);
    let x_diff = mod_sub(&p.x, &x3, &curve.p);
    let y3 = mod_sub(&mod_mul(&lambda, &x_diff, &curve.p), &p.y, &curve.p);

    Ok(AffinePoint { x: x3, y: y3, infinity: false })
}

/**
 * Multiplies a point on the elliptic curve by a scalar using the curve's parameters
 * Args:
 *    k - &BigNum: The scalar to multiply by
 *    point - &AffinePoint: The point to multiply
 *    curve - &CurveParams: The parameters of the elliptic curve
 *
 * Returns:
 *    Result<AffinePoint>: The resulting point after scalar multiplication, or an error if the operation fails
 */
fn scalar_mult(k: &BigNum, point: &AffinePoint, curve: &CurveParams) -> Result<AffinePoint> {
    let mut result = AffinePoint::infinity();
    if k.is_zero() {
        return Ok(result);
    }

    let bits = k.bit_length();
    for i in (0..bits).rev() {
        result = point_double(&result, curve)?;
        if k.get_bit(i) {
            result = point_add(&result, point, curve)?;
        }
    }

    Ok(result)
}

/**
 * Checks if a point lies on the elliptic curve defined by the given parameters
 * Args:
 *    point - &AffinePoint: The point to check
 *    curve - &CurveParams: The parameters of the elliptic curve
 *
 * Returns:
 *    bool: True if the point is on the curve, false otherwise
 */
fn is_on_curve(point: &AffinePoint, curve: &CurveParams) -> bool {
    if point.infinity {
        return false;
    }

    let y2 = mod_mul(&point.y, &point.y, &curve.p);
    let x3 = mod_mul(&mod_mul(&point.x, &point.x, &curve.p), &point.x, &curve.p);
    let ax = mod_mul(&curve.a, &point.x, &curve.p);
    let rhs = mod_add(&mod_add(&x3, &ax, &curve.p), &curve.b, &curve.p);

    y2 == rhs
}

/**
 * Decodes a SEC1 uncompressed point (0x04 || X || Y) into an AffinePoint
 * Args:
 *    bytes - &[u8]: The encoded public key point
 *    curve - &CurveParams: The curve the point should lie on
 *
 * Returns:
 *    Result<AffinePoint>: The decoded point, or an error if the encoding is invalid
 */
fn decode_uncompressed_point(bytes: &[u8], curve: &CurveParams) -> Result<AffinePoint> {
    let expected_len = 1 + curve.field_bytes * 2;
    if bytes.len() != expected_len || bytes[0] != 0x04 {
        return Err(Error::InvalidData(
            "Unsupported EC point encoding (expected uncompressed SEC1)".to_string(),
        ));
    }

    let x = BigNum::from_bytes_be(&bytes[1..1 + curve.field_bytes]);
    let y = BigNum::from_bytes_be(&bytes[1 + curve.field_bytes..]);

    Ok(AffinePoint { x, y, infinity: false })
}

/**
 * Parses a DER ECDSA-Sig-Value (`SEQUENCE { r INTEGER, s INTEGER }`) into (r, s) as BigNums
 * Args:
 *    der - &[u8]: The DER-encoded signature, as stored in a certificate's signatureValue
 *
 * Returns:
 *    Result<(BigNum, BigNum)>: The (r, s) pair, or an error if the encoding is invalid
 */
fn parse_der_signature(der: &[u8]) -> Result<(BigNum, BigNum)> {
    let mut decoder = DerDecoder::new(der);
    decoder.sequence(|seq| {
            let r = seq.integer()?;
            let s = seq.integer()?;
            Ok((BigNum::from_bytes_be(&r), BigNum::from_bytes_be(&s)))
        }).map_err(|_| Error::InvalidData("Invalid ECDSA-Sig-Value DER encoding".to_string()))
}

fn write_fixed_be(value: &BigNum, dest: &mut [u8]) -> Result<()> {
    let bytes = value.to_bytes_be();
    if bytes.len() > dest.len() {
        return Err(Error::InvalidData(
            "Signature component too large for curve field width".to_string(),
        ));
    }

    let start = dest.len() - bytes.len();
    dest[start..].copy_from_slice(&bytes);
    Ok(())
}

/**
 * Converts a DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`, the form certificates
 * actually carry) into fixed-width big-endian `r || s`, for feeding curve implementations that
 * expect a raw fixed-length signature instead
 * Args:
 *    der - &[u8]: The DER-encoded signature
 *    field_bytes - usize: The curve's coordinate width (32 for P-256)
 *
 * Returns:
 *    Result<Vec<u8>>: The fixed-width `r || s` signature
 */
pub fn der_signature_to_fixed(der: &[u8], field_bytes: usize) -> Result<Vec<u8>> {
    let (r, s) = parse_der_signature(der)?;
    let mut out = vec![0u8; field_bytes * 2];
    write_fixed_be(&r, &mut out[..field_bytes])?;
    write_fixed_be(&s, &mut out[field_bytes..])?;
    
    Ok(out)
}

/**
 * Verifies an ECDSA signature over a pre-computed message digest
 * Args:
 *    curve - NistCurve: Which NIST curve the public key is on
 *    public_key_bytes - &[u8]: The SEC1 uncompressed public key point
 *    digest - &[u8]: The message digest (already hashed per the certificate's signature
 *      algorithm - e.g. SHA-384 for ecdsa-with-SHA384)
 *    der_signature - &[u8]: The DER-encoded ECDSA-Sig-Value signature
 *
 * Returns:
 *    Result<bool>: True if the signature is valid
 */
pub fn verify_prehashed(curve: NistCurve, public_key_bytes: &[u8], digest: &[u8], der_signature: &[u8]) -> Result<bool> {
    let params = curve_params(curve);
    let public_key = decode_uncompressed_point(public_key_bytes, &params)?;
    if !is_on_curve(&public_key, &params) {
        return Ok(false);
    }

    let (r, s) = parse_der_signature(der_signature)?;
    if r.is_zero() || s.is_zero() || r.cmp(&params.n) != Ordering::Less || s.cmp(&params.n) != Ordering::Less {
        return Ok(false);
    }

    let e = hash_to_int(digest, &params.n);
    let w = match mod_inv(&s, &params.n) {
        Ok(inv) => inv,
        Err(_) => return Ok(false),
    };

    let u1 = mod_mul(&e, &w, &params.n);
    let u2 = mod_mul(&r, &w, &params.n);

    let p1 = scalar_mult(&u1, &params.g, &params)?;
    let p2 = scalar_mult(&u2, &public_key, &params)?;
    let point = point_add(&p1, &p2, &params)?;
    if point.infinity {
        return Ok(false);
    }

    let v = point.x.modulo(&params.n);
    Ok(v == r)
}

/**
 * Converts a message digest to an integer for ECDSA: when the digest is longer than 
 * the group order in bits, only the leftmost `n_bits` bits are used
 * Args:
 *    digest - &[u8]: The message digest
 *    n - &BigNum: The curve's group order
 *
 * Returns:
 *    BigNum: The digest interpreted as an integer, truncated to the order's bit length if needed
 */
fn hash_to_int(digest: &[u8], n: &BigNum) -> BigNum {
    let n_bits = n.bit_length();
    let digest_bits = digest.len() * 8;
    let e = BigNum::from_bytes_be(digest);
    if digest_bits > n_bits {
        e.shr(digest_bits - n_bits)
    } else {
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_is_on_curve_p384() {
        let curve = curve_params(NistCurve::P384);
        assert!(is_on_curve(&curve.g, &curve));
    }

    #[test]
    fn test_generator_is_on_curve_p521() {
        let curve = curve_params(NistCurve::P521);
        assert!(is_on_curve(&curve.g, &curve));
    }

    #[test]
    fn test_scalar_mult_by_order_is_infinity_p384() {
        let curve = curve_params(NistCurve::P384);
        let result = scalar_mult(&curve.n, &curve.g, &curve).unwrap();
        assert!(result.infinity, "n*G should be the point at infinity");
    }

    #[test]
    fn test_scalar_mult_by_order_is_infinity_p521() {
        let curve = curve_params(NistCurve::P521);
        let result = scalar_mult(&curve.n, &curve.g, &curve).unwrap();
        assert!(result.infinity, "n*G should be the point at infinity");
    }

    #[test]
    fn test_double_matches_add_to_self_p384() {
        let curve = curve_params(NistCurve::P384);
        let doubled = point_double(&curve.g, &curve).unwrap();
        let added = point_add(&curve.g, &curve.g, &curve).unwrap();
        assert_eq!(doubled.x, added.x);
        assert_eq!(doubled.y, added.y);
        assert!(is_on_curve(&doubled, &curve));
    }

    #[test]
    fn test_scalar_mult_two_matches_double_p521() {
        let curve = curve_params(NistCurve::P521);
        let doubled = point_double(&curve.g, &curve).unwrap();
        let via_scalar = scalar_mult(&BigNum::from_u64(2), &curve.g, &curve).unwrap();
        assert_eq!(doubled.x, via_scalar.x);
        assert_eq!(doubled.y, via_scalar.y);
    }

    #[test]
    fn test_curve_field_widths_match_encoded_generator() {
        let p384 = curve_params(NistCurve::P384);
        assert!(p384.g.x.to_bytes_be().len() <= p384.field_bytes);
        assert!(p384.g.y.to_bytes_be().len() <= p384.field_bytes);

        let p521 = curve_params(NistCurve::P521);
        assert!(p521.g.x.to_bytes_be().len() <= p521.field_bytes);
        assert!(p521.g.y.to_bytes_be().len() <= p521.field_bytes);
    }
}