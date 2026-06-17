// ECDSA (Edwards Curve Digital Signature Algorithm) implementation supporting Ed25519 and P-256 curves
// https://www.rfc-editor.org/rfc/rfc8032

use crate::crypto::{Error, Result};
use crate::crypto::bignum::BigNum;
use super::{ed25519, p256};
use crate::crypto::hash::sha2::Sha256;
use crate::crypto::hash::hmac::Hmac;
use std::ops::{Add, Sub, Mul, Div};
use std::cmp::Ordering;

// SignatureScheme trait for signing messages
pub trait SignatureScheme {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn public_bytes(&self) -> Vec<u8>;
}

// VerificationScheme trait for verifying signatures
pub trait VerificationScheme {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool>;
    fn to_bytes(&self) -> Vec<u8>;
}

// P-256 curve order in bytes
const P256_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

// Supported signature curves
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCurve {
    Ed25519,
    P256,
}

// SigningKey enum encapsulating different private key types
pub enum SigningKey {
    Ed25519(ed25519::Ed25519PrivateKey),
    P256Ecdsa(P256EcdsaPrivateKey),
}

// VerifyingKey enum encapsulating different public key types
pub enum VerifyingKey {
    Ed25519(ed25519::Ed25519PublicKey),
    P256Ecdsa(P256EcdsaPublicKey),
}

// Signature enum encapsulating different signature types
pub enum Signature {
    Ed25519(ed25519::Ed25519Signature),
    P256Ecdsa(p256::P256Signature),
}

// P-256 ECDSA Private Key structure
pub struct P256EcdsaPrivateKey {
    inner: p256::P256PrivateKey,
}

// P-256 ECDSA Public Key structure
pub struct P256EcdsaPublicKey {
    inner: p256::P256PublicKey,
}

// P-256 Point structure for elliptic curve point operations
#[derive(Clone, Debug)]
struct P256Point {
    x: BigNum,
    y: BigNum,
    infinity: bool,
}

impl SigningKey {

    /**
     * Generates a new SigningKey for the specified curve
     * Args:
     *    curve - SignatureCurve: The signature curve to use
     * 
     * Returns:
     *    Result<Self>: The generated SigningKey or an error if generation fails
     */
    pub fn generate(curve: SignatureCurve) -> Result<Self> {
        match curve {
            SignatureCurve::Ed25519 => {
                Ok(SigningKey::Ed25519(ed25519::Ed25519PrivateKey::generate()?))
            }
            SignatureCurve::P256 => {
                let p256_key = p256::P256PrivateKey::generate()?;

                Ok(SigningKey::P256Ecdsa(P256EcdsaPrivateKey { inner: p256_key }))
            }
        }
    }
    
    /**
     * Creates a SigningKey from bytes for the specified curve
     * Args:
     *    curve - SignatureCurve: The signature curve to use
     *    bytes - &[u8]: The byte representation of the private key
     * 
     * Returns:
     *    Result<Self>: The created SigningKey or an error if creation fails
     */
    pub fn from_bytes(curve: SignatureCurve, bytes: &[u8]) -> Result<Self> {
        match curve {
            SignatureCurve::Ed25519 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidKeySize);
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(bytes);

                Ok(SigningKey::Ed25519(ed25519::Ed25519PrivateKey::from_seed(&seed)?))
            }
            SignatureCurve::P256 => {
                let p256_key = p256::P256PrivateKey::from_bytes(bytes)?;

                Ok(SigningKey::P256Ecdsa(P256EcdsaPrivateKey { inner: p256_key }))
            }
        }
    }
    
    /**
     * Converts the SigningKey to its byte representation
     * Args:
     *    &self: The SigningKey instance
     * 
     * Returns:
     *    Vec<u8>: The byte representation of the SigningKey
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(key) => key.to_bytes().to_vec(),
            SigningKey::P256Ecdsa(key) => key.inner.to_bytes().to_vec(),
        }
    }
    
    /**
     * Retrieves the corresponding VerifyingKey for the SigningKey
     * Args:
     *    &self: The SigningKey instance
     * 
     * Returns:
     *    VerifyingKey: The corresponding VerifyingKey
     */
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::Ed25519(key) => {
                VerifyingKey::Ed25519(key.public_key().clone())
            }
            SigningKey::P256Ecdsa(key) => {
                VerifyingKey::P256Ecdsa(P256EcdsaPublicKey {
                    inner: key.inner.public_key(),
                })
            }
        }
    }
    
    /**
     * Retrieves the signature curve of the SigningKey
     * Args:
     *    &self: The SigningKey instance
     * 
     * Returns:
     *    SignatureCurve: The signature curve used by the SigningKey
     */
    pub fn curve(&self) -> SignatureCurve {
        match self {
            SigningKey::Ed25519(_) => SignatureCurve::Ed25519,
            SigningKey::P256Ecdsa(_) => SignatureCurve::P256,
        }
    }
    
    /**
     * Signs a message using the SigningKey
     * Args:
     *    &self: The SigningKey instance
     *    message - &[u8]: The message to be signed
     * 
     * Returns:
     *    Result<Signature>: The generated Signature or an error if signing fails
     */
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        match self {
            SigningKey::Ed25519(key) => {
                Ok(Signature::Ed25519(key.sign(message)))
            }
            SigningKey::P256Ecdsa(key) => {
                let sig = key.sign_ecdsa(message)?;

                Ok(Signature::P256Ecdsa(sig))
            }
        }
    }
}

impl VerifyingKey {

    /**
     * Creates a VerifyingKey from bytes for the specified curve
     * Args:
     *    curve - SignatureCurve: The signature curve to use
     *    bytes - &[u8]: The byte representation of the public key
     * 
     * Returns:
     *    Result<Self>: The created VerifyingKey or an error if creation fails
     */
    pub fn from_bytes(curve: SignatureCurve, bytes: &[u8]) -> Result<Self> {
        match curve {
            SignatureCurve::Ed25519 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidKeySize);
                }

                Ok(VerifyingKey::Ed25519(ed25519::Ed25519PublicKey::from_bytes(bytes)?))
            }
            SignatureCurve::P256 => {
                let p256_pub = if bytes.len() == 65 {
                    p256::P256PublicKey::from_uncompressed(bytes)?
                } else if bytes.len() == 33 {
                    p256::P256PublicKey::from_compressed(bytes)?
                } else {
                    return Err(Error::InvalidKeySize);
                };

                Ok(VerifyingKey::P256Ecdsa(P256EcdsaPublicKey { inner: p256_pub }))
            }
        }
    }
    
    /**
     * Converts the VerifyingKey to its byte representation
     * Args:
     *    &self: The VerifyingKey instance
     * 
     * Returns:
     *    Vec<u8>: The byte representation of the VerifyingKey
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VerifyingKey::Ed25519(key) => key.to_bytes().to_vec(),
            VerifyingKey::P256Ecdsa(key) => key.inner.to_uncompressed().to_vec(),
        }
    }
    
    /**
     * Converts the VerifyingKey to its compressed byte representation
     * Args:
     *    &self: The VerifyingKey instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The compressed byte representation of the VerifyingKey
     *    or an error if conversion fails
     */
    pub fn to_compressed(&self) -> Result<Vec<u8>> {
        match self {
            VerifyingKey::Ed25519(key) => Ok(key.to_bytes().to_vec()),
            VerifyingKey::P256Ecdsa(key) => Ok(key.inner.to_compressed().to_vec()),
        }
    }
    
    /**
     * Retrieves the signature curve of the VerifyingKey
     * Args:
     *    &self: The VerifyingKey instance
     * 
     * Returns:
     *    SignatureCurve: The signature curve used by the VerifyingKey
     */
    pub fn curve(&self) -> SignatureCurve {
        match self {
            VerifyingKey::Ed25519(_) => SignatureCurve::Ed25519,
            VerifyingKey::P256Ecdsa(_) => SignatureCurve::P256,
        }
    }
    
    /**
     * Verifies a signature for a given message using the VerifyingKey
     * Args:
     *    &self: The VerifyingKey instance
     *    message - &[u8]: The message to verify
     *    signature - &Signature: The signature to verify
     * 
     * Returns:
     *    Result<bool>: True if the signature is valid, false otherwise or an error if verification fails
     */
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        if self.curve() != signature.curve() {
            return Err(Error::CryptoError("Signature curve mismatch".to_string()));
        }
        
        match (self, signature) {
            (VerifyingKey::Ed25519(key), Signature::Ed25519(sig)) => {
                Ok(key.verify(message, sig))
            }
            (VerifyingKey::P256Ecdsa(key), Signature::P256Ecdsa(sig)) => {
                key.verify_ecdsa(message, sig)
            }
            _ => Err(Error::CryptoError("Signature curve mismatch".to_string())),
        }
    }
}

impl Signature {

    /**
     * Creates a Signature from its byte representation
     * Args:
     *    curve - SignatureCurve: The signature curve type
     *    bytes - &[u8]: The byte representation of the signature
     * 
     * Returns:
     *    Result<Self>: The Signature instance or an error if creation fails
     */
    pub fn from_bytes(curve: SignatureCurve, bytes: &[u8]) -> Result<Self> {
        match curve {
            SignatureCurve::Ed25519 => {
                if bytes.len() != 64 {
                    return Err(Error::InvalidSignature);
                }

                Ok(Signature::Ed25519(ed25519::Ed25519Signature::from_bytes(bytes)?))
            }
            SignatureCurve::P256 => {
                if bytes.len() != 64 {
                    return Err(Error::InvalidSignature);
                }

                Ok(Signature::P256Ecdsa(p256::P256Signature::from_bytes(bytes)?))
            }
        }
    }
    
    /**
     * Converts the Signature to its byte representation
     * Args:
     *    &self: The Signature instance
     * 
     * Returns:
     *    Vec<u8>: The byte representation of the Signature
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::P256Ecdsa(sig) => sig.to_bytes().to_vec(),
        }
    }
    
    /**
     * Retrieves the signature curve of the Signature
     * Args:
     *    &self: The Signature instance
     * 
     * Returns:
     *    SignatureCurve: The signature curve used by the Signature
     */
    pub fn curve(&self) -> SignatureCurve {
        match self {
            Signature::Ed25519(_) => SignatureCurve::Ed25519,
            Signature::P256Ecdsa(_) => SignatureCurve::P256,
        }
    }
}

impl P256EcdsaPrivateKey {

    /**
     * Signs a message using the P256 ECDSA private key
     * Args:
     *    &self: The P256EcdsaPrivateKey instance
     *    message - &[u8]: The message to sign
     * 
     * Returns:
     *    Result<p256::P256Signature>: The generated signature or an error if signing fails
     */
    fn sign_ecdsa(&self, message: &[u8]) -> Result<p256::P256Signature> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let d_bytes = self.inner.to_bytes();
        let d = BigNum::from_bytes_be(&d_bytes);
        let n = BigNum::from_bytes_be(&P256_ORDER_BYTES);
        
        let k = generate_k_rfc6979(&d_bytes, &hash, &P256_ORDER_BYTES)?;
        
        let r_point = scalar_mult_base(&k)?;
        let r_x = r_point.x_coordinate();
        let r = r_x.modulo(&n);
        if r.is_zero() {
            return Err(Error::CryptoError("Invalid r value".to_string()));
        }
        
        let e = BigNum::from_bytes_be(&hash[0..32]);
        
        let k_inv = k.mod_inverse(&n)?;
        let r_d = r.clone().mul(d).modulo(&n);
        let e_plus_rd = e.add(r_d).modulo(&n);
        let s = k_inv.mul(e_plus_rd).modulo(&n);
        
        if s.is_zero() {
            return Err(Error::CryptoError("Invalid s value".to_string()));
        }
        
        let n_half = n.clone().div(BigNum::from_u64(2));
        let s_final = if s.cmp(&n_half) == Ordering::Greater {
            n.sub(s)
        } else {
            s
        };
        
        let mut sig_bytes = [0u8; 64];
        let r_bytes_raw = r.to_bytes_be();
        let s_bytes_raw = s_final.to_bytes_be();
        
        // Pad to 32 bytes
        let r_start = 32 - r_bytes_raw.len().min(32);
        let s_start = 32 - s_bytes_raw.len().min(32);
        sig_bytes[r_start..32].copy_from_slice(&r_bytes_raw[r_bytes_raw.len().saturating_sub(32)..]);
        sig_bytes[32 + s_start..64].copy_from_slice(&s_bytes_raw[s_bytes_raw.len().saturating_sub(32)..]);
        
        p256::P256Signature::from_bytes(&sig_bytes)
    }
}

impl P256EcdsaPublicKey {

    /**
     * Verifies a P256 ECDSA signature for a given message
     * Args:
     *    &self: The P256EcdsaPublicKey instance
     *    message - &[u8]: The message to verify
     *    signature - &p256::P256Signature: The signature to verify
     * 
     * Returns:
     *    Result<bool>: True if the signature is valid, false otherwise or an error if verification fails
     */
    fn verify_ecdsa(&self, message: &[u8], signature: &p256::P256Signature) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let sig_bytes = signature.to_bytes();
        let r = BigNum::from_bytes_be(&sig_bytes[0..32]);
        let s = BigNum::from_bytes_be(&sig_bytes[32..64]);
        let n = BigNum::from_bytes_be(&P256_ORDER_BYTES);
        if r.is_zero() || s.is_zero() || r.cmp(&n) != Ordering::Less || s.cmp(&n) != Ordering::Less {
            return Ok(false);
        }
        
        let e = BigNum::from_bytes_be(&hash[0..32]);
        let w = match s.mod_inverse(&n) {
            Ok(inv) => inv,
            Err(_) => return Ok(false),
        };
        
        let u1 = e.mul(w.clone()).modulo(&n);
        let u2 = r.clone().mul(w).modulo(&n);
        let point = compute_verification_point(&u1, &u2, &self.inner)?;
        
        let x = point.x_coordinate();
        let v = x.modulo(&n);
        
        Ok(v.cmp(&r) == Ordering::Equal)
    }
}

impl SignatureScheme for SigningKey {
    
    /**
     * Signs a message using the SigningKey
     * Args:
     *    &self: The SigningKey instance
     *    message - &[u8]: The message to be signed
     * 
     * Returns:
     *    Result<Vec<u8>>: The generated signature bytes or an error if signing fails
     */
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.sign(message)?.to_bytes())
    }
    
    /**
     * Retrieves the public key bytes corresponding to the SigningKey
     * Args:
     *    &self: The SigningKey instance
     * 
     * Returns:
     *    Vec<u8>: The byte representation of the public key
     */
    fn public_bytes(&self) -> Vec<u8> {
        self.verifying_key().to_bytes()
    }
}

impl VerificationScheme for VerifyingKey {

    /**
     * Verifies a signature for a given message using the VerifyingKey
     * Args:
     *    &self: The VerifyingKey instance
     *    message - &[u8]: The message to verify
     *    signature - &[u8]: The signature bytes to verify
     * 
     * Returns:
     *    Result<bool>: True if the signature is valid, false otherwise or an error if verification fails
     */
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = Signature::from_bytes(self.curve(), signature)?;
        self.verify(message, &sig)
    }
    
    /**
     * Converts the VerifyingKey to its byte representation
     * Args:
     *    &self: The VerifyingKey instance
     * 
     * Returns:
     *    Vec<u8>: The byte representation of the VerifyingKey
     */
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            VerifyingKey::Ed25519(key) => key.to_bytes().to_vec(),
            VerifyingKey::P256Ecdsa(key) => key.inner.to_uncompressed().to_vec(),
        }
    }
}

/**
 * Signs a message using the specified signature curve and private key bytes
 * Args:
 *    curve - SignatureCurve: The signature curve to use
 *    private_key - &[u8]: The private key bytes
 *    message - &[u8]: The message to be signed
 * 
 * Returns:
 *    Result<Vec<u8>>: The generated signature bytes or an error if signing fails
 */
pub fn sign(curve: SignatureCurve, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let key = SigningKey::from_bytes(curve, private_key)?;
    Ok(key.sign(message)?.to_bytes())
}

/**
 * Verifies a signature for a given message using the specified signature curve and public key bytes
 * Args:
 *    curve - SignatureCurve: The signature curve to use
 *    public_key - &[u8]: The public key bytes
 *    message - &[u8]: The message to verify
 *    signature - &[u8]: The signature bytes to verify
 * 
 * Returns:
 *    Result<bool>: True if the signature is valid, false otherwise or an error if verification fails
 */
pub fn verify(curve: SignatureCurve, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let key = VerifyingKey::from_bytes(curve, public_key)?;
    let sig = Signature::from_bytes(curve, signature)?;
    key.verify(message, &sig)
}

/**
 * Generates a new keypair for the specified signature curve
 * Args:
 *    curve - SignatureCurve: The signature curve to use
 * 
 * Returns:
 *    Result<(SigningKey, VerifyingKey)>: The generated SigningKey and VerifyingKey
 *    or an error if generation fails
 */
pub fn generate_keypair(curve: SignatureCurve) -> Result<(SigningKey, VerifyingKey)> {
    let signing = SigningKey::generate(curve)?;
    let verifying = signing.verifying_key();
    Ok((signing, verifying))
}

/**
 * Generates a deterministic nonce 'k' for ECDSA signing using RFC 6979
 * Args:
 *    private_key - &[u8; 32]: The private key bytes
 *    hash - &[u8; 32]: The hash of the message to be signed
 *    order - &[u8; 32]: The order of the elliptic curve
 * 
 * Returns:
 *    Result<BigNum>: The generated nonce 'k' or an error if generation fails
 */
fn generate_k_rfc6979(private_key: &[u8; 32], hash: &[u8; 32], order: &[u8; 32]) -> Result<BigNum> {
    let mut v = [0x01u8; 32];
    let mut k_hmac = [0x00u8; 32];
    
    let mut hmac = Hmac::<Sha256>::new(&k_hmac);
    hmac.update(&v);
    hmac.update(&[0x00]);
    hmac.update(private_key);
    hmac.update(hash);
    k_hmac = hmac.finalize()[0..32].try_into().unwrap();
    
    let mut hmac = Hmac::<Sha256>::new(&k_hmac);
    hmac.update(&v);
    v = hmac.finalize()[0..32].try_into().unwrap();
    
    let mut hmac = Hmac::<Sha256>::new(&k_hmac);
    hmac.update(&v);
    hmac.update(&[0x01]);
    hmac.update(private_key);
    hmac.update(hash);
    k_hmac = hmac.finalize()[0..32].try_into().unwrap();
    
    let mut hmac = Hmac::<Sha256>::new(&k_hmac);
    hmac.update(&v);
    v = hmac.finalize()[0..32].try_into().unwrap();
    
    let n = BigNum::from_bytes_be(order);
    let one = BigNum::from_u64(1);
    
    loop {
        let mut t = Vec::new();
        let mut hmac = Hmac::<Sha256>::new(&k_hmac);
        hmac.update(&v);
        v = hmac.finalize()[0..32].try_into().unwrap();
        t.extend_from_slice(&v);
        
        let k = BigNum::from_bytes_be(&t[0..32]);
        if k.cmp(&one) != Ordering::Less && k.cmp(&n) == Ordering::Less {
            return Ok(k);
        }
        
        let mut hmac = Hmac::<Sha256>::new(&k_hmac);
        hmac.update(&v);
        hmac.update(&[0x00]);
        k_hmac = hmac.finalize()[0..32].try_into().unwrap();
        
        let mut hmac = Hmac::<Sha256>::new(&k_hmac);
        hmac.update(&v);
        v = hmac.finalize()[0..32].try_into().unwrap();
    }
}

impl P256Point {

    /**
     * Retrieves the x-coordinate of the P256Point
     * Args:
     *    &self: The P256Point instance
     * 
     * Returns:
     *    BigNum: The x-coordinate of the point
     */
    fn x_coordinate(&self) -> BigNum {
        self.x.clone()
    }
    
    /**
     * Checks if the P256Point is the point at infinity
     * Args:
     *    &self: The P256Point instance
     * 
     * Returns:
     *    bool: True if the point is at infinity, false otherwise
     */
    fn is_infinity(&self) -> bool {
        self.infinity
    }
}

/**
 * Performs scalar multiplication of the base point G by a scalar k
 * Args:
 *    k - &BigNum: The scalar multiplier
 * 
 * Returns:
 *    Result<P256Point>: The resulting P256Point after multiplication, or an error if the operation fails
 */
fn scalar_mult_base(k: &BigNum) -> Result<P256Point> {
    let gx_bytes = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
        0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    ];
    let gy_bytes = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
        0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
        0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
    ];
    
    let g = P256Point {
        x: BigNum::from_bytes_be(&gx_bytes),
        y: BigNum::from_bytes_be(&gy_bytes),
        infinity: false,
    };
    
    scalar_mult(k, &g)
}

/**
 * Converts a scalar k to its Windowed Non-Adjacent Form (wNAF)
 * Args:
 *    k - &BigNum: The scalar to convert
 *    window_width - u32: The width of the window for wNAF
 * 
 * Returns:
 *    Vec<i32>: The wNAF representation of the scalar k
 */
fn to_wnaf(k: &BigNum, window_width: u32) -> Vec<i32> {
    let window = 1i32 << window_width;
    let mask = (window - 1) as i32;
    let one = BigNum::from_u64(1);
    
    let mut wnaf = Vec::new();
    let mut k = k.clone();
    while !k.is_zero() {
        let k_u64 = if k.limbs.len() > 0 { k.limbs[0] as i32 } else { 0 };
        if (k_u64 & 1) == 1 {
            let width_pow = 1u64 << window_width;
            let rem = (k_u64 & mask) as i32;
            let w = if rem >= (window / 2) {
                rem - window
            } else {
                rem
            };
            
            wnaf.push(w);
            if w >= 0 {
                k = k.sub(BigNum::from_u64(w as u64));
            } else {
                k = k.add(BigNum::from_u64((-w) as u64));
            }
        } else {
            wnaf.push(0);
        }
        
        k = k.div(BigNum::from_u64(2));
    }
    
    wnaf
}

/**
 * Negates a P256Point (computes -P)
 * Args:
 *    p - &P256Point: The point to negate
 * 
 * Returns:
 *    P256Point: The negated point -P
 */
fn point_negate(p: &P256Point) -> P256Point {
    if p.infinity {
        return P256Point {
            x: BigNum::from_u64(0),
            y: BigNum::from_u64(0),
            infinity: true,
        };
    }
    
    let prime_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    let prime = BigNum::from_bytes_be(&prime_bytes);
    
    P256Point {
        x: p.x.clone(),
        y: prime.sub(p.y.clone()),
        infinity: false,
    }
}

/**
 * Precomputes the odd multiples of a point for wNAF scalar multiplication
 * Args:
 *    point - &P256Point: The point for which to precompute multiples
 *    window_width - u32: The width of the window for wNAF
 * 
 * Returns:
 *    Result<Vec<P256Point>>: A vector of precomputed odd multiples of the point
 *        or an error if the operation fails
 */
fn precompute_wnaf_multiples(point: &P256Point, window_width: u32) -> Result<Vec<P256Point>> {
    let table_size = 1usize << (window_width - 1);
    let mut table = Vec::with_capacity(table_size);
    
    table.push(point.clone());
    let mut current = point.clone();
    for _ in 1..table_size {
        current = point_double(&current)?;
        current = point_add(&current, point)?;
        table.push(current.clone());
    }
    
    Ok(table)
}

/**
 * Performs scalar multiplication of a point by a scalar k using wNAF optimization
 * Args:
 *    k - &BigNum: The scalar multiplier
 *    point - &P256Point: The point to be multiplied
 * 
 * Returns:
 *    Result<P256Point>: The resulting P256Point after multiplication
 *        or an error if the operation fails
 */
fn scalar_mult_wnaf(k: &BigNum, point: &P256Point) -> Result<P256Point> {
    if k.is_zero() || point.infinity {
        return Ok(P256Point {
            x: BigNum::from_u64(0),
            y: BigNum::from_u64(0),
            infinity: true,
        });
    }
    
    const WINDOW_WIDTH: u32 = 4;
    let wnaf = to_wnaf(k, WINDOW_WIDTH);
    let table = precompute_wnaf_multiples(point, WINDOW_WIDTH)?;
    let mut result = P256Point {
        x: BigNum::from_u64(0),
        y: BigNum::from_u64(0),
        infinity: true,
    };
    
    for i in (0..wnaf.len()).rev() {
        result = point_double(&result)?;
        if wnaf[i] > 0 {
            let idx = ((wnaf[i] >> 1) as usize);
            if idx < table.len() {
                result = point_add(&result, &table[idx])?;
            }
        } else if wnaf[i] < 0 {
            let idx = (((-wnaf[i]) >> 1) as usize);
            if idx < table.len() {
                let neg_point = point_negate(&table[idx]);
                result = point_add(&result, &neg_point)?;
            }
        }
    }
    
    Ok(result)
}

/**
 * Performs scalar multiplication of a point by a scalar k
 * Uses wNAF optimization for improved performance
 * Args:
 *    k - &BigNum: The scalar multiplier
 *    point - &P256Point: The point to be multiplied
 * 
 * Returns:
 *    Result<P256Point>: The resulting P256Point after multiplication, or an error if the operation fails
 */
fn scalar_mult(k: &BigNum, point: &P256Point) -> Result<P256Point> {
    scalar_mult_wnaf(k, point)
}

/**
 * Adds two P256Points together
 * Args:
 *    p - &P256Point: The first point
 *    q - &P256Point: The second point
 * 
 * Returns:
 *    Result<P256Point>: The resulting P256Point after addition, or an error if the operation fails
 */
fn point_add(p: &P256Point, q: &P256Point) -> Result<P256Point> {
    if p.is_infinity() {
        return Ok(q.clone());
    }

    if q.is_infinity() {
        return Ok(p.clone());
    }
    
    let prime_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    let prime = BigNum::from_bytes_be(&prime_bytes);
    if p.x.cmp(&q.x) == Ordering::Equal {
        if p.y.cmp(&q.y) == Ordering::Equal {
            return point_double(p);
        } else {
            return Ok(P256Point {
                x: BigNum::from_u64(0),
                y: BigNum::from_u64(0),
                infinity: true,
            });
        }
    }
    
    let dy = q.y.clone().sub(p.y.clone()).modulo(&prime);
    let dx = q.x.clone().sub(p.x.clone()).modulo(&prime);
    let dx_inv = dx.mod_inverse(&prime)?;
    let s = dy.mul(dx_inv).modulo(&prime);
    
    let s2 = s.clone().mul(s.clone()).modulo(&prime);
    let x3 = s2.sub(p.x.clone()).sub(q.x.clone()).modulo(&prime);
    
    let y3 = s.mul(p.x.clone().sub(x3.clone())).sub(p.y.clone()).modulo(&prime);
    
    Ok(P256Point {
        x: x3,
        y: y3,
        infinity: false,
    })
}

/**
 * Doubles a P256Point
 * Args:
 *    p - &P256Point: The point to be doubled
 * 
 * Returns:
 *    Result<P256Point>: The resulting P256Point after doubling, or an error if the operation fails
 */
fn point_double(p: &P256Point) -> Result<P256Point> {
    if p.is_infinity() {
        return Ok(p.clone());
    }
    
    let prime_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    let prime = BigNum::from_bytes_be(&prime_bytes);
    let a = BigNum::from_bytes_be(&prime_bytes).sub(BigNum::from_u64(3));
    
    let x2 = p.x.clone().mul(p.x.clone()).modulo(&prime);
    let three_x2 = x2.mul(BigNum::from_u64(3)).modulo(&prime);
    let numerator = three_x2.add(a).modulo(&prime);
    
    let two_y = p.y.clone().mul(BigNum::from_u64(2)).modulo(&prime);
    let two_y_inv = two_y.mod_inverse(&prime)?;
    let s = numerator.mul(two_y_inv).modulo(&prime);
    
    let s2 = s.clone().mul(s.clone()).modulo(&prime);
    let two_x = p.x.clone().mul(BigNum::from_u64(2)).modulo(&prime);
    let x3 = s2.sub(two_x).modulo(&prime);
    
    let y3 = s.mul(p.x.clone().sub(x3.clone())).sub(p.y.clone()).modulo(&prime);
    
    Ok(P256Point {
        x: x3,
        y: y3,
        infinity: false,
    })
}

/**
 * Computes the verification point for ECDSA signature verification
 * Args:
 *    u1 - &BigNum: The first scalar
 *    u2 - &BigNum: The second scalar
 *    public_key - &p256::P256PublicKey: The public key point
 * 
 * Returns:
 *    Result<P256Point>: The resulting verification point, or an error if the operation fails
 */
fn compute_verification_point(u1: &BigNum, u2: &BigNum, public_key: &p256::P256PublicKey) -> Result<P256Point> {
    let p1 = scalar_mult_base(u1)?;
    
    let pub_bytes = public_key.to_uncompressed();
    let x = BigNum::from_bytes_be(&pub_bytes[1..33]);
    let y = BigNum::from_bytes_be(&pub_bytes[33..65]);
    let q = P256Point {
        x,
        y,
        infinity: false,
    };
    
    let p2 = scalar_mult(u2, &q)?;
    
    point_add(&p1, &p2)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let (signing, verifying) = generate_keypair(SignatureCurve::Ed25519).unwrap();
        let message = b"test message";
        
        let signature = signing.sign(message).unwrap();
        assert!(verifying.verify(message, &signature).unwrap());
        
        assert!(!verifying.verify(b"wrong message", &signature).unwrap());
    }
    
    #[test]
    fn test_p256_sign_verify() {
        let (signing, verifying) = generate_keypair(SignatureCurve::P256).unwrap();
        let message = b"test message for P-256";
        
        let signature = signing.sign(message).unwrap();
        assert!(verifying.verify(message, &signature).unwrap());
        
        assert!(!verifying.verify(b"wrong message", &signature).unwrap());
    }
    
    #[test]
    fn test_signature_serialization() {
        let (signing, verifying) = generate_keypair(SignatureCurve::Ed25519).unwrap();
        let message = b"test message";
        
        let signature = signing.sign(message).unwrap();
        let sig_bytes = signature.to_bytes();
        
        let restored_sig = Signature::from_bytes(SignatureCurve::Ed25519, &sig_bytes).unwrap();
        assert!(verifying.verify(message, &restored_sig).unwrap());
    }
    
    #[test]
    fn test_key_serialization() {
        let (signing, verifying) = generate_keypair(SignatureCurve::Ed25519).unwrap();
        
        let signing_bytes = signing.to_bytes();
        let verifying_bytes = verifying.to_bytes();
        
        let restored_signing = SigningKey::from_bytes(SignatureCurve::Ed25519, &signing_bytes).unwrap();
        let restored_verifying = VerifyingKey::from_bytes(SignatureCurve::Ed25519, &verifying_bytes).unwrap();
        
        assert_eq!(signing.to_bytes(), restored_signing.to_bytes());
        assert_eq!(verifying.to_bytes(), restored_verifying.to_bytes());
    }
    
    #[test]
    fn test_curve_mismatch() {
        let (signing, _) = generate_keypair(SignatureCurve::Ed25519).unwrap();
        let message = b"test message";
        let signature = signing.sign(message).unwrap();
        
        let result = VerifyingKey::from_bytes(SignatureCurve::P256, &signing.verifying_key().to_bytes());
        assert!(result.is_err());
    }
    
    #[test]
    fn test_raw_sign_verify() {
        let (signing, verifying) = generate_keypair(SignatureCurve::Ed25519).unwrap();
        let message = b"test message";
        
        let signature = sign(
            SignatureCurve::Ed25519,
            &signing.to_bytes(),
            message,
        ).unwrap();
        
        let valid = verify(
            SignatureCurve::Ed25519,
            &verifying.to_bytes(),
            message,
            &signature,
        ).unwrap();
        
        assert!(valid);
    }
    
    #[test]
    fn test_rfc6979_deterministic() {
        let (signing, _) = generate_keypair(SignatureCurve::P256).unwrap();
        let message = b"deterministic test";
        
        let sig1 = signing.sign(message).unwrap();
        let sig2 = signing.sign(message).unwrap();
        
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}