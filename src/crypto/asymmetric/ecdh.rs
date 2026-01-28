// crypto/asymmetric/ecdh.rs - Elliptic Curve Diffie-Hellman (ECDH) key exchange
// https://datatracker.ietf.org/doc/html/rfc7748#section-6

use crate::crypto::{Error, Result};
use super::{x25519, p256};

// ECDH Key trait for key exchange operations
pub trait EcdhKey {
    fn exchange(&self, their_public: &[u8]) -> Result<Vec<u8>>;

    fn public_bytes(&self) -> Vec<u8>;
}

// Supported ECDH curves
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhCurve {
    X25519,
    P256,
}

// ECDH Private Key enum supporting multiple curves
pub enum EcdhPrivateKey {
    X25519(x25519::X25519PrivateKey),
    P256(p256::P256PrivateKey),
}

// ECDH Public Key enum supporting multiple curves
pub enum EcdhPublicKey {
    X25519(x25519::X25519PublicKey),
    P256(p256::P256PublicKey)
}

impl EcdhPrivateKey {

    /**
     * Generates a new ECDH private key for the specified curve
     * Args:
     *    curve - EcdhCurve: The elliptic curve to use
     * 
     * Returns:
     *    Result<Self>: The generated ECDH private key
     */
    pub fn generate(curve: EcdhCurve) -> Result<Self> {
        match curve {
            EcdhCurve::X25519 => Ok(EcdhPrivateKey::X25519(x25519::X25519PrivateKey::generate()?)),
            EcdhCurve::P256 => Ok(EcdhPrivateKey::P256(p256::P256PrivateKey::generate()?)),
        }
    }
    
    /**
     * Creates an ECDH private key from raw bytes for the specified curve
     * Args:
     *    curve - EcdhCurve: The elliptic curve to use
     *    bytes - &[u8]: The byte slice representing the private key
     * 
     * Returns:
     *    Result<Self>: The created ECDH private key
     */
    pub fn from_bytes(curve: EcdhCurve, bytes: &[u8]) -> Result<Self> {
        match curve {
            EcdhCurve::X25519 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidKeySize);
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);

                Ok(EcdhPrivateKey::X25519(x25519::X25519PrivateKey::from_bytes(&key_bytes)?))
            }
            EcdhCurve::P256 => {
                Ok(EcdhPrivateKey::P256(p256::P256PrivateKey::from_bytes(bytes)?))
            }
        }
    }
    
    /**
     * Serializes the ECDH private key to raw bytes
     * Args:
     *    &self: The ECDH private key instance
     * 
     * Returns:
     *    Vec<u8>: The serialized byte vector of the private key
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPrivateKey::X25519(key) => key.to_bytes().to_vec(),
            EcdhPrivateKey::P256(key) => key.to_bytes().to_vec(),
        }
    }
    
    /**
     * Derives the corresponding ECDH public key from the private key
     * Args:
     *    &self: The ECDH private key instance
     * 
     * Returns:
     *    EcdhPublicKey: The derived ECDH public key
     */
    pub fn public_key(&self) -> EcdhPublicKey {
        match self {
            EcdhPrivateKey::X25519(key) => EcdhPublicKey::X25519(key.public_key()),
            EcdhPrivateKey::P256(key) => EcdhPublicKey::P256(key.public_key()),
        }
    }
    
    /**
     * Gets the curve type of the ECDH private key
     * Args:
     *    &self: The ECDH private key instance
     * 
     * Returns:
     *    EcdhCurve: The curve type of the private key
     */
    pub fn curve(&self) -> EcdhCurve {
        match self {
            EcdhPrivateKey::X25519(_) => EcdhCurve::X25519,
            EcdhPrivateKey::P256(_) => EcdhCurve::P256,
        }
    }
    
    /**
     * Performs ECDH key exchange with a given public key
     * Args:
     *    &self: The ECDH private key instance
     *    their_public - &EcdhPublicKey: The peer's ECDH public key
     * 
     * Returns:
     *    Result<Vec<u8>>: The derived shared secret or an error if the exchange fails
     */
    pub fn exchange(&self, their_public: &EcdhPublicKey) -> Result<Vec<u8>> {
        if self.curve() != their_public.curve() {
            return Err(Error::CryptoError("Curve mismatch in ECDH exchange".to_string()));
        }
        
        match (self, their_public) {
            (EcdhPrivateKey::X25519(priv_key), EcdhPublicKey::X25519(pub_key)) => {
                Ok(priv_key.diffie_hellman(pub_key)?.to_vec())
            }
            (EcdhPrivateKey::P256(priv_key), EcdhPublicKey::P256(pub_key)) => {
                Ok(priv_key.diffie_hellman(pub_key)?.to_vec())
            }
            _ => Err(Error::CryptoError("Curve mismatch in ECDH exchange".to_string())),
        }
    }
}

impl EcdhPublicKey {

    /**
     * Creates an ECDH public key from raw bytes for the specified curve
     * Args:
     *    curve - EcdhCurve: The elliptic curve to use
     *    bytes - &[u8]: The byte slice representing the public key
     * 
     * Returns:
     *    Result<Self>: The created ECDH public key
     */
    pub fn from_bytes(curve: EcdhCurve, bytes: &[u8]) -> Result<Self> {
        match curve {
            EcdhCurve::X25519 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidKeySize);
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);
                
                Ok(EcdhPublicKey::X25519(x25519::X25519PublicKey::from_bytes(&key_bytes)?))
            }
            EcdhCurve::P256 => {
                if bytes.len() == 65 {
                    Ok(EcdhPublicKey::P256(p256::P256PublicKey::from_uncompressed(bytes)?))
                } else if bytes.len() == 33 {
                    Ok(EcdhPublicKey::P256(p256::P256PublicKey::from_compressed(bytes)?))
                } else {
                    Err(Error::InvalidKeySize)
                }
            }
        }
    }
    
    /**
     * Serializes the ECDH public key to raw bytes
     * Args:
     *    &self: The ECDH public key instance
     * 
     * Returns:
     *    Vec<u8>: The serialized byte vector of the public key
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPublicKey::X25519(key) => key.to_bytes().to_vec(),
            EcdhPublicKey::P256(key) => key.to_uncompressed().to_vec(),
        }
    }
    
    /**
     * Serializes the ECDH public key to compressed raw bytes
     * Args:
     *    &self: The ECDH public key instance
     * 
     * Returns:
     *    Result<Vec<u8>>: The serialized compressed byte vector of the public key
     */
    pub fn to_compressed(&self) -> Result<Vec<u8>> {
        match self {
            EcdhPublicKey::X25519(key) => Ok(key.to_bytes().to_vec()),
            EcdhPublicKey::P256(key) => Ok(key.to_compressed().to_vec()),
        }
    }
    
    /**
     * Returns the curve type of the ECDH public key
     * Args:
     *    &self: The ECDH public key instance
     * 
     * Returns:
     *    EcdhCurve: The curve type of the public key
     */
    pub fn curve(&self) -> EcdhCurve {
        match self {
            EcdhPublicKey::X25519(_) => EcdhCurve::X25519,
            EcdhPublicKey::P256(_) => EcdhCurve::P256,
        }
    }
}

impl EcdhKey for EcdhPrivateKey {

    /**
     * Performs ECDH key exchange with a given public key in raw bytes
     * Args:
     *    &self: The ECDH private key instance
     *    their_public - &[u8]: The peer's ECDH public key in raw bytes
     * 
     * Returns:
     *    Result<Vec<u8>>: The derived shared secret or an error if the exchange fails
     */
    fn exchange(&self, their_public: &[u8]) -> Result<Vec<u8>> {
        let pub_key = EcdhPublicKey::from_bytes(self.curve(), their_public)?;

        self.exchange(&pub_key)
    }
    
    /**
     * Gets the public key bytes corresponding to the private key
     * Args:
     *    &self: The ECDH private key instance
     * 
     * Returns:
     *    Vec<u8>: The serialized byte vector of the public key
     */
    fn public_bytes(&self) -> Vec<u8> {
        self.public_key().to_bytes()
    }
}

/**
 * Performs ECDH key exchange given raw private and public key bytes
 * Args:
 *    curve - EcdhCurve: The elliptic curve to use
 *    our_private - &[u8]: Our ECDH private key in raw bytes
 *    their_public - &[u8]: The peer's ECDH public key in raw bytes
 * 
 * Returns:
 *    Result<Vec<u8>>: The derived shared secret or an error if the exchange fails
 */
pub fn ecdh_exchange(curve: EcdhCurve, our_private: &[u8], their_public: &[u8]) -> Result<Vec<u8>> {
    let priv_key = EcdhPrivateKey::from_bytes(curve, our_private)?;
    let pub_key = EcdhPublicKey::from_bytes(curve, their_public)?;

    priv_key.exchange(&pub_key)
}

/**
 * Generates a new ECDH keypair for the specified curve
 * Args:
 *    curve - EcdhCurve: The elliptic curve to use
 * 
 * Returns:
 *    Result<(EcdhPrivateKey, EcdhPublicKey)>: The generated ECDH private and public keypair
 */
pub fn generate_keypair(curve: EcdhCurve) -> Result<(EcdhPrivateKey, EcdhPublicKey)> {
    let private = EcdhPrivateKey::generate(curve)?;
    let public = private.public_key();

    Ok((private, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ecdh_x25519() {
        let (alice_priv, alice_pub) = generate_keypair(EcdhCurve::X25519).unwrap();
        let (bob_priv, bob_pub) = generate_keypair(EcdhCurve::X25519).unwrap();
        
        let alice_shared = alice_priv.exchange(&bob_pub).unwrap();
        let bob_shared = bob_priv.exchange(&alice_pub).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_ecdh_p256() {
        let (alice_priv, alice_pub) = generate_keypair(EcdhCurve::P256).unwrap();
        let (bob_priv, bob_pub) = generate_keypair(EcdhCurve::P256).unwrap();
        
        let alice_shared = alice_priv.exchange(&bob_pub).unwrap();
        let bob_shared = bob_priv.exchange(&alice_pub).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_ecdh_serialization() {
        let (priv_key, pub_key) = generate_keypair(EcdhCurve::X25519).unwrap();
        
        let priv_bytes = priv_key.to_bytes();
        let pub_bytes = pub_key.to_bytes();
        
        let priv_restored = EcdhPrivateKey::from_bytes(EcdhCurve::X25519, &priv_bytes).unwrap();
        let pub_restored = EcdhPublicKey::from_bytes(EcdhCurve::X25519, &pub_bytes).unwrap();
        
        assert_eq!(priv_key.to_bytes(), priv_restored.to_bytes());
        assert_eq!(pub_key.to_bytes(), pub_restored.to_bytes());
    }
    
    #[test]
    fn test_ecdh_curve_mismatch() {
        let (alice_priv, _) = generate_keypair(EcdhCurve::X25519).unwrap();
        let (_, bob_pub) = generate_keypair(EcdhCurve::P256).unwrap();
        
        assert!(alice_priv.exchange(&bob_pub).is_err());
    }
    
    #[test]
    fn test_ecdh_raw_exchange() {
        let (alice_priv, alice_pub) = generate_keypair(EcdhCurve::X25519).unwrap();
        let (bob_priv, bob_pub) = generate_keypair(EcdhCurve::X25519).unwrap();
        
        let alice_shared = ecdh_exchange(
            EcdhCurve::X25519,
            &alice_priv.to_bytes(),
            &bob_pub.to_bytes(),
        ).unwrap();
        
        let bob_shared = ecdh_exchange(
            EcdhCurve::X25519,
            &bob_priv.to_bytes(),
            &alice_pub.to_bytes(),
        ).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
}