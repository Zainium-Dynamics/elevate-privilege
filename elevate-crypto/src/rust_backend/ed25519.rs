//! Ed25519 signatures (primary signatures for elevate — not SHA-based schemes).

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::error::{CryptoError, CryptoResult};

/// 32-byte Ed25519 public key.
pub type PublicKey = [u8; 32];
/// 32-byte Ed25519 secret seed.
pub type SecretKey = [u8; 32];
/// 64-byte Ed25519 signature.
pub type SignatureBytes = [u8; 64];

/// Generate a new Ed25519 keypair (seed, public).
pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    (*pk.as_bytes(), sk.to_bytes())
}

/// Sign a message with a 32-byte secret seed.
pub fn sign(secret: &SecretKey, message: &[u8]) -> CryptoResult<SignatureBytes> {
    let sk = SigningKey::from_bytes(secret);
    let sig = sk.sign(message);
    Ok(sig.to_bytes())
}

/// Verify an Ed25519 signature.
pub fn verify(public: &PublicKey, message: &[u8], signature: &SignatureBytes) -> CryptoResult<()> {
    let pk = VerifyingKey::from_bytes(public)
        .map_err(|_| CryptoError::InvalidInput("invalid ed25519 public key"))?;
    let sig = Signature::from_bytes(signature);
    pk.verify(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Sign and return signature as Vec.
pub fn sign_vec(secret: &SecretKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
    Ok(sign(secret, message)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let (pk, sk) = generate_keypair();
        let msg = b"elevate-crypto ed25519";
        let sig = sign(&sk, msg).unwrap();
        assert!(verify(&pk, msg, &sig).is_ok());
        assert!(verify(&pk, b"tampered", &sig).is_err());
    }
}
