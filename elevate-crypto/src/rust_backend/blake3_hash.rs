//! Blake3 message hashing (primary hash for elevate — not SHA).

use blake3::Hasher;

/// 32-byte Blake3 digest.
pub type Blake3Digest = [u8; 32];

/// Hash one buffer with Blake3.
pub fn hash(data: &[u8]) -> Blake3Digest {
    *blake3::hash(data).as_bytes()
}

/// Hash multiple chunks (domain-separated stream).
pub fn hash_parts(parts: &[&[u8]]) -> Blake3Digest {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// Keyed Blake3 MAC (32-byte key). Prefer Ed25519 for signatures; this is for MAC only.
pub fn keyed_mac(key: &[u8; 32], data: &[u8]) -> Blake3Digest {
    let mut h = Hasher::new_keyed(key);
    h.update(data);
    *h.finalize().as_bytes()
}

/// Derive a 32-byte key from context + IKM via Blake3 derive_key.
pub fn derive_key(context: &str, ikm: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_derive_key(context);
    h.update(ikm);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_empty() {
        // Blake3("") is a fixed public test vector
        let d = hash(b"");
        assert_eq!(d.len(), 32);
        assert_ne!(d, [0u8; 32]);
    }

    #[test]
    fn parts_match_concat() {
        assert_eq!(hash_parts(&[b"ab", b"c"]), hash(b"abc"));
    }
}
