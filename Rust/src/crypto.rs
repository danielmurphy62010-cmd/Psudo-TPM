use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use anyhow::{bail, Result};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const AES_MAGIC: &[u8; 4] = b"AGM1";
const CHACHA_MAGIC: &[u8; 4] = b"CPM1";
const NONCE_LEN: usize = 12;

/// Authenticated AES-256-GCM. The returned framing is magic || nonce || ciphertext+tag.
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 { bail!("AES-256-GCM requires a 32-byte key"); }
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let body = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })?;
    let mut out = Vec::with_capacity(4 + NONCE_LEN + body.len());
    out.extend_from_slice(AES_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn aes_gcm_decrypt(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || blob.len() < 4 + NONCE_LEN + 16 || &blob[..4] != AES_MAGIC {
        bail!("Invalid AES-GCM envelope");
    }
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let pt = cipher.decrypt(
        Nonce::from_slice(&blob[4..4 + NONCE_LEN]),
        Payload { msg: &blob[4 + NONCE_LEN..], aad },
    )?;
    Ok(Zeroizing::new(pt))
}

/// Authenticated ChaCha20-Poly1305 for named application keys.
pub fn chacha_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 { bail!("ChaCha20-Poly1305 requires a 32-byte key"); }
    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let body = cipher.encrypt(ChaChaNonce::from_slice(&nonce), Payload { msg: plaintext, aad })?;
    let mut out = Vec::with_capacity(4 + NONCE_LEN + body.len());
    out.extend_from_slice(CHACHA_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn chacha_decrypt(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || blob.len() < 4 + NONCE_LEN + 16 || &blob[..4] != CHACHA_MAGIC {
        bail!("Invalid ChaCha20-Poly1305 envelope");
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let pt = cipher.decrypt(
        ChaChaNonce::from_slice(&blob[4..4 + NONCE_LEN]),
        Payload { msg: &blob[4 + NONCE_LEN..], aad },
    )?;
    Ok(Zeroizing::new(pt))
}

/// Domain-separated keyed BLAKE3 PRF. `manifest_digest` commits to all sorted paths and
/// file contents; because the master key is random/high entropy, a password KDF is not used.
pub fn derive_container_key(master: &[u8; 32], manifest_digest: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_keyed(master);
    h.update(b"Psudo-TPM container encryption key v1\0");
    h.update(manifest_digest);
    Zeroizing::new(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_round_trip_and_authentication() {
        let key = [7u8; 32];
        let aad = b"manifest-context";
        let plaintext = b"secret payload";
        let blob = aes_gcm_encrypt(&key, plaintext, aad).unwrap();
        let opened = aes_gcm_decrypt(&key, &blob, aad).unwrap();
        assert_eq!(&opened[..], plaintext);
        assert!(aes_gcm_decrypt(&key, &blob, b"wrong-context").is_err());
    }

    #[test]
    fn container_key_is_deterministic_and_domain_keyed() {
        let master = [3u8; 32];
        let a = [4u8; 32];
        let b = [5u8; 32];
        assert_eq!(derive_container_key(&master, &a)[..], derive_container_key(&master, &a)[..]);
        assert_ne!(derive_container_key(&master, &a)[..], derive_container_key(&master, &b)[..]);
    }
}
