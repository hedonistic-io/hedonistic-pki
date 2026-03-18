//! Pure Rust Ed25519 key generation and signing.
//!
//! Replaces all OpenSSL subprocess calls for Ed25519 operations with
//! pure Rust using `ed25519-dalek`. Keys are generated from OS CSPRNG
//! and can be encrypted via our in-memory vault.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use zeroize::Zeroize;

use crate::vault::Vault;

/// An Ed25519 keypair with PEM-encoded representations
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    /// PKCS#8 PEM-encoded private key
    pub private_pem: String,
    /// SPKI PEM-encoded public key
    pub public_pem: String,
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        self.private_pem.zeroize();
        // public_pem is not sensitive, but clean up anyway
        self.public_pem.zeroize();
    }
}

/// Generate a new Ed25519 keypair using OS CSPRNG.
///
/// The private key is encoded as PKCS#8 v1 DER wrapped in PEM.
/// The public key is encoded as SubjectPublicKeyInfo (SPKI) DER wrapped in PEM.
pub fn generate_ed25519_keypair() -> Result<Ed25519KeyPair> {
    // Generate 32 bytes from OS CSPRNG
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    getrandom::fill(&mut seed)
        .map_err(|e| anyhow::anyhow!("OS CSPRNG failed: {e}"))?;

    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();

    let verifying_key = signing_key.verifying_key();

    let private_pem = encode_ed25519_private_pem(&signing_key);
    let public_pem = encode_ed25519_public_pem(&verifying_key);

    Ok(Ed25519KeyPair {
        signing_key,
        verifying_key,
        private_pem,
        public_pem,
    })
}

/// Encrypt an Ed25519 private key PEM using the vault's ephemeral encryption.
///
/// Returns the encrypted blob that can be stored or written to disk.
/// The vault uses ChaCha20-Poly1305 with an ephemeral key.
pub fn encrypt_ed25519_key(key: &Ed25519KeyPair, vault: &Vault) -> Result<crate::vault::EncryptedBlob> {
    vault
        .encrypt(key.private_pem.as_bytes())
        .context("Failed to encrypt Ed25519 key in vault")
}

/// Sign data with an Ed25519 key, returning a base64-encoded signature.
pub fn sign_with_ed25519(key: &Ed25519KeyPair, data: &[u8]) -> Result<String> {
    let signature = key.signing_key.sign(data);
    Ok(BASE64.encode(signature.to_bytes()))
}

/// Verify an Ed25519 signature given a PEM-encoded public key.
///
/// `signature_b64` must be the base64-encoded 64-byte Ed25519 signature.
pub fn verify_ed25519(public_pem: &str, data: &[u8], signature_b64: &str) -> Result<bool> {
    let verifying_key = decode_ed25519_public_pem(public_pem)?;

    let sig_bytes = BASE64
        .decode(signature_b64)
        .context("Invalid base64 in signature")?;

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .context("Invalid Ed25519 signature (must be 64 bytes)")?;

    match verifying_key.verify(data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ─── PEM encoding/decoding helpers ───────────────────────────────────

/// Ed25519 PKCS#8 v1 private key OID prefix.
/// This is the fixed DER header for an Ed25519 private key in PKCS#8 format:
///   SEQUENCE {
///     INTEGER 0 (version)
///     SEQUENCE { OID 1.3.101.112 (Ed25519) }
///     OCTET STRING { OCTET STRING { 32 bytes of key } }
///   }
const PKCS8_ED25519_PREFIX: &[u8] = &[
    0x30, 0x2e,             // SEQUENCE (46 bytes)
    0x02, 0x01, 0x00,       // INTEGER 0 (version)
    0x30, 0x05,             // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22,             // OCTET STRING (34 bytes)
    0x04, 0x20,             // OCTET STRING (32 bytes) — the actual key
];

/// SPKI prefix for Ed25519 public keys:
///   SEQUENCE {
///     SEQUENCE { OID 1.3.101.112 (Ed25519) }
///     BIT STRING { 0x00 padding, 32 bytes of key }
///   }
const SPKI_ED25519_PREFIX: &[u8] = &[
    0x30, 0x2a,             // SEQUENCE (42 bytes)
    0x30, 0x05,             // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x03, 0x21,             // BIT STRING (33 bytes)
    0x00,                   // no unused bits
];

fn encode_ed25519_private_pem(key: &SigningKey) -> String {
    let mut der = Vec::with_capacity(PKCS8_ED25519_PREFIX.len() + SECRET_KEY_LENGTH);
    der.extend_from_slice(PKCS8_ED25519_PREFIX);
    der.extend_from_slice(key.as_bytes());

    let b64 = BASE64.encode(&der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    der.zeroize();
    pem
}

fn encode_ed25519_public_pem(key: &VerifyingKey) -> String {
    let mut der = Vec::with_capacity(SPKI_ED25519_PREFIX.len() + 32);
    der.extend_from_slice(SPKI_ED25519_PREFIX);
    der.extend_from_slice(key.as_bytes());

    let b64 = BASE64.encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn decode_ed25519_public_pem(pem: &str) -> Result<VerifyingKey> {
    let pem = pem.trim();
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();

    let der = BASE64
        .decode(&b64)
        .context("Invalid base64 in public key PEM")?;

    if der.len() != SPKI_ED25519_PREFIX.len() + 32 {
        anyhow::bail!(
            "Invalid SPKI length: expected {}, got {}",
            SPKI_ED25519_PREFIX.len() + 32,
            der.len()
        );
    }

    if &der[..SPKI_ED25519_PREFIX.len()] != SPKI_ED25519_PREFIX {
        anyhow::bail!("Not an Ed25519 SPKI public key (wrong OID prefix)");
    }

    let key_bytes: [u8; 32] = der[SPKI_ED25519_PREFIX.len()..]
        .try_into()
        .context("Public key must be exactly 32 bytes")?;

    VerifyingKey::from_bytes(&key_bytes)
        .context("Invalid Ed25519 public key point")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_succeeds() {
        let kp = generate_ed25519_keypair().unwrap();
        assert!(kp.private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(kp.public_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = generate_ed25519_keypair().unwrap();
        let data = b"hedonistic pki test payload";

        let sig = sign_with_ed25519(&kp, data).unwrap();
        let valid = verify_ed25519(&kp.public_pem, data, &sig).unwrap();
        assert!(valid, "Signature should verify against correct data");
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let kp = generate_ed25519_keypair().unwrap();
        let sig = sign_with_ed25519(&kp, b"original data").unwrap();

        let valid = verify_ed25519(&kp.public_pem, b"tampered data", &sig).unwrap();
        assert!(!valid, "Signature should not verify against wrong data");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = generate_ed25519_keypair().unwrap();
        let kp2 = generate_ed25519_keypair().unwrap();
        let data = b"test data";

        let sig = sign_with_ed25519(&kp1, data).unwrap();
        let valid = verify_ed25519(&kp2.public_pem, data, &sig).unwrap();
        assert!(!valid, "Signature should not verify against wrong key");
    }

    #[test]
    fn pem_roundtrip() {
        let kp = generate_ed25519_keypair().unwrap();
        // Decode the public PEM back and verify it matches
        let decoded = decode_ed25519_public_pem(&kp.public_pem).unwrap();
        assert_eq!(decoded.as_bytes(), kp.verifying_key.as_bytes());
    }

    #[test]
    fn vault_encrypt_roundtrip() {
        let vault = Vault::new().unwrap();
        let kp = generate_ed25519_keypair().unwrap();
        let blob = encrypt_ed25519_key(&kp, &vault).unwrap();
        let decrypted = vault.decrypt(&blob).unwrap();
        assert_eq!(decrypted.as_str().unwrap(), kp.private_pem);
    }
}
