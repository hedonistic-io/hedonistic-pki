//! Post-quantum cryptography layer.
//!
//! Implements hybrid PQ operations using NIST FIPS 203/204 standards:
//!   - ML-DSA-87 (Dilithium) — FIPS 204 — digital signatures (security level 5)
//!   - ML-KEM-1024 (Kyber)   — FIPS 203 — key encapsulation (security level 5)
//!
//! All PQ operations run alongside classical RSA for defense-in-depth.
//! Verification requires BOTH signatures to pass (hybrid AND).

use anyhow::{Context, Result};
use kem::{Decapsulate, Encapsulate, Generate};
use ml_dsa::{KeyGen, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
use sha2::{Digest, Sha512};

use crate::vault::{EncryptedBlob, Vault};

/// OS-backed CSPRNG that implements TryCryptoRng for the PQ crates
struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("OS RNG failed");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("OS RNG failed");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dest).expect("OS RNG failed");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

// Type aliases for clarity
type DsaSigningKey = SigningKey<MlDsa87>;
// Used by verify_signature (public API for downstream verifiers)
#[allow(dead_code)]
type DsaVerifyingKey = VerifyingKey<MlDsa87>;
#[allow(dead_code)]
type DsaSignature = Signature<MlDsa87>;
type KemDecapsKey = DecapsulationKey<MlKem1024>;
// Used by pq_encrypt (public API for downstream encryptors)
#[allow(dead_code)]
type KemEncapsKey = EncapsulationKey<MlKem1024>;

/// A PQ signing key pair (ML-DSA-87)
pub struct PqSigningKeyPair {
    pub verifying_key_bytes: Vec<u8>,
    pub signing_key_encrypted: EncryptedBlob,
}

/// A PQ encryption key pair (ML-KEM-1024)
pub struct PqEncryptionKeyPair {
    pub encapsulation_key_bytes: Vec<u8>,
    pub decapsulation_key_encrypted: EncryptedBlob,
}

/// A PQ signature over some data
pub struct PqSignature {
    pub signature_bytes: Vec<u8>,
    /// SHA-512 hash of the signed data (used by verifiers for integrity checks)
    #[allow(dead_code)]
    pub data_hash: [u8; 64],
}

/// The full PQ key bundle for the PKI
pub struct PqKeyBundle {
    pub root_signing: PqSigningKeyPair,
    pub intermediate_signing: PqSigningKeyPair,
    pub code_signing: PqSigningKeyPair,
    pub code_encryption: PqEncryptionKeyPair,
    pub intermediate_endorsement: PqSignature,
    pub code_signing_endorsement: PqSignature,
}

/// PQ key metadata for serialization to JSON
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PqKeyManifest {
    pub algorithm_signing: String,
    pub algorithm_encryption: String,
    pub security_level: u8,
    pub nist_standard_signing: String,
    pub nist_standard_encryption: String,
    pub root_verifying_key_hex: String,
    pub intermediate_verifying_key_hex: String,
    pub code_signing_verifying_key_hex: String,
    pub code_encapsulation_key_hex: String,
    pub intermediate_endorsement_hex: String,
    pub code_signing_endorsement_hex: String,
}

/// Generate the complete PQ key bundle
pub fn generate_pq_keys(vault: &Vault) -> Result<PqKeyBundle> {
    eprintln!("\n=== Generating Post-Quantum Keys (ML-DSA-87 + ML-KEM-1024) ===");

    eprintln!("  Generating Root CA ML-DSA-87 key pair...");
    let root_signing =
        generate_signing_keypair(vault).context("Failed to generate root CA PQ signing key")?;
    eprintln!(
        "    Verifying key: {} bytes",
        root_signing.verifying_key_bytes.len()
    );

    eprintln!("  Generating Intermediate CA ML-DSA-87 key pair...");
    let intermediate_signing = generate_signing_keypair(vault)
        .context("Failed to generate intermediate CA PQ signing key")?;

    eprintln!("  Generating Code Signing ML-DSA-87 key pair...");
    let code_signing = generate_signing_keypair(vault)
        .context("Failed to generate code signing PQ signing key")?;

    eprintln!("  Generating Code Signing ML-KEM-1024 key pair...");
    let code_encryption = generate_encryption_keypair(vault)
        .context("Failed to generate code signing PQ encryption key")?;
    eprintln!(
        "    Encapsulation key: {} bytes",
        code_encryption.encapsulation_key_bytes.len()
    );

    // Cross-sign: root endorses intermediate's PQ key
    eprintln!("  Root CA endorsing Intermediate CA PQ key...");
    let intermediate_endorsement = sign_data(
        &intermediate_signing.verifying_key_bytes,
        &root_signing.signing_key_encrypted,
        vault,
    )
    .context("Failed to endorse intermediate CA PQ key")?;

    // Cross-sign: intermediate endorses code signing's PQ key
    eprintln!("  Intermediate CA endorsing Code Signing PQ key...");
    let code_signing_endorsement = sign_data(
        &code_signing.verifying_key_bytes,
        &intermediate_signing.signing_key_encrypted,
        vault,
    )
    .context("Failed to endorse code signing PQ key")?;

    eprintln!("  All PQ keys generated and cross-signed.");

    Ok(PqKeyBundle {
        root_signing,
        intermediate_signing,
        code_signing,
        code_encryption,
        intermediate_endorsement,
        code_signing_endorsement,
    })
}

/// Sign arbitrary data with an ML-DSA-87 key
pub fn sign_data(
    data: &[u8],
    signing_key_encrypted: &EncryptedBlob,
    vault: &Vault,
) -> Result<PqSignature> {
    let key_bytes = vault
        .decrypt(signing_key_encrypted)
        .context("Failed to decrypt PQ signing key from vault")?;

    let signing_key = DsaSigningKey::from_seed(
        key_bytes
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 seed length"))?,
    );

    let signature = signing_key
        .sign_deterministic(data, &[])
        .map_err(|e| anyhow::anyhow!("ML-DSA-87 signing failed: {e}"))?;
    let sig_encoded = signature.encode();
    let sig_bytes: Vec<u8> = sig_encoded.as_slice().to_vec();

    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash: [u8; 64] = hasher.finalize().into();

    Ok(PqSignature {
        signature_bytes: sig_bytes,
        data_hash: hash,
    })
}

/// Verify a PQ signature
/// Public API for downstream verifiers (Partitura, release tooling)
#[allow(dead_code)]
pub fn verify_signature(
    data: &[u8],
    sig: &PqSignature,
    verifying_key_bytes: &[u8],
) -> Result<bool> {
    let vk = DsaVerifyingKey::decode(
        verifying_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 verifying key length"))?,
    );

    let encoded_sig = sig
        .signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-87 signature length"))?;
    let signature = DsaSignature::decode(encoded_sig)
        .ok_or_else(|| anyhow::anyhow!("Failed to decode ML-DSA-87 signature"))?;

    Ok(vk.verify_with_context(data, &[], &signature))
}

/// Encrypt data using ML-KEM-1024 + AES-256-GCM hybrid
///
/// Output format: KEM_CIPHERTEXT || NONCE (12 bytes) || AES_CIPHERTEXT
/// Public API for downstream encryptors (artifact protection)
#[allow(dead_code)]
pub fn pq_encrypt(data: &[u8], encapsulation_key_bytes: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm,
        aead::{Aead, KeyInit},
    };
    use ring::rand::{SecureRandom, SystemRandom};

    let ek = KemEncapsKey::new(
        encapsulation_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ML-KEM-1024 encapsulation key length"))?,
    )
    .map_err(|e| anyhow::anyhow!("Invalid ML-KEM-1024 encapsulation key: {e}"))?;

    // Encapsulate — produces (ciphertext, shared_secret)
    let mut rng = rand_core::UnwrapErr(OsRng);
    let (kem_ciphertext, shared_secret) =
        <KemEncapsKey as Encapsulate>::encapsulate_with_rng(&ek, &mut rng);

    // Use shared secret (32 bytes) as AES-256-GCM key
    let shared_key_bytes: &[u8; 32] = shared_secret.as_ref();
    let cipher = Aes256Gcm::new_from_slice(shared_key_bytes)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM init failed: {e}"))?;

    // Random nonce
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let aes_ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))?;

    // Pack: KEM_CT || NONCE || AES_CT
    let kem_ct_ref: &[u8] = kem_ciphertext.as_slice();
    let mut output = Vec::with_capacity(kem_ct_ref.len() + 12 + aes_ciphertext.len());
    output.extend_from_slice(kem_ct_ref);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&aes_ciphertext);

    Ok(output)
}

/// Decrypt data using ML-KEM-1024 + AES-256-GCM hybrid
/// Public API for downstream decryptors (artifact protection)
#[allow(dead_code)]
pub fn pq_decrypt(
    encrypted: &[u8],
    decapsulation_key_encrypted: &EncryptedBlob,
    vault: &Vault,
) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm,
        aead::{Aead, KeyInit},
    };
    use ml_kem::ml_kem_1024;

    // ML-KEM-1024 ciphertext size
    const KEM_CT_LEN: usize = 1568;
    const NONCE_LEN: usize = 12;

    if encrypted.len() < KEM_CT_LEN + NONCE_LEN + 1 {
        anyhow::bail!("Encrypted data too short for ML-KEM-1024 + AES-256-GCM");
    }

    let kem_ct_bytes = &encrypted[..KEM_CT_LEN];
    let nonce_bytes = &encrypted[KEM_CT_LEN..KEM_CT_LEN + NONCE_LEN];
    let aes_ciphertext = &encrypted[KEM_CT_LEN + NONCE_LEN..];

    // Decrypt the decapsulation key from vault
    let dk_seed_bytes = vault
        .decrypt(decapsulation_key_encrypted)
        .context("Failed to decrypt ML-KEM decapsulation key from vault")?;

    let seed: ml_kem::Seed = dk_seed_bytes
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid ML-KEM-1024 seed length"))?;
    let dk = KemDecapsKey::from_seed(seed);

    let kem_ct: ml_kem_1024::Ciphertext = kem_ct_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid KEM ciphertext length"))?;

    // Decapsulate to get shared secret
    let shared_secret = dk.decapsulate(&kem_ct);

    // Decrypt with AES-256-GCM
    let shared_key_bytes: &[u8] = shared_secret.as_ref();
    let cipher = Aes256Gcm::new_from_slice(shared_key_bytes)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM init failed: {e}"))?;

    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, aes_ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM decryption failed: {e}"))?;

    Ok(plaintext)
}

/// Generate an ML-DSA-87 signing key pair
fn generate_signing_keypair(vault: &Vault) -> Result<PqSigningKeyPair> {
    let mut rng = rand_core::UnwrapErr(OsRng);
    let keypair = <MlDsa87 as KeyGen>::key_gen(&mut rng);
    let vk = keypair.verifying_key();
    let vk_encoded = vk.encode();
    let vk_bytes: Vec<u8> = vk_encoded.as_slice().to_vec();

    // Store the seed (32 bytes) — this is what we need to reconstruct the key
    let seed = keypair.to_seed();
    let seed_bytes: Vec<u8> = seed.as_slice().to_vec();

    let signing_key_encrypted = vault
        .encrypt(&seed_bytes)
        .context("Failed to encrypt PQ signing key seed in vault")?;

    Ok(PqSigningKeyPair {
        verifying_key_bytes: vk_bytes,
        signing_key_encrypted,
    })
}

/// Generate an ML-KEM-1024 encryption key pair
fn generate_encryption_keypair(vault: &Vault) -> Result<PqEncryptionKeyPair> {
    let mut rng = rand_core::UnwrapErr(OsRng);
    let dk = <KemDecapsKey as Generate>::generate_from_rng(&mut rng);
    let ek = dk.encapsulation_key();

    // Export encapsulation key bytes via KeyExport::to_bytes
    use kem::KeyExport;
    let ek_bytes: Vec<u8> = ek.to_bytes().as_slice().to_vec();

    // Store the decapsulation key bytes
    let seed_bytes: Vec<u8> = dk.to_bytes().as_slice().to_vec();

    let decapsulation_key_encrypted = vault
        .encrypt(&seed_bytes)
        .context("Failed to encrypt PQ decapsulation key seed in vault")?;

    Ok(PqEncryptionKeyPair {
        encapsulation_key_bytes: ek_bytes,
        decapsulation_key_encrypted,
    })
}

/// Create the PQ key manifest (JSON metadata for verification)
pub fn create_manifest(bundle: &PqKeyBundle) -> PqKeyManifest {
    PqKeyManifest {
        algorithm_signing: "ML-DSA-87".to_string(),
        algorithm_encryption: "ML-KEM-1024".to_string(),
        security_level: 5,
        nist_standard_signing: "FIPS 204".to_string(),
        nist_standard_encryption: "FIPS 203".to_string(),
        root_verifying_key_hex: hex::encode(&bundle.root_signing.verifying_key_bytes),
        intermediate_verifying_key_hex: hex::encode(
            &bundle.intermediate_signing.verifying_key_bytes,
        ),
        code_signing_verifying_key_hex: hex::encode(&bundle.code_signing.verifying_key_bytes),
        code_encapsulation_key_hex: hex::encode(&bundle.code_encryption.encapsulation_key_bytes),
        intermediate_endorsement_hex: hex::encode(&bundle.intermediate_endorsement.signature_bytes),
        code_signing_endorsement_hex: hex::encode(&bundle.code_signing_endorsement.signature_bytes),
    }
}

/// Write the PQ key bundle to disk
pub fn write_pq_bundle(
    output: &std::path::Path,
    bundle: &PqKeyBundle,
    vault: &Vault,
) -> Result<()> {
    use std::fs;

    let pq_dir = output.join("pq");
    fs::create_dir_all(&pq_dir)?;

    // Public keys
    write_pq_file(
        &pq_dir,
        "root-ca.vk",
        &bundle.root_signing.verifying_key_bytes,
    )?;
    write_pq_file(
        &pq_dir,
        "intermediate-ca.vk",
        &bundle.intermediate_signing.verifying_key_bytes,
    )?;
    write_pq_file(
        &pq_dir,
        "code-signing.vk",
        &bundle.code_signing.verifying_key_bytes,
    )?;
    write_pq_file(
        &pq_dir,
        "code-signing.ek",
        &bundle.code_encryption.encapsulation_key_bytes,
    )?;

    // Endorsement signatures
    write_pq_file(
        &pq_dir,
        "intermediate-ca.endorsement.sig",
        &bundle.intermediate_endorsement.signature_bytes,
    )?;
    write_pq_file(
        &pq_dir,
        "code-signing.endorsement.sig",
        &bundle.code_signing_endorsement.signature_bytes,
    )?;

    // Secret keys — decrypt from vault, write with restrictive permissions
    write_pq_secret_key(
        &pq_dir,
        "root-ca.sk",
        &bundle.root_signing.signing_key_encrypted,
        vault,
    )?;
    write_pq_secret_key(
        &pq_dir,
        "intermediate-ca.sk",
        &bundle.intermediate_signing.signing_key_encrypted,
        vault,
    )?;
    write_pq_secret_key(
        &pq_dir,
        "code-signing.sk",
        &bundle.code_signing.signing_key_encrypted,
        vault,
    )?;
    write_pq_secret_key(
        &pq_dir,
        "code-signing.dk",
        &bundle.code_encryption.decapsulation_key_encrypted,
        vault,
    )?;

    // Write manifest
    let manifest = create_manifest(bundle);
    let manifest_json =
        serde_json::to_string_pretty(&manifest).context("Failed to serialize PQ manifest")?;
    fs::write(pq_dir.join("manifest.json"), manifest_json)?;
    eprintln!("  wrote pq/manifest.json");

    // Write README
    fs::write(pq_dir.join("README.md"), PQ_README)?;
    eprintln!("  wrote pq/README.md");

    Ok(())
}

fn write_pq_file(dir: &std::path::Path, name: &str, data: &[u8]) -> Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, data).with_context(|| format!("Failed to write pq/{name}"))?;
    eprintln!("  wrote pq/{name} ({} bytes)", data.len());
    Ok(())
}

fn write_pq_secret_key(
    dir: &std::path::Path,
    filename: &str,
    encrypted: &EncryptedBlob,
    vault: &Vault,
) -> Result<()> {
    let key_bytes = vault
        .decrypt(encrypted)
        .context("Failed to decrypt PQ key from vault for writing")?;

    let path = dir.join(filename);
    std::fs::write(&path, key_bytes.as_bytes())
        .with_context(|| format!("Failed to write pq/{filename}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
    }

    eprintln!(
        "  wrote pq/{filename} (secret, 0o400, {} bytes)",
        key_bytes.as_bytes().len()
    );
    Ok(())
}

const PQ_README: &str = r#"# Post-Quantum Key Bundle

## Algorithms
- **Signing**: ML-DSA-87 (FIPS 204, CRYSTALS-Dilithium, Security Level 5)
- **Encryption**: ML-KEM-1024 (FIPS 203, CRYSTALS-Kyber, Security Level 5)

## Hybrid Verification Model
This PKI uses a hybrid approach: classical RSA-4096/SHA-512 alongside
post-quantum ML-DSA-87. Both signatures must verify for an artifact
to be trusted. This provides:
  - Backward compatibility with existing tooling (RSA)
  - Forward security against quantum computers (ML-DSA-87)
  - Defense-in-depth (compromise of either alone is insufficient)

## Trust Chain

```
Root CA (ML-DSA-87)
  |-- endorses --> Intermediate CA (ML-DSA-87)
      |-- endorses --> Code Signing (ML-DSA-87 + ML-KEM-1024)
```

## File Layout
  root-ca.vk                     — Root CA verifying key (public)
  root-ca.sk                     — Root CA signing key seed (SECRET)
  intermediate-ca.vk             — Intermediate CA verifying key (public)
  intermediate-ca.sk             — Intermediate CA signing key seed (SECRET)
  intermediate-ca.endorsement.sig — Root's endorsement of intermediate
  code-signing.vk                — Code signing verifying key (public)
  code-signing.sk                — Code signing signing key seed (SECRET)
  code-signing.ek                — Code signing encapsulation key (public)
  code-signing.dk                — Code signing decapsulation key seed (SECRET)
  code-signing.endorsement.sig   — Intermediate's endorsement of code signing
  manifest.json                  — All public keys in hex + metadata

## Verification (Pseudocode)

```
# Verify the PQ trust chain
assert ml_dsa_87_verify(intermediate_ca_vk, root_ca_endorsement_sig, root_ca_vk)
assert ml_dsa_87_verify(code_signing_vk, intermediate_endorsement_sig, intermediate_ca_vk)

# Verify a binary
assert openssl_cms_verify(binary, binary.sig, chain.crt)        # Classical
assert ml_dsa_87_verify(binary, binary.pq.sig, code_signing_vk)  # Post-quantum
# Both must pass
```
"#;
