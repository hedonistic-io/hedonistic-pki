//! Generalized N-level X.509 certificate hierarchy generation.
//!
//! Supports arbitrary certificate chains driven by `CertGenSpec` configs,
//! with both RSA-4096 and Ed25519 key algorithms.
//!
//! Backward-compatible: `generate_pki_chain()` still produces the original
//! 3-tier example chain (Root → Intermediate → Code Signing).

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroize;

use crate::vault::{EncryptedBlob, Vault};

// ═══════════════════════════════════════════════════════════════
// Public types — generalized certificate generation
// ═══════════════════════════════════════════════════════════════

/// Algorithm to use for key generation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertAlgorithm {
    Rsa4096,
    Ed25519,
}

/// Configuration for a single certificate to generate
#[derive(Debug, Clone)]
pub struct CertGenSpec {
    pub name: String,
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub is_ca: bool,
    pub pathlen: Option<u8>,
    pub validity_days: u32,
    pub key_usages: Vec<KeyUsagePurpose>,
    pub ext_key_usages: Vec<ExtendedKeyUsagePurpose>,
    pub algorithm: CertAlgorithm,
}

/// A generated certificate with its keypair and metadata
pub struct GeneratedCert {
    pub name: String,
    /// PEM-encoded X.509 certificate
    pub cert_pem: String,
    /// PEM-encoded private key (unencrypted in memory)
    pub key_pem: String,
    /// Full chain PEM: this cert + all parents up to root
    pub chain_pem: String,
    /// The rcgen KeyPair (for signing children)
    pub key_pair: KeyPair,
    /// The rcgen Certificate (for signing children)
    pub certificate: rcgen::Certificate,
    /// Whether this is a CA certificate (used by ceremony pipeline)
    #[allow(dead_code)]
    pub is_ca: bool,
    /// Algorithm identifier (used by ceremony pipeline for manifest output)
    #[allow(dead_code)]
    pub algorithm: String,
}

impl Drop for GeneratedCert {
    fn drop(&mut self) {
        self.key_pem.zeroize();
    }
}

// ═══════════════════════════════════════════════════════════════
// Generalized generation functions
// ═══════════════════════════════════════════════════════════════

/// Generate a self-signed root CA from a spec.
pub fn generate_root_ca(spec: &CertGenSpec) -> Result<GeneratedCert> {
    let key_pair = generate_key_pair(&spec.algorithm)?;
    let params = build_cert_params(spec)?;

    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign root CA")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let chain_pem = cert_pem.clone();
    let algorithm = format!("{:?}", spec.algorithm);

    Ok(GeneratedCert {
        name: spec.name.clone(),
        cert_pem,
        key_pem,
        chain_pem,
        key_pair,
        certificate: cert,
        is_ca: true,
        algorithm,
    })
}

/// Generate a certificate signed by a parent CA.
pub fn generate_signed_cert(spec: &CertGenSpec, parent: &GeneratedCert) -> Result<GeneratedCert> {
    let key_pair = generate_key_pair(&spec.algorithm)?;
    let params = build_cert_params(spec)?;

    let signed_cert = params
        .signed_by(&key_pair, &parent.certificate, &parent.key_pair)
        .with_context(|| {
            format!(
                "Failed to sign '{}' with parent '{}'",
                spec.name, parent.name
            )
        })?;

    let cert_pem = signed_cert.pem();
    let key_pem = key_pair.serialize_pem();
    // Chain = this cert + parent's chain (which includes parent + grandparent + ... + root)
    let chain_pem = format!("{}{}", cert_pem, parent.chain_pem);
    let algorithm = format!("{:?}", spec.algorithm);

    Ok(GeneratedCert {
        name: spec.name.clone(),
        cert_pem,
        key_pem,
        chain_pem,
        key_pair,
        certificate: signed_cert,
        is_ca: spec.is_ca,
        algorithm,
    })
}

/// Generate a CRL revoking the specified certificate serial numbers.
///
/// `issuer` is the CA that signs the CRL. `revoked_serials` are the
/// DER-encoded serial numbers of certificates to revoke.
/// Used by the ceremony pipeline for programmatic revocation.
#[allow(dead_code)]
pub fn generate_crl_from_serials(
    issuer: &GeneratedCert,
    revoked_serials: &[Vec<u8>],
) -> Result<String> {
    let now = OffsetDateTime::now_utc();

    let revoked_certs: Vec<RevokedCertParams> = revoked_serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(serial),
            revocation_time: now,
            reason_code: Some(RevocationReason::Superseded),
            invalidity_date: None,
        })
        .collect();

    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + Duration::days(365),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = crl_params
        .signed_by(&issuer.certificate, &issuer.key_pair)
        .context("Failed to sign CRL")?;

    crl.pem().context("Failed to serialize CRL to PEM")
}

/// Build a chain PEM from a certificate and its ordered parents (immediate parent first, root last).
/// Used by the ceremony pipeline for custom chain assembly.
#[allow(dead_code)]
pub fn build_chain(cert: &GeneratedCert, parents: &[&GeneratedCert]) -> String {
    let mut chain = cert.cert_pem.clone();
    for parent in parents {
        chain.push_str(&parent.cert_pem);
    }
    chain
}

// ═══════════════════════════════════════════════════════════════
// Backward-compatible legacy types and functions
// ═══════════════════════════════════════════════════════════════

/// A generated certificate + encrypted private key (legacy interface)
pub struct LegacyGeneratedCert {
    /// PEM-encoded certificate
    pub cert_pem: String,
    /// PEM-encoded private key, encrypted in the vault
    pub key_encrypted: EncryptedBlob,
    /// PEM-encoded CSR (not applicable for self-signed root)
    pub csr_pem: Option<String>,
}

/// The full PKI chain output (legacy interface)
pub struct PkiChain {
    pub root_ca: LegacyGeneratedCert,
    pub intermediate_ca: LegacyGeneratedCert,
    pub code_signing: LegacyGeneratedCert,
    pub chain_pem: String,
}

/// Generate the complete 3-tier PKI chain (backward-compatible).
///
/// Produces: Root CA → Intermediate CA → Code Signing, all RSA-4096/SHA-512.
pub fn generate_pki_chain(vault: &Vault) -> Result<PkiChain> {
    // Root CA
    eprintln!("\n=== Generating Root CA (RSA-4096, SHA-512, 20 years) ===");
    let root_spec = CertGenSpec {
        name: "root-ca".into(),
        common_name: "Example Root CA".into(),
        organization: Some("Example Organization".into()),
        organizational_unit: Some("Certificate Authority".into()),
        country: Some("US".into()),
        is_ca: true,
        pathlen: None, // unconstrained
        validity_days: 7300,
        key_usages: vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::KeyCertSign,
        ],
        ext_key_usages: vec![],
        algorithm: CertAlgorithm::Rsa4096,
    };
    let root = generate_root_ca(&root_spec)?;
    let root_key_encrypted = vault
        .encrypt(root.key_pem.as_bytes())
        .context("Failed to encrypt root CA key in vault")?;
    eprintln!("  Root CA generated: CN=Example Root CA");

    // Intermediate CA
    eprintln!("\n=== Generating Intermediate CA (RSA-4096, SHA-512, 10 years) ===");
    let inter_spec = CertGenSpec {
        name: "intermediate-ca".into(),
        common_name: "Example Intermediate CA".into(),
        organization: Some("Example Organization".into()),
        organizational_unit: Some("Code Signing".into()),
        country: Some("US".into()),
        is_ca: true,
        pathlen: Some(0),
        validity_days: 3650,
        key_usages: vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::KeyCertSign,
        ],
        ext_key_usages: vec![],
        algorithm: CertAlgorithm::Rsa4096,
    };
    let inter = generate_signed_cert(&inter_spec, &root)?;
    let inter_key_encrypted = vault
        .encrypt(inter.key_pem.as_bytes())
        .context("Failed to encrypt intermediate CA key in vault")?;

    // Generate CSR for the intermediate
    let inter_csr_pem = generate_csr(&inter_spec, &inter.key_pair)?;
    eprintln!("  Intermediate CA generated: CN=Example Intermediate CA");

    // Code Signing
    eprintln!("\n=== Generating Code Signing Certificate (RSA-4096, SHA-512, 2 years) ===");
    let signing_spec = CertGenSpec {
        name: "code-signing".into(),
        common_name: "Example Code Signing".into(),
        organization: Some("Example Organization".into()),
        organizational_unit: Some("Release Engineering".into()),
        country: Some("US".into()),
        is_ca: false,
        pathlen: None,
        validity_days: 730,
        key_usages: vec![KeyUsagePurpose::DigitalSignature],
        ext_key_usages: vec![ExtendedKeyUsagePurpose::CodeSigning],
        algorithm: CertAlgorithm::Rsa4096,
    };
    let signing = generate_signed_cert(&signing_spec, &inter)?;
    let signing_key_encrypted = vault
        .encrypt(signing.key_pem.as_bytes())
        .context("Failed to encrypt code signing key in vault")?;

    let signing_csr_pem = generate_csr(&signing_spec, &signing.key_pair)?;
    eprintln!("  Code Signing cert generated: CN=Example Code Signing");

    // Legacy chain PEM = intermediate + root (not including leaf)
    let chain_pem = format!("{}{}", inter.cert_pem, root.cert_pem);

    Ok(PkiChain {
        root_ca: LegacyGeneratedCert {
            cert_pem: root.cert_pem.clone(),
            key_encrypted: root_key_encrypted,
            csr_pem: None,
        },
        intermediate_ca: LegacyGeneratedCert {
            cert_pem: inter.cert_pem.clone(),
            key_encrypted: inter_key_encrypted,
            csr_pem: Some(inter_csr_pem),
        },
        code_signing: LegacyGeneratedCert {
            cert_pem: signing.cert_pem.clone(),
            key_encrypted: signing_key_encrypted,
            csr_pem: Some(signing_csr_pem),
        },
        chain_pem,
    })
}

/// Generate a CRL by reading old certs from disk (backward-compatible).
pub fn generate_crl(
    old_root_crt_path: &Path,
    old_root_key_path: &Path,
    _old_root_passphrase: &str,
    old_inter_crt_path: &Path,
) -> Result<String> {
    let root_crt_pem = std::fs::read_to_string(old_root_crt_path)
        .context("Failed to read old root CA certificate")?;
    let root_key_pem =
        std::fs::read_to_string(old_root_key_path).context("Failed to read old root CA key")?;
    let inter_crt_pem = std::fs::read_to_string(old_inter_crt_path)
        .context("Failed to read old intermediate CA certificate")?;

    // Reconstruct the root CA from disk PEMs
    let root_key = KeyPair::from_pem(&root_key_pem).context("Failed to parse old root CA key")?;
    let root_params = CertificateParams::from_ca_cert_pem(&root_crt_pem)
        .context("Failed to parse old root CA cert")?;
    let root_cert = root_params
        .self_signed(&root_key)
        .context("Failed to reconstruct root CA for CRL signing")?;

    // Parse the old intermediate cert to get its serial number
    let inter_cert = x509_parser::pem::parse_x509_pem(inter_crt_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse intermediate cert PEM: {e}"))?;
    let (_, inter_x509) = x509_parser::parse_x509_certificate(&inter_cert.1.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse intermediate cert DER: {e}"))?;

    let serial = inter_x509.serial.to_bytes_be();
    let serial_bigint = rcgen::SerialNumber::from_slice(&serial);

    let now = OffsetDateTime::now_utc();

    let revoked = RevokedCertParams {
        serial_number: serial_bigint,
        revocation_time: now,
        reason_code: Some(RevocationReason::Superseded),
        invalidity_date: None,
    };

    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + Duration::days(365),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![revoked],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = crl_params
        .signed_by(&root_cert, &root_key)
        .context("Failed to sign CRL")?;

    crl.pem().context("Failed to serialize CRL to PEM")
}

// ═══════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════

fn generate_key_pair(algorithm: &CertAlgorithm) -> Result<KeyPair> {
    match algorithm {
        CertAlgorithm::Rsa4096 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA512)
            .context("Failed to generate RSA-4096 key pair"),
        CertAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .context("Failed to generate Ed25519 key pair"),
    }
}

fn build_cert_params(spec: &CertGenSpec) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();

    // Distinguished Name
    if let Some(ref country) = spec.country {
        params
            .distinguished_name
            .push(DnType::CountryName, country.as_str());
    }
    if let Some(ref org) = spec.organization {
        params
            .distinguished_name
            .push(DnType::OrganizationName, org.as_str());
    }
    if let Some(ref ou) = spec.organizational_unit {
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, ou.as_str());
    }
    params
        .distinguished_name
        .push(DnType::CommonName, spec.common_name.as_str());

    // CA constraints
    if spec.is_ca {
        params.is_ca = match spec.pathlen {
            Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
            None => IsCa::Ca(BasicConstraints::Unconstrained),
        };
    } else {
        params.is_ca = IsCa::NoCa;
    }

    // Key usages
    params.key_usages = spec.key_usages.clone();
    params.extended_key_usages = spec.ext_key_usages.clone();

    // Validity
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(spec.validity_days as i64);

    Ok(params)
}

fn generate_csr(spec: &CertGenSpec, key_pair: &KeyPair) -> Result<String> {
    // CSRs only contain the DN — CA constraints, key usages, and validity
    // are set by the issuing CA, not the requester.
    let mut params = CertificateParams::default();
    if let Some(ref country) = spec.country {
        params
            .distinguished_name
            .push(DnType::CountryName, country.as_str());
    }
    if let Some(ref org) = spec.organization {
        params
            .distinguished_name
            .push(DnType::OrganizationName, org.as_str());
    }
    if let Some(ref ou) = spec.organizational_unit {
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, ou.as_str());
    }
    params
        .distinguished_name
        .push(DnType::CommonName, spec.common_name.as_str());

    let csr = params
        .serialize_request(key_pair)
        .context("Failed to serialize CSR")?;
    csr.pem().context("Failed to encode CSR as PEM")
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root_spec(algorithm: CertAlgorithm) -> CertGenSpec {
        CertGenSpec {
            name: "test-root".into(),
            common_name: "Test Root CA".into(),
            organization: Some("Test Org".into()),
            organizational_unit: None,
            country: Some("US".into()),
            is_ca: true,
            pathlen: None,
            validity_days: 365,
            key_usages: vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::KeyCertSign,
            ],
            ext_key_usages: vec![],
            algorithm,
        }
    }

    fn make_leaf_spec(algorithm: CertAlgorithm) -> CertGenSpec {
        CertGenSpec {
            name: "test-leaf".into(),
            common_name: "Test Leaf".into(),
            organization: Some("Test Org".into()),
            organizational_unit: None,
            country: Some("US".into()),
            is_ca: false,
            pathlen: None,
            validity_days: 90,
            key_usages: vec![KeyUsagePurpose::DigitalSignature],
            ext_key_usages: vec![ExtendedKeyUsagePurpose::CodeSigning],
            algorithm,
        }
    }

    #[test]
    fn generate_rsa_root_ca() {
        let spec = make_root_spec(CertAlgorithm::Rsa4096);
        let root = generate_root_ca(&spec).unwrap();
        assert!(root.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(root.key_pem.contains("BEGIN"));
        assert!(root.is_ca);
        assert_eq!(root.name, "test-root");
    }

    #[test]
    fn generate_ed25519_root_ca() {
        let spec = make_root_spec(CertAlgorithm::Ed25519);
        let root = generate_root_ca(&spec).unwrap();
        assert!(root.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(root.is_ca);
        assert_eq!(root.algorithm, "Ed25519");
    }

    #[test]
    fn generate_signed_leaf_rsa() {
        let root_spec = make_root_spec(CertAlgorithm::Rsa4096);
        let root = generate_root_ca(&root_spec).unwrap();

        let leaf_spec = make_leaf_spec(CertAlgorithm::Rsa4096);
        let leaf = generate_signed_cert(&leaf_spec, &root).unwrap();

        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!leaf.is_ca);
        assert_eq!(leaf.name, "test-leaf");
        // Chain should contain both leaf and root certs
        assert!(leaf.chain_pem.contains(&leaf.cert_pem));
        assert!(leaf.chain_pem.contains(&root.cert_pem));
    }

    #[test]
    fn generate_signed_leaf_ed25519() {
        let root_spec = make_root_spec(CertAlgorithm::Ed25519);
        let root = generate_root_ca(&root_spec).unwrap();

        let leaf_spec = make_leaf_spec(CertAlgorithm::Ed25519);
        let leaf = generate_signed_cert(&leaf_spec, &root).unwrap();

        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!leaf.is_ca);
    }

    #[test]
    fn three_tier_hierarchy() {
        let root = generate_root_ca(&CertGenSpec {
            name: "root".into(),
            common_name: "Root CA".into(),
            organization: Some("Test".into()),
            organizational_unit: None,
            country: None,
            is_ca: true,
            pathlen: None,
            validity_days: 3650,
            key_usages: vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::KeyCertSign,
            ],
            ext_key_usages: vec![],
            algorithm: CertAlgorithm::Ed25519,
        })
        .unwrap();

        let inter = generate_signed_cert(
            &CertGenSpec {
                name: "inter".into(),
                common_name: "Intermediate CA".into(),
                organization: Some("Test".into()),
                organizational_unit: None,
                country: None,
                is_ca: true,
                pathlen: Some(0),
                validity_days: 1825,
                key_usages: vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::CrlSign,
                    KeyUsagePurpose::KeyCertSign,
                ],
                ext_key_usages: vec![],
                algorithm: CertAlgorithm::Ed25519,
            },
            &root,
        )
        .unwrap();

        let leaf = generate_signed_cert(
            &CertGenSpec {
                name: "leaf".into(),
                common_name: "End Entity".into(),
                organization: Some("Test".into()),
                organizational_unit: None,
                country: None,
                is_ca: false,
                pathlen: None,
                validity_days: 365,
                key_usages: vec![KeyUsagePurpose::DigitalSignature],
                ext_key_usages: vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ],
                algorithm: CertAlgorithm::Ed25519,
            },
            &inter,
        )
        .unwrap();

        // Verify chain building
        let chain = build_chain(&leaf, &[&inter, &root]);
        assert!(chain.contains(&leaf.cert_pem));
        assert!(chain.contains(&inter.cert_pem));
        assert!(chain.contains(&root.cert_pem));

        // Verify the auto-built chain_pem on the leaf
        // leaf.chain_pem = leaf + inter.chain_pem = leaf + inter + root
        assert!(leaf.chain_pem.contains(&leaf.cert_pem));
        assert!(leaf.chain_pem.contains(&inter.cert_pem));
        assert!(leaf.chain_pem.contains(&root.cert_pem));
    }

    #[test]
    fn crl_generation_from_serials() {
        let root_spec = make_root_spec(CertAlgorithm::Ed25519);
        let root = generate_root_ca(&root_spec).unwrap();

        // Fake serial numbers to revoke
        let serials = vec![vec![0x01, 0x02, 0x03], vec![0xDE, 0xAD]];
        let crl_pem = generate_crl_from_serials(&root, &serials).unwrap();
        assert!(crl_pem.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn legacy_pki_chain_generation() {
        let vault = Vault::new().unwrap();
        let chain = generate_pki_chain(&vault).unwrap();

        assert!(chain.root_ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(chain.intermediate_ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(chain.code_signing.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(chain.chain_pem.contains(&chain.intermediate_ca.cert_pem));
        assert!(chain.chain_pem.contains(&chain.root_ca.cert_pem));
        // Root has no CSR
        assert!(chain.root_ca.csr_pem.is_none());
        // Intermediate and code signing have CSRs
        assert!(chain.intermediate_ca.csr_pem.is_some());
        assert!(chain.code_signing.csr_pem.is_some());
    }
}
