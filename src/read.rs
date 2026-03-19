//! Certificate reader and expiry analysis for PKI directories.
//!
//! Scans a PKI directory tree, parses all X.509 certificates, and extracts
//! structured metadata including subject, issuer, algorithm, extensions,
//! fingerprint, and expiry status.

use std::fs;
use std::path::{Path, PathBuf};

use ::time::OffsetDateTime;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Parsed metadata from a single X.509 certificate file.
pub struct CertInfo {
    /// Directory name containing this certificate (e.g. "root-ca")
    pub name: String,
    /// Absolute path to the .crt file
    pub file_path: PathBuf,
    /// Hex-encoded serial number
    pub serial_hex: String,
    /// Subject Common Name
    pub subject_cn: String,
    /// Issuer Common Name
    pub issuer_cn: String,
    /// Certificate validity start
    pub not_before: OffsetDateTime,
    /// Certificate validity end
    pub not_after: OffsetDateTime,
    /// Human-readable algorithm description (e.g. "RSA-4096", "Ed25519")
    pub algorithm: String,
    /// Whether the Basic Constraints extension marks this as a CA
    pub is_ca: bool,
    /// Path length constraint from Basic Constraints, if present
    pub pathlen: Option<u32>,
    /// Key Usage extension values (e.g. "Digital Signature", "Key Cert Sign")
    pub key_usage: Vec<String>,
    /// Extended Key Usage OID descriptions
    pub extended_key_usage: Vec<String>,
    /// SHA-256 fingerprint of the DER-encoded certificate
    pub fingerprint_sha256: String,
    /// Whether a .key file exists alongside this certificate
    pub has_private_key: bool,
}

/// Expiry classification for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    /// Certificate has already expired
    Expired,
    /// Expires within 7 days
    Critical,
    /// Expires within 30 days
    Warning,
    /// Expires within 90 days
    Notice,
    /// More than 90 days until expiry
    Healthy,
}

impl ExpiryStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ExpiryStatus::Expired => "EXPIRED",
            ExpiryStatus::Critical => "CRITICAL",
            ExpiryStatus::Warning => "WARNING",
            ExpiryStatus::Notice => "NOTICE",
            ExpiryStatus::Healthy => "HEALTHY",
        }
    }
}

impl std::fmt::Display for ExpiryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ═══════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════

/// Recursively scan a PKI directory for .crt files and parse each one.
///
/// Returns a `Vec<CertInfo>` sorted alphabetically by `name`.
pub fn scan_pki_directory(dir: &Path) -> Result<Vec<CertInfo>> {
    let mut certs = Vec::new();
    scan_recursive(dir, &mut certs)?;
    certs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(certs)
}

/// Parse a single PEM-encoded X.509 certificate file and extract metadata.
pub fn parse_certificate(path: &Path) -> Result<CertInfo> {
    let pem_data = fs::read(path)
        .with_context(|| format!("Failed to read certificate file: {}", path.display()))?;

    // Parse PEM to get DER contents
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM from {}: {e}", path.display()))?;

    // Parse DER into X.509 certificate
    let (_, x509) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509 DER from {}: {e}", path.display()))?;

    // Directory name (e.g. "root-ca")
    let name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Serial number as hex
    let serial_hex = hex::encode(x509.serial.to_bytes_be());

    // Subject CN
    let subject_cn = extract_cn(x509.subject()).unwrap_or_else(|| x509.subject().to_string());

    // Issuer CN
    let issuer_cn = extract_cn(x509.issuer()).unwrap_or_else(|| x509.issuer().to_string());

    // Validity timestamps — convert ASN1Time to OffsetDateTime via epoch seconds
    let not_before = OffsetDateTime::from_unix_timestamp(x509.validity().not_before.timestamp())
        .context("Invalid not_before timestamp")?;
    let not_after = OffsetDateTime::from_unix_timestamp(x509.validity().not_after.timestamp())
        .context("Invalid not_after timestamp")?;

    // Algorithm detection
    let algorithm = detect_algorithm(&x509);

    // Basic Constraints
    let (is_ca, pathlen) = extract_basic_constraints(&x509);

    // Key Usage
    let key_usage = extract_key_usage(&x509);

    // Extended Key Usage
    let extended_key_usage = extract_extended_key_usage(&x509);

    // SHA-256 fingerprint of the DER-encoded certificate
    let mut hasher = Sha256::new();
    hasher.update(&pem.contents);
    let fingerprint_sha256 = hex::encode(hasher.finalize());

    // Check for a sibling .key file
    let has_private_key = check_private_key_exists(path);

    Ok(CertInfo {
        name,
        file_path: path.to_path_buf(),
        serial_hex,
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        algorithm,
        is_ca,
        pathlen,
        key_usage,
        extended_key_usage,
        fingerprint_sha256,
        has_private_key,
    })
}

/// Compute the number of days from now until the certificate's `not_after` date.
///
/// Returns a negative value if the certificate has already expired.
pub fn days_until_expiry(cert: &CertInfo) -> i64 {
    let now = OffsetDateTime::now_utc();
    let duration = cert.not_after - now;
    duration.whole_days()
}

/// Classify a certificate's expiry status based on days remaining.
pub fn classify_expiry(cert: &CertInfo) -> ExpiryStatus {
    let days = days_until_expiry(cert);
    if days < 0 {
        ExpiryStatus::Expired
    } else if days < 7 {
        ExpiryStatus::Critical
    } else if days < 30 {
        ExpiryStatus::Warning
    } else if days < 90 {
        ExpiryStatus::Notice
    } else {
        ExpiryStatus::Healthy
    }
}

// ═══════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════

/// Recursively scan directories for .crt files, skipping dotfiles/dotdirs.
fn scan_recursive(dir: &Path, certs: &mut Vec<CertInfo>) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Skip hidden files and directories
        if name.starts_with('.') {
            continue;
        }

        if path.is_dir() {
            scan_recursive(&path, certs)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("crt") {
            // Skip chain files — they contain multiple certs and are concatenations
            if name == "chain.crt" {
                continue;
            }
            match parse_certificate(&path) {
                Ok(info) => certs.push(info),
                Err(e) => {
                    eprintln!("  Warning: failed to parse {}: {e:#}", path.display());
                }
            }
        }
    }

    Ok(())
}

/// Extract the Common Name from an X.500 distinguished name.
fn extract_cn(name: &X509Name) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME
                && let Ok(s) = attr.as_str()
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Detect the public key algorithm and key size from the certificate.
fn detect_algorithm(x509: &X509Certificate) -> String {
    let spki = x509.public_key();
    let alg_oid = spki.algorithm.algorithm.clone();

    // RSA OID: 1.2.840.113549.1.1.1 or sha256WithRSAEncryption
    if alg_oid == oid_registry::OID_PKCS1_RSAENCRYPTION
        || alg_oid == oid_registry::OID_PKCS1_SHA256WITHRSA
    {
        // Estimate RSA key size from the SubjectPublicKeyInfo raw key bit length
        let key_bits = spki.subject_public_key.data.len() * 8;
        if key_bits >= 4096 {
            return "RSA-4096".to_string();
        } else if key_bits >= 2048 {
            return "RSA-2048".to_string();
        } else if key_bits > 0 {
            return format!("RSA-{key_bits}");
        }
        return "RSA".to_string();
    }

    // Ed25519 OID: 1.3.101.112
    if alg_oid == oid_registry::OID_SIG_ED25519 {
        return "Ed25519".to_string();
    }

    // EC OID: 1.2.840.10045.2.1
    if alg_oid == oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        return "ECDSA".to_string();
    }

    // Fallback: use the OID string
    format!("Unknown({})", alg_oid)
}

/// Extract Basic Constraints extension: (is_ca, optional pathlen).
fn extract_basic_constraints(x509: &X509Certificate) -> (bool, Option<u32>) {
    if let Ok(Some(bc_ext)) = x509.basic_constraints() {
        let bc = bc_ext.value;
        let pathlen = bc.path_len_constraint;
        (bc.ca, pathlen)
    } else {
        (false, None)
    }
}

/// Extract Key Usage extension as human-readable strings.
fn extract_key_usage(x509: &X509Certificate) -> Vec<String> {
    let mut usages = Vec::new();

    if let Ok(Some(ku_ext)) = x509.key_usage() {
        let ku = ku_ext.value;
        if ku.digital_signature() {
            usages.push("Digital Signature".to_string());
        }
        if ku.non_repudiation() {
            usages.push("Non Repudiation".to_string());
        }
        if ku.key_encipherment() {
            usages.push("Key Encipherment".to_string());
        }
        if ku.data_encipherment() {
            usages.push("Data Encipherment".to_string());
        }
        if ku.key_agreement() {
            usages.push("Key Agreement".to_string());
        }
        if ku.key_cert_sign() {
            usages.push("Key Cert Sign".to_string());
        }
        if ku.crl_sign() {
            usages.push("CRL Sign".to_string());
        }
        if ku.encipher_only() {
            usages.push("Encipher Only".to_string());
        }
        if ku.decipher_only() {
            usages.push("Decipher Only".to_string());
        }
    }

    usages
}

/// Extract Extended Key Usage OID descriptions.
fn extract_extended_key_usage(x509: &X509Certificate) -> Vec<String> {
    let mut usages = Vec::new();

    if let Ok(Some(eku_ext)) = x509.extended_key_usage() {
        let eku = eku_ext.value;
        if eku.server_auth {
            usages.push("Server Auth".to_string());
        }
        if eku.client_auth {
            usages.push("Client Auth".to_string());
        }
        if eku.code_signing {
            usages.push("Code Signing".to_string());
        }
        if eku.email_protection {
            usages.push("Email Protection".to_string());
        }
        if eku.time_stamping {
            usages.push("Time Stamping".to_string());
        }
        if eku.ocsp_signing {
            usages.push("OCSP Signing".to_string());
        }
        // Any other OIDs present
        for oid in &eku.other {
            usages.push(format!("OID({})", oid));
        }
    }

    usages
}

/// Check whether a private key file (.key) exists alongside this certificate.
///
/// Looks for files matching the certificate stem with a .key extension in the
/// same directory (e.g. root-ca.crt -> root-ca.key), and also checks for
/// ed25519 variants (e.g. root-ca.ed25519.key).
fn check_private_key_exists(cert_path: &Path) -> bool {
    let parent = match cert_path.parent() {
        Some(p) => p,
        None => return false,
    };
    let stem = match cert_path.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return false,
    };

    // Check <stem>.key
    if parent.join(format!("{stem}.key")).exists() {
        return true;
    }

    // Check <stem>.ed25519.key
    if parent.join(format!("{stem}.ed25519.key")).exists() {
        return true;
    }

    false
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helper ──

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "hedonistic-pki-test-read-{}-{}",
            std::process::id(),
            id,
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Generate a self-signed test certificate using rcgen.
    fn generate_test_cert(cn: &str, is_ca: bool) -> (String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");

        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        } else {
            params.is_ca = IsCa::NoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        }

        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn parse_self_signed_ca_cert() {
        let tmp = tempdir();
        let ca_dir = tmp.join("test-ca");
        fs::create_dir_all(&ca_dir).unwrap();

        let (cert_pem, key_pem) = generate_test_cert("Test Root CA", true);
        fs::write(ca_dir.join("test-ca.crt"), &cert_pem).unwrap();
        fs::write(ca_dir.join("test-ca.key"), &key_pem).unwrap();

        let info = parse_certificate(&ca_dir.join("test-ca.crt")).unwrap();

        assert_eq!(info.subject_cn, "Test Root CA");
        assert_eq!(info.issuer_cn, "Test Root CA"); // self-signed
        assert!(info.is_ca);
        assert!(!info.serial_hex.is_empty());
        assert!(!info.fingerprint_sha256.is_empty());
        assert!(info.has_private_key);
        assert_eq!(info.name, "test-ca");
        assert!(info.key_usage.contains(&"Key Cert Sign".to_string()));
        assert!(info.key_usage.contains(&"CRL Sign".to_string()));
    }

    #[test]
    fn parse_leaf_cert() {
        let tmp = tempdir();
        let leaf_dir = tmp.join("code-signing");
        fs::create_dir_all(&leaf_dir).unwrap();

        let (cert_pem, _key_pem) = generate_test_cert("Code Signing Leaf", false);
        // Don't write key — test has_private_key = false
        fs::write(leaf_dir.join("code-signing.crt"), &cert_pem).unwrap();

        let info = parse_certificate(&leaf_dir.join("code-signing.crt")).unwrap();

        assert_eq!(info.subject_cn, "Code Signing Leaf");
        assert!(!info.is_ca);
        assert!(!info.has_private_key);
        assert!(info.key_usage.contains(&"Digital Signature".to_string()));
        assert!(
            info.extended_key_usage
                .contains(&"Code Signing".to_string())
        );
    }

    #[test]
    fn scan_pki_directory_finds_certs() {
        let tmp = tempdir();

        let root_dir = tmp.join("root-ca");
        let inter_dir = tmp.join("intermediate-ca");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(&inter_dir).unwrap();

        let (root_pem, root_key) = generate_test_cert("Root CA", true);
        fs::write(root_dir.join("root-ca.crt"), &root_pem).unwrap();
        fs::write(root_dir.join("root-ca.key"), &root_key).unwrap();

        let (inter_pem, _) = generate_test_cert("Intermediate CA", true);
        fs::write(inter_dir.join("intermediate-ca.crt"), &inter_pem).unwrap();
        // Also write a chain.crt that should be skipped
        fs::write(
            inter_dir.join("chain.crt"),
            &format!("{inter_pem}{root_pem}"),
        )
        .unwrap();

        let certs = scan_pki_directory(&tmp).unwrap();

        // Should find 2 certs (chain.crt is skipped)
        assert_eq!(certs.len(), 2);
        // Sorted by name: intermediate-ca before root-ca
        assert_eq!(certs[0].name, "intermediate-ca");
        assert_eq!(certs[1].name, "root-ca");
        assert!(certs[1].has_private_key);
        assert!(!certs[0].has_private_key);
    }

    #[test]
    fn scan_skips_dotfiles_and_dotdirs() {
        let tmp = tempdir();

        let hidden = tmp.join(".hidden");
        fs::create_dir_all(&hidden).unwrap();
        let (cert_pem, _) = generate_test_cert("Hidden Cert", false);
        fs::write(hidden.join("hidden.crt"), &cert_pem).unwrap();

        // Also a visible cert
        let vis_dir = tmp.join("visible");
        fs::create_dir_all(&vis_dir).unwrap();
        let (vis_pem, _) = generate_test_cert("Visible Cert", false);
        fs::write(vis_dir.join("visible.crt"), &vis_pem).unwrap();

        let certs = scan_pki_directory(&tmp).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject_cn, "Visible Cert");
    }

    #[test]
    fn days_until_expiry_positive_for_valid_cert() {
        let tmp = tempdir();
        let dir = tmp.join("test");
        fs::create_dir_all(&dir).unwrap();

        let (cert_pem, _) = generate_test_cert("Valid Cert", false);
        fs::write(dir.join("test.crt"), &cert_pem).unwrap();

        let info = parse_certificate(&dir.join("test.crt")).unwrap();
        let days = days_until_expiry(&info);

        // rcgen defaults give ~365 days of validity
        assert!(days > 0, "Expected positive days, got {days}");
    }

    #[test]
    fn classify_expiry_healthy_for_fresh_cert() {
        let tmp = tempdir();
        let dir = tmp.join("test");
        fs::create_dir_all(&dir).unwrap();

        let (cert_pem, _) = generate_test_cert("Fresh Cert", false);
        fs::write(dir.join("test.crt"), &cert_pem).unwrap();

        let info = parse_certificate(&dir.join("test.crt")).unwrap();
        let status = classify_expiry(&info);

        assert_eq!(status, ExpiryStatus::Healthy);
        assert_eq!(status.label(), "HEALTHY");
    }

    #[test]
    fn classify_expiry_returns_correct_status_for_thresholds() {
        // Test the classification logic directly with synthetic CertInfo
        let make_cert = |days_remaining: i64| -> CertInfo {
            let now = OffsetDateTime::now_utc();
            CertInfo {
                name: "test".to_string(),
                file_path: PathBuf::from("/tmp/test.crt"),
                serial_hex: "01".to_string(),
                subject_cn: "Test".to_string(),
                issuer_cn: "Test".to_string(),
                not_before: now - ::time::Duration::days(1),
                not_after: now + ::time::Duration::days(days_remaining),
                algorithm: "RSA-4096".to_string(),
                is_ca: false,
                pathlen: None,
                key_usage: vec![],
                extended_key_usage: vec![],
                fingerprint_sha256: "aabbccdd".to_string(),
                has_private_key: false,
            }
        };

        // Use values well inside each bucket to avoid boundary truncation
        // from whole_days() rounding. Boundaries: <0 Expired, <7 Critical,
        // <30 Warning, <90 Notice, >=90 Healthy.
        assert_eq!(classify_expiry(&make_cert(-5)), ExpiryStatus::Expired);
        assert_eq!(classify_expiry(&make_cert(1)), ExpiryStatus::Critical);
        assert_eq!(classify_expiry(&make_cert(3)), ExpiryStatus::Critical);
        assert_eq!(classify_expiry(&make_cert(10)), ExpiryStatus::Warning);
        assert_eq!(classify_expiry(&make_cert(20)), ExpiryStatus::Warning);
        assert_eq!(classify_expiry(&make_cert(35)), ExpiryStatus::Notice);
        assert_eq!(classify_expiry(&make_cert(80)), ExpiryStatus::Notice);
        assert_eq!(classify_expiry(&make_cert(100)), ExpiryStatus::Healthy);
        assert_eq!(classify_expiry(&make_cert(365)), ExpiryStatus::Healthy);
    }

    #[test]
    fn fingerprint_is_consistent() {
        let tmp = tempdir();
        let dir = tmp.join("test");
        fs::create_dir_all(&dir).unwrap();

        let (cert_pem, _) = generate_test_cert("Fingerprint Test", false);
        let cert_path = dir.join("test.crt");
        fs::write(&cert_path, &cert_pem).unwrap();

        let info1 = parse_certificate(&cert_path).unwrap();
        let info2 = parse_certificate(&cert_path).unwrap();

        assert_eq!(info1.fingerprint_sha256, info2.fingerprint_sha256);
        // SHA-256 hex should be 64 characters
        assert_eq!(info1.fingerprint_sha256.len(), 64);
    }

    #[test]
    fn expiry_status_display() {
        assert_eq!(format!("{}", ExpiryStatus::Expired), "EXPIRED");
        assert_eq!(format!("{}", ExpiryStatus::Critical), "CRITICAL");
        assert_eq!(format!("{}", ExpiryStatus::Warning), "WARNING");
        assert_eq!(format!("{}", ExpiryStatus::Notice), "NOTICE");
        assert_eq!(format!("{}", ExpiryStatus::Healthy), "HEALTHY");
    }

    #[test]
    fn parse_nonexistent_file_errors() {
        let result = parse_certificate(Path::new("/tmp/nonexistent-cert-12345.crt"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_pem_errors() {
        let tmp = tempdir();
        let dir = tmp.join("bad");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bad.crt"), b"this is not a PEM file").unwrap();

        let result = parse_certificate(&dir.join("bad.crt"));
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_key_detection() {
        let tmp = tempdir();
        let dir = tmp.join("test-ed");
        fs::create_dir_all(&dir).unwrap();

        let (cert_pem, _) = generate_test_cert("Ed Test", false);
        fs::write(dir.join("test.crt"), &cert_pem).unwrap();
        // Write an ed25519 key file to test detection
        fs::write(dir.join("test.ed25519.key"), b"fake ed25519 key").unwrap();

        let info = parse_certificate(&dir.join("test.crt")).unwrap();
        assert!(info.has_private_key);
    }
}
