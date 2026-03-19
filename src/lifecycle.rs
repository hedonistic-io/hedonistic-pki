//! PKI lifecycle operations — renewing, revoking, and regenerating certificates.
//!
//! Provides functions for loading existing CA certificates from disk,
//! finding descendants in a hierarchy, revoking certificates with CRL
//! generation, renewing certificate chains, and changing key passphrases.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, KeyPair};

use crate::certgen::{self, CertAlgorithm, CertGenSpec, GeneratedCert};
use crate::config::{Algorithm, CeremonyConfig, CertType};
use crate::state::{self, PkiState};

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// A CA certificate and key pair loaded from disk, ready for signing.
pub struct LoadedCa {
    /// PEM-encoded certificate
    pub cert_pem: String,
    /// PEM-encoded private key (decrypted)
    pub key_pem: String,
    /// Reconstructed rcgen CertificateParams (parsed from cert PEM)
    pub params: CertificateParams,
    /// Reconstructed rcgen KeyPair (parsed from key PEM)
    pub key_pair: KeyPair,
}

// ═══════════════════════════════════════════════════════════════
// 1. Load a CA certificate + key from disk
// ═══════════════════════════════════════════════════════════════

/// Load a CA certificate and its private key from disk for signing operations.
///
/// Reads `{name}.crt` and `{name}.key` from `cert_dir`. If a passphrase is
/// provided, the PKCS#8-encrypted key is decrypted via the `openssl` CLI.
/// Returns a `LoadedCa` containing the PEM data and reconstructed rcgen
/// objects suitable for signing child certificates or CRLs.
pub fn load_ca_from_disk(
    cert_dir: &Path,
    name: &str,
    passphrase: Option<&str>,
) -> Result<LoadedCa> {
    let cert_path = cert_dir.join(format!("{name}.crt"));
    let key_path = cert_dir.join(format!("{name}.key"));

    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("Failed to read CA certificate: {}", cert_path.display()))?;

    let key_pem = if let Some(pass) = passphrase {
        // Decrypt PKCS#8-encrypted key via openssl CLI
        decrypt_pkcs8_key(&key_path, pass)?
    } else {
        std::fs::read_to_string(&key_path)
            .with_context(|| format!("Failed to read CA key: {}", key_path.display()))?
    };

    // Reconstruct rcgen objects from PEM — same pattern as certgen::generate_crl
    let key_pair = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("Failed to parse key PEM for '{name}'"))?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .with_context(|| format!("Failed to parse cert PEM for '{name}'"))?;

    Ok(LoadedCa {
        cert_pem,
        key_pem,
        params,
        key_pair,
    })
}

/// Decrypt a PKCS#8-encrypted private key using the openssl CLI.
fn decrypt_pkcs8_key(key_path: &Path, passphrase: &str) -> Result<String> {
    let output = Command::new("openssl")
        .args([
            "pkcs8",
            "-in",
            key_path.to_str().unwrap_or(""),
            "-passin",
            &format!("pass:{passphrase}"),
        ])
        .stdin(Stdio::null())
        .output()
        .with_context(|| {
            format!(
                "Failed to run openssl to decrypt key: {}",
                key_path.display()
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to decrypt key at {}: {}",
            key_path.display(),
            stderr.trim()
        );
    }

    String::from_utf8(output.stdout).context("Decrypted key is not valid UTF-8")
}

/// Convert a `LoadedCa` into a `GeneratedCert` suitable for use as a parent
/// in `certgen::generate_signed_cert()`.
fn loaded_ca_to_generated_cert(loaded: &LoadedCa, name: &str) -> Result<GeneratedCert> {
    // Re-self-sign to get an rcgen Certificate object
    let cert = loaded
        .params
        .clone()
        .self_signed(&loaded.key_pair)
        .with_context(|| format!("Failed to reconstruct CA certificate for '{name}'"))?;

    Ok(GeneratedCert {
        name: name.to_string(),
        cert_pem: loaded.cert_pem.clone(),
        key_pem: loaded.key_pem.clone(),
        chain_pem: loaded.cert_pem.clone(),
        key_pair: KeyPair::from_pem(&loaded.key_pem)
            .with_context(|| format!("Failed to re-parse key for '{name}'"))?,
        certificate: cert,
        is_ca: true,
        algorithm: "unknown".to_string(),
    })
}

// ═══════════════════════════════════════════════════════════════
// 2. Find all descendants of a cert in the hierarchy
// ═══════════════════════════════════════════════════════════════

/// Walk the state's cert records and find all certificates that are children
/// (direct or transitive) of the named certificate.
///
/// Returns names in topological order (parents before children).
/// Does not include `cert_name` itself in the result.
pub fn find_descendants(state: &PkiState, cert_name: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(cert_name.to_string());

    while let Some(parent) = queue.pop_front() {
        let children = state.find_children(&parent);
        for child in children {
            // Avoid duplicates (shouldn't happen in a tree, but defensive)
            if !result.contains(&child.name) {
                result.push(child.name.clone());
                queue.push_back(child.name.clone());
            }
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════════
// 3. Revoke certificates and generate CRL
// ═══════════════════════════════════════════════════════════════

/// Revoke the named certificates and generate a CRL signed by the issuer CA.
///
/// - Loads the issuer CA from disk (using the passphrase to decrypt its key)
/// - Collects serial numbers for all named certs from the state
/// - Generates a CRL via `certgen::generate_crl_from_serials()`
/// - Writes the CRL to `pki_dir/revocation/{issuer_name}-{timestamp}.crl.pem`
/// - Marks all named certs as revoked in the state
/// - Saves the updated state
///
/// Returns the path to the written CRL file.
pub fn revoke_certs(
    pki_dir: &Path,
    state: &mut PkiState,
    cert_names: &[String],
    issuer_name: &str,
    issuer_passphrase: &str,
) -> Result<PathBuf> {
    // Load the issuer CA
    let issuer_dir = pki_dir.join(issuer_name);
    let loaded = load_ca_from_disk(&issuer_dir, issuer_name, Some(issuer_passphrase))
        .with_context(|| format!("Failed to load issuer CA '{issuer_name}'"))?;

    let issuer_cert = loaded_ca_to_generated_cert(&loaded, issuer_name)?;

    // Collect serial numbers from state
    let mut serials: Vec<Vec<u8>> = Vec::new();
    for name in cert_names {
        let record = state
            .find_cert(name)
            .ok_or_else(|| anyhow::anyhow!("Certificate '{name}' not found in state"))?;
        let serial_bytes = hex::decode(&record.serial_hex)
            .with_context(|| format!("Invalid serial hex for '{name}': {}", record.serial_hex))?;
        serials.push(serial_bytes);
    }

    if serials.is_empty() {
        bail!("No certificates to revoke");
    }

    // Generate CRL
    let crl_pem = certgen::generate_crl_from_serials(&issuer_cert, &serials)
        .context("Failed to generate CRL")?;

    // Write CRL to disk
    let revocation_dir = pki_dir.join("revocation");
    std::fs::create_dir_all(&revocation_dir).context("Failed to create revocation directory")?;

    let timestamp = state::now_iso8601().replace(':', "-");
    let crl_filename = format!("{issuer_name}-{timestamp}.crl.pem");
    let crl_path = revocation_dir.join(&crl_filename);

    std::fs::write(&crl_path, crl_pem.as_bytes())
        .with_context(|| format!("Failed to write CRL to {}", crl_path.display()))?;

    // Mark all certs as revoked in the state
    for name in cert_names {
        state.mark_revoked(name);
    }

    // Save updated state
    state
        .save(pki_dir)
        .context("Failed to save updated PKI state")?;

    Ok(crl_path)
}

// ═══════════════════════════════════════════════════════════════
// 4. Renew a certificate chain
// ═══════════════════════════════════════════════════════════════

/// Renew a certificate and all its descendants in topological order.
///
/// For each certificate to renew:
/// - Finds its parent in the state
/// - Loads the parent CA from disk (prompting for passphrase via rpassword)
/// - Rebuilds the `CertGenSpec` from the ceremony config
/// - Generates a new certificate signed by the parent
/// - Writes new cert and key to disk
/// - Updates the state with new serial, fingerprint, and timestamps
///
/// Returns the list of renewed certificate names.
pub fn renew_cert_chain(
    pki_dir: &Path,
    state: &mut PkiState,
    cert_name: &str,
    config: &CeremonyConfig,
) -> Result<Vec<String>> {
    // Build the list: the cert itself + all descendants
    let mut to_renew = vec![cert_name.to_string()];
    let descendants = find_descendants(state, cert_name);
    to_renew.extend(descendants);

    let mut renewed: Vec<String> = Vec::new();

    for name in &to_renew {
        let cert_spec = config
            .hierarchy
            .iter()
            .find(|s| s.name == *name)
            .ok_or_else(|| anyhow::anyhow!("Certificate '{name}' not found in ceremony config"))?;

        let certgen_spec = cert_spec_to_certgen_spec(cert_spec, &config.organization)?;

        if cert_spec.cert_type == CertType::Root {
            // Root CA: self-sign
            let generated = certgen::generate_root_ca(&certgen_spec)
                .with_context(|| format!("Failed to regenerate root CA '{name}'"))?;

            write_renewed_cert(pki_dir, name, &generated)?;
            update_state_record(state, name, &generated)?;
        } else {
            // Non-root: need parent
            let parent_name = cert_spec
                .parent
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Non-root cert '{name}' has no parent"))?;

            let parent_dir = pki_dir.join(parent_name.as_str());

            // Prompt for parent passphrase
            let passphrase = rpassword::prompt_password(format!(
                "  Enter passphrase for parent CA '{}': ",
                parent_name
            ))
            .with_context(|| format!("Failed to read passphrase for '{parent_name}'"))?;

            let pass_opt = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.as_str())
            };

            let loaded_parent = load_ca_from_disk(&parent_dir, parent_name, pass_opt)
                .with_context(|| format!("Failed to load parent CA '{parent_name}'"))?;

            let parent_cert = loaded_ca_to_generated_cert(&loaded_parent, parent_name)?;

            let generated = certgen::generate_signed_cert(&certgen_spec, &parent_cert)
                .with_context(|| {
                    format!("Failed to generate renewed cert '{name}' signed by '{parent_name}'")
                })?;

            write_renewed_cert(pki_dir, name, &generated)?;
            update_state_record(state, name, &generated)?;
        }

        renewed.push(name.clone());
    }

    // Save the updated state
    state
        .save(pki_dir)
        .context("Failed to save updated PKI state after renewal")?;

    Ok(renewed)
}

/// Convert a config `CertSpec` to a `CertGenSpec` for certificate generation.
fn cert_spec_to_certgen_spec(
    spec: &crate::config::CertSpec,
    organization: &str,
) -> Result<CertGenSpec> {
    let algorithm = match spec.algorithm {
        Algorithm::Rsa4096 => CertAlgorithm::Rsa4096,
        Algorithm::Ed25519 => CertAlgorithm::Ed25519,
        _ => bail!(
            "Algorithm {:?} is not supported for X.509 certificate generation",
            spec.algorithm
        ),
    };

    let is_ca = matches!(
        spec.cert_type,
        CertType::Root | CertType::Intermediate | CertType::SubCa
    );

    let validity_days = if let Some(years) = spec.validity.years {
        years * 365
    } else if let Some(days) = spec.validity.days {
        days
    } else {
        bail!("Cert '{}' has no validity period", spec.name);
    };

    let mut key_usages = Vec::new();
    let mut ext_key_usages = Vec::new();

    if is_ca {
        key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);
        key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    } else {
        key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);
        ext_key_usages.push(rcgen::ExtendedKeyUsagePurpose::CodeSigning);
    }

    // Override with explicit extensions if provided
    if let Some(ref exts) = spec.extensions {
        if !exts.key_usage.is_empty() {
            key_usages.clear();
            for ku in &exts.key_usage {
                match ku.as_str() {
                    "digitalSignature" => key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature),
                    "keyCertSign" => key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign),
                    "cRLSign" => key_usages.push(rcgen::KeyUsagePurpose::CrlSign),
                    "keyEncipherment" => key_usages.push(rcgen::KeyUsagePurpose::KeyEncipherment),
                    "dataEncipherment" => key_usages.push(rcgen::KeyUsagePurpose::DataEncipherment),
                    "keyAgreement" => key_usages.push(rcgen::KeyUsagePurpose::KeyAgreement),
                    _ => {} // ignore unknown
                }
            }
        }
        if !exts.extended_key_usage.is_empty() {
            ext_key_usages.clear();
            for eku in &exts.extended_key_usage {
                match eku.as_str() {
                    "serverAuth" => ext_key_usages.push(rcgen::ExtendedKeyUsagePurpose::ServerAuth),
                    "clientAuth" => ext_key_usages.push(rcgen::ExtendedKeyUsagePurpose::ClientAuth),
                    "codeSigning" => {
                        ext_key_usages.push(rcgen::ExtendedKeyUsagePurpose::CodeSigning)
                    }
                    "emailProtection" => {
                        ext_key_usages.push(rcgen::ExtendedKeyUsagePurpose::EmailProtection)
                    }
                    "timeStamping" => {
                        ext_key_usages.push(rcgen::ExtendedKeyUsagePurpose::TimeStamping)
                    }
                    _ => {}
                }
            }
        }
    }

    let subject = spec.subject.as_ref();

    Ok(CertGenSpec {
        name: spec.name.clone(),
        common_name: spec.cn.clone(),
        organization: subject
            .and_then(|s| s.organization.clone())
            .or_else(|| Some(organization.to_string())),
        organizational_unit: subject.and_then(|s| s.organizational_unit.clone()),
        country: subject.and_then(|s| s.country.clone()),
        is_ca,
        pathlen: spec.pathlen,
        validity_days,
        key_usages,
        ext_key_usages,
        algorithm,
    })
}

/// Write a renewed certificate and key to disk.
fn write_renewed_cert(pki_dir: &Path, name: &str, cert: &GeneratedCert) -> Result<()> {
    let cert_dir = pki_dir.join(name);
    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("Failed to create directory for '{name}'"))?;

    let cert_path = cert_dir.join(format!("{name}.crt"));
    let key_path = cert_dir.join(format!("{name}.key"));

    std::fs::write(&cert_path, cert.cert_pem.as_bytes())
        .with_context(|| format!("Failed to write cert to {}", cert_path.display()))?;

    std::fs::write(&key_path, cert.key_pem.as_bytes())
        .with_context(|| format!("Failed to write key to {}", key_path.display()))?;

    // Write chain if available and different from cert
    if cert.chain_pem != cert.cert_pem {
        let chain_path = cert_dir.join("chain.crt");
        std::fs::write(&chain_path, cert.chain_pem.as_bytes())
            .with_context(|| format!("Failed to write chain to {}", chain_path.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400));
    }

    Ok(())
}

/// Update a CertRecord in the state with new values from a regenerated cert.
fn update_state_record(state: &mut PkiState, name: &str, cert: &GeneratedCert) -> Result<()> {
    // Parse the cert PEM to extract serial and fingerprint
    let pem_bytes = cert.cert_pem.as_bytes();
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse renewed cert PEM for '{name}': {e}"))?;
    let (_, x509) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse renewed cert DER for '{name}': {e}"))?;

    let serial_hex = hex::encode(x509.serial.to_bytes_be());

    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&pem.contents);
    let fingerprint = hex::encode(hasher.finalize());

    let now = state::now_iso8601();

    // Find and update the record
    if let Some(record) = state.certs.iter_mut().find(|c| c.name == name) {
        record.serial_hex = serial_hex;
        record.fingerprint_sha256 = fingerprint;
        record.generated_at = now.clone();
        record.revoked = false;
        record.revoked_at = None;

        // Update validity timestamps from the X.509 cert
        let not_before =
            time::OffsetDateTime::from_unix_timestamp(x509.validity().not_before.timestamp())
                .map(|t| format!("{t}"))
                .unwrap_or_default();
        let not_after =
            time::OffsetDateTime::from_unix_timestamp(x509.validity().not_after.timestamp())
                .map(|t| format!("{t}"))
                .unwrap_or_default();
        record.not_before = not_before;
        record.not_after = not_after;
    } else {
        bail!("Certificate '{name}' not found in state for update");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 5. Change key passphrase
// ═══════════════════════════════════════════════════════════════

/// Change the passphrase on a PKCS#8-encrypted private key file.
///
/// Decrypts with the old passphrase and re-encrypts with the new one
/// using the openssl CLI. The operation is piped so plaintext never
/// touches disk.
pub fn change_key_passphrase(key_path: &Path, old_pass: &str, new_pass: &str) -> Result<()> {
    if !key_path.exists() {
        bail!("Key file not found: {}", key_path.display());
    }

    // Decrypt with old passphrase, re-encrypt with new passphrase.
    // Pipeline: openssl pkcs8 -in KEY -passin pass:OLD |
    //           openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:NEW -out KEY
    //
    // Use a temp file to avoid clobbering the input during piped write.
    let key_path_str = key_path.to_str().unwrap_or("");
    let tmp_path = key_path.with_extension("key.tmp");
    let tmp_path_str = tmp_path.to_str().unwrap_or("");

    let script = format!(
        "openssl pkcs8 -in '{}' -passin 'pass:{}' | \
         openssl pkcs8 -topk8 -v2 aes-256-cbc -passout 'pass:{}' -out '{}'",
        key_path_str, old_pass, new_pass, tmp_path_str
    );

    let output = Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .output()
        .context("Failed to run openssl for passphrase change")?;

    if !output.status.success() {
        // Clean up temp file on failure
        let _ = std::fs::remove_file(&tmp_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to change passphrase for {}: {}",
            key_path.display(),
            stderr.trim()
        );
    }

    // Move temp file to original path
    std::fs::rename(&tmp_path, key_path).with_context(|| {
        format!(
            "Failed to replace key file after passphrase change: {}",
            key_path.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o400));
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::CertRecord;

    fn sample_config() -> serde_json::Value {
        serde_json::json!({
            "name": "test-pki",
            "organization": "Test LLC",
            "hierarchy": []
        })
    }

    fn sample_record(name: &str, parent: Option<&str>) -> CertRecord {
        CertRecord {
            name: name.to_string(),
            cn: format!("Test {name}"),
            serial_hex: "01".to_string(),
            fingerprint_sha256: "abcdef1234567890".to_string(),
            algorithm: "Ed25519".to_string(),
            cert_type: if parent.is_none() {
                "root"
            } else {
                "intermediate"
            }
            .to_string(),
            parent: parent.map(|s| s.to_string()),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2046-01-01T00:00:00Z".to_string(),
            generated_at: "2026-03-19T00:00:00Z".to_string(),
            offline: parent.is_none(),
            revoked: false,
            revoked_at: None,
        }
    }

    // ── find_descendants tests ──

    #[test]
    fn find_descendants_multi_tier() {
        let mut state = PkiState::new(&sample_config());
        state.add_cert(sample_record("root-ca", None));
        state.add_cert(sample_record("inter-a", Some("root-ca")));
        state.add_cert(sample_record("inter-b", Some("root-ca")));
        state.add_cert(sample_record("sub-ca", Some("inter-a")));
        state.add_cert(sample_record("leaf-1", Some("sub-ca")));
        state.add_cert(sample_record("leaf-2", Some("inter-b")));

        // Descendants of root-ca
        let desc = find_descendants(&state, "root-ca");
        assert_eq!(desc.len(), 5);
        // Parents should come before children (BFS order)
        let inter_a_pos = desc.iter().position(|n| n == "inter-a").unwrap();
        let sub_ca_pos = desc.iter().position(|n| n == "sub-ca").unwrap();
        let leaf_1_pos = desc.iter().position(|n| n == "leaf-1").unwrap();
        assert!(inter_a_pos < sub_ca_pos);
        assert!(sub_ca_pos < leaf_1_pos);

        // Descendants of inter-a
        let desc_a = find_descendants(&state, "inter-a");
        assert_eq!(desc_a.len(), 2);
        assert!(desc_a.contains(&"sub-ca".to_string()));
        assert!(desc_a.contains(&"leaf-1".to_string()));

        // Descendants of inter-b
        let desc_b = find_descendants(&state, "inter-b");
        assert_eq!(desc_b.len(), 1);
        assert_eq!(desc_b[0], "leaf-2");
    }

    #[test]
    fn find_descendants_no_children_returns_empty() {
        let mut state = PkiState::new(&sample_config());
        state.add_cert(sample_record("root-ca", None));
        state.add_cert(sample_record("leaf", Some("root-ca")));

        let desc = find_descendants(&state, "leaf");
        assert!(desc.is_empty());
    }

    #[test]
    fn find_descendants_nonexistent_cert_returns_empty() {
        let state = PkiState::new(&sample_config());
        let desc = find_descendants(&state, "ghost");
        assert!(desc.is_empty());
    }

    #[test]
    fn find_descendants_single_child() {
        let mut state = PkiState::new(&sample_config());
        state.add_cert(sample_record("root-ca", None));
        state.add_cert(sample_record("inter", Some("root-ca")));

        let desc = find_descendants(&state, "root-ca");
        assert_eq!(desc.len(), 1);
        assert_eq!(desc[0], "inter");
    }

    #[test]
    fn find_descendants_deep_chain() {
        let mut state = PkiState::new(&sample_config());
        state.add_cert(sample_record("root", None));
        state.add_cert(sample_record("l1", Some("root")));
        state.add_cert(sample_record("l2", Some("l1")));
        state.add_cert(sample_record("l3", Some("l2")));
        state.add_cert(sample_record("l4", Some("l3")));

        let desc = find_descendants(&state, "root");
        assert_eq!(desc, vec!["l1", "l2", "l3", "l4"]);
    }

    // ── cert_spec_to_certgen_spec tests ──

    #[test]
    fn cert_spec_to_certgen_spec_root_ca() {
        let spec = crate::config::CertSpec {
            name: "test-root".to_string(),
            cn: "Test Root CA".to_string(),
            cert_type: CertType::Root,
            parent: None,
            algorithm: Algorithm::Rsa4096,
            hash: None,
            validity: crate::config::Validity {
                years: Some(20),
                days: None,
            },
            pathlen: None,
            offline: true,
            no_passphrase: false,
            parallel_keys: vec![],
            extensions: None,
            subject: Some(crate::config::SubjectSpec {
                country: Some("US".to_string()),
                organization: Some("Test Org".to_string()),
                organizational_unit: Some("PKI".to_string()),
            }),
            tags: vec![],
            deploy_to: None,
        };

        let gen_spec = cert_spec_to_certgen_spec(&spec, "Default Org").unwrap();
        assert_eq!(gen_spec.name, "test-root");
        assert_eq!(gen_spec.common_name, "Test Root CA");
        assert!(gen_spec.is_ca);
        assert_eq!(gen_spec.validity_days, 7300);
        assert_eq!(gen_spec.algorithm, CertAlgorithm::Rsa4096);
        assert_eq!(gen_spec.organization, Some("Test Org".to_string()));
        assert_eq!(gen_spec.country, Some("US".to_string()));
    }

    #[test]
    fn cert_spec_to_certgen_spec_leaf() {
        let spec = crate::config::CertSpec {
            name: "test-leaf".to_string(),
            cn: "Test Leaf".to_string(),
            cert_type: CertType::Leaf,
            parent: Some("root".to_string()),
            algorithm: Algorithm::Ed25519,
            hash: None,
            validity: crate::config::Validity {
                years: None,
                days: Some(365),
            },
            pathlen: None,
            offline: false,
            no_passphrase: true,
            parallel_keys: vec![],
            extensions: None,
            subject: None,
            tags: vec![],
            deploy_to: None,
        };

        let gen_spec = cert_spec_to_certgen_spec(&spec, "Org").unwrap();
        assert_eq!(gen_spec.name, "test-leaf");
        assert!(!gen_spec.is_ca);
        assert_eq!(gen_spec.validity_days, 365);
        assert_eq!(gen_spec.algorithm, CertAlgorithm::Ed25519);
        assert_eq!(gen_spec.organization, Some("Org".to_string()));
    }

    #[test]
    fn cert_spec_to_certgen_spec_rejects_pq_algorithm() {
        let spec = crate::config::CertSpec {
            name: "pq".to_string(),
            cn: "PQ Cert".to_string(),
            cert_type: CertType::Root,
            parent: None,
            algorithm: Algorithm::MlDsa87,
            hash: None,
            validity: crate::config::Validity {
                years: Some(10),
                days: None,
            },
            pathlen: None,
            offline: false,
            no_passphrase: false,
            parallel_keys: vec![],
            extensions: None,
            subject: None,
            tags: vec![],
            deploy_to: None,
        };

        let err = cert_spec_to_certgen_spec(&spec, "Org").unwrap_err();
        assert!(
            err.to_string().contains("not supported"),
            "Expected 'not supported' error, got: {err}"
        );
    }

    // ── load_ca_from_disk tests ──

    #[test]
    fn load_ca_from_disk_unencrypted() {
        let tmp = std::env::temp_dir().join(format!("hpki-lifecycle-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Generate a real CA cert using certgen
        let spec = CertGenSpec {
            name: "test-ca".to_string(),
            common_name: "Test CA".to_string(),
            organization: Some("Test".to_string()),
            organizational_unit: None,
            country: None,
            is_ca: true,
            pathlen: None,
            validity_days: 365,
            key_usages: vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
                rcgen::KeyUsagePurpose::KeyCertSign,
            ],
            ext_key_usages: vec![],
            algorithm: CertAlgorithm::Ed25519,
        };
        let generated = certgen::generate_root_ca(&spec).unwrap();

        // Write to disk
        std::fs::write(tmp.join("test-ca.crt"), &generated.cert_pem).unwrap();
        std::fs::write(tmp.join("test-ca.key"), &generated.key_pem).unwrap();

        // Load it back
        let loaded = load_ca_from_disk(&tmp, "test-ca", None).unwrap();
        assert!(loaded.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(loaded.key_pem.contains("PRIVATE KEY"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
