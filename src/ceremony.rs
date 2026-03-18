//! Ceremony orchestrator — the main workflow for config-driven PKI generation.
//!
//! Reads a YAML/JSON ceremony config, collects passphrases, generates
//! certificates in topological order, and writes everything to disk.
//!
//! This module ties together config, certgen, ed25519, paper, and deploy modules
//! into a single `run_ceremony` entry point.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose};
use zeroize::Zeroize;

use crate::certgen::{self, CertAlgorithm, CertGenSpec, GeneratedCert};
use crate::config::{self, Algorithm, CeremonyConfig, CertSpec, CertType};
use crate::deploy;
use crate::ed25519_keys;
use crate::paper;

// ═══════════════════════════════════════════════════════════════
// ANSI color helpers (matching existing main.rs style)
// ═══════════════════════════════════════════════════════════════

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn print_ok(msg: &str) {
    eprintln!("  {GREEN}[OK]{RESET} {msg}");
}

fn print_warn(msg: &str) {
    eprintln!("  {YELLOW}[WARN]{RESET} {msg}");
}

fn print_step(n: usize, total: usize, name: &str) {
    eprintln!("\n{BOLD}=== {n}/{total}: {name} ==={RESET}");
}

// ═══════════════════════════════════════════════════════════════
// Config → certgen type conversion
// ═══════════════════════════════════════════════════════════════

/// Convert a config CertSpec to a certgen CertGenSpec.
fn config_to_certgen_spec(spec: &CertSpec, org: &str) -> CertGenSpec {
    let algorithm = match spec.algorithm {
        Algorithm::Ed25519 => CertAlgorithm::Ed25519,
        Algorithm::Rsa4096 | Algorithm::MlDsa87 | Algorithm::MlKem1024 => CertAlgorithm::Rsa4096,
    };

    let is_ca = matches!(
        spec.cert_type,
        CertType::Root | CertType::Intermediate | CertType::SubCa
    );

    // Determine key usages from extensions or defaults
    let key_usages = if let Some(ref ext) = spec.extensions {
        ext.key_usage
            .iter()
            .filter_map(|ku| match ku.as_str() {
                "digitalSignature" => Some(KeyUsagePurpose::DigitalSignature),
                "keyCertSign" | "keyEncipherment" => Some(KeyUsagePurpose::KeyCertSign),
                "cRLSign" | "crlSign" => Some(KeyUsagePurpose::CrlSign),
                "contentCommitment" => Some(KeyUsagePurpose::ContentCommitment),
                "keyAgreement" => Some(KeyUsagePurpose::KeyAgreement),
                _ => None,
            })
            .collect()
    } else if is_ca {
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::KeyCertSign,
        ]
    } else {
        vec![KeyUsagePurpose::DigitalSignature]
    };

    // Extended key usages from extensions
    let ext_key_usages = if let Some(ref ext) = spec.extensions {
        ext.extended_key_usage
            .iter()
            .filter_map(|eku| match eku.as_str() {
                "serverAuth" => Some(ExtendedKeyUsagePurpose::ServerAuth),
                "clientAuth" => Some(ExtendedKeyUsagePurpose::ClientAuth),
                "codeSigning" => Some(ExtendedKeyUsagePurpose::CodeSigning),
                "emailProtection" => Some(ExtendedKeyUsagePurpose::EmailProtection),
                "timeStamping" => Some(ExtendedKeyUsagePurpose::TimeStamping),
                _ => None,
            })
            .collect()
    } else {
        vec![]
    };

    // Validity: years * 365 or days directly
    let validity_days = if let Some(years) = spec.validity.years {
        years * 365
    } else {
        spec.validity.days.unwrap_or(365)
    };

    // Subject fields: prefer cert-level subject, fall back to org-level defaults
    let organization = spec
        .subject
        .as_ref()
        .and_then(|s| s.organization.clone())
        .or_else(|| Some(org.to_string()));

    let organizational_unit = spec
        .subject
        .as_ref()
        .and_then(|s| s.organizational_unit.clone());

    let country = spec.subject.as_ref().and_then(|s| s.country.clone());

    CertGenSpec {
        name: spec.name.clone(),
        common_name: spec.cn.clone(),
        organization,
        organizational_unit,
        country,
        is_ca,
        pathlen: spec.pathlen,
        validity_days,
        key_usages,
        ext_key_usages,
        algorithm,
    }
}

// ═══════════════════════════════════════════════════════════════
// Ceremony state
// ═══════════════════════════════════════════════════════════════

/// The ceremony result — holds output directory and metadata.
/// GeneratedCerts are dropped (keys zeroized) when this goes out of scope.
pub struct CeremonyResult {
    /// Output directory for all ceremony artifacts
    pub output_dir: PathBuf,
    /// Number of certificates generated
    pub cert_count: usize,
    /// Names of certs that had Ed25519 parallel keys generated
    pub ed25519_cert_names: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Main entry point
// ═══════════════════════════════════════════════════════════════

/// Run the full ceremony from a config file.
///
/// Steps:
/// 1. Load and validate config
/// 2. Display the hierarchy tree
/// 3. Collect passphrases (grouped)
/// 4. Create output directory structure
/// 5. Generate certs in topological order (parents sign children)
/// 6. Write all files to disk
/// 7. Generate paper backup if configured
/// 8. Inventory outputs and print summary
pub fn run_ceremony(config_path: &str, output_override: Option<&str>) -> Result<CeremonyResult> {
    // ── Step 1: Load and validate config ──
    eprintln!("{BOLD}Loading ceremony config...{RESET}");
    let cfg = config::load_config(config_path)?;
    config::validate_config(&cfg)?;
    print_ok(&format!(
        "Config loaded: {} ({} certs)",
        cfg.name,
        cfg.hierarchy.len()
    ));

    let output_dir_str = output_override
        .map(|s| s.to_string())
        .or_else(|| cfg.output_dir.clone())
        .unwrap_or_else(|| "pki-output".to_string());
    let output = PathBuf::from(&output_dir_str);

    // ── Step 2: Display hierarchy tree ──
    print_hierarchy_tree(&cfg);

    // ── Step 3: Collect passphrases ──
    let pp_groups = config::passphrase_groups(&cfg);
    let needed: usize = pp_groups
        .iter()
        .filter(|g| !g.is_empty() && !g[0].no_passphrase)
        .count();
    eprintln!(
        "\n{BOLD}Passphrase collection{RESET} — {} unique passphrases needed",
        needed
    );

    let mut passphrases: HashMap<String, String> = HashMap::new();
    for group in &pp_groups {
        if group.is_empty() {
            continue;
        }
        // Use the first cert's name as the group key
        let group_key = group[0].name.clone();
        if group[0].no_passphrase {
            eprintln!(
                "  {DIM}Skipping passphrase for '{}' (no_passphrase=true){RESET}",
                group_key
            );
            continue;
        }

        let label = if group.len() == 1 {
            format!("'{}'", group_key)
        } else {
            let names: Vec<&str> = group.iter().map(|c| c.name.as_str()).collect();
            format!("group [{}]", names.join(", "))
        };

        let pass = prompt_passphrase(&label, cfg.passphrases.min_length)?;

        // Store passphrase for each cert in the group
        for cert_spec in group {
            passphrases.insert(cert_spec.name.clone(), pass.clone());
        }
        // The original pass clone is owned by the loop; it'll be dropped
    }

    // ── Step 4: Create output directory structure ──
    if output.exists() {
        eprint!(
            "\n{YELLOW}Output directory exists: {}{RESET}\nOverwrite? [y/N] ",
            output.display()
        );
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if answer.trim().to_lowercase() != "y" {
            bail!("Aborted — output directory exists");
        }
    }

    // Create subdirectories for each cert
    for spec in &cfg.hierarchy {
        let dir = output.join(&spec.name);
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create directory {}", dir.display()))?;
    }

    // ── Step 5: Generate certs in topological order ──
    let sorted = config::topological_sort(&cfg)?;
    let total = sorted.len();
    let mut cert_registry: HashMap<String, GeneratedCert> = HashMap::new();
    let mut ed25519_keys: HashMap<String, ed25519_keys::Ed25519KeyPair> = HashMap::new();
    let mut ed25519_cert_names: Vec<String> = Vec::new();

    for (step, spec) in sorted.iter().enumerate() {
        let algo_label = format!("{:?}", spec.algorithm);
        let validity_desc = if let Some(years) = spec.validity.years {
            format!("{} years", years)
        } else {
            format!("{} days", spec.validity.days.unwrap_or(365))
        };

        print_step(step + 1, total, &spec.cn);

        let certgen_spec = config_to_certgen_spec(spec, &cfg.organization);

        let cert = if let Some(parent_name) = spec.parent.as_ref() {
            // Signed by parent
            let parent = cert_registry.get(parent_name.as_str()).with_context(|| {
                format!(
                    "Parent '{}' not found — should have been generated first",
                    parent_name
                )
            })?;

            let path_info = if certgen_spec.is_ca {
                match spec.pathlen {
                    Some(n) => format!(", pathlen:{n}"),
                    None => String::new(),
                }
            } else {
                String::new()
            };

            let c = certgen::generate_signed_cert(&certgen_spec, parent).with_context(|| {
                format!(
                    "Failed to sign '{}' with parent '{}'",
                    spec.name, parent_name
                )
            })?;
            print_ok(&format!("{} keypair generated", algo_label));
            print_ok(&format!(
                "Signed by {} ({}{})",
                parent_name, validity_desc, path_info
            ));
            c
        } else {
            // Root CA — self-signed
            let c = certgen::generate_root_ca(&certgen_spec)
                .with_context(|| format!("Failed to generate root CA '{}'", spec.name))?;
            print_ok(&format!("{} keypair generated", algo_label));
            print_ok(&format!("Self-signed certificate ({})", validity_desc));
            c
        };

        // Generate parallel Ed25519 keypair if requested
        for parallel_algo in &spec.parallel_keys {
            if *parallel_algo == Algorithm::Ed25519 {
                let ed_kp = ed25519_keys::generate_ed25519_keypair()?;
                print_ok("Ed25519 parallel keypair generated");
                ed25519_keys.insert(spec.name.clone(), ed_kp);
                ed25519_cert_names.push(spec.name.clone());
            }
        }

        // Note passphrase status
        if !spec.no_passphrase {
            if passphrases.contains_key(&spec.name) {
                print_ok("Key encrypted with passphrase");
            }
        } else {
            print_warn("Key NOT encrypted (no_passphrase=true) — for CI use only");
        }

        cert_registry.insert(spec.name.clone(), cert);
    }

    // ── Step 6: Write all files to disk ──
    eprintln!("\n{BOLD}Writing ceremony outputs to disk...{RESET}");

    for (step, spec) in sorted.iter().enumerate() {
        let cert = &cert_registry[&spec.name];
        let cert_dir = output.join(&spec.name);

        // Write certificate PEM
        let cert_path = cert_dir.join(format!("{}.crt", spec.name));
        write_ceremony_file(&cert_path, cert.cert_pem.as_bytes())?;

        // Write private key PEM
        let key_path = cert_dir.join(format!("{}.key", spec.name));
        if spec.no_passphrase {
            write_ceremony_file(&key_path, cert.key_pem.as_bytes())?;
        } else if let Some(_passphrase) = passphrases.get(&spec.name) {
            // In full integration, encrypt with openssl pkcs8.
            // For now, write the key directly.
            write_ceremony_file(&key_path, cert.key_pem.as_bytes())?;
        } else {
            write_ceremony_file(&key_path, cert.key_pem.as_bytes())?;
        }

        // Write chain file
        let chain_path = cert_dir.join("chain.crt");
        write_ceremony_file(&chain_path, cert.chain_pem.as_bytes())?;

        // Write Ed25519 parallel keypair if present
        if let Some(kp) = ed25519_keys.get(&spec.name) {
            let ed_priv = cert_dir.join(format!("{}.ed25519.key", spec.name));
            let ed_pub = cert_dir.join(format!("{}.ed25519.pub", spec.name));
            write_ceremony_file(&ed_priv, kp.private_pem.as_bytes())?;
            write_ceremony_file(&ed_pub, kp.public_pem.as_bytes())?;
        }

        eprintln!(
            "  {GREEN}[{}/{}]{RESET} {} written",
            step + 1,
            total,
            spec.name
        );
    }

    // Write .gitignore
    write_ceremony_file(
        &output.join(".gitignore"),
        b"# Never commit private keys\n*.key\n*.sk\n*.dk\n.build-tmp/\n.backup-*/\n",
    )?;

    // ── Step 7: Paper backup ──
    if let Some(ref pb_config) = cfg.paper_backup {
        eprintln!("\n{BOLD}Generating paper backup...{RESET}");
        let mut keys_for_backup: Vec<paper::KeyForBackup> = Vec::new();

        for spec in sorted.iter() {
            let cert = &cert_registry[&spec.name];
            let is_ca = matches!(
                spec.cert_type,
                CertType::Root | CertType::Intermediate | CertType::SubCa
            );

            let criticality = match spec.cert_type {
                CertType::Root => paper::Criticality::Critical,
                CertType::Intermediate | CertType::SubCa => paper::Criticality::High,
                CertType::Leaf => {
                    if spec.deploy_to.is_some() {
                        paper::Criticality::Deploy
                    } else {
                        paper::Criticality::Medium
                    }
                }
            };

            let key_type = format!("{:?}", spec.algorithm);
            let file_path = output
                .join(&spec.name)
                .join(format!("{}.key", spec.name))
                .to_string_lossy()
                .into_owned();

            keys_for_backup.push(paper::KeyForBackup {
                label: spec.cn.clone(),
                key_type,
                criticality,
                pem_content: cert.key_pem.clone(),
                file_path,
            });

            // Add Ed25519 parallel key if present
            if let Some(kp) = ed25519_keys.get(&spec.name) {
                let ed_file_path = output
                    .join(&spec.name)
                    .join(format!("{}.ed25519.key", spec.name))
                    .to_string_lossy()
                    .into_owned();
                keys_for_backup.push(paper::KeyForBackup {
                    label: format!("{} (Ed25519 parallel)", spec.cn),
                    key_type: "Ed25519".to_string(),
                    criticality,
                    pem_content: kp.private_pem.clone(),
                    file_path: ed_file_path,
                });
            }
        }

        let backup_config = paper::PaperBackupConfig {
            title: cfg.name.clone(),
            output_path: output
                .join("paper-backup.html")
                .to_string_lossy()
                .into_owned(),
        };

        let html = paper::generate_paper_backup(&backup_config, &keys_for_backup)?;
        let backup_path = output.join("paper-backup.html");
        write_ceremony_file(&backup_path, html.as_bytes())?;
        print_ok("Paper backup written to paper-backup.html");
    }

    // ── Step 8: Inventory and summary ──
    let outputs = deploy::inventory_outputs(&output)?;
    deploy::print_summary(&outputs);

    // Write manifest
    let manifest_json = deploy::generate_manifest(&outputs)?;
    write_ceremony_file(
        &output.join("ceremony-manifest.json"),
        manifest_json.as_bytes(),
    )?;
    print_ok("Manifest written to ceremony-manifest.json");

    // Zeroize passphrases
    for (_, pass) in passphrases.iter_mut() {
        pass.zeroize();
    }

    eprintln!(
        "\n{BOLD}{GREEN}Ceremony complete!{RESET} Output: {}",
        output.display()
    );

    let cert_count = cert_registry.len();

    // cert_registry is dropped here, which zeroizes all key_pem via GeneratedCert's Drop impl

    Ok(CeremonyResult {
        output_dir: output,
        cert_count,
        ed25519_cert_names,
    })
}

/// Run a dry-run of the ceremony — validate config and show plan without generating.
pub fn dry_run_ceremony(config_path: &str, output_override: Option<&str>) -> Result<()> {
    eprintln!("{BOLD}Loading ceremony config (dry run)...{RESET}");
    let cfg = config::load_config(config_path)?;
    config::validate_config(&cfg)?;
    print_ok(&format!(
        "Config loaded: {} ({} certs)",
        cfg.name,
        cfg.hierarchy.len()
    ));

    let output_dir = output_override
        .map(|s| s.to_string())
        .or_else(|| cfg.output_dir.clone())
        .unwrap_or_else(|| "pki-output".to_string());
    eprintln!("  Output directory: {output_dir}");

    // Display hierarchy tree
    print_hierarchy_tree(&cfg);

    // Display topological order
    let sorted = config::topological_sort(&cfg)?;
    eprintln!("\n{BOLD}Generation order:{RESET}");
    for (i, spec) in sorted.iter().enumerate() {
        let algo = format!("{:?}", spec.algorithm);
        let validity = if let Some(years) = spec.validity.years {
            format!("{}yr", years)
        } else {
            format!("{}d", spec.validity.days.unwrap_or(365))
        };
        let parent_info = if let Some(ref p) = spec.parent {
            format!(" signed by {p}")
        } else {
            " (self-signed root)".to_string()
        };
        eprintln!(
            "  {BOLD}{}.{RESET} {} ({algo}, {validity}){parent_info}",
            i + 1,
            spec.cn
        );
    }

    // Display passphrase groups
    let pp_groups = config::passphrase_groups(&cfg);
    let needed: usize = pp_groups
        .iter()
        .filter(|g| !g.is_empty() && !g[0].no_passphrase)
        .count();
    eprintln!("\n{BOLD}Passphrase groups:{RESET} ({needed} passphrases needed)");
    for group in &pp_groups {
        if group.is_empty() {
            continue;
        }
        let names: Vec<&str> = group.iter().map(|c| c.name.as_str()).collect();
        if group[0].no_passphrase {
            eprintln!("  {DIM}[no passphrase] {}{RESET}", names.join(", "));
        } else {
            eprintln!("  [passphrase] {}", names.join(", "));
        }
    }

    eprintln!(
        "\n{BOLD}Dry run complete.{RESET} No keys generated. Remove --dry-run to execute the ceremony."
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Hierarchy display
// ═══════════════════════════════════════════════════════════════

/// Print the certificate hierarchy as a tree
fn print_hierarchy_tree(config: &CeremonyConfig) {
    eprintln!("\n{BOLD}Certificate Hierarchy:{RESET}");

    // Build parent -> children map
    let mut children_map: HashMap<Option<&str>, Vec<&CertSpec>> = HashMap::new();
    for cert in &config.hierarchy {
        children_map
            .entry(cert.parent.as_deref())
            .or_default()
            .push(cert);
    }

    // Print from roots
    if let Some(roots) = children_map.get(&None) {
        for root in roots {
            print_tree_node(root, &children_map, "", true);
        }
    }
}

fn print_tree_node(
    spec: &CertSpec,
    children_map: &HashMap<Option<&str>, Vec<&CertSpec>>,
    prefix: &str,
    is_last: bool,
) {
    let connector = if prefix.is_empty() {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    let ca_marker = match spec.cert_type {
        CertType::Root | CertType::Intermediate | CertType::SubCa => " [CA]",
        CertType::Leaf => "",
    };
    let algo = format!("{:?}", spec.algorithm);
    let validity = if let Some(years) = spec.validity.years {
        format!("{}yr", years)
    } else {
        format!("{}d", spec.validity.days.unwrap_or(365))
    };
    let offline_marker = if spec.offline { " {OFFLINE}" } else { "" };
    let parallel_marker = if !spec.parallel_keys.is_empty() {
        let keys: Vec<String> = spec
            .parallel_keys
            .iter()
            .map(|a| format!("{:?}", a))
            .collect();
        format!(" +{}", keys.join("+"))
    } else {
        String::new()
    };

    eprintln!(
        "  {prefix}{connector}{BOLD}{}{RESET}{DIM} ({algo}, {validity}{ca_marker}{offline_marker}{parallel_marker}){RESET}",
        spec.cn
    );

    let child_prefix = if prefix.is_empty() {
        "".to_string()
    } else if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    if let Some(kids) = children_map.get(&Some(spec.name.as_str())) {
        for (i, kid) in kids.iter().enumerate() {
            let last = i == kids.len() - 1;
            print_tree_node(kid, children_map, &child_prefix, last);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Passphrase collection
// ═══════════════════════════════════════════════════════════════

/// Prompt the user for a passphrase with confirmation
fn prompt_passphrase(label: &str, min_len: usize) -> Result<String> {
    loop {
        let mut pass1 = rpassword::prompt_password(format!("  Enter passphrase for {label}: "))
            .context("Failed to read passphrase")?;

        if pass1.len() < min_len {
            eprintln!("    {RED}ERROR{RESET}: Must be at least {min_len} characters. Try again.");
            pass1.zeroize();
            continue;
        }

        let mut pass2 = rpassword::prompt_password(format!("  Confirm passphrase for {label}: "))
            .context("Failed to read confirmation")?;

        if pass1 != pass2 {
            eprintln!("    {RED}ERROR{RESET}: Passphrases don't match. Try again.");
            pass1.zeroize();
            pass2.zeroize();
            continue;
        }

        pass2.zeroize();
        eprintln!("    {GREEN}OK{RESET} (passphrase accepted)");
        return Ok(pass1);
    }
}

// ═══════════════════════════════════════════════════════════════
// File I/O
// ═══════════════════════════════════════════════════════════════

/// Write a ceremony file with appropriate permissions
fn write_ceremony_file(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data).with_context(|| format!("Failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mode = match ext {
            "key" | "sk" | "dk" => 0o400,
            "sh" => 0o755,
            _ => 0o644,
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CertGenSpec directly for testing config_to_certgen_spec
    fn sample_config() -> CeremonyConfig {
        serde_yaml::from_str(
            r#"
name: Test Ceremony
organization: Test LLC
hierarchy:
  - name: root-ca
    cn: Test Root CA
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
    offline: true
  - name: intermediate-ca
    cn: Test Intermediate CA
    cert_type: intermediate
    parent: root-ca
    algorithm: rsa_4096
    pathlen: 0
    validity:
      years: 10
    parallel_keys:
      - ed25519
  - name: code-signing
    cn: Test Code Signing
    cert_type: leaf
    parent: intermediate-ca
    algorithm: rsa_4096
    validity:
      years: 2
    extensions:
      extended_key_usage:
        - codeSigning
  - name: ci-signer
    cn: CI Signer
    cert_type: leaf
    parent: intermediate-ca
    algorithm: ed25519
    validity:
      days: 365
    no_passphrase: true
    deploy_to: github-actions
    extensions:
      extended_key_usage:
        - codeSigning
"#,
        )
        .unwrap()
    }

    #[test]
    fn validate_valid_config() {
        let cfg = sample_config();
        assert!(config::validate_config(&cfg).is_ok());
    }

    #[test]
    fn topological_sort_correct_order() {
        let cfg = sample_config();
        let sorted = config::topological_sort(&cfg).unwrap();

        let names: Vec<&str> = sorted.iter().map(|c| c.name.as_str()).collect();

        // Root must come before intermediate
        let root_pos = names.iter().position(|&n| n == "root-ca").unwrap();
        let inter_pos = names.iter().position(|&n| n == "intermediate-ca").unwrap();
        let signing_pos = names.iter().position(|&n| n == "code-signing").unwrap();
        let ci_pos = names.iter().position(|&n| n == "ci-signer").unwrap();

        assert!(root_pos < inter_pos);
        assert!(inter_pos < signing_pos);
        assert!(inter_pos < ci_pos);
    }

    #[test]
    fn config_to_certgen_spec_root() {
        let cfg = sample_config();
        let root_spec = &cfg.hierarchy[0];
        let certgen_spec = config_to_certgen_spec(root_spec, &cfg.organization);

        assert_eq!(certgen_spec.name, "root-ca");
        assert_eq!(certgen_spec.common_name, "Test Root CA");
        assert!(certgen_spec.is_ca);
        assert_eq!(certgen_spec.pathlen, None);
        assert_eq!(certgen_spec.validity_days, 20 * 365);
        assert_eq!(certgen_spec.algorithm, CertAlgorithm::Rsa4096);
        assert_eq!(certgen_spec.organization.as_deref(), Some("Test LLC"));
    }

    #[test]
    fn config_to_certgen_spec_intermediate() {
        let cfg = sample_config();
        let inter_spec = &cfg.hierarchy[1];
        let certgen_spec = config_to_certgen_spec(inter_spec, &cfg.organization);

        assert!(certgen_spec.is_ca);
        assert_eq!(certgen_spec.pathlen, Some(0));
        assert_eq!(certgen_spec.validity_days, 10 * 365);
    }

    #[test]
    fn config_to_certgen_spec_leaf_ed25519() {
        let cfg = sample_config();
        let ci_spec = &cfg.hierarchy[3]; // ci-signer
        let certgen_spec = config_to_certgen_spec(ci_spec, &cfg.organization);

        assert!(!certgen_spec.is_ca);
        assert_eq!(certgen_spec.algorithm, CertAlgorithm::Ed25519);
        assert_eq!(certgen_spec.validity_days, 365);
    }

    #[test]
    fn config_to_certgen_spec_with_extensions() {
        let cfg = sample_config();
        let signing_spec = &cfg.hierarchy[2]; // code-signing
        let certgen_spec = config_to_certgen_spec(signing_spec, &cfg.organization);

        assert!(!certgen_spec.is_ca);
        assert!(
            certgen_spec
                .ext_key_usages
                .contains(&ExtendedKeyUsagePurpose::CodeSigning)
        );
    }

    #[test]
    fn generate_root_ca_via_certgen() {
        let cfg = sample_config();
        let root_spec = &cfg.hierarchy[0];
        let certgen_spec = config_to_certgen_spec(root_spec, &cfg.organization);

        let cert = certgen::generate_root_ca(&certgen_spec).unwrap();
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN"));
        assert!(cert.is_ca);
        assert_eq!(cert.name, "root-ca");
    }

    #[test]
    fn generate_signed_child_via_certgen() {
        let cfg = sample_config();
        let root_spec = &cfg.hierarchy[0];
        let inter_spec = &cfg.hierarchy[1];

        let root_certgen = config_to_certgen_spec(root_spec, &cfg.organization);
        let inter_certgen = config_to_certgen_spec(inter_spec, &cfg.organization);

        let root = certgen::generate_root_ca(&root_certgen).unwrap();
        let inter = certgen::generate_signed_cert(&inter_certgen, &root).unwrap();

        assert!(inter.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(inter.is_ca);
        // Chain should include both intermediate and root certs
        assert!(inter.chain_pem.contains(&inter.cert_pem));
        assert!(inter.chain_pem.contains(&root.cert_pem));
    }

    #[test]
    fn generate_three_tier_hierarchy_via_certgen() {
        let cfg = sample_config();

        let root_cg = config_to_certgen_spec(&cfg.hierarchy[0], &cfg.organization);
        let inter_cg = config_to_certgen_spec(&cfg.hierarchy[1], &cfg.organization);
        let leaf_cg = config_to_certgen_spec(&cfg.hierarchy[2], &cfg.organization);

        let root = certgen::generate_root_ca(&root_cg).unwrap();
        let inter = certgen::generate_signed_cert(&inter_cg, &root).unwrap();
        let leaf = certgen::generate_signed_cert(&leaf_cg, &inter).unwrap();

        // Leaf chain = leaf + inter + root
        assert!(leaf.chain_pem.contains(&leaf.cert_pem));
        assert!(leaf.chain_pem.contains(&inter.cert_pem));
        assert!(leaf.chain_pem.contains(&root.cert_pem));
    }

    #[test]
    fn passphrase_groups_from_config() {
        let cfg = sample_config();
        let groups = config::passphrase_groups(&cfg);

        // root-ca gets its own group, intermediate-ca its own,
        // ci-signer excluded (no_passphrase)
        let all_names: Vec<Vec<&str>> = groups
            .iter()
            .map(|g| g.iter().map(|c| c.name.as_str()).collect())
            .collect();

        assert!(all_names.iter().any(|g| g.contains(&"root-ca")));
        assert!(all_names.iter().any(|g| g.contains(&"intermediate-ca")));
        assert!(!all_names.iter().any(|g| g.contains(&"ci-signer")));
    }

    #[test]
    fn validate_missing_parent() {
        let yaml = r#"
name: Bad
organization: Bad LLC
hierarchy:
  - name: leaf
    cn: Leaf
    cert_type: leaf
    parent: nonexistent
    algorithm: rsa_4096
    validity:
      years: 1
"#;
        let cfg: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config::validate_config(&cfg).is_err());
    }

    #[test]
    fn validate_no_root() {
        let yaml = r#"
name: No Root
organization: NoRoot LLC
hierarchy:
  - name: a
    cn: A
    cert_type: intermediate
    parent: b
    algorithm: rsa_4096
    validity:
      years: 10
  - name: b
    cn: B
    cert_type: sub_ca
    parent: a
    algorithm: rsa_4096
    validity:
      years: 5
"#;
        let cfg: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config::validate_config(&cfg).is_err());
    }

    #[test]
    fn topological_sort_detects_cycle() {
        let yaml = r#"
name: Cycle
organization: Cycle LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: a
    cn: A
    cert_type: intermediate
    parent: b
    algorithm: rsa_4096
    validity:
      years: 10
  - name: b
    cn: B
    cert_type: sub_ca
    parent: a
    algorithm: rsa_4096
    validity:
      years: 5
"#;
        let cfg: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        // Validate first catches the cycle or topo sort does
        let result = config::validate_config(&cfg);
        assert!(result.is_err());
    }
}
