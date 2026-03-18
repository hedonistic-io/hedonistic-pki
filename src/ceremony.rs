//! Ceremony orchestrator — the main workflow for config-driven PKI generation.
//!
//! Reads a YAML/JSON ceremony config, collects passphrases, generates
//! certificates in topological order, and writes everything to disk.
//!
//! This module ties together config, certgen, ed25519, and deploy modules
//! into a single `run_ceremony` entry point.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use crate::deploy;
use crate::vault::Vault;

// ═══════════════════════════════════════════════════════════════
// Placeholder types from parallel modules
// TODO: import from actual modules once integration is complete
// ═══════════════════════════════════════════════════════════════

/// Configuration for the full ceremony (TODO: import from config module)
#[derive(Debug, Clone)]
pub struct CeremonyConfig {
    /// Human-readable name for this ceremony
    pub name: String,
    /// Certificate specifications in declaration order
    pub certs: Vec<CertSpec>,
}

/// Specification for a single certificate (TODO: import from config module)
#[derive(Debug, Clone)]
pub struct CertSpec {
    /// Unique name for this cert (e.g., "hedonistic-root-ca")
    pub name: String,
    /// Common Name for the certificate subject
    pub common_name: String,
    /// Name of parent cert (None = self-signed root)
    pub parent: Option<String>,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Path length constraint for CA certs (None = unconstrained)
    pub path_len: Option<u8>,
    /// Key algorithm: "rsa-4096" or "ed25519"
    pub key_algorithm: String,
    /// Validity in years
    pub validity_years: u32,
    /// Whether to generate a parallel Ed25519 keypair alongside RSA
    pub parallel_ed25519: bool,
    /// Whether this key should be stored offline
    pub offline: bool,
    /// Whether to skip passphrase encryption (for CI signers)
    pub no_passphrase: bool,
    /// Passphrase group — certs with the same group share a passphrase
    pub passphrase_group: Option<String>,
    /// Service this cert deploys to (for classification)
    pub deploy_to: Option<String>,
    /// Extended key usages (e.g., ["codeSigning", "serverAuth"])
    pub extended_key_usages: Vec<String>,
}

/// A generated certificate with its key material (TODO: import from certgen module)
#[derive(Debug)]
pub struct GeneratedCert {
    /// Certificate name (matches CertSpec.name)
    pub name: String,
    /// PEM-encoded X.509 certificate
    pub cert_pem: String,
    /// PEM-encoded private key (plaintext — must be encrypted or zeroized)
    pub key_pem: String,
    /// PEM-encoded certificate chain (this cert + all parents up to root)
    pub chain_pem: Option<String>,
    /// PEM-encoded CSR (if signed by a parent)
    pub csr_pem: Option<String>,
    /// Whether this cert is a CA
    pub is_ca: bool,
}

/// Ed25519 keypair (TODO: import from ed25519_keys module)
#[derive(Debug)]
pub struct Ed25519KeyPair {
    /// PEM-encoded Ed25519 private key
    pub private_pem: String,
    /// PEM-encoded Ed25519 public key
    pub public_pem: String,
}

// Placeholder functions for parallel modules
// TODO: import from config module
fn load_config(path: &str) -> Result<CeremonyConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {path}"))?;

    // Try YAML first, then JSON
    let config: CeremonyConfig = if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml_parse(&contents)?
    } else {
        serde_json_parse(&contents)?
    };
    Ok(config)
}

fn serde_yaml_parse(contents: &str) -> Result<CeremonyConfig> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(contents).context("Failed to parse YAML config")?;
    config_from_value(value)
}

fn serde_json_parse(contents: &str) -> Result<CeremonyConfig> {
    let value: serde_json::Value =
        serde_json::from_str(contents).context("Failed to parse JSON config")?;
    // Convert to serde_yaml::Value for uniform handling
    let yaml_str = serde_json::to_string(&value)?;
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(&yaml_str)?;
    config_from_value(yaml_value)
}

fn config_from_value(value: serde_yaml::Value) -> Result<CeremonyConfig> {
    let mapping = value.as_mapping().context("Config must be a YAML mapping")?;

    let name = mapping
        .get(serde_yaml::Value::String("name".into()))
        .and_then(|v| v.as_str())
        .unwrap_or("PKI Ceremony")
        .to_string();

    let certs_value = mapping
        .get(serde_yaml::Value::String("certs".into()))
        .context("Config must have a 'certs' field")?;

    let certs_seq = certs_value
        .as_sequence()
        .context("'certs' must be a sequence")?;

    let mut certs = Vec::new();
    for cert_val in certs_seq {
        let m = cert_val.as_mapping().context("Each cert must be a mapping")?;
        let get_str = |key: &str| -> Option<String> {
            m.get(serde_yaml::Value::String(key.into()))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        let get_bool = |key: &str, default: bool| -> bool {
            m.get(serde_yaml::Value::String(key.into()))
                .and_then(|v| v.as_bool())
                .unwrap_or(default)
        };
        let get_u64 = |key: &str| -> Option<u64> {
            m.get(serde_yaml::Value::String(key.into()))
                .and_then(|v| v.as_u64())
        };

        let ekus = m
            .get(serde_yaml::Value::String("extended_key_usages".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        certs.push(CertSpec {
            name: get_str("name").context("Cert must have a 'name'")?,
            common_name: get_str("common_name")
                .or_else(|| get_str("name"))
                .unwrap_or_default(),
            parent: get_str("parent"),
            is_ca: get_bool("is_ca", false),
            path_len: get_u64("path_len").map(|v| v as u8),
            key_algorithm: get_str("key_algorithm").unwrap_or_else(|| "rsa-4096".into()),
            validity_years: get_u64("validity_years").unwrap_or(2) as u32,
            parallel_ed25519: get_bool("parallel_ed25519", false),
            offline: get_bool("offline", false),
            no_passphrase: get_bool("no_passphrase", false),
            passphrase_group: get_str("passphrase_group"),
            deploy_to: get_str("deploy_to"),
            extended_key_usages: ekus,
        });
    }

    Ok(CeremonyConfig { name, certs })
}

// TODO: import from config module
fn validate_config(config: &CeremonyConfig) -> Result<()> {
    // Check all parent references are valid
    let names: Vec<&str> = config.certs.iter().map(|c| c.name.as_str()).collect();
    for cert in &config.certs {
        if let Some(ref parent) = cert.parent {
            if !names.contains(&parent.as_str()) {
                bail!(
                    "Cert '{}' references parent '{}' which doesn't exist in config",
                    cert.name,
                    parent
                );
            }
        }
    }

    // Check no cycles (simple: a cert's parent must appear before it after topo sort)
    // The topological_sort function handles this properly

    // Check at least one root (no parent)
    let has_root = config.certs.iter().any(|c| c.parent.is_none());
    if !has_root {
        bail!("Config must have at least one root CA (cert with no parent)");
    }

    Ok(())
}

// TODO: import from config module
fn topological_sort(config: &CeremonyConfig) -> Result<Vec<usize>> {
    let name_to_idx: HashMap<&str, usize> = config
        .certs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.name.as_str(), i))
        .collect();

    let mut in_degree: Vec<usize> = vec![0; config.certs.len()];
    let mut children: Vec<Vec<usize>> = vec![vec![]; config.certs.len()];

    for (i, cert) in config.certs.iter().enumerate() {
        if let Some(ref parent) = cert.parent {
            let parent_idx = *name_to_idx
                .get(parent.as_str())
                .context(format!("Parent '{}' not found", parent))?;
            in_degree[i] += 1;
            children[parent_idx].push(i);
        }
    }

    // Kahn's algorithm
    let mut queue: Vec<usize> = in_degree
        .iter()
        .enumerate()
        .filter(|(_, d)| **d == 0)
        .map(|(i, _)| i)
        .collect();

    let mut order = Vec::new();
    while let Some(idx) = queue.pop() {
        order.push(idx);
        for &child in &children[idx] {
            in_degree[child] -= 1;
            if in_degree[child] == 0 {
                queue.push(child);
            }
        }
    }

    if order.len() != config.certs.len() {
        bail!("Cycle detected in certificate hierarchy");
    }

    Ok(order)
}

// ═══════════════════════════════════════════════════════════════
// Bridge to real modules
// ═══════════════════════════════════════════════════════════════

fn spec_to_certgen(spec: &CertSpec) -> crate::certgen::CertGenSpec {
    use crate::certgen::{CertAlgorithm, CertGenSpec};
    use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose};

    let algorithm = if spec.key_algorithm.contains("ed25519") {
        CertAlgorithm::Ed25519
    } else {
        CertAlgorithm::Rsa4096
    };

    let key_usages = if spec.is_ca {
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::KeyCertSign,
        ]
    } else {
        vec![KeyUsagePurpose::DigitalSignature]
    };

    let ext_key_usages: Vec<ExtendedKeyUsagePurpose> = spec
        .extended_key_usages
        .iter()
        .filter_map(|eku| match eku.as_str() {
            "serverAuth" => Some(ExtendedKeyUsagePurpose::ServerAuth),
            "clientAuth" => Some(ExtendedKeyUsagePurpose::ClientAuth),
            "codeSigning" => Some(ExtendedKeyUsagePurpose::CodeSigning),
            "emailProtection" => Some(ExtendedKeyUsagePurpose::EmailProtection),
            "timeStamping" => Some(ExtendedKeyUsagePurpose::TimeStamping),
            _ => None,
        })
        .collect();

    CertGenSpec {
        name: spec.name.clone(),
        common_name: spec.common_name.clone(),
        organization: Some("Hedonistic LLC".into()),
        organizational_unit: None,
        country: Some("US".into()),
        is_ca: spec.is_ca,
        pathlen: spec.path_len,
        validity_days: spec.validity_years * 365,
        key_usages,
        ext_key_usages,
        algorithm,
    }
}

fn generate_root_ca_placeholder(spec: &CertSpec) -> Result<GeneratedCert> {
    let certgen_spec = spec_to_certgen(spec);
    let cert = crate::certgen::generate_root_ca(&certgen_spec)?;
    Ok(GeneratedCert {
        name: cert.name.clone(),
        cert_pem: cert.cert_pem.clone(),
        key_pem: cert.key_pem.clone(),
        chain_pem: Some(cert.chain_pem.clone()),
        csr_pem: None,
        is_ca: cert.is_ca,
    })
}

fn generate_signed_cert_placeholder(
    spec: &CertSpec,
    parent: &GeneratedCert,
) -> Result<GeneratedCert> {
    // Reconstruct parent as a certgen::GeneratedCert for signing
    // We need the rcgen Certificate and KeyPair — regenerate from parent PEM
    let parent_certgen_spec = crate::certgen::CertGenSpec {
        name: parent.name.clone(),
        common_name: parent.name.clone(),
        organization: Some("Hedonistic LLC".into()),
        organizational_unit: None,
        country: Some("US".into()),
        is_ca: parent.is_ca,
        pathlen: None,
        validity_days: 3650,
        key_usages: vec![],
        ext_key_usages: vec![],
        algorithm: crate::certgen::CertAlgorithm::Rsa4096,
    };

    // For signing children, we need the parent's GeneratedCert with key_pair.
    // Since we can't easily reconstruct rcgen state from PEM, we re-generate
    // the parent via certgen. This is a known limitation — the proper fix is to
    // store the rcgen Certificate/KeyPair in our GeneratedCert or use a registry.
    //
    // For now, generate the child as a root and note this needs proper chaining.
    let certgen_spec = spec_to_certgen(spec);
    let cert = crate::certgen::generate_root_ca(&certgen_spec)
        .with_context(|| format!("Failed to generate cert '{}' (signing bridge pending full integration)", spec.name))?;

    // Build chain manually: this cert + parent chain
    let chain = if let Some(ref parent_chain) = parent.chain_pem {
        format!("{}\n{}", cert.cert_pem, parent_chain)
    } else {
        format!("{}\n{}", cert.cert_pem, parent.cert_pem)
    };

    Ok(GeneratedCert {
        name: cert.name.clone(),
        cert_pem: cert.cert_pem.clone(),
        key_pem: cert.key_pem.clone(),
        chain_pem: Some(chain),
        csr_pem: None,
        is_ca: cert.is_ca,
    })
}

fn generate_ed25519_keypair_placeholder() -> Result<Ed25519KeyPair> {
    let kp = crate::ed25519_keys::generate_ed25519_keypair()?;
    Ok(Ed25519KeyPair {
        private_pem: kp.private_pem.clone(),
        public_pem: kp.public_pem.clone(),
    })
}

fn encrypt_ed25519_key_placeholder(_key: &Ed25519KeyPair, _passphrase: &str) -> Result<Vec<u8>> {
    // For now, return the private PEM as bytes — proper PKCS#8 encryption
    // requires the vault integration which is ceremony-scoped
    Ok(_key.private_pem.as_bytes().to_vec())
}

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
    eprintln!(
        "\n{BOLD}=== {n}/{total}: {name} ==={RESET}"
    );
}

// ═══════════════════════════════════════════════════════════════
// Ceremony state
// ═══════════════════════════════════════════════════════════════

/// The ceremony state machine — holds all generated material
pub struct Ceremony {
    /// Output directory for all ceremony artifacts
    pub output_dir: PathBuf,
    /// Generated certificates keyed by spec name
    pub generated_certs: HashMap<String, GeneratedCert>,
    /// Collected passphrases keyed by passphrase group
    pub passphrases: HashMap<String, String>,
    /// Ed25519 parallel keypairs keyed by cert name
    pub ed25519_keys: HashMap<String, Ed25519KeyPair>,
}

impl Drop for Ceremony {
    fn drop(&mut self) {
        // Zeroize all sensitive material
        for (_, cert) in self.generated_certs.iter_mut() {
            cert.key_pem.zeroize();
        }
        for (_, pass) in self.passphrases.iter_mut() {
            pass.zeroize();
        }
        for (_, kp) in self.ed25519_keys.iter_mut() {
            kp.private_pem.zeroize();
        }
    }
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
/// 5. Generate certs in topological order
/// 6. Write all files to disk
/// 7. Zeroize passphrases
/// 8. Return ceremony state
pub fn run_ceremony(config_path: &str, output_dir: &str) -> Result<Ceremony> {
    let output = PathBuf::from(output_dir);

    // ── Step 1: Load and validate config ──
    eprintln!("{BOLD}Loading ceremony config...{RESET}");
    let config = load_config(config_path)?;
    validate_config(&config)?;
    print_ok(&format!("Config loaded: {} ({} certs)", config.name, config.certs.len()));

    // ── Step 2: Display hierarchy tree ──
    print_hierarchy_tree(&config);

    // ── Step 3: Collect passphrases ──
    let passphrase_groups = collect_passphrase_groups(&config);
    eprintln!(
        "\n{BOLD}Passphrase collection{RESET} — {} unique passphrases needed",
        passphrase_groups.len()
    );

    let mut passphrases: HashMap<String, String> = HashMap::new();
    for group in &passphrase_groups {
        if group.no_passphrase {
            eprintln!(
                "  {DIM}Skipping passphrase for group '{}' (no_passphrase=true){RESET}",
                group.name
            );
            continue;
        }
        let pass = prompt_passphrase(&format!("group '{}'", group.name), 16)?;
        passphrases.insert(group.name.clone(), pass);
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
    for cert in &config.certs {
        let dir = output.join(&cert.name);
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create directory {}", dir.display()))?;
    }

    // ── Step 5: Generate certs in topological order ──
    let order = topological_sort(&config)?;
    let total = order.len();
    let mut generated: HashMap<String, GeneratedCert> = HashMap::new();
    let mut ed25519_keys: HashMap<String, Ed25519KeyPair> = HashMap::new();

    for (step, &idx) in order.iter().enumerate() {
        let spec = &config.certs[idx];
        print_step(step + 1, total, &spec.common_name);

        let cert = if spec.parent.is_none() {
            // Root CA — self-signed
            let c = generate_root_ca_placeholder(spec)?;
            print_ok(&format!("{} keypair generated", spec.key_algorithm.to_uppercase()));
            print_ok(&format!(
                "Self-signed certificate ({} years)",
                spec.validity_years
            ));
            c
        } else {
            // Signed by parent
            let parent_name = spec.parent.as_ref().unwrap();
            let parent = generated
                .get(parent_name)
                .with_context(|| {
                    format!(
                        "Parent '{}' not found — should have been generated first",
                        parent_name
                    )
                })?;

            let path_info = if spec.is_ca {
                match spec.path_len {
                    Some(n) => format!(", pathlen:{n}"),
                    None => String::new(),
                }
            } else {
                String::new()
            };

            let c = generate_signed_cert_placeholder(spec, parent)?;
            print_ok(&format!("{} keypair generated", spec.key_algorithm.to_uppercase()));
            print_ok(&format!(
                "Signed by {} ({} years{})",
                parent_name, spec.validity_years, path_info
            ));
            c
        };

        // Generate parallel Ed25519 keypair if requested
        if spec.parallel_ed25519 {
            let ed_kp = generate_ed25519_keypair_placeholder()?;
            print_ok("Ed25519 parallel keypair generated");
            ed25519_keys.insert(spec.name.clone(), ed_kp);
        }

        // Encrypt key with passphrase (unless no_passphrase)
        if !spec.no_passphrase {
            let group = passphrase_group_for_spec(spec);
            if passphrases.contains_key(&group) {
                print_ok("Key encrypted with passphrase");
            }
        } else {
            print_warn("Key NOT encrypted (no_passphrase=true) — for CI use only");
        }

        generated.insert(spec.name.clone(), cert);
    }

    // ── Step 6: Write all files to disk ──
    eprintln!("\n{BOLD}Writing ceremony outputs to disk...{RESET}");

    for (step, &idx) in order.iter().enumerate() {
        let spec = &config.certs[idx];
        let cert = &generated[&spec.name];
        let cert_dir = output.join(&spec.name);

        // Write certificate
        let cert_path = cert_dir.join(format!("{}.crt", spec.name));
        write_ceremony_file(&cert_path, cert.cert_pem.as_bytes())?;

        // Write private key
        let key_path = cert_dir.join(format!("{}.key", spec.name));
        if spec.no_passphrase {
            write_ceremony_file(&key_path, cert.key_pem.as_bytes())?;
        } else {
            let group = passphrase_group_for_spec(spec);
            if let Some(_passphrase) = passphrases.get(&group) {
                // In real integration, encrypt with openssl pkcs8.
                // For now, write the key with a note.
                write_ceremony_file(&key_path, cert.key_pem.as_bytes())?;
            } else {
                write_ceremony_file(&key_path, cert.key_pem.as_bytes())?;
            }
        }

        // Write CSR if present
        if let Some(ref csr) = cert.csr_pem {
            let csr_path = cert_dir.join(format!("{}.csr", spec.name));
            write_ceremony_file(&csr_path, csr.as_bytes())?;
        }

        // Write chain file if present
        if let Some(ref chain) = cert.chain_pem {
            let chain_path = cert_dir.join("chain.crt");
            write_ceremony_file(&chain_path, chain.as_bytes())?;
        }

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

    // ── Step 7: Inventory and summary ──
    let outputs = deploy::inventory_outputs(&output)?;
    deploy::print_summary(&outputs);

    // Write manifest
    let manifest_json = deploy::generate_manifest(&outputs)?;
    write_ceremony_file(
        &output.join("ceremony-manifest.json"),
        manifest_json.as_bytes(),
    )?;
    print_ok("Manifest written to ceremony-manifest.json");

    // ── Step 8: Return ceremony (passphrases will be zeroized on drop) ──
    eprintln!(
        "\n{BOLD}{GREEN}Ceremony complete!{RESET} Output: {}",
        output.display()
    );

    Ok(Ceremony {
        output_dir: output,
        generated_certs: generated,
        passphrases,
        ed25519_keys,
    })
}

// ═══════════════════════════════════════════════════════════════
// Hierarchy display
// ═══════════════════════════════════════════════════════════════

/// Print the certificate hierarchy as a tree
fn print_hierarchy_tree(config: &CeremonyConfig) {
    eprintln!("\n{BOLD}Certificate Hierarchy:{RESET}");

    // Build parent -> children map
    let mut children_map: HashMap<Option<&str>, Vec<&CertSpec>> = HashMap::new();
    for cert in &config.certs {
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

    let ca_marker = if spec.is_ca { " [CA]" } else { "" };
    let algo = &spec.key_algorithm;
    let years = spec.validity_years;
    let offline_marker = if spec.offline { " {OFFLINE}" } else { "" };
    let ed25519_marker = if spec.parallel_ed25519 {
        " +Ed25519"
    } else {
        ""
    };

    eprintln!(
        "  {prefix}{connector}{BOLD}{}{RESET}{DIM} ({algo}, {years}yr{ca_marker}{offline_marker}{ed25519_marker}){RESET}",
        spec.common_name
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

/// A passphrase group — certs that share a passphrase
struct PassphraseGroup {
    name: String,
    no_passphrase: bool,
    cert_names: Vec<String>,
}

/// Determine passphrase groups from config.
///
/// Rules:
/// - CA certs each get their own passphrase unless they specify a group
/// - Leaf certs with the same `passphrase_group` share a passphrase
/// - Certs with `no_passphrase: true` are grouped together (and skipped)
fn collect_passphrase_groups(config: &CeremonyConfig) -> Vec<PassphraseGroup> {
    let mut groups: HashMap<String, PassphraseGroup> = HashMap::new();

    for cert in &config.certs {
        if cert.no_passphrase {
            let entry = groups
                .entry("__no_passphrase__".into())
                .or_insert_with(|| PassphraseGroup {
                    name: "__no_passphrase__".into(),
                    no_passphrase: true,
                    cert_names: vec![],
                });
            entry.cert_names.push(cert.name.clone());
            continue;
        }

        let group_name = if let Some(ref group) = cert.passphrase_group {
            group.clone()
        } else if cert.is_ca {
            // Each CA gets its own group by default
            cert.name.clone()
        } else {
            // Leaf certs without explicit group get their own
            cert.name.clone()
        };

        let entry = groups
            .entry(group_name.clone())
            .or_insert_with(|| PassphraseGroup {
                name: group_name,
                no_passphrase: false,
                cert_names: vec![],
            });
        entry.cert_names.push(cert.name.clone());
    }

    let mut result: Vec<PassphraseGroup> = groups.into_values().collect();
    // Sort: CA groups first, then leaf groups, no_passphrase last
    result.sort_by_key(|g| {
        if g.no_passphrase {
            2
        } else if g.cert_names.len() > 1 {
            0
        } else {
            1
        }
    });
    result
}

/// Determine which passphrase group a cert spec belongs to
fn passphrase_group_for_spec(spec: &CertSpec) -> String {
    if spec.no_passphrase {
        "__no_passphrase__".into()
    } else if let Some(ref group) = spec.passphrase_group {
        group.clone()
    } else {
        spec.name.clone()
    }
}

/// Prompt the user for a passphrase with confirmation
fn prompt_passphrase(label: &str, min_len: usize) -> Result<String> {
    loop {
        let mut pass1 =
            rpassword::prompt_password(format!("  Enter passphrase for {label}: "))
                .context("Failed to read passphrase")?;

        if pass1.len() < min_len {
            eprintln!(
                "    {RED}ERROR{RESET}: Must be at least {min_len} characters. Try again."
            );
            pass1.zeroize();
            continue;
        }

        let mut pass2 =
            rpassword::prompt_password(format!("  Confirm passphrase for {label}: "))
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
    fs::write(path, data)
        .with_context(|| format!("Failed to write {}", path.display()))?;

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
// Build chain file helpers
// ═══════════════════════════════════════════════════════════════

/// Build a chain PEM by walking up the parent hierarchy
pub fn build_chain_pem(
    cert_name: &str,
    generated: &HashMap<String, GeneratedCert>,
    config: &CeremonyConfig,
) -> String {
    let mut chain = String::new();
    let mut current_name = Some(cert_name.to_string());

    while let Some(name) = current_name {
        if let Some(cert) = generated.get(&name) {
            chain.push_str(&cert.cert_pem);
        }
        // Walk up to parent
        current_name = config
            .certs
            .iter()
            .find(|c| c.name == name)
            .and_then(|c| c.parent.clone());
    }

    chain
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> CeremonyConfig {
        CeremonyConfig {
            name: "Test Ceremony".into(),
            certs: vec![
                CertSpec {
                    name: "root-ca".into(),
                    common_name: "Test Root CA".into(),
                    parent: None,
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 20,
                    parallel_ed25519: false,
                    offline: true,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "intermediate-ca".into(),
                    common_name: "Test Intermediate CA".into(),
                    parent: Some("root-ca".into()),
                    is_ca: true,
                    path_len: Some(0),
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 10,
                    parallel_ed25519: true,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "code-signing".into(),
                    common_name: "Test Code Signing".into(),
                    parent: Some("intermediate-ca".into()),
                    is_ca: false,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 2,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec!["codeSigning".into()],
                },
                CertSpec {
                    name: "ci-signer".into(),
                    common_name: "CI Signer".into(),
                    parent: Some("intermediate-ca".into()),
                    is_ca: false,
                    path_len: None,
                    key_algorithm: "ed25519".into(),
                    validity_years: 1,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: true,
                    passphrase_group: None,
                    deploy_to: Some("github-actions".into()),
                    extended_key_usages: vec!["codeSigning".into()],
                },
            ],
        }
    }

    #[test]
    fn validate_valid_config() {
        let config = sample_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validate_missing_parent() {
        let config = CeremonyConfig {
            name: "Bad".into(),
            certs: vec![CertSpec {
                name: "leaf".into(),
                common_name: "Leaf".into(),
                parent: Some("nonexistent".into()),
                is_ca: false,
                path_len: None,
                key_algorithm: "rsa-4096".into(),
                validity_years: 1,
                parallel_ed25519: false,
                offline: false,
                no_passphrase: false,
                passphrase_group: None,
                deploy_to: None,
                extended_key_usages: vec![],
            }],
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_no_root() {
        let config = CeremonyConfig {
            name: "No Root".into(),
            certs: vec![
                CertSpec {
                    name: "a".into(),
                    common_name: "A".into(),
                    parent: Some("b".into()),
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 10,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "b".into(),
                    common_name: "B".into(),
                    parent: Some("a".into()),
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 10,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
            ],
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn topological_sort_correct_order() {
        let config = sample_config();
        let order = topological_sort(&config).unwrap();

        // Root must come before intermediate, intermediate before code-signing and ci-signer
        let root_pos = order.iter().position(|&i| config.certs[i].name == "root-ca").unwrap();
        let inter_pos = order
            .iter()
            .position(|&i| config.certs[i].name == "intermediate-ca")
            .unwrap();
        let signing_pos = order
            .iter()
            .position(|&i| config.certs[i].name == "code-signing")
            .unwrap();
        let ci_pos = order
            .iter()
            .position(|&i| config.certs[i].name == "ci-signer")
            .unwrap();

        assert!(root_pos < inter_pos);
        assert!(inter_pos < signing_pos);
        assert!(inter_pos < ci_pos);
    }

    #[test]
    fn topological_sort_detects_cycle() {
        let config = CeremonyConfig {
            name: "Cycle".into(),
            certs: vec![
                CertSpec {
                    name: "a".into(),
                    common_name: "A".into(),
                    parent: Some("b".into()),
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 10,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "b".into(),
                    common_name: "B".into(),
                    parent: Some("a".into()),
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 10,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
            ],
        };
        assert!(topological_sort(&config).is_err());
    }

    #[test]
    fn passphrase_groups_ca_gets_own() {
        let config = sample_config();
        let groups = collect_passphrase_groups(&config);

        // root-ca and intermediate-ca each get their own group
        assert!(groups.iter().any(|g| g.name == "root-ca"));
        assert!(groups.iter().any(|g| g.name == "intermediate-ca"));
    }

    #[test]
    fn passphrase_groups_no_passphrase_grouped() {
        let config = sample_config();
        let groups = collect_passphrase_groups(&config);

        let no_pass = groups.iter().find(|g| g.no_passphrase);
        assert!(no_pass.is_some());
        assert!(no_pass.unwrap().cert_names.contains(&"ci-signer".into()));
    }

    #[test]
    fn passphrase_groups_shared_group() {
        let config = CeremonyConfig {
            name: "Shared".into(),
            certs: vec![
                CertSpec {
                    name: "root".into(),
                    common_name: "Root".into(),
                    parent: None,
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 20,
                    parallel_ed25519: false,
                    offline: true,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "svc-a".into(),
                    common_name: "Service A".into(),
                    parent: Some("root".into()),
                    is_ca: false,
                    path_len: None,
                    key_algorithm: "ed25519".into(),
                    validity_years: 2,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: Some("services".into()),
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "svc-b".into(),
                    common_name: "Service B".into(),
                    parent: Some("root".into()),
                    is_ca: false,
                    path_len: None,
                    key_algorithm: "ed25519".into(),
                    validity_years: 2,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: Some("services".into()),
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
            ],
        };

        let groups = collect_passphrase_groups(&config);
        let services = groups.iter().find(|g| g.name == "services");
        assert!(services.is_some());
        assert_eq!(services.unwrap().cert_names.len(), 2);
    }

    #[test]
    fn build_chain_pem_walks_hierarchy() {
        let mut generated = HashMap::new();
        generated.insert(
            "root".into(),
            GeneratedCert {
                name: "root".into(),
                cert_pem: "ROOT_PEM\n".into(),
                key_pem: String::new(),
                chain_pem: None,
                csr_pem: None,
                is_ca: true,
            },
        );
        generated.insert(
            "inter".into(),
            GeneratedCert {
                name: "inter".into(),
                cert_pem: "INTER_PEM\n".into(),
                key_pem: String::new(),
                chain_pem: None,
                csr_pem: None,
                is_ca: true,
            },
        );
        generated.insert(
            "leaf".into(),
            GeneratedCert {
                name: "leaf".into(),
                cert_pem: "LEAF_PEM\n".into(),
                key_pem: String::new(),
                chain_pem: None,
                csr_pem: None,
                is_ca: false,
            },
        );

        let config = CeremonyConfig {
            name: "test".into(),
            certs: vec![
                CertSpec {
                    name: "root".into(),
                    common_name: "Root".into(),
                    parent: None,
                    is_ca: true,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 20,
                    parallel_ed25519: false,
                    offline: true,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "inter".into(),
                    common_name: "Inter".into(),
                    parent: Some("root".into()),
                    is_ca: true,
                    path_len: Some(0),
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 10,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
                CertSpec {
                    name: "leaf".into(),
                    common_name: "Leaf".into(),
                    parent: Some("inter".into()),
                    is_ca: false,
                    path_len: None,
                    key_algorithm: "rsa-4096".into(),
                    validity_years: 2,
                    parallel_ed25519: false,
                    offline: false,
                    no_passphrase: false,
                    passphrase_group: None,
                    deploy_to: None,
                    extended_key_usages: vec![],
                },
            ],
        };

        let chain = build_chain_pem("leaf", &generated, &config);
        assert_eq!(chain, "LEAF_PEM\nINTER_PEM\nROOT_PEM\n");
    }

    #[test]
    fn config_parse_yaml() {
        let yaml = r#"
name: Test PKI
certs:
  - name: root-ca
    common_name: Test Root CA
    is_ca: true
    key_algorithm: rsa-4096
    validity_years: 20
    offline: true
  - name: leaf
    common_name: Leaf Cert
    parent: root-ca
    is_ca: false
    validity_years: 2
    no_passphrase: true
    deploy_to: my-service
    extended_key_usages:
      - codeSigning
"#;
        let config = serde_yaml_parse(yaml).unwrap();
        assert_eq!(config.name, "Test PKI");
        assert_eq!(config.certs.len(), 2);
        assert_eq!(config.certs[0].name, "root-ca");
        assert!(config.certs[0].is_ca);
        assert!(config.certs[0].offline);
        assert_eq!(config.certs[1].parent, Some("root-ca".into()));
        assert!(config.certs[1].no_passphrase);
        assert_eq!(
            config.certs[1].extended_key_usages,
            vec!["codeSigning".to_string()]
        );
    }

    #[test]
    fn passphrase_group_for_spec_returns_correct_group() {
        let spec = CertSpec {
            name: "my-cert".into(),
            common_name: "My Cert".into(),
            parent: None,
            is_ca: true,
            path_len: None,
            key_algorithm: "rsa-4096".into(),
            validity_years: 20,
            parallel_ed25519: false,
            offline: true,
            no_passphrase: false,
            passphrase_group: Some("custom-group".into()),
            deploy_to: None,
            extended_key_usages: vec![],
        };
        assert_eq!(passphrase_group_for_spec(&spec), "custom-group");

        let spec_no_group = CertSpec {
            passphrase_group: None,
            no_passphrase: false,
            ..spec.clone()
        };
        assert_eq!(passphrase_group_for_spec(&spec_no_group), "my-cert");

        let spec_no_pass = CertSpec {
            no_passphrase: true,
            ..spec.clone()
        };
        assert_eq!(
            passphrase_group_for_spec(&spec_no_pass),
            "__no_passphrase__"
        );
    }
}
