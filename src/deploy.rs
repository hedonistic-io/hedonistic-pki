//! Deployment package generator for ceremony outputs.
//!
//! After a PKI ceremony completes, this module:
//!   - Classifies every generated file (Public / Deploy / Offline / Transient)
//!   - Computes SHA-256 checksums
//!   - Generates a JSON manifest
//!   - Creates per-classification tar.gz deployment archives
//!   - Prints a summary table

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Classification of a generated file
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileClass {
    /// Public certificate — safe to commit to git
    Public,
    /// Private key for deployment to a service — goes to secrets manager
    Deploy,
    /// Offline key — move to USB, delete from machine
    Offline,
    /// Generated artifact (CSR, serial, index) — transient
    Transient,
}

impl FileClass {
    pub fn label(&self) -> &'static str {
        match self {
            FileClass::Public => "PUBLIC",
            FileClass::Deploy => "DEPLOY",
            FileClass::Offline => "OFFLINE",
            FileClass::Transient => "TRANSIENT",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            FileClass::Public => "\x1b[32m",    // green
            FileClass::Deploy => "\x1b[33m",    // yellow
            FileClass::Offline => "\x1b[31m",   // red
            FileClass::Transient => "\x1b[90m", // dim
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            FileClass::Public => "Safe to commit to git / distribute",
            FileClass::Deploy => "Send to secrets manager for service deployment",
            FileClass::Offline => "Move to offline USB, delete from this machine",
            FileClass::Transient => "Intermediate artifact — safe to delete",
        }
    }
}

impl std::fmt::Display for FileClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A file produced by the ceremony
#[derive(Debug)]
pub struct CeremonyOutput {
    pub path: PathBuf,
    pub class: FileClass,
    pub description: String,
    pub sha256: String,
}

// ═══════════════════════════════════════════════════════════════
// Classification
// ═══════════════════════════════════════════════════════════════

/// Classify a file based on its extension and context flags.
///
/// - `is_ca`: true if this file belongs to a CA (root or intermediate)
/// - `is_offline`: true if the cert spec has `offline: true`
/// - `no_passphrase`: true if the cert spec has `no_passphrase: true` (CI signers)
pub fn classify_file(path: &Path, is_ca: bool, is_offline: bool, no_passphrase: bool) -> FileClass {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");

    match ext {
        // Certificates and public keys are always public
        "crt" | "pub" => FileClass::Public,

        // Key files need context-dependent classification
        "key" => {
            if filename.contains("ed25519") {
                // Ed25519 deploy keys
                if no_passphrase {
                    FileClass::Deploy
                } else if is_offline {
                    FileClass::Offline
                } else {
                    FileClass::Deploy
                }
            } else {
                // RSA keys
                if is_offline || is_ca {
                    FileClass::Offline
                } else if no_passphrase {
                    FileClass::Deploy
                } else {
                    FileClass::Deploy
                }
            }
        }

        // CSRs and bookkeeping files are transient
        "csr" | "txt" => FileClass::Transient,

        // Post-quantum signing/decapsulation keys
        "sk" | "dk" => {
            if is_offline || is_ca {
                FileClass::Offline
            } else {
                FileClass::Deploy
            }
        }

        // Post-quantum verification/encapsulation keys are public
        "vk" | "ek" => FileClass::Public,

        // Signature files are public
        "sig" => FileClass::Public,

        // JSON manifests are public
        "json" => FileClass::Public,

        // Chain files
        _ => {
            if filename == "chain.crt" {
                FileClass::Public
            } else if filename == "serial" || filename == "index.txt" || filename == "crlnumber" {
                FileClass::Transient
            } else {
                // Default: treat unknown as transient (safe side)
                FileClass::Transient
            }
        }
    }
}

/// Compute SHA-256 of a file's contents and return hex-encoded digest
fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path)
        .with_context(|| format!("Failed to read {} for checksum", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Describe a file based on its name and location
fn describe_file(path: &Path) -> String {
    let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("unknown");
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "crt" => {
            if filename == "chain.crt" {
                format!("{parent} certificate chain")
            } else {
                format!("{parent} certificate")
            }
        }
        "key" => {
            if filename.contains("ed25519") {
                format!("{parent} Ed25519 private key")
            } else {
                format!("{parent} RSA private key (encrypted)")
            }
        }
        "pub" => format!("{parent} public key"),
        "csr" => format!("{parent} certificate signing request"),
        "vk" => format!("{parent} post-quantum verifying key"),
        "sk" => format!("{parent} post-quantum signing key"),
        "ek" => format!("{parent} post-quantum encapsulation key"),
        "dk" => format!("{parent} post-quantum decapsulation key"),
        "sig" => format!("{parent} signature"),
        "json" => format!("{parent} manifest"),
        _ => format!("{parent}/{filename}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// Inventory
// ═══════════════════════════════════════════════════════════════

/// Scan a ceremony output directory and classify all files.
///
/// Uses heuristics based on directory names to infer `is_ca` and `is_offline`
/// context, since the raw directory scan doesn't have access to the config.
pub fn inventory_outputs(pki_dir: &Path) -> Result<Vec<CeremonyOutput>> {
    let mut outputs = Vec::new();
    inventory_recursive(pki_dir, pki_dir, &mut outputs)?;
    // Sort by classification (offline first, then deploy, then public, then transient)
    outputs.sort_by_key(|o| match o.class {
        FileClass::Offline => 0,
        FileClass::Deploy => 1,
        FileClass::Public => 2,
        FileClass::Transient => 3,
    });
    Ok(outputs)
}

fn inventory_recursive(
    base_dir: &Path,
    current: &Path,
    outputs: &mut Vec<CeremonyOutput>,
) -> Result<()> {
    let entries = fs::read_dir(current)
        .with_context(|| format!("Failed to read directory {}", current.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip hidden directories (.build-tmp, .backup, etc.)
            let dirname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if dirname.starts_with('.') {
                continue;
            }
            inventory_recursive(base_dir, &path, outputs)?;
        } else {
            // Skip .gitignore and other dotfiles
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if filename.starts_with('.') {
                continue;
            }

            // Infer context from parent directory name
            let parent_name = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("");

            let is_ca = parent_name.contains("root") || parent_name.contains("intermediate");
            let is_offline = parent_name.contains("root");
            let no_passphrase = false; // Conservative default from directory scan

            let class = classify_file(&path, is_ca, is_offline, no_passphrase);
            let sha256 = sha256_file(&path)?;
            let description = describe_file(&path);

            outputs.push(CeremonyOutput {
                path,
                class,
                description,
                sha256,
            });
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Manifest
// ═══════════════════════════════════════════════════════════════

/// Generate a deployment manifest (JSON) listing all files and their classifications
pub fn generate_manifest(outputs: &[CeremonyOutput]) -> Result<String> {
    let entries: Vec<serde_json::Value> = outputs
        .iter()
        .map(|o| {
            serde_json::json!({
                "path": o.path.display().to_string(),
                "class": o.class.label(),
                "description": o.description,
                "sha256": o.sha256,
            })
        })
        .collect();

    let manifest = serde_json::json!({
        "version": 1,
        "generator": format!("hedonistic-pki v{}", env!("CARGO_PKG_VERSION")),
        "generated_at": chrono_now_iso8601(),
        "files": entries,
        "summary": {
            "public": outputs.iter().filter(|o| o.class == FileClass::Public).count(),
            "deploy": outputs.iter().filter(|o| o.class == FileClass::Deploy).count(),
            "offline": outputs.iter().filter(|o| o.class == FileClass::Offline).count(),
            "transient": outputs.iter().filter(|o| o.class == FileClass::Transient).count(),
            "total": outputs.len(),
        }
    });

    serde_json::to_string_pretty(&manifest).context("Failed to serialize manifest")
}

/// Simple ISO-8601 timestamp without pulling in chrono
fn chrono_now_iso8601() -> String {
    // Use the `time` crate already in dependencies
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

// ═══════════════════════════════════════════════════════════════
// Archive creation
// ═══════════════════════════════════════════════════════════════

/// Create a tar.gz archive of files matching a classification.
///
/// Files are stored with paths relative to their common base directory.
pub fn create_deployment_archive(
    outputs: &[CeremonyOutput],
    class: FileClass,
    archive_path: &Path,
) -> Result<()> {
    let matching: Vec<&CeremonyOutput> = outputs
        .iter()
        .filter(|o| o.class == class)
        .collect();

    if matching.is_empty() {
        anyhow::bail!("No files with classification {} to archive", class.label());
    }

    // Find the common base directory
    let base_dir = find_common_base(&matching)?;

    let file = fs::File::create(archive_path)
        .with_context(|| format!("Failed to create archive {}", archive_path.display()))?;
    let enc = GzEncoder::new(file, Compression::best());
    let mut tar = tar::Builder::new(enc);

    for output in &matching {
        let relative = output
            .path
            .strip_prefix(&base_dir)
            .unwrap_or(&output.path);
        tar.append_path_with_name(&output.path, relative)
            .with_context(|| {
                format!("Failed to add {} to archive", output.path.display())
            })?;
    }

    tar.into_inner()
        .context("Failed to finish gzip stream")?
        .finish()
        .context("Failed to finalize gzip")?;

    Ok(())
}

/// Find the common ancestor directory of all outputs
fn find_common_base(outputs: &[&CeremonyOutput]) -> Result<PathBuf> {
    if outputs.is_empty() {
        anyhow::bail!("Cannot find common base of empty file list");
    }

    let first = outputs[0]
        .path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    let mut common = first;
    for output in &outputs[1..] {
        let parent = output
            .path
            .parent()
            .unwrap_or(Path::new("."));
        while !parent.starts_with(&common) {
            if !common.pop() {
                return Ok(PathBuf::from("."));
            }
        }
    }

    Ok(common)
}

// ═══════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════

/// Print a summary table of all outputs grouped by classification
pub fn print_summary(outputs: &[CeremonyOutput]) {
    const RESET: &str = "\x1b[0m";
    const BOLD: &str = "\x1b[1m";

    // Group by classification
    let mut grouped: HashMap<FileClass, Vec<&CeremonyOutput>> = HashMap::new();
    for output in outputs {
        grouped.entry(output.class).or_default().push(output);
    }

    eprintln!("\n{BOLD}═══════════════════════════════════════════════════════════════{RESET}");
    eprintln!("{BOLD}  Ceremony Output Summary{RESET}");
    eprintln!("{BOLD}═══════════════════════════════════════════════════════════════{RESET}");

    // Print in priority order
    for class in [
        FileClass::Offline,
        FileClass::Deploy,
        FileClass::Public,
        FileClass::Transient,
    ] {
        if let Some(files) = grouped.get(&class) {
            let color = class.color_code();
            eprintln!(
                "\n  {color}{BOLD}[{}]{RESET} — {}",
                class.label(),
                class.description()
            );
            for file in files {
                let filename = file
                    .path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("?");
                let parent = file
                    .path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|p| p.to_str())
                    .unwrap_or("");
                eprintln!(
                    "    {color}{parent}/{filename}{RESET}  sha256:{:.16}…",
                    file.sha256
                );
            }
        }
    }

    // Counts
    eprintln!("\n  Totals:");
    for class in [
        FileClass::Offline,
        FileClass::Deploy,
        FileClass::Public,
        FileClass::Transient,
    ] {
        let count = grouped.get(&class).map_or(0, |v| v.len());
        if count > 0 {
            let color = class.color_code();
            eprintln!("    {color}{:>3} {}{RESET}", count, class.label());
        }
    }
    eprintln!("    {:>3} TOTAL", outputs.len());
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── Classification tests ──

    #[test]
    fn classify_crt_is_public() {
        let path = Path::new("root-ca/root-ca.crt");
        assert_eq!(classify_file(path, true, true, false), FileClass::Public);
    }

    #[test]
    fn classify_chain_crt_is_public() {
        let path = Path::new("intermediate-ca/chain.crt");
        assert_eq!(classify_file(path, true, false, false), FileClass::Public);
    }

    #[test]
    fn classify_pub_is_public() {
        let path = Path::new("code-signing/signing.pub");
        assert_eq!(classify_file(path, false, false, false), FileClass::Public);
    }

    #[test]
    fn classify_ca_rsa_key_is_offline() {
        let path = Path::new("root-ca/root-ca.key");
        assert_eq!(classify_file(path, true, true, false), FileClass::Offline);
    }

    #[test]
    fn classify_intermediate_ca_key_is_offline() {
        let path = Path::new("intermediate-ca/intermediate-ca.key");
        assert_eq!(
            classify_file(path, true, false, false),
            FileClass::Offline
        );
    }

    #[test]
    fn classify_leaf_rsa_key_no_passphrase_is_deploy() {
        let path = Path::new("ci-signer/ci-signer.key");
        assert_eq!(classify_file(path, false, false, true), FileClass::Deploy);
    }

    #[test]
    fn classify_leaf_rsa_key_with_passphrase_is_deploy() {
        let path = Path::new("code-signing/code-signing.key");
        assert_eq!(classify_file(path, false, false, false), FileClass::Deploy);
    }

    #[test]
    fn classify_ed25519_key_is_deploy() {
        let path = Path::new("services/partitura.ed25519.key");
        assert_eq!(classify_file(path, false, false, false), FileClass::Deploy);
    }

    #[test]
    fn classify_ed25519_key_offline_is_offline() {
        let path = Path::new("root-ca/root.ed25519.key");
        assert_eq!(classify_file(path, false, true, false), FileClass::Offline);
    }

    #[test]
    fn classify_csr_is_transient() {
        let path = Path::new("intermediate-ca/intermediate-ca.csr");
        assert_eq!(
            classify_file(path, true, false, false),
            FileClass::Transient
        );
    }

    #[test]
    fn classify_serial_is_transient() {
        let path = Path::new("ca-db/serial");
        // No extension — falls through to filename match
        assert_eq!(
            classify_file(path, false, false, false),
            FileClass::Transient
        );
    }

    #[test]
    fn classify_index_txt_is_transient() {
        let path = Path::new("ca-db/index.txt");
        assert_eq!(
            classify_file(path, false, false, false),
            FileClass::Transient
        );
    }

    #[test]
    fn classify_vk_is_public() {
        let path = Path::new("pq/root-ca.vk");
        assert_eq!(classify_file(path, true, true, false), FileClass::Public);
    }

    #[test]
    fn classify_sk_ca_is_offline() {
        let path = Path::new("pq/root-ca.sk");
        assert_eq!(classify_file(path, true, true, false), FileClass::Offline);
    }

    #[test]
    fn classify_sk_leaf_is_deploy() {
        let path = Path::new("pq/code-signing.sk");
        assert_eq!(classify_file(path, false, false, false), FileClass::Deploy);
    }

    #[test]
    fn classify_sig_is_public() {
        let path = Path::new("pq/root-ca.endorsement.sig");
        assert_eq!(classify_file(path, false, false, false), FileClass::Public);
    }

    #[test]
    fn classify_json_is_public() {
        let path = Path::new("pq/manifest.json");
        assert_eq!(classify_file(path, false, false, false), FileClass::Public);
    }

    // ── Manifest tests ──

    #[test]
    fn manifest_generates_valid_json() {
        let outputs = vec![
            CeremonyOutput {
                path: PathBuf::from("root-ca/root-ca.crt"),
                class: FileClass::Public,
                description: "Root CA certificate".into(),
                sha256: "abcd1234".into(),
            },
            CeremonyOutput {
                path: PathBuf::from("root-ca/root-ca.key"),
                class: FileClass::Offline,
                description: "Root CA private key".into(),
                sha256: "ef567890".into(),
            },
        ];

        let json = generate_manifest(&outputs).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["files"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["summary"]["public"], 1);
        assert_eq!(parsed["summary"]["offline"], 1);
        assert_eq!(parsed["summary"]["total"], 2);
    }

    #[test]
    fn manifest_empty_outputs() {
        let outputs: Vec<CeremonyOutput> = vec![];
        let json = generate_manifest(&outputs).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["summary"]["total"], 0);
        assert!(parsed["files"].as_array().unwrap().is_empty());
    }

    // ── Archive tests ──

    #[test]
    fn archive_creates_valid_targz() {
        let tmp = tempdir();

        // Create some test files
        let pub_dir = tmp.join("certs");
        fs::create_dir_all(&pub_dir).unwrap();
        fs::write(pub_dir.join("root.crt"), b"CERT DATA").unwrap();
        fs::write(pub_dir.join("inter.crt"), b"INTER CERT").unwrap();

        let outputs = vec![
            CeremonyOutput {
                path: pub_dir.join("root.crt"),
                class: FileClass::Public,
                description: "Root cert".into(),
                sha256: "aaa".into(),
            },
            CeremonyOutput {
                path: pub_dir.join("inter.crt"),
                class: FileClass::Public,
                description: "Intermediate cert".into(),
                sha256: "bbb".into(),
            },
        ];

        let archive_path = tmp.join("public.tar.gz");
        create_deployment_archive(&outputs, FileClass::Public, &archive_path).unwrap();

        // Verify the archive exists and is non-empty
        let metadata = fs::metadata(&archive_path).unwrap();
        assert!(metadata.len() > 0);

        // Verify we can decompress and read it
        let file = fs::File::open(&archive_path).unwrap();
        let dec = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(dec);

        let entries: Vec<_> = archive.entries().unwrap().collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn archive_empty_class_errors() {
        let outputs = vec![CeremonyOutput {
            path: PathBuf::from("root-ca/root-ca.crt"),
            class: FileClass::Public,
            description: "Root cert".into(),
            sha256: "aaa".into(),
        }];

        // Trying to archive Deploy when there are none
        let result = create_deployment_archive(
            &outputs,
            FileClass::Deploy,
            Path::new("/tmp/empty.tar.gz"),
        );
        assert!(result.is_err());
    }

    // ── Inventory tests ──

    #[test]
    fn inventory_scans_directory() {
        let tmp = tempdir();

        // Create a realistic directory structure
        let root_dir = tmp.join("root-ca");
        let inter_dir = tmp.join("intermediate-ca");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(&inter_dir).unwrap();

        fs::write(root_dir.join("root-ca.crt"), b"ROOT CERT").unwrap();
        fs::write(root_dir.join("root-ca.key"), b"ROOT KEY").unwrap();
        fs::write(inter_dir.join("intermediate-ca.crt"), b"INTER CERT").unwrap();
        fs::write(inter_dir.join("chain.crt"), b"CHAIN").unwrap();

        let outputs = inventory_outputs(&tmp).unwrap();
        assert_eq!(outputs.len(), 4);

        // root-ca.key should be offline (root CA)
        let root_key = outputs.iter().find(|o| {
            o.path
                .file_name()
                .and_then(|f| f.to_str())
                == Some("root-ca.key")
        });
        assert!(root_key.is_some());
        assert_eq!(root_key.unwrap().class, FileClass::Offline);

        // root-ca.crt should be public
        let root_crt = outputs.iter().find(|o| {
            o.path
                .file_name()
                .and_then(|f| f.to_str())
                == Some("root-ca.crt")
        });
        assert!(root_crt.is_some());
        assert_eq!(root_crt.unwrap().class, FileClass::Public);
    }

    #[test]
    fn inventory_skips_dotfiles() {
        let tmp = tempdir();
        fs::write(tmp.join(".gitignore"), b"*.key").unwrap();
        fs::write(tmp.join("root.crt"), b"CERT").unwrap();

        let outputs = inventory_outputs(&tmp).unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0]
            .path
            .file_name()
            .and_then(|f| f.to_str())
            == Some("root.crt"));
    }

    // ── SHA-256 tests ──

    #[test]
    fn sha256_computes_correct_hash() {
        let tmp = tempdir();
        let path = tmp.join("test.bin");
        fs::write(&path, b"hello world").unwrap();

        let hash = sha256_file(&path).unwrap();
        // Known SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // ── Test helper ──

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hedonistic-pki-test-deploy-{}",
            std::process::id()
        ));
        // Clean up from previous runs
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
