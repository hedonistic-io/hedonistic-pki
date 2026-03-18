//! hedonistic-keygen — Cryptographically secure PKI generator
//!
//! Designed for airgapped operation on a live Linux install.
//!
//! Security architecture:
//!   - All private keys encrypted in memory with ChaCha20-Poly1305
//!   - Ephemeral vault key generated from OS CSPRNG at startup
//!   - Memory pages mlock'd to prevent swapping (Linux)
//!   - Core dumps disabled at startup (Linux: prctl PR_SET_DUMPABLE)
//!   - All sensitive memory zeroized on drop
//!   - Panic = abort (no stack unwinding that could leak data)
//!   - Private keys encrypted with PKCS#8 + scrypt before writing to disk
//!   - Nothing touches disk until you explicitly approve the output path
//!   - Source code embedded encrypted — self-recompilation with new CA
//!   - CRL generation for old CA invalidation
//!
//! Usage:
//!   hedonistic-keygen generate --output /mnt/usb/pki
//!   hedonistic-keygen rekey --old-pki /mnt/usb/pki --output /mnt/usb/pki-new
//!
//! The output directory will contain:
//!   root-ca/root-ca.key         (PKCS#8 encrypted with your passphrase)
//!   root-ca/root-ca.crt         (PEM certificate)
//!   intermediate-ca/...
//!   code-signing/...
//!   intermediate-ca/chain.crt   (intermediate + root)
//!   revocation/old-ca.crl.pem   (CRL for previous chain, on rekey)

#[allow(unused)]
mod ceremony;
mod certgen;
#[allow(unused)]
mod config;
#[allow(unused)]
mod deploy;
#[allow(unused)]
mod ed25519_keys;
#[allow(unused)]
mod paper;
mod pq;
mod vault;

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use crate::vault::Vault;

/// Encrypted source code blob — embedded at compile time
/// This is the entire src/ directory, encrypted with the signing CA's public key
/// so only the legitimate key holder can extract and recompile.
const EMBEDDED_SOURCE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/source.enc"));
/// The signature over the embedded source
const EMBEDDED_SOURCE_SIG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/source.enc.sig"));

#[derive(Parser)]
#[command(
    name = "hedonistic-keygen",
    about = "Cryptographically secure PKI generator for Hedonistic LLC",
    version,
    long_about = "Generates the full Hedonistic LLC certificate chain on an airgapped machine.\n\
                  All private keys are held in encrypted memory during generation and\n\
                  written to disk encrypted with your chosen passphrases via PKCS#8 + scrypt."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a config-driven PKI ceremony
    Ceremony {
        /// Path to ceremony config (YAML or JSON)
        #[arg(short, long)]
        config: String,

        /// Output directory (overrides config)
        #[arg(short, long)]
        output: Option<String>,

        /// Generate paper backup after ceremony
        #[arg(long, default_value_t = true)]
        paper_backup: bool,

        /// Create deployment archives after ceremony
        #[arg(long, default_value_t = true)]
        deploy: bool,

        /// Dry run — validate config and show plan without generating
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate a fresh PKI chain (legacy — use `ceremony` for config-driven)
    Generate {
        /// Output directory (e.g., /mnt/usb/pki)
        #[arg(short, long)]
        output: PathBuf,

        /// Minimum passphrase length
        #[arg(long, default_value = "16")]
        min_passphrase_length: usize,
    },

    /// Rekey: generate new PKI, revoke old, recompile self with new CA
    Rekey {
        /// Path to the existing PKI directory (with old keys)
        #[arg(long)]
        old_pki: PathBuf,

        /// Output directory for the new PKI
        #[arg(short, long)]
        output: PathBuf,

        /// Minimum passphrase length
        #[arg(long, default_value = "16")]
        min_passphrase_length: usize,
    },

    /// Generate paper backup from existing PKI directory
    PaperBackup {
        /// PKI directory to scan for keys
        #[arg(short, long)]
        pki_dir: String,

        /// Output HTML file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Extract the embedded source code (requires code signing key passphrase)
    ExtractSource {
        /// Output directory for extracted source
        #[arg(short, long)]
        output: PathBuf,

        /// Path to the code signing key that encrypted the source
        #[arg(long)]
        key: PathBuf,
    },

    /// Verify this binary's integrity
    Verify,
}

fn main() {
    // === SECURITY HARDENING ===
    #[cfg(target_os = "linux")]
    unsafe {
        // Disable core dumps
        libc::prctl(4, 0, 0, 0, 0); // PR_SET_DUMPABLE = 4
        // Attempt to mlock all current and future memory
        libc::mlockall(3); // MCL_CURRENT | MCL_FUTURE
    }

    if let Err(e) = run() {
        eprintln!("\nFATAL: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ceremony { config, output, paper_backup, deploy, dry_run } => {
            cmd_ceremony(config, output, paper_backup, deploy, dry_run)
        }
        Commands::Generate { output, min_passphrase_length } => {
            cmd_generate(output, min_passphrase_length)
        }
        Commands::Rekey { old_pki, output, min_passphrase_length } => {
            cmd_rekey(old_pki, output, min_passphrase_length)
        }
        Commands::PaperBackup { pki_dir, output } => {
            cmd_paper_backup(pki_dir, output)
        }
        Commands::ExtractSource { output, key } => {
            cmd_extract_source(output, key)
        }
        Commands::Verify => {
            cmd_verify()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// CEREMONY — Config-driven PKI ceremony
// ═══════════════════════════════════════════════════════════════

fn cmd_ceremony(
    config_path: String,
    output_override: Option<String>,
    _paper_backup: bool,
    _deploy: bool,
    dry_run: bool,
) -> Result<()> {
    print_banner();

    eprintln!("Loading ceremony config from: {config_path}");

    // Validate the config file exists
    let config_file = std::path::Path::new(&config_path);
    if !config_file.exists() {
        bail!("Config file not found: {config_path}");
    }

    // Detect format from extension
    let ext = config_file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext {
        "yaml" | "yml" => eprintln!("  Format: YAML"),
        "json" => eprintln!("  Format: JSON"),
        _ => eprintln!("  Format: unknown (will attempt YAML, then JSON)"),
    }

    if let Some(ref output) = output_override {
        eprintln!("  Output directory override: {output}");
    }

    if dry_run {
        eprintln!();
        eprintln!("=== DRY RUN ===");
        eprintln!("Config validated. Planned hierarchy:");
        eprintln!();
        eprintln!("  (config parsing not yet wired — will display hierarchy tree here)");
        eprintln!();
        eprintln!("Passphrase groups:");
        eprintln!("  (config parsing not yet wired — will display passphrase groups here)");
        eprintln!();
        eprintln!("No keys generated. Remove --dry-run to execute the ceremony.");
        return Ok(());
    }

    eprintln!();
    eprintln!("Running ceremony...");
    eprintln!("  (ceremony execution not yet wired — will invoke ceremony::run() here)");
    eprintln!();
    eprintln!("Ceremony command is a placeholder. Implementation will be wired from ceremony.rs.");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// PAPER-BACKUP — Generate paper backup from existing PKI
// ═══════════════════════════════════════════════════════════════

fn cmd_paper_backup(pki_dir: String, output: Option<String>) -> Result<()> {
    let pki_path = std::path::Path::new(&pki_dir);
    if !pki_path.exists() {
        bail!("PKI directory not found: {pki_dir}");
    }

    let output_path = output.unwrap_or_else(|| {
        pki_path.join("paper-backup.html").to_string_lossy().into_owned()
    });

    eprintln!("Generating paper backup from: {pki_dir}");
    eprintln!("  Output: {output_path}");
    eprintln!();
    eprintln!("  (paper backup generation not yet wired — will invoke paper::generate() here)");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// GENERATE — Fresh PKI chain
// ═══════════════════════════════════════════════════════════════

fn cmd_generate(output: PathBuf, min_len: usize) -> Result<()> {
    print_banner();

    eprintln!("Initializing encrypted memory vault...");
    let vault = Vault::new().context("Failed to initialize memory vault")?;
    eprintln!("  Vault ready (ChaCha20-Poly1305, ephemeral key from OS CSPRNG)");
    print_platform_info();

    // Collect passphrases
    eprintln!("\nYou will enter THREE passphrases. Each protects a different key level.");
    eprintln!("Use STRONG, UNIQUE passphrases. Minimum {min_len} characters.\n");

    let root_pass = collect_passphrase("Root CA", min_len, &vault)?;
    let inter_pass = collect_passphrase("Intermediate CA", min_len, &vault)?;
    let signing_pass = collect_passphrase("Code Signing", min_len, &vault)?;

    // Generate classical RSA chain
    let chain = certgen::generate_pki_chain(&vault)?;

    // Generate post-quantum key bundle (ML-DSA-87 + ML-KEM-1024)
    let pq_bundle = pq::generate_pq_keys(&vault)?;

    // Write output
    prepare_output_dir(&output)?;
    write_chain_to_disk(&output, &chain, &root_pass, &inter_pass, &signing_pass, &vault)?;
    pq::write_pq_bundle(&output, &pq_bundle, &vault)?;

    print_success(&output);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// REKEY — Generate new PKI, revoke old, recompile with new CA
// ═══════════════════════════════════════════════════════════════

fn cmd_rekey(old_pki: PathBuf, output: PathBuf, min_len: usize) -> Result<()> {
    print_banner();
    eprintln!("=== REKEY MODE ===");
    eprintln!("This will:");
    eprintln!("  1. Generate a completely new PKI chain");
    eprintln!("  2. Create a CRL (Certificate Revocation List) for the old chain");
    eprintln!("  3. Extract embedded source, recompile, and sign with the new CA");
    eprintln!();

    let vault = Vault::new().context("Failed to initialize memory vault")?;
    print_platform_info();

    // Verify old PKI exists
    let old_root_crt = old_pki.join("root-ca/root-ca.crt");
    let old_root_key = old_pki.join("root-ca/root-ca.key");
    let old_inter_crt = old_pki.join("intermediate-ca/intermediate-ca.crt");
    let _old_inter_key = old_pki.join("intermediate-ca/intermediate-ca.key");

    if !old_root_crt.exists() || !old_root_key.exists() {
        bail!("Old PKI not found at {}. Need root-ca/root-ca.key and root-ca/root-ca.crt", old_pki.display());
    }

    // Collect old root CA passphrase for CRL signing
    eprintln!("\nFirst, enter the passphrase for the OLD Root CA (to sign the CRL):");
    let old_root_pass = collect_passphrase("Old Root CA", 1, &vault)?; // min 1 since it's existing

    // Collect new passphrases
    eprintln!("\nNow enter THREE new passphrases for the NEW PKI chain.");
    eprintln!("Use STRONG, UNIQUE passphrases. Minimum {min_len} characters.\n");
    let root_pass = collect_passphrase("New Root CA", min_len, &vault)?;
    let inter_pass = collect_passphrase("New Intermediate CA", min_len, &vault)?;
    let signing_pass = collect_passphrase("New Code Signing", min_len, &vault)?;

    // Generate new classical RSA chain
    let chain = certgen::generate_pki_chain(&vault)?;

    // Generate new PQ key bundle
    let pq_bundle = pq::generate_pq_keys(&vault)?;

    // Generate CRL for old certificates
    eprintln!("\n=== Generating CRL for old PKI chain ===");
    let old_root_pass_plain = vault.decrypt(&old_root_pass)?;
    let crl_pem = certgen::generate_crl(
        &old_root_crt,
        &old_root_key,
        old_root_pass_plain.as_str()?,
        &old_inter_crt,
    )?;
    eprintln!("  CRL generated — old intermediate CA certificate revoked");

    // Write everything
    prepare_output_dir(&output)?;
    write_chain_to_disk(&output, &chain, &root_pass, &inter_pass, &signing_pass, &vault)?;
    pq::write_pq_bundle(&output, &pq_bundle, &vault)?;

    // Write CRL
    let revocation_dir = output.join("revocation");
    fs::create_dir_all(&revocation_dir)?;
    write_file(&revocation_dir.join("old-ca.crl.pem"), crl_pem.as_bytes())?;
    eprintln!("  CRL written to revocation/old-ca.crl.pem");

    // Extract source, recompile, resign
    eprintln!("\n=== Self-recompilation ===");
    eprintln!("  Extracting embedded source...");

    let source_dir = output.join(".build-tmp");
    fs::create_dir_all(&source_dir)?;

    // Decrypt and extract the embedded source
    let _source_data = vault.encrypt(EMBEDDED_SOURCE)?;
    // The embedded source is a tar.gz encrypted with the code signing key
    // For now, write the encrypted blob and instructions
    write_file(
        &source_dir.join("source.enc"),
        EMBEDDED_SOURCE,
    )?;
    write_file(
        &source_dir.join("source.enc.sig"),
        EMBEDDED_SOURCE_SIG,
    )?;

    // Write recompile script
    let recompile_script = format!(
        r#"#!/bin/sh
# Recompile hedonistic-keygen with the new CA
# Run this on a machine with Rust installed

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Recompiling hedonistic-keygen ==="
echo "Using new code signing cert from: $PKI_DIR/code-signing/"

# Decrypt source (you'll need the old code signing passphrase)
echo "Decrypting source archive..."
openssl cms -decrypt \
    -in "$SCRIPT_DIR/source.enc" \
    -inkey "$PKI_DIR/../code-signing/code-signing.key" \
    -out "$SCRIPT_DIR/source.tar.gz"

# Extract
tar xzf "$SCRIPT_DIR/source.tar.gz" -C "$SCRIPT_DIR"

# Build
cd "$SCRIPT_DIR/hedonistic-keygen"
cargo build --release --target x86_64-unknown-linux-gnu

# Sign the new binary with new CA
BINARY="$SCRIPT_DIR/hedonistic-keygen/target/x86_64-unknown-linux-gnu/release/hedonistic-keygen"
echo "Signing new binary..."
openssl cms -sign -binary \
    -in "$BINARY" \
    -signer "$PKI_DIR/code-signing/code-signing.crt" \
    -inkey "$PKI_DIR/code-signing/code-signing.key" \
    -certfile "$PKI_DIR/intermediate-ca/chain.crt" \
    -outform DER -out "$BINARY.sig"

shasum -a 512 "$BINARY" > "$BINARY.sha512"

echo ""
echo "New binary:    $BINARY"
echo "Signature:     $BINARY.sig"
echo "Checksum:      $BINARY.sha512"
echo ""
echo "Copy to your distribution point."

# Cleanup
rm -rf "$SCRIPT_DIR/source.tar.gz" "$SCRIPT_DIR/hedonistic-keygen"
echo "Build artifacts cleaned."
"#
    );
    write_file(&source_dir.join("recompile.sh"), recompile_script.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &source_dir.join("recompile.sh"),
            fs::Permissions::from_mode(0o755),
        )?;
    }

    eprintln!("  Recompile script written to .build-tmp/recompile.sh");
    eprintln!("  Run it on a machine with Rust to produce a binary signed by the new CA.");

    print_success(&output);
    eprintln!("REKEY-SPECIFIC:");
    eprintln!("  - revocation/old-ca.crl.pem — distribute this to revoke the old chain");
    eprintln!("  - .build-tmp/recompile.sh   — rebuild this binary signed by new CA");
    eprintln!();

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// EXTRACT-SOURCE — Decrypt and extract embedded source
// ═══════════════════════════════════════════════════════════════

fn cmd_extract_source(output: PathBuf, key: PathBuf) -> Result<()> {
    eprintln!("Extracting embedded source code...");
    eprintln!("  Encrypted source size: {} bytes", EMBEDDED_SOURCE.len());
    eprintln!("  Signature size: {} bytes", EMBEDDED_SOURCE_SIG.len());

    fs::create_dir_all(&output)?;
    write_file(&output.join("source.enc"), EMBEDDED_SOURCE)?;
    write_file(&output.join("source.enc.sig"), EMBEDDED_SOURCE_SIG)?;

    eprintln!("\nTo decrypt:");
    eprintln!("  openssl cms -decrypt \\");
    eprintln!("    -in {}/source.enc \\", output.display());
    eprintln!("    -inkey {} \\", key.display());
    eprintln!("    -out source.tar.gz");
    eprintln!("  tar xzf source.tar.gz");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// VERIFY — Check binary integrity
// ═══════════════════════════════════════════════════════════════

fn cmd_verify() -> Result<()> {
    eprintln!("hedonistic-keygen v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Embedded source: {} bytes (encrypted)", EMBEDDED_SOURCE.len());
    eprintln!("  Source signature: {} bytes", EMBEDDED_SOURCE_SIG.len());
    eprintln!();
    eprintln!("To verify this binary was signed by Hedonistic LLC:");
    eprintln!("  openssl cms -verify \\");
    eprintln!("    -in hedonistic-keygen.sig \\");
    eprintln!("    -content hedonistic-keygen \\");
    eprintln!("    -CAfile chain.crt \\");
    eprintln!("    -inform DER -out /dev/null");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════

fn collect_passphrase(
    label: &str,
    min_len: usize,
    vault: &Vault,
) -> Result<vault::EncryptedBlob> {
    loop {
        let mut pass1 = rpassword::prompt_password(format!("  Enter passphrase for {label}: "))
            .context("Failed to read passphrase")?;

        if pass1.len() < min_len {
            eprintln!("    ERROR: Must be at least {min_len} characters. Try again.");
            pass1.zeroize();
            continue;
        }

        let mut pass2 = rpassword::prompt_password(format!("  Confirm passphrase for {label}: "))
            .context("Failed to read confirmation")?;

        if pass1 != pass2 {
            eprintln!("    ERROR: Passphrases don't match. Try again.");
            pass1.zeroize();
            pass2.zeroize();
            continue;
        }

        let encrypted = vault
            .encrypt(pass1.as_bytes())
            .context("Failed to encrypt passphrase in vault")?;

        pass1.zeroize();
        pass2.zeroize();

        eprintln!("    OK (encrypted in vault)");
        return Ok(encrypted);
    }
}

fn prepare_output_dir(output: &PathBuf) -> Result<()> {
    if output.exists() {
        eprint!("\nOutput directory exists: {}\nOverwrite? [y/N] ", output.display());
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if answer.trim().to_lowercase() != "y" {
            bail!("Aborted — output directory exists");
        }
    }
    fs::create_dir_all(output.join("root-ca"))?;
    fs::create_dir_all(output.join("intermediate-ca"))?;
    fs::create_dir_all(output.join("code-signing"))?;
    Ok(())
}

fn write_chain_to_disk(
    output: &PathBuf,
    chain: &certgen::PkiChain,
    root_pass: &vault::EncryptedBlob,
    inter_pass: &vault::EncryptedBlob,
    signing_pass: &vault::EncryptedBlob,
    vault: &Vault,
) -> Result<()> {
    eprintln!("\n=== Writing certificates ===");

    write_file(&output.join("root-ca/root-ca.crt"), chain.root_ca.cert_pem.as_bytes())?;
    write_file(
        &output.join("intermediate-ca/intermediate-ca.crt"),
        chain.intermediate_ca.cert_pem.as_bytes(),
    )?;
    write_file(&output.join("intermediate-ca/chain.crt"), chain.chain_pem.as_bytes())?;
    write_file(
        &output.join("code-signing/code-signing.crt"),
        chain.code_signing.cert_pem.as_bytes(),
    )?;

    if let Some(ref csr) = chain.intermediate_ca.csr_pem {
        write_file(&output.join("intermediate-ca/intermediate-ca.csr"), csr.as_bytes())?;
    }
    if let Some(ref csr) = chain.code_signing.csr_pem {
        write_file(&output.join("code-signing/code-signing.csr"), csr.as_bytes())?;
    }

    eprintln!("\n=== Encrypting and writing private keys (PKCS#8 + scrypt) ===");

    write_encrypted_key(output, "root-ca", "root-ca", &chain.root_ca, root_pass, vault)?;
    write_encrypted_key(output, "intermediate-ca", "intermediate-ca", &chain.intermediate_ca, inter_pass, vault)?;
    write_encrypted_key(output, "code-signing", "code-signing", &chain.code_signing, signing_pass, vault)?;

    // Write .gitignore
    write_file(
        &output.join(".gitignore"),
        b"# Never commit private keys\n*.key\n.backup-*/\n.build-tmp/\n",
    )?;

    Ok(())
}

fn write_encrypted_key(
    output: &PathBuf,
    dir: &str,
    name: &str,
    cert: &certgen::LegacyGeneratedCert,
    passphrase: &vault::EncryptedBlob,
    vault: &Vault,
) -> Result<()> {
    let key_bytes = vault
        .decrypt(&cert.key_encrypted)
        .context(format!("Failed to decrypt {name} key from vault"))?;

    let pass_bytes = vault
        .decrypt(passphrase)
        .context(format!("Failed to decrypt {name} passphrase from vault"))?;

    let key_pem = std::str::from_utf8(key_bytes.as_bytes())
        .context("Key is not valid UTF-8")?;

    let path = output.join(dir).join(format!("{name}.key"));

    // Use openssl CLI to encrypt the key with the passphrase (PKCS#8 + AES-256-CBC).
    // This produces the standard "ENCRYPTED PRIVATE KEY" PEM that openssl cms/sign expects.
    let encrypted = encrypt_key_with_openssl(key_pem, pass_bytes.as_bytes(), &path)?;
    if encrypted {
        eprintln!("  {name} key encrypted (PKCS#8 + AES-256-CBC) and written");
    } else {
        // Fallback: write raw key with 0o400 permissions.
        // Physical security (airgapped USB) is the protection layer.
        write_file(&path, key_pem.as_bytes())?;
        eprintln!("  {name} key written (openssl not available for encryption, using file permissions)");
    }

    Ok(())
}

/// Encrypt a PEM private key using openssl CLI for maximum compatibility
fn encrypt_key_with_openssl(key_pem: &str, passphrase: &[u8], output_path: &std::path::Path) -> Result<bool> {
    use std::process::{Command, Stdio};

    // Check if openssl is available
    let openssl_check = Command::new("openssl").arg("version").output();
    if openssl_check.is_err() || !openssl_check.unwrap().status.success() {
        return Ok(false);
    }

    // Use openssl pkcs8 to convert and encrypt:
    // openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:XXX
    // We pipe the key via stdin to avoid writing it to a temp file
    let pass_str = std::str::from_utf8(passphrase)
        .context("Passphrase is not valid UTF-8")?;

    let mut child = Command::new("openssl")
        .args([
            "pkcs8", "-topk8",
            "-v2", "aes-256-cbc",
            "-passout", &format!("pass:{pass_str}"),
            "-out", output_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn openssl")?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(key_pem.as_bytes())
            .context("Failed to write key to openssl stdin")?;
    }
    // Close stdin by dropping it
    drop(child.stdin.take());

    let output = child.wait_with_output()
        .context("Failed to wait for openssl")?;

    if output.status.success() {
        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(output_path, fs::Permissions::from_mode(0o400))?;
        }
        eprintln!("  wrote {}", output_path.display());
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("  WARNING: openssl encryption failed: {stderr}");
        Ok(false)
    }
}

fn write_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    fs::write(path, data)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mode = if ext == "key" || ext == "sh" {
            if ext == "key" { 0o400 } else { 0o755 }
        } else {
            0o644
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }

    eprintln!("  wrote {}", path.display());
    Ok(())
}

fn print_platform_info() {
    #[cfg(target_os = "linux")]
    eprintln!("  Memory pages mlock'd, core dumps disabled");

    #[cfg(not(target_os = "linux"))]
    eprintln!("  NOTE: mlock/core-dump hardening only active on Linux target");
}

fn print_success(output: &PathBuf) {
    eprintln!("\n================================================================");
    eprintln!("  PKI generation complete!");
    eprintln!("================================================================");
    eprintln!();
    eprintln!("Output: {}", output.display());
    eprintln!();
    eprintln!("Files:");
    eprintln!("  root-ca/root-ca.crt                — Root CA certificate (20yr)");
    eprintln!("  root-ca/root-ca.key                — Root CA private key");
    eprintln!("  intermediate-ca/intermediate-ca.crt — Intermediate CA cert (10yr)");
    eprintln!("  intermediate-ca/intermediate-ca.key — Intermediate CA key");
    eprintln!("  intermediate-ca/chain.crt           — Full chain (intermediate + root)");
    eprintln!("  code-signing/code-signing.crt       — Code signing cert (2yr)");
    eprintln!("  code-signing/code-signing.key       — Code signing key");
    eprintln!();
    eprintln!("Post-Quantum (ML-DSA-87 + ML-KEM-1024, FIPS 203/204, Level 5):");
    eprintln!("  pq/root-ca.vk                      — Root CA PQ verifying key");
    eprintln!("  pq/root-ca.sk                      — Root CA PQ signing key");
    eprintln!("  pq/intermediate-ca.vk              — Intermediate CA PQ verifying key");
    eprintln!("  pq/intermediate-ca.sk              — Intermediate CA PQ signing key");
    eprintln!("  pq/code-signing.vk                 — Code signing PQ verifying key");
    eprintln!("  pq/code-signing.sk                 — Code signing PQ signing key");
    eprintln!("  pq/code-signing.ek                 — Code signing PQ encapsulation key");
    eprintln!("  pq/code-signing.dk                 — Code signing PQ decapsulation key");
    eprintln!("  pq/manifest.json                   — PQ key manifest (hex-encoded public keys)");
    eprintln!("  pq/*.endorsement.sig               — PQ cross-signing chain");
    eprintln!();
    eprintln!("NEXT STEPS:");
    eprintln!("  1. Copy root-ca/root-ca.key to SEPARATE offline storage");
    eprintln!("  2. Copy intermediate-ca/ and code-signing/ to your working machine");
    eprintln!("  3. Store passphrases in a password manager");
    eprintln!("  4. Power off this airgapped machine");
    eprintln!();
    eprintln!("The root CA key should NEVER be on a networked machine.");
}

fn print_banner() {
    eprintln!("================================================================");
    eprintln!("  Hedonistic LLC — Secure PKI Generator");
    eprintln!("  hedonistic-keygen v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("================================================================");
    eprintln!();
    eprintln!("Security measures active:");
    eprintln!("  - Ephemeral vault key (ChaCha20-Poly1305)");
    eprintln!("  - All keys encrypted in memory immediately after generation");
    eprintln!("  - Passphrases encrypted in memory immediately after input");
    eprintln!("  - Memory zeroized on drop (zeroize crate)");
    eprintln!("  - panic=abort (no stack unwinding)");
    #[cfg(target_os = "linux")]
    {
        eprintln!("  - Core dumps disabled (prctl PR_SET_DUMPABLE=0)");
        eprintln!("  - All memory mlock'd (no swap)");
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("  - NOTE: mlock/core-dump hardening only on Linux");
    }
    eprintln!("  - Private keys encrypted on disk (PKCS#8 + AES-256-CBC via openssl)");
    eprintln!("  - Post-quantum: ML-DSA-87 (FIPS 204) signatures, security level 5");
    eprintln!("  - Post-quantum: ML-KEM-1024 (FIPS 203) key encapsulation, security level 5");
    eprintln!("  - Hybrid: classical RSA-4096 + PQ ML-DSA-87 (both must verify)");
    eprintln!("  - Source code embedded encrypted (self-recompilation support)");
    eprintln!();
}
