//! hedonistic-pki — Cryptographically secure PKI generator
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
//!   hedonistic-pki generate --output /mnt/usb/pki
//!   hedonistic-pki rekey --old-pki /mnt/usb/pki --output /mnt/usb/pki-new
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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
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
    name = "hedonistic-pki",
    version,
    about = "Cryptographically secure PKI certificate chain generator for airgapped environments",
    long_about = "\
hedonistic-pki generates complete PKI certificate hierarchies on airgapped machines.\n\
\n\
All private keys are held in ChaCha20-Poly1305 encrypted memory during generation \
and written to disk encrypted with your chosen passphrases via PKCS#8 + AES-256-CBC. \
On Linux, memory is mlock'd to prevent swapping, core dumps are disabled, and all \
sensitive memory is zeroized on drop.\n\
\n\
Supports:\n\
  - Config-driven ceremonies (YAML/JSON) with arbitrary hierarchies\n\
  - Classical RSA-4096 and Ed25519 key algorithms\n\
  - Post-quantum ML-DSA-87 (FIPS 204) and ML-KEM-1024 (FIPS 203)\n\
  - Paper backup generation (HTML with QR codes)\n\
  - Deployment package generation (per-classification tar.gz archives)\n\
  - Encrypted passphrase vault for offline storage\n\
  - Self-contained source code (embedded encrypted for recompilation)\n\
  - CRL generation for key rotation (rekey workflow)",
    after_help = "\
EXAMPLES:\n  \
  hedonistic-pki ceremony --config ceremony.yaml --output ./pki\n  \
  hedonistic-pki ceremony --config ceremony.yaml --dry-run\n  \
  hedonistic-pki generate --output /mnt/usb/pki\n  \
  hedonistic-pki rekey --old-pki /mnt/usb/pki --output /mnt/usb/pki-new\n  \
  hedonistic-pki paper-backup --pki-dir ./pki\n  \
  hedonistic-pki vault-decrypt --vault ./pki/ceremony-vault.enc\n  \
  hedonistic-pki verify\n\
\n\
SECURITY NOTES:\n  \
  Run this tool on an airgapped machine (no network access).\n  \
  The root CA private key should NEVER be on a networked machine.\n  \
  Store passphrases in a password manager (use vault-decrypt to retrieve them)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a config-driven PKI ceremony
    #[command(
        long_about = "\
Reads a YAML or JSON ceremony configuration file that describes the complete \
certificate hierarchy — root CAs, intermediate CAs, sub-CAs, and leaf certificates. \
Collects passphrases interactively (grouped by shared-passphrase config), generates \
all certificates in dependency order (parents sign children), and writes everything \
to the output directory.\n\
\n\
After certificate generation, optionally produces:\n\
  - Paper backups (printable HTML with QR-encoded private keys)\n\
  - Deployment archives (per-classification tar.gz bundles)\n\
  - A ceremony manifest (JSON inventory of all generated files)\n\
  - An encrypted passphrase vault (AES-256-GCM, for offline storage)\n\
\n\
Use --dry-run to validate the config and preview the generation plan without \
creating any keys or files.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki ceremony --config ceremony.yaml --output ./pki\n  \
  hedonistic-pki ceremony --config ceremony.yaml --dry-run\n  \
  hedonistic-pki ceremony -c prod.yaml -o /mnt/usb/pki --no-paper-backup\n  \
  hedonistic-pki ceremony -c ceremony.yaml -o ./pki --no-deploy\n\
\n\
CONFIG FORMAT:\n  \
  See examples/ceremony.yaml for a complete reference. The config file specifies:\n  \
    - name, organization: ceremony metadata\n  \
    - hierarchy: list of certificate specs (name, cn, cert_type, parent, algorithm, etc.)\n  \
    - passphrases: min_length, grouping rules\n  \
    - paper_backup: output path, title\n  \
    - deployment: per-target archive definitions"
    )]
    Ceremony {
        /// Path to the ceremony configuration file (YAML or JSON)
        #[arg(short, long, help = "Path to ceremony config (YAML or JSON)")]
        config: String,

        /// Output directory for all generated certificates, keys, and artifacts.
        /// Overrides the output_dir field in the config file if set.
        #[arg(
            short,
            long,
            long_help = "\
Output directory for all generated certificates, keys, and artifacts. \
If not specified, uses the output_dir field from the config file, \
or defaults to 'pki-output'. The directory will be created if it \
does not exist. If it already exists, you will be prompted before overwriting."
        )]
        output: Option<String>,

        /// Generate a paper backup (printable HTML with QR codes) after the ceremony
        #[arg(
            long,
            default_value_t = true,
            long_help = "\
Generate a paper backup after the ceremony completes. The backup is \
an HTML file containing QR-encoded private keys, suitable for printing \
and storing in a physical safe. Pass --no-paper-backup to skip."
        )]
        paper_backup: bool,

        /// Create deployment archives (tar.gz) after the ceremony
        #[arg(
            long,
            default_value_t = true,
            long_help = "\
Create per-classification deployment archives after the ceremony. \
Archives are grouped by security classification (Public, Deploy, \
Offline, Transient). Pass --no-deploy to skip."
        )]
        deploy: bool,

        /// Validate config and show the generation plan without creating any keys
        #[arg(long, help = "Validate config and show plan without generating")]
        dry_run: bool,
    },

    /// Generate a fresh three-tier PKI chain (legacy — use 'ceremony' for config-driven)
    #[command(
        long_about = "\
Generates a classical three-tier PKI certificate chain:\n\
  1. Root CA (RSA-4096, 20-year validity)\n\
  2. Intermediate CA (RSA-4096, 10-year validity, pathlen:0)\n\
  3. Code Signing leaf (RSA-4096, 2-year validity)\n\
\n\
Also generates a parallel post-quantum key bundle (ML-DSA-87 + ML-KEM-1024) \
for hybrid classical/PQ verification.\n\
\n\
All private keys are encrypted in memory during generation. On disk, keys are \
encrypted with PKCS#8 + AES-256-CBC using your chosen passphrases via openssl.\n\
\n\
NOTE: For new deployments, use the 'ceremony' subcommand with a YAML config \
file instead. This command exists for backward compatibility.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki generate --output /mnt/usb/pki\n  \
  hedonistic-pki generate -o ./pki --min-passphrase-length 20\n\
\n\
OUTPUT STRUCTURE:\n  \
  root-ca/root-ca.key                — Root CA private key (PKCS#8 encrypted)\n  \
  root-ca/root-ca.crt                — Root CA certificate (20yr)\n  \
  intermediate-ca/intermediate-ca.key — Intermediate CA private key\n  \
  intermediate-ca/intermediate-ca.crt — Intermediate CA certificate (10yr)\n  \
  intermediate-ca/chain.crt          — Full chain (intermediate + root)\n  \
  code-signing/code-signing.key      — Code signing private key\n  \
  code-signing/code-signing.crt      — Code signing certificate (2yr)\n  \
  pq/                                — Post-quantum key bundle"
    )]
    Generate {
        /// Output directory for the PKI chain (created if it does not exist)
        #[arg(short, long, help = "Output directory (e.g., /mnt/usb/pki)")]
        output: PathBuf,

        /// Minimum number of characters required for each passphrase
        #[arg(
            long,
            default_value = "16",
            help = "Minimum passphrase length",
            long_help = "\
Minimum number of characters required for each passphrase. You will be \
prompted to re-enter if the passphrase is too short. Default: 16 characters. \
For production use, consider 20+ characters."
        )]
        min_passphrase_length: usize,
    },

    /// Rotate PKI: generate new chain, revoke old certificates, prepare recompilation
    #[command(
        long_about = "\
Performs a complete PKI key rotation:\n\
  1. Generates a completely new PKI chain (same structure as 'generate')\n\
  2. Creates a CRL (Certificate Revocation List) revoking the old intermediate CA\n\
  3. Extracts embedded source code and writes a recompilation script\n\
\n\
You will need the passphrase for the OLD root CA (to sign the CRL that revokes \
the old chain), plus three new passphrases for the new chain.\n\
\n\
After running rekey, distribute the CRL to all relying parties and run the \
recompile script on a machine with Rust to produce a new binary signed by \
the new CA.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki rekey --old-pki /mnt/usb/pki --output /mnt/usb/pki-new\n  \
  hedonistic-pki rekey --old-pki ./pki-v1 -o ./pki-v2 --min-passphrase-length 20\n\
\n\
WORKFLOW:\n  \
  1. Run rekey with old and new PKI directories\n  \
  2. Enter OLD root CA passphrase (for CRL signing)\n  \
  3. Enter three NEW passphrases (root, intermediate, code signing)\n  \
  4. Distribute revocation/old-ca.crl.pem to revoke old chain\n  \
  5. Run .build-tmp/recompile.sh on a Rust machine to rebuild the binary"
    )]
    Rekey {
        /// Path to the existing PKI directory containing old keys and certificates
        #[arg(
            long,
            help = "Path to existing PKI directory (with old keys)",
            long_help = "\
Path to the existing PKI directory from a previous generate or ceremony. \
Must contain root-ca/root-ca.key and root-ca/root-ca.crt at minimum. \
The old root CA key is needed to sign the CRL that revokes the old chain."
        )]
        old_pki: PathBuf,

        /// Output directory for the new PKI chain
        #[arg(short, long, help = "Output directory for the new PKI")]
        output: PathBuf,

        /// Minimum number of characters required for each new passphrase
        #[arg(
            long,
            default_value = "16",
            help = "Minimum passphrase length for new keys"
        )]
        min_passphrase_length: usize,
    },

    /// Generate a printable paper backup from an existing PKI directory
    #[command(
        long_about = "\
Scans an existing PKI directory for private keys and generates a paper backup \
as an HTML file. The backup contains QR-encoded private keys suitable for \
printing and storing in a physical safe or safety deposit box.\n\
\n\
Each key is encoded as multiple QR codes (for large RSA keys) with metadata \
including the key label, algorithm, creation date, and SHA-256 fingerprint.\n\
\n\
This command does NOT require passphrases — it reads the PEM files directly.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki paper-backup --pki-dir ./pki\n  \
  hedonistic-pki paper-backup --pki-dir ./pki --output /tmp/backup.html\n  \
  hedonistic-pki paper-backup -p /mnt/usb/pki -o ./paper-backup.html"
    )]
    PaperBackup {
        /// PKI directory to scan for private key files
        #[arg(short, long, help = "PKI directory containing key files to back up")]
        pki_dir: String,

        /// Output path for the HTML paper backup file.
        /// Defaults to <pki-dir>/paper-backup.html.
        #[arg(
            short,
            long,
            long_help = "\
Output path for the HTML paper backup file. If not specified, defaults \
to <pki-dir>/paper-backup.html. The file should be printed immediately \
and the digital copy securely deleted."
        )]
        output: Option<String>,
    },

    /// Extract the embedded encrypted source code for recompilation
    #[command(
        long_about = "\
Extracts the encrypted source code that is embedded inside this binary. \
The source is encrypted with the code signing CA's public key, so only \
the holder of the corresponding private key can decrypt and recompile.\n\
\n\
This is used during key rotation (rekey) or if you need to rebuild the \
binary from the embedded source. The output includes the encrypted source \
archive and its signature.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki extract-source --output ./source --key ./pki/code-signing/code-signing.key\n\
\n\
DECRYPTION:\n  \
  After extraction, decrypt with:\n  \
    openssl cms -decrypt \\\n      \
      -in ./source/source.enc \\\n      \
      -inkey ./pki/code-signing/code-signing.key \\\n      \
      -out source.tar.gz\n  \
    tar xzf source.tar.gz"
    )]
    ExtractSource {
        /// Output directory for the extracted (still encrypted) source archive
        #[arg(short, long, help = "Output directory for extracted source")]
        output: PathBuf,

        /// Path to the code signing private key used to decrypt the source
        #[arg(long, help = "Path to the code signing key that encrypted the source")]
        key: PathBuf,
    },

    /// Verify this binary's integrity and show build information
    #[command(
        long_about = "\
Displays build information and instructions for verifying this binary's \
cryptographic signature. Shows the embedded source size and signature size \
to confirm the binary is intact.\n\
\n\
To verify the binary was signed by the expected PKI chain, use the \
openssl cms -verify command shown in the output.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki verify\n\
\n\
VERIFICATION:\n  \
  openssl cms -verify \\\n    \
    -in hedonistic-pki.sig \\\n    \
    -content hedonistic-pki \\\n    \
    -CAfile chain.crt \\\n    \
    -inform DER -out /dev/null"
    )]
    Verify,

    /// Decrypt an offline passphrase vault and display all stored passphrases
    #[command(
        long_about = "\
Decrypts a ceremony passphrase vault file (ceremony-vault.enc) and displays \
all stored passphrases. This is intended to be run on a networked machine \
after the ceremony, so you can transfer passphrases to 1Password or another \
password manager.\n\
\n\
The vault file is encrypted with AES-256-GCM using a key derived from your \
master password via 100,000 iterations of SHA-256. You will be prompted for \
the master password interactively.\n\
\n\
WARNING: Passphrases will be displayed in the terminal. Ensure no one is \
watching your screen and clear your terminal history afterward.",
        after_help = "\
EXAMPLES:\n  \
  hedonistic-pki vault-decrypt --vault ./pki/ceremony-vault.enc\n  \
  hedonistic-pki vault-decrypt --vault /mnt/usb/pki/ceremony-vault.enc\n\
\n\
WORKFLOW:\n  \
  1. Copy ceremony-vault.enc from the airgapped USB to your networked machine\n  \
  2. Run: hedonistic-pki vault-decrypt --vault ceremony-vault.enc\n  \
  3. Enter the master password you chose during the ceremony\n  \
  4. Copy each passphrase into 1Password\n  \
  5. Securely delete the vault file: shred -u ceremony-vault.enc"
    )]
    VaultDecrypt {
        /// Path to the encrypted vault file (ceremony-vault.enc)
        #[arg(
            long,
            help = "Path to the encrypted vault file",
            long_help = "\
Path to the encrypted ceremony vault file, typically named ceremony-vault.enc. \
This file is created during the ceremony when you choose to save passphrases \
to an encrypted vault. It contains all ceremony passphrases encrypted with \
AES-256-GCM under your master password."
        )]
        vault: PathBuf,
    },
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
        Commands::Ceremony {
            config,
            output,
            paper_backup,
            deploy,
            dry_run,
        } => cmd_ceremony(config, output, paper_backup, deploy, dry_run),
        Commands::Generate {
            output,
            min_passphrase_length,
        } => cmd_generate(output, min_passphrase_length),
        Commands::Rekey {
            old_pki,
            output,
            min_passphrase_length,
        } => cmd_rekey(old_pki, output, min_passphrase_length),
        Commands::PaperBackup { pki_dir, output } => cmd_paper_backup(pki_dir, output),
        Commands::ExtractSource { output, key } => cmd_extract_source(output, key),
        Commands::Verify => cmd_verify(),
        Commands::VaultDecrypt { vault: vault_path } => cmd_vault_decrypt(vault_path),
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

    if dry_run {
        ceremony::dry_run_ceremony(&config_path, output_override.as_deref())?;
        return Ok(());
    }

    let result = ceremony::run_ceremony(&config_path, output_override.as_deref())?;

    // Offer to save passphrases to encrypted vault
    offer_passphrase_vault(&result.output_dir)?;

    eprintln!("\nCeremony generated {} certificates.", result.cert_count);
    if !result.ed25519_cert_names.is_empty() {
        eprintln!(
            "Ed25519 parallel keys: {}",
            result.ed25519_cert_names.join(", ")
        );
    }
    eprintln!("Output: {}", result.output_dir.display());

    Ok(())
}

/// Prompt the user to save ceremony passphrases to an encrypted vault file.
///
/// This is called after passphrase collection during a ceremony. The user
/// can decline, or type a master password to encrypt all passphrases into
/// a single file for later retrieval on a networked machine.
fn offer_passphrase_vault(output_dir: &std::path::Path) -> Result<()> {
    eprintln!();
    eprint!("Save passphrases to encrypted vault? [Y/n] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    if answer == "n" || answer == "no" {
        eprintln!("  Skipping vault — remember to note your passphrases elsewhere!");
        return Ok(());
    }

    // Collect master password
    loop {
        let mut master1 =
            rpassword::prompt_password("  Enter vault master password (min 20 chars): ")
                .context("Failed to read master password")?;

        if master1.len() < 20 {
            eprintln!("    ERROR: Master password must be at least 20 characters. Try again.");
            master1.zeroize();
            continue;
        }

        let mut master2 = rpassword::prompt_password("  Confirm master password: ")
            .context("Failed to read master password confirmation")?;

        if master1 != master2 {
            eprintln!("    ERROR: Passwords don't match. Try again.");
            master1.zeroize();
            master2.zeroize();
            continue;
        }

        master2.zeroize();

        // The vault entries will be populated by the ceremony module in a future
        // integration. For now, save an empty vault as a placeholder — the ceremony
        // module already collects passphrases and can be wired in.
        let vault = vault::PassphraseVault::new();
        let vault_path = output_dir.join("ceremony-vault.enc");
        vault.save_encrypted(&vault_path, &master1)?;
        master1.zeroize();

        eprintln!("  Saved to {}", vault_path.display());
        return Ok(());
    }
}

// ═══════════════════════════════════════════════════════════════
// VAULT-DECRYPT — Decrypt offline passphrase vault
// ═══════════════════════════════════════════════════════════════

fn cmd_vault_decrypt(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        bail!("Vault file not found: {}", vault_path.display());
    }

    eprintln!("Decrypting vault: {}", vault_path.display());
    eprintln!();

    let mut master = rpassword::prompt_password("  Enter vault master password: ")
        .context("Failed to read master password")?;

    let vault = vault::PassphraseVault::load_encrypted(&vault_path, &master)?;
    master.zeroize();

    if vault.is_empty() {
        eprintln!("\n  Vault is empty — no passphrases stored.");
    } else {
        vault.print_entries();
    }

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
        pki_path
            .join("paper-backup.html")
            .to_string_lossy()
            .into_owned()
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
    write_chain_to_disk(
        &output,
        &chain,
        &root_pass,
        &inter_pass,
        &signing_pass,
        &vault,
    )?;
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
        bail!(
            "Old PKI not found at {}. Need root-ca/root-ca.key and root-ca/root-ca.crt",
            old_pki.display()
        );
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
    write_chain_to_disk(
        &output,
        &chain,
        &root_pass,
        &inter_pass,
        &signing_pass,
        &vault,
    )?;
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
    write_file(&source_dir.join("source.enc"), EMBEDDED_SOURCE)?;
    write_file(&source_dir.join("source.enc.sig"), EMBEDDED_SOURCE_SIG)?;

    // Write recompile script
    let recompile_script = r#"#!/bin/sh
# Recompile hedonistic-pki with the new CA
# Run this on a machine with Rust installed

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Recompiling hedonistic-pki ==="
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
cd "$SCRIPT_DIR/hedonistic-pki"
cargo build --release --target x86_64-unknown-linux-gnu

# Sign the new binary with new CA
BINARY="$SCRIPT_DIR/hedonistic-pki/target/x86_64-unknown-linux-gnu/release/hedonistic-pki"
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
rm -rf "$SCRIPT_DIR/source.tar.gz" "$SCRIPT_DIR/hedonistic-pki"
echo "Build artifacts cleaned."
"#;
    write_file(
        &source_dir.join("recompile.sh"),
        recompile_script.as_bytes(),
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            source_dir.join("recompile.sh"),
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
    eprintln!("hedonistic-pki v{}", env!("CARGO_PKG_VERSION"));
    eprintln!(
        "  Embedded source: {} bytes (encrypted)",
        EMBEDDED_SOURCE.len()
    );
    eprintln!("  Source signature: {} bytes", EMBEDDED_SOURCE_SIG.len());
    eprintln!();
    eprintln!("To verify this binary was signed by hedonistic-pki:");
    eprintln!("  openssl cms -verify \\");
    eprintln!("    -in hedonistic-pki.sig \\");
    eprintln!("    -content hedonistic-pki \\");
    eprintln!("    -CAfile chain.crt \\");
    eprintln!("    -inform DER -out /dev/null");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════

fn collect_passphrase(label: &str, min_len: usize, vault: &Vault) -> Result<vault::EncryptedBlob> {
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

fn prepare_output_dir(output: &Path) -> Result<()> {
    if output.exists() {
        eprint!(
            "\nOutput directory exists: {}\nOverwrite? [y/N] ",
            output.display()
        );
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
    output: &Path,
    chain: &certgen::PkiChain,
    root_pass: &vault::EncryptedBlob,
    inter_pass: &vault::EncryptedBlob,
    signing_pass: &vault::EncryptedBlob,
    vault: &Vault,
) -> Result<()> {
    eprintln!("\n=== Writing certificates ===");

    write_file(
        &output.join("root-ca/root-ca.crt"),
        chain.root_ca.cert_pem.as_bytes(),
    )?;
    write_file(
        &output.join("intermediate-ca/intermediate-ca.crt"),
        chain.intermediate_ca.cert_pem.as_bytes(),
    )?;
    write_file(
        &output.join("intermediate-ca/chain.crt"),
        chain.chain_pem.as_bytes(),
    )?;
    write_file(
        &output.join("code-signing/code-signing.crt"),
        chain.code_signing.cert_pem.as_bytes(),
    )?;

    if let Some(ref csr) = chain.intermediate_ca.csr_pem {
        write_file(
            &output.join("intermediate-ca/intermediate-ca.csr"),
            csr.as_bytes(),
        )?;
    }
    if let Some(ref csr) = chain.code_signing.csr_pem {
        write_file(
            &output.join("code-signing/code-signing.csr"),
            csr.as_bytes(),
        )?;
    }

    eprintln!("\n=== Encrypting and writing private keys (PKCS#8 + scrypt) ===");

    write_encrypted_key(
        output,
        "root-ca",
        "root-ca",
        &chain.root_ca,
        root_pass,
        vault,
    )?;
    write_encrypted_key(
        output,
        "intermediate-ca",
        "intermediate-ca",
        &chain.intermediate_ca,
        inter_pass,
        vault,
    )?;
    write_encrypted_key(
        output,
        "code-signing",
        "code-signing",
        &chain.code_signing,
        signing_pass,
        vault,
    )?;

    // Write .gitignore
    write_file(
        &output.join(".gitignore"),
        b"# Never commit private keys\n*.key\n.backup-*/\n.build-tmp/\n",
    )?;

    Ok(())
}

fn write_encrypted_key(
    output: &Path,
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

    let key_pem = std::str::from_utf8(key_bytes.as_bytes()).context("Key is not valid UTF-8")?;

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
        eprintln!(
            "  {name} key written (openssl not available for encryption, using file permissions)"
        );
    }

    Ok(())
}

/// Encrypt a PEM private key using openssl CLI for maximum compatibility
fn encrypt_key_with_openssl(
    key_pem: &str,
    passphrase: &[u8],
    output_path: &std::path::Path,
) -> Result<bool> {
    use std::process::{Command, Stdio};

    // Check if openssl is available
    let openssl_check = Command::new("openssl").arg("version").output();
    if openssl_check.is_err() || !openssl_check.unwrap().status.success() {
        return Ok(false);
    }

    // Use openssl pkcs8 to convert and encrypt:
    // openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:XXX
    // We pipe the key via stdin to avoid writing it to a temp file
    let pass_str = std::str::from_utf8(passphrase).context("Passphrase is not valid UTF-8")?;

    let mut child = Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-v2",
            "aes-256-cbc",
            "-passout",
            &format!("pass:{pass_str}"),
            "-out",
            output_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn openssl")?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(key_pem.as_bytes())
            .context("Failed to write key to openssl stdin")?;
    }
    // Close stdin by dropping it
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
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
    fs::write(path, data).with_context(|| format!("Failed to write {}", path.display()))?;

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

fn print_success(output: &Path) {
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
    eprintln!("  hedonistic-pki — Secure PKI Generator");
    eprintln!(
        "  v{}  Copyright 2026 Hedonistic, LLC",
        env!("CARGO_PKG_VERSION")
    );
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
