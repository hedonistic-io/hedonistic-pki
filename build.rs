//! Build script for hedonistic-keygen
//!
//! At compile time, this:
//!   1. Archives the entire src/ directory as a tar.gz
//!   2. Encrypts it with the code signing certificate (if available)
//!   3. Embeds the encrypted archive into the binary via include_bytes!
//!
//! If no signing cert is available (first build), embeds a placeholder.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let _src_dir = manifest_dir.join("src");

    // Look for code signing cert in the PKI directory (parent of keygen/)
    let pki_dir = manifest_dir.parent().unwrap_or(&manifest_dir);
    let signing_cert = pki_dir.join("code-signing/code-signing.crt");

    let source_enc_path = out_dir.join("source.enc");
    let source_sig_path = out_dir.join("source.enc.sig");

    if signing_cert.exists() && has_openssl() {
        // Full build: archive, encrypt with cert, sign
        eprintln!("cargo:warning=Embedding encrypted source (signed by code-signing cert)");

        let tar_path = out_dir.join("source.tar.gz");

        // Create tar.gz of src/
        let status = Command::new("tar")
            .args(["czf", tar_path.to_str().unwrap(), "-C", manifest_dir.to_str().unwrap()])
            .args(["src/", "Cargo.toml", "build.rs"])
            .status();

        if let Ok(s) = status {
            if s.success() {
                // Encrypt with the code signing certificate's public key
                let enc_status = Command::new("openssl")
                    .args([
                        "cms", "-encrypt",
                        "-aes-256-cbc",
                        "-in", tar_path.to_str().unwrap(),
                        "-outform", "DER",
                        "-out", source_enc_path.to_str().unwrap(),
                        signing_cert.to_str().unwrap(),
                    ])
                    .status();

                if let Ok(s) = enc_status {
                    if s.success() {
                        // Sign the encrypted blob with the signing key if available
                        let signing_key = pki_dir.join("code-signing/code-signing.key");
                        let chain = pki_dir.join("intermediate-ca/chain.crt");

                        if signing_key.exists() && chain.exists() {
                            let sig_status = Command::new("openssl")
                                .args([
                                    "cms", "-sign", "-binary",
                                    "-in", source_enc_path.to_str().unwrap(),
                                    "-signer", signing_cert.to_str().unwrap(),
                                    "-inkey", signing_key.to_str().unwrap(),
                                    "-certfile", chain.to_str().unwrap(),
                                    "-outform", "DER",
                                    "-out", source_sig_path.to_str().unwrap(),
                                ])
                                .status();

                            if sig_status.map(|s| s.success()).unwrap_or(false) {
                                eprintln!("cargo:warning=Source encrypted and signed successfully");
                                // Clean up tar
                                let _ = fs::remove_file(&tar_path);
                                return;
                            }
                        }

                        // Encrypted but no signature (key not available at build time)
                        write_placeholder_sig(&source_sig_path);
                        let _ = fs::remove_file(&tar_path);
                        return;
                    }
                }
            }
        }

        // Fallthrough: openssl/tar failed, use placeholder
        eprintln!("cargo:warning=Encryption failed, embedding placeholder");
    } else {
        eprintln!("cargo:warning=No signing cert found, embedding placeholder source blob");
    }

    // Placeholder: just the raw tar.gz (not encrypted)
    // This is the bootstrap case — first build before any PKI exists
    let tar_path = out_dir.join("source.tar.gz");
    let status = Command::new("tar")
        .args(["czf", tar_path.to_str().unwrap(), "-C", manifest_dir.to_str().unwrap()])
        .args(["src/", "Cargo.toml", "build.rs"])
        .status();

    match status {
        Ok(s) if s.success() => {
            // Copy tar as the "encrypted" blob (it's not actually encrypted in bootstrap)
            fs::copy(&tar_path, &source_enc_path).unwrap();
            let _ = fs::remove_file(&tar_path);
        }
        _ => {
            // Last resort: empty placeholder
            fs::write(&source_enc_path, b"PLACEHOLDER:NO_SOURCE_EMBEDDED").unwrap();
        }
    }

    write_placeholder_sig(&source_sig_path);

    // Tell cargo to rerun if source changes
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
}

fn write_placeholder_sig(path: &Path) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(b"PLACEHOLDER:NO_SIGNATURE").unwrap();
}

fn has_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
