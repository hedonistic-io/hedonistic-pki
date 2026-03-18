# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — Pleasure Through Creation — 2026-03-17

### Capabilities

- **Config-driven PKI ceremonies**: Describe your entire certificate hierarchy in YAML or JSON and generate it in one command. Flat list with parent references, topologically sorted.
- **Classical cryptography**: RSA-4096 and Ed25519 X.509 certificate generation with full chain building and configurable pathlen constraints.
- **Post-quantum cryptography**: ML-DSA-87 digital signatures (NIST FIPS 204) and ML-KEM-1024 key encapsulation (NIST FIPS 203), security level 5. Per-cert algorithm selection with parallel key generation for hybrid deployments.
- **Passphrase vault**: After a ceremony, optionally save all passphrases to an AES-256-GCM encrypted vault file. Decrypt later with `vault-decrypt` for transfer to 1Password or another password manager.
- **`vault-decrypt` command**: Decrypt offline passphrase vault files and display stored passphrases for password manager transfer.
- **Memory-hardened vault**: All private keys encrypted in-memory with ChaCha20-Poly1305 using ephemeral OS CSPRNG keys. Linux targets get mlock, core dump disable, and panic=abort.
- **Encrypted key output**: Private keys written to disk with PKCS#8 + AES-256-CBC encryption. Nothing leaves the binary unencrypted.
- **Paper backups**: Self-contained printable HTML with QR, Aztec, or PDF417 barcodes. Large keys split across multiple sheets with SHA-256 verification checksums.
- **Deployment packaging**: Automatic classification of ceremony outputs into offline, online, and public archives with JSON manifests.
- **PKI lifecycle**: Key rotation via `rekey` with CRL generation. Self-recompilation support via embedded encrypted source.
- **Dry-run mode**: Validate configs and preview ceremony plans without generating any keys.
- **Zero system dependencies**: Single static binary. No OpenSSL, no shared libraries. Copy to a USB stick and run on an airgapped machine.
