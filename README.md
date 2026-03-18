# hedonistic-pki

> Config-driven PKI ceremony tool -- zero dependencies, airgap-safe, post-quantum ready.

A single static binary that generates your entire PKI hierarchy from a YAML config file.
No OpenSSL runtime required. No system dependencies. Download it, write your config,
run the ceremony on an airgapped machine, and walk away with encrypted keys, signed
certificates, paper backups, and deployment-ready archives. Supports classical RSA-4096
X.509 chains alongside post-quantum ML-DSA-87 and ML-KEM-1024 (NIST FIPS 203/204,
security level 5) in a hybrid dual-signature model.

Built by [Hedonistic IO](https://hedonistic.io) for internal use and released as open
source because PKI tooling should not require a week of OpenSSL incantations.

## Features

- **Config-driven**: Describe your entire PKI hierarchy in YAML or JSON -- every CA,
  intermediate, signer, and leaf -- and the tool builds exactly what you specified.
- **Zero system dependencies**: Single static binary. No OpenSSL, no GnuTLS, no
  shared libraries. Copy it to a USB stick and run it anywhere.
- **Airgap-safe**: Runs fully offline. No network calls, no telemetry, no update
  checks. Designed for ceremony machines that never touch a network.
- **Post-quantum ready**: ML-DSA-87 digital signatures and ML-KEM-1024 key
  encapsulation (NIST FIPS 203/204, security level 5) generated alongside classical
  RSA-4096 keys. Both must verify -- hybrid model, not either/or.
- **Paper backups**: QR-code-based paper backup generation with multi-part splitting
  for disaster recovery. Print it, laminate it, lock it in a safe.
- **Deployment packages**: Automated classification of ceremony outputs into
  deployment-ready tar.gz archives (offline keys, online keys, public trust bundle).
- **Memory hardened**: All private keys encrypted in memory with ChaCha20-Poly1305
  using an ephemeral vault key from OS CSPRNG. Memory pages mlock'd (Linux). Core
  dumps disabled. All sensitive memory zeroized on drop. Panic = abort.
- **Encrypted on disk**: Private keys written with PKCS#8 + AES-256-CBC encryption.
  Nothing leaves the binary unencrypted.

## Quick Start

```bash
# 1. Download the binary for your platform
curl -LO https://github.com/hedonistic-io/hedonistic-pki/releases/latest/download/hedonistic-pki-linux-amd64
chmod +x hedonistic-pki-linux-amd64

# 2. Write your ceremony config
cat > ceremony.yaml << 'EOF'
organization: "Acme Corp"
output_dir: "./pki-output"

hierarchy:
  - name: "Acme Root CA"
    key_type: rsa4096
    validity_years: 20
    self_signed: true
    children:
      - name: "Acme Intermediate CA"
        key_type: rsa4096
        validity_years: 10
        path_length: 0
        children:
          - name: "Acme Code Signing"
            key_type: rsa4096
            validity_years: 2
            usage: [code_signing]

post_quantum:
  enabled: true
  algorithm: ml-dsa-87
  kem: ml-kem-1024

paper_backup:
  enabled: true
  qr_parts: 3  # Split across 3 QR sheets

deploy:
  enabled: true
  packages:
    - name: offline
      include: ["root-ca/*.key", "intermediate-ca/*.key"]
    - name: online
      include: ["code-signing/*", "intermediate-ca/chain.crt"]
    - name: trust-bundle
      include: ["**/*.crt", "pq/*.vk"]
EOF

# 3. Run the ceremony
./hedonistic-pki-linux-amd64 ceremony --config ceremony.yaml
```

## Installation

### From GitHub Releases

Pre-built static binaries are available for Linux (x86_64, aarch64) and macOS
(Apple Silicon):

```bash
# Linux x86_64
curl -LO https://github.com/hedonistic-io/hedonistic-pki/releases/latest/download/hedonistic-pki-linux-amd64

# Linux aarch64
curl -LO https://github.com/hedonistic-io/hedonistic-pki/releases/latest/download/hedonistic-pki-linux-arm64

# macOS Apple Silicon
curl -LO https://github.com/hedonistic-io/hedonistic-pki/releases/latest/download/hedonistic-pki-darwin-arm64

chmod +x hedonistic-pki-*
```

### From Source

Requires Rust 1.85+ (2024 edition):

```bash
git clone https://github.com/hedonistic-io/hedonistic-pki.git
cd hedonistic-pki
cargo build --release
# Binary: target/release/hedonistic-pki
```

For cross-compilation to Linux from macOS (requires cross-compilation toolchain):

```bash
./build-linux.sh
```

## Usage

### `hedonistic-pki ceremony`

The primary command. Reads a YAML or JSON config that describes your desired PKI
hierarchy and executes the full ceremony: key generation, certificate signing,
post-quantum key generation, paper backup, and deployment packaging.

```bash
hedonistic-pki ceremony --config ceremony.yaml

# Override output directory
hedonistic-pki ceremony --config ceremony.yaml --output /mnt/usb/pki

# Dry run -- validate config and show the planned hierarchy
hedonistic-pki ceremony --config ceremony.yaml --dry-run

# Skip paper backup generation
hedonistic-pki ceremony --config ceremony.yaml --no-paper-backup

# Skip deployment archive generation
hedonistic-pki ceremony --config ceremony.yaml --no-deploy
```

During the ceremony, you will be prompted interactively for passphrases. Each CA
or signer that requires a passphrase (as declared in the config) will prompt twice
for confirmation. Passphrases are encrypted in the memory vault immediately after
input and never stored in plaintext.

### `hedonistic-pki generate`

Legacy command for simple three-tier PKI generation without a config file. Generates
a Root CA, Intermediate CA, and Code Signing certificate with sensible defaults.

```bash
hedonistic-pki generate --output /mnt/usb/pki

# Custom minimum passphrase length (default: 16)
hedonistic-pki generate --output /mnt/usb/pki --min-passphrase-length 24
```

Output structure:

```
/mnt/usb/pki/
  root-ca/
    root-ca.crt               # Root CA certificate (20yr, RSA-4096)
    root-ca.key               # Root CA private key (PKCS#8 encrypted)
  intermediate-ca/
    intermediate-ca.crt       # Intermediate CA certificate (10yr)
    intermediate-ca.key       # Intermediate CA private key (PKCS#8 encrypted)
    chain.crt                 # Full chain (intermediate + root)
  code-signing/
    code-signing.crt          # Code signing certificate (2yr)
    code-signing.key          # Code signing private key (PKCS#8 encrypted)
  pq/
    root-ca.vk                # ML-DSA-87 verification key
    root-ca.sk                # ML-DSA-87 signing key
    intermediate-ca.vk        # ML-DSA-87 verification key
    intermediate-ca.sk        # ML-DSA-87 signing key
    code-signing.vk           # ML-DSA-87 verification key
    code-signing.sk           # ML-DSA-87 signing key
    code-signing.ek           # ML-KEM-1024 encapsulation key
    code-signing.dk           # ML-KEM-1024 decapsulation key
    manifest.json             # PQ key manifest (hex-encoded public keys)
    *.endorsement.sig         # PQ cross-signing chain
```

### `hedonistic-pki rekey`

Generate a completely new PKI chain, revoke the old chain via CRL, and prepare a
self-recompilation package so the binary can be rebuilt with the new CA embedded.

```bash
hedonistic-pki rekey --old-pki /mnt/usb/pki --output /mnt/usb/pki-new
```

This command:
1. Generates a fresh PKI chain (identical to `generate`)
2. Creates a Certificate Revocation List (CRL) for the old chain
3. Extracts the embedded source code and writes a recompilation script

You will be prompted for the **old** Root CA passphrase (to sign the CRL) and three
**new** passphrases for the replacement chain.

### `hedonistic-pki verify`

Display binary metadata and provide instructions for verifying the binary's CMS
signature against the certificate chain.

```bash
hedonistic-pki verify
```

### `hedonistic-pki paper-backup`

Generate a paper backup from an existing PKI directory. Produces an HTML document
with QR codes encoding the private keys, suitable for printing and archival storage.

```bash
hedonistic-pki paper-backup --pki-dir /mnt/usb/pki

# Custom output path
hedonistic-pki paper-backup --pki-dir /mnt/usb/pki --output backup.html
```

### `hedonistic-pki extract-source`

Extract the encrypted source code embedded in the binary. Useful for auditing or
recompilation.

```bash
hedonistic-pki extract-source --output ./source --key /mnt/usb/pki/code-signing/code-signing.key
```

## Configuration Reference

The ceremony config file is YAML or JSON. Every field is documented below.

### Top-Level Fields

```yaml
# Organization name embedded in certificate subjects
organization: "Acme Corp"

# Base output directory for all ceremony artifacts
output_dir: "./pki-output"

# Minimum passphrase length enforced during ceremony (default: 16)
min_passphrase_length: 16

# The certificate hierarchy tree
hierarchy:
  - # ... (see Hierarchy Node below)

# Post-quantum key generation settings
post_quantum:
  # ... (see Post-Quantum section below)

# Paper backup settings
paper_backup:
  # ... (see Paper Backup section below)

# Deployment archive settings
deploy:
  # ... (see Deploy section below)

# Passphrase groups -- share passphrases across multiple nodes
passphrase_groups:
  # ... (see Passphrase Groups below)
```

### Hierarchy Node

Each node in the `hierarchy` array represents a CA or leaf certificate:

```yaml
hierarchy:
  - name: "Acme Root CA"
    # Common Name for the certificate subject
    # Required.

    key_type: rsa4096
    # Key algorithm. One of: rsa2048, rsa4096, ed25519
    # Default: rsa4096

    validity_years: 20
    # Certificate validity period in years.
    # Required.

    self_signed: true
    # Whether this is a self-signed root CA.
    # Default: false. Only valid for the top-level node.

    path_length: 1
    # X.509 pathlen constraint. Limits how many CAs can exist below.
    # Optional. Omit for leaf certificates.

    passphrase: true
    # Whether to prompt for a passphrase for this key.
    # Default: true for CAs, false for CI signers.

    passphrase_group: "offline-cas"
    # Share a passphrase with other nodes in the same group.
    # Optional. See Passphrase Groups.

    usage:
      - code_signing
    # Extended Key Usage. Options:
    #   code_signing, server_auth, client_auth, email_protection,
    #   time_stamping, lifetime_signing
    # Optional. Defaults based on certificate type.

    subject:
      country: "US"
      state: "California"
      locality: "San Francisco"
      org_unit: "Engineering"
    # Additional X.509 subject fields.
    # Optional. Organization is inherited from the top-level field.

    children:
      - # ... nested hierarchy nodes
    # Sub-certificates signed by this CA.
    # Optional. Leaf certificates have no children.
```

### Post-Quantum Settings

```yaml
post_quantum:
  enabled: true
  # Generate post-quantum keys alongside classical keys.
  # Default: true

  algorithm: ml-dsa-87
  # Signature algorithm. Options: ml-dsa-44, ml-dsa-65, ml-dsa-87
  # Default: ml-dsa-87 (NIST security level 5)

  kem: ml-kem-1024
  # Key encapsulation mechanism. Options: ml-kem-512, ml-kem-768, ml-kem-1024
  # Default: ml-kem-1024 (NIST security level 5)
  # Only generated for leaf certificates with code_signing usage.

  cross_sign: true
  # Generate cross-signing endorsements between PQ and classical keys.
  # Default: true
```

### Paper Backup Settings

```yaml
paper_backup:
  enabled: true
  # Generate paper backup HTML after ceremony.
  # Default: true

  qr_parts: 3
  # Split each key across N QR code sheets.
  # Each sheet is needed for reconstruction.
  # Default: 1 (no splitting)

  include_public: true
  # Include public keys/certificates in the paper backup.
  # Default: true

  output: "paper-backup.html"
  # Output filename for the HTML paper backup.
  # Default: "paper-backup.html" in the output directory.
```

### Deployment Settings

```yaml
deploy:
  enabled: true
  # Generate deployment archives after ceremony.
  # Default: true

  packages:
    - name: offline
      # Archive name. Produces: deploy/offline.tar.gz
      description: "Offline root and intermediate keys -- safe storage only"
      include:
        - "root-ca/*.key"
        - "intermediate-ca/*.key"

    - name: online
      description: "Keys and certs for online services"
      include:
        - "code-signing/*"
        - "intermediate-ca/chain.crt"
      exclude:
        - "*.key"  # Exclude private keys from this package

    - name: trust-bundle
      description: "Public trust bundle for verification"
      include:
        - "**/*.crt"
        - "pq/*.vk"
        - "pq/manifest.json"
```

### Passphrase Groups

Passphrase groups let you use a single passphrase for multiple keys. Useful when
several CAs share the same security tier:

```yaml
passphrase_groups:
  offline-cas:
    min_length: 24
    # Override minimum length for this group.

  ci-signers:
    passphrase: false
    # CI signers get no passphrase (keys protected by deployment security).
```

Reference groups from hierarchy nodes via the `passphrase_group` field.

## Security Architecture

### Memory Vault

All private key material is encrypted in memory immediately after generation. The
vault uses ChaCha20-Poly1305 with a 256-bit ephemeral key sourced from the OS CSPRNG
(`getrandom`). The vault key exists only in process memory and is never written to
disk.

When a key needs to be used (e.g., to sign a child certificate), it is decrypted
into a `Zeroizing<Vec<u8>>` buffer, used, and immediately zeroized. At no point do
plaintext private keys exist in unprotected memory.

### Platform Hardening (Linux)

On Linux targets, the binary applies additional protections at startup:

- **mlock**: All current and future memory pages are locked (`mlockall`), preventing
  the kernel from swapping sensitive data to disk.
- **Core dumps disabled**: `prctl(PR_SET_DUMPABLE, 0)` prevents core dumps that
  could contain key material.
- **panic=abort**: The binary aborts on panic rather than unwinding the stack, which
  prevents stack traces from leaking sensitive data.

On non-Linux platforms, these protections are noted as unavailable but the vault
encryption and zeroization still apply.

### Post-Quantum Cryptography

The tool generates post-quantum keys using NIST-standardized algorithms:

- **ML-DSA-87** (FIPS 204, formerly Dilithium): Digital signatures at security
  level 5. Used to sign the PQ endorsement chain that parallels the classical X.509
  chain.
- **ML-KEM-1024** (FIPS 203, formerly Kyber): Key encapsulation at security level 5.
  Generated for code signing leaves to enable post-quantum encrypted distribution
  channels.

The classical and post-quantum chains are independent but cross-signed. Verification
requires both chains to validate -- this is a hybrid "and" model, not "or".

### Disk Encryption

Private keys are encrypted before writing to disk using PKCS#8 with AES-256-CBC key
derivation via scrypt. The passphrase you provide during the ceremony is the only way
to decrypt the keys. If OpenSSL is not available on the system, keys are written with
restrictive file permissions (0400) as a fallback, and a warning is printed.

### Embedded Source

The binary embeds an encrypted copy of its own source code, signed with the code
signing certificate. This allows the binary to be recompiled with a new CA during
rekey ceremonies without needing to trust an external source archive.

## Paper Backup Format

Paper backups are generated as self-contained HTML files designed for printing. Each
page contains:

1. **Header**: Certificate name, generation timestamp, key fingerprint
2. **QR Code**: The private key material encoded as a QR code
3. **PEM Text**: The full PEM-encoded key printed below the QR code as a fallback
4. **Reconstruction Instructions**: Step-by-step procedure printed on each page

When `qr_parts` is greater than 1, each key is split across multiple QR codes using
byte-level splitting. All parts are required for reconstruction. Each part is labeled
(e.g., "Part 1 of 3") and includes a SHA-256 checksum of the complete key for
verification after reassembly.

### Reconstruction Procedure

1. Scan all QR code parts for a given key
2. Concatenate the parts in order
3. Verify the SHA-256 checksum matches the value printed on each page
4. The result is the PEM-encoded private key

If QR scanning fails, manually type the PEM text from the printed backup.

## Building from Source

### Prerequisites

- Rust 1.85+ (2024 edition)
- No system dependencies required for the build itself

### Debug Build

```bash
cargo build
```

### Release Build

```bash
cargo build --release
```

The release profile is optimized for size (`opt-level = "z"`) with LTO enabled,
single codegen unit, symbols stripped, and panic=abort.

### Cross-Compilation

The included `build-linux.sh` script handles cross-compilation to
`x86_64-unknown-linux-gnu` from macOS:

```bash
./build-linux.sh
```

For other targets, use standard Rust cross-compilation:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Build Script

The `build.rs` script handles embedding the encrypted source archive into the binary.
It compresses and encrypts the `src/` directory at compile time so that the binary is
self-contained for rekey operations.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Credits

Built by [Hedonistic IO](https://hedonistic.io). Part of the Hedonistic brand family
of tools for infrastructure, security, and AI orchestration.

Post-quantum cryptography powered by the [ml-dsa](https://crates.io/crates/ml-dsa)
and [ml-kem](https://crates.io/crates/ml-kem) crates implementing NIST FIPS 203/204.
Classical certificate generation via [rcgen](https://crates.io/crates/rcgen). Memory
vault uses [chacha20poly1305](https://crates.io/crates/chacha20poly1305) from the
RustCrypto project.
