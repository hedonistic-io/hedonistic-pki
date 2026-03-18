# hedonistic-pki

> Config-driven PKI ceremony tool -- zero dependencies, airgap-safe, post-quantum ready.

A single static binary that generates your entire PKI hierarchy from a YAML config file.
No OpenSSL runtime required. No system dependencies. Download it, write your config,
run the ceremony on an airgapped machine, and walk away with encrypted keys, signed
certificates, paper backups, and deployment-ready archives. Supports classical RSA-4096
and Ed25519 alongside post-quantum ML-DSA-87 and ML-KEM-1024 (NIST FIPS 203/204,
security level 5) via per-cert algorithm selection.

Copyright [Hedonistic, LLC](https://hedonistic.io). Built for internal use and released
as open source because PKI tooling should not require a week of OpenSSL incantations.

## Features

- **Config-driven**: Describe your entire PKI hierarchy in YAML or JSON -- every CA,
  intermediate, and leaf -- as a flat list with parent references. The tool topologically
  sorts the hierarchy and builds certificates in the correct order.
- **Zero system dependencies**: Single static binary. No OpenSSL, no GnuTLS, no
  shared libraries. Copy it to a USB stick and run it anywhere.
- **Airgap-safe**: Runs fully offline. No network calls, no telemetry, no update
  checks. Designed for ceremony machines that never touch a network.
- **Post-quantum ready**: ML-DSA-87 digital signatures and ML-KEM-1024 key
  encapsulation (NIST FIPS 203/204, security level 5). Select PQ algorithms per-cert
  via the `algorithm` field, or generate parallel classical + PQ keys with `parallel_keys`.
- **Paper backups**: Barcode-based paper backup generation (QR, Aztec, PDF417) with
  multi-part splitting for disaster recovery. Print it, laminate it, lock it in a safe.
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
name: acme-pki
organization: "Acme Corp"

passphrases:
  min_length: 16

hierarchy:
  - name: root-ca
    cn: "Acme Corp Root CA"
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
    offline: true
    subject:
      country: US
      organization: "Acme Corp"
      organizational_unit: "Certificate Authority"

  - name: intermediate-ca
    cn: "Acme Corp Intermediate CA"
    cert_type: intermediate
    parent: root-ca
    algorithm: rsa_4096
    validity:
      years: 10
    pathlen: 0
    subject:
      country: US
      organization: "Acme Corp"

  - name: code-signing
    cn: "Acme Corp Code Signing"
    cert_type: leaf
    parent: intermediate-ca
    algorithm: rsa_4096
    validity:
      years: 2
    extensions:
      extended_key_usage: [codeSigning]
    subject:
      organizational_unit: Engineering
EOF

# 3. Run the ceremony (dry run first to validate)
./hedonistic-pki-linux-amd64 ceremony --config ceremony.yaml --dry-run

# 4. Run for real
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

Requires Rust 1.93+ (2024 edition):

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

# Disable paper backup generation
hedonistic-pki ceremony --config ceremony.yaml --paper-backup false

# Disable deployment archive generation
hedonistic-pki ceremony --config ceremony.yaml --deploy false
```

During the ceremony, you will be prompted interactively for passphrases. Certs
sharing the same parent are automatically grouped so you only enter one passphrase
per group. Certs with `no_passphrase: true` are skipped. Passphrases are encrypted
in the memory vault immediately after input and never stored in plaintext.

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
with barcodes encoding the private keys, suitable for printing and archival storage.

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

### Top-Level Fields (`CeremonyConfig`)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Internal name for this ceremony |
| `organization` | string | yes | -- | Organization name embedded in certificate subjects |
| `output_dir` | string | no | `null` | Base output directory (overridable via `--output` CLI flag) |
| `passphrases` | object | no | see below | Passphrase policy settings |
| `hierarchy` | array | yes | -- | Flat list of certificate specs (see CertSpec below) |
| `paper_backup` | object | no | `null` | Paper backup settings (see below) |
| `deployment` | object | no | `null` | Deployment archive settings (see below) |

### Passphrase Config (`passphrases`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_length` | integer | `16` | Minimum passphrase length enforced during ceremony |
| `manager_hint` | string | `null` | Hint displayed during passphrase prompts (e.g., "use 1Password") |

### Certificate Spec (`CertSpec`) -- entries in `hierarchy`

Each entry in the `hierarchy` array describes one certificate:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Internal identifier, used as parent reference by children |
| `cn` | string | yes | -- | Common Name for the X.509 subject |
| `cert_type` | enum | yes | -- | One of: `root`, `intermediate`, `sub_ca`, `leaf` |
| `parent` | string | no | `null` | `name` of the parent CA that signs this cert. Required for all non-root types. Root certs must not have a parent. |
| `algorithm` | enum | no | `rsa_4096` | Key algorithm: `rsa_4096`, `ed25519`, `ml_dsa_87`, `ml_kem_1024` |
| `hash` | enum | no | `null` | Hash algorithm: `sha256`, `sha384`, `sha512` |
| `validity` | object | yes | -- | Must contain `years` (integer) and/or `days` (integer) |
| `pathlen` | integer | no | `null` | X.509 path length constraint. Only valid on CA types, not leaves. |
| `offline` | boolean | no | `false` | Mark this cert as offline (affects passphrase grouping and deployment classification) |
| `no_passphrase` | boolean | no | `false` | Skip passphrase for this key (e.g., CI/CD service keys) |
| `parallel_keys` | array | no | `[]` | Additional algorithms to generate alongside the primary. E.g., `[ed25519, ml_dsa_87]` generates those keys in parallel with the primary `algorithm`. |
| `extensions` | object | no | `null` | X.509 extension overrides (see below) |
| `subject` | object | no | `null` | Additional X.509 subject fields (see below) |
| `tags` | array | no | `[]` | Arbitrary string tags for metadata |
| `deploy_to` | string | no | `null` | Deployment target hint (e.g., `github-actions`) |

### Extension Spec (`extensions`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `key_usage` | array | `[]` | X.509 Key Usage values (e.g., `[keyCertSign, cRLSign]`) |
| `extended_key_usage` | array | `[]` | Extended Key Usage values (e.g., `[codeSigning, serverAuth, clientAuth]`) |
| `basic_constraints_ca` | boolean | `null` | Explicit CA flag override |

### Subject Spec (`subject`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `country` | string | `null` | Two-letter country code |
| `organization` | string | `null` | Organization name (overrides top-level `organization` for this cert) |
| `organizational_unit` | string | `null` | Organizational unit |

### Paper Backup Config (`paper_backup`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `formats` | array | `[]` | Barcode formats to generate: `qr`, `aztec`, `pdf417` |
| `output` | string | `"html"` | Output format identifier |
| `include_pem` | boolean | `true` | Include PEM-encoded key text alongside barcodes |

### Deployment Config (`deployment`)

| Field | Type | Description |
|-------|------|-------------|
| `packages` | array | List of deployment packages to create |

Each package (`DeployPackage`):

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Archive name (produces `deploy/<name>.tar.gz`) |
| `target` | string | Target directory path for the archive |
| `patterns` | array | Glob patterns for files to include (e.g., `["*.crt", "*.pub"]`) |

### Full Example

See [`examples/quickstart.yaml`](examples/quickstart.yaml) for a complete working config.

### Post-Quantum Keys

There is no top-level post-quantum configuration block. PQ algorithms are selected
per-cert via the `algorithm` field:

```yaml
hierarchy:
  - name: pq-signer
    cn: "PQ Code Signer"
    cert_type: leaf
    parent: intermediate-ca
    algorithm: ml_dsa_87
    validity:
      years: 2
```

To generate both classical and PQ keys for the same cert, use `parallel_keys`:

```yaml
hierarchy:
  - name: hybrid-root
    cn: "Hybrid Root CA"
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
    parallel_keys:
      - ed25519
      - ml_dsa_87
```

### Passphrase Grouping

Passphrase grouping is automatic -- there is no config field for it. The rules are:

- Certs with `no_passphrase: true` get no passphrase
- Each root CA gets its own passphrase
- Non-root certs sharing the same parent share a passphrase

This means you are prompted once per root CA and once per group of siblings,
rather than once per cert.

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
2. **Barcode**: The private key material encoded as a barcode (QR, Aztec, or PDF417)
3. **PEM Text**: The full PEM-encoded key printed below the barcode as a fallback
   (when `include_pem` is true)
4. **Reconstruction Instructions**: Step-by-step procedure printed on each page

When multiple formats are specified in `paper_backup.formats`, each key gets a
barcode in each requested format. Keys are split across multiple barcodes when they
exceed a single barcode's capacity. Each part is labeled (e.g., "Part 1 of 3") and
includes a SHA-256 checksum of the complete key for verification after reassembly.

### Reconstruction Procedure

1. Scan all barcode parts for a given key
2. Concatenate the parts in order
3. Verify the SHA-256 checksum matches the value printed on each page
4. The result is the PEM-encoded private key

If barcode scanning fails, manually type the PEM text from the printed backup.

## Building from Source

### Prerequisites

- Rust 1.93+ (2024 edition)
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

Copyright 2026 [Hedonistic, LLC](https://hedonistic.io). Part of the Hedonistic brand
family of tools for infrastructure, security, and AI orchestration.

Post-quantum cryptography powered by the [ml-dsa](https://crates.io/crates/ml-dsa)
and [ml-kem](https://crates.io/crates/ml-kem) crates implementing NIST FIPS 203/204.
Classical certificate generation via [rcgen](https://crates.io/crates/rcgen). Memory
vault uses [chacha20poly1305](https://crates.io/crates/chacha20poly1305) from the
RustCrypto project.
