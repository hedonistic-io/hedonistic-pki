# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-17

### Added

- Config-driven PKI ceremony engine with YAML and JSON support
- Flat hierarchy with parent references and topological sort for build order
- RSA-4096 and Ed25519 classical key generation via rcgen and ed25519-dalek
- Post-quantum ML-DSA-87 digital signatures (NIST FIPS 204)
- Post-quantum ML-KEM-1024 key encapsulation (NIST FIPS 203)
- Per-cert algorithm selection including PQ algorithms
- Parallel key generation via `parallel_keys` for multi-algorithm certs
- Parent-signed certificate generation via `generate_signed_cert()`
- Full X.509 chain building with configurable pathlen constraints
- ChaCha20-Poly1305 encrypted in-memory vault for private key material
- PKCS#8 + AES-256-CBC encrypted private key output
- QR code paper backup generation as self-contained printable HTML
- Multiple barcode format support (QR, Aztec, PDF417)
- Multi-part key splitting across barcode sheets
- Deployment archive generation with file classification (offline/online/public)
- Automatic passphrase grouping by hierarchy position
- Configurable passphrase minimum length
- Dry-run mode for config validation and ceremony planning
- Linux memory hardening (mlock, core dump disable, panic=abort)
- Legacy `generate` command for simple 3-tier PKI without config
- `rekey` command for PKI rotation with CRL generation
- `paper-backup` command for standalone backup generation
- `verify` command for binary integrity checks
- `extract-source` command for embedded source recovery
- Pinned Rust toolchain (1.93.1) for reproducible builds
- Cross-compilation support via `build-linux.sh`
- 93 tests covering config parsing, validation, cert generation, paper backup, and deployment
