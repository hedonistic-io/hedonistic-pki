# hedonistic-pki

<!-- HEM Profile: open-source -->

Config-driven PKI ceremony tool — zero dependencies, airgap-safe, post-quantum ready.

## What This Is

A single Rust binary that generates complete PKI hierarchies from a YAML/JSON config file. Designed for air-gapped ceremony machines with no system dependencies — no OpenSSL, no brew, no package manager required.

Part of the **Hedonistic IO** brand family of open-source tools.

## Commands

```bash
hedonistic-pki ceremony --config ceremony.yaml --output /mnt/usb/pki
hedonistic-pki paper-backup --pki-dir /mnt/usb/pki
hedonistic-pki generate --output /mnt/usb/pki      # legacy 3-tier
hedonistic-pki rekey --old-pki /old --output /new
hedonistic-pki verify
```

## Architecture

| Module | Purpose |
|--------|---------|
| `config.rs` | YAML/JSON ceremony schema, validation, topological sort |
| `ceremony.rs` | Orchestrator — reads config, collects passphrases, generates certs |
| `certgen.rs` | Generalized N-level X.509 hierarchy (RSA-4096 + Ed25519) |
| `ed25519_keys.rs` | Pure Rust Ed25519 via ed25519-dalek |
| `paper.rs` | QR code paper backups with self-contained printable HTML |
| `deploy.rs` | File classification and deployment archive generation |
| `pq.rs` | Post-quantum: ML-DSA-87 + ML-KEM-1024 (NIST FIPS 203/204) |
| `vault.rs` | ChaCha20-Poly1305 encrypted memory vault |

## Development

```bash
cargo build           # debug build
cargo test            # 91 tests
cargo build --release # optimized binary (~2MB)
```

## Integration Status

The ceremony orchestrator wires config → certgen → paper → deploy. The bridge from ceremony.rs to certgen.rs currently generates self-signed certs for children (chain building is manual). Full parent-signed cert generation requires storing rcgen Certificate/KeyPair state across the ceremony — tracked as the primary integration TODO.

## Destination

GitHub: `hedonistic-io/hedonistic-pki`
License: Apache-2.0
