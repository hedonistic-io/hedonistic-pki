# hedonistic-pki

<!-- HEM Profile: open-source -->

Config-driven PKI ceremony tool — zero dependencies, airgap-safe, post-quantum ready.

## What This Is

A single Rust binary that generates complete PKI hierarchies from a YAML/JSON config file. Designed for air-gapped ceremony machines with no system dependencies — no OpenSSL, no brew, no package manager required.

Part of the **Hedonistic IO** brand family of open-source tools.

## Commands

```bash
# Ceremony
hedonistic-pki ceremony --config ceremony.yaml --output /mnt/usb/pki
hedonistic-pki generate --output /mnt/usb/pki      # legacy 3-tier
hedonistic-pki paper-backup --pki-dir /mnt/usb/pki
hedonistic-pki vault-decrypt --vault ./pki/ceremony-vault.enc

# Lifecycle
hedonistic-pki inspect --pki-dir /mnt/usb/pki
hedonistic-pki check-expiry --pki-dir /mnt/usb/pki --days 90
hedonistic-pki generate-ical --pki-dir /mnt/usb/pki
hedonistic-pki renew --pki-dir /mnt/usb/pki --name intermediate-ca
hedonistic-pki revoke --pki-dir /mnt/usb/pki --name code-signing --cascade
hedonistic-pki regen --pki-dir /mnt/usb/pki --name intermediate-ca

# Key/vault management
hedonistic-pki change-vault-password --vault ./pki/ceremony-vault.enc
hedonistic-pki change-key-password --key ./pki/root-ca/root-ca.key
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
| `vault.rs` | ChaCha20-Poly1305 encrypted memory vault + passphrase vault |
| `read.rs` | X.509 certificate parser and PKI directory scanner |
| `state.rs` | PKI state file (pki-state.json) for lifecycle tracking |
| `ical.rs` | RFC 5545 iCalendar expiry reminder generator |
| `lifecycle.rs` | Renew, revoke, regen, and key passphrase operations |

## Development

```bash
cargo build           # debug build
cargo test            # 141 tests
cargo build --release # optimized binary (~2MB)
```

## Integration Status

The ceremony orchestrator fully wires config, certgen, ed25519, paper, and deploy. Parent-signed cert generation works via `generate_signed_cert()`. The full chain from config parsing through deployment archive generation is operational. Ceremonies automatically write `pki-state.json` and iCalendar reminder files.

Lifecycle operations (inspect, renew, revoke, regen) load existing certs from disk using x509-parser and reconstruct rcgen CAs for re-signing. The `lifecycle.rs` module handles chain traversal and CRL generation for revocation.

## Destination

GitHub: `hedonistic-io/hedonistic-pki`
License: Apache-2.0
