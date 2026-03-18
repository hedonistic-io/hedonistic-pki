# Contributing to hedonistic-pki

Thanks for your interest in contributing to hedonistic-pki, a hybrid
classical/post-quantum PKI toolkit designed for airgapped ceremony use.

## Development Setup

1. Install Rust via [rustup](https://rustup.rs/) (the repo pins the toolchain
   in `rust-toolchain.toml`).
2. Clone the repository and build:
   ```bash
   git clone https://github.com/hedonisticIO/hedonistic-pki.git
   cd hedonistic-pki
   cargo build
   ```
3. Run the test suite:
   ```bash
   cargo test
   ```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes in focused, atomic commits using conventional commit
   messages (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`).
3. Ensure all checks pass before opening a PR:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
4. Open a pull request against `main` with a clear description of the change
   and its motivation.
5. A maintainer will review your PR. Expect at least one round of feedback.

## Code Style

- Run `cargo fmt` before committing.
- Run `cargo clippy -- -D warnings` and fix all lints.
- No `unsafe` code without a clear justification comment and a `// SAFETY:`
  annotation explaining the invariants.
- Keep functions small and focused. Prefer returning `Result` over panicking.

## Security

This is a security-critical tool. If you discover a vulnerability:

- **Do NOT open a public issue.**
- Email security@hedonistic.io with a description of the issue.
- We will acknowledge receipt within 48 hours and work with you on a fix.

## Architecture

The codebase is organized into these modules:

| Module        | Purpose                                              |
|---------------|------------------------------------------------------|
| `main.rs`     | CLI entry point (clap), command dispatch             |
| `certgen.rs`  | X.509 certificate generation (RSA-4096, Ed25519)    |
| `pq.rs`       | Post-quantum keys (ML-DSA-87, ML-KEM-1024)          |
| `vault.rs`    | In-memory encrypted key storage (ChaCha20-Poly1305) |
| `ceremony.rs` | Config-driven PKI ceremony orchestration             |
| `config.rs`   | Ceremony configuration parsing (YAML/JSON)           |
| `deploy.rs`   | Deployment archive generation                        |
| `paper.rs`    | Paper backup (printable HTML) generation             |
| `ed25519_keys.rs` | Ed25519 key utilities                            |

New features typically belong in an existing module. If you need a new module,
discuss it in an issue first.

## License

This project is licensed under Apache-2.0. By submitting a pull request you
agree that your contribution is licensed under the same terms. No CLA is
required.
