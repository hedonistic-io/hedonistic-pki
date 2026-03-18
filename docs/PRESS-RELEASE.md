# Hedonistic IO Releases Open-Source Post-Quantum PKI Ceremony Tool

**FOR IMMEDIATE RELEASE**

**March 18, 2026 -- California** -- Hedonistic, LLC today announced the open-source
release of **hedonistic-pki v1.0.0**, a config-driven PKI ceremony tool that generates
complete certificate hierarchies from a single YAML file. The tool ships as a static
Rust binary with zero system dependencies, runs fully offline on airgapped machines,
and includes built-in support for NIST post-quantum cryptographic algorithms alongside
classical RSA-4096 and Ed25519.

PKI ceremonies -- the process of generating root certificate authorities, intermediate
CAs, and leaf certificates -- have traditionally required extensive manual procedures,
OpenSSL command-line incantations, and careful coordination across multiple tools.
hedonistic-pki replaces this fragile workflow with a single declarative configuration
file and one command.

"PKI ceremonies should be reproducible, auditable, and accessible to any engineering
team, not just organizations with dedicated security staff," said the hedonistic-pki
team. "We built this tool for our own infrastructure and released it because the
existing options all assume you have OpenSSL installed, a network connection, and a
week to read man pages."

## Key Features

- **Config-driven ceremonies**: Describe your entire PKI hierarchy in YAML or JSON.
  The tool topologically sorts the hierarchy and generates certificates in the correct
  order, handling parent-child signing relationships automatically.

- **Zero system dependencies**: A single static binary. No OpenSSL, no GnuTLS, no
  shared libraries, no package manager. Copy it to a USB stick and run it on any
  Linux or macOS machine.

- **Airgap-safe**: No network calls, no telemetry, no update checks. Designed for
  ceremony machines that never touch a network.

- **Post-quantum ready**: ML-DSA-87 digital signatures and ML-KEM-1024 key
  encapsulation (NIST FIPS 203/204, security level 5). Select PQ algorithms per
  certificate or generate hybrid classical + PQ key pairs for migration readiness.

- **Paper backups**: Generate printable HTML documents with barcode-encoded private
  keys (QR, Aztec, PDF417) for disaster recovery. Multi-part splitting handles keys
  that exceed a single barcode's capacity.

- **Memory hardened**: All private keys are encrypted in memory using
  ChaCha20-Poly1305 with ephemeral keys. Memory pages are locked on Linux to prevent
  swapping. Core dumps are disabled. All sensitive memory is zeroized on drop.

- **Deployment packaging**: Automatically classifies ceremony outputs and generates
  deployment-ready tar.gz archives for offline storage, online servers, and public
  trust bundles.

## Availability

hedonistic-pki v1.0.0 is available immediately under the Apache-2.0 license. Pre-built
static binaries are provided for Linux (x86_64, aarch64) and macOS (Apple Silicon).

- **GitHub**: https://github.com/hedonistic-io/hedonistic-pki
- **Releases**: https://github.com/hedonistic-io/hedonistic-pki/releases
- **Documentation**: https://github.com/hedonistic-io/hedonistic-pki#readme

## Community

Contributions are welcome via pull requests on GitHub. The project includes 99 tests
covering config parsing, certificate generation, post-quantum key operations, memory
vault integrity, and deployment packaging. Security researchers are encouraged to
review the codebase and report findings per the project's security policy.

## About Hedonistic IO

Hedonistic, LLC builds open-source tools for infrastructure, security, and AI
orchestration. Based in California, the company develops software for teams that
value correctness, simplicity, and operational independence. hedonistic-pki is part
of the Hedonistic brand family of open-source tools.

## Contact

- **General**: info@hedonistic.io
- **Security**: security@hedonistic.io
- **Web**: https://hedonistic.io
- **GitHub**: https://github.com/hedonistic-io

---

hedonistic-pki is a trademark of Hedonistic, LLC. All other trademarks are the
property of their respective owners.
