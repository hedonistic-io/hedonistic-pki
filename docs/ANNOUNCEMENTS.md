# hedonistic-pki v1.0.0 -- Channel Announcements

Ready-to-post announcements for the v1.0.0 open-source release. Each section is
tailored to its audience and ready to copy-paste.

---

## Hacker News (Show HN)

**Title:**

```
Show HN: hedonistic-pki -- Config-driven PKI ceremonies, post-quantum, single binary
```

**Body:**

I'm releasing hedonistic-pki, a Rust tool that generates complete PKI hierarchies
from a YAML config file. You describe your CAs and leaf certs declaratively, and
the tool handles topological ordering, key generation, parent-child signing, paper
backups, and deployment packaging in one shot.

What makes it different from shelling out to OpenSSL:

- Single static binary, zero system dependencies. No OpenSSL, no shared libs.
  Copy it to a USB stick and run it on an airgapped ceremony machine.
- Post-quantum ready: ML-DSA-87 signatures and ML-KEM-1024 key encapsulation
  (NIST FIPS 203/204, security level 5) selectable per-cert alongside classical
  RSA-4096 and Ed25519.
- Memory hardened: all private keys encrypted in-memory with ChaCha20-Poly1305,
  ephemeral vault key from OS CSPRNG, mlock on Linux, core dumps disabled,
  zeroize on drop, panic=abort.
- Paper backups: generates printable HTML with QR/Aztec/PDF417 barcodes encoding
  private keys, with multi-part splitting and SHA-256 checksums.

99 tests, clippy clean, Rust 2024 edition. Apache-2.0 licensed.

GitHub: https://github.com/hedonistic-io/hedonistic-pki

---

## Reddit r/rust

**Title:**

```
hedonistic-pki v1.0.0: Config-driven PKI ceremony tool -- pure Rust, no OpenSSL, post-quantum ready
```

**Body:**

Just released hedonistic-pki, a PKI ceremony tool written in pure Rust. It generates
complete certificate hierarchies from a YAML config file -- root CAs, intermediates,
leaf certs -- with automatic topological sorting and parent-child signing.

**Why Rust?** The whole point of a ceremony tool is that it runs on airgapped machines
with nothing installed. A single static binary with no system dependencies was the
requirement, and Rust delivered. No OpenSSL, no GnuTLS, no shared libraries. The
release binary is about 2MB with `opt-level = "z"`, LTO, and strip.

**Crate highlights:**

- `rcgen` for X.509 certificate generation (RSA-4096, Ed25519)
- `ed25519-dalek` for pure-Rust Ed25519 key generation
- `ml-dsa` and `ml-kem` for NIST FIPS 203/204 post-quantum crypto
- `chacha20poly1305` for the in-memory key vault
- `zeroize` for guaranteed sensitive memory cleanup
- `qrcode` + `image` for paper backup barcode generation

No `unsafe` in the project code. The only `unsafe` is deep in the crypto
dependencies.

**Testing:** 99 tests covering config parsing, certificate generation, PQ key
operations, memory vault integrity, paper backup generation, and deployment
packaging. Clippy clean, Rust 2024 edition.

Apache-2.0 licensed. Contributions welcome.

- GitHub: https://github.com/hedonistic-io/hedonistic-pki
- Releases: https://github.com/hedonistic-io/hedonistic-pki/releases

---

## Reddit r/netsec

**Title:**

```
hedonistic-pki: Open-source PKI ceremony tool with post-quantum crypto, memory hardening, and airgap-safe design
```

**Body:**

Releasing hedonistic-pki v1.0.0, an open-source tool for running PKI ceremonies on
airgapped machines. It generates complete certificate hierarchies from a declarative
YAML config -- one command, one binary, no system dependencies.

**Security architecture:**

- **Memory vault**: All private key material encrypted in-memory with
  ChaCha20-Poly1305 using a 256-bit ephemeral key from OS CSPRNG. Keys are
  decrypted into `Zeroizing` buffers only when needed for signing, then immediately
  cleared.
- **Platform hardening** (Linux): `mlockall` prevents swapping, `PR_SET_DUMPABLE=0`
  disables core dumps, `panic=abort` prevents stack unwinding leaks.
- **Disk encryption**: Private keys written with PKCS#8 + AES-256-CBC via scrypt
  key derivation. Nothing leaves the process unencrypted.
- **Post-quantum**: ML-DSA-87 (FIPS 204) signatures and ML-KEM-1024 (FIPS 203) key
  encapsulation at security level 5. Hybrid model -- classical and PQ chains are
  independent but cross-signed. Both must validate.
- **Paper backups**: QR/Aztec/PDF417 barcodes with multi-part splitting and SHA-256
  checksums for disaster recovery.

Written in Rust with no `unsafe` in project code. 99 tests. Apache-2.0.

Security research is explicitly welcome. The project has a security policy with safe
harbor provisions. Reports to security@hedonistic.io.

GitHub: https://github.com/hedonistic-io/hedonistic-pki

---

## Reddit r/crypto (Cryptography)

**Title:**

```
hedonistic-pki: Open-source PKI tool with ML-DSA-87 and ML-KEM-1024 (FIPS 203/204) hybrid support
```

**Body:**

I've released hedonistic-pki v1.0.0, a config-driven PKI ceremony tool that supports
both classical and post-quantum cryptographic algorithms. Wanted to share the PQ
implementation details for feedback from this community.

**Post-quantum implementation:**

- **ML-DSA-87** (FIPS 204, formerly Dilithium-5): Used for digital signatures at
  NIST security level 5. The tool generates a PQ signature chain that parallels
  the classical X.509 chain. Each PQ signing key endorses its children, creating
  a verifiable PQ trust hierarchy.
- **ML-KEM-1024** (FIPS 203, formerly Kyber-1024): Key encapsulation at security
  level 5. Generated for leaf certificates to enable post-quantum encrypted
  distribution channels.
- **Hybrid model**: The classical X.509 chain and PQ endorsement chain are
  independent but cross-signed. Verification requires both chains to validate --
  this is a "both must pass" hybrid, not "either suffices."
- **Per-cert algorithm selection**: Each certificate in the hierarchy can specify
  its own algorithm (`rsa_4096`, `ed25519`, `ml_dsa_87`, `ml_kem_1024`), or use
  `parallel_keys` to generate multiple algorithm keys for the same cert.

The PQ implementation uses the `ml-dsa` (v0.1.0-rc.7) and `ml-kem` (v0.3.0-rc.0)
Rust crates, which implement the NIST final standards (not the draft Dilithium/Kyber
specs).

Interested in feedback on the hybrid cross-signing approach and whether the "both
must validate" model is the right default vs. offering "either suffices" as an option.

GitHub: https://github.com/hedonistic-io/hedonistic-pki

---

## Lobsters

**Title:**

```
hedonistic-pki: Config-driven PKI ceremonies in a single Rust binary, with post-quantum crypto
```

**Body:**

hedonistic-pki v1.0.0 is out. It's a Rust tool that generates complete PKI
hierarchies from a YAML config. Designed for airgapped ceremony machines -- single
static binary, no OpenSSL, no system dependencies.

Notable bits: post-quantum support via ML-DSA-87 and ML-KEM-1024 (NIST FIPS
203/204), in-memory key encryption with ChaCha20-Poly1305, paper backups with
barcode-encoded keys, and automatic deployment archive generation. 99 tests,
no `unsafe`, Apache-2.0.

https://github.com/hedonistic-io/hedonistic-pki

---

## Twitter/X Thread

**Tweet 1 (Hook):**

```
Releasing hedonistic-pki v1.0.0 -- an open-source PKI ceremony tool.

One YAML config. One command. One binary. Your entire certificate hierarchy, generated on an airgapped machine with zero system dependencies.
```

**Tweet 2 (Problem):**

```
PKI ceremonies today mean hours of OpenSSL commands, copy-pasting between terminals, and praying you got the extensions right.

Most teams skip them entirely because the tooling is hostile. That's how you end up with self-signed certs in production and expired roots at 2am.
```

**Tweet 3 (Solution):**

```
hedonistic-pki reads a YAML file that describes your CAs and leaf certs. It topologically sorts the hierarchy, generates keys, signs certificates in order, and packages everything for deployment.

Dry-run mode validates your config before you touch a key.
```

**Tweet 4 (PQ):**

```
Post-quantum ready out of the box.

ML-DSA-87 signatures + ML-KEM-1024 key encapsulation (NIST FIPS 203/204, security level 5). Select per-cert or generate hybrid classical + PQ key pairs.

Your PKI doesn't have to be a migration emergency when Q-day arrives.
```

**Tweet 5 (Features):**

```
Other things it does:
- Paper backups with QR/Aztec/PDF417 barcodes
- In-memory key encryption (ChaCha20-Poly1305)
- mlock + no core dumps on Linux
- Deployment archive generation
- Passphrase vault for 1Password transfer
- ~2MB static binary
```

**Tweet 6 (CTA):**

```
Apache-2.0. Written in Rust. 99 tests. Security research welcome.

GitHub: https://github.com/hedonistic-io/hedonistic-pki

If your team runs PKI ceremonies (or should be), give it a look.
```

---

## Mastodon/Fediverse

```
Releasing hedonistic-pki v1.0.0 -- a config-driven PKI ceremony tool.

Describe your certificate hierarchy in YAML, run one command on an airgapped machine, get signed certs + post-quantum keys + paper backups + deployment archives.

Single static Rust binary. No OpenSSL. No system deps. ML-DSA-87 + ML-KEM-1024 (NIST FIPS 203/204). Memory-hardened. 99 tests. Apache-2.0.

https://github.com/hedonistic-io/hedonistic-pki

#infosec #pki #postquantum #rust #opensource #cryptography #security
```

---

## LinkedIn

Announcing the open-source release of hedonistic-pki v1.0.0.

PKI ceremonies are one of those critical infrastructure tasks that most organizations
either do manually with error-prone OpenSSL scripts or outsource entirely. Neither
option scales well, and neither prepares you for the post-quantum transition that
NIST has been standardizing since 2024.

hedonistic-pki takes a different approach: describe your entire certificate hierarchy
in a YAML configuration file, and the tool handles key generation, certificate
signing, post-quantum key generation, paper backups, and deployment packaging in a
single automated run.

What makes it relevant for security and compliance teams:

- Runs on airgapped machines with zero system dependencies -- no OpenSSL, no package
  managers, no network calls
- Supports NIST FIPS 203/204 post-quantum algorithms (ML-DSA-87, ML-KEM-1024) at
  security level 5, alongside classical RSA-4096 and Ed25519
- Memory-hardened: private keys are encrypted in process memory and zeroized after use
- Generates auditable deployment archives and printable paper backups for disaster
  recovery
- Deterministic, repeatable ceremonies from version-controlled config files

The tool is Apache-2.0 licensed with pre-built binaries for Linux and macOS. Whether
you are standing up a new PKI, preparing for post-quantum migration, or just want to
stop hand-rolling OpenSSL commands, it is worth evaluating.

GitHub: https://github.com/hedonistic-io/hedonistic-pki

---

## Dev.to / Hashnode Article Outline

**Title:** Stop Hand-Rolling OpenSSL Commands: Config-Driven PKI Ceremonies with hedonistic-pki

**Subtitle:** How a single YAML file and a Rust binary replaced our entire PKI ceremony runbook

### Outline (~1500 words)

**1. The Problem: PKI Ceremonies Are Painful (300 words)**
- What a PKI ceremony actually is and why organizations need them
- The traditional approach: dozens of OpenSSL commands, bash scripts, printed
  runbooks, and multiple operators
- Common failure modes: wrong extensions, expired intermediates, lost root keys,
  untested backup procedures
- Why most small-to-mid teams skip formal ceremonies and accumulate technical debt

**2. The Idea: What If Your PKI Was a Config File? (200 words)**
- Declarative infrastructure has won everywhere else (Terraform, Kubernetes,
  Ansible) -- why not PKI?
- Design goals: zero dependencies, airgap-safe, post-quantum ready, paper backups
- Why Rust: static binary requirement, memory safety for key material, no runtime

**3. How It Works: Architecture Overview (300 words)**
- The YAML config schema: hierarchy as a flat list with parent references
- Topological sorting: the tool figures out build order
- Ceremony flow: config parse, passphrase collection, key generation, certificate
  signing, PQ key generation, paper backup, deployment packaging
- Memory vault: ChaCha20-Poly1305 in-memory encryption of all key material
- Code walkthrough of the example quickstart config

**4. Post-Quantum: Preparing for Q-Day (250 words)**
- NIST FIPS 203/204: ML-DSA-87 and ML-KEM-1024
- The hybrid model: classical + PQ chains, both must validate
- Per-cert algorithm selection and parallel_keys for migration
- Why security level 5 was chosen as the default

**5. Getting Started: Your First Ceremony (300 words)**
- Installing the binary (download or build from source)
- Writing a minimal config (root CA + intermediate + leaf)
- Running a dry run
- Running the real ceremony
- What the output directory looks like
- Generating paper backups
- Transferring passphrases via the encrypted vault

**6. What's Next (150 words)**
- Planned features: OCSP responder config, certificate templates, HSM integration
- Contributing: how to get involved
- Security research welcome
- Link to GitHub, releases, and security policy
