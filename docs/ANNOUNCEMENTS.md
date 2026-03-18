# hedonistic-pki v1.0.0 channel announcements

Copy-paste ready. Each one is written for its audience.

---

## Hacker News (Show HN)

**Title:**

```
Show HN: hedonistic-pki – PKI ceremonies from a YAML file, single binary, post-quantum
```

**Body:**

I got tired of writing OpenSSL shell scripts every time we needed to stand up
a certificate hierarchy. So I wrote a tool that reads a YAML file describing
your CAs and leaf certs, figures out the dependency order, and generates
everything in one shot.

It is a single static Rust binary. No OpenSSL, no shared libraries, nothing
to install. You copy it to a USB stick and run it on your airgapped ceremony
machine.

Some things it does that I haven't seen elsewhere:

- Post-quantum keys (ML-DSA-87 + ML-KEM-1024, NIST FIPS 203/204) alongside
  classical RSA-4096 and Ed25519. Both chains must verify. You pick algorithms
  per cert.
- Private keys are encrypted in memory with ChaCha20-Poly1305 for the entire
  ceremony. On Linux, memory is locked and core dumps are disabled.
- Paper backups: generates printable HTML with QR codes encoding your keys.
  Large keys get split across multiple codes with SHA-256 checksums.
- Passphrase vault: encrypts all your ceremony passphrases into one file so
  you can transfer them to 1Password later.

99 tests. Apache-2.0. Security research welcome.

https://github.com/hedonistic-io/hedonistic-pki

---

## Reddit r/rust

**Title:**

```
hedonistic-pki v1.0.0: PKI ceremony tool, pure Rust, no OpenSSL, post-quantum
```

**Body:**

Just shipped hedonistic-pki. It generates complete certificate hierarchies from
a YAML config file. Root CAs, intermediates, leaf certs, post-quantum keys,
paper backups, deployment archives. One command.

I built it because PKI ceremonies on airgapped machines need a tool with zero
system dependencies. Rust made that possible. The release binary is about 2MB
with `opt-level = "z"`, LTO, and strip.

Crates doing the heavy lifting:

- `rcgen` for X.509 (RSA-4096, Ed25519)
- `ed25519-dalek` for pure-Rust Ed25519
- `ml-dsa` and `ml-kem` for NIST FIPS 203/204 post-quantum
- `chacha20poly1305` for the in-memory key vault
- `zeroize` for sensitive memory cleanup
- `qrcode` + `image` for paper backup generation

No `unsafe` in project code. 99 tests covering config parsing, cert generation,
PQ operations, vault integrity, paper backups, and deployment. Clippy clean,
2024 edition.

Feedback on the crate choices and the hybrid PQ model welcome. Contributions
welcome too.

https://github.com/hedonistic-io/hedonistic-pki

---

## Reddit r/netsec

**Title:**

```
hedonistic-pki: open-source PKI ceremony tool with ML-DSA-87/ML-KEM-1024, memory hardening, airgap design
```

**Body:**

Releasing hedonistic-pki v1.0.0. It runs PKI ceremonies on airgapped machines
from a declarative YAML config.

The security model:

**Memory**: Private keys are encrypted in-memory with ChaCha20-Poly1305 using
a 256-bit ephemeral key from OS CSPRNG. Decrypted into `Zeroizing` buffers
only when needed for signing, then cleared.

**Linux hardening**: `mlockall` prevents swapping. `PR_SET_DUMPABLE=0` kills
core dumps. `panic=abort` prevents stack unwinding leaks.

**Disk**: Keys are written with PKCS#8 + AES-256-CBC via scrypt. Nothing
unencrypted touches the filesystem.

**Post-quantum**: ML-DSA-87 (FIPS 204) and ML-KEM-1024 (FIPS 203) at security
level 5. Classical X.509 chain and PQ endorsement chain are independent but
cross-signed. Both must validate. Per-cert algorithm selection.

**Paper backups**: QR codes with multi-part splitting and SHA-256 checksums.

Single static Rust binary. No `unsafe` in project code. 99 tests. Apache-2.0.

Security research is explicitly welcome. There is a security policy with safe
harbor provisions. Reports go to security@hedonistic.io.

https://github.com/hedonistic-io/hedonistic-pki

---

## Reddit r/crypto

**Title:**

```
hedonistic-pki: open-source PKI tool with ML-DSA-87 + ML-KEM-1024 (FIPS 203/204) hybrid support
```

**Body:**

Released hedonistic-pki v1.0.0, a config-driven PKI ceremony tool with
post-quantum support. Sharing the PQ design for feedback.

The tool generates a classical X.509 chain and a parallel post-quantum
endorsement chain. Each cert in the hierarchy can specify its own algorithm:
`rsa_4096`, `ed25519`, `ml_dsa_87`, or `ml_kem_1024`. Or use `parallel_keys`
to generate multiple algorithm keys for the same cert.

PQ implementation:

- ML-DSA-87 (FIPS 204, formerly Dilithium-5) for signing at NIST security
  level 5. Each PQ signing key endorses its children, building a verifiable
  PQ trust hierarchy parallel to the X.509 chain.
- ML-KEM-1024 (FIPS 203, formerly Kyber-1024) for key encapsulation at
  security level 5. Generated for leaf certs.
- Hybrid model: the two chains are independent but cross-signed. Verification
  requires both chains to pass. This is a "both must validate" model, not
  "either suffices."

Uses the `ml-dsa` (v0.1.0-rc.7) and `ml-kem` (v0.3.0-rc.0) crates, which
implement the NIST final standards, not the draft Dilithium/Kyber specs.

I am interested in feedback on the hybrid cross-signing approach. Is "both
must validate" the right default, or should "either suffices" be an option?

https://github.com/hedonistic-io/hedonistic-pki

---

## Lobsters

**Title:**

```
hedonistic-pki: config-driven PKI ceremonies, single Rust binary, post-quantum
```

**Body:**

hedonistic-pki v1.0.0. Generates PKI hierarchies from a YAML config. Single
static binary, no OpenSSL, no system deps. Runs on airgapped machines.

Post-quantum support via ML-DSA-87 and ML-KEM-1024 (NIST FIPS 203/204).
In-memory key encryption with ChaCha20-Poly1305. Paper backups with QR codes.
Deployment archive generation. 99 tests. No `unsafe`. Apache-2.0.

https://github.com/hedonistic-io/hedonistic-pki

---

## Twitter/X

**Thread (6 posts):**

**1.**

```
Shipped hedonistic-pki v1.0.0.

It generates your entire PKI from a YAML file. Root CAs, intermediates, leaf
certs, post-quantum keys, paper backups, deployment archives. One binary, one
command, no OpenSSL.

https://github.com/hedonistic-io/hedonistic-pki
```

**2.**

```
The problem it solves: PKI ceremonies are hours of OpenSSL commands, bash
scripts, and praying you got the extensions right. Most teams skip them
entirely. That is how you end up with self-signed certs in production.
```

**3.**

```
How it works: you write a YAML config describing your cert hierarchy. The tool
topologically sorts the dependencies, generates keys, signs certs in order,
and packages everything. Dry-run mode validates before you touch a key.
```

**4.**

```
Post-quantum out of the box. ML-DSA-87 signatures and ML-KEM-1024 key
encapsulation (NIST FIPS 203/204, security level 5). Pick algorithms per cert.
Generate hybrid classical + PQ key pairs. Your PKI won't be a fire drill when
quantum computers show up.
```

**5.**

```
Other things it does:
- Paper backups with QR codes
- In-memory key encryption (ChaCha20-Poly1305)
- mlock + no core dumps on Linux
- Deployment archive generation
- Encrypted passphrase vault
- ~2MB static binary, zero deps
```

**6.**

```
Apache-2.0. Rust. 99 tests. Security research welcome.

If your team runs PKI ceremonies or has been meaning to, give it a look.

https://github.com/hedonistic-io/hedonistic-pki
```

---

## Mastodon

```
Shipped hedonistic-pki v1.0.0.

PKI ceremony tool. Describe your cert hierarchy in YAML, run one command on an
airgapped machine, get signed certificates + post-quantum keys + paper backups
+ deployment archives.

Single static Rust binary. No OpenSSL. No system deps. ML-DSA-87 + ML-KEM-1024
(NIST FIPS 203/204). Memory-hardened. 99 tests. Apache-2.0. Security research
welcome.

https://github.com/hedonistic-io/hedonistic-pki

#infosec #pki #postquantum #rust #opensource #cryptography
```

---

## LinkedIn

Releasing hedonistic-pki v1.0.0. It is an open-source PKI ceremony tool.

PKI ceremonies are the process of generating your organization's root CAs,
intermediate CAs, and leaf certificates on a secure machine. They are one of
those things that everyone agrees is important and nobody wants to do, because
the tooling is awful. You end up with a 40-page runbook full of OpenSSL
commands and a prayer that nobody fat-fingers a flag.

hedonistic-pki replaces that with a YAML config file. You describe your
certificate hierarchy, the tool figures out the build order, generates keys,
signs everything in the right sequence, and packages the output. It runs as a
single static binary on an airgapped machine with nothing else installed.

A few things that matter for security and compliance teams:

It supports NIST post-quantum algorithms (ML-DSA-87 and ML-KEM-1024, FIPS
203/204, security level 5) alongside classical RSA-4096 and Ed25519. You can
pick algorithms per certificate and generate hybrid key pairs. When the
post-quantum migration deadline arrives, your PKI is already ready.

It keeps keys encrypted in process memory with ChaCha20-Poly1305 for the
duration of the ceremony. On Linux, memory is locked and core dumps are
disabled. Keys hit disk encrypted. Nothing is plaintext at any point.

It generates paper backups (printable HTML with QR-encoded keys) and
deployment archives sorted by security classification, which makes audit and
disaster recovery planning straightforward.

Apache-2.0 licensed. Pre-built binaries for Linux and macOS. Security research
is welcome, and there is a published vulnerability disclosure policy.

https://github.com/hedonistic-io/hedonistic-pki

---

## Dev.to / Hashnode article

**Title:** We replaced our PKI ceremony runbook with a YAML file

**Subtitle:** How a 2MB Rust binary replaced 40 pages of OpenSSL commands

### Outline

**1. The runbook problem** (~300 words)

Talk about what a PKI ceremony actually is and why it matters. Not the
abstract version. The real version: you are in a windowless room with an
airgapped laptop, a USB stick, and a printed runbook. You type OpenSSL
commands for two hours. You mess up the pathlen constraint on the
intermediate and have to start over. You realize the paper backup procedure
was written for a different key algorithm. You go home at 9pm.

Every team that has done this has a horror story. Most teams that haven't
done it are running self-signed certs and hoping for the best.

**2. What if your ceremony was a config file?** (~200 words)

The core idea. Declarative infrastructure won everywhere else. Terraform for
cloud. Kubernetes for compute. Ansible for configuration. PKI should work
the same way. Describe what you want, let the tool figure out how.

Design constraints: must run on an airgapped machine with nothing installed.
Must produce encrypted keys, signed certs, paper backups, and deployment
packages. Must support post-quantum algorithms. Must fit on a USB stick.

**3. The config format** (~300 words)

Walk through the quickstart example. Show a real config. Explain the flat
list with parent references, how topological sorting works, the passphrase
grouping rules. Include the YAML from the quickstart example.

**4. Post-quantum: what it means in practice** (~250 words)

Explain ML-DSA-87 and ML-KEM-1024 without buzzwords. What these algorithms
are. Why security level 5. How the hybrid model works (both chains must
verify). How per-cert algorithm selection lets you migrate incrementally.

**5. Running your first ceremony** (~300 words)

Step by step. Download binary, write config, dry run, real run, check
output. Show what the output directory looks like. Show the paper backup
command. Show the passphrase vault workflow.

**6. What is next** (~100 words)

Contributing, security research invitation, links.
