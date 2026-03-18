# hedonistic-pki v1.0.0

**For immediate release. March 18, 2026.**

Hedonistic, LLC has released hedonistic-pki, an open-source tool that generates
complete PKI certificate hierarchies from a YAML config file. It is a single
static Rust binary with no system dependencies. It runs on airgapped machines.
It does not require OpenSSL.

The tool exists because PKI ceremonies are needlessly painful. The standard
approach involves dozens of OpenSSL commands, hand-written shell scripts, and
printed runbooks that nobody trusts. Most small teams skip the process entirely
and accumulate self-signed certificates until something breaks at 2am.

hedonistic-pki replaces all of that with a config file. You describe your root
CAs, intermediates, and leaf certificates as a flat YAML list. The tool figures
out the dependency order, generates keys, signs certificates, and packages
everything for deployment. One command, start to finish.

It also generates post-quantum keys. Every certificate in the hierarchy can
produce ML-DSA-87 signing keys and ML-KEM-1024 encapsulation keys (NIST FIPS
203 and 204, security level 5) alongside classical RSA-4096 or Ed25519. The
classical and post-quantum chains are independent but cross-signed. Both must
verify.

All private keys are encrypted in memory with ChaCha20-Poly1305 for the
duration of the ceremony. On Linux, memory pages are locked and core dumps are
disabled. Keys hit disk encrypted with PKCS#8 and AES-256-CBC. The tool also
generates printable paper backups with QR-encoded keys and deployment archives
sorted by security classification.

The project ships under the Apache-2.0 license with pre-built binaries for
Linux (x86_64, aarch64) and macOS (Apple Silicon, Intel). Security research
is welcome. The project has a published security policy with responsible
disclosure instructions at security@hedonistic.io.

**Links**

- Source: https://github.com/hedonistic-io/hedonistic-pki
- Releases: https://github.com/hedonistic-io/hedonistic-pki/releases
- Documentation: https://hedonistic-io.github.io/hedonistic-pki/

**About Hedonistic IO**

Hedonistic, LLC builds open-source tools for infrastructure and security.
Based in California.

- Web: https://hedonistic.io
- Email: info@hedonistic.io
- Security: security@hedonistic.io
