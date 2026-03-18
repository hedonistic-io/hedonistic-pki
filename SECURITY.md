# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in hedonistic-pki, please report it
responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

Send your report to: **security@hedonistic.io**

### What to Include

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected version(s)
- Potential impact assessment
- Suggested fix, if you have one

### Response Timeline

- **Acknowledgment**: Within 48 hours of receipt
- **Initial assessment**: Within 7 calendar days
- **Fix target**: Depends on severity, but we aim for patches within 30 days for
  critical issues and 90 days for lower-severity findings

### What Qualifies as a Security Issue

The following categories are in scope:

- **Memory safety**: Buffer overflows, use-after-free, uninitialized memory reads,
  or any bypass of the memory vault protections
- **Key material leakage**: Private keys written to disk unencrypted, leaked via
  error messages, logs, core dumps, or swap
- **Cryptographic weaknesses**: Flaws in the use of ChaCha20-Poly1305, AES-256-GCM,
  RSA-4096, Ed25519, ML-DSA-87, or ML-KEM-1024 -- including weak RNG seeding,
  nonce reuse, or incorrect parameter choices
- **Vault bypass**: Any way to extract plaintext key material from the encrypted
  memory vault without the correct passphrase
- **Zeroization failures**: Sensitive data remaining in memory after it should have
  been cleared
- **Configuration injection**: Malicious YAML/JSON configs that cause unintended
  behavior beyond the intended ceremony scope
- **Path traversal**: File writes outside the intended output directory
- **Dependency vulnerabilities**: Security issues in direct dependencies that affect
  hedonistic-pki's security posture

### Out of Scope

- Denial of service via large config files (the tool is designed for interactive use)
- Issues that require physical access to the ceremony machine (airgap assumption)
- Social engineering attacks
- Vulnerabilities in software not maintained by this project

## Safe Harbor

We consider security research conducted in good faith to be authorized and will not
pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and
  service disruption
- Report vulnerabilities promptly and provide sufficient detail for reproduction
- Do not publicly disclose the vulnerability before a fix is available and a
  reasonable disclosure timeline has been agreed upon
- Do not exploit the vulnerability beyond what is necessary to demonstrate it

## Credit and Acknowledgment

We gratefully acknowledge security researchers who report valid vulnerabilities.
With your permission, we will credit you by name (or handle) in the release notes
for the version that includes the fix. If you prefer to remain anonymous, we will
respect that.

## PGP Key

A PGP key for encrypted vulnerability reports is coming soon. In the interim, please
use the email address above. If your report contains sensitive material (e.g.,
working exploit code), note that in the subject line and we will coordinate a secure
channel.

## Contact

- Security reports: security@hedonistic.io
- General inquiries: info@hedonistic.io
- Project: https://github.com/hedonistic-io/hedonistic-pki
