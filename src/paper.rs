//! Paper backup generator — printable HTML with QR codes and full PEM text
//!
//! Generates self-contained HTML files optimized for printing that contain:
//!   - QR code(s) for each key (SVG, inline)
//!   - Full PEM text with line numbers (manual transcription fallback)
//!   - SHA-256 fingerprints for verification after recovery
//!   - Cover page with table of contents and recovery instructions
//!
//! For RSA-4096 keys (~3.4KB PEM): split across multiple QR codes
//! For Ed25519 keys (~300B PEM): single QR code
//!
//! Multi-part QR format: `HEDON-PKI:N/M:<data>`

use anyhow::{Context, Result};
use qrcode::QrCode;
use qrcode::render::svg;
use sha2::{Digest, Sha256};

/// Maximum bytes per QR chunk — safe for QR binary mode with ECC level M
const QR_CHUNK_SIZE: usize = 1600;

/// Configuration for paper backup generation
pub struct PaperBackupConfig {
    pub title: String,
    pub output_path: String,
}

/// A key to include in the paper backup
pub struct KeyForBackup {
    pub label: String,
    pub key_type: String,
    pub criticality: Criticality,
    pub pem_content: String,
    pub file_path: String,
}

/// Criticality level — drives visual styling on the printed page
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criticality {
    Critical, // Root CA — red
    High,     // Intermediate CAs — orange
    Medium,   // Leaf signers — yellow
    Deploy,   // Deployment keys — blue
}

impl Criticality {
    fn label(self) -> &'static str {
        match self {
            Criticality::Critical => "CRITICAL",
            Criticality::High => "HIGH",
            Criticality::Medium => "MEDIUM",
            Criticality::Deploy => "DEPLOY",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Criticality::Critical => "#c0392b",
            Criticality::High => "#e67e22",
            Criticality::Medium => "#f1c40f",
            Criticality::Deploy => "#2980b9",
        }
    }

    fn bg_color(self) -> &'static str {
        match self {
            Criticality::Critical => "#fdedec",
            Criticality::High => "#fef5e7",
            Criticality::Medium => "#fef9e7",
            Criticality::Deploy => "#ebf5fb",
        }
    }
}

/// Generate the complete paper backup HTML file
pub fn generate_paper_backup(config: &PaperBackupConfig, keys: &[KeyForBackup]) -> Result<String> {
    let date = current_date_string();

    let mut html = String::with_capacity(64 * 1024);

    // Document head
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} — Paper Backup</title>
<style>
{css}
</style>
</head>
<body>
"#,
        title = html_escape(&config.title),
        css = CSS_STYLES,
    ));

    // Cover page
    html.push_str(&generate_cover_page(config, keys, &date));

    // Key pages
    for key in keys {
        html.push_str(&generate_key_page(key)?);
    }

    html.push_str("</body>\n</html>\n");
    Ok(html)
}

/// Generate QR code(s) for a PEM string, returns SVG strings.
/// For data > QR_CHUNK_SIZE bytes, splits into multiple QR codes with headers.
pub fn generate_qr_codes(data: &str, label: &str) -> Result<Vec<String>> {
    let bytes = data.as_bytes();

    if bytes.len() <= QR_CHUNK_SIZE {
        let code =
            QrCode::new(bytes).with_context(|| format!("Failed to encode QR for {label}"))?;
        let svg_str = code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .max_dimensions(300, 300)
            .quiet_zone(true)
            .build();
        return Ok(vec![svg_str]);
    }

    // Split into chunks with sequence headers
    let chunks = split_into_chunks(data);
    let total = chunks.len();
    let mut svgs = Vec::with_capacity(total);

    for (i, chunk) in chunks.iter().enumerate() {
        let prefixed = format!("HEDON-PKI:{}/{}:{}", i + 1, total, chunk);
        let code = QrCode::new(prefixed.as_bytes()).with_context(|| {
            format!("Failed to encode QR part {}/{} for {}", i + 1, total, label)
        })?;
        let svg_str = code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .max_dimensions(300, 300)
            .quiet_zone(true)
            .build();
        svgs.push(svg_str);
    }

    Ok(svgs)
}

/// Compute SHA-256 fingerprint of key content
pub fn compute_fingerprint(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// ═══════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════

/// Split data into chunks of QR_CHUNK_SIZE bytes
fn split_into_chunks(data: &str) -> Vec<&str> {
    let bytes = data.as_bytes();
    let mut chunks = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        let end = std::cmp::min(start + QR_CHUNK_SIZE, bytes.len());
        // PEM is ASCII, so byte boundaries are char boundaries
        chunks.push(&data[start..end]);
        start = end;
    }

    chunks
}

fn current_date_string() -> String {
    // Use compile-time or runtime date. We avoid external chrono dependency.
    // For a CLI tool, the build date is sufficient.
    // Format: YYYY-MM-DD
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple date calculation (no leap second precision needed for a label)
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn generate_cover_page(config: &PaperBackupConfig, keys: &[KeyForBackup], date: &str) -> String {
    let mut toc_rows = String::new();
    for (i, key) in keys.iter().enumerate() {
        toc_rows.push_str(&format!(
            r#"<tr>
<td>{num}</td>
<td>{label}</td>
<td>{key_type}</td>
<td><span class="badge" style="background:{color};color:#fff">{crit}</span></td>
<td style="font-family:monospace;font-size:0.75em">{fingerprint}</td>
</tr>
"#,
            num = i + 1,
            label = html_escape(&key.label),
            key_type = html_escape(&key.key_type),
            color = key.criticality.color(),
            crit = key.criticality.label(),
            fingerprint = &compute_fingerprint(&key.pem_content)[..16],
        ));
    }

    format!(
        r#"<div class="page cover-page">
<h1>{title}</h1>
<h2>Paper Key Backup</h2>
<p class="date">Generated: {date}</p>

<h3>Table of Contents</h3>
<table class="toc-table">
<thead>
<tr><th>#</th><th>Key</th><th>Type</th><th>Criticality</th><th>Fingerprint (first 16)</th></tr>
</thead>
<tbody>
{toc_rows}
</tbody>
</table>

<h3>Recovery Procedure</h3>
<ol class="instructions">
<li>Scan the QR code(s) for each key using any QR scanner app.</li>
<li>For multi-part keys: scan all parts and concatenate in order (parts are prefixed
    with <code>HEDON-PKI:N/M:</code> — strip the prefix and join).</li>
<li>Save the reconstructed PEM text to a file (e.g., <code>recovered.key</code>).</li>
<li>Verify the SHA-256 fingerprint matches the one printed on the key's page:
    <br><code>sha256sum recovered.key</code></li>
<li>Test the key: <code>openssl rsa -in recovered.key -check -noout</code> (RSA)
    or verify Ed25519 with the appropriate tool.</li>
<li>All private keys are passphrase-protected. You will need the passphrase
    (stored separately) to use the recovered key.</li>
</ol>

<h3>QR Code Format</h3>
<p>Single-part keys encode the raw PEM text directly.</p>
<p>Multi-part keys use the format: <code>HEDON-PKI:N/M:&lt;data&gt;</code></p>
<ul>
<li><strong>N</strong> — part number (1-indexed)</li>
<li><strong>M</strong> — total number of parts</li>
<li><strong>data</strong> — the PEM fragment for this part</li>
</ul>
<p>To reassemble: strip the <code>HEDON-PKI:N/M:</code> prefix from each part,
sort by N, and concatenate.</p>

<div class="warning-box">
<strong>SECURITY WARNING</strong><br>
This document contains cryptographic private keys. Store in a locked safe
or security deposit box. Destroy all copies when no longer needed.
Do not photograph or digitize this document on a networked device.
</div>
</div>
"#,
        title = html_escape(&config.title),
        date = date,
        toc_rows = toc_rows,
    )
}

fn generate_key_page(key: &KeyForBackup) -> Result<String> {
    let fingerprint = compute_fingerprint(&key.pem_content);
    let qr_svgs = generate_qr_codes(&key.pem_content, &key.label)?;
    let is_multipart = qr_svgs.len() > 1;

    let mut page = String::with_capacity(16 * 1024);

    // Page start
    page.push_str(&format!(
        r#"<div class="page key-page" style="border-top: 4px solid {color}">
<div class="key-header">
<h2>{label}</h2>
<span class="badge" style="background:{color};color:#fff">{crit}</span>
<span class="key-type">{key_type}</span>
</div>

<div class="fingerprint">
<strong>SHA-256:</strong> <code>{fingerprint}</code>
</div>

<div class="file-path">
<strong>Original path:</strong> <code>{file_path}</code>
</div>
"#,
        color = key.criticality.color(),
        label = html_escape(&key.label),
        crit = key.criticality.label(),
        key_type = html_escape(&key.key_type),
        fingerprint = fingerprint,
        file_path = html_escape(&key.file_path),
    ));

    // QR codes
    page.push_str("<div class=\"qr-section\">\n");
    if is_multipart {
        page.push_str(&format!(
            "<p class=\"multipart-notice\">Key split across <strong>{}</strong> QR codes. \
             Scan all parts and reassemble in order.</p>\n",
            qr_svgs.len()
        ));
    }

    for (i, svg) in qr_svgs.iter().enumerate() {
        if is_multipart {
            page.push_str(&format!(
                "<div class=\"qr-part\">\n<p class=\"part-label\">Part {} of {}</p>\n{}\n</div>\n",
                i + 1,
                qr_svgs.len(),
                svg,
            ));
        } else {
            page.push_str(&format!("<div class=\"qr-single\">\n{}\n</div>\n", svg));
        }
    }
    page.push_str("</div>\n");

    // Reassembly instructions for multi-part
    if is_multipart {
        page.push_str(
            r#"<div class="reassembly-instructions">
<strong>Reassembly:</strong> Each QR contains <code>HEDON-PKI:N/M:&lt;data&gt;</code>.
Strip the prefix from each scanned part, sort by part number, and concatenate
to reconstruct the full PEM file.
</div>
"#,
        );
    }

    // Full PEM text with line numbers
    page.push_str("<div class=\"pem-section\">\n");
    page.push_str("<h3>Full PEM Text (manual transcription fallback)</h3>\n");
    page.push_str("<pre class=\"pem-text\">");
    for (i, line) in key.pem_content.lines().enumerate() {
        page.push_str(&format!(
            "<span class=\"line-num\">{:>3}</span> {}\n",
            i + 1,
            html_escape(line),
        ));
    }
    page.push_str("</pre>\n</div>\n");

    // Reconstruction instructions
    page.push_str(&format!(
        r#"<div class="reconstruction">
<h3>Reconstruction &amp; Verification</h3>
<ol>
<li>Scan QR code(s) and save to file: <code>{filename}</code></li>
<li>Verify fingerprint: <code>sha256sum {filename}</code>
    <br>Expected: <code>{fingerprint}</code></li>
<li>Test key: <code>{test_cmd}</code></li>
</ol>
</div>
"#,
        filename = recovery_filename(key),
        fingerprint = fingerprint,
        test_cmd = html_escape(&test_command(key)),
    ));

    // Warning box
    page.push_str(
        r#"<div class="warning-box">
<strong>WARNING:</strong> This key is passphrase-protected.
The passphrase is NOT printed on this page.
You must have the passphrase stored separately to use this key.
</div>
"#,
    );

    page.push_str("</div>\n");
    Ok(page)
}

fn recovery_filename(key: &KeyForBackup) -> String {
    // Derive a filename from the label
    let base = key
        .label
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .to_lowercase();
    format!("{base}.key")
}

fn test_command(key: &KeyForBackup) -> String {
    if key.key_type.contains("Ed25519") || key.key_type.contains("ed25519") {
        format!("openssl pkey -in {} -check -noout", recovery_filename(key),)
    } else {
        format!("openssl rsa -in {} -check -noout", recovery_filename(key),)
    }
}

// ═══════════════════════════════════════════════════════════════
// CSS — all inline, print-optimized
// ═══════════════════════════════════════════════════════════════

const CSS_STYLES: &str = r#"
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: "Courier New", Courier, monospace;
    font-size: 11pt;
    line-height: 1.4;
    color: #1a1a1a;
    background: #fff;
}

.page {
    padding: 20mm;
    page-break-after: always;
    min-height: 100vh;
}

.page:last-child {
    page-break-after: auto;
}

.cover-page h1 {
    font-size: 24pt;
    margin-bottom: 4pt;
    border-bottom: 3px solid #2c3e50;
    padding-bottom: 8pt;
}

.cover-page h2 {
    font-size: 16pt;
    color: #555;
    margin-bottom: 16pt;
}

.cover-page h3 {
    font-size: 13pt;
    margin-top: 20pt;
    margin-bottom: 8pt;
    border-bottom: 1px solid #bdc3c7;
    padding-bottom: 4pt;
}

.date {
    font-size: 10pt;
    color: #777;
    margin-bottom: 16pt;
}

.toc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    margin-bottom: 16pt;
}

.toc-table th,
.toc-table td {
    border: 1px solid #bdc3c7;
    padding: 4pt 6pt;
    text-align: left;
}

.toc-table th {
    background: #ecf0f1;
    font-weight: bold;
}

.instructions {
    margin-left: 20pt;
    margin-bottom: 12pt;
}

.instructions li {
    margin-bottom: 6pt;
}

.badge {
    display: inline-block;
    padding: 2pt 8pt;
    border-radius: 3pt;
    font-size: 8pt;
    font-weight: bold;
    letter-spacing: 0.5pt;
}

.key-header {
    display: flex;
    align-items: center;
    gap: 12pt;
    margin-bottom: 12pt;
}

.key-header h2 {
    font-size: 16pt;
    flex-grow: 1;
}

.key-type {
    font-size: 10pt;
    color: #555;
    border: 1px solid #bdc3c7;
    padding: 2pt 6pt;
    border-radius: 2pt;
}

.fingerprint {
    font-size: 9pt;
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    padding: 6pt 10pt;
    margin-bottom: 8pt;
    word-break: break-all;
}

.file-path {
    font-size: 8pt;
    color: #777;
    margin-bottom: 12pt;
}

.qr-section {
    margin-bottom: 16pt;
    text-align: center;
}

.qr-single,
.qr-part {
    display: inline-block;
    margin: 8pt;
    vertical-align: top;
}

.qr-part {
    border: 1px solid #dee2e6;
    padding: 8pt;
}

.part-label {
    font-size: 9pt;
    font-weight: bold;
    margin-bottom: 4pt;
    color: #2c3e50;
}

.multipart-notice {
    font-size: 10pt;
    color: #c0392b;
    margin-bottom: 8pt;
}

.pem-section {
    margin-bottom: 16pt;
}

.pem-section h3 {
    font-size: 11pt;
    margin-bottom: 6pt;
    border-bottom: 1px solid #dee2e6;
    padding-bottom: 4pt;
}

.pem-text {
    font-size: 7pt;
    line-height: 1.3;
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    padding: 8pt;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-wrap: break-word;
}

.line-num {
    color: #999;
    user-select: none;
    display: inline-block;
    width: 3ch;
    text-align: right;
    margin-right: 1ch;
}

.reconstruction {
    margin-bottom: 12pt;
}

.reconstruction h3 {
    font-size: 11pt;
    margin-bottom: 6pt;
}

.reconstruction ol {
    margin-left: 16pt;
    font-size: 9pt;
}

.reconstruction li {
    margin-bottom: 4pt;
}

.reassembly-instructions {
    font-size: 9pt;
    background: #eaf2f8;
    border: 1px solid #aed6f1;
    padding: 6pt 10pt;
    margin-bottom: 12pt;
}

.warning-box {
    background: #fef9e7;
    border: 2px solid #f39c12;
    padding: 10pt 14pt;
    font-size: 9pt;
    margin-top: 12pt;
}

code {
    background: #ecf0f1;
    padding: 1pt 4pt;
    font-size: inherit;
    font-family: "Courier New", Courier, monospace;
}

@media print {
    body { background: none; }
    .page { padding: 15mm; min-height: auto; }
    .warning-box { border-width: 2pt; }
    .qr-section svg { max-width: 250pt; height: auto; }
}
"#;

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ED25519_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGrpBFwsPmXGc4AI2DGWzLk7PGBfhtESxEiSUfcD8Htc
-----END PRIVATE KEY-----";

    fn sample_rsa_pem() -> String {
        // Generate a ~3400-byte fake RSA PEM for multi-part testing
        let mut pem = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        // ~48 chars per line, ~50 lines ≈ 2400 chars of base64 content
        for i in 0..60 {
            let line: String = format!(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklm{:03}+/=",
                i
            );
            // Trim or pad to 64 chars
            let trimmed = &line[..std::cmp::min(line.len(), 64)];
            pem.push_str(trimmed);
            pem.push('\n');
        }
        pem.push_str("-----END RSA PRIVATE KEY-----\n");
        pem
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let fp1 = compute_fingerprint("hello world");
        let fp2 = compute_fingerprint("hello world");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_fingerprint_different_inputs() {
        let fp1 = compute_fingerprint("key-a");
        let fp2 = compute_fingerprint("key-b");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_qr_single_small_key() {
        let svgs = generate_qr_codes(SAMPLE_ED25519_PEM, "test-ed25519").unwrap();
        assert_eq!(svgs.len(), 1);
        assert!(svgs[0].contains("<svg"));
        assert!(svgs[0].contains("</svg>"));
    }

    #[test]
    fn test_qr_multipart_large_key() {
        let pem = sample_rsa_pem();
        assert!(
            pem.len() > QR_CHUNK_SIZE,
            "Test PEM should exceed chunk size: {} <= {}",
            pem.len(),
            QR_CHUNK_SIZE,
        );

        let svgs = generate_qr_codes(&pem, "test-rsa").unwrap();
        assert!(svgs.len() > 1, "Should produce multiple QR codes");

        for svg in &svgs {
            assert!(svg.contains("<svg"));
        }
    }

    #[test]
    fn test_split_into_chunks() {
        let data = "A".repeat(QR_CHUNK_SIZE * 2 + 100);
        let chunks = split_into_chunks(&data);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), QR_CHUNK_SIZE);
        assert_eq!(chunks[1].len(), QR_CHUNK_SIZE);
        assert_eq!(chunks[2].len(), 100);

        // Concatenation must equal original
        let reconstructed: String = chunks.iter().copied().collect();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_split_exact_boundary() {
        let data = "B".repeat(QR_CHUNK_SIZE);
        let chunks = split_into_chunks(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), QR_CHUNK_SIZE);
    }

    #[test]
    fn test_split_empty() {
        let chunks = split_into_chunks("");
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_generate_paper_backup_structure() {
        let config = PaperBackupConfig {
            title: "Test PKI Backup".to_string(),
            output_path: "/tmp/test-backup.html".to_string(),
        };

        let keys = vec![
            KeyForBackup {
                label: "Root CA".to_string(),
                key_type: "Ed25519".to_string(),
                criticality: Criticality::Critical,
                pem_content: SAMPLE_ED25519_PEM.to_string(),
                file_path: "/pki/root-ca/root-ca.key".to_string(),
            },
            KeyForBackup {
                label: "Intermediate CA".to_string(),
                key_type: "Ed25519".to_string(),
                criticality: Criticality::High,
                pem_content: SAMPLE_ED25519_PEM.to_string(),
                file_path: "/pki/intermediate-ca/intermediate-ca.key".to_string(),
            },
        ];

        let html = generate_paper_backup(&config, &keys).unwrap();

        // Validate overall structure
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<style>"));

        // Cover page
        assert!(html.contains("Test PKI Backup"));
        assert!(html.contains("Paper Key Backup"));
        assert!(html.contains("Table of Contents"));
        assert!(html.contains("Recovery Procedure"));
        assert!(html.contains("QR Code Format"));

        // Key pages
        assert!(html.contains("Root CA"));
        assert!(html.contains("Intermediate CA"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("HIGH"));

        // QR codes present
        assert!(html.contains("<svg"));

        // PEM text present
        assert!(html.contains("BEGIN PRIVATE KEY"));

        // Fingerprints present
        assert!(html.contains("SHA-256:"));

        // Warning boxes
        assert!(html.contains("passphrase-protected"));

        // Print CSS
        assert!(html.contains("@media print"));

        // Self-contained: no external stylesheets, scripts, or fonts
        assert!(!html.contains("<link "), "No external stylesheets");
        assert!(!html.contains("<script src"), "No external scripts");
        assert!(!html.contains("@import"), "No CSS imports");
    }

    #[test]
    fn test_generate_paper_backup_multipart_rsa() {
        let config = PaperBackupConfig {
            title: "RSA Test".to_string(),
            output_path: "/tmp/rsa-backup.html".to_string(),
        };

        let pem = sample_rsa_pem();
        let keys = vec![KeyForBackup {
            label: "RSA Root CA".to_string(),
            key_type: "RSA-4096".to_string(),
            criticality: Criticality::Critical,
            pem_content: pem,
            file_path: "/pki/root-ca.key".to_string(),
        }];

        let html = generate_paper_backup(&config, &keys).unwrap();

        // Should have multi-part notice
        assert!(html.contains("split across"));
        assert!(html.contains("Part 1 of"));
        assert!(html.contains("HEDON-PKI:N/M:"));
        assert!(html.contains("Reassembly"));
    }

    #[test]
    fn test_criticality_colors() {
        // Ensure all variants have distinct colors
        let colors: Vec<&str> = [
            Criticality::Critical,
            Criticality::High,
            Criticality::Medium,
            Criticality::Deploy,
        ]
        .iter()
        .map(|c| c.color())
        .collect();

        for (i, a) in colors.iter().enumerate() {
            for (j, b) in colors.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Criticality colors must be unique");
                }
            }
        }
    }

    #[test]
    fn test_recovery_filename() {
        let key = KeyForBackup {
            label: "1: Root CA (Example Organization)".to_string(),
            key_type: "RSA-4096".to_string(),
            criticality: Criticality::Critical,
            pem_content: String::new(),
            file_path: String::new(),
        };
        let name = recovery_filename(&key);
        assert!(name.ends_with(".key"));
        assert!(!name.contains(' '));
        assert!(!name.contains('('));
    }

    #[test]
    fn test_test_command_rsa_vs_ed25519() {
        let rsa = KeyForBackup {
            label: "test".to_string(),
            key_type: "RSA-4096".to_string(),
            criticality: Criticality::Critical,
            pem_content: String::new(),
            file_path: String::new(),
        };
        assert!(test_command(&rsa).contains("openssl rsa"));

        let ed = KeyForBackup {
            label: "test".to_string(),
            key_type: "Ed25519".to_string(),
            criticality: Criticality::Medium,
            pem_content: String::new(),
            file_path: String::new(),
        };
        assert!(test_command(&ed).contains("openssl pkey"));
    }

    #[test]
    fn test_page_breaks_between_keys() {
        let config = PaperBackupConfig {
            title: "Test".to_string(),
            output_path: "/tmp/test.html".to_string(),
        };

        let keys: Vec<KeyForBackup> = (0..3)
            .map(|i| KeyForBackup {
                label: format!("Key {}", i),
                key_type: "Ed25519".to_string(),
                criticality: Criticality::Medium,
                pem_content: SAMPLE_ED25519_PEM.to_string(),
                file_path: format!("/key-{}.key", i),
            })
            .collect();

        let html = generate_paper_backup(&config, &keys).unwrap();

        // CSS has page-break-after: always on .page
        assert!(html.contains("page-break-after: always"));
        // 4 pages total: cover + 3 keys
        let page_count = html.matches("class=\"page").count();
        assert_eq!(page_count, 4);
    }

    #[test]
    fn test_line_numbers_in_pem() {
        let config = PaperBackupConfig {
            title: "Test".to_string(),
            output_path: "/tmp/test.html".to_string(),
        };

        let keys = vec![KeyForBackup {
            label: "Test Key".to_string(),
            key_type: "Ed25519".to_string(),
            criticality: Criticality::Deploy,
            pem_content: SAMPLE_ED25519_PEM.to_string(),
            file_path: "/test.key".to_string(),
        }];

        let html = generate_paper_backup(&config, &keys).unwrap();

        // Line numbers should be present
        assert!(html.contains("class=\"line-num\""));
        // First line number
        assert!(html.contains(">  1</span>"));
    }
}
