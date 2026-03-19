//! iCalendar (.ics) generator for certificate expiry reminders.
//!
//! Generates RFC 5545 compliant iCalendar files with VEVENT entries
//! for certificate expiration warnings at various intervals.

use std::fmt::Write as FmtWrite;
use std::path::Path;

use anyhow::{Context, Result};

/// Reminder intervals: (days before expiry, summary prefix, priority)
const REMINDERS: &[(i64, &str, u8)] = &[
    (90, "Certificate expires in 90 days", 5),
    (60, "Certificate expires in 60 days", 5),
    (45, "Certificate expires in 45 days", 5),
    (30, "Certificate expires in 30 days", 5),
    (15, "Certificate expires in 15 days", 5),
    (7, "Certificate expires in 7 days", 5),
    (1, "URGENT: Certificate expires tomorrow", 1),
    (0, "EXPIRED", 1),
];

/// Fold a line per RFC 5545: lines must not exceed 75 octets.
/// Long lines are broken with CRLF followed by a single space.
fn fold_line(line: &str) -> String {
    const MAX_OCTETS: usize = 75;
    let bytes = line.as_bytes();
    if bytes.len() <= MAX_OCTETS {
        return format!("{}\r\n", line);
    }

    let mut result = String::new();
    let len = bytes.len();

    // First line: up to 75 octets
    let first_end = MAX_OCTETS.min(len);
    // Walk back to avoid splitting a multi-byte UTF-8 character
    let first_end = find_char_boundary(bytes, first_end);
    result.push_str(&line[..first_end]);
    result.push_str("\r\n");
    let mut pos = first_end;

    // Continuation lines: space + up to 74 octets of content
    while pos < len {
        let chunk_max = (MAX_OCTETS - 1).min(len - pos); // -1 for leading space
        let chunk_end = find_char_boundary(bytes, pos + chunk_max);
        result.push(' ');
        result.push_str(&line[pos..chunk_end]);
        result.push_str("\r\n");
        pos = chunk_end;
    }

    result
}

/// Find the largest valid UTF-8 character boundary at or before `pos`.
fn find_char_boundary(bytes: &[u8], pos: usize) -> usize {
    let mut p = pos.min(bytes.len());
    while p > 0 && !is_utf8_char_start(bytes[p.min(bytes.len() - 1)]) {
        p -= 1;
    }
    p
}

/// Check if a byte is the start of a UTF-8 character.
fn is_utf8_char_start(b: u8) -> bool {
    // UTF-8 continuation bytes start with 10xxxxxx
    (b & 0xC0) != 0x80
}

/// Format a `time::OffsetDateTime` as iCalendar UTC datetime: YYYYMMDDTHHMMSSZ
fn format_datetime_utc(dt: time::OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    )
}

/// Format a `time::OffsetDateTime` as iCalendar all-day date: YYYYMMDD
fn format_date(dt: time::OffsetDateTime) -> String {
    format!("{:04}{:02}{:02}", dt.year(), dt.month() as u8, dt.day(),)
}

/// Format a `time::OffsetDateTime` for human-readable display in descriptions.
fn format_human_datetime(dt: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    )
}

/// Format the current UTC time as an iCalendar DTSTAMP value.
fn dtstamp_now() -> String {
    format_datetime_utc(time::OffsetDateTime::now_utc())
}

/// Generate a complete VCALENDAR string with 8 VEVENT entries for a single
/// certificate's expiry reminders.
///
/// # Arguments
/// * `name` - Short name for the certificate (used in filenames)
/// * `cn` - Common Name from the certificate subject
/// * `serial` - Certificate serial number (hex string)
/// * `algorithm` - Key algorithm (e.g., "RSA-4096", "Ed25519")
/// * `not_after` - Certificate expiration datetime
pub fn generate_ical_for_cert(
    name: &str,
    cn: &str,
    serial: &str,
    algorithm: &str,
    not_after: time::OffsetDateTime,
) -> String {
    let mut cal = String::new();

    write_vcalendar_header(&mut cal);
    write_events_for_cert(&mut cal, name, cn, serial, algorithm, not_after);
    cal.push_str("END:VCALENDAR\r\n");

    cal
}

/// Generate a combined VCALENDAR string with events for multiple certificates.
///
/// Each tuple is (name, cn, serial, algorithm, not_after).
pub fn generate_combined_ical(
    certs: &[(String, String, String, String, time::OffsetDateTime)],
) -> String {
    let mut cal = String::new();

    write_vcalendar_header(&mut cal);
    for (name, cn, serial, algorithm, not_after) in certs {
        write_events_for_cert(&mut cal, name, cn, serial, algorithm, *not_after);
    }
    cal.push_str("END:VCALENDAR\r\n");

    cal
}

/// Write individual .ics files per certificate and a combined file.
///
/// Creates a `calendars/` subdirectory under `output_dir` containing:
/// - `{name}-expiry.ics` for each certificate
/// - `all-certs-expiry.ics` with all events combined
pub fn write_ical_files(
    output_dir: &Path,
    certs: &[(String, String, String, String, time::OffsetDateTime)],
) -> Result<()> {
    let cal_dir = output_dir.join("calendars");
    std::fs::create_dir_all(&cal_dir)
        .with_context(|| format!("Failed to create directory: {}", cal_dir.display()))?;

    // Write per-cert files
    for (name, cn, serial, algorithm, not_after) in certs {
        let ical = generate_ical_for_cert(name, cn, serial, algorithm, *not_after);
        let file_path = cal_dir.join(format!("{name}-expiry.ics"));
        std::fs::write(&file_path, &ical)
            .with_context(|| format!("Failed to write {}", file_path.display()))?;
        eprintln!("  wrote {}", file_path.display());
    }

    // Write combined file
    let combined = generate_combined_ical(certs);
    let combined_path = cal_dir.join("all-certs-expiry.ics");
    std::fs::write(&combined_path, &combined)
        .with_context(|| format!("Failed to write {}", combined_path.display()))?;
    eprintln!("  wrote {}", combined_path.display());

    Ok(())
}

/// Write the VCALENDAR header lines.
fn write_vcalendar_header(cal: &mut String) {
    cal.push_str("BEGIN:VCALENDAR\r\n");
    cal.push_str("VERSION:2.0\r\n");
    cal.push_str("PRODID:-//Hedonistic LLC//hedonistic-pki//EN\r\n");
    cal.push_str("CALSCALE:GREGORIAN\r\n");
    cal.push_str("METHOD:PUBLISH\r\n");
    cal.push_str("X-WR-CALNAME:Certificate Expiry Reminders\r\n");
}

/// Write all 8 VEVENT entries for a single certificate.
fn write_events_for_cert(
    cal: &mut String,
    _name: &str,
    cn: &str,
    serial: &str,
    algorithm: &str,
    not_after: time::OffsetDateTime,
) {
    let dtstamp = dtstamp_now();
    let human_expiry = format_human_datetime(not_after);

    let description = format!(
        "Certificate: {}\\nAlgorithm: {}\\nSerial: {}\\nExpires: {}\\n\\nGenerated by hedonistic-pki",
        cn, algorithm, serial, human_expiry,
    );

    for &(days_before, prefix, priority) in REMINDERS {
        let reminder_dt = not_after - time::Duration::days(days_before);
        let summary = format!("{}: {}", prefix, cn);
        let uid = format!("{}-{}@hedonistic-pki", serial, days_before);

        cal.push_str("BEGIN:VEVENT\r\n");

        // UID
        cal.push_str(&fold_line(&format!("UID:{}", uid)));

        // DTSTAMP
        cal.push_str(&fold_line(&format!("DTSTAMP:{}", dtstamp)));

        if days_before == 0 {
            // Day-of expiry: timed event using actual not_after time
            let dtstart = format_datetime_utc(not_after);
            // 1-hour event
            let dtend_dt = not_after + time::Duration::hours(1);
            let dtend = format_datetime_utc(dtend_dt);
            cal.push_str(&fold_line(&format!("DTSTART:{}", dtstart)));
            cal.push_str(&fold_line(&format!("DTEND:{}", dtend)));
        } else {
            // Advance warning: all-day event
            let date_str = format_date(reminder_dt);
            // For all-day events, DTEND is the next day
            let next_day = reminder_dt + time::Duration::days(1);
            let end_date_str = format_date(next_day);
            cal.push_str(&fold_line(&format!("DTSTART;VALUE=DATE:{}", date_str)));
            cal.push_str(&fold_line(&format!("DTEND;VALUE=DATE:{}", end_date_str)));
        }

        // SUMMARY
        cal.push_str(&fold_line(&format!("SUMMARY:{}", summary)));

        // DESCRIPTION
        cal.push_str(&fold_line(&format!("DESCRIPTION:{}", description)));

        // PRIORITY
        let _ = write!(cal, "PRIORITY:{}\r\n", priority);

        // STATUS
        cal.push_str("STATUS:CONFIRMED\r\n");

        cal.push_str("END:VEVENT\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample_expiry() -> time::OffsetDateTime {
        datetime!(2027-06-15 12:00:00 UTC)
    }

    #[test]
    fn test_ical_structure() {
        let ical = generate_ical_for_cert(
            "root-ca",
            "Hedonistic Root CA",
            "AABBCCDD",
            "RSA-4096",
            sample_expiry(),
        );

        assert!(ical.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ical.ends_with("END:VCALENDAR\r\n"));
        assert!(ical.contains("VERSION:2.0\r\n"));
        assert!(ical.contains("PRODID:-//Hedonistic LLC//hedonistic-pki//EN\r\n"));

        // Should have exactly 8 VEVENTs
        let vevent_count = ical.matches("BEGIN:VEVENT").count();
        assert_eq!(vevent_count, 8, "Expected 8 VEVENTs, got {}", vevent_count);

        let end_vevent_count = ical.matches("END:VEVENT").count();
        assert_eq!(end_vevent_count, 8);
    }

    #[test]
    fn test_ical_event_content() {
        let ical = generate_ical_for_cert(
            "root-ca",
            "Hedonistic Root CA",
            "AABBCCDD",
            "RSA-4096",
            sample_expiry(),
        );

        // Check for expected summaries
        assert!(ical.contains("Certificate expires in 90 days: Hedonistic Root CA"));
        assert!(ical.contains("Certificate expires in 60 days: Hedonistic Root CA"));
        assert!(ical.contains("Certificate expires in 7 days: Hedonistic Root CA"));
        assert!(ical.contains("URGENT: Certificate expires tomorrow: Hedonistic Root CA"));
        assert!(ical.contains("EXPIRED: Hedonistic Root CA"));

        // Check UIDs
        assert!(ical.contains("UID:AABBCCDD-90@hedonistic-pki"));
        assert!(ical.contains("UID:AABBCCDD-0@hedonistic-pki"));

        // Check priorities
        assert!(ical.contains("PRIORITY:5"));
        assert!(ical.contains("PRIORITY:1"));

        // Check status
        assert!(ical.contains("STATUS:CONFIRMED"));
    }

    #[test]
    fn test_date_formatting() {
        let dt = datetime!(2027-06-15 12:00:00 UTC);
        assert_eq!(format_datetime_utc(dt), "20270615T120000Z");
        assert_eq!(format_date(dt), "20270615");

        let dt2 = datetime!(2026-01-05 08:30:45 UTC);
        assert_eq!(format_datetime_utc(dt2), "20260105T083045Z");
        assert_eq!(format_date(dt2), "20260105");
    }

    #[test]
    fn test_line_folding_short() {
        let short = "SUMMARY:Short line";
        let folded = fold_line(short);
        assert_eq!(folded, "SUMMARY:Short line\r\n");
    }

    #[test]
    fn test_line_folding_long() {
        // Create a line longer than 75 octets
        let long_line = format!("DESCRIPTION:{}", "A".repeat(100));
        let folded = fold_line(&long_line);

        // Every line (including continuations) must be <= 75 octets
        for line in folded.split("\r\n") {
            if line.is_empty() {
                continue;
            }
            assert!(
                line.len() <= 75,
                "Line exceeds 75 octets ({}): {:?}",
                line.len(),
                line,
            );
        }

        // Must start with CRLF + space for continuation
        assert!(folded.contains("\r\n "));

        // Content must be preserved when unfolded
        let unfolded: String = folded.replace("\r\n ", "").replace("\r\n", "");
        assert_eq!(unfolded, long_line);
    }

    #[test]
    fn test_line_folding_exactly_75() {
        // Exactly 75 characters should NOT be folded
        let exact = "X".repeat(75);
        let folded = fold_line(&exact);
        assert_eq!(folded, format!("{}\r\n", exact));
    }

    #[test]
    fn test_all_day_event_dates() {
        let ical = generate_ical_for_cert(
            "test",
            "Test CA",
            "1234",
            "Ed25519",
            sample_expiry(), // 2027-06-15 12:00:00 UTC
        );

        // 90 days before 2027-06-15 = 2027-03-17
        assert!(ical.contains("DTSTART;VALUE=DATE:20270317"));

        // Day-of event should be a timed event (no VALUE=DATE)
        // The EXPIRED event uses DTSTART:20270615T120000Z
        assert!(ical.contains("DTSTART:20270615T120000Z"));
    }

    #[test]
    fn test_combined_ical() {
        let certs = vec![
            (
                "root-ca".to_string(),
                "Root CA".to_string(),
                "AA".to_string(),
                "RSA-4096".to_string(),
                sample_expiry(),
            ),
            (
                "intermediate".to_string(),
                "Intermediate CA".to_string(),
                "BB".to_string(),
                "RSA-4096".to_string(),
                sample_expiry(),
            ),
        ];

        let ical = generate_combined_ical(&certs);

        assert!(ical.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ical.ends_with("END:VCALENDAR\r\n"));

        // 8 events per cert * 2 certs = 16
        let count = ical.matches("BEGIN:VEVENT").count();
        assert_eq!(count, 16, "Expected 16 VEVENTs, got {}", count);
    }

    #[test]
    fn test_write_ical_files() {
        let dir = std::env::temp_dir().join("hedonistic-pki-ical-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let certs = vec![
            (
                "root-ca".to_string(),
                "Root CA".to_string(),
                "AA".to_string(),
                "RSA-4096".to_string(),
                sample_expiry(),
            ),
            (
                "leaf".to_string(),
                "Leaf Cert".to_string(),
                "BB".to_string(),
                "Ed25519".to_string(),
                sample_expiry(),
            ),
        ];

        write_ical_files(&dir, &certs).unwrap();

        let cal_dir = dir.join("calendars");
        assert!(cal_dir.join("root-ca-expiry.ics").exists());
        assert!(cal_dir.join("leaf-expiry.ics").exists());
        assert!(cal_dir.join("all-certs-expiry.ics").exists());

        // Verify combined file has events from both certs
        let combined = std::fs::read_to_string(cal_dir.join("all-certs-expiry.ics")).unwrap();
        assert_eq!(combined.matches("BEGIN:VEVENT").count(), 16);

        // Verify individual files have 8 events each
        let root_ical = std::fs::read_to_string(cal_dir.join("root-ca-expiry.ics")).unwrap();
        assert_eq!(root_ical.matches("BEGIN:VEVENT").count(), 8);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
