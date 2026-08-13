//! Shared utility functions for the resolver.
//!
//! Provides [`language_rank`] for SMI version preference ordering and
//! [`normalize_timestamp`] for LAST-UPDATED timestamp comparison. Both
//! are used by the OID and import phases to select the preferred module
//! when multiple modules define the same symbol or OID.

use crate::types::Language;

/// Return a numeric rank for SMI language version.
///
/// Higher values are preferred when multiple modules define the same OID.
/// SMIv2 (rank 2) takes precedence over SMIv1 and SPPI (rank 1).
pub(super) fn language_rank(lang: Language) -> u8 {
    match lang {
        Language::SMIv2 => 2,
        Language::SMIv1 => 1,
        Language::SPPI => 1,
        Language::Unknown => 0,
    }
}

/// Normalize a valid ASCII ExtUTCTime timestamp for comparison.
///
/// Expands 11-byte timestamps (YYMMDDHHmmZ) to 13-byte form
/// (YYYYMMDDHHmmZ) by prepending "19" for years >= 70 and "20" otherwise.
/// Already-expanded timestamps are returned as-is. Invalid timestamps return
/// an empty string so they do not influence module preference.
pub(super) fn normalize_timestamp(ts: &str) -> String {
    let bytes = ts.as_bytes();
    if !matches!(bytes.len(), 11 | 13)
        || bytes[bytes.len() - 1] != b'Z'
        || !bytes[..bytes.len() - 1].iter().all(u8::is_ascii_digit)
    {
        return String::new();
    }

    let digit = |i: usize| u32::from(bytes[i] - b'0');
    let (year, offset) = if bytes.len() == 11 {
        let year = digit(0) * 10 + digit(1);
        (if year >= 70 { 1900 + year } else { 2000 + year }, 2)
    } else {
        (
            digit(0) * 1000 + digit(1) * 100 + digit(2) * 10 + digit(3),
            4,
        )
    };
    let month = digit(offset) * 10 + digit(offset + 1);
    let day = digit(offset + 2) * 10 + digit(offset + 3);
    let hour = digit(offset + 4) * 10 + digit(offset + 5);
    let minute = digit(offset + 6) * 10 + digit(offset + 7);

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
    {
        return String::new();
    }

    if bytes.len() == 11 {
        let prefix = if year < 2000 { "19" } else { "20" };
        format!("{prefix}{ts}")
    } else {
        ts.to_string()
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_timestamp;

    #[test]
    fn normalizes_only_valid_ascii_ext_utc_time() {
        assert_eq!(normalize_timestamp("0210180000Z"), "200210180000Z");
        assert_eq!(normalize_timestamp("7001010000Z"), "197001010000Z");
        assert_eq!(normalize_timestamp("200002290000Z"), "200002290000Z");

        for timestamp in [
            "",
            "200210180000",
            "200213180000Z",
            "200102290000Z",
            "aé1234567Z",
        ] {
            assert_eq!(normalize_timestamp(timestamp), "", "{timestamp:?}");
        }
    }
}
