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

/// Normalize LAST-UPDATED timestamps for comparison.
///
/// Expands 11-character timestamps (YYMMDDHHmmZ) to 13-character form
/// (YYYYMMDDHHmmZ) by prepending "19" for years >= 70 and "20" otherwise.
/// Already-expanded timestamps are returned as-is.
pub(super) fn normalize_timestamp(ts: &str) -> String {
    if ts.len() == 11 {
        // YYMMDDHHmmZ format
        let year_digits = &ts[..2];
        let year: u32 = year_digits.parse().unwrap_or(0);
        let prefix = if year >= 70 { "19" } else { "20" };
        format!("{prefix}{ts}")
    } else {
        ts.to_string()
    }
}
