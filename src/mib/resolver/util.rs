use crate::types::Language;

/// Return a numeric rank for SMI language version. Higher is preferred when
/// multiple modules define the same OID.
pub(super) fn language_rank(lang: Language) -> u8 {
    match lang {
        Language::SMIv2 => 2,
        Language::SMIv1 => 1,
        Language::SPPI => 1,
        Language::Unknown => 0,
    }
}

/// Normalize timestamps: expand 10-digit (YYMMDDHHmmZ) to 12-digit (YYYYMMDDHHmmZ).
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
