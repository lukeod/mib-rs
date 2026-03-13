//! ExtUTCTime date validation for MODULE-IDENTITY dates and revisions.
//!
//! Validates the `LAST-UPDATED` and `REVISION` date strings against the
//! ExtUTCTime format defined in RFC 2578. Checks for correct length,
//! character validity, calendar validity, chronological ordering, and
//! emits style warnings for dates outside the reasonable SMI range.

use crate::types::{DiagCode, Span};

use super::LoweringContext;

/// Validates date formats and revision ordering for a MODULE-IDENTITY.
///
/// Checks each date for valid ExtUTCTime format, ensures revisions are
/// in reverse chronological order, and warns if any revision is after
/// LAST-UPDATED.
pub(super) fn check_module_identity_dates(
    ctx: &mut LoweringContext,
    last_updated: &str,
    last_updated_span: Span,
    revision_dates: &[(String, Span)],
) {
    let now = now_utc();

    let last_updated_time = check_date(ctx, last_updated, last_updated_span, now);

    // Validate each revision date and collect parsed times for ordering checks.
    let revs: Vec<(Option<DateComponents>, Span)> = revision_dates
        .iter()
        .map(|(date, span)| (check_date(ctx, date, *span, now), *span))
        .collect();

    // Check revision ordering: must be reverse chronological (descending).
    for i in 1..revs.len() {
        if let (Some(prev), Some(curr)) = (&revs[i - 1].0, &revs[i].0)
            && curr >= prev
        {
            ctx.emit_diagnostic(
                DiagCode::RevisionNotDescending,
                revs[i].1,
                format!(
                    "revision {} is not in reverse chronological order",
                    revision_dates[i].0
                ),
            );
        }
    }

    // Check revision-after-update: no revision may exceed LAST-UPDATED.
    if let Some(last_updated_time) = &last_updated_time {
        for (i, rev) in revs.iter().enumerate() {
            if let Some(t) = &rev.0
                && t > last_updated_time
            {
                ctx.emit_diagnostic(
                    DiagCode::RevisionAfterUpdate,
                    rev.1,
                    format!(
                        "revision {} is after LAST-UPDATED {}",
                        revision_dates[i].0, last_updated
                    ),
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DateComponents {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
}

/// Validates a single SMI date string (ExtUTCTime format).
/// Format: YYMMDDHHMMZ (11 chars) or YYYYMMDDHHMMZ (13 chars).
fn check_date(
    ctx: &mut LoweringContext,
    date: &str,
    span: Span,
    now: DateComponents,
) -> Option<DateComponents> {
    if date.is_empty() {
        return None;
    }

    let bytes = date.as_bytes();

    // Check length: must be 11 (2-digit year) or 13 (4-digit year).
    if bytes.len() != 11 && bytes.len() != 13 {
        ctx.emit_diagnostic(
            DiagCode::DateLength,
            span,
            format!(
                "date {:?} has illegal length {} (expected 11 or 13)",
                date,
                bytes.len()
            ),
        );
        return None;
    }

    // All characters before final must be digits, final must be 'Z'.
    for (i, &b) in bytes[..bytes.len() - 1].iter().enumerate() {
        if !b.is_ascii_digit() {
            ctx.emit_diagnostic(
                DiagCode::DateCharacter,
                span,
                format!(
                    "date {:?} contains illegal character at position {}",
                    date,
                    i + 1
                ),
            );
            return None;
        }
    }
    if bytes[bytes.len() - 1] != b'Z' {
        ctx.emit_diagnostic(
            DiagCode::DateCharacter,
            span,
            format!("date {:?} must end with 'Z'", date),
        );
        return None;
    }

    // Parse numeric components.
    let digit = |i: usize| -> u32 { (bytes[i] - b'0') as u32 };

    let (year, offset) = if bytes.len() == 11 {
        let y = digit(0) * 10 + digit(1) + 1900;
        ctx.emit_diagnostic(
            DiagCode::DateYear2Digits,
            span,
            format!("date {:?} uses 2-digit year representing {}", date, y),
        );
        (y, 2)
    } else {
        (
            digit(0) * 1000 + digit(1) * 100 + digit(2) * 10 + digit(3),
            4,
        )
    };

    let month = digit(offset) * 10 + digit(offset + 1);
    let day = digit(offset + 2) * 10 + digit(offset + 3);
    let hour = digit(offset + 4) * 10 + digit(offset + 5);
    let min = digit(offset + 6) * 10 + digit(offset + 7);

    // Validate ranges.
    if !(1..=12).contains(&month) {
        ctx.emit_diagnostic(
            DiagCode::DateMonth,
            span,
            format!("date {:?} has illegal month {:02}", date, month),
        );
        return None;
    }
    if !(1..=31).contains(&day) {
        ctx.emit_diagnostic(
            DiagCode::DateDay,
            span,
            format!("date {:?} has illegal day {:02}", date, day),
        );
        return None;
    }
    if hour > 23 {
        ctx.emit_diagnostic(
            DiagCode::DateHour,
            span,
            format!("date {:?} has illegal hour {:02}", date, hour),
        );
        return None;
    }
    if min > 59 {
        ctx.emit_diagnostic(
            DiagCode::DateMinutes,
            span,
            format!("date {:?} has illegal minutes {:02}", date, min),
        );
        return None;
    }

    // Check calendar validity (e.g. Feb 30 is not valid).
    if !is_valid_date(year, month, day) {
        ctx.emit_diagnostic(
            DiagCode::DateValue,
            span,
            format!("date {:?} is not a valid calendar date", date),
        );
        return None;
    }

    let dc = DateComponents {
        year,
        month,
        day,
        hour,
        min,
    };

    // Style warnings for dates outside reasonable range.
    // SMI epoch is Jan 1, 1990.
    let smi_epoch = DateComponents {
        year: 1990,
        month: 1,
        day: 1,
        hour: 0,
        min: 0,
    };
    if dc < smi_epoch {
        ctx.emit_diagnostic(
            DiagCode::DateInPast,
            span,
            format!("date {:?} predates the SMI standard", date),
        );
    }
    if dc > now {
        ctx.emit_diagnostic(
            DiagCode::DateInFuture,
            span,
            format!("date {:?} is in the future", date),
        );
    }

    Some(dc)
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_valid_date(year: u32, month: u32, day: u32) -> bool {
    day <= days_in_month(year, month)
}

fn now_utc() -> DateComponents {
    // Use a simple approach: parse current time from SystemTime.
    // We only need year/month/day/hour/min.
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert seconds since epoch to date components.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = (time_of_day / 3600) as u32;
    let min = ((time_of_day % 3600) / 60) as u32;

    // Civil date from days since 1970-01-01 (algorithm from Howard Hinnant).
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    DateComponents {
        year: year as u32,
        month: m,
        day: d,
        hour,
        min,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dates() {
        assert!(is_valid_date(2024, 2, 29)); // leap year
        assert!(!is_valid_date(2023, 2, 29)); // not leap year
        assert!(is_valid_date(2023, 12, 31));
        assert!(!is_valid_date(2023, 4, 31));
    }

    #[test]
    fn date_comparison() {
        let d1 = DateComponents {
            year: 2020,
            month: 1,
            day: 1,
            hour: 0,
            min: 0,
        };
        let d2 = DateComponents {
            year: 2021,
            month: 1,
            day: 1,
            hour: 0,
            min: 0,
        };
        assert!(d1 < d2);
        assert!(d2 > d1);
        assert!(d1 <= d2);
    }
}
