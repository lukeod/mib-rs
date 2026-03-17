//! RFC 2579 DISPLAY-HINT formatting for SNMP values.
//!
//! Formats raw SNMP values according to DISPLAY-HINT strings from
//! TEXTUAL-CONVENTIONs. Supports both integer hints (for INTEGER-based
//! types) and octet-string hints (for OCTET STRING types).
//!
//! See RFC 2579 Section 3.1 for the specification.
//!
//! # Using with the handle API
//!
//! The easiest way to apply a display hint is through the
//! [`Object`](super::handle::Object) handle, which carries the
//! resolved hint from the type chain:
//!
//! ```rust,no_run
//! # let mib: mib_rs::Mib = unimplemented!();
//! let obj = mib.object("exTemperature").unwrap();
//!
//! // Format as display string: 2345 -> "23.45"
//! let text = obj.format_integer(2345);
//!
//! // Scale to f64 for metrics: 2345 -> 23.45
//! let value = obj.scale_integer(2345);
//!
//! // Format octet strings the same way:
//! let obj = mib.object("exDeviceMac").unwrap();
//! let mac = obj.format_octets(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
//! // -> Some("00:1A:2B:3C:4D:5E")
//! ```
//!
//! Objects without a display hint return `None` from these methods.
//!
//! # Standalone functions
//!
//! The functions below can also be called directly when you have a hint
//! string but no Object handle (e.g. from configuration or another
//! source).
//!
//! ## Integer hints
//!
//! Integer hints have the form `{d|x|o|b}[-N]`:
//! - `d` - decimal, optionally with `-N` for an implied decimal point
//! - `x` - hexadecimal (lowercase, no leading zeros)
//! - `o` - octal (no leading zeros)
//! - `b` - binary (no leading zeros)
//!
//! ```
//! use mib_rs::mib::display_hint;
//!
//! assert_eq!(display_hint::format_integer("d-2", 1234), Some("12.34".into()));
//! assert_eq!(display_hint::format_integer("d-2", 5), Some("0.05".into()));
//! assert_eq!(display_hint::format_integer("x", 255), Some("ff".into()));
//! assert_eq!(display_hint::format_integer("o", 8), Some("10".into()));
//! assert_eq!(display_hint::format_integer("b", 5), Some("101".into()));
//! ```
//!
//! ## Scaled numeric values
//!
//! For monitoring applications that need a numeric value rather than a
//! display string, [`scale_integer`] applies the `d-N` implied decimal
//! point as an `f64`:
//!
//! ```
//! use mib_rs::mib::display_hint;
//!
//! // Board temperature: raw value 2345, hint "d-2" -> 23.45 degrees
//! assert_eq!(display_hint::scale_integer("d-2", 2345), Some(23.45));
//! assert_eq!(display_hint::scale_integer("d-2", 5), Some(0.05));
//! assert_eq!(display_hint::scale_integer("d", 42), Some(42.0));
//!
//! // Non-decimal hints return None (no meaningful numeric scaling).
//! assert_eq!(display_hint::scale_integer("x", 255), None);
//! ```
//!
//! ## Octet-string hints
//!
//! Octet-string hints consist of one or more format specifications, each
//! containing: an optional `*` repeat indicator, an octet length, a format
//! character (`d`/`x`/`o`/`a`/`t`), an optional separator, and an optional
//! repeat terminator.
//!
//! ```
//! use mib_rs::mib::display_hint;
//!
//! // IPv4 address
//! assert_eq!(
//!     display_hint::format_octets("1d.1d.1d.1d", &[192, 168, 1, 1]),
//!     Some("192.168.1.1".into()),
//! );
//!
//! // MAC address
//! assert_eq!(
//!     display_hint::format_octets("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
//!     Some("00:1A:2B:3C:4D:5E".into()),
//! );
//! ```

use std::fmt::Write;

/// Format an integer value according to an RFC 2579 integer display hint.
///
/// The hint must be one of `d`, `d-N`, `x`, `o`, or `b`. Returns `None`
/// if the hint is malformed.
///
/// For `d-N`, the decimal point is placed N digits from the right. If the
/// value has fewer than N+1 digits, leading zeros are added (e.g., `d-2`
/// on 5 produces `"0.05"`).
///
/// Negative values are prefixed with `-`.
pub fn format_integer(hint: &str, value: i64) -> Option<String> {
    let bytes = hint.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let fmt_char = bytes[0];
    let rest = &hint[1..];

    match fmt_char {
        b'x' if rest.is_empty() => Some(format_signed(value, 16)),
        b'o' if rest.is_empty() => Some(format_signed(value, 8)),
        b'b' if rest.is_empty() => Some(format_signed(value, 2)),
        b'd' if rest.is_empty() => Some(value.to_string()),
        b'd' if rest.starts_with('-') => {
            let places: usize = rest[1..].parse().ok().filter(|&n| {
                // Reject empty string (which parse would fail on anyway)
                // and unreasonably large values
                n <= 100
            })?;
            if places == 0 {
                return Some(value.to_string());
            }
            Some(format_decimal_with_point(value, places))
        }
        _ => None,
    }
}

/// Apply an RFC 2579 integer display hint as numeric scaling, returning `f64`.
///
/// Only `d` and `d-N` hints produce a meaningful numeric result:
/// - `d` returns the value as-is (converted to `f64`)
/// - `d-N` divides by 10^N (e.g. `d-2` on 1234 returns 12.34)
///
/// Returns `None` for non-decimal hints (`x`, `o`, `b`) since those are
/// display-only formats with no numeric scaling, and for malformed hints.
pub fn scale_integer(hint: &str, value: i64) -> Option<f64> {
    let bytes = hint.as_bytes();
    if bytes.first() != Some(&b'd') {
        return None;
    }
    let rest = &hint[1..];
    if rest.is_empty() {
        return Some(value as f64);
    }
    if !rest.starts_with('-') {
        return None;
    }
    let places: u32 = rest[1..].parse().ok().filter(|&n| n <= 20)?;
    if places == 0 {
        return Some(value as f64);
    }
    Some(value as f64 / 10f64.powi(places as i32))
}

fn format_signed(value: i64, base: u32) -> String {
    let abs = value.unsigned_abs();
    let mut s = if value < 0 {
        String::from("-")
    } else {
        String::new()
    };
    match base {
        16 => write!(s, "{:x}", abs).unwrap(),
        8 => write!(s, "{:o}", abs).unwrap(),
        2 => write!(s, "{:b}", abs).unwrap(),
        _ => write!(s, "{}", abs).unwrap(),
    }
    s
}

fn format_decimal_with_point(value: i64, places: usize) -> String {
    let negative = value < 0;
    let abs = value.unsigned_abs();
    let digits = abs.to_string();

    let capacity = digits.len() + 2 + usize::from(negative) + places;
    let mut result = String::with_capacity(capacity);

    if negative {
        result.push('-');
    }

    if digits.len() <= places {
        // Need leading zeros: e.g. value=5, places=2 -> "0.05"
        result.push_str("0.");
        for _ in 0..(places - digits.len()) {
            result.push('0');
        }
        result.push_str(&digits);
    } else {
        let split = digits.len() - places;
        result.push_str(&digits[..split]);
        result.push('.');
        result.push_str(&digits[split..]);
    }

    result
}

/// Format an octet string according to an RFC 2579 octet-string display hint.
///
/// The hint consists of one or more format specifications. Each spec has:
/// - Optional `*` repeat indicator (next data byte is the repeat count)
/// - Octet length (decimal digits, number of bytes to consume)
/// - Format character: `d` decimal, `x` hex, `o` octal, `a` ASCII, `t` UTF-8
/// - Optional separator character (emitted between repetitions)
/// - Optional terminator character (emitted after a repeat group, requires `*`)
///
/// The last specification repeats implicitly until all data is consumed.
/// Trailing separators and terminators are suppressed.
///
/// Returns `None` if the hint is malformed or if both hint and data are empty.
pub fn format_octets(hint: &str, data: &[u8]) -> Option<String> {
    if hint.is_empty() || data.is_empty() {
        return None;
    }

    let hint = hint.as_bytes();
    let mut result = String::with_capacity(data.len() * 4);
    let mut hint_pos: usize = 0;
    let mut data_pos: usize = 0;

    // Track the start of the last spec for implicit repetition.
    let mut last_spec_start: usize = 0;
    // Whether the last spec consumes at least one data byte.
    let mut last_spec_consumes = false;

    while data_pos < data.len() {
        let mut spec_start = hint_pos;

        // If hint is exhausted, restart from the last spec (implicit repetition).
        if hint_pos >= hint.len() {
            if !last_spec_consumes {
                return None;
            }
            hint_pos = last_spec_start;
            spec_start = last_spec_start;
        }

        // (1) Optional '*' repeat indicator.
        let star_prefix = hint_pos < hint.len() && hint[hint_pos] == b'*';
        if star_prefix {
            hint_pos += 1;
        }

        // (2) Octet length (required, one or more decimal digits).
        if hint_pos >= hint.len() || !hint[hint_pos].is_ascii_digit() {
            return None;
        }
        let mut take: usize = 0;
        while hint_pos < hint.len() && hint[hint_pos].is_ascii_digit() {
            take = take
                .checked_mul(10)?
                .checked_add((hint[hint_pos] - b'0') as usize)?;
            hint_pos += 1;
        }

        // (3) Format character (required).
        if hint_pos >= hint.len() {
            return None;
        }
        let fmt_char = hint[hint_pos];
        if !matches!(fmt_char, b'd' | b'x' | b'o' | b'a' | b't') {
            return None;
        }
        hint_pos += 1;

        // (4) Optional separator (any char that isn't a digit or '*').
        let (has_sep, sep) = if hint_pos < hint.len()
            && !hint[hint_pos].is_ascii_digit()
            && hint[hint_pos] != b'*'
        {
            let s = hint[hint_pos];
            hint_pos += 1;
            (true, s)
        } else {
            (false, 0)
        };

        // (5) Optional terminator (only valid with star prefix).
        let (has_term, term) = if star_prefix
            && hint_pos < hint.len()
            && !hint[hint_pos].is_ascii_digit()
            && hint[hint_pos] != b'*'
        {
            let t = hint[hint_pos];
            hint_pos += 1;
            (true, t)
        } else {
            (false, 0)
        };

        // Remember this spec for implicit repetition.
        last_spec_start = spec_start;
        last_spec_consumes = take > 0 || star_prefix;

        // Determine repeat count.
        let repeat_count = if star_prefix && data_pos < data.len() {
            let c = data[data_pos] as usize;
            data_pos += 1;
            c
        } else {
            1
        };

        for r in 0..repeat_count {
            if data_pos >= data.len() {
                break;
            }

            let end = data_pos
                .checked_add(take)
                .unwrap_or(data.len())
                .min(data.len());
            let chunk = &data[data_pos..end];

            match fmt_char {
                b'd' => {
                    if chunk.len() > 8 {
                        return None;
                    }
                    let val = big_endian_u64(chunk);
                    write!(result, "{}", val).unwrap();
                }
                b'x' => {
                    for &b in chunk {
                        write!(result, "{:02X}", b).unwrap();
                    }
                }
                b'o' => {
                    if chunk.len() > 8 {
                        return None;
                    }
                    let val = big_endian_u64(chunk);
                    write!(result, "{:o}", val).unwrap();
                }
                b'a' => {
                    // ASCII: fall back to Latin-1 byte mapping for non-ASCII
                    // bytes so the output is always a valid Rust String.
                    match std::str::from_utf8(chunk) {
                        Ok(s) => result.push_str(s),
                        Err(_) => {
                            for &b in chunk {
                                result.push(char::from(b));
                            }
                        }
                    }
                }
                b't' => {
                    // UTF-8: emit valid prefix, discard trailing bytes that
                    // don't form a complete character (RFC 2579 Section 3.1).
                    match std::str::from_utf8(chunk) {
                        Ok(s) => result.push_str(s),
                        Err(e) => {
                            let valid = std::str::from_utf8(&chunk[..e.valid_up_to()]).unwrap();
                            result.push_str(valid);
                        }
                    }
                }
                _ => unreachable!(),
            }
            data_pos = end;

            // Emit separator (suppressed at end of data or before terminator).
            let more_data = data_pos < data.len();
            if has_sep && more_data && (!has_term || r != repeat_count - 1) {
                result.push(sep as char);
            }
        }

        // Emit terminator after repeat group.
        if has_term && data_pos < data.len() {
            result.push(term as char);
        }
    }

    Some(result)
}

/// Interpret bytes as a big-endian unsigned integer.
fn big_endian_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    u64::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Integer formatting ----

    #[test]
    fn integer_decimal() {
        assert_eq!(format_integer("d", 0), Some("0".into()));
        assert_eq!(format_integer("d", 42), Some("42".into()));
        assert_eq!(format_integer("d", -42), Some("-42".into()));
        assert_eq!(format_integer("d", i64::MAX), Some(i64::MAX.to_string()));
        assert_eq!(format_integer("d", i64::MIN), Some(i64::MIN.to_string()));
    }

    #[test]
    fn integer_decimal_with_point() {
        assert_eq!(format_integer("d-2", 1234), Some("12.34".into()));
        assert_eq!(format_integer("d-2", 5), Some("0.05".into()));
        assert_eq!(format_integer("d-2", 0), Some("0.00".into()));
        assert_eq!(format_integer("d-2", 100), Some("1.00".into()));
        assert_eq!(format_integer("d-2", -1234), Some("-12.34".into()));
        assert_eq!(format_integer("d-2", -5), Some("-0.05".into()));
        assert_eq!(format_integer("d-1", 15), Some("1.5".into()));
        assert_eq!(format_integer("d-3", 12345), Some("12.345".into()));
        assert_eq!(format_integer("d-5", 123), Some("0.00123".into()));
        assert_eq!(format_integer("d-0", 42), Some("42".into()));
    }

    #[test]
    fn integer_hex() {
        assert_eq!(format_integer("x", 0), Some("0".into()));
        assert_eq!(format_integer("x", 255), Some("ff".into()));
        assert_eq!(format_integer("x", 256), Some("100".into()));
        assert_eq!(format_integer("x", -255), Some("-ff".into()));
    }

    #[test]
    fn integer_octal() {
        assert_eq!(format_integer("o", 0), Some("0".into()));
        assert_eq!(format_integer("o", 8), Some("10".into()));
        assert_eq!(format_integer("o", 63), Some("77".into()));
        assert_eq!(format_integer("o", -8), Some("-10".into()));
    }

    #[test]
    fn integer_binary() {
        assert_eq!(format_integer("b", 0), Some("0".into()));
        assert_eq!(format_integer("b", 5), Some("101".into()));
        assert_eq!(format_integer("b", 255), Some("11111111".into()));
        assert_eq!(format_integer("b", -5), Some("-101".into()));
    }

    #[test]
    fn integer_errors() {
        assert_eq!(format_integer("", 0), None);
        assert_eq!(format_integer("z", 0), None);
        assert_eq!(format_integer("x1", 0), None); // no trailing chars for x
        assert_eq!(format_integer("o1", 0), None);
        assert_eq!(format_integer("b1", 0), None);
        assert_eq!(format_integer("d-", 0), None); // missing decimal places
        assert_eq!(format_integer("d-abc", 0), None);
        assert_eq!(format_integer("dd", 0), None);
    }

    // ---- Integer scaling ----

    #[test]
    fn scale_decimal() {
        assert_eq!(scale_integer("d", 0), Some(0.0));
        assert_eq!(scale_integer("d", 42), Some(42.0));
        assert_eq!(scale_integer("d", -42), Some(-42.0));
    }

    #[test]
    fn scale_decimal_with_places() {
        assert_eq!(scale_integer("d-2", 1234), Some(12.34));
        assert_eq!(scale_integer("d-2", 5), Some(0.05));
        assert_eq!(scale_integer("d-2", 0), Some(0.0));
        assert_eq!(scale_integer("d-2", -1234), Some(-12.34));
        assert_eq!(scale_integer("d-1", 15), Some(1.5));
        assert_eq!(scale_integer("d-3", 12345), Some(12.345));
        assert_eq!(scale_integer("d-0", 42), Some(42.0));
    }

    #[test]
    fn scale_non_decimal_returns_none() {
        assert_eq!(scale_integer("x", 255), None);
        assert_eq!(scale_integer("o", 8), None);
        assert_eq!(scale_integer("b", 5), None);
    }

    #[test]
    fn scale_errors() {
        assert_eq!(scale_integer("", 0), None);
        assert_eq!(scale_integer("z", 0), None);
        assert_eq!(scale_integer("d-", 0), None);
        assert_eq!(scale_integer("d-abc", 0), None);
        assert_eq!(scale_integer("dd", 0), None);
    }

    // ---- Octet-string formatting ----

    #[test]
    fn octets_ipv4() {
        assert_eq!(
            format_octets("1d.1d.1d.1d", &[192, 168, 1, 1]),
            Some("192.168.1.1".into()),
        );
    }

    #[test]
    fn octets_ipv4_with_zone() {
        assert_eq!(
            format_octets("1d.1d.1d.1d%4d", &[192, 168, 1, 1, 0, 0, 0, 3]),
            Some("192.168.1.1%3".into()),
        );
    }

    #[test]
    fn octets_mac_address() {
        assert_eq!(
            format_octets("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            Some("00:1A:2B:3C:4D:5E".into()),
        );
    }

    #[test]
    fn octets_ipv6() {
        assert_eq!(
            format_octets(
                "2x:2x:2x:2x:2x:2x:2x:2x",
                &[
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01
                ]
            ),
            Some("2001:0DB8:0000:0000:0000:0000:0000:0001".into()),
        );
    }

    #[test]
    fn octets_ipv6_with_zone() {
        assert_eq!(
            format_octets(
                "2x:2x:2x:2x:2x:2x:2x:2x%4d",
                &[
                    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0x05
                ]
            ),
            Some("FE80:0000:0000:0000:0000:0000:0000:0001%5".into()),
        );
    }

    #[test]
    fn octets_display_string() {
        assert_eq!(
            format_octets("255a", b"Hello, World!"),
            Some("Hello, World!".into()),
        );
    }

    #[test]
    fn octets_simple_decimal() {
        assert_eq!(format_octets("1d", &[42]), Some("42".into()));
    }

    #[test]
    fn octets_multi_byte_decimal() {
        assert_eq!(
            format_octets("4d", &[0x00, 0x01, 0x00, 0x00]),
            Some("65536".into()),
        );
    }

    #[test]
    fn octets_octal() {
        assert_eq!(format_octets("1o", &[8]), Some("10".into()));
    }

    #[test]
    fn octets_hex_dash_separator() {
        assert_eq!(
            format_octets("1x-", &[0xaa, 0xbb, 0xcc]),
            Some("AA-BB-CC".into()),
        );
    }

    #[test]
    fn octets_star_repeat() {
        assert_eq!(
            format_octets("*1x:", &[3, 0xaa, 0xbb, 0xcc]),
            Some("AA:BB:CC".into()),
        );
    }

    #[test]
    fn octets_star_with_terminator() {
        assert_eq!(
            format_octets("*1d./1d", &[3, 10, 20, 30, 40]),
            Some("10.20.30/40".into()),
        );
    }

    #[test]
    fn octets_trailing_separator_suppressed() {
        assert_eq!(format_octets("1d.", &[1, 2, 3]), Some("1.2.3".into()),);
    }

    #[test]
    fn octets_date_and_time() {
        assert_eq!(
            format_octets("2d-1d-1d,1d:1d:1d.1d", &[0x07, 0xE6, 8, 15, 8, 1, 15, 0]),
            Some("2022-8-15,8:1:15.0".into()),
        );
    }

    #[test]
    fn octets_data_shorter_than_spec() {
        assert_eq!(
            format_octets("1d.1d.1d.1d", &[10, 20]),
            Some("10.20".into()),
        );
    }

    #[test]
    fn octets_utf8() {
        assert_eq!(format_octets("10t", b"hello"), Some("hello".into()));
    }

    #[test]
    fn octets_uuid() {
        assert_eq!(
            format_octets(
                "4x-2x-2x-1x1x-6x",
                &[
                    0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x00, 0x11, 0x22,
                    0x33, 0x44, 0x55
                ]
            ),
            Some("12345678-ABCD-EF01-2345-001122334455".into()),
        );
    }

    #[test]
    fn octets_ipv4_with_prefix() {
        assert_eq!(
            format_octets("1d.1d.1d.1d/1d", &[10, 0, 0, 0, 24]),
            Some("10.0.0.0/24".into()),
        );
    }

    #[test]
    fn octets_two_digit_take() {
        assert_eq!(
            format_octets("10d", &[0, 0, 0, 0, 0, 0, 0, 1]),
            Some("1".into()),
        );
    }

    #[test]
    fn octets_zero_padded_hex() {
        assert_eq!(format_octets("1x", &[0x0f]), Some("0F".into()));
    }

    #[test]
    fn octets_single_byte_trailing_sep_suppressed() {
        assert_eq!(format_octets("1d.", &[42]), Some("42".into()));
    }

    #[test]
    fn octets_implicit_repetition() {
        assert_eq!(
            format_octets("1d.", &[1, 2, 3, 4, 5]),
            Some("1.2.3.4.5".into()),
        );
    }

    #[test]
    fn octets_last_spec_repeats() {
        assert_eq!(
            format_octets("1d-1d.", &[1, 2, 3, 4, 5, 6]),
            Some("1-2.3.4.5.6".into()),
        );
    }

    #[test]
    fn octets_valid_utf8_preserved() {
        let data = "Hello, 世界!".as_bytes();
        assert_eq!(format_octets("255t", data), Some("Hello, 世界!".into()),);
    }

    #[test]
    fn octets_utf8_trailing_invalid_discarded() {
        // RFC 2579: "Trailing octets which do not form a valid UTF-8
        // encoded character are discarded."

        // Valid e-acute (U+00E9 = C3 A9) followed by orphaned continuation byte.
        assert_eq!(
            format_octets("10t", &[0xC3, 0xA9, 0x80]),
            Some("\u{00E9}".into()),
        );

        // Orphaned lead byte at end of chunk.
        assert_eq!(format_octets("5t", &[b'A', b'B', 0xC3]), Some("AB".into()),);

        // All invalid bytes - everything discarded.
        assert_eq!(format_octets("3t", &[0x80, 0x80, 0x80]), Some("".into()),);
    }

    #[test]
    fn octets_ascii_with_non_utf8_bytes() {
        // 'a' format: non-ASCII bytes are mapped to Latin-1 Unicode code points.
        let result = format_octets("10a", &[b'H', b'i', 0x80, 0xFF, b'!']).unwrap();
        assert!(result.starts_with("Hi"));
        assert!(result.ends_with('!'));
        assert_eq!(result.len(), "Hi".len() + 2 + 2 + "!".len()); // 0x80 and 0xFF each become 2-byte UTF-8
        assert!(result.is_char_boundary(0)); // always valid UTF-8
    }

    #[test]
    fn octets_star_repeat_count_zero() {
        // RFC says repeat count "may be zero".
        // With repeat_count=0 the format body is not applied.
        assert_eq!(format_octets("*1d./1d", &[0, 42]), Some("/42".into()),);
    }

    // ---- Zero-width specs ----

    #[test]
    fn octets_zero_width_bracket_prefix() {
        assert_eq!(
            format_octets("0a[1a]1a", &[0x41, 0x42]),
            Some("[A]B".into()),
        );
    }

    #[test]
    fn octets_zero_width_prefix_trailing_suppressed() {
        assert_eq!(format_octets("0a[1a", &[0x41]), Some("[A".into()),);
    }

    #[test]
    fn octets_transport_address_ipv6_style() {
        assert_eq!(
            format_octets("0a[2x]0a:2d", &[0x20, 0x01, 0x00, 0x50]),
            Some("[2001]:80".into()),
        );
    }

    #[test]
    fn octets_zero_width_prefix_only() {
        assert_eq!(
            format_octets("0a<1d-1d-1d", &[1, 2, 3]),
            Some("<1-2-3".into()),
        );
    }

    #[test]
    fn octets_zero_width_mid_hint() {
        assert_eq!(format_octets("1d-0a.1d", &[10, 20]), Some("10-.20".into()),);
    }

    // ---- Error cases ----

    #[test]
    fn octets_empty_hint() {
        assert_eq!(format_octets("", &[1, 2, 3]), None);
    }

    #[test]
    fn octets_empty_data() {
        assert_eq!(format_octets("1d", &[]), None);
    }

    #[test]
    fn octets_invalid_format_char() {
        assert_eq!(format_octets("1z", &[1, 2, 3]), None);
    }

    #[test]
    fn octets_missing_format_char() {
        assert_eq!(format_octets("1", &[1, 2, 3]), None);
    }

    #[test]
    fn octets_missing_take() {
        assert_eq!(format_octets("d", &[1, 2, 3]), None);
    }

    #[test]
    fn octets_decimal_take_too_large() {
        assert_eq!(format_octets("9d", &[1, 0, 0, 0, 0, 0, 0, 0, 0]), None,);
    }

    #[test]
    fn octets_octal_take_too_large() {
        assert_eq!(format_octets("9o", &[1, 0, 0, 0, 0, 0, 0, 0, 0]), None,);
    }

    #[test]
    fn octets_zero_width_trailing_loops() {
        assert_eq!(format_octets("0x", &[0x41, 0x42]), None);
        assert_eq!(format_octets("0d", &[1, 2, 3]), None);
        assert_eq!(format_octets("0o", &[8, 9]), None);
        assert_eq!(format_octets("0a.", &[1, 2, 3]), None);
    }

    #[test]
    fn octets_overflow_take_value() {
        // Huge take values should not panic.
        assert!(
            format_octets("1d9223372036854775807d", &[1, 2, 3]).is_none()
                || format_octets("1d9223372036854775807d", &[1, 2, 3]).is_some()
        );
        assert!(
            format_octets("2d9999999999999999999d", &[0, 1, 2, 3, 4]).is_none()
                || format_octets("2d9999999999999999999d", &[0, 1, 2, 3, 4]).is_some()
        );
    }
}
