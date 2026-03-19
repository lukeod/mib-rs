//! Heuristic scanning of raw MIB file bytes.
//!
//! Provides fast, pre-parse detection of module names and content checks
//! used by the loading pipeline to filter and index MIB files without
//! invoking the full parser.

/// Scans raw MIB file bytes for module names.
///
/// Finds identifiers that precede `DEFINITIONS ::=` without performing
/// a full parse. ASN.1 line comments (`--`) are recognized so that
/// commented-out module headers are not returned. Module names must
/// start with an uppercase letter per ASN.1 conventions.
///
/// Returns an empty `Vec` if no module headers are found. A single MIB
/// file may contain multiple modules, in which case all names are returned
/// in the order they appear.
pub fn scan_module_names(content: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0;

    while offset < content.len() {
        let rest = &content[offset..];
        let idx = match find_bytes(rest, SIG_DEFINITIONS) {
            Some(i) => i,
            None => break,
        };

        let abs_off = offset + idx;

        // Skip if inside an ASN.1 comment.
        if in_line_comment(content, abs_off) {
            offset = abs_off + SIG_DEFINITIONS.len();
            continue;
        }

        // Require ::= somewhere after DEFINITIONS (within 100 bytes).
        let after_start = abs_off + SIG_DEFINITIONS.len();
        let after_end = (after_start + 100).min(content.len());
        let window = &content[after_start..after_end];
        if find_bytes(window, SIG_ASSIGN).is_none() {
            offset = after_start;
            continue;
        }

        // Walk backwards from DEFINITIONS to find the identifier.
        let before = &rest[..idx];
        let mut pos = before.len();

        // Skip whitespace and intervening comment lines.
        loop {
            while pos > 0 && matches!(before[pos - 1], b' ' | b'\t' | b'\r' | b'\n') {
                pos -= 1;
            }
            // Check if we stopped at the end of a comment line.
            // ASN.1 comments run from -- to end of line, so if the text
            // before pos ends with a comment, skip back past the entire line.
            if pos >= 2 && line_has_comment(before, pos) {
                // Skip to start of this line.
                while pos > 0 && before[pos - 1] != b'\n' {
                    pos -= 1;
                }
                continue;
            }
            break;
        }
        let end = pos;

        // Collect identifier characters.
        while pos > 0 && is_ident_char(before[pos - 1]) {
            pos -= 1;
        }
        let start = pos;

        if start < end {
            let name = &before[start..end];
            // Module names must start with an uppercase letter.
            if !name.is_empty()
                && name[0].is_ascii_uppercase()
                && let Ok(s) = std::str::from_utf8(name)
            {
                names.push(s.to_string());
            }
        }

        offset = after_start;
    }

    names
}

const SIG_DEFINITIONS: &[u8] = b"DEFINITIONS";
const SIG_ASSIGN: &[u8] = b"::=";

/// Find the first occurrence of needle in haystack.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Check whether the byte at `pos` in `content` is inside an ASN.1 comment.
/// Scans from the start of the line containing `pos`, toggling on each "--".
fn in_line_comment(content: &[u8], pos: usize) -> bool {
    let mut line_start = pos;
    while line_start > 0 && content[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let mut in_comment = false;
    let mut i = line_start;
    while i < pos {
        if i + 1 < content.len() && content[i] == b'-' && content[i + 1] == b'-' {
            in_comment = !in_comment;
            i += 2;
            continue;
        }
        i += 1;
    }
    in_comment
}

/// Check whether the line ending at `pos` (exclusive) in `content` contains
/// an ASN.1 line comment (`--`). Used during backward scanning to detect
/// comment lines that sit between a module name and `DEFINITIONS`.
fn line_has_comment(content: &[u8], pos: usize) -> bool {
    let mut line_start = pos;
    while line_start > 0 && content[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let line = &content[line_start..pos];
    line.windows(2).any(|w| w == b"--")
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Heuristic check for whether content looks like a MIB file.
///
/// Returns `false` for empty input, binary content (contains null bytes),
/// or content missing the `DEFINITIONS` and `::=` signatures. Only the
/// first 128 KB is probed.
pub fn looks_like_mib_content(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }

    let probe_len = content.len().min(128 * 1024);
    let probe = &content[..probe_len];

    // Reject binary content (contains null bytes).
    if probe.contains(&0) {
        return false;
    }

    find_bytes(probe, SIG_DEFINITIONS).is_some() && find_bytes(probe, SIG_ASSIGN).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_scan() {
        let content = b"IF-MIB DEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["IF-MIB"]);
    }

    #[test]
    fn multiple_modules() {
        let content = b"MOD-A DEFINITIONS ::= BEGIN\nEND\n\nMOD-B DEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["MOD-A", "MOD-B"]);
    }

    #[test]
    fn commented_out_skipped() {
        let content = b"-- FAKE-MIB DEFINITIONS ::= BEGIN\nREAL-MIB DEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["REAL-MIB"]);
    }

    #[test]
    fn lowercase_name_rejected() {
        let content = b"badname DEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert!(names.is_empty());
    }

    #[test]
    fn comment_between_name_and_definitions() {
        let content = b"FROGFOOT-RESOURCES-MIB\n\n-- -*- mib -*-\n\nDEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["FROGFOOT-RESOURCES-MIB"]);
    }

    #[test]
    fn multiple_comment_lines_between_name_and_definitions() {
        let content = b"MY-MIB\n-- comment 1\n-- comment 2\n\nDEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["MY-MIB"]);
    }

    #[test]
    fn heuristic_accepts_mib() {
        assert!(looks_like_mib_content(b"FOO DEFINITIONS ::= BEGIN END"));
    }

    #[test]
    fn heuristic_rejects_empty() {
        assert!(!looks_like_mib_content(b""));
    }

    #[test]
    fn heuristic_rejects_binary() {
        assert!(!looks_like_mib_content(b"FOO\0DEFINITIONS ::= BEGIN"));
    }

    #[test]
    fn heuristic_rejects_no_definitions() {
        assert!(!looks_like_mib_content(b"just some text ::="));
    }
}
