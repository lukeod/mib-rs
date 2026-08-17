//! Heuristic scanning of raw MIB file bytes.
//!
//! Provides fast, pre-parse detection of module names and content checks
//! used by the loading pipeline to filter and index MIB files without
//! invoking the full parser.

use std::sync::Arc;

use crate::lexer::{Lexer, Token, TokenKind};
use crate::source::{SourceOrigin, SourceSet};
use crate::types::DiagnosticConfig;

/// Scans raw MIB file bytes for module names.
///
/// Finds token sequences forming `NAME DEFINITIONS ::= BEGIN` module headers
/// without performing a full parse. Comments and quoted strings cannot
/// advertise modules. Module names must start with an uppercase letter per
/// ASN.1 conventions; reserved uppercase keywords are retained as candidates
/// because the parser accepts them with a configurable diagnostic. Obsolete
/// module OIDs between the name and `DEFINITIONS` are accepted.
///
/// Returns an empty `Vec` if no module headers are found. A single MIB
/// file may contain multiple modules, in which case all names are returned
/// in the order they appear.
pub fn scan_module_names(content: &[u8]) -> Vec<String> {
    let config = DiagnosticConfig::silent();
    let mut sources = SourceSet::new();
    let source_id = sources
        .insert(
            SourceOrigin::memory("module-name-scan"),
            "module-name-scan",
            Arc::from(content),
        )
        .expect("scanner input fits the compiler source coordinate space");
    let document = sources
        .get(source_id)
        .expect("the scanner source was just inserted");
    let (tokens, _) = Lexer::new(document, &config).tokenize();
    let mut names = Vec::new();
    let mut i = next_scan_token(&tokens, 0);
    let mut in_module = false;
    let mut macro_end_pending = false;

    while let Some(token) = tokens.get(i) {
        if token.kind == TokenKind::Eof {
            break;
        }

        if in_module {
            match token.kind {
                TokenKind::KwMacro => macro_end_pending = true,
                TokenKind::KwEnd if macro_end_pending => macro_end_pending = false,
                TokenKind::KwEnd => in_module = false,
                _ => {}
            }
            i = next_scan_token(&tokens, i + 1);
            continue;
        }

        // The parser only begins a module at the first significant token or
        // directly after the preceding module's END. If a header cannot be
        // parsed there, parsing stops and later header-shaped text is not
        // loadable either.
        if !matches!(
            token.kind,
            TokenKind::UppercaseIdent | TokenKind::ForbiddenKeyword
        ) {
            break;
        }
        let name_token = token;
        let mut j = next_scan_token(&tokens, i + 1);

        // Some old ASN.1 modules include an obsolete module OID between
        // the module name and DEFINITIONS.
        if tokens.get(j).is_some_and(|t| t.kind == TokenKind::LBrace) {
            let mut depth = 0usize;
            while let Some(token) = tokens.get(j) {
                match token.kind {
                    TokenKind::LBrace => depth += 1,
                    TokenKind::RBrace => {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    TokenKind::Eof => break,
                    _ => {}
                }
                j += 1;
            }
            if depth != 0 {
                break;
            }
            j = next_scan_token(&tokens, j);
        }

        if tokens
            .get(j)
            .is_none_or(|t| t.kind != TokenKind::KwDefinitions)
        {
            break;
        }
        j = next_scan_token(&tokens, j + 1);

        if tokens
            .get(j)
            .is_none_or(|t| t.kind != TokenKind::ColonColonEqual)
        {
            break;
        }
        j = next_scan_token(&tokens, j + 1);

        if tokens.get(j).is_none_or(|t| t.kind != TokenKind::KwBegin) {
            break;
        }

        if let Ok(name) = std::str::from_utf8(
            document
                .slice(name_token.span)
                .expect("scanner tokens belong to the scanner document"),
        ) {
            names.push(name.to_string());
        }
        in_module = true;
        i = next_scan_token(&tokens, j + 1);
    }

    names
}

fn next_scan_token(tokens: &[Token], mut i: usize) -> usize {
    while tokens.get(i).is_some_and(|t| t.kind == TokenKind::Comment) {
        i += 1;
    }
    i
}

const SIG_DEFINITIONS: &[u8] = b"DEFINITIONS";
const SIG_ASSIGN: &[u8] = b"::=";

/// Find the first occurrence of needle in haystack.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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
    fn reserved_keyword_name_is_retained_for_parser_diagnostics() {
        let content = b"TRUE DEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["TRUE"]);
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
    fn obsolete_module_oid_is_accepted() {
        let content = b"OLD-MIB { iso 3 } DEFINITIONS ::= BEGIN\nEND";
        let names = scan_module_names(content);
        assert_eq!(names, vec!["OLD-MIB"]);
    }

    #[test]
    fn quoted_and_partial_headers_are_rejected() {
        let content = br#"REAL-MIB DEFINITIONS ::= BEGIN
DESCRIPTION "QUOTED-MIB DEFINITIONS ::= BEGIN"
LONGER-MIB MY-DEFINITIONS ::= BEGIN
NO-ASSIGN-MIB DEFINITIONS MYASSIGN::= BEGIN
NO-BEGIN-MIB DEFINITIONS ::= SOMETHING
END
"#;
        let names = scan_module_names(content);
        assert_eq!(names, vec!["REAL-MIB"]);
    }

    #[test]
    fn header_sequence_after_leading_token_is_rejected() {
        let content = b"LEADING-TOKEN REAL-MIB DEFINITIONS ::= BEGIN\nEND";
        assert!(scan_module_names(content).is_empty());
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
