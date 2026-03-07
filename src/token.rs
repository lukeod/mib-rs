//! Public token types and tokenization entry point.
//!
//! Re-exports [`TokenKind`] and [`Token`] from the lexer, and provides
//! a convenience [`tokenize`] function for external callers.

pub use crate::lexer::token::{Token, TokenKind};
use crate::types::{DiagnosticConfig, SpanDiagnostic};

/// Tokenize MIB source bytes, returning all tokens and any diagnostics.
///
/// This is the public entry point for callers who want raw token output
/// without parsing. Uses default diagnostic settings.
pub fn tokenize(source: &[u8]) -> (Vec<Token>, Vec<SpanDiagnostic>) {
    tokenize_with_config(source, &DiagnosticConfig::default())
}

/// Tokenize with a specific diagnostic configuration.
pub fn tokenize_with_config(
    source: &[u8],
    diag_config: &DiagnosticConfig,
) -> (Vec<Token>, Vec<SpanDiagnostic>) {
    let lexer = crate::lexer::Lexer::new(source, diag_config.clone());
    lexer.tokenize()
}
