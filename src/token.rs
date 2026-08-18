//! Public token types and tokenization entry point.
//!
//! Re-exports [`SyntaxKind`] and [`Token`] from the lexer, and provides
//! a convenience [`tokenize`] function for external callers.

pub use crate::lexer::token::Token;
use crate::source::SourceDocument;
pub use crate::syntax::SyntaxKind;
use crate::types::{Diagnostic, DiagnosticConfig};

/// Tokenize MIB source bytes with default [`DiagnosticConfig`] settings.
///
/// Returns all tokens (always ending with [`SyntaxKind::EofToken`]) and any
/// diagnostics produced during lexing. For custom diagnostic settings,
/// use [`tokenize_with_config`].
pub fn tokenize(document: &SourceDocument) -> (Vec<Token>, Vec<Diagnostic>) {
    tokenize_with_config(document, &DiagnosticConfig::default())
}

/// Tokenize MIB source bytes with a specific [`DiagnosticConfig`].
///
/// See [`tokenize`] for the default-config convenience wrapper.
pub fn tokenize_with_config(
    document: &SourceDocument,
    diag_config: &DiagnosticConfig,
) -> (Vec<Token>, Vec<Diagnostic>) {
    let lexer = crate::lexer::Lexer::new(document, diag_config);
    lexer.tokenize()
}

/// Tokenize MIB source bytes without discarding any source text.
///
/// The returned stream includes whitespace and comments, skipped `EXPORTS`
/// and `MACRO` bodies as [`SyntaxKind::OpaqueText`], recovery regions as
/// [`SyntaxKind::ErrorToken`], and a final zero-length EOF token. Concatenating
/// the source slices of every non-EOF token reproduces the document bytes.
pub fn tokenize_lossless(document: &SourceDocument) -> (Vec<Token>, Vec<Diagnostic>) {
    tokenize_lossless_with_config(document, &DiagnosticConfig::default())
}

/// Losslessly tokenize MIB source bytes with a specific [`DiagnosticConfig`].
///
/// See [`tokenize_lossless`] for the default-config convenience wrapper.
pub fn tokenize_lossless_with_config(
    document: &SourceDocument,
    diag_config: &DiagnosticConfig,
) -> (Vec<Token>, Vec<Diagnostic>) {
    let lexer = crate::lexer::Lexer::new_lossless(document, diag_config);
    lexer.tokenize()
}
