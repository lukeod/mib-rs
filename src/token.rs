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
