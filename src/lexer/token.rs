//! Tokens produced by the SMI/MIB [`Lexer`](super::Lexer).

use crate::source::SourceRange;
use crate::syntax::SyntaxKind;

/// A single lexed token with its classification and source location.
///
/// Use [`SyntaxKind`] to determine what the token represents, and
/// [`SourceRange`] to index back into its [`SourceDocument`](crate::SourceDocument).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// What kind of token this is (keyword, identifier, literal, etc.).
    pub kind: SyntaxKind,
    /// Byte range in the source text that produced this token.
    pub span: SourceRange,
}
