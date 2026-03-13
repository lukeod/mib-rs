//! Common AST leaf types shared across definitions and syntax nodes.
//!
//! These small types ([`Ident`], [`QuotedString`], [`NamedNumber`]) appear
//! throughout the AST as building blocks for larger constructs.

use crate::types::Span;

/// A named reference in MIB source with its location span.
///
/// Used for module names, object names, type names, and any other
/// identifier token in the AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    /// The identifier text.
    pub name: String,
    /// Source location of the identifier.
    pub span: Span,
}

/// A quoted string literal with its source span.
///
/// Appears in DESCRIPTION, REFERENCE, CONTACT-INFO, and similar clauses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedString {
    /// The string content (quotes stripped).
    pub value: String,
    /// Source location of the quoted string.
    pub span: Span,
}

/// A named number in an enumeration or BITS definition.
///
/// For example, `up(1)` in `INTEGER { up(1), down(2) }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedNumber {
    /// The label, e.g. `up`.
    pub name: Ident,
    /// The numeric value, e.g. `1`.
    pub value: i64,
    /// Source location covering `name(value)`.
    pub span: Span,
}
