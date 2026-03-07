use crate::types::Span;

/// A named reference in MIB source with its span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

/// A string literal value with its source span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedString {
    pub value: String,
    pub span: Span,
}

/// A named number in an enumeration or BITS definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedNumber {
    pub name: Ident,
    pub value: i64,
    pub span: Span,
}
