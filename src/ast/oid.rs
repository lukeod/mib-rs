use super::common::Ident;
use crate::types::Span;

/// Parsed components of an OBJECT IDENTIFIER value,
/// e.g. { iso org(3) dod(6) 1 }.
#[derive(Debug, PartialEq, Eq)]
pub struct OidAssignment {
    pub components: Vec<OidComponent>,
    pub span: Span,
}

/// A single element in an OID value assignment.
#[derive(Debug, PartialEq, Eq)]
pub enum OidComponent {
    /// Named reference, e.g. internet, ifEntry.
    Name(Ident),
    /// Numeric sub-identifier, e.g. 1, 31.
    Number { value: u32, span: Span },
    /// Name with number, e.g. iso(1), org(3).
    NamedNumber { name: Ident, num: u32, span: Span },
    /// Module-qualified reference, e.g. SNMPv2-SMI.enterprises.
    QualifiedName {
        module_name: Ident,
        name: Ident,
        span: Span,
    },
    /// Module-qualified name with number, e.g. SNMPv2-SMI.enterprises(1).
    QualifiedNamedNumber {
        module_name: Ident,
        name: Ident,
        num: u32,
        span: Span,
    },
}

impl OidComponent {
    pub fn span(&self) -> Span {
        match self {
            OidComponent::Name(ident) => ident.span,
            OidComponent::Number { span, .. }
            | OidComponent::NamedNumber { span, .. }
            | OidComponent::QualifiedName { span, .. }
            | OidComponent::QualifiedNamedNumber { span, .. } => *span,
        }
    }
}
