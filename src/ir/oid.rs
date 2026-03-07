use crate::types::Span;

/// An unresolved OID assignment. Components remain as symbolic references
/// until the resolver phase.
#[derive(Debug, Clone)]
pub struct OidAssignment {
    pub components: Vec<OidComponent>,
    pub span: Span,
}

/// A single element of an OID assignment.
#[derive(Debug, Clone)]
pub enum OidComponent {
    /// Symbolic name reference, e.g. internet.
    Name { name: String, span: Span },
    /// Numeric arc, e.g. 1 or 31.
    Number { value: u32, span: Span },
    /// Name with number, e.g. org(3).
    NamedNumber {
        name: String,
        number: u32,
        span: Span,
    },
    /// Module-qualified reference, e.g. SNMPv2-SMI.enterprises.
    QualifiedName {
        module: String,
        name: String,
        span: Span,
    },
    /// Module-qualified name with number, e.g. SNMPv2-SMI.enterprises(1).
    QualifiedNamedNumber {
        module: String,
        name: String,
        number: u32,
        span: Span,
    },
}

impl OidComponent {
    pub fn span(&self) -> Span {
        match self {
            OidComponent::Name { span, .. }
            | OidComponent::Number { span, .. }
            | OidComponent::NamedNumber { span, .. }
            | OidComponent::QualifiedName { span, .. }
            | OidComponent::QualifiedNamedNumber { span, .. } => *span,
        }
    }
}
