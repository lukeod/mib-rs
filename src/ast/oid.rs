//! AST types for OBJECT IDENTIFIER value assignments and their components.
//!
//! An [`OidAssignment`] represents the `::= { ... }` portion of an OID
//! definition, containing a sequence of [`OidComponent`]s that form the
//! path from a well-known root to the assigned node.

use super::common::Ident;
use crate::source::SourceRange;

/// Parsed components of an OBJECT IDENTIFIER value,
/// e.g. `{ iso org(3) dod(6) 1 }`.
#[derive(Debug, PartialEq, Eq)]
pub struct OidAssignment {
    /// The ordered list of components forming the OID path.
    pub components: Vec<OidComponent>,
    /// Source span covering the entire `{ ... }` assignment.
    pub span: SourceRange,
}

/// A single element in an OID value assignment.
///
/// OID values are written as a sequence of these components between
/// braces, mixing named references and numeric sub-identifiers.
/// Overflowing numeric sub-identifiers are retained as zero and accompanied
/// by an `invalid-u32` parser diagnostic over the literal.
#[derive(Debug, PartialEq, Eq)]
pub enum OidComponent {
    /// Named reference, e.g. `internet`, `ifEntry`.
    Name(Ident),
    /// Numeric sub-identifier, e.g. `1`, `31`.
    Number { value: u32, span: SourceRange },
    /// Name with number, e.g. `iso(1)`, `org(3)`.
    NamedNumber {
        name: Ident,
        num: u32,
        span: SourceRange,
    },
    /// Module-qualified reference, e.g. `SNMPv2-SMI.enterprises`.
    QualifiedName {
        module_name: Ident,
        name: Ident,
        span: SourceRange,
    },
    /// Module-qualified name with number, e.g. `SNMPv2-SMI.enterprises(1)`.
    QualifiedNamedNumber {
        module_name: Ident,
        name: Ident,
        num: u32,
        span: SourceRange,
    },
}

impl OidComponent {
    /// Returns the source span of this component.
    pub fn span(&self) -> SourceRange {
        match self {
            OidComponent::Name(ident) => ident.span,
            OidComponent::Number { span, .. }
            | OidComponent::NamedNumber { span, .. }
            | OidComponent::QualifiedName { span, .. }
            | OidComponent::QualifiedNamedNumber { span, .. } => *span,
        }
    }
}
