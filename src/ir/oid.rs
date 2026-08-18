//! IR types for OID assignments and their components.
//!
//! These mirror [`crate::ast::oid`] but use `String` names instead of
//! [`Ident`](crate::ast::Ident) nodes.

use crate::source::SourceRange;

/// An unresolved OID assignment. Components remain as symbolic references
/// until the resolver phase.
#[derive(Debug, Clone)]
pub struct OidAssignment {
    /// Ordered list of OID components (symbolic or numeric).
    pub components: Vec<OidComponent>,
    /// Source range covering the entire `{ ... }` assignment.
    pub range: SourceRange,
}

/// A single element of an OID assignment.
#[derive(Debug, Clone)]
pub enum OidComponent {
    /// Symbolic name reference, e.g. `internet`.
    Name { name: String, range: SourceRange },
    /// Numeric arc, e.g. `1` or `31`.
    Number { value: u32, range: SourceRange },
    /// Name with number, e.g. `org(3)`.
    NamedNumber {
        name: String,
        number: u32,
        /// Exact source range of `name`, excluding the numeric annotation.
        name_range: SourceRange,
        range: SourceRange,
    },
    /// Module-qualified reference, e.g. `SNMPv2-SMI.enterprises`.
    QualifiedName {
        module: String,
        name: String,
        range: SourceRange,
    },
    /// Module-qualified name with number, e.g. `SNMPv2-SMI.enterprises(1)`.
    QualifiedNamedNumber {
        module: String,
        name: String,
        number: u32,
        /// Exact source range of `module.name`, excluding the numeric annotation.
        name_range: SourceRange,
        range: SourceRange,
    },
}

impl OidComponent {
    /// Returns the source range of this component.
    pub fn range(&self) -> SourceRange {
        match self {
            OidComponent::Name { range, .. }
            | OidComponent::Number { range, .. }
            | OidComponent::NamedNumber { range, .. }
            | OidComponent::QualifiedName { range, .. }
            | OidComponent::QualifiedNamedNumber { range, .. } => *range,
        }
    }
}
