pub mod common;
pub mod definition;
pub mod oid;
pub mod syntax;

pub use common::{Ident, NamedNumber, QuotedString};
pub use definition::*;
pub use oid::{OidAssignment, OidComponent};
pub use syntax::*;

use crate::types::{Severity, Span, SpanDiagnostic};

/// Top-level AST node for a parsed MIB module.
#[derive(Debug, PartialEq, Eq)]
pub struct Module {
    pub name: Ident,
    pub imports: Vec<ImportClause>,
    pub body: Vec<Definition>,
    pub span: Span,
    pub diagnostics: Vec<SpanDiagnostic>,
}

impl Module {
    pub fn new(name: Ident, span: Span) -> Self {
        Module {
            name,
            imports: Vec::new(),
            body: Vec::new(),
            span,
            diagnostics: Vec::new(),
        }
    }

    /// Reports whether any diagnostic has error severity or worse.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity <= Severity::Error)
    }
}

/// Groups symbols imported from a single source module.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportClause {
    pub symbols: Vec<Ident>,
    pub from_module: Ident,
    pub span: Span,
}
