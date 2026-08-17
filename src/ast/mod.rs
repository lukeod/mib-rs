//! Abstract syntax tree types produced by the parser.
//!
//! These types directly reflect the surface syntax of SMI MIB modules.
//! After parsing, the AST is consumed by the [lowering pass](crate::lower)
//! which normalizes it into a language-independent [`ir::Module`](crate::ir::Module).

pub mod common;
pub mod definition;
pub mod oid;
pub mod syntax;

pub use common::{Ident, NamedNumber, QuotedString};
pub use definition::*;
pub use oid::{OidAssignment, OidComponent};
pub use syntax::*;

use crate::source::SourceRange;
use crate::types::{Diagnostic, Severity};

/// Top-level AST node for a parsed MIB module.
///
/// Produced by the parser from a single MIB source file. Contains the
/// module's [`ImportClause`]s, body [`Definition`]s, and any diagnostics
/// emitted during parsing.
#[derive(Debug, PartialEq, Eq)]
pub struct Module {
    /// Module name (e.g. `IF-MIB`). `None` if parsing failed before the header.
    pub name: Option<Ident>,
    /// `IMPORTS ... ;` clauses.
    pub imports: Vec<ImportClause>,
    /// Definitions in the module body, between `BEGIN` and `END`.
    pub body: Vec<Definition>,
    /// Source range covering the entire module.
    pub span: SourceRange,
    /// Diagnostics collected during parsing.
    pub diagnostics: Vec<Diagnostic>,
}

impl Module {
    /// Creates a new module with the given name and span, and empty imports/body/diagnostics.
    pub fn new(name: Ident, span: SourceRange) -> Self {
        Module {
            name: Some(name),
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

/// Symbols imported from a single source module.
///
/// Corresponds to one `symbol1, symbol2 FROM ModuleName` group
/// inside an `IMPORTS` section.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportClause {
    /// Imported symbol names.
    pub symbols: Vec<Ident>,
    /// Source module name (the `FROM` target).
    pub from_module: Ident,
    /// Source range covering the entire clause.
    pub span: SourceRange,
}
