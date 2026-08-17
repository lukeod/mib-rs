//! Intermediate representation produced by [lowering](crate::lower) the AST.
//!
//! The IR is language-independent: SMIv1 and SMIv2 constructs are unified
//! (e.g. `TRAP-TYPE` and `NOTIFICATION-TYPE` both become [`Notification`]).
//! Type and OID references remain unresolved strings until the resolver phase
//! transforms the IR into a fully resolved [`Mib`](crate::mib::Mib).
//!
//! Unlike the AST, the IR uses plain `String` values instead of [`Ident`](crate::ast::Ident)
//! nodes, and optional clauses are represented as empty strings rather than `Option`s.

pub mod definition;
pub mod oid;
pub mod syntax;

pub use definition::*;
pub use oid::{OidAssignment, OidComponent};
pub use syntax::*;

use crate::source::{SourceId, SourceRange};
use crate::types::{Diagnostic, Language};

/// A normalized, language-independent MIB module.
///
/// Lowering transforms AST structures into this simplified representation
/// independent of whether the source was SMIv1 or SMIv2.
#[derive(Debug, Clone)]
pub struct Module {
    /// Canonical module name (e.g. `"IF-MIB"`).
    pub name: String,
    /// Detected SMI language version, or [`Language::Unknown`] when syntax and
    /// imports provide insufficient or conflicting version evidence.
    pub language: Language,
    /// Flattened imports: one [`Import`] per imported symbol.
    pub imports: Vec<Import>,
    /// All definitions in source order.
    pub definitions: Vec<Definition>,
    /// Range covering the entire module, or `None` for a generated module.
    pub range: Option<SourceRange>,
    /// Diagnostics collected during lowering.
    pub diagnostics: Vec<Diagnostic>,
    /// Compilation-local source document containing this module.
    pub(crate) source_id: Option<SourceId>,
}

impl Module {
    /// Creates a new module with the given name and source range. All other fields
    /// are initialized to empty/default values.
    pub fn new(name: String, range: Option<SourceRange>) -> Self {
        let source_id = range.map(SourceRange::source);
        Module {
            name,
            language: Language::Unknown,
            imports: Vec::new(),
            definitions: Vec::new(),
            range,
            diagnostics: Vec::new(),
            source_id,
        }
    }

    /// Returns an iterator over the names of all definitions.
    pub fn definition_names(&self) -> impl Iterator<Item = &str> {
        self.definitions.iter().map(|d| d.name())
    }
}

/// A single imported symbol, flattened from the AST's grouped format.
#[derive(Debug, Clone)]
pub struct Import {
    /// Source module name (the FROM target).
    pub module: String,
    /// Imported symbol name.
    pub symbol: String,
    /// Source range of the symbol in the `IMPORTS` section.
    pub range: SourceRange,
}
