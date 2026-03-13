//! Intermediate representation produced by [lowering](crate::lower) the AST.
//!
//! The IR is language-independent: SMIv1 and SMIv2 constructs are unified
//! (e.g. TRAP-TYPE and NOTIFICATION-TYPE both become [`Notification`]).
//! Type and OID references remain unresolved strings until the resolver phase
//! transforms the IR into a fully resolved [`Mib`](crate::mib::Mib).

pub mod definition;
pub mod oid;
pub mod syntax;

pub use definition::*;
pub use oid::{OidAssignment, OidComponent};
pub use syntax::*;

use crate::types::{Diagnostic, Language, Span};

/// A normalized, language-independent MIB module.
///
/// Lowering transforms AST structures into this simplified representation
/// independent of whether the source was SMIv1 or SMIv2.
#[derive(Debug, Clone)]
pub struct Module {
    /// Canonical module name (e.g. `"IF-MIB"`).
    pub name: String,
    /// Detected SMI language version.
    pub language: Language,
    /// Flattened imports (one entry per symbol).
    pub imports: Vec<Import>,
    /// All definitions in source order.
    pub definitions: Vec<Definition>,
    /// Span covering the entire module.
    pub span: Span,
    /// Diagnostics collected during lowering.
    pub diagnostics: Vec<Diagnostic>,
    /// File path this module was loaded from. Empty for synthetic base modules.
    pub source_path: String,
    /// Maps line numbers to byte offsets of line starts.
    /// Entry i holds the byte offset where line i+1 begins (0-indexed).
    pub line_table: Vec<usize>,
}

impl Module {
    /// Creates a new module with the given name and span. All other fields
    /// are initialized to empty/default values.
    pub fn new(name: String, span: Span) -> Self {
        Module {
            name,
            language: Language::Unknown,
            imports: Vec::new(),
            definitions: Vec::new(),
            span,
            diagnostics: Vec::new(),
            source_path: String::new(),
            line_table: Vec::new(),
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
    /// Source span of the symbol in the IMPORTS section.
    pub span: Span,
}
