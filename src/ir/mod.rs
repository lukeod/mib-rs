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
#[derive(Clone)]
pub struct Module {
    pub name: String,
    pub language: Language,
    pub imports: Vec<Import>,
    pub definitions: Vec<Definition>,
    pub span: Span,
    pub diagnostics: Vec<Diagnostic>,
    /// File path this module was loaded from. Empty for synthetic base modules.
    pub source_path: String,
    /// Maps line numbers to byte offsets of line starts.
    /// Entry i holds the byte offset where line i+1 begins (0-indexed).
    pub line_table: Vec<usize>,
}

impl Module {
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
    pub module: String,
    pub symbol: String,
    pub span: Span,
}
