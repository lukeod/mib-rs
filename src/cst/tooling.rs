//! Combined syntactic and semantic source navigation for tooling.

use crate::mib::{Module as SemanticModule, SemanticSpan, SemanticSpanKind};
use crate::source::{
    ByteOffset, Position, PositionEncoding, PositionError, SourceDocument, SourceRange,
    SourceRangeError,
};

use super::{CursorContext, SyntaxKind, SyntaxTree};

/// Failure to pair a concrete syntax tree with a resolved module.
///
/// [`crate::SourceId`] values are local to one compilation, so this check does
/// not compare them. A pair is accepted only when the source origin and
/// complete bytes are equal. Display labels are intentionally not
/// identity: the CST and resolved compilation may present the same document
/// differently. This permits separate source arenas while rejecting stale
/// editor buffers and unrelated documents whose numeric source IDs happen to
/// be equal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SourcePairError {
    /// The resolved module was synthesized or otherwise has no retained source.
    #[error("the resolved module does not retain a source document")]
    SemanticSourceUnavailable,
    /// The CST and resolved module describe different source documents.
    #[error("the syntax tree and resolved module describe different source documents")]
    MismatchedDocuments,
}

/// A range paired with the document that owns its compilation-local source ID.
///
/// Keep this pair intact when crossing compilation boundaries. Resolving a
/// [`SourceRange`] through another document solely because its numeric
/// [`crate::SourceId`] is equal is invalid.
#[derive(Clone, Copy, Debug)]
pub struct LocatedRange<'src> {
    document: &'src SourceDocument,
    range: SourceRange,
}

impl<'src> LocatedRange<'src> {
    fn new(document: &'src SourceDocument, range: SourceRange) -> Self {
        debug_assert_eq!(document.id(), range.source());
        Self { document, range }
    }

    /// Return the document that owns this range.
    pub fn document(self) -> &'src SourceDocument {
        self.document
    }

    /// Return the checked, source-qualified byte range.
    pub fn range(self) -> SourceRange {
        self.range
    }

    /// Return the exact source bytes covered by this range.
    ///
    /// # Errors
    ///
    /// Returns an error only if the retained range invariants were violated.
    pub fn text(self) -> Result<&'src [u8], SourceRangeError> {
        self.document.slice(self.range)
    }
}

/// Combined tooling context at one source position.
///
/// The syntactic result is always retained for a valid offset, including when
/// no resolved module was supplied or semantic resolution found no symbol.
/// Semantic lookup is suppressed only in comments and string literal bodies.
/// Otherwise `semantic` preserves the result of
/// [`SemanticModule::semantic_at`], including broad definition spans selected
/// on their internal whitespace, punctuation, and keywords.
///
/// `syntax` and `semantic` remain separate so recovery context is never hidden
/// by a resolved result. Their ranges belong to separate compilation-local
/// source arenas; use [`Self::syntax_range`] and [`Self::semantic_range`] to
/// retain the corresponding owner.
#[derive(Clone, Copy, Debug)]
pub struct SymbolAtPosition<'tree, 'mib> {
    /// Lossless syntactic context at the requested position.
    pub syntax: CursorContext<'tree, 'tree>,
    /// Resolved semantic span, when available and appropriate for the token.
    pub semantic: Option<SemanticSpan<'mib>>,
    syntax_document: &'tree SourceDocument,
    semantic_document: Option<&'mib SourceDocument>,
}

impl<'tree, 'mib> SymbolAtPosition<'tree, 'mib> {
    /// Return the selected CST token range with its source-owning document.
    pub fn syntax_range(self) -> LocatedRange<'tree> {
        LocatedRange::new(self.syntax_document, self.syntax.token().range())
    }

    /// Return the semantic span range with its source-owning document.
    pub fn semantic_range(self) -> Option<LocatedRange<'mib>> {
        Some(LocatedRange::new(
            self.semantic_document?,
            self.semantic?.range,
        ))
    }

    /// Return the exact source range most useful for a symbol-oriented action.
    ///
    /// Semantic results use the resolved module's source owner. Reference and
    /// import spans are already exact; a definition's broad declaration span
    /// is narrowed to its leading name. With no semantic result, this falls
    /// back to the selected CST token (including an empty EOF token).
    pub fn primary_range<'src>(self) -> LocatedRange<'src>
    where
        'tree: 'src,
        'mib: 'src,
    {
        let Some(span) = self.semantic else {
            let syntax = self.syntax_range();
            return LocatedRange::new(syntax.document(), syntax.range());
        };
        let document = self
            .semantic_document
            .expect("a semantic span has its paired retained source");
        let range = primary_semantic_range(document, span);
        LocatedRange::new(document, range)
    }
}

/// Source-safe facade for repeated symbol-at-position queries.
///
/// Construct with `None` to query broken or parse-only source syntactically.
/// Supplying a module validates provenance once, before any byte offset can be
/// interpreted in both independently owned source arenas.
#[derive(Clone, Copy, Debug)]
pub struct SymbolNavigator<'tree, 'mib> {
    tree: &'tree SyntaxTree,
    module: Option<SemanticModule<'mib>>,
}

impl<'tree, 'mib> SymbolNavigator<'tree, 'mib> {
    /// Pair a syntax tree with an optional resolved module.
    ///
    /// # Errors
    ///
    /// Returns [`SourcePairError::SemanticSourceUnavailable`] if `module` has
    /// no retained source, or [`SourcePairError::MismatchedDocuments`] unless
    /// both source documents have equal stable origin and complete bytes.
    /// Display labels may differ.
    pub fn new(
        tree: &'tree SyntaxTree,
        module: Option<SemanticModule<'mib>>,
    ) -> Result<Self, SourcePairError> {
        if let Some(module) = module {
            let semantic = module
                .source()
                .ok_or(SourcePairError::SemanticSourceUnavailable)?;
            let syntax = tree.document();
            if syntax.origin() != semantic.origin() || syntax.bytes() != semantic.bytes() {
                return Err(SourcePairError::MismatchedDocuments);
            }
        }
        Ok(Self { tree, module })
    }

    /// Return the retained syntax tree.
    pub fn tree(self) -> &'tree SyntaxTree {
        self.tree
    }

    /// Return the paired resolved module, if any.
    pub fn module(self) -> Option<SemanticModule<'mib>> {
        self.module
    }

    /// Query combined context at a byte offset.
    ///
    /// The offset is interpreted in the CST document. The exact EOF offset is
    /// valid and returns syntax context without semantics; an offset after EOF
    /// returns `None`.
    pub fn symbol_at(self, offset: ByteOffset) -> Option<SymbolAtPosition<'tree, 'mib>> {
        let syntax = self.tree.cursor_context(offset)?;
        let semantic = self.module.and_then(|module| {
            if suppress_semantics(syntax) {
                return None;
            }
            module.semantic_at(offset)
        });

        Some(SymbolAtPosition {
            syntax,
            semantic,
            syntax_document: self.tree.document(),
            semantic_document: self.module.and_then(SemanticModule::source),
        })
    }

    /// Query combined context at a zero-based editor position.
    ///
    /// Position conversion uses the CST document and the requested UTF
    /// encoding. Invalid lines, columns, code-point boundaries, and UTF-8 are
    /// returned unchanged as [`PositionError`].
    pub fn symbol_at_position(
        self,
        position: Position,
        encoding: PositionEncoding,
    ) -> Result<Option<SymbolAtPosition<'tree, 'mib>>, PositionError> {
        let offset = self.tree.document().position_offset(position, encoding)?;
        Ok(self.symbol_at(offset))
    }
}

fn suppress_semantics(context: CursorContext<'_, '_>) -> bool {
    matches!(
        context.token().kind(),
        SyntaxKind::Comment
            | SyntaxKind::QuotedString
            | SyntaxKind::HexString
            | SyntaxKind::BinString
    )
}

fn primary_semantic_range(document: &SourceDocument, span: SemanticSpan<'_>) -> SourceRange {
    assert_eq!(
        document.id(),
        span.range.source(),
        "a semantic span belongs to its module source"
    );
    if span.kind != SemanticSpanKind::Definition {
        return span.range;
    }

    let start = span.range.start().as_usize();
    let end = start
        .checked_add(span.declared_name.len())
        .expect("a retained definition name fits the source coordinate space");
    assert!(
        end <= span.range.end().as_usize(),
        "a retained definition name is inside its definition span"
    );
    let range = document
        .range(start..end)
        .expect("a retained definition span belongs to its module source");
    assert_eq!(
        document
            .slice(range)
            .expect("the narrowed definition range belongs to its module source"),
        span.declared_name.as_bytes(),
        "a retained definition span starts with its declared name"
    );
    range
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::cst;
    use crate::mib::{Mib, ModuleData};
    use crate::source::{SourceCandidate, SourceOrigin};

    #[test]
    fn source_less_semantic_module_is_rejected_before_lookup() {
        let candidate = SourceCandidate::new(
            "syntax",
            SourceOrigin::memory("syntax"),
            "syntax",
            Arc::<[u8]>::from(b"SYNTAX-MIB DEFINITIONS ::= BEGIN END".as_slice()),
        );
        let (tree, _) = cst::parse(candidate).unwrap();

        let mut mib = Mib::new();
        mib.add_module(ModuleData::new("GENERATED-MIB".into()));
        let module = mib.module("GENERATED-MIB").unwrap();
        assert_eq!(
            SymbolNavigator::new(&tree, Some(module)).unwrap_err(),
            SourcePairError::SemanticSourceUnavailable
        );
    }
}
