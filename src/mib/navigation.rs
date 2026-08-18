//! Source-oriented navigation over the resolved semantic model.
//!
//! Unlike the lossless CST cursor helpers, this module answers questions about
//! names retained by lowering and linked by resolution. Queries are scoped to
//! one module and use the module's retained source document.

use crate::source::{ByteOffset, Position, PositionEncoding, PositionError, SourceId, SourceRange};

use super::{ModuleId, Symbol};

/// The semantic role of a source span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticSpanKind {
    /// The complete source range of a definition owned by the queried module.
    Definition,
    /// A symbol declared in the module's `IMPORTS` section.
    Import,
    /// A symbolic component in an OID assignment or an OID-valued `DEFVAL`.
    OidReference,
    /// A named type used by a type-syntax expression.
    TypeReference,
    /// A named semantic reference in a group or capability clause.
    SymbolReference,
}

impl SemanticSpanKind {
    const fn tie_break_priority(self) -> u8 {
        match self {
            Self::Import => 3,
            Self::OidReference => 2,
            Self::TypeReference | Self::SymbolReference => 1,
            Self::Definition => 0,
        }
    }
}

/// Resolved semantic context for a source position.
///
/// `declared_name` and `range` always describe the text written in the queried
/// module, including when resolution failed. `symbol` and `module` identify the
/// exact declared identity when one is available, even if that identity has the
/// wrong semantic kind for its use. `module` may therefore be present while
/// `symbol` is absent when a target module is known but the name is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticSpan<'a> {
    /// The semantic role of the matched span.
    pub kind: SemanticSpanKind,
    /// The name as declared in source. Qualified OID names retain their module
    /// qualifier, for example `SNMPv2-SMI.enterprises`.
    pub declared_name: &'a str,
    /// The exact source range retained for this semantic item.
    pub range: SourceRange,
    /// The exact declared symbol, when one is available.
    ///
    /// This may contain a symbol of the wrong semantic kind when use-site
    /// resolution failed; `None` means no declared symbol was available.
    pub symbol: Option<Symbol>,
    /// The resolved defining module, when one is known.
    pub module: Option<ModuleId>,
}

#[derive(Debug, Clone)]
pub(crate) struct SemanticSpanEntry {
    pub(crate) kind: SemanticSpanKind,
    pub(crate) declared_name: String,
    pub(crate) range: SourceRange,
    pub(crate) symbol: Option<Symbol>,
    pub(crate) module: Option<ModuleId>,
    ordinal: usize,
}

impl SemanticSpanEntry {
    pub(crate) fn new(
        kind: SemanticSpanKind,
        declared_name: String,
        range: SourceRange,
        symbol: Option<Symbol>,
        module: Option<ModuleId>,
    ) -> Self {
        Self {
            kind,
            declared_name,
            range,
            symbol,
            module,
            ordinal: 0,
        }
    }

    fn as_public(&self) -> SemanticSpan<'_> {
        SemanticSpan {
            kind: self.kind,
            declared_name: &self.declared_name,
            range: self.range,
            symbol: self.symbol,
            module: self.module,
        }
    }

    fn width(&self) -> u32 {
        self.range.end().get() - self.range.start().get()
    }

    fn outranks(&self, other: &Self) -> bool {
        self.width()
            .cmp(&other.width())
            .then_with(|| {
                other
                    .kind
                    .tie_break_priority()
                    .cmp(&self.kind.tie_break_priority())
            })
            .then_with(|| other.range.start().cmp(&self.range.start()))
            .then_with(|| self.ordinal.cmp(&other.ordinal))
            .is_lt()
    }
}

/// Precomputed, module-local semantic span index.
///
/// References and definitions are indexed separately so a broad definition
/// range does not force a linear scan of all earlier references. Reference
/// candidates use a prefix maximum endpoint to stop searching once no earlier
/// interval can contain the requested offset. Lookup is logarithmic plus the
/// number of potentially overlapping preceding intervals; adversarial deeply
/// nested intervals can therefore make one lookup linear in the module's span
/// count.
#[derive(Debug, Clone, Default)]
pub(crate) struct SemanticSpanIndex {
    source_id: Option<SourceId>,
    definitions: Vec<SemanticSpanEntry>,
    definition_prefix_max_end: Vec<ByteOffset>,
    references: Vec<SemanticSpanEntry>,
    reference_prefix_max_end: Vec<ByteOffset>,
}

impl SemanticSpanIndex {
    pub(crate) fn build(
        source_id: Option<SourceId>,
        entries: impl IntoIterator<Item = SemanticSpanEntry>,
    ) -> Self {
        let mut definitions = Vec::new();
        let mut references = Vec::new();

        for (ordinal, mut entry) in entries.into_iter().enumerate() {
            if source_id != Some(entry.range.source()) || entry.range.start() == entry.range.end() {
                continue;
            }
            entry.ordinal = ordinal;
            if entry.kind == SemanticSpanKind::Definition {
                definitions.push(entry);
            } else {
                references.push(entry);
            }
        }

        let sort = |entries: &mut Vec<SemanticSpanEntry>| {
            entries.sort_by_key(|entry| {
                (
                    entry.range.start(),
                    entry.range.end(),
                    entry.kind.tie_break_priority(),
                    entry.ordinal,
                )
            });
        };
        sort(&mut definitions);
        sort(&mut references);

        let prefix_max_end = |entries: &[SemanticSpanEntry]| {
            let mut maximum = ByteOffset::new(0);
            entries
                .iter()
                .map(|entry| {
                    maximum = maximum.max(entry.range.end());
                    maximum
                })
                .collect()
        };
        let definition_prefix_max_end = prefix_max_end(&definitions);
        let reference_prefix_max_end = prefix_max_end(&references);

        Self {
            source_id,
            definitions,
            definition_prefix_max_end,
            references,
            reference_prefix_max_end,
        }
    }

    pub(crate) fn source_id(&self) -> Option<SourceId> {
        self.source_id
    }

    pub(crate) fn get(&self, offset: ByteOffset) -> Option<SemanticSpan<'_>> {
        self.best_reference(offset)
            .or_else(|| self.best_definition(offset))
            .map(SemanticSpanEntry::as_public)
    }

    fn best_reference(&self, offset: ByteOffset) -> Option<&SemanticSpanEntry> {
        let mut cursor = self
            .references
            .partition_point(|entry| entry.range.start() <= offset);
        let mut best: Option<&SemanticSpanEntry> = None;

        while cursor > 0 {
            cursor -= 1;
            if self.reference_prefix_max_end[cursor] <= offset {
                break;
            }
            let candidate = &self.references[cursor];
            if candidate.range.start() <= offset
                && offset < candidate.range.end()
                && best.is_none_or(|current| candidate.outranks(current))
            {
                best = Some(candidate);
            }
        }
        best
    }

    fn best_definition(&self, offset: ByteOffset) -> Option<&SemanticSpanEntry> {
        let mut cursor = self
            .definitions
            .partition_point(|entry| entry.range.start() <= offset);
        let mut best: Option<&SemanticSpanEntry> = None;
        while cursor > 0 {
            cursor -= 1;
            if self.definition_prefix_max_end[cursor] <= offset {
                break;
            }
            let candidate = &self.definitions[cursor];
            if offset < candidate.range.end()
                && best.is_none_or(|current| candidate.outranks(current))
            {
                best = Some(candidate);
            }
        }
        best
    }
}

/// Convert an editor position for a module source and query its semantic span.
pub(crate) fn at_position<'a>(
    index: &'a SemanticSpanIndex,
    document: Option<&crate::source::SourceDocument>,
    position: Position,
    encoding: PositionEncoding,
) -> Result<Option<SemanticSpan<'a>>, PositionError> {
    let Some(document) = document else {
        return Ok(None);
    };
    let offset = document.position_offset(position, encoding)?;
    Ok(index.get(offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{SourceOrigin, SourceSet};
    use std::sync::Arc;

    #[test]
    fn overlap_precedence_is_innermost_then_kind_then_retained_order() {
        let mut sources = SourceSet::new();
        let source_id = sources
            .insert(
                SourceOrigin::memory("overlap"),
                "overlap",
                Arc::from(&b"0123456789"[..]),
            )
            .unwrap();
        let source = sources.get(source_id).unwrap();
        let entries = vec![
            SemanticSpanEntry::new(
                SemanticSpanKind::Definition,
                "definition".into(),
                source.range(0..10).unwrap(),
                None,
                None,
            ),
            SemanticSpanEntry::new(
                SemanticSpanKind::TypeReference,
                "wide".into(),
                source.range(2..8).unwrap(),
                None,
                None,
            ),
            SemanticSpanEntry::new(
                SemanticSpanKind::OidReference,
                "oid".into(),
                source.range(3..7).unwrap(),
                None,
                None,
            ),
            SemanticSpanEntry::new(
                SemanticSpanKind::TypeReference,
                "type".into(),
                source.range(3..7).unwrap(),
                None,
                None,
            ),
            SemanticSpanEntry::new(
                SemanticSpanKind::OidReference,
                "later".into(),
                source.range(3..7).unwrap(),
                None,
                None,
            ),
        ];
        let index = SemanticSpanIndex::build(Some(source_id), entries);

        assert_eq!(
            index.get(ByteOffset::new(1)).unwrap().declared_name,
            "definition"
        );
        assert_eq!(index.get(ByteOffset::new(2)).unwrap().declared_name, "wide");
        assert_eq!(index.get(ByteOffset::new(3)).unwrap().declared_name, "oid");
        assert_eq!(index.get(ByteOffset::new(7)).unwrap().declared_name, "wide");
        assert!(index.get(ByteOffset::new(10)).is_none());
    }

    #[test]
    fn equal_width_same_kind_overlap_prefers_the_later_start() {
        let mut sources = SourceSet::new();
        let source_id = sources
            .insert(
                SourceOrigin::memory("equal-width"),
                "equal-width",
                Arc::from(&b"0123456789"[..]),
            )
            .unwrap();
        let source = sources.get(source_id).unwrap();
        let index = SemanticSpanIndex::build(
            Some(source_id),
            [
                SemanticSpanEntry::new(
                    SemanticSpanKind::SymbolReference,
                    "left".into(),
                    source.range(1..6).unwrap(),
                    None,
                    None,
                ),
                SemanticSpanEntry::new(
                    SemanticSpanKind::SymbolReference,
                    "right".into(),
                    source.range(2..7).unwrap(),
                    None,
                    None,
                ),
            ],
        );
        assert_eq!(
            index.get(ByteOffset::new(3)).unwrap().declared_name,
            "right"
        );
    }

    #[test]
    fn foreign_and_empty_ranges_are_not_indexed() {
        let mut sources = SourceSet::new();
        let first = sources
            .insert(
                SourceOrigin::memory("first"),
                "first",
                Arc::from(&b"abc"[..]),
            )
            .unwrap();
        let second = sources
            .insert(
                SourceOrigin::memory("second"),
                "second",
                Arc::from(&b"xyz"[..]),
            )
            .unwrap();
        let entries = vec![
            SemanticSpanEntry::new(
                SemanticSpanKind::Import,
                "foreign".into(),
                sources.get(second).unwrap().range(0..1).unwrap(),
                None,
                None,
            ),
            SemanticSpanEntry::new(
                SemanticSpanKind::Import,
                "empty".into(),
                sources.get(first).unwrap().empty_range(0).unwrap(),
                None,
                None,
            ),
        ];
        let index = SemanticSpanIndex::build(Some(first), entries);
        assert!(index.get(ByteOffset::new(0)).is_none());
    }

    #[test]
    fn index_without_a_source_never_matches() {
        let mut sources = SourceSet::new();
        let source_id = sources
            .insert(
                SourceOrigin::memory("source"),
                "source",
                Arc::from(&b"abc"[..]),
            )
            .unwrap();
        let entry = SemanticSpanEntry::new(
            SemanticSpanKind::Definition,
            "name".into(),
            sources.get(source_id).unwrap().range(0..3).unwrap(),
            None,
            None,
        );
        let index = SemanticSpanIndex::build(None, [entry]);
        assert_eq!(index.source_id(), None);
        assert!(index.get(ByteOffset::new(0)).is_none());
    }

    #[test]
    fn source_less_module_handle_supports_every_query_form() {
        let mut mib = crate::mib::Mib::new();
        mib.add_module(crate::mib::ModuleData::new("GENERATED-MIB".into()));
        let module = mib.module("GENERATED-MIB").unwrap();
        assert_eq!(module.source_id(), None);
        assert!(module.semantic_at(ByteOffset::new(0)).is_none());

        let mut sources = SourceSet::new();
        let foreign = sources
            .insert(
                SourceOrigin::memory("foreign"),
                "foreign",
                Arc::from(&b"x"[..]),
            )
            .unwrap();
        assert!(
            module
                .semantic_at_source(foreign, ByteOffset::new(0))
                .is_none()
        );
        assert_eq!(
            module
                .semantic_at_position(Position::new(0, 0), PositionEncoding::Utf8)
                .unwrap(),
            None
        );
        assert_eq!(
            module
                .semantic_at_source_position(
                    foreign,
                    Position::new(u32::MAX, u32::MAX),
                    PositionEncoding::Utf16,
                )
                .unwrap(),
            None
        );
    }
}
