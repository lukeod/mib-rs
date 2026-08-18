use std::sync::Arc;

use mib_rs::compile::{LocatedRange, SourcePairError, SymbolAtPosition, SymbolNavigator, parse};
use mib_rs::source::{ByteOffset, Position, PositionEncoding, memory};
use mib_rs::{
    DiagnosticConfig, Loader, ResolverStrictness, SemanticSpanKind, SourceCandidate, SourceOrigin,
};

const NAME: &str = "NAV-TOOL-MIB";
const LABEL: &str = "<memory:NAV-TOOL-MIB>";
const SOURCE_TEXT: &str = r#"-- 😀 tooling fixture
NAV-TOOL-MIB DEFINITIONS ::= BEGIN
IMPORTS
    Integer32
        FROM SNMPv2-SMI
    OBJECT-GROUP
        FROM SNMPv2-CONF;

toolRoot OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 99001 }

ToolAlias ::= Integer32

toolObject OBJECT-TYPE
    SYNTAX ToolAlias
    -- toolObject in a comment
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "toolObject in a description"
    ::= { toolRoot 1 }

toolGroup OBJECT-GROUP
    OBJECTS { toolObject }
    STATUS current
    DESCRIPTION "group"
    ::= { toolRoot 2 }

hexValue OCTET STRING ::= 'DEAD'H
binValue OCTET STRING ::= '0101'B
END
"#;
const SOURCE: &[u8] = SOURCE_TEXT.as_bytes();

fn candidate(bytes: impl Into<Arc<[u8]>>) -> SourceCandidate {
    SourceCandidate::new(NAME, SourceOrigin::memory(NAME), LABEL, bytes)
}

fn offset(source: &[u8], needle: &[u8], occurrence: usize) -> ByteOffset {
    let start = source
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .nth(occurrence)
        .map(|(index, _)| index)
        .unwrap_or_else(|| panic!("missing occurrence {occurrence} of {needle:?}"));
    ByteOffset::try_from(start).unwrap()
}

fn resolved_fixture() -> mib_rs::Mib {
    Loader::new()
        .source(memory(NAME, SOURCE))
        .modules([NAME])
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("tooling fixture should load")
}

#[test]
fn public_facade_combines_exact_definition_import_oid_type_and_symbol_spans() {
    let (tree, _) = parse(candidate(Arc::<[u8]>::from(SOURCE))).unwrap();
    let mib = resolved_fixture();
    let module = mib.module(NAME).unwrap();
    let navigator = SymbolNavigator::new(&tree, Some(module)).unwrap();

    // The two compilations deliberately own independent arenas and allocations.
    assert_eq!(tree.document().id(), module.source_id().unwrap());
    assert!(!std::ptr::eq(tree.document(), module.source().unwrap()));
    assert_ne!(
        tree.document().bytes().as_ptr(),
        module.source().unwrap().bytes().as_ptr()
    );

    let cases = [
        (b"toolObject".as_slice(), 0, SemanticSpanKind::Definition),
        (b"Integer32".as_slice(), 0, SemanticSpanKind::Import),
        (b"toolRoot".as_slice(), 1, SemanticSpanKind::OidReference),
        (b"ToolAlias".as_slice(), 1, SemanticSpanKind::TypeReference),
        (
            b"toolObject".as_slice(),
            3,
            SemanticSpanKind::SymbolReference,
        ),
    ];

    for (needle, occurrence, expected_kind) in cases {
        let result: SymbolAtPosition<'_, '_> = navigator
            .symbol_at(offset(SOURCE, needle, occurrence))
            .unwrap();
        let semantic = result.semantic.expect("expected semantic span");
        assert_eq!(semantic.kind, expected_kind);
        assert_eq!(semantic.declared_name.as_bytes(), needle);
        let semantic_range: LocatedRange<'_> = result.semantic_range().unwrap();
        assert!(std::ptr::eq(
            semantic_range.document(),
            module.source().unwrap()
        ));
        assert_eq!(
            semantic_range.text().unwrap(),
            module.source().unwrap().slice(semantic.range).unwrap()
        );
        let primary = result.primary_range();
        assert!(std::ptr::eq(primary.document(), module.source().unwrap()));
        assert_eq!(primary.text().unwrap(), needle);
    }

    assert!(std::ptr::eq(navigator.tree(), &tree));
    assert_eq!(navigator.module(), Some(module));
}

#[test]
fn comments_and_every_string_literal_body_keep_syntax_but_suppress_semantics() {
    let (tree, _) = parse(candidate(Arc::<[u8]>::from(SOURCE))).unwrap();
    let mib = resolved_fixture();
    let module = mib.module(NAME).unwrap();
    let navigator = SymbolNavigator::new(&tree, Some(module)).unwrap();

    let comment = navigator
        .symbol_at(offset(SOURCE, b"toolObject in a comment", 0))
        .unwrap();
    assert!(comment.syntax.in_comment());
    assert_eq!(comment.semantic, None);
    assert_eq!(
        comment.primary_range().text().unwrap(),
        b"-- toolObject in a comment"
    );

    let quoted = navigator
        .symbol_at(offset(SOURCE, b"toolObject in a description", 0))
        .unwrap();
    assert!(quoted.syntax.in_string());
    assert_eq!(quoted.semantic, None);
    assert_eq!(
        quoted.primary_range().text().unwrap(),
        b"\"toolObject in a description\""
    );

    for literal in [b"'DEAD'H".as_slice(), b"'0101'B".as_slice()] {
        let result = navigator.symbol_at(offset(SOURCE, literal, 0)).unwrap();
        assert!(result.syntax.in_string());
        assert_eq!(result.semantic, None);
        assert_eq!(result.primary_range().text().unwrap(), literal);
    }

    let whitespace = navigator
        .symbol_at(offset(SOURCE, b"    MAX-ACCESS", 0))
        .unwrap();
    assert!(whitespace.syntax.token().kind().is_trivia());
    assert_eq!(
        whitespace.semantic.unwrap().kind,
        SemanticSpanKind::Definition
    );
    assert_eq!(
        whitespace.primary_range().document().label(),
        module.source().unwrap().label()
    );
    assert_eq!(whitespace.primary_range().text().unwrap(), b"toolObject");

    let keyword = navigator
        .symbol_at(offset(SOURCE, b"MAX-ACCESS", 0))
        .unwrap();
    assert_eq!(keyword.semantic.unwrap().kind, SemanticSpanKind::Definition);
    assert_eq!(keyword.primary_range().text().unwrap(), b"toolObject");
    assert!(keyword.syntax.definition().is_some());

    let between = ByteOffset::new(offset(SOURCE, b"\n\nToolAlias", 0).get() + 1);
    let between = navigator.symbol_at(between).unwrap();
    assert!(between.syntax.token().kind().is_trivia());
    assert_eq!(between.semantic, None);
    assert_eq!(between.primary_range().document().label(), LABEL);
}

#[test]
fn exact_boundaries_eof_offsets_and_editor_positions_are_defined() {
    let (tree, _) = parse(candidate(Arc::<[u8]>::from(SOURCE))).unwrap();
    let mib = resolved_fixture();
    let module = mib.module(NAME).unwrap();
    let navigator = SymbolNavigator::new(&tree, Some(module)).unwrap();

    let start = offset(SOURCE, b"ToolAlias", 1);
    let span = navigator.symbol_at(start).unwrap().semantic.unwrap();
    assert_eq!(span.kind, SemanticSpanKind::TypeReference);
    assert!(
        navigator
            .symbol_at(ByteOffset::new(span.range.end().get() - 1))
            .unwrap()
            .semantic
            .is_some()
    );
    assert_eq!(
        navigator
            .symbol_at(span.range.end())
            .unwrap()
            .semantic
            .unwrap()
            .kind,
        SemanticSpanKind::Definition,
        "the narrower type span is half-open while the containing definition remains"
    );

    for encoding in [
        PositionEncoding::Utf8,
        PositionEncoding::Utf16,
        PositionEncoding::Utf32,
    ] {
        let position = tree.document().position(start, encoding).unwrap();
        assert_eq!(
            navigator
                .symbol_at_position(position, encoding)
                .unwrap()
                .unwrap()
                .semantic
                .unwrap()
                .declared_name,
            "ToolAlias"
        );
    }

    assert!(
        navigator
            .symbol_at_position(Position::new(0, 4), PositionEncoding::Utf8)
            .is_err()
    );
    assert!(
        navigator
            .symbol_at_position(Position::new(u32::MAX, 0), PositionEncoding::Utf16)
            .is_err()
    );

    let eof = navigator.symbol_at(tree.document().len()).unwrap();
    assert_eq!(eof.semantic, None);
    assert!(eof.primary_range().text().unwrap().is_empty());
    assert!(
        navigator
            .symbol_at(ByteOffset::new(tree.document().len().get() + 1))
            .is_none()
    );
}

#[test]
fn pairing_uses_full_provenance_instead_of_compilation_local_source_ids() {
    let mib = resolved_fixture();
    let module = mib.module(NAME).unwrap();

    let different_bytes: Vec<u8> = SOURCE
        .iter()
        .map(|byte| if *byte == b't' { b'x' } else { *byte })
        .collect();
    let (stale, _) = parse(candidate(Arc::<[u8]>::from(different_bytes))).unwrap();
    assert_eq!(stale.document().id(), module.source_id().unwrap());
    assert_eq!(
        SymbolNavigator::new(&stale, Some(module)).unwrap_err(),
        SourcePairError::MismatchedDocuments
    );

    let different_label = SourceCandidate::new(
        NAME,
        SourceOrigin::memory(NAME),
        "editor:renamed",
        Arc::<[u8]>::from(SOURCE),
    );
    let (renamed, _) = parse(different_label).unwrap();
    assert_eq!(renamed.document().id(), module.source_id().unwrap());
    let renamed_navigator = SymbolNavigator::new(&renamed, Some(module)).unwrap();
    let renamed_result = renamed_navigator
        .symbol_at(offset(SOURCE, b"ToolAlias", 1))
        .unwrap();
    assert_eq!(
        renamed_result.syntax_range().document().label(),
        "editor:renamed"
    );
    assert_eq!(
        renamed_result.semantic_range().unwrap().document().label(),
        LABEL
    );
    assert_eq!(
        renamed_result.primary_range().document().label(),
        LABEL,
        "resolved primary ranges retain the semantic source owner"
    );

    let different_origin = SourceCandidate::new(
        NAME,
        SourceOrigin::memory("different-buffer"),
        LABEL,
        Arc::<[u8]>::from(SOURCE),
    );
    let (foreign, _) = parse(different_origin).unwrap();
    assert_eq!(foreign.document().id(), module.source_id().unwrap());
    assert_eq!(
        SymbolNavigator::new(&foreign, Some(module)).unwrap_err(),
        SourcePairError::MismatchedDocuments
    );
}

#[test]
fn malformed_source_remains_queryable_without_a_resolved_module() {
    let source = b"BROKEN-MIB DEFINITIONS ::= BEGIN\nthing OBJECT-TYPE\n    SYNTAX MissingType\n    @\nlater OBJECT IDENTIFIER ::= { 1 3 }\n";
    let broken = SourceCandidate::new(
        "broken",
        SourceOrigin::memory("broken"),
        "broken-buffer",
        Arc::<[u8]>::from(source.as_slice()),
    );
    let (tree, diagnostics) = parse(broken).unwrap();
    assert!(!diagnostics.is_empty());
    let navigator = SymbolNavigator::new(&tree, None).unwrap();

    let missing = navigator
        .symbol_at(offset(source, b"MissingType", 0))
        .unwrap();
    assert_eq!(missing.semantic, None);
    assert!(missing.syntax.definition().is_some());
    assert_eq!(missing.syntax.token().text(), b"MissingType");

    let recovery = navigator.symbol_at(offset(source, b"@", 0)).unwrap();
    assert_eq!(recovery.semantic, None);
    assert!(recovery.syntax.error().is_some() || recovery.syntax.unparsed_region().is_some());

    let later = navigator.symbol_at(offset(source, b"later", 0)).unwrap();
    assert_eq!(later.semantic, None);
    assert!(later.syntax.definition().is_some());
}
