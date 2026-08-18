//! Immutable lossless concrete syntax trees.
//!
//! A [`SyntaxTree`] borrows the exact [`SourceDocument`] from which it was
//! built. Node and token handles retain that document internally, so source
//! text is never resolved through a caller-supplied source arena.

use std::iter::FusedIterator;

use crate::source::{SourceDocument, SourceRange};
use crate::syntax::SyntaxKind;
use crate::token::Token;
use crate::types::{Diagnostic, DiagnosticConfig};

mod parser;
mod typed;

pub use typed::{
    CstNode, ErrorRegion, ImportGroup, Imports, Module, ModuleHeader, SourceFile, UnparsedRegion,
};

/// An immutable lossless syntax tree for one source document.
///
/// The root is a [`SyntaxKind::SourceFile`] containing typed module structure,
/// recovery regions, and every lossless lexer token in source order.
#[derive(Debug)]
pub struct SyntaxTree<'src> {
    document: &'src SourceDocument,
    root: NodeData,
}

impl<'src> SyntaxTree<'src> {
    /// Return the exact source document retained by this tree.
    pub fn document(&self) -> &'src SourceDocument {
        self.document
    }

    /// Return the source-file root node.
    pub fn root(&self) -> SyntaxNode<'_, 'src> {
        SyntaxNode::new(&self.root, self.document)
    }

    /// Return the typed source-file root.
    pub fn source_file(&self) -> SourceFile<'_, 'src> {
        SourceFile::cast(self.root()).expect("a syntax tree root is always a source file")
    }

    /// Iterate over all nodes in depth-first pre-order, including the root.
    pub fn nodes(&self) -> DescendantNodes<'_, 'src> {
        self.root().descendant_nodes()
    }

    /// Iterate over all tokens in source order, including EOF.
    pub fn tokens(&self) -> DescendantTokens<'_, 'src> {
        self.root().descendant_tokens()
    }

    /// Reconstruct the original source bytes from the tree's tokens.
    pub fn reconstruct_text(&self) -> Vec<u8> {
        let mut text = Vec::with_capacity(self.document.bytes().len());
        for token in self.tokens() {
            text.extend_from_slice(token.text());
        }
        text
    }
}

#[allow(dead_code, reason = "used by the next CST parsing stage")]
pub(crate) fn build_lossless_tree<'src>(
    document: &'src SourceDocument,
    diag_config: &DiagnosticConfig,
) -> (SyntaxTree<'src>, Vec<Diagnostic>) {
    let (tokens, mut diagnostics) =
        crate::token::tokenize_lossless_with_config(document, diag_config);
    let tokens = validate_tokens(document, tokens)
        .expect("lossless lexer must produce an ordered, source-complete token stream");
    let (root, parse_diagnostics) = parser::parse(document, &tokens, diag_config);
    diagnostics.extend(parse_diagnostics);
    (SyntaxTree { document, root }, diagnostics)
}

/// A borrowed immutable syntax node.
#[derive(Clone, Copy, Debug)]
pub struct SyntaxNode<'tree, 'src> {
    data: &'tree NodeData,
    document: &'src SourceDocument,
}

impl<'tree, 'src> SyntaxNode<'tree, 'src> {
    fn new(data: &'tree NodeData, document: &'src SourceDocument) -> Self {
        Self { data, document }
    }

    /// Return this node's syntax kind.
    pub fn kind(self) -> SyntaxKind {
        self.data.kind
    }

    /// Return the checked source range covered by this node.
    pub fn range(self) -> SourceRange {
        self.data.range
    }

    /// Return the exact source bytes covered by this node.
    pub fn text(self) -> &'src [u8] {
        self.document
            .slice(self.data.range)
            .expect("CST node ranges belong to the retained source document")
    }

    /// Iterate over this node's immediate children in source order.
    pub fn children(self) -> Children<'tree, 'src> {
        Children {
            inner: self.data.children.iter(),
            document: self.document,
        }
    }

    /// Iterate over this node and all descendant nodes in depth-first pre-order.
    pub fn descendant_nodes(self) -> DescendantNodes<'tree, 'src> {
        DescendantNodes { stack: vec![self] }
    }

    /// Iterate over all descendant tokens in source order.
    pub fn descendant_tokens(self) -> DescendantTokens<'tree, 'src> {
        DescendantTokens {
            stack: vec![self.data.children.iter()],
            document: self.document,
        }
    }

    /// Cast this untyped node to a typed CST wrapper.
    pub fn cast<N>(self) -> Option<N>
    where
        N: CstNode<'tree, 'src>,
    {
        N::cast(self)
    }
}

/// A borrowed immutable syntax token.
#[derive(Clone, Copy, Debug)]
pub struct SyntaxToken<'tree, 'src> {
    data: &'tree TokenData,
    document: &'src SourceDocument,
}

impl<'tree, 'src> SyntaxToken<'tree, 'src> {
    /// Return this token's syntax kind.
    pub fn kind(self) -> SyntaxKind {
        self.data.kind
    }

    /// Return the checked source range covered by this token.
    pub fn range(self) -> SourceRange {
        self.data.range
    }

    /// Return this token's exact source bytes.
    pub fn text(self) -> &'src [u8] {
        self.document
            .slice(self.data.range)
            .expect("CST token ranges belong to the retained source document")
    }
}

/// An immediate syntax-tree child.
#[derive(Clone, Copy, Debug)]
pub enum SyntaxElement<'tree, 'src> {
    /// A child node.
    Node(SyntaxNode<'tree, 'src>),
    /// A child token.
    Token(SyntaxToken<'tree, 'src>),
}

impl<'tree, 'src> SyntaxElement<'tree, 'src> {
    /// Return this element's syntax kind.
    pub fn kind(self) -> SyntaxKind {
        match self {
            Self::Node(node) => node.kind(),
            Self::Token(token) => token.kind(),
        }
    }

    /// Return this element's checked source range.
    pub fn range(self) -> SourceRange {
        match self {
            Self::Node(node) => node.range(),
            Self::Token(token) => token.range(),
        }
    }

    /// Return the exact source bytes covered by this element.
    pub fn text(self) -> &'src [u8] {
        match self {
            Self::Node(node) => node.text(),
            Self::Token(token) => token.text(),
        }
    }

    /// Return this element as a node, if it is one.
    pub fn as_node(self) -> Option<SyntaxNode<'tree, 'src>> {
        match self {
            Self::Node(node) => Some(node),
            Self::Token(_) => None,
        }
    }

    /// Return this element as a token, if it is one.
    pub fn as_token(self) -> Option<SyntaxToken<'tree, 'src>> {
        match self {
            Self::Node(_) => None,
            Self::Token(token) => Some(token),
        }
    }
}

/// Iterator over a node's immediate children.
#[derive(Clone, Debug)]
pub struct Children<'tree, 'src> {
    inner: std::slice::Iter<'tree, ElementData>,
    document: &'src SourceDocument,
}

impl<'tree, 'src> Iterator for Children<'tree, 'src> {
    type Item = SyntaxElement<'tree, 'src>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|element| match element {
            ElementData::Node(node) => SyntaxElement::Node(SyntaxNode::new(node, self.document)),
            ElementData::Token(token) => SyntaxElement::Token(SyntaxToken {
                data: token,
                document: self.document,
            }),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Children<'_, '_> {}
impl FusedIterator for Children<'_, '_> {}

/// Iterator over nodes in depth-first pre-order.
#[derive(Clone, Debug)]
pub struct DescendantNodes<'tree, 'src> {
    stack: Vec<SyntaxNode<'tree, 'src>>,
}

impl<'tree, 'src> Iterator for DescendantNodes<'tree, 'src> {
    type Item = SyntaxNode<'tree, 'src>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        // Reverse once when pushing so the LIFO stack yields source order.
        self.stack.extend(
            node.data
                .children
                .iter()
                .rev()
                .filter_map(|child| match child {
                    ElementData::Node(child) => Some(SyntaxNode::new(child, node.document)),
                    ElementData::Token(_) => None,
                }),
        );
        Some(node)
    }
}

impl FusedIterator for DescendantNodes<'_, '_> {}

/// Iterator over tokens in depth-first source order.
#[derive(Clone, Debug)]
pub struct DescendantTokens<'tree, 'src> {
    stack: Vec<std::slice::Iter<'tree, ElementData>>,
    document: &'src SourceDocument,
}

impl<'tree, 'src> Iterator for DescendantTokens<'tree, 'src> {
    type Item = SyntaxToken<'tree, 'src>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let children = self.stack.last_mut()?;
            match children.next() {
                Some(ElementData::Node(node)) => self.stack.push(node.children.iter()),
                Some(ElementData::Token(token)) => {
                    return Some(SyntaxToken {
                        data: token,
                        document: self.document,
                    });
                }
                None => {
                    self.stack.pop();
                }
            }
        }
    }
}

impl FusedIterator for DescendantTokens<'_, '_> {}

#[derive(Debug)]
pub(super) struct NodeData {
    kind: SyntaxKind,
    range: SourceRange,
    children: Box<[ElementData]>,
}

#[derive(Debug)]
pub(super) enum ElementData {
    Node(NodeData),
    Token(TokenData),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TokenData {
    kind: SyntaxKind,
    range: SourceRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildError {
    WrongSource,
    NonTokenKind,
    EmptyToken,
    GapOrOverlap,
    MissingEof,
    EarlyEof,
}

fn validate_tokens(
    document: &SourceDocument,
    tokens: Vec<Token>,
) -> Result<Box<[TokenData]>, BuildError> {
    let mut validated = Vec::with_capacity(tokens.len());
    let mut cursor = 0usize;
    let token_count = tokens.len();

    for (index, token) in tokens.into_iter().enumerate() {
        if document.slice(token.span).is_err() {
            return Err(BuildError::WrongSource);
        }
        if !token.kind.is_token() {
            return Err(BuildError::NonTokenKind);
        }

        let range = token.span.byte_range();
        if range.start != cursor {
            return Err(BuildError::GapOrOverlap);
        }

        if token.kind == SyntaxKind::EofToken {
            if index + 1 != token_count {
                return Err(BuildError::EarlyEof);
            }
            if range.start != range.end || range.end != document.bytes().len() {
                return Err(BuildError::MissingEof);
            }
        } else {
            if range.start == range.end {
                return Err(BuildError::EmptyToken);
            }
            cursor = range.end;
        }

        validated.push(TokenData {
            kind: token.kind,
            range: token.span,
        });
    }

    if !matches!(validated.last(), Some(token) if token.kind == SyntaxKind::EofToken) {
        return Err(BuildError::MissingEof);
    }
    Ok(validated.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::source::{SourceOrigin, SourceSet};

    fn with_document<T>(input: &[u8], f: impl FnOnce(&SourceDocument) -> T) -> T {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                SourceOrigin::memory("cst-test"),
                "cst-test",
                Arc::from(input),
            )
            .unwrap();
        f(sources.get(id).unwrap())
    }

    fn build(document: &SourceDocument) -> (SyntaxTree<'_>, Vec<Diagnostic>) {
        build_lossless_tree(document, &DiagnosticConfig::default())
    }

    #[test]
    fn empty_input_has_root_and_eof() {
        with_document(b"", |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            assert_eq!(tree.root().kind(), SyntaxKind::SourceFile);
            assert_eq!(tree.root().range().byte_range(), 0..0);
            assert_eq!(
                tree.tokens().map(SyntaxToken::kind).collect::<Vec<_>>(),
                [SyntaxKind::EofToken]
            );
            assert_eq!(tree.reconstruct_text(), b"");
        });
    }

    #[test]
    fn minimal_module_retains_every_token() {
        let input = b"MINIMAL-MIB DEFINITIONS ::= BEGIN\nEND\n";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty());
            assert_eq!(tree.root().text(), input);
            assert_eq!(
                tree.nodes().map(SyntaxNode::kind).collect::<Vec<_>>(),
                [
                    SyntaxKind::SourceFile,
                    SyntaxKind::Module,
                    SyntaxKind::ModuleHeader
                ]
            );
            assert_eq!(
                tree.tokens().map(SyntaxToken::kind).collect::<Vec<_>>(),
                [
                    SyntaxKind::UppercaseIdent,
                    SyntaxKind::Whitespace,
                    SyntaxKind::KwDefinitions,
                    SyntaxKind::Whitespace,
                    SyntaxKind::ColonColonEqual,
                    SyntaxKind::Whitespace,
                    SyntaxKind::KwBegin,
                    SyntaxKind::Whitespace,
                    SyntaxKind::KwEnd,
                    SyntaxKind::Whitespace,
                    SyntaxKind::EofToken,
                ]
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn invalid_input_is_retained_in_an_error_node() {
        let input = b"@ invalid\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            assert_eq!(
                tree.nodes().map(SyntaxNode::kind).collect::<Vec<_>>(),
                [SyntaxKind::SourceFile, SyntaxKind::Error]
            );

            let error = tree
                .root()
                .children()
                .find_map(SyntaxElement::as_node)
                .unwrap();
            assert_eq!(error.text(), input);
            assert_eq!(
                error
                    .descendant_tokens()
                    .map(SyntaxToken::kind)
                    .collect::<Vec<_>>(),
                [
                    SyntaxKind::ErrorToken,
                    SyntaxKind::Whitespace,
                    SyntaxKind::KwEnd,
                ]
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn traversal_is_depth_first_and_in_source_order() {
        let input = b"one @ bad\ntwo";
        with_document(input, |document| {
            let (tree, _) = build(document);
            let elements = tree
                .root()
                .children()
                .map(|element| (element.kind(), element.range().byte_range()))
                .collect::<Vec<_>>();
            assert_eq!(
                elements,
                [(SyntaxKind::Error, 0..13), (SyntaxKind::EofToken, 13..13),]
            );
            assert_eq!(
                tree.tokens()
                    .map(|token| (token.kind(), token.range().byte_range()))
                    .collect::<Vec<_>>(),
                [
                    (SyntaxKind::LowercaseIdent, 0..3),
                    (SyntaxKind::Whitespace, 3..4),
                    (SyntaxKind::ErrorToken, 4..9),
                    (SyntaxKind::Whitespace, 9..10),
                    (SyntaxKind::LowercaseIdent, 10..13),
                    (SyntaxKind::EofToken, 13..13),
                ]
            );
        });
    }

    #[test]
    fn nested_node_traversal_is_depth_first_in_source_order() {
        let input = b"ORDER-MIB DEFINITIONS ::= BEGIN\nIMPORTS item FROM ITEM-MIB;\nvalue INTEGER ::= 1\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let expected = [
                SyntaxKind::SourceFile,
                SyntaxKind::Module,
                SyntaxKind::ModuleHeader,
                SyntaxKind::Imports,
                SyntaxKind::ImportGroup,
                SyntaxKind::UnparsedRegion,
            ];
            assert_eq!(
                tree.nodes().map(SyntaxNode::kind).collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                tree.root()
                    .descendant_nodes()
                    .map(SyntaxNode::kind)
                    .collect::<Vec<_>>(),
                expected
            );

            let module = tree.source_file().modules().next().unwrap();
            assert!(module.header().is_some());
            assert_eq!(module.imports().unwrap().groups().count(), 1);
            assert_eq!(module.unparsed_regions().count(), 1);
            assert_eq!(
                module
                    .syntax()
                    .descendant_nodes()
                    .map(SyntaxNode::kind)
                    .collect::<Vec<_>>(),
                &expected[1..]
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn reconstruction_preserves_arbitrary_source_bytes() {
        let input = b"A DEFINITIONS ::= BEGIN\r\n-- comment --\r\n\xff\xfe\nEND";
        with_document(input, |document| {
            let (tree, _) = build(document);
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn typed_minimal_module_exposes_header_tokens() {
        let input = b"MINIMAL-MIB DEFINITIONS ::= BEGIN\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty());

            let modules = tree.source_file().modules().collect::<Vec<_>>();
            assert_eq!(modules.len(), 1);
            let module = modules[0];
            let header = module.header().unwrap();
            assert_eq!(header.name().unwrap().text(), b"MINIMAL-MIB");
            assert_eq!(header.definitions().unwrap().text(), b"DEFINITIONS");
            assert_eq!(header.assignment().unwrap().text(), b"::=");
            assert_eq!(header.begin().unwrap().text(), b"BEGIN");
            assert!(module.imports().is_none());
            assert_eq!(module.end().unwrap().text(), b"END");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn multiple_modules_and_inter_module_tokens_remain_in_source_order() {
        let input = b"-- lead --\nFIRST-MIB DEFINITIONS ::= BEGIN\nEND\ninter-module junk\nSECOND-MIB DEFINITIONS ::= BEGIN\nEND\n";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.message == "tokens outside a recognized module"
                })
            );
            let file = tree.source_file();
            let names = file
                .modules()
                .map(|module| module.header().unwrap().name().unwrap().text())
                .collect::<Vec<_>>();
            assert_eq!(names, [b"FIRST-MIB".as_slice(), b"SECOND-MIB".as_slice()]);
            assert_eq!(file.recovery_regions().count(), 1);
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn malformed_header_is_partial_and_lossless() {
        let input = b"BROKEN-MIB DEFINITIONS , BEGIN\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let module = tree.source_file().modules().next().unwrap();
            let header = module.header().unwrap();
            assert_eq!(header.name().unwrap().text(), b"BROKEN-MIB");
            assert!(header.definitions().is_some());
            assert!(header.assignment().is_none());
            assert!(header.begin().is_some());
            assert_eq!(header.recovery_regions().count(), 1);
            assert!(module.end().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn malformed_imports_recover_to_later_groups_and_body() {
        let input = b"IMPORT-TEST-MIB DEFINITIONS ::= BEGIN\nIMPORTS\n first, FROM FIRST-MIB\n second FROM lowercase;\nvalue OBJECT IDENTIFIER ::= { 1 }\nEND\n";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let module = tree.source_file().modules().next().unwrap();
            let imports = module.imports().unwrap();
            let groups = imports.groups().collect::<Vec<_>>();
            assert_eq!(groups.len(), 2);
            assert_eq!(groups[0].symbols().next().unwrap().text(), b"first");
            assert_eq!(groups[0].module_name().unwrap().text(), b"FIRST-MIB");
            assert_eq!(groups[1].symbols().next().unwrap().text(), b"second");
            assert!(groups[1].module_name().is_none());
            assert_eq!(groups[1].recovery_regions().count(), 1);
            assert!(imports.semicolon().is_some());
            assert_eq!(module.unparsed_regions().count(), 1);
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn imports_without_semicolon_stop_at_an_unparsed_definition() {
        for definition in [
            b"value OBJECT IDENTIFIER ::= { 1 }".as_slice(),
            b"value INTEGER ::= 1".as_slice(),
            b"value TypeName ::= other".as_slice(),
            b"value OCTET STRING ::= \"x\"".as_slice(),
            b"value [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (0..8)) ::= \"x\"".as_slice(),
            b"value INTEGER { zero(0), one(1) } ::= 0".as_slice(),
            b"value SEQUENCE OF TypeName ::= other".as_slice(),
            b"object OBJECT-TYPE SYNTAX INTEGER ::= { 1 }".as_slice(),
            b"TypeName ::= TEXTUAL-CONVENTION SYNTAX INTEGER".as_slice(),
        ] {
            let mut input =
                b"IMPORT-TEST-MIB DEFINITIONS ::= BEGIN\nIMPORTS first FROM FIRST-MIB\n".to_vec();
            input.extend_from_slice(definition);
            input.extend_from_slice(b"\nEND");
            with_document(&input, |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty());
                let module = tree.source_file().modules().next().unwrap();
                let imports = module.imports().unwrap();
                assert_eq!(imports.groups().count(), 1);
                assert!(imports.semicolon().is_none());
                let body = module.unparsed_regions().next().unwrap();
                assert!(
                    body.syntax().text().starts_with(definition),
                    "definition={:?}, body={:?}",
                    String::from_utf8_lossy(definition),
                    String::from_utf8_lossy(body.syntax().text())
                );
                assert_eq!(tree.reconstruct_text(), input);
            });
        }
    }

    #[test]
    fn assignment_lookahead_does_not_cut_off_valid_import_groups() {
        for imports_text in [
            b"value, OCTET, STRING FROM TYPES-MIB;".as_slice(),
            b"value TypeName FROM TYPES-MIB;".as_slice(),
            b"OBJECT-TYPE, MODULE-IDENTITY FROM SNMPv2-SMI;".as_slice(),
        ] {
            let mut input = b"IMPORT-TEST-MIB DEFINITIONS ::= BEGIN\nIMPORTS ".to_vec();
            input.extend_from_slice(imports_text);
            input.extend_from_slice(b"\nEND");
            with_document(&input, |document| {
                let (tree, _) = build(document);
                let module = tree.source_file().modules().next().unwrap();
                let imports = module.imports().unwrap();
                assert!(imports.semicolon().is_some());
                assert_eq!(imports.groups().count(), 1);
                assert_eq!(module.unparsed_regions().count(), 0);
                assert_eq!(tree.reconstruct_text(), input);
            });
        }
    }

    #[test]
    fn exports_before_imports_retains_both_regions() {
        let input = b"EXPORT-TEST-MIB DEFINITIONS ::= BEGIN\nEXPORTS first, second;\nIMPORTS third FROM THIRD-MIB;\nvalue INTEGER ::= 1\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let module = tree.source_file().modules().next().unwrap();
            let imports = module.imports().unwrap();
            assert_eq!(imports.groups().count(), 1);
            assert_eq!(imports.groups().next().unwrap().symbols().count(), 1);
            let regions = module.unparsed_regions().collect::<Vec<_>>();
            assert_eq!(regions.len(), 2);
            assert!(regions[0].syntax().text().starts_with(b"\nEXPORTS"));
            assert!(
                regions[1]
                    .syntax()
                    .text()
                    .windows(5)
                    .any(|text| text == b"value")
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn legacy_macro_end_does_not_close_the_module() {
        let input = b"MACRO-TEST-MIB DEFINITIONS ::= BEGIN\nOBJECT-TYPE MACRO ::= BEGIN\nTYPE NOTATION ::= \"SYNTAX\" type\nVALUE NOTATION ::= value(VALUE ObjectName)\nEND\nafter OBJECT IDENTIFIER ::= { 1 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let module = tree.source_file().modules().next().unwrap();
            let end = module.end().unwrap();
            assert_eq!(end.range().byte_range().start, input.len() - 3);
            let body = module.unparsed_regions().next().unwrap();
            assert!(body.syntax().text().windows(5).any(|text| text == b"after"));
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn embedded_rfc_1212_macro_round_trips_as_one_module() {
        let input = include_bytes!("../lower/embedded/RFC-1212");
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let modules = tree.source_file().modules().collect::<Vec<_>>();
            assert_eq!(modules.len(), 1);
            assert!(modules[0].end().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn obsolete_module_oid_headers_support_complete_and_truncated_forms() {
        let complete = b"OID-MIB { iso org(3) 6 } DEFINITIONS ::= BEGIN\nEND";
        with_document(complete, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty());
            let module = tree.source_file().modules().next().unwrap();
            let header = module.header().unwrap();
            assert!(header.begin().is_some());
            assert_eq!(header.syntax().text(), &complete[..complete.len() - 4]);
            assert_eq!(tree.reconstruct_text(), complete);
        });

        let truncated = b"OID-MIB { iso org(3) 6";
        with_document(truncated, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let module = tree.source_file().modules().next().unwrap();
            let header = module.header().unwrap();
            assert_eq!(header.name().unwrap().text(), b"OID-MIB");
            assert!(header.definitions().is_none());
            assert!(header.begin().is_none());
            assert_eq!(header.syntax().text(), truncated);
            assert_eq!(tree.reconstruct_text(), truncated);
        });
    }

    #[test]
    fn missing_end_recovers_to_complete_and_partial_next_modules() {
        for second_header in [
            b"SECOND-MIB DEFINITIONS ::= BEGIN".as_slice(),
            b"SECOND-MIB ::= BEGIN".as_slice(),
        ] {
            let mut input = b"FIRST-MIB DEFINITIONS ::= BEGIN\nfirst INTEGER ::= 1\n".to_vec();
            input.extend_from_slice(second_header);
            input.extend_from_slice(b"\nEND");
            with_document(&input, |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty());
                let modules = tree.source_file().modules().collect::<Vec<_>>();
                assert_eq!(modules.len(), 2);
                assert!(modules[0].end().is_none());
                assert_eq!(
                    modules[1].header().unwrap().name().unwrap().text(),
                    b"SECOND-MIB"
                );
                assert!(modules[1].end().is_some());
                assert_eq!(tree.reconstruct_text(), input);
            });
        }
    }

    #[test]
    fn header_like_body_tokens_do_not_split_a_closed_module() {
        let input =
            b"ONE-MIB DEFINITIONS ::= BEGIN\nnoise DEFINITIONS ::= BEGIN\nvalue INTEGER ::= 1\nEND";
        with_document(input, |document| {
            let (tree, _) = build(document);
            assert_eq!(tree.source_file().modules().count(), 1);
            assert!(tree.source_file().modules().next().unwrap().end().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn typed_casts_reject_wrong_node_kinds() {
        let input = b"CAST-MIB DEFINITIONS ::= BEGIN END";
        with_document(input, |document| {
            let (tree, _) = build(document);
            let root = tree.root();
            let module = tree.source_file().modules().next().unwrap();
            assert!(Module::cast(root).is_none());
            assert!(SourceFile::cast(module.syntax()).is_none());
            assert!(ModuleHeader::cast(module.syntax()).is_none());
        });
    }

    #[test]
    fn node_ranges_contain_ordered_children() {
        fn check(node: SyntaxNode<'_, '_>) {
            let parent = node.range().byte_range();
            let mut cursor = parent.start;
            for child in node.children() {
                let range = child.range().byte_range();
                assert_eq!(range.start, cursor);
                assert!(range.end <= parent.end);
                cursor = range.end;
                if let Some(child) = child.as_node() {
                    check(child);
                }
            }
            assert_eq!(cursor, parent.end);
        }

        let input = b"junk\nRANGE-MIB DEFINITIONS ::= BEGIN\nEXPORTS foo;\nIMPORTS bar FROM BAR-MIB;\nvalue INTEGER ::= 1\nEND\ntrailing";
        with_document(input, |document| {
            let (tree, _) = build(document);
            check(tree.root());
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn trailing_junk_is_a_typed_recovery_region() {
        let input = b"TRAILING-MIB DEFINITIONS ::= BEGIN\nEND\n\xff junk";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let file = tree.source_file();
            assert_eq!(file.modules().count(), 1);
            let recovery = file.recovery_regions().next().unwrap();
            assert_eq!(recovery.syntax().text(), b"\xff junk");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn builder_rejects_ranges_from_another_document() {
        let mut sources = SourceSet::new();
        let first = sources
            .insert(SourceOrigin::memory("first"), "first", Arc::from(&b"x"[..]))
            .unwrap();
        let second = sources
            .insert(
                SourceOrigin::memory("second"),
                "second",
                Arc::from(&b"x"[..]),
            )
            .unwrap();
        let first_document = sources.get(first).unwrap();
        let second_document = sources.get(second).unwrap();
        let tokens = vec![
            Token {
                kind: SyntaxKind::LowercaseIdent,
                span: first_document.range(0..1).unwrap(),
            },
            Token {
                kind: SyntaxKind::EofToken,
                span: first_document.empty_range(1).unwrap(),
            },
        ];

        assert_eq!(
            validate_tokens(second_document, tokens).unwrap_err(),
            BuildError::WrongSource
        );
    }

    #[test]
    fn builder_enforces_complete_ordered_token_coverage() {
        with_document(b"abc", |document| {
            let gap = vec![
                Token {
                    kind: SyntaxKind::LowercaseIdent,
                    span: document.range(1..3).unwrap(),
                },
                Token {
                    kind: SyntaxKind::EofToken,
                    span: document.empty_range(3).unwrap(),
                },
            ];
            assert_eq!(
                validate_tokens(document, gap).unwrap_err(),
                BuildError::GapOrOverlap
            );

            let missing_eof = vec![Token {
                kind: SyntaxKind::LowercaseIdent,
                span: document.range(0..3).unwrap(),
            }];
            assert_eq!(
                validate_tokens(document, missing_eof).unwrap_err(),
                BuildError::MissingEof
            );
        });
    }
}
