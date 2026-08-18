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

/// An immutable lossless syntax tree for one source document.
///
/// The initial tree shape consists of a [`SyntaxKind::SourceFile`] root whose
/// children retain every lossless lexer token in source order. Lexer recovery
/// tokens are wrapped in [`SyntaxKind::Error`] nodes so later parsing stages
/// can extend the same tree without changing recovery representation.
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
    let (tokens, diagnostics) = crate::token::tokenize_lossless_with_config(document, diag_config);
    let root = build_root(document, tokens)
        .expect("lossless lexer must produce an ordered, source-complete token stream");
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
struct NodeData {
    kind: SyntaxKind,
    range: SourceRange,
    children: Box<[ElementData]>,
}

#[derive(Debug)]
#[allow(dead_code, reason = "constructed by the next CST parsing stage")]
enum ElementData {
    Node(NodeData),
    Token(TokenData),
}

#[derive(Debug)]
struct TokenData {
    kind: SyntaxKind,
    range: SourceRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code, reason = "reported by the staged CST builder")]
enum BuildError {
    WrongSource,
    NonTokenKind,
    EmptyToken,
    GapOrOverlap,
    MissingEof,
    EarlyEof,
}

#[allow(dead_code, reason = "used by the next CST parsing stage")]
fn build_root(document: &SourceDocument, tokens: Vec<Token>) -> Result<NodeData, BuildError> {
    let mut children = Vec::with_capacity(tokens.len());
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

        let token = TokenData {
            kind: token.kind,
            range: token.span,
        };
        if token.kind == SyntaxKind::ErrorToken {
            children.push(ElementData::Node(NodeData {
                kind: SyntaxKind::Error,
                range: token.range,
                children: Box::new([ElementData::Token(token)]),
            }));
        } else {
            children.push(ElementData::Token(token));
        }
    }

    if !matches!(children.last(), Some(ElementData::Token(token)) if token.kind == SyntaxKind::EofToken)
    {
        return Err(BuildError::MissingEof);
    }

    let range = document
        .range(0..document.bytes().len())
        .expect("the full document is always a valid source range");
    Ok(NodeData {
        kind: SyntaxKind::SourceFile,
        range,
        children: children.into_boxed_slice(),
    })
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
            assert!(diagnostics.is_empty());
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
            assert_eq!(error.text(), b"@ invalid");
            assert_eq!(
                error
                    .descendant_tokens()
                    .map(SyntaxToken::kind)
                    .collect::<Vec<_>>(),
                [SyntaxKind::ErrorToken]
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
                [
                    (SyntaxKind::LowercaseIdent, 0..3),
                    (SyntaxKind::Whitespace, 3..4),
                    (SyntaxKind::Error, 4..9),
                    (SyntaxKind::Whitespace, 9..10),
                    (SyntaxKind::LowercaseIdent, 10..13),
                    (SyntaxKind::EofToken, 13..13),
                ]
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
    fn reconstruction_preserves_arbitrary_source_bytes() {
        let input = b"A DEFINITIONS ::= BEGIN\r\n-- comment --\r\n\xff\xfe\nEND";
        with_document(input, |document| {
            let (tree, _) = build(document);
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
            build_root(second_document, tokens).unwrap_err(),
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
                build_root(document, gap).unwrap_err(),
                BuildError::GapOrOverlap
            );

            let missing_eof = vec![Token {
                kind: SyntaxKind::LowercaseIdent,
                span: document.range(0..3).unwrap(),
            }];
            assert_eq!(
                build_root(document, missing_eof).unwrap_err(),
                BuildError::MissingEof
            );
        });
    }
}
