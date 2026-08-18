//! Immutable lossless concrete syntax trees.
//!
//! Use [`parse`] to retain every source byte in a typed concrete syntax tree.
//! The returned [`SyntaxTree`] retains the arena containing its exact
//! [`SourceDocument`], while node and token handles borrow both tree structure
//! and source text from the tree.
//! This makes the tree movable without a self-reference and prevents handles
//! from outliving or cross-resolving their source.
//!
//! This CST API represents written syntax, including whitespace, comments,
//! malformed input, and recovery regions. It does not perform semantic
//! validation or name and OID resolution. Use [`crate::parser`] for the
//! semantic AST parser, [`crate::lower`] for lowering, or [`crate::Loader`] for
//! a resolved MIB.

use std::iter::FusedIterator;
use std::sync::Arc;

use crate::source::{
    ByteOffset, SourceCandidate, SourceDocument, SourceId, SourceRange, SourceRangeError, SourceSet,
};
pub use crate::syntax::SyntaxKind;
use crate::token::Token;
use crate::types::{Diagnostic, DiagnosticConfig, DiagnosticReport};

mod body;
mod navigation;
mod parser;
mod typed;

pub use navigation::{ClauseKind, CursorClause, CursorContext};
pub use typed::{
    AccessClause, AgentCapabilitiesDefinition, AugmentsClause, BitsSyntax, ChoiceSyntax,
    ComplianceGroup, ComplianceModule, ComplianceObject, ComplianceRefinement, ConstrainedSyntax,
    Constraint, ContactInfoClause, CreationRequiresClause, CstNode, Definition, DefvalClause,
    DefvalContent, DescriptionClause, DisplayHintClause, EnterpriseClause, ErrorRegion,
    ImportGroup, Imports, IncludesClause, IndexClause, IndexItem, IntegerEnumSyntax,
    LastUpdatedClause, MacroDefinition, MandatoryGroupsClause, Module, ModuleComplianceDefinition,
    ModuleHeader, ModuleIdentityDefinition, NamedNumber, NotificationGroupDefinition,
    NotificationTypeDefinition, NotificationsClause, ObjectGroupDefinition, ObjectIdentifierSyntax,
    ObjectIdentityDefinition, ObjectTypeDefinition, ObjectsClause, OctetStringSyntax,
    OidAssignment, OidComponent, OrganizationClause, ProductReleaseClause, Range, ReferenceClause,
    RevisionClause, SequenceField, SequenceOfSyntax, SequenceSyntax, SourceFile, StatusClause,
    SupportsModule, SyntaxClause, TaggedSyntax, TextualConventionDefinition, TrapTypeDefinition,
    TypeAssignment, TypeRefSyntax, UnitsClause, UnparsedRegion, ValueAssignment, VariablesClause,
    VariationClause, WriteSyntaxClause,
};

/// An immutable lossless syntax tree for one source document.
///
/// The root is a [`SyntaxKind::SourceFile`] containing typed module structure,
/// recovery regions, and every lossless lexer token in source order.
#[derive(Debug)]
pub struct SyntaxTree {
    sources: Arc<SourceSet>,
    document: SourceId,
    root: NodeData,
    token_index: Box<[TokenData]>,
}

impl SyntaxTree {
    /// Return the exact source document retained by this tree.
    pub fn document(&self) -> &SourceDocument {
        self.sources
            .get(self.document)
            .expect("a syntax tree retains its source document")
    }

    /// Return the source-file root node.
    pub fn root(&self) -> SyntaxNode<'_, '_> {
        SyntaxNode::new(&self.root, self.document())
    }

    /// Return the typed source-file root.
    pub fn source_file(&self) -> SourceFile<'_, '_> {
        SourceFile::cast(self.root()).expect("a syntax tree root is always a source file")
    }

    /// Iterate over all nodes in depth-first pre-order, including the root.
    pub fn nodes(&self) -> DescendantNodes<'_, '_> {
        self.root().descendant_nodes()
    }

    /// Iterate over all tokens in source order, including EOF.
    pub fn tokens(&self) -> DescendantTokens<'_, '_> {
        self.root().descendant_tokens()
    }

    /// Return the token at a byte offset in this tree's source document.
    ///
    /// Token ranges are interpreted as half-open: an offset in
    /// `[token.start(), token.end())` selects that token. Consequently, an
    /// offset exactly at a token's start selects that token, while an offset
    /// exactly at its end selects the following token. Whitespace and comments
    /// are returned like any other token. The document's exclusive end selects
    /// the zero-length [`SyntaxKind::EofToken`], including for an empty
    /// document; an offset beyond the document returns `None`.
    ///
    /// [`ByteOffset`] has no source identity, so `offset` is always interpreted
    /// in the retained document returned by [`Self::document`]. Offsets are
    /// byte-based and need not fall on a UTF-8 code-point boundary; each byte
    /// within multibyte or invalid source text selects its containing token.
    /// The lookup uses the tree's immutable token index and takes `O(log n)`
    /// time for `n` tokens.
    pub fn token_at(&self, offset: ByteOffset) -> Option<SyntaxToken<'_, '_>> {
        if offset > self.document().len() {
            return None;
        }

        let index = self
            .token_index
            .partition_point(|token| token.range.start() <= offset)
            .checked_sub(1)?;
        self.token_index.get(index).map(|data| SyntaxToken {
            data,
            document: self.document(),
        })
    }

    /// Return the syntactic context at a byte offset.
    ///
    /// The offset follows the same byte-coordinate and validity rules as
    /// [`Self::token_at`]. See [`CursorContext`] for the containment and exact
    /// boundary rules used by this query.
    pub fn cursor_context(&self, offset: ByteOffset) -> Option<CursorContext<'_, '_>> {
        navigation::cursor_context(self, offset)
    }

    /// Reconstruct the original source bytes from the tree's tokens.
    pub fn reconstruct_text(&self) -> Vec<u8> {
        let mut text = Vec::with_capacity(self.document().bytes().len());
        for token in self.tokens() {
            text.extend_from_slice(token.text());
        }
        text
    }
}

/// Parse one owned source candidate into a lossless concrete syntax tree.
///
/// The tree retains the candidate's origin, label, and shared immutable bytes
/// in its [`SourceDocument`]. The returned diagnostics contain lexer and CST
/// parser issues; diagnostics do not prevent a tree from being returned. The
/// returned [`DiagnosticReport`] shares the tree's retained source arena, so
/// use its report-owned entries to inspect source ranges and positions.
///
/// # Errors
///
/// Returns [`SourceRangeError::SourceTooLarge`] when the source cannot be
/// represented by the compiler's byte-coordinate type.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
/// use mib_rs::compile::{Definition, parse};
/// use mib_rs::{SourceCandidate, SourceOrigin};
///
/// let bytes = Arc::<[u8]>::from(
///     b"EXAMPLE-MIB DEFINITIONS ::= BEGIN\nvalue OBJECT IDENTIFIER ::= { 1 3 }\nEND"
///         .as_slice(),
/// );
/// let source = SourceCandidate::new(
///     "example-buffer",
///     SourceOrigin::memory("example-buffer"),
///     "EXAMPLE-MIB",
///     Arc::clone(&bytes),
/// );
/// let (tree, diagnostics) = parse(source)?;
///
/// let module = tree.source_file().modules().next().unwrap();
/// assert_eq!(module.header().unwrap().name().unwrap().text(), b"EXAMPLE-MIB");
/// assert!(matches!(
///     module.definitions().next(),
///     Some(Definition::ValueAssignment(_))
/// ));
/// assert!(diagnostics.is_empty());
/// for entry in diagnostics.iter() {
///     // Locations are resolved only through their source-owning report.
///     assert!(entry.slice().is_ok());
/// }
/// assert_eq!(tree.reconstruct_text(), bytes.as_ref());
/// # Ok::<(), mib_rs::SourceRangeError>(())
/// ```
pub fn parse(source: SourceCandidate) -> Result<(SyntaxTree, DiagnosticReport), SourceRangeError> {
    parse_with_config(source, &DiagnosticConfig::default())
}

/// Parse one owned source candidate with a specific diagnostic configuration.
///
/// This has the same lossless and source-owning behavior as [`parse`]. The
/// configuration controls which diagnostics are collected and their effective
/// severities; it does not make the CST parser reject recoverable input.
///
/// # Errors
///
/// Returns [`SourceRangeError::SourceTooLarge`] when the source cannot be
/// represented by the compiler's byte-coordinate type.
pub fn parse_with_config(
    source: SourceCandidate,
    diag_config: &DiagnosticConfig,
) -> Result<(SyntaxTree, DiagnosticReport), SourceRangeError> {
    let mut sources = SourceSet::new();
    let document = sources.insert(
        source.origin().clone(),
        source.label(),
        Arc::clone(source.shared_bytes()),
    )?;
    let sources = Arc::new(sources);
    let (tree, diagnostics) = build_lossless_tree(Arc::clone(&sources), document, diag_config);
    let report = DiagnosticReport::new(diagnostics, sources);
    Ok((tree, report))
}

fn build_lossless_tree(
    sources: Arc<SourceSet>,
    document_id: SourceId,
    diag_config: &DiagnosticConfig,
) -> (SyntaxTree, Vec<Diagnostic>) {
    let document = sources
        .get(document_id)
        .expect("the CST source was retained before parsing");
    let (tokens, mut diagnostics) =
        crate::token::tokenize_lossless_with_config(document, diag_config);
    let tokens = validate_tokens(document, tokens)
        .expect("lossless lexer must produce an ordered, source-complete token stream");
    let (root, parse_diagnostics) = parser::parse(document, &tokens, diag_config);
    diagnostics.extend(parse_diagnostics);
    (
        SyntaxTree {
            sources,
            document: document_id,
            root,
            token_index: tokens,
        },
        diagnostics,
    )
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
    use std::fmt::Write as _;
    use std::sync::Arc;

    use super::*;
    use crate::source::{SourceOrigin, SourceSet};
    use crate::types::{DiagCode, Severity};

    struct TestDocument {
        sources: Arc<SourceSet>,
        id: SourceId,
    }

    impl std::ops::Deref for TestDocument {
        type Target = SourceDocument;

        fn deref(&self) -> &Self::Target {
            self.sources
                .get(self.id)
                .expect("the test source set retains its document")
        }
    }

    fn with_document<T>(input: &[u8], f: impl FnOnce(&TestDocument) -> T) -> T {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                SourceOrigin::memory("cst-test"),
                "cst-test",
                Arc::from(input),
            )
            .unwrap();
        let document = TestDocument {
            sources: Arc::new(sources),
            id,
        };
        f(&document)
    }

    fn build(document: &TestDocument) -> (SyntaxTree, Vec<Diagnostic>) {
        build_with_config(document, &DiagnosticConfig::default())
    }

    fn build_with_config(
        document: &TestDocument,
        config: &DiagnosticConfig,
    ) -> (SyntaxTree, Vec<Diagnostic>) {
        let result = build_lossless_tree(Arc::clone(&document.sources), document.id, config);
        assert!(std::ptr::eq(result.0.document(), &**document));
        result
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
    fn public_parse_tree_and_report_share_one_source_arena() {
        let candidate = SourceCandidate::new(
            "shared-arena-test",
            SourceOrigin::memory("shared-arena-test"),
            "SHARED-ARENA-MIB",
            Arc::<[u8]>::from(b"SHARED-ARENA-MIB DEFINITIONS ::= BEGIN\n@\nEND".as_slice()),
        );
        let (tree, report) = parse(candidate).unwrap();

        assert!(Arc::ptr_eq(&tree.sources, report.shared_sources()));
        let entry = report
            .iter()
            .find(|entry| entry.slice().unwrap() == Some(b"@"))
            .unwrap();
        let document = entry.range().unwrap().unwrap().0;
        assert!(std::ptr::eq(document, tree.document()));
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
    fn token_lookup_has_exhaustive_half_open_boundary_behavior() {
        let input = b"name \t-- caf\xc3\xa9 --\n\"h\xc3\xa9\",{7}\xff";
        with_document(input, |document| {
            let (tree, _) = build(document);
            let tokens = tree
                .tokens()
                .map(|token| (token.kind(), token.range().byte_range()))
                .collect::<Vec<_>>();

            assert!(tokens.iter().any(|(kind, _)| kind.is_identifier()));
            assert!(
                tokens
                    .iter()
                    .any(|(kind, _)| *kind == SyntaxKind::Whitespace)
            );
            assert!(tokens.iter().any(|(kind, _)| *kind == SyntaxKind::Comment));
            assert!(tokens.iter().any(|(kind, _)| kind.is_literal()));
            assert!(tokens.iter().any(|(kind, _)| kind.is_punctuation()));
            assert!(
                tokens
                    .iter()
                    .any(|(kind, _)| *kind == SyntaxKind::ErrorToken)
            );

            for (index, (kind, range)) in tokens.iter().enumerate() {
                let at_start = tree
                    .token_at(ByteOffset::new(range.start as u32))
                    .expect("every token start is in the document");
                assert_eq!(at_start.kind(), *kind, "start of token {index}");
                assert_eq!(
                    at_start.range().byte_range(),
                    *range,
                    "start of token {index}"
                );

                for byte in range.clone() {
                    let inside = tree.token_at(ByteOffset::new(byte as u32)).unwrap();
                    assert_eq!(inside.kind(), *kind, "byte {byte} of token {index}");
                    assert_eq!(inside.range().byte_range(), *range, "byte {byte}");
                }

                let at_end = tree
                    .token_at(ByteOffset::new(range.end as u32))
                    .expect("token ends are in the document");
                let expected = tokens
                    .get(index + 1)
                    .unwrap_or_else(|| tokens.last().expect("the token stream includes EOF"));
                assert_eq!(at_end.kind(), expected.0, "end of token {index}");
                assert_eq!(
                    at_end.range().byte_range(),
                    expected.1,
                    "end of token {index}"
                );
            }

            for (position, expected_kind) in [
                (
                    input
                        .windows(2)
                        .position(|bytes| bytes == b"\xc3\xa9")
                        .unwrap(),
                    SyntaxKind::Comment,
                ),
                (
                    input
                        .windows(2)
                        .rposition(|bytes| bytes == b"\xc3\xa9")
                        .unwrap(),
                    SyntaxKind::QuotedString,
                ),
            ] {
                for offset in position..position + 2 {
                    assert_eq!(
                        tree.token_at(ByteOffset::new(offset as u32))
                            .unwrap()
                            .kind(),
                        expected_kind
                    );
                }
            }
            assert_eq!(
                tree.token_at(ByteOffset::new((input.len() - 1) as u32))
                    .unwrap()
                    .kind(),
                SyntaxKind::ErrorToken
            );
            assert_eq!(
                tree.token_at(ByteOffset::new(input.len() as u32))
                    .unwrap()
                    .kind(),
                SyntaxKind::EofToken
            );
            assert!(
                tree.token_at(ByteOffset::new(input.len() as u32 + 1))
                    .is_none()
            );
            assert!(tree.token_at(ByteOffset::new(u32::MAX)).is_none());
        });
    }

    #[test]
    fn empty_input_token_lookup_returns_only_eof_at_document_end() {
        with_document(b"", |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty());
            let eof = tree.token_at(ByteOffset::new(0)).unwrap();
            assert_eq!(eof.kind(), SyntaxKind::EofToken);
            assert_eq!(eof.range().byte_range(), 0..0);
            assert_eq!(eof.text(), b"");
            assert!(tree.token_at(ByteOffset::new(1)).is_none());
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
                SyntaxKind::TypeRefSyntax,
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
    fn embedded_foundation_corpus_round_trips_with_definition_nodes() {
        for (name, input) in [
            (
                "RFC1065-SMI",
                include_bytes!("../lower/embedded/RFC1065-SMI").as_slice(),
            ),
            (
                "RFC1155-SMI",
                include_bytes!("../lower/embedded/RFC1155-SMI").as_slice(),
            ),
            (
                "RFC-1212",
                include_bytes!("../lower/embedded/RFC-1212").as_slice(),
            ),
            (
                "RFC-1215",
                include_bytes!("../lower/embedded/RFC-1215").as_slice(),
            ),
            (
                "SNMPv2-SMI",
                include_bytes!("../lower/embedded/SNMPv2-SMI").as_slice(),
            ),
            (
                "SNMPv2-TC",
                include_bytes!("../lower/embedded/SNMPv2-TC").as_slice(),
            ),
            (
                "SNMPv2-CONF",
                include_bytes!("../lower/embedded/SNMPv2-CONF").as_slice(),
            ),
        ] {
            with_document(input, |document| {
                let (tree, _) = build(document);
                assert!(tree.source_file().modules().count() > 0, "{name}");
                assert!(tree.source_file().definitions().count() > 0, "{name}");
                assert_eq!(tree.reconstruct_text(), input, "{name}");
            });
        }
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
    fn common_clause_wrappers_retain_valid_values() {
        let input = br#"CLAUSE-MIB DEFINITIONS ::= BEGIN
item OBJECT-TYPE
    SYNTAX INTEGER (0..10)
    UNITS "widgets"
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "description"
    REFERENCE "reference"
    INDEX { IMPLIED indexObject, OCTET STRING }
    DEFVAL { { enabled, disabled } }
    ::= { ROOT-MIB.root(1) 2 leaf }
augmented OBJECT-TYPE
    SYNTAX INTEGER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "augmented"
    AUGMENTS { parentEntry }
    ::= { item 2 }
notice NOTIFICATION-TYPE
    OBJECTS { item, other }
    STATUS current
    DESCRIPTION "notice"
    ::= { item 3 }
noticeGroup NOTIFICATION-GROUP
    NOTIFICATIONS { notice }
    STATUS current
    DESCRIPTION "group"
    ::= { item 4 }
identity MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "org"
    CONTACT-INFO "contact"
    DESCRIPTION "identity"
    REVISION "202608180000Z"
    DESCRIPTION "revision"
    ::= { item 5 }
legacy TRAP-TYPE
    ENTERPRISE item
    VARIABLES { item }
    DESCRIPTION "trap"
    ::= 1
Text ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "d"
    STATUS current
    DESCRIPTION "text"
    REFERENCE "reference"
    SYNTAX BITS { enabled(0), disabled(1) }
caps AGENT-CAPABILITIES
    PRODUCT-RELEASE "release"
    STATUS current
    DESCRIPTION "caps"
    ::= { item 5 }
END"#;
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");

            let syntax = tree
                .nodes()
                .filter_map(SyntaxClause::cast)
                .collect::<Vec<_>>();
            assert_eq!(syntax.len(), 3);
            assert!(syntax.iter().all(|clause| clause.type_syntax().is_some()));
            let access = tree.nodes().find_map(AccessClause::cast).unwrap();
            assert_eq!(access.keyword().unwrap().text(), b"MAX-ACCESS");
            assert_eq!(access.value().unwrap().text(), b"read-only");
            assert!(tree.nodes().find_map(StatusClause::cast).is_some());
            assert!(tree.nodes().find_map(DescriptionClause::cast).is_some());
            assert!(tree.nodes().find_map(ReferenceClause::cast).is_some());
            assert!(tree.nodes().find_map(UnitsClause::cast).is_some());
            assert!(tree.nodes().find_map(DisplayHintClause::cast).is_some());
            assert!(tree.nodes().find_map(LastUpdatedClause::cast).is_some());
            assert!(tree.nodes().find_map(OrganizationClause::cast).is_some());
            assert!(tree.nodes().find_map(ContactInfoClause::cast).is_some());
            assert!(tree.nodes().find_map(RevisionClause::cast).is_some());
            assert!(tree.nodes().find_map(EnterpriseClause::cast).is_some());
            assert!(tree.nodes().find_map(ProductReleaseClause::cast).is_some());

            let index = tree.nodes().find_map(IndexClause::cast).unwrap();
            let items = index.items().collect::<Vec<_>>();
            assert_eq!(items.len(), 2);
            assert!(items[0].implied().is_some());
            assert_eq!(items[0].object().unwrap().text(), b"indexObject");
            assert_eq!(items[1].object().unwrap().text(), b"OCTET");
            assert_eq!(items[1].string_keyword().unwrap().text(), b"STRING");
            assert_eq!(
                tree.nodes()
                    .find_map(AugmentsClause::cast)
                    .unwrap()
                    .target()
                    .unwrap()
                    .text(),
                b"parentEntry"
            );
            assert_eq!(
                tree.nodes()
                    .find_map(ObjectsClause::cast)
                    .unwrap()
                    .names()
                    .count(),
                2
            );
            assert!(tree.nodes().find_map(NotificationsClause::cast).is_some());
            assert!(tree.nodes().find_map(VariablesClause::cast).is_some());

            let defval = tree.nodes().find_map(DefvalClause::cast).unwrap();
            let content = defval.content().unwrap();
            assert!(content.l_brace().is_some());
            assert!(content.r_brace().is_some());
            assert_eq!(
                content.tokens().map(SyntaxToken::text).collect::<Vec<_>>(),
                [
                    b" ".as_slice(),
                    b"{".as_slice(),
                    b" ".as_slice(),
                    b"enabled".as_slice(),
                    b",".as_slice(),
                    b" ".as_slice(),
                    b"disabled".as_slice(),
                    b" ".as_slice(),
                    b"}".as_slice(),
                    b" ".as_slice()
                ]
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn common_clause_wrappers_preserve_missing_and_malformed_parts() {
        let input = b"BROKEN-CLAUSE-MIB DEFINITIONS ::= BEGIN\nitem OBJECT-TYPE\n SYNTAX\n MAX-ACCESS\n STATUS @bad\n DESCRIPTION\n INDEX { IMPLIED }\n AUGMENTS { one, two }\n DEFVAL { { one }\n OBJECTS { first, @bad\nnext OBJECT IDENTIFIER ::= { root 1 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let syntax = tree.nodes().find_map(SyntaxClause::cast).unwrap();
            assert!(syntax.type_syntax().is_none());
            let access = tree.nodes().find_map(AccessClause::cast).unwrap();
            assert!(access.value().is_none());
            let status = tree.nodes().find_map(StatusClause::cast).unwrap();
            assert!(status.value().is_none());
            assert_eq!(status.recovery_regions().count(), 1);
            let description = tree.nodes().find_map(DescriptionClause::cast).unwrap();
            assert!(description.value().is_none());
            let index = tree.nodes().find_map(IndexClause::cast).unwrap();
            let item = index.items().next().unwrap();
            assert!(item.implied().is_some());
            assert!(item.object().is_none());
            assert!(index.r_brace().is_some());
            let augments = tree.nodes().find_map(AugmentsClause::cast).unwrap();
            assert_eq!(augments.target().unwrap().text(), b"one");
            let defval = tree.nodes().find_map(DefvalClause::cast).unwrap();
            assert!(defval.content().unwrap().r_brace().is_none());
            let objects = tree.nodes().find_map(ObjectsClause::cast).unwrap();
            assert!(objects.r_brace().is_none());
            assert_eq!(objects.recovery_regions().count(), 1);
            // Recovery stops before the later complete definition.
            let oids = tree
                .nodes()
                .filter_map(OidAssignment::cast)
                .collect::<Vec<_>>();
            assert_eq!(oids.len(), 1);
            assert!(oids[0].r_brace().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn every_common_clause_family_retains_truncated_values() {
        let input = b"TRUNCATED-CLAUSE-MIB DEFINITIONS ::= BEGIN\nidentity MODULE-IDENTITY\n LAST-UPDATED\n ORGANIZATION\n CONTACT-INFO\n REVISION\n DESCRIPTION\n REFERENCE\n ::= { root 1 }\ntc ::= TEXTUAL-CONVENTION\n DISPLAY-HINT\n STATUS\n DESCRIPTION\n REFERENCE\n SYNTAX INTEGER\nobject OBJECT-TYPE\n SYNTAX INTEGER\n UNITS\n MAX-ACCESS\n DEFVAL\n ::= { root 2 }\ntrap TRAP-TYPE\n ENTERPRISE\n VARIABLES { item\n ::= 1\nnotice NOTIFICATION-TYPE\n OBJECTS { item\n ::= { root 3 }\ngroup NOTIFICATION-GROUP\n NOTIFICATIONS { notice\n STATUS current\n DESCRIPTION \"group\"\n ::= { root 4 }\ncaps AGENT-CAPABILITIES\n PRODUCT-RELEASE\n STATUS current\n DESCRIPTION \"caps\"\n ::= { root 5 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());

            assert!(
                tree.nodes()
                    .find_map(LastUpdatedClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(OrganizationClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(ContactInfoClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(RevisionClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(DescriptionClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(ReferenceClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(DisplayHintClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(StatusClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(UnitsClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(AccessClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(DefvalClause::cast)
                    .unwrap()
                    .content()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(EnterpriseClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(VariablesClause::cast)
                    .unwrap()
                    .r_brace()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(ObjectsClause::cast)
                    .unwrap()
                    .r_brace()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(NotificationsClause::cast)
                    .unwrap()
                    .r_brace()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(ProductReleaseClause::cast)
                    .unwrap()
                    .value()
                    .is_none()
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn oid_assignment_and_component_wrappers_cover_all_forms() {
        let input = b"OID-CST-MIB DEFINITIONS ::= BEGIN\nvalue OBJECT IDENTIFIER ::= { 1 iso org(3) OTHER-MIB.root OTHER-MIB.branch(7) }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let syntax = tree.nodes().find_map(ObjectIdentifierSyntax::cast).unwrap();
            assert!(syntax.object().is_some());
            assert!(syntax.identifier().is_some());
            let oid = tree.nodes().find_map(OidAssignment::cast).unwrap();
            let components = oid.components().collect::<Vec<_>>();
            assert_eq!(components.len(), 5);
            assert_eq!(components[0].number().unwrap().text(), b"1");
            assert_eq!(components[1].name().unwrap().text(), b"iso");
            assert_eq!(components[2].name().unwrap().text(), b"org");
            assert_eq!(components[2].number().unwrap().text(), b"3");
            assert_eq!(components[3].module().unwrap().text(), b"OTHER-MIB");
            assert_eq!(components[3].name().unwrap().text(), b"root");
            assert_eq!(components[4].number().unwrap().text(), b"7");
            assert!(oid.r_brace().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });

        let truncated = b"OID-CST-MIB DEFINITIONS ::= BEGIN\nfirst OBJECT IDENTIFIER ::= { root( ) OTHER. }\nsecond OBJECT IDENTIFIER ::= { root(1)\nEND";
        with_document(truncated, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let oids = tree
                .nodes()
                .filter_map(OidAssignment::cast)
                .collect::<Vec<_>>();
            assert_eq!(oids.len(), 2);
            assert!(oids[0].r_brace().is_some());
            assert!(
                oids[0]
                    .components()
                    .any(|component| component.number().is_none())
            );
            assert!(oids[1].r_brace().is_none());
            assert_eq!(tree.reconstruct_text(), truncated);
        });
    }

    #[test]
    fn named_numbers_and_constraint_wrappers_are_nested_and_lossless() {
        let input = b"TYPE-CST-MIB DEFINITIONS ::= BEGIN\nEnum ::= INTEGER { up(1), down(-1) }\nRestricted ::= Enum { first(4), second(5) }\nFlags ::= BITS { a(0), b(1) }\nSized ::= OCTET STRING (SIZE (0..16 | 32))\nRanged ::= INTEGER (-1..MAX | 8)\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let enums = tree
                .nodes()
                .filter_map(IntegerEnumSyntax::cast)
                .collect::<Vec<_>>();
            assert_eq!(enums.len(), 2);
            assert_eq!(enums[0].values().count(), 2);
            assert_eq!(enums[1].base().unwrap().text(), b"Enum");
            let bits = tree.nodes().find_map(BitsSyntax::cast).unwrap();
            assert_eq!(bits.values().count(), 2);
            let named = tree.nodes().find_map(NamedNumber::cast).unwrap();
            assert!(named.label().is_some());
            assert!(named.value().is_some());
            let constrained = tree
                .nodes()
                .filter_map(ConstrainedSyntax::cast)
                .collect::<Vec<_>>();
            assert_eq!(constrained.len(), 2);
            let size = constrained[0].constraint().unwrap();
            assert!(size.size().is_some());
            assert_eq!(size.ranges().count(), 2);
            let ranged = constrained[1].constraint().unwrap();
            let ranges = ranged.ranges().collect::<Vec<_>>();
            assert_eq!(ranges.len(), 2);
            assert_eq!(ranges[0].min().unwrap().text(), b"-1");
            assert_eq!(ranges[0].max().unwrap().text(), b"MAX");
            assert!(ranges[1].dot_dot().is_none());
            assert!(tree.nodes().find_map(OctetStringSyntax::cast).is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });

        let malformed = b"TYPE-CST-MIB DEFINITIONS ::= BEGIN\nBadEnum ::= INTEGER { one(), two(x) }\nBadBits ::= BITS { flag(x) }\nBadRange ::= INTEGER (0.. | @bad)\nAfter ::= INTEGER\nEND";
        with_document(malformed, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let values = tree
                .nodes()
                .filter_map(NamedNumber::cast)
                .collect::<Vec<_>>();
            assert!(values.iter().any(|value| value.value().is_none()));
            assert!(
                values
                    .iter()
                    .any(|value| value.recovery_regions().count() == 1)
            );
            assert!(
                tree.nodes()
                    .find_map(BitsSyntax::cast)
                    .unwrap()
                    .values()
                    .any(|value| value.recovery_regions().count() == 1)
            );
            let ranges = tree.nodes().filter_map(Range::cast).collect::<Vec<_>>();
            assert!(
                ranges
                    .iter()
                    .any(|range| { range.dot_dot().is_some() && range.max().is_none() })
            );
            assert!(
                tree.nodes()
                    .filter_map(TypeRefSyntax::cast)
                    .any(|syntax| syntax.name().unwrap().text() == b"INTEGER")
            );
            assert_eq!(tree.reconstruct_text(), malformed);
        });
    }

    #[test]
    fn composite_and_tagged_type_wrappers_recover_to_later_types() {
        let input = b"COMPOSITE-CST-MIB DEFINITIONS ::= BEGIN\nRows ::= SEQUENCE OF Row\nRow ::= SEQUENCE { first INTEGER, second OCTET STRING }\nUnion ::= CHOICE { number INTEGER, text OCTET STRING }\nTagged ::= [APPLICATION 4] IMPLICIT OCTET STRING\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let sequence_of = tree.nodes().find_map(SequenceOfSyntax::cast).unwrap();
            assert_eq!(sequence_of.entry_type().unwrap().text(), b"Row");
            let sequence = tree.nodes().find_map(SequenceSyntax::cast).unwrap();
            assert_eq!(sequence.fields().count(), 2);
            let field = tree.nodes().find_map(SequenceField::cast).unwrap();
            assert!(field.name().is_some());
            assert!(field.type_syntax().is_some());
            let choice = tree.nodes().find_map(ChoiceSyntax::cast).unwrap();
            assert_eq!(choice.fields().count(), 2);
            let tagged = tree.nodes().find_map(TaggedSyntax::cast).unwrap();
            assert_eq!(tagged.tag_class().unwrap().text(), b"APPLICATION");
            assert_eq!(tagged.tag_number().unwrap().text(), b"4");
            assert!(tagged.implicit().is_some());
            assert!(tagged.inner().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });

        let malformed = b"COMPOSITE-CST-MIB DEFINITIONS ::= BEGIN\nBadRows ::= SEQUENCE OF\nBadRow ::= SEQUENCE { missing, good INTEGER }\nBadChoice ::= CHOICE { alt }\nBadTag ::= [APPLICATION ] IMPLICIT\nBadOctets ::= OCTET\nBadOidType ::= OBJECT\nAfter ::= INTEGER\nEND";
        with_document(malformed, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let sequence_of = tree.nodes().find_map(SequenceOfSyntax::cast).unwrap();
            assert!(sequence_of.entry_type().is_none());
            let fields = tree
                .nodes()
                .filter_map(SequenceField::cast)
                .collect::<Vec<_>>();
            assert!(fields.iter().any(|field| field.type_syntax().is_none()));
            let tagged = tree.nodes().find_map(TaggedSyntax::cast).unwrap();
            assert!(tagged.tag_number().is_none());
            assert!(tagged.inner().is_none());
            assert!(
                tree.nodes()
                    .find_map(OctetStringSyntax::cast)
                    .unwrap()
                    .string()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(ObjectIdentifierSyntax::cast)
                    .unwrap()
                    .identifier()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .filter_map(TypeRefSyntax::cast)
                    .any(|syntax| syntax.name().unwrap().text() == b"INTEGER")
            );
            assert_eq!(tree.reconstruct_text(), malformed);
        });
    }

    #[test]
    fn unterminated_constraints_and_field_types_stop_at_definition_boundaries() {
        let input = b"BOUNDARY-CST-MIB DEFINITIONS ::= BEGIN\nconstrained OBJECT-TYPE\n SYNTAX INTEGER (0..10\n STATUS current\n DESCRIPTION \"constraint survived\"\n ::= { root 1 }\nsequence OBJECT-TYPE\n SYNTAX SEQUENCE { field INTEGER\n STATUS current\n DESCRIPTION \"sequence survived\"\n ::= { root 2 }\nchoice OBJECT-TYPE\n SYNTAX CHOICE { alternative OCTET STRING\n STATUS current\n DESCRIPTION \"choice survived\"\n ::= { root 3 }\nafter OBJECT IDENTIFIER ::= { root 4 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());

            let constraint = tree.nodes().find_map(Constraint::cast).unwrap();
            assert!(constraint.r_paren().is_none());
            assert!(
                tree.nodes()
                    .find_map(SequenceSyntax::cast)
                    .unwrap()
                    .r_brace()
                    .is_none()
            );
            assert!(
                tree.nodes()
                    .find_map(ChoiceSyntax::cast)
                    .unwrap()
                    .r_brace()
                    .is_none()
            );
            assert_eq!(tree.nodes().filter_map(StatusClause::cast).count(), 3);
            assert_eq!(tree.nodes().filter_map(DescriptionClause::cast).count(), 3);

            let oids = tree
                .nodes()
                .filter_map(OidAssignment::cast)
                .collect::<Vec<_>>();
            assert_eq!(oids.len(), 4);
            assert!(oids.iter().all(|oid| oid.r_brace().is_some()));
            assert_eq!(
                oids[3].components().next().unwrap().name().unwrap().text(),
                b"root"
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn type_and_oid_contexts_distinguish_declarations_from_values() {
        let input = b"CONTEXT-CST-MIB DEFINITIONS ::= BEGIN\nfoo SomeType ::= otherValue\nFoo ::= SomeType\ntaggedValue [APPLICATION 1] IMPLICIT SomeType ::= otherTagged\nTaggedType ::= [APPLICATION 2] IMPLICIT SomeType\nbitsValue BITS ::= { first, second }\nactual OBJECT IDENTIFIER ::= { ROOT-MIB.root 1 }\nobject OBJECT-TYPE\n SYNTAX INTEGER\n MAX-ACCESS read-only\n STATUS current\n DESCRIPTION \"object\"\n ::= { actual 2 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");

            let type_names = tree
                .nodes()
                .filter_map(TypeRefSyntax::cast)
                .map(|syntax| syntax.name().unwrap().text())
                .collect::<Vec<_>>();
            assert_eq!(
                type_names
                    .iter()
                    .filter(|name| **name == b"SomeType")
                    .count(),
                4
            );
            assert!(!type_names.iter().any(|name| {
                matches!(*name, b"otherValue" | b"otherTagged" | b"first" | b"second")
            }));
            assert!(type_names.iter().any(|name| *name == b"BITS"));
            assert_eq!(tree.nodes().filter_map(TaggedSyntax::cast).count(), 2);

            let oids = tree
                .nodes()
                .filter_map(OidAssignment::cast)
                .collect::<Vec<_>>();
            assert_eq!(oids.len(), 2);
            let qualified = oids[0].components().next().unwrap();
            assert_eq!(qualified.module().unwrap().text(), b"ROOT-MIB");
            assert_eq!(qualified.name().unwrap().text(), b"root");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn oid_assignment_context_is_not_reused_by_a_stray_assignment() {
        let input = b"STALE-OID-CST-MIB DEFINITIONS ::= BEGIN\ngood OBJECT IDENTIFIER ::= { root 1 }\n::= { stray 2 }\nEND";
        with_document(input, |document| {
            let (tree, _) = build(document);
            let oids = tree
                .nodes()
                .filter_map(OidAssignment::cast)
                .collect::<Vec<_>>();
            assert_eq!(oids.len(), 1);
            assert!(oids[0].r_brace().is_some());
            assert!(
                !oids[0]
                    .components()
                    .any(|part| { part.name().is_some_and(|name| name.text() == b"stray") })
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn definition_assignment_context_is_consumed_once_and_resets_at_next_definition() {
        let input = b"STALE-CST-MIB DEFINITIONS ::= BEGIN\nGoodType ::= SomeType\n::= OtherType\nbroken OBJECT IDENTIFIER ::= { root 3\nlater OBJECT IDENTIFIER ::= { root 4 }\nLaterType ::= FinalType\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());

            let oids = tree
                .nodes()
                .filter_map(OidAssignment::cast)
                .collect::<Vec<_>>();
            assert_eq!(oids.len(), 2);
            assert!(oids[0].r_brace().is_none());
            assert!(oids[1].r_brace().is_some());

            let type_names = tree
                .nodes()
                .filter_map(TypeRefSyntax::cast)
                .map(|syntax| syntax.name().unwrap().text())
                .collect::<Vec<_>>();
            assert_eq!(
                type_names,
                [b"SomeType".as_slice(), b"FinalType".as_slice()]
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn balanced_defval_content_does_not_create_nested_definition_boundaries() {
        let input = b"NESTED-CST-MIB DEFINITIONS ::= BEGIN\nitem OBJECT-TYPE\n SYNTAX INTEGER\n MAX-ACCESS read-only\n STATUS current\n DESCRIPTION \"item\"\n DEFVAL {\n  fake ::= INTEGER\n }\n ::= { root 1 }\nlater OBJECT IDENTIFIER ::= { root 2 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");

            let content = tree.nodes().find_map(DefvalContent::cast).unwrap();
            assert!(content.r_brace().is_some());
            let content_text = content.tokens().fold(Vec::new(), |mut text, token| {
                text.extend_from_slice(token.text());
                text
            });
            assert_eq!(content_text, b"\n  fake ::= INTEGER\n ");
            assert_eq!(
                tree.nodes()
                    .filter_map(TypeRefSyntax::cast)
                    .filter(|syntax| syntax.name().is_some_and(|name| name.text() == b"INTEGER"))
                    .count(),
                1
            );
            assert_eq!(tree.nodes().filter_map(OidAssignment::cast).count(), 2);
            let definitions = tree
                .source_file()
                .modules()
                .next()
                .unwrap()
                .definitions()
                .collect::<Vec<_>>();
            assert_eq!(definitions.len(), 2);
            assert_eq!(definitions[0].name().unwrap().text(), b"item");
            assert_eq!(definitions[1].name().unwrap().text(), b"later");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn assignment_like_tokens_in_type_content_do_not_create_definitions() {
        let input = b"NESTED-TYPE-CST-MIB DEFINITIONS ::= BEGIN\nOuter ::= SEQUENCE { fake ::= INTEGER }\nAfter ::= INTEGER\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let module = tree.source_file().modules().next().unwrap();
            let definitions = module.definitions().collect::<Vec<_>>();
            assert_eq!(definitions.len(), 2);
            assert!(matches!(definitions[0], Definition::Error(_)));
            assert_eq!(definitions[1].name().unwrap().text(), b"After");
            assert_eq!(tree.nodes().filter_map(TypeAssignment::cast).count(), 2);
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn unclosed_nested_content_recovers_at_a_confident_later_definition() {
        let input = b"UNCLOSED-NESTED-CST-MIB DEFINITIONS ::= BEGIN\nbroken OBJECT-TYPE\n SYNTAX INTEGER\n DEFVAL { value\nlater OBJECT IDENTIFIER ::= { root 2 }\nAfter ::= FinalType\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            assert!(
                tree.nodes()
                    .find_map(DefvalContent::cast)
                    .unwrap()
                    .r_brace()
                    .is_none()
            );
            assert_eq!(tree.nodes().filter_map(OidAssignment::cast).count(), 1);
            assert!(tree.nodes().filter_map(TypeRefSyntax::cast).any(|syntax| {
                syntax
                    .name()
                    .is_some_and(|name| name.text() == b"FinalType")
            }));
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn definition_context_work_is_linear_for_many_assignments() {
        const DEFINITION_COUNT: usize = 4_000;

        let mut input = String::from("LINEAR-CST-MIB DEFINITIONS ::= BEGIN\n");
        for index in 0..DEFINITION_COUNT {
            writeln!(input, "Type{index} ::= INTEGER").unwrap();
        }
        input.push_str("END");

        with_document(input.as_bytes(), |document| {
            super::body::reset_definition_context_work();
            let (tree, diagnostics) = build(document);
            let work = super::body::definition_context_work();
            let token_count = tree.tokens().count();

            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            assert_eq!(
                tree.nodes().filter_map(TypeRefSyntax::cast).count(),
                DEFINITION_COUNT
            );
            assert_eq!(
                tree.source_file()
                    .modules()
                    .next()
                    .unwrap()
                    .definitions()
                    .count(),
                DEFINITION_COUNT
            );
            assert!(
                work <= token_count * 4,
                "definition-context work {work} exceeded linear bound for {token_count} tokens"
            );
            assert_eq!(tree.reconstruct_text(), input.as_bytes());
        });
    }

    #[test]
    fn primary_definition_families_are_typed_and_iterated_in_source_order() {
        let cases: &[(&str, &[u8], SyntaxKind)] = &[
            (
                "value assignment",
                b"value OBJECT IDENTIFIER ::= { root 1 }",
                SyntaxKind::ValueAssignment,
            ),
            (
                "type assignment",
                b"Type ::= INTEGER (0..10)",
                SyntaxKind::TypeAssignment,
            ),
            (
                "textual convention",
                br#"Convention ::= TEXTUAL-CONVENTION
 STATUS current
 DESCRIPTION "convention"
 SYNTAX OCTET STRING"#,
                SyntaxKind::TextualConventionDefinition,
            ),
            (
                "object type",
                br#"object OBJECT-TYPE
 SYNTAX INTEGER
 MAX-ACCESS read-only
 STATUS current
 DESCRIPTION "object"
 ::= { root 1 }"#,
                SyntaxKind::ObjectTypeDefinition,
            ),
            (
                "module identity",
                br#"module MODULE-IDENTITY
 LAST-UPDATED "202608180000Z"
 ORGANIZATION "org"
 CONTACT-INFO "contact"
 DESCRIPTION "module"
 REVISION "202608170000Z"
 DESCRIPTION "revision"
 ::= { root 1 }"#,
                SyntaxKind::ModuleIdentityDefinition,
            ),
            (
                "object identity",
                br#"identity OBJECT-IDENTITY
 STATUS current
 DESCRIPTION "identity"
 ::= { root 1 }"#,
                SyntaxKind::ObjectIdentityDefinition,
            ),
            (
                "notification type",
                br#"notice NOTIFICATION-TYPE
 OBJECTS { object }
 STATUS current
 DESCRIPTION "notice"
 ::= { root 1 }"#,
                SyntaxKind::NotificationTypeDefinition,
            ),
            (
                "trap type",
                br#"trap TRAP-TYPE
 ENTERPRISE root
 VARIABLES { object }
 DESCRIPTION "trap"
 ::= 7"#,
                SyntaxKind::TrapTypeDefinition,
            ),
            (
                "macro",
                b"TEST-MACRO MACRO -- framing -- ::= -- begin -- BEGIN\nTYPE NOTATION ::= \"type\"\nEND",
                SyntaxKind::MacroDefinition,
            ),
        ];

        for &(family, definition, expected_kind) in cases {
            let mut input = b"DEFINITION-CST-MIB DEFINITIONS ::= BEGIN\n".to_vec();
            input.extend_from_slice(definition);
            input.extend_from_slice(b"\nAfter ::= INTEGER\nEND");
            with_document(&input, |document| {
                let (tree, diagnostics) = build(document);
                assert!(diagnostics.is_empty(), "{family}: {diagnostics:#?}");
                let module = tree.source_file().modules().next().unwrap();
                let definitions = module.definitions().collect::<Vec<_>>();
                assert_eq!(definitions.len(), 2, "{family}");
                assert_eq!(definitions[0].syntax().kind(), expected_kind, "{family}");
                assert_eq!(definitions[0].syntax().text(), definition, "{family}");
                match definitions[0] {
                    Definition::ValueAssignment(node) => {
                        assert!(node.identifier().is_some());
                        assert!(node.oid().is_some());
                    }
                    Definition::TypeAssignment(node) => {
                        assert!(node.assignment().is_some());
                        assert!(node.type_syntax().is_some());
                    }
                    Definition::TextualConvention(node) => {
                        assert!(node.status().is_some());
                        assert!(node.description().is_some());
                        assert!(node.syntax_clause().is_some());
                    }
                    Definition::ObjectType(node) => {
                        assert!(node.syntax_clause().is_some());
                        assert!(node.access().is_some());
                        assert!(node.status().is_some());
                        assert!(node.description().is_some());
                        assert!(node.oid().is_some());
                    }
                    Definition::ModuleIdentity(node) => {
                        assert!(node.last_updated().is_some());
                        assert!(node.organization().is_some());
                        assert!(node.contact_info().is_some());
                        assert_eq!(node.descriptions().count(), 2);
                        assert_eq!(node.revisions().count(), 1);
                        assert!(node.oid().is_some());
                    }
                    Definition::ObjectIdentity(node) => {
                        assert!(node.status().is_some());
                        assert!(node.description().is_some());
                        assert!(node.oid().is_some());
                    }
                    Definition::NotificationType(node) => {
                        assert!(node.objects().is_some());
                        assert!(node.status().is_some());
                        assert!(node.description().is_some());
                        assert!(node.oid().is_some());
                    }
                    Definition::TrapType(node) => {
                        assert!(node.enterprise().is_some());
                        assert!(node.variables().is_some());
                        assert!(node.description().is_some());
                        assert!(node.trap_number().is_some());
                    }
                    Definition::Macro(node) => {
                        assert!(node.body().is_some());
                        assert!(node.end().is_some());
                    }
                    Definition::ObjectGroup(_)
                    | Definition::NotificationGroup(_)
                    | Definition::ModuleCompliance(_)
                    | Definition::AgentCapabilities(_) => {
                        panic!("{family}: unexpected CST-06 definition")
                    }
                    Definition::Error(_) => panic!("{family}: valid definition recovered"),
                }
                assert_eq!(definitions[1].name().unwrap().text(), b"After", "{family}");
                assert_eq!(tree.source_file().definitions().count(), 2, "{family}");
                assert_eq!(tree.reconstruct_text(), input, "{family}");
            });
        }
    }

    #[test]
    fn malformed_primary_definitions_recover_before_later_definitions() {
        let cases: &[(&str, &[u8], SyntaxKind)] = &[
            (
                "value assignment missing IDENTIFIER",
                b"broken OBJECT ::= { root 1 }",
                SyntaxKind::ValueAssignment,
            ),
            (
                "value assignment truncated OID",
                b"broken OBJECT IDENTIFIER ::= { root 1",
                SyntaxKind::ValueAssignment,
            ),
            (
                "type assignment missing operator",
                b"Broken INTEGER",
                SyntaxKind::TypeAssignment,
            ),
            (
                "type assignment missing syntax",
                b"Broken ::=",
                SyntaxKind::TypeAssignment,
            ),
            (
                "textual convention missing status",
                b"Broken ::= TEXTUAL-CONVENTION DESCRIPTION \"broken\" SYNTAX INTEGER",
                SyntaxKind::TextualConventionDefinition,
            ),
            (
                "textual convention wrong order",
                b"Broken ::= TEXTUAL-CONVENTION STATUS current SYNTAX INTEGER DESCRIPTION \"broken\"",
                SyntaxKind::TextualConventionDefinition,
            ),
            (
                "object type missing access",
                b"broken OBJECT-TYPE SYNTAX INTEGER STATUS current DESCRIPTION \"broken\" ::= { root 1 }",
                SyntaxKind::ObjectTypeDefinition,
            ),
            (
                "object type wrong order",
                b"broken OBJECT-TYPE SYNTAX INTEGER STATUS current MAX-ACCESS read-only DESCRIPTION \"broken\" ::= { root 1 }",
                SyntaxKind::ObjectTypeDefinition,
            ),
            (
                "module identity missing organization",
                b"broken MODULE-IDENTITY LAST-UPDATED \"202608180000Z\" CONTACT-INFO \"contact\" DESCRIPTION \"broken\" ::= { root 1 }",
                SyntaxKind::ModuleIdentityDefinition,
            ),
            (
                "module identity wrong revision order",
                b"broken MODULE-IDENTITY LAST-UPDATED \"202608180000Z\" ORGANIZATION \"org\" CONTACT-INFO \"contact\" REVISION \"202608180000Z\" DESCRIPTION \"revision\" ::= { root 1 }",
                SyntaxKind::ModuleIdentityDefinition,
            ),
            (
                "object identity missing description",
                b"broken OBJECT-IDENTITY STATUS current ::= { root 1 }",
                SyntaxKind::ObjectIdentityDefinition,
            ),
            (
                "object identity wrong order",
                b"broken OBJECT-IDENTITY DESCRIPTION \"broken\" STATUS current ::= { root 1 }",
                SyntaxKind::ObjectIdentityDefinition,
            ),
            (
                "notification type missing status",
                b"broken NOTIFICATION-TYPE OBJECTS { object } DESCRIPTION \"broken\" ::= { root 1 }",
                SyntaxKind::NotificationTypeDefinition,
            ),
            (
                "notification type wrong objects order",
                b"broken NOTIFICATION-TYPE STATUS current OBJECTS { object } DESCRIPTION \"broken\" ::= { root 1 }",
                SyntaxKind::NotificationTypeDefinition,
            ),
            (
                "trap type missing enterprise",
                b"broken TRAP-TYPE DESCRIPTION \"broken\" ::= 1",
                SyntaxKind::TrapTypeDefinition,
            ),
            (
                "trap type wrong order",
                b"broken TRAP-TYPE VARIABLES { object } ENTERPRISE root ::= 1",
                SyntaxKind::TrapTypeDefinition,
            ),
            (
                "macro missing framing",
                b"BROKEN-MACRO MACRO missing-framing\nEND",
                SyntaxKind::MacroDefinition,
            ),
            (
                "macro reversed framing",
                b"BROKEN-MACRO MACRO BEGIN ::= body\nEND",
                SyntaxKind::MacroDefinition,
            ),
            (
                "macro quoted framing false positive",
                b"BROKEN-MACRO MACRO \"::= BEGIN\"\nEND",
                SyntaxKind::MacroDefinition,
            ),
            (
                "macro commented framing false positive",
                b"BROKEN-MACRO MACRO -- ::= BEGIN\nbody\nEND",
                SyntaxKind::MacroDefinition,
            ),
        ];

        for &(family, definition, partial_kind) in cases {
            let mut input = b"RECOVERY-CST-MIB DEFINITIONS ::= BEGIN\n".to_vec();
            input.extend_from_slice(definition);
            input.extend_from_slice(b"\nAfter ::= INTEGER\nEND");
            with_document(&input, |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty(), "{family}");
                let definitions = tree
                    .source_file()
                    .modules()
                    .next()
                    .unwrap()
                    .definitions()
                    .collect::<Vec<_>>();
                assert_eq!(definitions.len(), 2, "{family}");
                assert!(matches!(definitions[0], Definition::Error(_)), "{family}");
                assert_eq!(definitions[0].syntax().text(), definition, "{family}");
                let partials = definitions[0]
                    .syntax()
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .collect::<Vec<_>>();
                assert_eq!(partials.len(), 1, "{family}");
                assert_eq!(partials[0].kind(), partial_kind, "{family}");
                assert!(matches!(definitions[1], Definition::TypeAssignment(_)));
                assert_eq!(definitions[1].name().unwrap().text(), b"After", "{family}");
                assert_eq!(tree.reconstruct_text(), input, "{family}");
            });
        }
    }

    #[test]
    fn direct_textual_convention_form_is_retained() {
        let input = b"DIRECT-TC-CST-MIB DEFINITIONS ::= BEGIN\nConvention TEXTUAL-CONVENTION\n STATUS current\n DESCRIPTION \"direct\"\n SYNTAX INTEGER\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let definition = tree.source_file().definitions().next().unwrap();
            let Definition::TextualConvention(convention) = definition else {
                panic!("expected textual convention: {definition:?}");
            };
            assert!(convention.assignment().is_none());
            assert_eq!(convention.name().unwrap().text(), b"Convention");
            assert!(convention.status().is_some());
            assert!(convention.description().is_some());
            assert!(convention.syntax_clause().is_some());
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn object_type_accepts_smiv1_access_and_status_values() {
        let input = b"SMIV1-OBJECT-CST-MIB DEFINITIONS ::= BEGIN\nlegacy OBJECT-TYPE\n SYNTAX INTEGER\n ACCESS read-only\n STATUS mandatory\n DESCRIPTION \"legacy\"\n ::= { root 1 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let Definition::ObjectType(object) = tree.source_file().definitions().next().unwrap()
            else {
                panic!("expected OBJECT-TYPE");
            };
            assert_eq!(
                object.access().unwrap().keyword().unwrap().text(),
                b"ACCESS"
            );
            assert_eq!(
                object.status().unwrap().value().unwrap().text(),
                b"mandatory"
            );
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn object_type_status_and_description_are_independently_optional() {
        for (name, optional_clauses) in [
            ("without status", " DESCRIPTION \"description\"\n"),
            ("without description", " STATUS current\n"),
            ("without both", ""),
        ] {
            let input = format!(
                "OPTIONAL-OBJECT-CST-MIB DEFINITIONS ::= BEGIN\nobject OBJECT-TYPE\n SYNTAX INTEGER\n MAX-ACCESS read-only\n{optional_clauses} ::= {{ root 1 }}\nEND"
            );
            with_document(input.as_bytes(), |document| {
                let (tree, diagnostics) = build(document);
                assert!(diagnostics.is_empty(), "{name}: {diagnostics:#?}");
                let Definition::ObjectType(object) =
                    tree.source_file().definitions().next().unwrap()
                else {
                    panic!("{name}: expected OBJECT-TYPE");
                };
                assert!(object.syntax_clause().is_some(), "{name}");
                assert!(object.access().is_some(), "{name}");
                assert!(object.oid().is_some(), "{name}");
                assert_eq!(tree.reconstruct_text(), input.as_bytes(), "{name}");
            });
        }
    }

    #[test]
    fn access_and_status_clauses_accept_the_semantic_keyword_sets() {
        for (keyword, value) in [
            ("MAX-ACCESS", "read-only"),
            ("ACCESS", "read-write"),
            ("MIN-ACCESS", "read-create"),
            ("MAX-ACCESS", "not-accessible"),
            ("ACCESS", "accessible-for-notify"),
            ("MIN-ACCESS", "write-only"),
            ("MAX-ACCESS", "not-implemented"),
        ] {
            let input = format!(
                "ACCESS-CST-MIB DEFINITIONS ::= BEGIN\nobject OBJECT-TYPE\n SYNTAX INTEGER\n {keyword} {value}\n STATUS current\n DESCRIPTION \"object\"\n ::= {{ root 1 }}\nEND"
            );
            with_document(input.as_bytes(), |document| {
                let (tree, diagnostics) = build(document);
                assert!(
                    diagnostics.is_empty(),
                    "{keyword} {value}: {diagnostics:#?}"
                );
                let Definition::ObjectType(object) =
                    tree.source_file().definitions().next().unwrap()
                else {
                    panic!("expected OBJECT-TYPE");
                };
                let access = object.access().unwrap();
                assert_eq!(access.keyword().unwrap().text(), keyword.as_bytes());
                assert_eq!(access.value().unwrap().text(), value.as_bytes());
                assert_eq!(tree.reconstruct_text(), input.as_bytes());
            });
        }

        for value in ["current", "deprecated", "obsolete", "mandatory", "optional"] {
            let input = format!(
                "STATUS-CST-MIB DEFINITIONS ::= BEGIN\nobject OBJECT-TYPE\n SYNTAX INTEGER\n MAX-ACCESS read-only\n STATUS {value}\n DESCRIPTION \"object\"\n ::= {{ root 1 }}\nEND"
            );
            with_document(input.as_bytes(), |document| {
                let (tree, diagnostics) = build(document);
                assert!(diagnostics.is_empty(), "{value}: {diagnostics:#?}");
                let Definition::ObjectType(object) =
                    tree.source_file().definitions().next().unwrap()
                else {
                    panic!("expected OBJECT-TYPE");
                };
                assert_eq!(
                    object.status().unwrap().value().unwrap().text(),
                    value.as_bytes()
                );
                assert_eq!(tree.reconstruct_text(), input.as_bytes());
            });
        }
    }

    #[test]
    fn swapped_access_and_status_values_recover_the_definition() {
        for (name, clauses, clause_kind) in [
            (
                "access uses status value",
                " MAX-ACCESS current\n STATUS current\n",
                SyntaxKind::AccessClause,
            ),
            (
                "status uses access value",
                " MAX-ACCESS read-only\n STATUS read-only\n",
                SyntaxKind::StatusClause,
            ),
        ] {
            let input = format!(
                "SWAPPED-CST-MIB DEFINITIONS ::= BEGIN\nbroken OBJECT-TYPE\n SYNTAX INTEGER\n{clauses} DESCRIPTION \"broken\"\n ::= {{ root 1 }}\nAfter ::= INTEGER\nEND"
            );
            with_document(input.as_bytes(), |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty(), "{name}");
                let definitions = tree.source_file().definitions().collect::<Vec<_>>();
                assert_eq!(definitions.len(), 2, "{name}");
                assert!(matches!(definitions[0], Definition::Error(_)), "{name}");
                assert!(matches!(definitions[1], Definition::TypeAssignment(_)));
                let clause = tree
                    .nodes()
                    .find(|node| node.kind() == clause_kind)
                    .unwrap();
                assert!(
                    clause
                        .descendant_nodes()
                        .any(|node| node.kind() == SyntaxKind::Error)
                );
                if clause_kind == SyntaxKind::AccessClause {
                    let access = AccessClause::cast(clause).unwrap();
                    assert!(access.value().is_none());
                    assert_eq!(access.recovery_regions().count(), 1);
                } else {
                    let status = StatusClause::cast(clause).unwrap();
                    assert!(status.value().is_none());
                    assert_eq!(status.recovery_regions().count(), 1);
                }
                assert_eq!(tree.reconstruct_text(), input.as_bytes(), "{name}");
            });
        }
    }

    #[test]
    fn macro_begin_boundary_matches_comment_and_identifier_rules() {
        let valid = b"MACRO-BOUNDARY-CST-MIB DEFINITIONS ::= BEGIN\nVALID-MACRO MACRO ::= BEGIN-- adjacent comment\nTYPE NOTATION ::= \"type\"\nEND\nAfter ::= INTEGER\nEND";
        with_document(valid, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            assert!(matches!(
                tree.source_file().definitions().next(),
                Some(Definition::Macro(_))
            ));
            assert_eq!(tree.reconstruct_text(), valid);
        });

        for (name, framing) in [
            ("single hyphen", "::= BEGIN-body"),
            ("identifier suffix", "::= BEGINsuffix"),
            ("underscore suffix", "::= BEGIN_suffix"),
        ] {
            let input = format!(
                "MACRO-BOUNDARY-CST-MIB DEFINITIONS ::= BEGIN\nBROKEN-MACRO MACRO {framing}\nEND\nAfter ::= INTEGER\nEND"
            );
            with_document(input.as_bytes(), |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty(), "{name}");
                let definitions = tree.source_file().definitions().collect::<Vec<_>>();
                assert_eq!(definitions.len(), 2, "{name}");
                assert!(matches!(definitions[0], Definition::Error(_)), "{name}");
                assert!(matches!(definitions[1], Definition::TypeAssignment(_)));
                assert_eq!(tree.reconstruct_text(), input.as_bytes(), "{name}");
            });
        }
    }

    #[test]
    fn definition_cast_rejects_nested_recovery_nodes() {
        let input = b"CAST-CST-MIB DEFINITIONS ::= BEGIN\nbroken OBJECT-TYPE\n SYNTAX INTEGER\n MAX-ACCESS read-only\n STATUS current\n DESCRIPTION @\n ::= { root 1 }\nAfter ::= INTEGER\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let errors = tree
                .nodes()
                .filter(|node| node.kind() == SyntaxKind::Error)
                .collect::<Vec<_>>();
            assert!(errors.len() >= 2);
            let definition_errors = errors
                .iter()
                .filter(|error| matches!(Definition::cast(**error), Some(Definition::Error(_))))
                .count();
            assert_eq!(definition_errors, 1);
            assert!(
                errors
                    .iter()
                    .any(|error| Definition::cast(*error).is_none())
            );
            assert_eq!(tree.source_file().definitions().count(), 2);
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn defval_content_tokens_include_nested_recovery_tokens_exactly_once() {
        let input = b"DEFVAL-CST-MIB DEFINITIONS ::= BEGIN\nitem OBJECT-TYPE\n SYNTAX INTEGER\n DEFVAL { first @\n second }\n ::= { root 1 }\nEND";
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let content = tree
                .nodes()
                .find_map(DefvalContent::cast)
                .expect("DEFVAL content");
            let tokens = content.tokens().collect::<Vec<_>>();
            assert!(
                tokens
                    .iter()
                    .any(|token| token.kind() == SyntaxKind::ErrorToken)
            );
            let concatenated = tokens.iter().fold(Vec::new(), |mut bytes, token| {
                bytes.extend_from_slice(token.text());
                bytes
            });
            assert_eq!(concatenated, b" first @\n second ");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn body_parse_diagnostics_honor_ignore_and_severity_override() {
        let input = b"CONFIG-CST-MIB DEFINITIONS ::= BEGIN\nitem OBJECT-TYPE\n SYNTAX INTEGER (0..10\n STATUS current\n ::= { root 1 }\nEND";
        with_document(input, |document| {
            let mut ignored = DiagnosticConfig::default();
            ignored.ignore.push(DiagCode::ParseError.as_code().into());
            let (tree, diagnostics) = build_with_config(document, &ignored);
            assert!(diagnostics.is_empty());
            assert_eq!(tree.nodes().filter_map(StatusClause::cast).count(), 1);
            assert!(matches!(
                tree.source_file().definitions().next(),
                Some(Definition::Error(_))
            ));
            assert_eq!(tree.reconstruct_text(), input);

            let mut overridden = DiagnosticConfig::default();
            overridden
                .overrides
                .insert(DiagCode::ParseError, Severity::Warning);
            let (tree, diagnostics) = build_with_config(document, &overridden);
            assert!(!diagnostics.is_empty());
            assert!(diagnostics.iter().all(|diagnostic| {
                diagnostic.code == DiagCode::ParseError && diagnostic.severity == Severity::Warning
            }));
            assert_eq!(tree.nodes().filter_map(OidAssignment::cast).count(), 1);
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn all_cst04_wrappers_have_valid_and_recovered_coverage() {
        const CST04_KINDS: &[SyntaxKind] = &[
            SyntaxKind::SyntaxClause,
            SyntaxKind::AccessClause,
            SyntaxKind::StatusClause,
            SyntaxKind::DescriptionClause,
            SyntaxKind::ReferenceClause,
            SyntaxKind::UnitsClause,
            SyntaxKind::DisplayHintClause,
            SyntaxKind::IndexClause,
            SyntaxKind::IndexItem,
            SyntaxKind::AugmentsClause,
            SyntaxKind::DefvalClause,
            SyntaxKind::DefvalContent,
            SyntaxKind::ObjectsClause,
            SyntaxKind::NotificationsClause,
            SyntaxKind::RevisionClause,
            SyntaxKind::LastUpdatedClause,
            SyntaxKind::OrganizationClause,
            SyntaxKind::ContactInfoClause,
            SyntaxKind::EnterpriseClause,
            SyntaxKind::VariablesClause,
            SyntaxKind::ProductReleaseClause,
            SyntaxKind::OidAssignment,
            SyntaxKind::OidComponent,
            SyntaxKind::TypeRefSyntax,
            SyntaxKind::IntegerEnumSyntax,
            SyntaxKind::BitsSyntax,
            SyntaxKind::ConstrainedSyntax,
            SyntaxKind::Constraint,
            SyntaxKind::Range,
            SyntaxKind::NamedNumber,
            SyntaxKind::SequenceOfSyntax,
            SyntaxKind::SequenceSyntax,
            SyntaxKind::SequenceField,
            SyntaxKind::ChoiceSyntax,
            SyntaxKind::TaggedSyntax,
            SyntaxKind::OctetStringSyntax,
            SyntaxKind::ObjectIdentifierSyntax,
        ];

        let valid = br#"COVERAGE-CST-MIB DEFINITIONS ::= BEGIN
item OBJECT-TYPE
 SYNTAX INTEGER { one(1), two(2) } (0..2)
 UNITS "units"
 MAX-ACCESS read-only
 STATUS current
 DESCRIPTION "description"
 REFERENCE "reference"
 INDEX { IMPLIED index }
 DEFVAL { one }
 ::= { ROOT-MIB.root(1) 1 }
augmented OBJECT-TYPE
 SYNTAX INTEGER
 MAX-ACCESS read-only
 STATUS current
 DESCRIPTION "augmented"
 AUGMENTS { row }
 ::= { item 2 }
notice NOTIFICATION-TYPE
 OBJECTS { item }
 STATUS current
 DESCRIPTION "notice"
 ::= { item 3 }
noticeGroup NOTIFICATION-GROUP
 NOTIFICATIONS { notice }
 STATUS current
 DESCRIPTION "group"
 ::= { item 4 }
identity MODULE-IDENTITY
 LAST-UPDATED "202608180000Z"
 ORGANIZATION "org"
 CONTACT-INFO "contact"
 DESCRIPTION "identity"
 REVISION "202608180000Z"
 DESCRIPTION "revision"
 ::= { item 5 }
trap TRAP-TYPE
 ENTERPRISE item
 VARIABLES { item }
 DESCRIPTION "trap"
 ::= 1
Text ::= TEXTUAL-CONVENTION
 DISPLAY-HINT "d"
 STATUS current
 DESCRIPTION "text"
 SYNTAX BITS { flag(0) }
caps AGENT-CAPABILITIES
 PRODUCT-RELEASE "release"
 STATUS current
 DESCRIPTION "caps"
 ::= { item 4 }
Rows ::= SEQUENCE OF Row
Row ::= SEQUENCE { field OCTET STRING }
Union ::= CHOICE { alternative INTEGER }
Tagged ::= [APPLICATION 4] IMPLICIT OCTET STRING
OidType ::= OBJECT IDENTIFIER
Plain ::= INTEGER
END"#;

        let recovered = b"COVERAGE-CST-MIB DEFINITIONS ::= BEGIN\nitem OBJECT-TYPE\n SYNTAX\n UNITS\n MAX-ACCESS\n STATUS\n DESCRIPTION\n REFERENCE\n INDEX { IMPLIED }\n AUGMENTS { one, two }\n DEFVAL { @\n }\n ::= { root() }\nnotice NOTIFICATION-TYPE\n OBJECTS { item, @\n }\n NOTIFICATIONS { @\n }\n STATUS current\n DESCRIPTION \"notice\"\n ::= { item 2 }\nidentity MODULE-IDENTITY\n LAST-UPDATED\n ORGANIZATION\n CONTACT-INFO\n REVISION\n DESCRIPTION\n ::= { item 3 }\ntrap TRAP-TYPE\n ENTERPRISE\n VARIABLES { @\n }\n DESCRIPTION \"trap\"\n ::= 1\nText ::= TEXTUAL-CONVENTION\n DISPLAY-HINT\n STATUS current\n DESCRIPTION \"text\"\n SYNTAX BITS { flag(x) }\ncaps AGENT-CAPABILITIES\n PRODUCT-RELEASE\n STATUS current\n DESCRIPTION \"caps\"\n ::= { item 4 }\nBadEnum ::= INTEGER { one() }\nBadRange ::= INTEGER (0..\nBadRows ::= SEQUENCE OF\nBadRow ::= SEQUENCE { field\nBadChoice ::= CHOICE { alternative\nBadTag ::= [APPLICATION ] IMPLICIT\nBadOctets ::= OCTET\nBadOidType ::= OBJECT\nAfter ::= INTEGER\nEND";

        for (name, input, should_recover) in [
            ("valid", valid.as_slice(), false),
            ("recovered", recovered.as_slice(), true),
        ] {
            with_document(input, |document| {
                let (tree, diagnostics) = build(document);
                assert_eq!(
                    !diagnostics.is_empty(),
                    should_recover,
                    "case={name}: {diagnostics:#?}"
                );
                for kind in CST04_KINDS {
                    assert!(
                        tree.nodes().any(|node| node.kind() == *kind),
                        "case={name}: missing {kind:?}"
                    );
                }
                if should_recover {
                    assert!(tree.nodes().any(|node| node.kind() == SyntaxKind::Error));
                    assert!(
                        tree.nodes()
                            .find_map(SyntaxClause::cast)
                            .unwrap()
                            .type_syntax()
                            .is_none()
                    );
                    assert!(
                        tree.nodes()
                            .find_map(SequenceOfSyntax::cast)
                            .unwrap()
                            .entry_type()
                            .is_none()
                    );
                    assert!(
                        tree.nodes()
                            .find_map(TaggedSyntax::cast)
                            .unwrap()
                            .inner()
                            .is_none()
                    );
                } else {
                    assert!(
                        tree.nodes()
                            .find_map(SyntaxClause::cast)
                            .unwrap()
                            .keyword()
                            .is_some()
                    );
                    assert!(
                        tree.nodes()
                            .find_map(ConstrainedSyntax::cast)
                            .unwrap()
                            .base()
                            .is_some()
                    );
                    assert!(
                        tree.nodes()
                            .find_map(SequenceSyntax::cast)
                            .unwrap()
                            .fields()
                            .next()
                            .unwrap()
                            .type_syntax()
                            .is_some()
                    );
                    assert!(
                        tree.nodes()
                            .find_map(OidAssignment::cast)
                            .unwrap()
                            .components()
                            .all(|component| component.recovery_regions().next().is_none())
                    );
                }
                assert_eq!(tree.reconstruct_text(), input, "case={name}");
            });
        }
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
    fn conformance_and_capability_definitions_expose_nested_source_order_and_ranges() {
        let input = br#"CST06-MIB DEFINITIONS ::= BEGIN
objectGroup OBJECT-GROUP
 OBJECTS { firstObject, secondObject }
 STATUS current
 DESCRIPTION "objects"
 REFERENCE "object reference"
 ::= { root 1 }
notificationGroup NOTIFICATION-GROUP
 NOTIFICATIONS { firstNotification, secondNotification }
 STATUS current
 DESCRIPTION "notifications"
 ::= { root 2 }
compliance MODULE-COMPLIANCE
 STATUS current
 DESCRIPTION "compliance"
 MODULE FIRST-MIB { firstRoot 1 }
  MANDATORY-GROUPS { objectGroup, notificationGroup }
  GROUP objectGroup DESCRIPTION "conditional"
  OBJECT firstObject
   SYNTAX INTEGER (0..10)
   WRITE-SYNTAX INTEGER (1..9)
   MIN-ACCESS read-only
   DESCRIPTION "refined"
 MODULE
  MANDATORY-GROUPS { notificationGroup }
 ::= { root 3 }
capabilities AGENT-CAPABILITIES
 PRODUCT-RELEASE "release"
 STATUS current
 DESCRIPTION "capabilities"
 SUPPORTS FIRST-MIB { firstRoot 1 }
  INCLUDES { objectGroup, notificationGroup }
  VARIATION firstObject
   SYNTAX INTEGER (0..8)
   WRITE-SYNTAX INTEGER (1..7)
   ACCESS read-only
   CREATION-REQUIRES { firstObject, secondObject }
   DEFVAL { 1 }
   DESCRIPTION "object variation"
  VARIATION firstNotification
   ACCESS not-implemented
   DESCRIPTION "notification variation"
 ::= { root 4 }
END"#;
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(diagnostics.is_empty(), "{diagnostics:#?}");
            let definitions = tree.source_file().definitions().collect::<Vec<_>>();
            assert_eq!(definitions.len(), 4);

            let Definition::ObjectGroup(group) = definitions[0] else {
                panic!("expected OBJECT-GROUP")
            };
            let objects = group.objects().unwrap().names().collect::<Vec<_>>();
            assert_eq!(
                objects.iter().map(|name| name.text()).collect::<Vec<_>>(),
                [b"firstObject".as_slice(), b"secondObject".as_slice()]
            );
            assert_eq!(objects[0].range().byte_range(), 68..79);

            let Definition::NotificationGroup(group) = definitions[1] else {
                panic!("expected NOTIFICATION-GROUP")
            };
            assert_eq!(group.notifications().unwrap().names().count(), 2);

            let Definition::ModuleCompliance(compliance) = definitions[2] else {
                panic!("expected MODULE-COMPLIANCE")
            };
            let modules = compliance.modules().collect::<Vec<_>>();
            assert_eq!(modules.len(), 2);
            assert_eq!(modules[0].module_name().unwrap().text(), b"FIRST-MIB");
            assert!(modules[0].oid().is_some());
            assert_eq!(modules[0].mandatory_groups().unwrap().names().count(), 2);
            assert!(matches!(
                modules[0].refinements().next(),
                Some(ComplianceRefinement::Group(_))
            ));
            assert!(matches!(
                modules[0].refinements().nth(1),
                Some(ComplianceRefinement::Object(_))
            ));
            let object = modules[0].objects().next().unwrap();
            assert_eq!(object.object().unwrap().text(), b"firstObject");
            assert_eq!(
                object.min_access().unwrap().keyword().unwrap().kind(),
                SyntaxKind::KwMinAccess
            );
            assert!(object.write_syntax().unwrap().type_syntax().is_some());

            let Definition::AgentCapabilities(capabilities) = definitions[3] else {
                panic!("expected AGENT-CAPABILITIES")
            };
            let supports = capabilities.supports().next().unwrap();
            assert_eq!(supports.module_name().unwrap().text(), b"FIRST-MIB");
            assert_eq!(supports.includes().unwrap().names().count(), 2);
            let variations = supports.variations().collect::<Vec<_>>();
            assert_eq!(variations.len(), 2);
            assert_eq!(variations[0].target().unwrap().text(), b"firstObject");
            assert_eq!(
                variations[0].access().unwrap().keyword().unwrap().kind(),
                SyntaxKind::KwAccess
            );
            assert_eq!(
                variations[0].creation_requires().unwrap().names().count(),
                2
            );
            assert!(variations[0].defval().is_some());
            assert_eq!(variations[1].target().unwrap().text(), b"firstNotification");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn representative_conformance_and_capability_corpora_round_trip() {
        for (name, input, expected_kind) in [
            (
                "IF-MIB",
                include_bytes!("../../testdata/corpus/primary/ietf/IF-MIB.mib").as_slice(),
                SyntaxKind::ModuleComplianceDefinition,
            ),
            (
                "JNX-SNMPv2-CAPABILITY",
                include_bytes!("../../testdata/corpus/primary/juniper/JNX-SNMPv2-CAPABILITY.mib")
                    .as_slice(),
                SyntaxKind::AgentCapabilitiesDefinition,
            ),
        ] {
            with_document(input, |document| {
                let (tree, _) = build(document);
                assert!(
                    tree.source_file()
                        .definitions()
                        .any(|definition| definition.syntax().kind() == expected_kind),
                    "{name}"
                );
                assert_eq!(tree.reconstruct_text(), input, "{name}");
            });
        }
    }

    #[test]
    fn truncated_cst06_families_are_one_partial_error_and_continue() {
        let cases: &[(&str, &[u8], SyntaxKind)] = &[
            ("object group", b"broken OBJECT-GROUP\n OBJECTS { first, second", SyntaxKind::ObjectGroupDefinition),
            ("notification group", b"broken NOTIFICATION-GROUP\n NOTIFICATIONS { first, second", SyntaxKind::NotificationGroupDefinition),
            ("module compliance", b"broken MODULE-COMPLIANCE\n STATUS current\n DESCRIPTION \"x\"\n MODULE TEST-MIB\n MANDATORY-GROUPS { group", SyntaxKind::ModuleComplianceDefinition),
            ("agent capabilities", b"broken AGENT-CAPABILITIES\n PRODUCT-RELEASE \"x\"\n STATUS current\n DESCRIPTION \"x\"\n SUPPORTS TEST-MIB\n INCLUDES { group\n VARIATION object\n CREATION-REQUIRES { column", SyntaxKind::AgentCapabilitiesDefinition),
        ];
        for &(name, broken, descendant_kind) in cases {
            let mut source = b"RECOVERY-MIB DEFINITIONS ::= BEGIN\n".to_vec();
            source.extend_from_slice(broken);
            source.extend_from_slice(b"\nAfter ::= INTEGER\nEND");
            with_document(&source, |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty(), "{name}");
                let definitions = tree.source_file().definitions().collect::<Vec<_>>();
                assert_eq!(definitions.len(), 2, "{name}");
                let Definition::Error(error) = definitions[0] else {
                    panic!("{name}: expected one definition error")
                };
                let descendants = error
                    .syntax()
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .collect::<Vec<_>>();
                assert_eq!(descendants.len(), 1, "{name}");
                assert_eq!(descendants[0].kind(), descendant_kind, "{name}");
                assert!(
                    matches!(definitions[1], Definition::TypeAssignment(_)),
                    "{name}"
                );
                assert_eq!(tree.reconstruct_text(), source, "{name}");
            });
        }
    }

    #[test]
    fn malformed_cst06_nested_structures_retain_typed_descendants_and_continue() {
        let cases: &[(&str, &[u8], SyntaxKind)] = &[
            (
                "OBJECTS member",
                br#"broken OBJECT-GROUP OBJECTS { first, @ } STATUS current DESCRIPTION "x" ::= { root 1 }"#,
                SyntaxKind::ObjectsClause,
            ),
            (
                "NOTIFICATIONS member",
                br#"broken NOTIFICATION-GROUP NOTIFICATIONS { first, @ } STATUS current DESCRIPTION "x" ::= { root 1 }"#,
                SyntaxKind::NotificationsClause,
            ),
            (
                "compliance module OID",
                br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE TEST-MIB { root @ } MANDATORY-GROUPS { group } ::= { root 1 }"#,
                SyntaxKind::ComplianceModule,
            ),
            (
                "mandatory group",
                br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE MANDATORY-GROUPS { group, @ } ::= { root 1 }"#,
                SyntaxKind::MandatoryGroupsClause,
            ),
            (
                "compliance group",
                br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE GROUP @ DESCRIPTION "group" ::= { root 1 }"#,
                SyntaxKind::ComplianceGroup,
            ),
            (
                "compliance object access",
                br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE OBJECT item MIN-ACCESS current DESCRIPTION "item" ::= { root 1 }"#,
                SyntaxKind::ComplianceObject,
            ),
            (
                "supports module",
                br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS @ INCLUDES { group } ::= { root 1 }"#,
                SyntaxKind::SupportsModule,
            ),
            (
                "includes group",
                br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group, @ } ::= { root 1 }"#,
                SyntaxKind::IncludesClause,
            ),
            (
                "variation write syntax",
                br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group } VARIATION item WRITE-SYNTAX @ DESCRIPTION "item" ::= { root 1 }"#,
                SyntaxKind::VariationClause,
            ),
            (
                "creation requirement",
                br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group } VARIATION item CREATION-REQUIRES { column, @ } DESCRIPTION "item" ::= { root 1 }"#,
                SyntaxKind::CreationRequiresClause,
            ),
            (
                "variation access status value",
                br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group } VARIATION item ACCESS current DESCRIPTION "item" ::= { root 1 }"#,
                SyntaxKind::AccessClause,
            ),
        ];
        for &(name, broken, descendant_kind) in cases {
            let mut source = b"MALFORMED-MIB DEFINITIONS ::= BEGIN\n".to_vec();
            source.extend_from_slice(broken);
            source.extend_from_slice(b"\nAfter ::= INTEGER\nEND");
            with_document(&source, |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty(), "{name}");
                let definitions = tree.source_file().definitions().collect::<Vec<_>>();
                assert!(
                    matches!(
                        definitions.as_slice(),
                        [Definition::Error(_), Definition::TypeAssignment(_)]
                    ),
                    "{name}: {definitions:#?}"
                );
                assert!(
                    definitions[0]
                        .syntax()
                        .descendant_nodes()
                        .any(|node| node.kind() == descendant_kind),
                    "{name}: missing {descendant_kind:?}"
                );
                assert_eq!(tree.reconstruct_text(), source, "{name}");
            });
        }
    }

    #[test]
    fn repeated_cst06_clauses_recover_without_losing_nested_nodes() {
        let cases: &[(&str, &[u8], SyntaxKind)] = &[
            ("object group objects", br#"broken OBJECT-GROUP OBJECTS { item } OBJECTS { other } STATUS current DESCRIPTION "x" ::= { root 1 }"#, SyntaxKind::ObjectsClause),
            ("object group status", br#"broken OBJECT-GROUP OBJECTS { item } STATUS current STATUS obsolete DESCRIPTION "x" ::= { root 1 }"#, SyntaxKind::StatusClause),
            ("notification group notifications", br#"broken NOTIFICATION-GROUP NOTIFICATIONS { notice } NOTIFICATIONS { other } STATUS current DESCRIPTION "x" ::= { root 1 }"#, SyntaxKind::NotificationsClause),
            ("notification group description", br#"broken NOTIFICATION-GROUP NOTIFICATIONS { notice } STATUS current DESCRIPTION "x" DESCRIPTION "y" ::= { root 1 }"#, SyntaxKind::DescriptionClause),
            ("mandatory groups", br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE MANDATORY-GROUPS { group } MANDATORY-GROUPS { other } ::= { root 1 }"#, SyntaxKind::MandatoryGroupsClause),
            ("compliance group description", br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE GROUP group DESCRIPTION "x" DESCRIPTION "y" ::= { root 1 }"#, SyntaxKind::DescriptionClause),
            ("compliance object syntax", br#"broken MODULE-COMPLIANCE STATUS current DESCRIPTION "x" MODULE OBJECT item SYNTAX INTEGER SYNTAX INTEGER DESCRIPTION "x" ::= { root 1 }"#, SyntaxKind::SyntaxClause),
            ("includes", br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group } INCLUDES { other } ::= { root 1 }"#, SyntaxKind::IncludesClause),
            ("variation access", br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group } VARIATION item ACCESS read-only ACCESS not-accessible DESCRIPTION "x" ::= { root 1 }"#, SyntaxKind::AccessClause),
            ("variation creation requirements", br#"broken AGENT-CAPABILITIES PRODUCT-RELEASE "x" STATUS current DESCRIPTION "x" SUPPORTS TEST-MIB INCLUDES { group } VARIATION item CREATION-REQUIRES { column } CREATION-REQUIRES { other } DESCRIPTION "x" ::= { root 1 }"#, SyntaxKind::CreationRequiresClause),
        ];
        for &(name, broken, repeated_kind) in cases {
            let mut source = b"REPEATED-MIB DEFINITIONS ::= BEGIN\n".to_vec();
            source.extend_from_slice(broken);
            source.extend_from_slice(b"\nAfter ::= INTEGER\nEND");
            with_document(&source, |document| {
                let (tree, diagnostics) = build(document);
                assert!(!diagnostics.is_empty(), "{name}");
                let definitions = tree.source_file().definitions().collect::<Vec<_>>();
                assert!(
                    matches!(
                        definitions.as_slice(),
                        [Definition::Error(_), Definition::TypeAssignment(_)]
                    ),
                    "{name}: {definitions:#?}"
                );
                let repeated = definitions[0]
                    .syntax()
                    .descendant_nodes()
                    .filter(|node| node.kind() == repeated_kind)
                    .count();
                assert!(repeated >= 2, "{name}: found {repeated}");
                assert_eq!(tree.reconstruct_text(), source, "{name}");
            });
        }
    }

    #[test]
    fn reordered_outer_lists_are_owned_by_their_sections_not_nested_items() {
        let input = br#"BOUNDARY-MIB DEFINITIONS ::= BEGIN
compliance MODULE-COMPLIANCE
 STATUS current
 DESCRIPTION "compliance"
 MODULE TEST-MIB
  MANDATORY-GROUPS { firstGroup }
  GROUP firstGroup DESCRIPTION "conditional"
  MANDATORY-GROUPS { laterGroup }
 ::= { root 1 }
capabilities AGENT-CAPABILITIES
 PRODUCT-RELEASE "release"
 STATUS current
 DESCRIPTION "capabilities"
 SUPPORTS TEST-MIB
  INCLUDES { firstGroup }
  VARIATION firstObject DESCRIPTION "variation"
  INCLUDES { laterGroup }
 ::= { root 2 }
After ::= INTEGER
END"#;
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let definitions = tree.source_file().definitions().collect::<Vec<_>>();
            assert!(matches!(
                definitions.as_slice(),
                [
                    Definition::Error(_),
                    Definition::Error(_),
                    Definition::TypeAssignment(_)
                ]
            ));

            let Definition::Error(compliance_error) = definitions[0] else {
                unreachable!()
            };
            let compliance = compliance_error
                .syntax()
                .children()
                .filter_map(SyntaxElement::as_node)
                .find_map(ModuleComplianceDefinition::cast)
                .unwrap();
            let module = compliance.modules().next().unwrap();
            let mandatory = module.mandatory_group_clauses().collect::<Vec<_>>();
            assert_eq!(mandatory.len(), 2);
            assert!(
                mandatory[0].syntax().range().byte_range().start
                    < mandatory[1].syntax().range().byte_range().start
            );
            assert_eq!(
                mandatory[1].syntax().text(),
                b"MANDATORY-GROUPS { laterGroup }"
            );
            assert_eq!(
                document.slice(mandatory[1].syntax().range()).unwrap(),
                mandatory[1].syntax().text()
            );
            let group = module.groups().next().unwrap();
            assert!(
                !group
                    .syntax()
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .any(|node| node.kind() == SyntaxKind::MandatoryGroupsClause)
            );
            assert!(
                group.syntax().range().byte_range().end
                    <= mandatory[1].syntax().range().byte_range().start
            );

            let Definition::Error(capabilities_error) = definitions[1] else {
                unreachable!()
            };
            let capabilities = capabilities_error
                .syntax()
                .children()
                .filter_map(SyntaxElement::as_node)
                .find_map(AgentCapabilitiesDefinition::cast)
                .unwrap();
            let supports = capabilities.supports().next().unwrap();
            let includes = supports.includes_clauses().collect::<Vec<_>>();
            assert_eq!(includes.len(), 2);
            assert!(
                includes[0].syntax().range().byte_range().start
                    < includes[1].syntax().range().byte_range().start
            );
            assert_eq!(includes[1].syntax().text(), b"INCLUDES { laterGroup }");
            assert_eq!(
                document.slice(includes[1].syntax().range()).unwrap(),
                includes[1].syntax().text()
            );
            let variation = supports.variations().next().unwrap();
            assert!(
                !variation
                    .syntax()
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .any(|node| node.kind() == SyntaxKind::IncludesClause)
            );
            assert!(
                variation.syntax().range().byte_range().end
                    <= includes[1].syntax().range().byte_range().start
            );

            assert_eq!(definitions[2].name().unwrap().text(), b"After");
            assert_eq!(tree.reconstruct_text(), input);
        });
    }

    #[test]
    fn unambiguous_definition_clauses_escape_nested_cst06_sections() {
        let input = br#"OUTER-BOUNDARY-MIB DEFINITIONS ::= BEGIN
compliance MODULE-COMPLIANCE
 STATUS current
 DESCRIPTION "compliance"
 MODULE
  GROUP firstGroup DESCRIPTION "conditional"
 STATUS obsolete
 REFERENCE "late compliance reference"
 ::= { root 1 }
capabilities AGENT-CAPABILITIES
 PRODUCT-RELEASE "release"
 STATUS current
 DESCRIPTION "capabilities"
 SUPPORTS TEST-MIB
  INCLUDES { firstGroup }
  VARIATION firstObject DESCRIPTION "variation"
 PRODUCT-RELEASE "late release"
 STATUS obsolete
 REFERENCE "late capabilities reference"
 ::= { root 2 }
After ::= INTEGER
END"#;
        with_document(input, |document| {
            let (tree, diagnostics) = build(document);
            assert!(!diagnostics.is_empty());
            let definitions = tree.source_file().definitions().collect::<Vec<_>>();
            assert!(matches!(
                definitions.as_slice(),
                [
                    Definition::Error(_),
                    Definition::Error(_),
                    Definition::TypeAssignment(_)
                ]
            ));

            let definition_nodes = definitions[..2]
                .iter()
                .map(|definition| {
                    definition
                        .syntax()
                        .children()
                        .filter_map(SyntaxElement::as_node)
                        .next()
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let compliance = ModuleComplianceDefinition::cast(definition_nodes[0]).unwrap();
            let module = compliance.modules().next().unwrap();
            assert_eq!(
                definition_nodes[0]
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .filter(|node| node.kind() == SyntaxKind::StatusClause)
                    .count(),
                2
            );
            assert_eq!(
                definition_nodes[0]
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .filter(|node| node.kind() == SyntaxKind::ReferenceClause)
                    .count(),
                1
            );
            assert!(!module.syntax().descendant_nodes().any(|node| {
                matches!(
                    node.kind(),
                    SyntaxKind::StatusClause | SyntaxKind::ReferenceClause
                )
            }));

            let capabilities = AgentCapabilitiesDefinition::cast(definition_nodes[1]).unwrap();
            let supports = capabilities.supports().next().unwrap();
            assert_eq!(
                definition_nodes[1]
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .filter(|node| node.kind() == SyntaxKind::ProductReleaseClause)
                    .count(),
                2
            );
            assert_eq!(
                definition_nodes[1]
                    .children()
                    .filter_map(SyntaxElement::as_node)
                    .filter(|node| node.kind() == SyntaxKind::StatusClause)
                    .count(),
                2
            );
            assert!(!supports.syntax().descendant_nodes().any(|node| {
                matches!(
                    node.kind(),
                    SyntaxKind::ProductReleaseClause
                        | SyntaxKind::StatusClause
                        | SyntaxKind::ReferenceClause
                )
            }));
            assert_eq!(definitions[2].name().unwrap().text(), b"After");
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
