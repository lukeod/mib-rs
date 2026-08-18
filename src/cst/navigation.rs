//! Source-position navigation over a lossless concrete syntax tree.

use super::{
    CstNode, Definition, ElementData, ErrorRegion, ImportGroup, Imports, Module, OidAssignment,
    SyntaxKind, SyntaxNode, SyntaxToken, SyntaxTree, UnparsedRegion,
};
use crate::source::ByteOffset;

/// The syntactic clause containing a cursor.
///
/// This includes ordinary definition clauses and the nested section clauses
/// used by `MODULE-COMPLIANCE` and `AGENT-CAPABILITIES`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClauseKind {
    /// `SYNTAX` clause.
    Syntax,
    /// `WRITE-SYNTAX` clause.
    WriteSyntax,
    /// `ACCESS`, `MAX-ACCESS`, or `MIN-ACCESS` clause.
    Access,
    /// `STATUS` clause.
    Status,
    /// `DESCRIPTION` clause.
    Description,
    /// `REFERENCE` clause.
    Reference,
    /// `UNITS` clause.
    Units,
    /// `DISPLAY-HINT` clause.
    DisplayHint,
    /// `INDEX` clause.
    Index,
    /// `AUGMENTS` clause.
    Augments,
    /// `DEFVAL` clause.
    Defval,
    /// `OBJECTS` clause.
    Objects,
    /// `NOTIFICATIONS` clause.
    Notifications,
    /// `REVISION` clause.
    Revision,
    /// `LAST-UPDATED` clause.
    LastUpdated,
    /// `ORGANIZATION` clause.
    Organization,
    /// `CONTACT-INFO` clause.
    ContactInfo,
    /// `ENTERPRISE` clause.
    Enterprise,
    /// `VARIABLES` clause.
    Variables,
    /// `PRODUCT-RELEASE` clause.
    ProductRelease,
    /// Nested `MODULE` compliance section.
    ComplianceModule,
    /// `MANDATORY-GROUPS` clause.
    MandatoryGroups,
    /// Nested `GROUP` compliance refinement.
    ComplianceGroup,
    /// Nested `OBJECT` compliance refinement.
    ComplianceObject,
    /// Nested `SUPPORTS` capability section.
    SupportsModule,
    /// `INCLUDES` clause.
    Includes,
    /// Nested `VARIATION` clause.
    Variation,
    /// `CREATION-REQUIRES` clause.
    CreationRequires,
}

impl ClauseKind {
    fn from_syntax(kind: SyntaxKind) -> Option<Self> {
        Some(match kind {
            SyntaxKind::SyntaxClause => Self::Syntax,
            SyntaxKind::WriteSyntaxClause => Self::WriteSyntax,
            SyntaxKind::AccessClause => Self::Access,
            SyntaxKind::StatusClause => Self::Status,
            SyntaxKind::DescriptionClause => Self::Description,
            SyntaxKind::ReferenceClause => Self::Reference,
            SyntaxKind::UnitsClause => Self::Units,
            SyntaxKind::DisplayHintClause => Self::DisplayHint,
            SyntaxKind::IndexClause => Self::Index,
            SyntaxKind::AugmentsClause => Self::Augments,
            SyntaxKind::DefvalClause => Self::Defval,
            SyntaxKind::ObjectsClause => Self::Objects,
            SyntaxKind::NotificationsClause => Self::Notifications,
            SyntaxKind::RevisionClause => Self::Revision,
            SyntaxKind::LastUpdatedClause => Self::LastUpdated,
            SyntaxKind::OrganizationClause => Self::Organization,
            SyntaxKind::ContactInfoClause => Self::ContactInfo,
            SyntaxKind::EnterpriseClause => Self::Enterprise,
            SyntaxKind::VariablesClause => Self::Variables,
            SyntaxKind::ProductReleaseClause => Self::ProductRelease,
            SyntaxKind::ComplianceModule => Self::ComplianceModule,
            SyntaxKind::MandatoryGroupsClause => Self::MandatoryGroups,
            SyntaxKind::ComplianceGroup => Self::ComplianceGroup,
            SyntaxKind::ComplianceObject => Self::ComplianceObject,
            SyntaxKind::SupportsModule => Self::SupportsModule,
            SyntaxKind::IncludesClause => Self::Includes,
            SyntaxKind::VariationClause => Self::Variation,
            SyntaxKind::CreationRequiresClause => Self::CreationRequires,
            _ => return None,
        })
    }
}

/// A clause and its exact CST node.
#[derive(Clone, Copy, Debug)]
pub struct CursorClause<'tree, 'src> {
    kind: ClauseKind,
    syntax: SyntaxNode<'tree, 'src>,
}

impl<'tree, 'src> CursorClause<'tree, 'src> {
    /// Return the clause's semantic kind.
    pub fn kind(self) -> ClauseKind {
        self.kind
    }

    /// Return the clause's exact syntax node.
    pub fn syntax(self) -> SyntaxNode<'tree, 'src> {
        self.syntax
    }
}

/// Syntactic context at one valid byte offset in a [`SyntaxTree`].
///
/// All non-empty ranges use half-open containment. A node is selected at its
/// start but not at its exclusive end, so an exact boundary belongs to the
/// construct beginning there. Whitespace and other trivia between constructs
/// do not inherit the preceding construct. At the document end, [`Self::token`]
/// is the zero-length EOF token and [`Self::innermost_node`] is the source-file
/// root; no preceding module or definition is selected.
///
/// Node descent is source ordered. Nested nodes take precedence over their
/// ancestors, including when their ranges are equal. Sibling elements have
/// ordered, non-overlapping ranges by CST construction. The containing
/// top-level definition is captured before descent, so a [`Definition::Error`]
/// remains visible even when its recovered recognized definition or a nested
/// clause is the innermost node.
///
/// The query uses [`SyntaxTree::token_at`] (`O(log t)` for `t` tokens), then
/// performs a binary search among the immediate children on each level of the
/// containing branch (`O(log t + sum(log c))` for child counts `c` along that
/// branch). It does not walk unrelated descendants.
#[derive(Clone, Copy, Debug)]
pub struct CursorContext<'tree, 'src> {
    token: SyntaxToken<'tree, 'src>,
    innermost_node: SyntaxNode<'tree, 'src>,
    module: Option<Module<'tree, 'src>>,
    definition: Option<Definition<'tree, 'src>>,
    imports: Option<Imports<'tree, 'src>>,
    import_group: Option<ImportGroup<'tree, 'src>>,
    oid: Option<OidAssignment<'tree, 'src>>,
    clause: Option<CursorClause<'tree, 'src>>,
    unparsed_region: Option<UnparsedRegion<'tree, 'src>>,
    error: Option<ErrorRegion<'tree, 'src>>,
}

impl<'tree, 'src> CursorContext<'tree, 'src> {
    /// Return the lossless token selected at the cursor, including trivia and EOF.
    pub fn token(self) -> SyntaxToken<'tree, 'src> {
        self.token
    }

    /// Return the deepest syntax node containing the cursor.
    pub fn innermost_node(self) -> SyntaxNode<'tree, 'src> {
        self.innermost_node
    }

    /// Return the containing module, if any.
    pub fn module(self) -> Option<Module<'tree, 'src>> {
        self.module
    }

    /// Return the containing top-level definition, including recovered definitions.
    pub fn definition(self) -> Option<Definition<'tree, 'src>> {
        self.definition
    }

    /// Return the containing `IMPORTS` section, if any.
    pub fn imports(self) -> Option<Imports<'tree, 'src>> {
        self.imports
    }

    /// Return the containing import group, if any.
    pub fn import_group(self) -> Option<ImportGroup<'tree, 'src>> {
        self.import_group
    }

    /// Return the innermost containing OID value, if any.
    pub fn oid(self) -> Option<OidAssignment<'tree, 'src>> {
        self.oid
    }

    /// Return the innermost containing common or nested clause, if any.
    pub fn clause(self) -> Option<CursorClause<'tree, 'src>> {
        self.clause
    }

    /// Return the containing module-body region, if any.
    pub fn unparsed_region(self) -> Option<UnparsedRegion<'tree, 'src>> {
        self.unparsed_region
    }

    /// Return the innermost containing error recovery node, if any.
    pub fn error(self) -> Option<ErrorRegion<'tree, 'src>> {
        self.error
    }

    /// Return whether the cursor token is a comment.
    pub fn in_comment(self) -> bool {
        self.token.kind() == SyntaxKind::Comment
    }

    /// Return whether the cursor token is a quoted, hexadecimal, or binary string.
    pub fn in_string(self) -> bool {
        matches!(
            self.token.kind(),
            SyntaxKind::QuotedString | SyntaxKind::HexString | SyntaxKind::BinString
        )
    }
}

pub(super) fn cursor_context(
    tree: &SyntaxTree,
    offset: ByteOffset,
) -> Option<CursorContext<'_, '_>> {
    let token = tree.token_at(offset)?;
    let root = tree.root();
    let mut context = CursorContext {
        token,
        innermost_node: root,
        module: None,
        definition: None,
        imports: None,
        import_group: None,
        oid: None,
        clause: None,
        unparsed_region: None,
        error: None,
    };

    // EOF is a valid cursor coordinate, but half-open descendants do not own it.
    if token.kind() == SyntaxKind::EofToken {
        return Some(context);
    }

    let mut node = root;
    loop {
        update_context(&mut context, node);
        let Some(child) = containing_child(node, offset) else {
            break;
        };
        node = child;
        context.innermost_node = node;
    }
    Some(context)
}

fn update_context<'tree, 'src>(
    context: &mut CursorContext<'tree, 'src>,
    node: SyntaxNode<'tree, 'src>,
) {
    if let Some(module) = Module::cast(node) {
        context.module = Some(module);
    }
    if context.definition.is_none()
        && let Some(definition) = Definition::cast(node)
    {
        context.definition = Some(definition);
    }
    if let Some(imports) = Imports::cast(node) {
        context.imports = Some(imports);
    }
    if let Some(group) = ImportGroup::cast(node) {
        context.import_group = Some(group);
    }
    if let Some(oid) = OidAssignment::cast(node) {
        context.oid = Some(oid);
    }
    if let Some(kind) = ClauseKind::from_syntax(node.kind()) {
        context.clause = Some(CursorClause { kind, syntax: node });
    }
    if let Some(region) = UnparsedRegion::cast(node) {
        context.unparsed_region = Some(region);
    }
    if let Some(error) = ErrorRegion::cast(node) {
        context.error = Some(error);
    }
}

fn containing_child<'tree, 'src>(
    node: SyntaxNode<'tree, 'src>,
    offset: ByteOffset,
) -> Option<SyntaxNode<'tree, 'src>> {
    let index = node
        .data
        .children
        .partition_point(|child| {
            let start = match child {
                ElementData::Node(child) => child.range.start(),
                ElementData::Token(child) => child.range.start(),
            };
            start <= offset
        })
        .checked_sub(1)?;
    let ElementData::Node(child) = &node.data.children[index] else {
        return None;
    };
    (offset < child.range.end()).then(|| SyntaxNode::new(child, node.document))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::cst::parse;
    use crate::source::{SourceCandidate, SourceOrigin};

    const SOURCE: &[u8] = br#"EXAMPLE-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, Integer32 FROM SNMPv2-SMI
    DisplayString FROM SNMPv2-TC;

exampleMIB MODULE-IDENTITY
    LAST-UPDATED "200601010000Z"
    ORGANIZATION "Example Inc."
    CONTACT-INFO "support@example.com"
    DESCRIPTION "An example MIB."
    ::= { enterprises 99999 }

exampleString OBJECT-TYPE
    SYNTAX DisplayString (SIZE (0..255))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "An example string object."
    ::= { exampleMIB 1 }

-- a trailing comment
END
"#;

    const COMMON_CLAUSE_SOURCE: &[u8] = br#"CLAUSE-MIB DEFINITIONS ::= BEGIN
item OBJECT-TYPE
    SYNTAX INTEGER (0..10)
    UNITS "widgets"
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "description"
    REFERENCE "reference"
    INDEX { IMPLIED indexObject, OCTET STRING }
    DEFVAL { enabled }
    ::= { root 1 }
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
    ::= { item 6 }
END"#;

    const NESTED_CLAUSE_SOURCE: &[u8] = br#"NESTED-MIB DEFINITIONS ::= BEGIN
comp MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "compliance"
    MODULE OTHER-MIB { iso 3 }
        MANDATORY-GROUPS { group }
        GROUP group DESCRIPTION "conditional"
        OBJECT object
            SYNTAX INTEGER
            MIN-ACCESS read-only
            DESCRIPTION "refined"
    ::= { iso 10 }
cap AGENT-CAPABILITIES
    PRODUCT-RELEASE "release"
    STATUS current
    DESCRIPTION "capability"
    SUPPORTS OTHER-MIB { iso 4 }
        INCLUDES { group }
        VARIATION object
            SYNTAX INTEGER
            WRITE-SYNTAX INTEGER
            ACCESS read-only
            CREATION-REQUIRES { object }
            DESCRIPTION "variation"
    ::= { iso 11 }
END"#;

    fn tree(source: &[u8]) -> SyntaxTree {
        parse(SourceCandidate::new(
            "cursor-test",
            SourceOrigin::memory("cursor-test"),
            "cursor-test",
            Arc::<[u8]>::from(source),
        ))
        .unwrap()
        .0
    }

    fn at(source: &[u8], needle: &[u8]) -> ByteOffset {
        ByteOffset::try_from(
            source
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("test needle must occur"),
        )
        .unwrap()
    }

    fn nth(source: &[u8], needle: &[u8], occurrence: usize) -> ByteOffset {
        let index = source
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle)
            .nth(occurrence)
            .expect("test needle occurrence must exist")
            .0;
        ByteOffset::try_from(index).unwrap()
    }

    fn at_after(source: &[u8], anchor: &[u8], needle: &[u8]) -> ByteOffset {
        let anchor = at(source, anchor).as_usize();
        let relative = source[anchor..]
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("test needle must occur after anchor");
        ByteOffset::try_from(anchor + relative).unwrap()
    }

    fn assert_clause(
        tree: &SyntaxTree,
        source: &[u8],
        anchor: &[u8],
        needle: &[u8],
        expected: ClauseKind,
        syntax_kind: SyntaxKind,
    ) {
        let clause = tree
            .cursor_context(at_after(source, anchor, needle))
            .unwrap()
            .clause()
            .unwrap();
        assert_eq!(
            clause.kind(),
            expected,
            "anchor={anchor:?}, needle={needle:?}"
        );
        assert_eq!(
            clause.syntax().kind(),
            syntax_kind,
            "anchor={anchor:?}, needle={needle:?}"
        );
    }

    #[test]
    fn reports_module_import_definition_oid_clause_and_token_context() {
        let tree = tree(SOURCE);

        let name = tree.cursor_context(at(SOURCE, b"EXAMPLE-MIB")).unwrap();
        assert!(name.module().is_some());
        assert!(name.definition().is_none());
        assert!(name.imports().is_none());

        let import_symbol = tree
            .cursor_context(at(SOURCE, b"MODULE-IDENTITY,"))
            .unwrap();
        assert!(import_symbol.module().is_some());
        assert!(import_symbol.imports().is_some());
        assert!(import_symbol.import_group().is_some());
        assert!(import_symbol.definition().is_none());

        let definition = tree.cursor_context(at(SOURCE, b"OBJECT-TYPE")).unwrap();
        assert!(matches!(
            definition.definition(),
            Some(Definition::ObjectType(_))
        ));
        assert!(definition.imports().is_none());
        assert!(definition.clause().is_none());

        let syntax = tree
            .cursor_context(nth(SOURCE, b"DisplayString", 1))
            .unwrap();
        assert_eq!(syntax.clause().unwrap().kind(), ClauseKind::Syntax);
        assert!(syntax.oid().is_none());

        let access = tree.cursor_context(at(SOURCE, b"read-only")).unwrap();
        assert_eq!(access.clause().unwrap().kind(), ClauseKind::Access);
        let status = tree.cursor_context(at(SOURCE, b"current")).unwrap();
        assert_eq!(status.clause().unwrap().kind(), ClauseKind::Status);

        let description = tree
            .cursor_context(at(SOURCE, b"An example string object."))
            .unwrap();
        assert_eq!(
            description.clause().unwrap().kind(),
            ClauseKind::Description
        );
        assert!(description.in_string());
        assert!(!description.in_comment());

        let oid = tree.cursor_context(at(SOURCE, b"enterprises")).unwrap();
        assert!(oid.oid().is_some());
        assert!(matches!(
            oid.definition(),
            Some(Definition::ModuleIdentity(_))
        ));

        let comment = tree
            .cursor_context(at(SOURCE, b"a trailing comment"))
            .unwrap();
        assert!(comment.in_comment());
        assert!(!comment.in_string());
        assert!(comment.module().is_some());
        assert!(comment.definition().is_none());
    }

    #[test]
    fn exact_boundaries_are_half_open_and_eof_is_explicit() {
        let tree = tree(SOURCE);
        let module = tree.source_file().modules().next().unwrap().syntax();
        let imports = tree
            .source_file()
            .modules()
            .next()
            .unwrap()
            .imports()
            .unwrap()
            .syntax();
        let group = tree
            .source_file()
            .modules()
            .next()
            .unwrap()
            .imports()
            .unwrap()
            .groups()
            .next()
            .unwrap()
            .syntax();
        let definition = tree
            .source_file()
            .modules()
            .next()
            .unwrap()
            .definitions()
            .next()
            .unwrap()
            .syntax();
        let oid = definition
            .descendant_nodes()
            .find_map(OidAssignment::cast)
            .unwrap()
            .syntax();
        let description = definition
            .descendant_nodes()
            .find(|node| node.kind() == SyntaxKind::DescriptionClause)
            .unwrap();

        assert!(
            tree.cursor_context(module.range().start())
                .unwrap()
                .module()
                .is_some()
        );
        assert!(
            tree.cursor_context(module.range().end())
                .unwrap()
                .module()
                .is_none()
        );
        assert!(
            tree.cursor_context(imports.range().start())
                .unwrap()
                .imports()
                .is_some()
        );
        assert!(
            tree.cursor_context(imports.range().end())
                .unwrap()
                .imports()
                .is_none()
        );
        assert!(
            tree.cursor_context(group.range().start())
                .unwrap()
                .import_group()
                .is_some()
        );
        assert!(
            tree.cursor_context(group.range().end())
                .unwrap()
                .import_group()
                .is_none()
        );
        assert!(
            tree.cursor_context(definition.range().start())
                .unwrap()
                .definition()
                .is_some()
        );
        assert!(
            tree.cursor_context(definition.range().end())
                .unwrap()
                .definition()
                .is_none()
        );
        assert!(
            tree.cursor_context(oid.range().start())
                .unwrap()
                .oid()
                .is_some()
        );
        assert!(
            tree.cursor_context(oid.range().end())
                .unwrap()
                .oid()
                .is_none()
        );
        assert_eq!(
            tree.cursor_context(description.range().start())
                .unwrap()
                .clause()
                .unwrap()
                .kind(),
            ClauseKind::Description
        );
        assert!(
            tree.cursor_context(description.range().end())
                .unwrap()
                .clause()
                .is_none()
        );

        let string = tree
            .tokens()
            .find(|token| token.text() == b"\"An example MIB.\"")
            .unwrap();
        assert!(
            tree.cursor_context(string.range().start())
                .unwrap()
                .in_string()
        );
        assert!(
            !tree
                .cursor_context(string.range().end())
                .unwrap()
                .in_string()
        );
        let comment = tree
            .tokens()
            .find(|token| token.kind() == SyntaxKind::Comment)
            .unwrap();
        assert!(
            tree.cursor_context(comment.range().start())
                .unwrap()
                .in_comment()
        );
        assert!(
            !tree
                .cursor_context(comment.range().end())
                .unwrap()
                .in_comment()
        );

        let eof = tree.cursor_context(tree.document().len()).unwrap();
        assert_eq!(eof.token().kind(), SyntaxKind::EofToken);
        assert_eq!(eof.innermost_node().kind(), SyntaxKind::SourceFile);
        assert!(eof.module().is_none());
        assert!(
            tree.cursor_context(ByteOffset::new(tree.document().len().get() + 1))
                .is_none()
        );
    }

    #[test]
    fn trivia_between_definitions_has_only_module_and_body_context() {
        let tree = tree(SOURCE);
        let next = at(SOURCE, b"exampleString OBJECT-TYPE");
        let blank = ByteOffset::new(next.get() - 1);
        let context = tree.cursor_context(blank).unwrap();
        assert!(context.module().is_some());
        assert!(context.unparsed_region().is_some());
        assert!(context.definition().is_none());
        assert!(context.imports().is_none());
        assert!(context.clause().is_none());
        assert_eq!(context.innermost_node().kind(), SyntaxKind::UnparsedRegion);
    }

    #[test]
    fn every_lossless_string_literal_kind_is_string_context() {
        let source = b"STRINGS-MIB DEFINITIONS ::= BEGIN\n\"quoted\" 'ab'H '01'B\nEND";
        let tree = tree(source);
        for needle in [b"\"quoted\"".as_slice(), b"'ab'H", b"'01'B"] {
            let context = tree.cursor_context(at(source, needle)).unwrap();
            assert!(context.in_string(), "{needle:?} should be a string token");
            assert!(!context.in_comment());
        }
    }

    #[test]
    fn every_clause_kind_is_returned_on_a_directly_owned_token() {
        let common = tree(COMMON_CLAUSE_SOURCE);
        for (anchor, needle, expected, syntax_kind) in [
            (
                b"item OBJECT-TYPE".as_slice(),
                b"SYNTAX".as_slice(),
                ClauseKind::Syntax,
                SyntaxKind::SyntaxClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"UNITS".as_slice(),
                ClauseKind::Units,
                SyntaxKind::UnitsClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"MAX-ACCESS".as_slice(),
                ClauseKind::Access,
                SyntaxKind::AccessClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"STATUS".as_slice(),
                ClauseKind::Status,
                SyntaxKind::StatusClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"DESCRIPTION".as_slice(),
                ClauseKind::Description,
                SyntaxKind::DescriptionClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"REFERENCE".as_slice(),
                ClauseKind::Reference,
                SyntaxKind::ReferenceClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"INDEX".as_slice(),
                ClauseKind::Index,
                SyntaxKind::IndexClause,
            ),
            (
                b"item OBJECT-TYPE".as_slice(),
                b"DEFVAL".as_slice(),
                ClauseKind::Defval,
                SyntaxKind::DefvalClause,
            ),
            (
                b"augmented OBJECT-TYPE".as_slice(),
                b"AUGMENTS".as_slice(),
                ClauseKind::Augments,
                SyntaxKind::AugmentsClause,
            ),
            (
                b"notice NOTIFICATION-TYPE".as_slice(),
                b"OBJECTS".as_slice(),
                ClauseKind::Objects,
                SyntaxKind::ObjectsClause,
            ),
            (
                b"noticeGroup NOTIFICATION-GROUP".as_slice(),
                b"NOTIFICATIONS".as_slice(),
                ClauseKind::Notifications,
                SyntaxKind::NotificationsClause,
            ),
            (
                b"identity MODULE-IDENTITY".as_slice(),
                b"LAST-UPDATED".as_slice(),
                ClauseKind::LastUpdated,
                SyntaxKind::LastUpdatedClause,
            ),
            (
                b"identity MODULE-IDENTITY".as_slice(),
                b"ORGANIZATION".as_slice(),
                ClauseKind::Organization,
                SyntaxKind::OrganizationClause,
            ),
            (
                b"identity MODULE-IDENTITY".as_slice(),
                b"CONTACT-INFO".as_slice(),
                ClauseKind::ContactInfo,
                SyntaxKind::ContactInfoClause,
            ),
            (
                b"identity MODULE-IDENTITY".as_slice(),
                b"REVISION".as_slice(),
                ClauseKind::Revision,
                SyntaxKind::RevisionClause,
            ),
            (
                b"legacy TRAP-TYPE".as_slice(),
                b"ENTERPRISE".as_slice(),
                ClauseKind::Enterprise,
                SyntaxKind::EnterpriseClause,
            ),
            (
                b"legacy TRAP-TYPE".as_slice(),
                b"VARIABLES".as_slice(),
                ClauseKind::Variables,
                SyntaxKind::VariablesClause,
            ),
            (
                b"Text ::= TEXTUAL-CONVENTION".as_slice(),
                b"DISPLAY-HINT".as_slice(),
                ClauseKind::DisplayHint,
                SyntaxKind::DisplayHintClause,
            ),
            (
                b"caps AGENT-CAPABILITIES".as_slice(),
                b"PRODUCT-RELEASE".as_slice(),
                ClauseKind::ProductRelease,
                SyntaxKind::ProductReleaseClause,
            ),
        ] {
            assert_clause(
                &common,
                COMMON_CLAUSE_SOURCE,
                anchor,
                needle,
                expected,
                syntax_kind,
            );
        }

        let nested = tree(NESTED_CLAUSE_SOURCE);
        for (anchor, needle, expected, syntax_kind) in [
            (
                b"comp MODULE-COMPLIANCE".as_slice(),
                b"MODULE OTHER-MIB".as_slice(),
                ClauseKind::ComplianceModule,
                SyntaxKind::ComplianceModule,
            ),
            (
                b"MODULE OTHER-MIB".as_slice(),
                b"MANDATORY-GROUPS".as_slice(),
                ClauseKind::MandatoryGroups,
                SyntaxKind::MandatoryGroupsClause,
            ),
            (
                b"MODULE OTHER-MIB".as_slice(),
                b"GROUP group".as_slice(),
                ClauseKind::ComplianceGroup,
                SyntaxKind::ComplianceGroup,
            ),
            (
                b"MODULE OTHER-MIB".as_slice(),
                b"OBJECT object".as_slice(),
                ClauseKind::ComplianceObject,
                SyntaxKind::ComplianceObject,
            ),
            (
                b"cap AGENT-CAPABILITIES".as_slice(),
                b"SUPPORTS OTHER-MIB".as_slice(),
                ClauseKind::SupportsModule,
                SyntaxKind::SupportsModule,
            ),
            (
                b"SUPPORTS OTHER-MIB".as_slice(),
                b"INCLUDES".as_slice(),
                ClauseKind::Includes,
                SyntaxKind::IncludesClause,
            ),
            (
                b"SUPPORTS OTHER-MIB".as_slice(),
                b"VARIATION object".as_slice(),
                ClauseKind::Variation,
                SyntaxKind::VariationClause,
            ),
            (
                b"VARIATION object".as_slice(),
                b"WRITE-SYNTAX".as_slice(),
                ClauseKind::WriteSyntax,
                SyntaxKind::WriteSyntaxClause,
            ),
            (
                b"VARIATION object".as_slice(),
                b"CREATION-REQUIRES".as_slice(),
                ClauseKind::CreationRequires,
                SyntaxKind::CreationRequiresClause,
            ),
        ] {
            assert_clause(
                &nested,
                NESTED_CLAUSE_SOURCE,
                anchor,
                needle,
                expected,
                syntax_kind,
            );
        }
    }

    #[test]
    fn nested_conformance_clauses_choose_the_innermost_context() {
        let source = NESTED_CLAUSE_SOURCE;
        let tree = tree(source);

        let module_oid = tree.cursor_context(at(source, b"iso 3")).unwrap();
        assert!(module_oid.oid().is_some());
        assert_eq!(
            module_oid.clause().unwrap().kind(),
            ClauseKind::ComplianceModule
        );
        assert!(matches!(
            module_oid.definition(),
            Some(Definition::ModuleCompliance(_))
        ));
        let compliance_module_name = tree
            .cursor_context(at_after(source, b"MODULE OTHER-MIB", b"OTHER-MIB"))
            .unwrap();
        assert_eq!(
            compliance_module_name.clause().unwrap().kind(),
            ClauseKind::ComplianceModule
        );

        let mandatory = tree
            .cursor_context(at(source, b"MANDATORY-GROUPS"))
            .unwrap();
        assert_eq!(
            mandatory.clause().unwrap().kind(),
            ClauseKind::MandatoryGroups
        );
        let group = tree.cursor_context(at(source, b"conditional")).unwrap();
        assert_eq!(group.clause().unwrap().kind(), ClauseKind::Description);

        let includes = tree.cursor_context(at(source, b"INCLUDES")).unwrap();
        assert_eq!(includes.clause().unwrap().kind(), ClauseKind::Includes);
        let write = tree.cursor_context(at(source, b"WRITE-SYNTAX")).unwrap();
        assert_eq!(write.clause().unwrap().kind(), ClauseKind::WriteSyntax);
        let creation = tree
            .cursor_context(at(source, b"CREATION-REQUIRES"))
            .unwrap();
        assert_eq!(
            creation.clause().unwrap().kind(),
            ClauseKind::CreationRequires
        );
        assert!(matches!(
            creation.definition(),
            Some(Definition::AgentCapabilities(_))
        ));

        // A nested common clause overrides its enclosing section, while the
        // section itself remains the context on its name and OID.
        let compliance_name = tree
            .cursor_context(at_after(source, b"GROUP group", b"group"))
            .unwrap();
        assert_eq!(
            compliance_name.clause().unwrap().kind(),
            ClauseKind::ComplianceGroup
        );
        let compliance_object_name = tree
            .cursor_context(at_after(source, b"OBJECT object", b"object"))
            .unwrap();
        assert_eq!(
            compliance_object_name.clause().unwrap().kind(),
            ClauseKind::ComplianceObject
        );
        let refinement_syntax = tree
            .cursor_context(at_after(source, b"OBJECT object", b"SYNTAX"))
            .unwrap();
        assert_eq!(
            refinement_syntax.clause().unwrap().kind(),
            ClauseKind::Syntax
        );
        let supports_name = tree
            .cursor_context(at_after(source, b"SUPPORTS OTHER-MIB", b"OTHER-MIB"))
            .unwrap();
        assert_eq!(
            supports_name.clause().unwrap().kind(),
            ClauseKind::SupportsModule
        );
        let supports_oid = tree
            .cursor_context(at_after(source, b"SUPPORTS OTHER-MIB", b"iso 4"))
            .unwrap();
        assert_eq!(
            supports_oid.clause().unwrap().kind(),
            ClauseKind::SupportsModule
        );
        assert!(supports_oid.oid().is_some());
        let variation_name = tree
            .cursor_context(at_after(source, b"VARIATION object", b"object"))
            .unwrap();
        assert_eq!(
            variation_name.clause().unwrap().kind(),
            ClauseKind::Variation
        );
        let variation_access = tree
            .cursor_context(at_after(source, b"VARIATION object", b"ACCESS"))
            .unwrap();
        assert_eq!(
            variation_access.clause().unwrap().kind(),
            ClauseKind::Access
        );
    }

    #[test]
    fn leading_trivia_and_malformed_headers_keep_exact_ownership() {
        let source = b"   \nBROKEN-MIB DEFINITIONS , BEGIN\nEND";
        let tree = tree(source);

        let leading = tree.cursor_context(ByteOffset::new(0)).unwrap();
        assert_eq!(leading.token().kind(), SyntaxKind::Whitespace);
        assert_eq!(leading.innermost_node().kind(), SyntaxKind::SourceFile);
        assert!(leading.module().is_none());
        assert!(leading.definition().is_none());

        let name = tree.cursor_context(at(source, b"BROKEN-MIB")).unwrap();
        assert!(name.module().is_some());
        assert!(name.error().is_none());
        assert_eq!(name.innermost_node().kind(), SyntaxKind::ModuleHeader);

        let malformed = tree.cursor_context(at(source, b",")).unwrap();
        assert!(malformed.module().is_some());
        assert!(malformed.definition().is_none());
        assert!(malformed.imports().is_none());
        assert!(malformed.error().is_some());
        assert_eq!(malformed.innermost_node().kind(), SyntaxKind::Error);

        let begin = tree.cursor_context(at(source, b"BEGIN")).unwrap();
        assert!(begin.module().is_some());
        assert_eq!(begin.innermost_node().kind(), SyntaxKind::ModuleHeader);
    }

    #[test]
    fn malformed_and_truncated_import_groups_preserve_cursor_context() {
        let malformed = b"IMPORT-MIB DEFINITIONS ::= BEGIN\nIMPORTS\n first, FROM FIRST-MIB\n second FROM lowercase;\nvalue OBJECT IDENTIFIER ::= { 1 }\nEND";
        let malformed_tree = tree(malformed);

        let before_from = malformed_tree
            .cursor_context(at_after(malformed, b"IMPORTS", b"first"))
            .unwrap();
        assert!(before_from.imports().is_some());
        assert!(before_from.import_group().is_some());
        assert!(before_from.error().is_none());

        let after_from = malformed_tree
            .cursor_context(at(malformed, b"FIRST-MIB"))
            .unwrap();
        assert!(after_from.imports().is_some());
        assert!(after_from.import_group().is_some());
        assert!(after_from.error().is_none());

        let bad_module = malformed_tree
            .cursor_context(at(malformed, b"lowercase"))
            .unwrap();
        assert!(bad_module.imports().is_some());
        assert!(bad_module.import_group().is_some());
        assert!(bad_module.error().is_some());
        assert_eq!(bad_module.innermost_node().kind(), SyntaxKind::Error);
        assert!(bad_module.definition().is_none());

        let truncated = b"TRUNCATED-MIB DEFINITIONS ::= BEGIN\nIMPORTS first, second FROM\nvalue OBJECT IDENTIFIER ::= { 1 }\nEND";
        let truncated_tree = tree(truncated);
        for symbol in [b"first".as_slice(), b"second"] {
            let context = truncated_tree
                .cursor_context(at_after(truncated, b"IMPORTS", symbol))
                .unwrap();
            assert!(context.imports().is_some());
            assert!(context.import_group().is_some());
        }
        let from = truncated_tree
            .cursor_context(at_after(truncated, b"IMPORTS", b"FROM"))
            .unwrap();
        assert!(from.imports().is_some());
        assert!(from.import_group().is_some());
        assert!(from.definition().is_none());

        let later = truncated_tree
            .cursor_context(at(truncated, b"value OBJECT"))
            .unwrap();
        assert!(later.imports().is_none());
        assert!(later.import_group().is_none());
        assert!(matches!(
            later.definition(),
            Some(Definition::ValueAssignment(_))
        ));
    }

    #[test]
    fn missing_end_and_empty_documents_define_eof_context() {
        let source = b"NO-END-MIB DEFINITIONS ::= BEGIN\nvalue OBJECT IDENTIFIER ::= { 1 }";
        let missing_end = tree(source);
        let value = missing_end.cursor_context(at(source, b"value")).unwrap();
        assert!(value.module().is_some());
        assert!(matches!(
            value.definition(),
            Some(Definition::ValueAssignment(_))
        ));

        let eof = missing_end
            .cursor_context(missing_end.document().len())
            .unwrap();
        assert_eq!(eof.token().kind(), SyntaxKind::EofToken);
        assert_eq!(eof.innermost_node().kind(), SyntaxKind::SourceFile);
        assert!(eof.module().is_none());
        assert!(eof.definition().is_none());
        assert!(eof.error().is_none());

        let empty = tree(b"");
        let empty_eof = empty.cursor_context(ByteOffset::new(0)).unwrap();
        assert_eq!(empty_eof.token().kind(), SyntaxKind::EofToken);
        assert_eq!(empty_eof.innermost_node().kind(), SyntaxKind::SourceFile);
        assert!(empty_eof.module().is_none());
        assert!(empty.cursor_context(ByteOffset::new(1)).is_none());
    }

    #[test]
    fn malformed_definition_preserves_outer_error_and_deep_context() {
        let source = br#"BROKEN-MIB DEFINITIONS ::= BEGIN
@

broken OBJECT-TYPE
    SYNTAX INTEGER
    STATUS current
    ::= { iso 1 }

good OBJECT IDENTIFIER ::= { iso 2 }
END"#;
        let tree = tree(source);
        let broken = tree.cursor_context(at(source, b"current")).unwrap();
        assert!(matches!(broken.definition(), Some(Definition::Error(_))));
        assert!(broken.error().is_some());
        assert_eq!(broken.clause().unwrap().kind(), ClauseKind::Status);
        assert_eq!(broken.innermost_node().kind(), SyntaxKind::StatusClause);

        let equal_range = tree.cursor_context(at(source, b"broken")).unwrap();
        assert!(matches!(
            equal_range.definition(),
            Some(Definition::Error(_))
        ));
        assert_eq!(
            equal_range.innermost_node().kind(),
            SyntaxKind::ObjectTypeDefinition
        );

        let garbage = tree.cursor_context(at(source, b"@")).unwrap();
        assert!(garbage.definition().is_none());
        assert!(garbage.error().is_some());
        assert_eq!(garbage.innermost_node().kind(), SyntaxKind::Error);

        let good = tree.cursor_context(at(source, b"iso 2")).unwrap();
        assert!(matches!(
            good.definition(),
            Some(Definition::ValueAssignment(_))
        ));
        assert!(good.oid().is_some());
        assert!(good.error().is_none());
    }
}
