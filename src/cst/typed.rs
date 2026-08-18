//! Typed wrappers for the module-level CST grammar.

use super::{SyntaxElement, SyntaxNode, SyntaxToken};
use crate::syntax::SyntaxKind;

/// A typed view over an immutable [`SyntaxNode`].
pub trait CstNode<'tree, 'src>: Copy {
    /// Return whether this wrapper accepts `kind`.
    fn can_cast(kind: SyntaxKind) -> bool;

    /// Cast an untyped node when it has the wrapper's syntax kind.
    fn cast(node: SyntaxNode<'tree, 'src>) -> Option<Self>;

    /// Return the underlying untyped node.
    fn syntax(self) -> SyntaxNode<'tree, 'src>;
}

macro_rules! typed_node {
    ($name:ident, $kind:ident) => {
        #[doc = concat!("Typed wrapper for a [`SyntaxKind::", stringify!($kind), "`] node.")]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'tree, 'src>(SyntaxNode<'tree, 'src>);

        impl<'tree, 'src> CstNode<'tree, 'src> for $name<'tree, 'src> {
            fn can_cast(kind: SyntaxKind) -> bool {
                kind == SyntaxKind::$kind
            }

            fn cast(node: SyntaxNode<'tree, 'src>) -> Option<Self> {
                Self::can_cast(node.kind()).then_some(Self(node))
            }

            fn syntax(self) -> SyntaxNode<'tree, 'src> {
                self.0
            }
        }
    };
}

typed_node!(SourceFile, SourceFile);
typed_node!(Module, Module);
typed_node!(ModuleHeader, ModuleHeader);
typed_node!(Imports, Imports);
typed_node!(ImportGroup, ImportGroup);
typed_node!(UnparsedRegion, UnparsedRegion);
typed_node!(ValueAssignment, ValueAssignment);
typed_node!(TypeAssignment, TypeAssignment);
typed_node!(TextualConventionDefinition, TextualConventionDefinition);
typed_node!(ObjectTypeDefinition, ObjectTypeDefinition);
typed_node!(ModuleIdentityDefinition, ModuleIdentityDefinition);
typed_node!(ObjectIdentityDefinition, ObjectIdentityDefinition);
typed_node!(NotificationTypeDefinition, NotificationTypeDefinition);
typed_node!(TrapTypeDefinition, TrapTypeDefinition);
typed_node!(MacroDefinition, MacroDefinition);
typed_node!(SyntaxClause, SyntaxClause);
typed_node!(AccessClause, AccessClause);
typed_node!(StatusClause, StatusClause);
typed_node!(DescriptionClause, DescriptionClause);
typed_node!(ReferenceClause, ReferenceClause);
typed_node!(UnitsClause, UnitsClause);
typed_node!(DisplayHintClause, DisplayHintClause);
typed_node!(IndexClause, IndexClause);
typed_node!(IndexItem, IndexItem);
typed_node!(AugmentsClause, AugmentsClause);
typed_node!(DefvalClause, DefvalClause);
typed_node!(DefvalContent, DefvalContent);
typed_node!(ObjectsClause, ObjectsClause);
typed_node!(NotificationsClause, NotificationsClause);
typed_node!(RevisionClause, RevisionClause);
typed_node!(LastUpdatedClause, LastUpdatedClause);
typed_node!(OrganizationClause, OrganizationClause);
typed_node!(ContactInfoClause, ContactInfoClause);
typed_node!(EnterpriseClause, EnterpriseClause);
typed_node!(VariablesClause, VariablesClause);
typed_node!(ProductReleaseClause, ProductReleaseClause);
typed_node!(OidAssignment, OidAssignment);
typed_node!(OidComponent, OidComponent);
typed_node!(TypeRefSyntax, TypeRefSyntax);
typed_node!(IntegerEnumSyntax, IntegerEnumSyntax);
typed_node!(BitsSyntax, BitsSyntax);
typed_node!(ConstrainedSyntax, ConstrainedSyntax);
typed_node!(Constraint, Constraint);
typed_node!(Range, Range);
typed_node!(NamedNumber, NamedNumber);
typed_node!(SequenceOfSyntax, SequenceOfSyntax);
typed_node!(SequenceSyntax, SequenceSyntax);
typed_node!(SequenceField, SequenceField);
typed_node!(ChoiceSyntax, ChoiceSyntax);
typed_node!(TaggedSyntax, TaggedSyntax);
typed_node!(OctetStringSyntax, OctetStringSyntax);
typed_node!(ObjectIdentifierSyntax, ObjectIdentifierSyntax);
typed_node!(ErrorRegion, Error);

/// A typed top-level definition or recovered malformed definition.
#[derive(Clone, Copy, Debug)]
pub enum Definition<'tree, 'src> {
    /// OID value assignment.
    ValueAssignment(ValueAssignment<'tree, 'src>),
    /// ASN.1/SMI type assignment.
    TypeAssignment(TypeAssignment<'tree, 'src>),
    /// `TEXTUAL-CONVENTION` definition.
    TextualConvention(TextualConventionDefinition<'tree, 'src>),
    /// `OBJECT-TYPE` definition.
    ObjectType(ObjectTypeDefinition<'tree, 'src>),
    /// `MODULE-IDENTITY` definition.
    ModuleIdentity(ModuleIdentityDefinition<'tree, 'src>),
    /// `OBJECT-IDENTITY` definition.
    ObjectIdentity(ObjectIdentityDefinition<'tree, 'src>),
    /// `NOTIFICATION-TYPE` definition.
    NotificationType(NotificationTypeDefinition<'tree, 'src>),
    /// `TRAP-TYPE` definition.
    TrapType(TrapTypeDefinition<'tree, 'src>),
    /// ASN.1 `MACRO` definition.
    Macro(MacroDefinition<'tree, 'src>),
    /// A malformed definition retained for recovery.
    Error(ErrorRegion<'tree, 'src>),
}

impl<'tree, 'src> Definition<'tree, 'src> {
    /// Cast a definition-level syntax node.
    pub fn cast(node: SyntaxNode<'tree, 'src>) -> Option<Self> {
        match node.kind() {
            SyntaxKind::ValueAssignment => ValueAssignment::cast(node).map(Self::ValueAssignment),
            SyntaxKind::TypeAssignment => TypeAssignment::cast(node).map(Self::TypeAssignment),
            SyntaxKind::TextualConventionDefinition => {
                TextualConventionDefinition::cast(node).map(Self::TextualConvention)
            }
            SyntaxKind::ObjectTypeDefinition => {
                ObjectTypeDefinition::cast(node).map(Self::ObjectType)
            }
            SyntaxKind::ModuleIdentityDefinition => {
                ModuleIdentityDefinition::cast(node).map(Self::ModuleIdentity)
            }
            SyntaxKind::ObjectIdentityDefinition => {
                ObjectIdentityDefinition::cast(node).map(Self::ObjectIdentity)
            }
            SyntaxKind::NotificationTypeDefinition => {
                NotificationTypeDefinition::cast(node).map(Self::NotificationType)
            }
            SyntaxKind::TrapTypeDefinition => TrapTypeDefinition::cast(node).map(Self::TrapType),
            SyntaxKind::MacroDefinition => MacroDefinition::cast(node).map(Self::Macro),
            SyntaxKind::Error if is_definition_or_recovery(node) => {
                ErrorRegion::cast(node).map(Self::Error)
            }
            _ => None,
        }
    }

    /// Return the underlying syntax node.
    pub fn syntax(self) -> SyntaxNode<'tree, 'src> {
        match self {
            Self::ValueAssignment(node) => node.syntax(),
            Self::TypeAssignment(node) => node.syntax(),
            Self::TextualConvention(node) => node.syntax(),
            Self::ObjectType(node) => node.syntax(),
            Self::ModuleIdentity(node) => node.syntax(),
            Self::ObjectIdentity(node) => node.syntax(),
            Self::NotificationType(node) => node.syntax(),
            Self::TrapType(node) => node.syntax(),
            Self::Macro(node) => node.syntax(),
            Self::Error(node) => node.syntax(),
        }
    }

    /// Return the definition name, if the definition was structurally valid.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        match self {
            Self::ValueAssignment(node) => node.name(),
            Self::TypeAssignment(node) => node.name(),
            Self::TextualConvention(node) => node.name(),
            Self::ObjectType(node) => node.name(),
            Self::ModuleIdentity(node) => node.name(),
            Self::ObjectIdentity(node) => node.name(),
            Self::NotificationType(node) => node.name(),
            Self::TrapType(node) => node.name(),
            Self::Macro(node) => node.name(),
            Self::Error(_) => None,
        }
    }
}

fn child_node<'tree, 'src, N>(node: SyntaxNode<'tree, 'src>) -> Option<N>
where
    N: CstNode<'tree, 'src>,
{
    node.children()
        .filter_map(SyntaxElement::as_node)
        .find_map(N::cast)
}

fn child_token<'tree, 'src>(
    node: SyntaxNode<'tree, 'src>,
    kind: SyntaxKind,
) -> Option<SyntaxToken<'tree, 'src>> {
    node.children()
        .filter_map(SyntaxElement::as_token)
        .find(|token| token.kind() == kind)
}

fn child_token_matching<'tree, 'src>(
    node: SyntaxNode<'tree, 'src>,
    predicate: impl Fn(SyntaxKind) -> bool,
) -> Option<SyntaxToken<'tree, 'src>> {
    node.children()
        .filter_map(SyntaxElement::as_token)
        .find(|token| predicate(token.kind()))
}

fn child_nodes<'tree, 'src, N>(node: SyntaxNode<'tree, 'src>) -> impl Iterator<Item = N>
where
    N: CstNode<'tree, 'src>,
{
    node.children()
        .filter_map(SyntaxElement::as_node)
        .filter_map(N::cast)
}

fn first_token<'tree, 'src>(node: SyntaxNode<'tree, 'src>) -> Option<SyntaxToken<'tree, 'src>> {
    node.children().find_map(SyntaxElement::as_token)
}

fn last_token<'tree, 'src>(node: SyntaxNode<'tree, 'src>) -> Option<SyntaxToken<'tree, 'src>> {
    node.children().filter_map(SyntaxElement::as_token).last()
}

fn child_type_syntax<'tree, 'src>(
    node: SyntaxNode<'tree, 'src>,
) -> Option<SyntaxNode<'tree, 'src>> {
    node.children()
        .filter_map(SyntaxElement::as_node)
        .find(|child| is_type_syntax_kind(child.kind()))
}

fn token_after<'tree, 'src>(
    node: SyntaxNode<'tree, 'src>,
    marker: SyntaxKind,
    expected: SyntaxKind,
) -> Option<SyntaxToken<'tree, 'src>> {
    let mut after_marker = false;
    node.children().find_map(|element| {
        let token = element.as_token()?;
        if token.kind() == marker {
            after_marker = true;
            return None;
        }
        (after_marker && token.kind() == expected).then_some(token)
    })
}

fn is_definition_kind(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::ValueAssignment
            | SyntaxKind::TypeAssignment
            | SyntaxKind::TextualConventionDefinition
            | SyntaxKind::ObjectTypeDefinition
            | SyntaxKind::ModuleIdentityDefinition
            | SyntaxKind::ObjectIdentityDefinition
            | SyntaxKind::NotificationTypeDefinition
            | SyntaxKind::TrapTypeDefinition
            | SyntaxKind::MacroDefinition
    )
}

fn is_definition_or_recovery(node: SyntaxNode<'_, '_>) -> bool {
    is_definition_kind(node.kind())
        || (node.kind() == SyntaxKind::Error
            && node
                .children()
                .filter_map(SyntaxElement::as_node)
                .any(|child| is_definition_kind(child.kind())))
}

impl<'tree, 'src> SourceFile<'tree, 'src> {
    /// Iterate over recognized modules in source order.
    pub fn modules(self) -> impl Iterator<Item = Module<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(Module::cast)
    }

    /// Iterate over top-level recovery regions outside recognized modules.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ErrorRegion::cast)
    }

    /// Iterate over definitions across all modules in source order.
    pub fn definitions(self) -> impl Iterator<Item = Definition<'tree, 'src>> {
        self.modules().flat_map(Module::definitions)
    }
}

impl<'tree, 'src> Module<'tree, 'src> {
    /// Return the module header, including partial or malformed headers.
    pub fn header(self) -> Option<ModuleHeader<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the module's `IMPORTS` section, when present.
    pub fn imports(self) -> Option<Imports<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the closing `END` token, when present.
    pub fn end(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwEnd)
    }

    /// Iterate over definition/body regions retained for later CST stages.
    pub fn unparsed_regions(self) -> impl Iterator<Item = UnparsedRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(UnparsedRegion::cast)
    }

    /// Iterate over primary definitions and malformed-definition recovery
    /// regions in source order.
    ///
    /// Conformance and capability definitions remain untyped until the next
    /// CST grammar stage and are therefore not yielded here.
    pub fn definitions(self) -> impl Iterator<Item = Definition<'tree, 'src>> {
        self.unparsed_regions().flat_map(|region| {
            region
                .syntax()
                .children()
                .filter_map(SyntaxElement::as_node)
                .filter(|node| is_definition_or_recovery(*node))
                .filter_map(Definition::cast)
        })
    }

    /// Iterate over immediate module-level recovery regions.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ErrorRegion::cast)
    }
}

macro_rules! definition_common {
    ($name:ident, $keyword:ident) => {
        impl<'tree, 'src> $name<'tree, 'src> {
            /// Return the definition name.
            pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
                first_token(self.0)
            }

            /// Return the family keyword.
            pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::$keyword)
            }

            /// Return the assignment operator, when this definition form has one.
            pub fn assignment(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::ColonColonEqual)
            }

            /// Iterate over malformed nested portions of this definition.
            pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
                self.0
                    .descendant_nodes()
                    .skip(1)
                    .filter_map(ErrorRegion::cast)
            }
        }
    };
}

definition_common!(TextualConventionDefinition, KwTextualConvention);
definition_common!(ObjectTypeDefinition, KwObjectType);
definition_common!(ModuleIdentityDefinition, KwModuleIdentity);
definition_common!(ObjectIdentityDefinition, KwObjectIdentity);
definition_common!(NotificationTypeDefinition, KwNotificationType);
definition_common!(TrapTypeDefinition, KwTrapType);
definition_common!(MacroDefinition, KwMacro);

impl<'tree, 'src> TypeAssignment<'tree, 'src> {
    /// Return the assigned type name.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0)
    }

    /// Return the assignment operator.
    pub fn assignment(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::ColonColonEqual)
    }

    /// Return the assigned type syntax.
    pub fn type_syntax(self) -> Option<SyntaxNode<'tree, 'src>> {
        child_type_syntax(self.0)
    }

    /// Iterate over malformed nested portions of this definition.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .descendant_nodes()
            .skip(1)
            .filter_map(ErrorRegion::cast)
    }
}

impl<'tree, 'src> ValueAssignment<'tree, 'src> {
    /// Return the assigned value name.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0)
    }

    /// Return the `OBJECT` keyword.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        self.0
            .descendant_tokens()
            .find(|token| token.kind() == SyntaxKind::KwObject)
    }

    /// Return the `IDENTIFIER` keyword.
    pub fn identifier(self) -> Option<SyntaxToken<'tree, 'src>> {
        self.0
            .descendant_tokens()
            .find(|token| token.kind() == SyntaxKind::KwIdentifier)
    }

    /// Return the assignment operator.
    pub fn assignment(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::ColonColonEqual)
    }

    /// Return the OID assigned to this name.
    pub fn oid(self) -> Option<OidAssignment<'tree, 'src>> {
        child_node(self.0)
    }

    /// Iterate over malformed nested portions of this definition.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .descendant_nodes()
            .skip(1)
            .filter_map(ErrorRegion::cast)
    }
}

impl<'tree, 'src> TextualConventionDefinition<'tree, 'src> {
    /// Return the optional display hint.
    pub fn display_hint(self) -> Option<DisplayHintClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the status clause.
    pub fn status(self) -> Option<StatusClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the description clause.
    pub fn description(self) -> Option<DescriptionClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional reference clause.
    pub fn reference(self) -> Option<ReferenceClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the underlying syntax clause.
    pub fn syntax_clause(self) -> Option<SyntaxClause<'tree, 'src>> {
        child_node(self.0)
    }
}

impl<'tree, 'src> ObjectTypeDefinition<'tree, 'src> {
    /// Return the object's syntax clause.
    pub fn syntax_clause(self) -> Option<SyntaxClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional units clause.
    pub fn units(self) -> Option<UnitsClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the access clause.
    pub fn access(self) -> Option<AccessClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional status clause.
    pub fn status(self) -> Option<StatusClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional description clause.
    pub fn description(self) -> Option<DescriptionClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional reference clause.
    pub fn reference(self) -> Option<ReferenceClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional index clause.
    pub fn index(self) -> Option<IndexClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional augments clause.
    pub fn augments(self) -> Option<AugmentsClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional default-value clause.
    pub fn defval(self) -> Option<DefvalClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the object's assigned OID.
    pub fn oid(self) -> Option<OidAssignment<'tree, 'src>> {
        child_node(self.0)
    }
}

impl<'tree, 'src> ModuleIdentityDefinition<'tree, 'src> {
    /// Return the last-updated clause.
    pub fn last_updated(self) -> Option<LastUpdatedClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the organization clause.
    pub fn organization(self) -> Option<OrganizationClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the contact-info clause.
    pub fn contact_info(self) -> Option<ContactInfoClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Iterate over description clauses, including revision descriptions.
    pub fn descriptions(self) -> impl Iterator<Item = DescriptionClause<'tree, 'src>> {
        child_nodes(self.0)
    }

    /// Iterate over revision date clauses.
    pub fn revisions(self) -> impl Iterator<Item = RevisionClause<'tree, 'src>> {
        child_nodes(self.0)
    }

    /// Return the module identity's assigned OID.
    pub fn oid(self) -> Option<OidAssignment<'tree, 'src>> {
        child_node(self.0)
    }
}

macro_rules! status_description_oid_definition {
    ($name:ident) => {
        impl<'tree, 'src> $name<'tree, 'src> {
            /// Return the status clause.
            pub fn status(self) -> Option<StatusClause<'tree, 'src>> {
                child_node(self.0)
            }

            /// Return the description clause.
            pub fn description(self) -> Option<DescriptionClause<'tree, 'src>> {
                child_node(self.0)
            }

            /// Return the optional reference clause.
            pub fn reference(self) -> Option<ReferenceClause<'tree, 'src>> {
                child_node(self.0)
            }

            /// Return the assigned OID.
            pub fn oid(self) -> Option<OidAssignment<'tree, 'src>> {
                child_node(self.0)
            }
        }
    };
}

status_description_oid_definition!(ObjectIdentityDefinition);
status_description_oid_definition!(NotificationTypeDefinition);

impl<'tree, 'src> NotificationTypeDefinition<'tree, 'src> {
    /// Return the optional objects clause.
    pub fn objects(self) -> Option<ObjectsClause<'tree, 'src>> {
        child_node(self.0)
    }
}

impl<'tree, 'src> TrapTypeDefinition<'tree, 'src> {
    /// Return the enterprise clause.
    pub fn enterprise(self) -> Option<EnterpriseClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional variables clause.
    pub fn variables(self) -> Option<VariablesClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional description clause.
    pub fn description(self) -> Option<DescriptionClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the optional reference clause.
    pub fn reference(self) -> Option<ReferenceClause<'tree, 'src>> {
        child_node(self.0)
    }

    /// Return the numeric trap value following `::=`.
    pub fn trap_number(self) -> Option<SyntaxToken<'tree, 'src>> {
        token_after(self.0, SyntaxKind::ColonColonEqual, SyntaxKind::Number)
    }
}

impl<'tree, 'src> MacroDefinition<'tree, 'src> {
    /// Return the opaque lexer token retaining the macro body.
    pub fn body(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::OpaqueText)
    }

    /// Return the macro's closing `END`.
    pub fn end(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwEnd)
    }
}

impl<'tree, 'src> ModuleHeader<'tree, 'src> {
    /// Return the module-name token, when present.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_token)
            .find(|token| token.kind().is_identifier())
    }

    /// Return the `DEFINITIONS` token, when present.
    pub fn definitions(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwDefinitions)
    }

    /// Return the `::=` token, when present.
    pub fn assignment(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::ColonColonEqual)
    }

    /// Return the `BEGIN` token, when present.
    pub fn begin(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwBegin)
    }

    /// Iterate over malformed portions of the header.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ErrorRegion::cast)
    }
}

impl<'tree, 'src> Imports<'tree, 'src> {
    /// Return the `IMPORTS` keyword.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwImports)
    }

    /// Iterate over import groups in source order.
    pub fn groups(self) -> impl Iterator<Item = ImportGroup<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ImportGroup::cast)
    }

    /// Return the closing semicolon, when present.
    pub fn semicolon(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::Semicolon)
    }

    /// Iterate over malformed portions not owned by an import group.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ErrorRegion::cast)
    }
}

impl<'tree, 'src> ImportGroup<'tree, 'src> {
    /// Iterate over imported symbol tokens in source order.
    pub fn symbols(self) -> impl Iterator<Item = SyntaxToken<'tree, 'src>> {
        let mut before_from = true;
        self.0.children().filter_map(move |element| {
            let token = element.as_token()?;
            if token.kind() == SyntaxKind::KwFrom {
                before_from = false;
                return None;
            }
            (before_from && is_import_symbol(token.kind())).then_some(token)
        })
    }

    /// Return the `FROM` keyword, when present.
    pub fn from(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwFrom)
    }

    /// Return the source module name following `FROM`, when present.
    pub fn module_name(self) -> Option<SyntaxToken<'tree, 'src>> {
        let mut after_from = false;
        self.0.children().find_map(|element| {
            let token = element.as_token()?;
            if token.kind() == SyntaxKind::KwFrom {
                after_from = true;
                return None;
            }
            (after_from && token.kind() == SyntaxKind::UppercaseIdent).then_some(token)
        })
    }

    /// Iterate over malformed portions of the group.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ErrorRegion::cast)
    }
}

impl<'tree, 'src> SyntaxClause<'tree, 'src> {
    /// Return the `SYNTAX` keyword.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwSyntax)
    }

    /// Return the contained type-syntax node, when it was present and recognized.
    pub fn type_syntax(self) -> Option<SyntaxNode<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .find(|node| is_type_syntax_kind(node.kind()))
    }

    /// Iterate over malformed portions of the clause.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

macro_rules! value_clause {
    ($name:ident, $keyword:ident, $value:expr) => {
        impl<'tree, 'src> $name<'tree, 'src> {
            /// Return the clause keyword.
            pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::$keyword)
            }

            /// Return the clause value, when present and lexically valid.
            pub fn value(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token_matching(self.0, $value)
            }

            /// Iterate over malformed portions of the clause.
            pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
                child_nodes(self.0)
            }
        }
    };
}

impl<'tree, 'src> AccessClause<'tree, 'src> {
    /// Return `MAX-ACCESS`, `MIN-ACCESS`, or `ACCESS`.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, |kind| {
            matches!(
                kind,
                SyntaxKind::KwMaxAccess | SyntaxKind::KwMinAccess | SyntaxKind::KwAccess
            )
        })
    }

    /// Return the access value, when present and lexically valid.
    pub fn value(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, is_access_value_kind)
    }

    /// Iterate over malformed portions of the clause.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

value_clause!(StatusClause, KwStatus, is_status_value_kind);
value_clause!(DescriptionClause, KwDescription, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(ReferenceClause, KwReference, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(UnitsClause, KwUnits, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(DisplayHintClause, KwDisplayHint, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(RevisionClause, KwRevision, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(LastUpdatedClause, KwLastUpdated, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(OrganizationClause, KwOrganization, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(ContactInfoClause, KwContactInfo, |kind| kind
    == SyntaxKind::QuotedString);
value_clause!(EnterpriseClause, KwEnterprise, SyntaxKind::is_identifier);
value_clause!(ProductReleaseClause, KwProductRelease, |kind| kind
    == SyntaxKind::QuotedString);

macro_rules! name_list_clause {
    ($name:ident, $keyword:ident) => {
        impl<'tree, 'src> $name<'tree, 'src> {
            /// Return the clause keyword.
            pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::$keyword)
            }

            /// Return the opening brace, when present.
            pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::LBrace)
            }

            /// Iterate over retained names in source order.
            pub fn names(self) -> impl Iterator<Item = SyntaxToken<'tree, 'src>> {
                self.0
                    .children()
                    .filter_map(SyntaxElement::as_token)
                    .filter(|token| token.kind().is_identifier())
            }

            /// Return the closing brace, when present.
            pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::RBrace)
            }

            /// Iterate over malformed portions of the clause.
            pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
                child_nodes(self.0)
            }
        }
    };
}

name_list_clause!(ObjectsClause, KwObjects);
name_list_clause!(NotificationsClause, KwNotifications);
name_list_clause!(VariablesClause, KwVariables);

impl<'tree, 'src> AugmentsClause<'tree, 'src> {
    /// Return the `AUGMENTS` keyword.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwAugments)
    }

    /// Return the opening brace, when present.
    pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LBrace)
    }

    /// Return the target row name, when present.
    pub fn target(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, SyntaxKind::is_identifier)
    }

    /// Return the closing brace, when present.
    pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::RBrace)
    }

    /// Iterate over malformed portions of the clause.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> IndexClause<'tree, 'src> {
    /// Return the `INDEX` keyword.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwIndex)
    }

    /// Return the opening brace, when present.
    pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LBrace)
    }

    /// Iterate over index items in source order.
    pub fn items(self) -> impl Iterator<Item = IndexItem<'tree, 'src>> {
        child_nodes(self.0)
    }

    /// Return the closing brace, when present.
    pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::RBrace)
    }

    /// Iterate over malformed portions not owned by an index item.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> IndexItem<'tree, 'src> {
    /// Return the optional `IMPLIED` keyword.
    pub fn implied(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwImplied)
    }

    /// Return the referenced object or `OCTET` token, when present.
    pub fn object(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, |kind| {
            kind.is_identifier() || kind == SyntaxKind::KwOctet
        })
    }

    /// Return `STRING` for the tolerated `OCTET STRING` index form.
    pub fn string_keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwString)
    }

    /// Iterate over malformed portions of the item.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> DefvalClause<'tree, 'src> {
    /// Return the `DEFVAL` keyword.
    pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwDefval)
    }

    /// Return the retained braced content, when present.
    pub fn content(self) -> Option<DefvalContent<'tree, 'src>> {
        child_node(self.0)
    }

    /// Iterate over malformed portions outside braced content.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> DefvalContent<'tree, 'src> {
    /// Return the opening brace.
    pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0).filter(|token| token.kind() == SyntaxKind::LBrace)
    }

    /// Iterate over the exact content tokens excluding the outer braces.
    pub fn tokens(self) -> impl Iterator<Item = SyntaxToken<'tree, 'src>> {
        let has_close = self.r_brace().is_some();
        let token_count = self.0.descendant_tokens().count();
        self.0
            .descendant_tokens()
            .enumerate()
            .filter_map(move |(index, token)| {
                if index == 0 || (has_close && index + 1 == token_count) {
                    None
                } else {
                    Some(token)
                }
            })
    }

    /// Return the closing brace, when present.
    pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        last_token(self.0).filter(|token| token.kind() == SyntaxKind::RBrace)
    }
}

impl<'tree, 'src> OidAssignment<'tree, 'src> {
    /// Return the opening brace.
    pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LBrace)
    }

    /// Iterate over OID components in source order.
    pub fn components(self) -> impl Iterator<Item = OidComponent<'tree, 'src>> {
        child_nodes(self.0)
    }

    /// Return the closing brace, when present.
    pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::RBrace)
    }

    /// Iterate over malformed portions outside components.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> OidComponent<'tree, 'src> {
    /// Return the module qualifier before `.`, when present.
    pub fn module(self) -> Option<SyntaxToken<'tree, 'src>> {
        let has_dot = child_token(self.0, SyntaxKind::Dot).is_some();
        has_dot.then(|| first_token(self.0)).flatten()
    }

    /// Return the qualifier dot, when present.
    pub fn dot(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::Dot)
    }

    /// Return the name portion, when present.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        let mut after_dot = self.dot().is_none();
        self.0.children().find_map(|element| {
            let token = element.as_token()?;
            if token.kind() == SyntaxKind::Dot {
                after_dot = true;
                return None;
            }
            (after_dot && token.kind().is_identifier()).then_some(token)
        })
    }

    /// Return the optional opening parenthesis around a numeric subidentifier.
    pub fn l_paren(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LParen)
    }

    /// Return the numeric component or named-number value, when present.
    pub fn number(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::Number)
    }

    /// Return the optional closing parenthesis around a numeric subidentifier.
    pub fn r_paren(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::RParen)
    }

    /// Iterate over malformed portions of the component.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> TypeRefSyntax<'tree, 'src> {
    /// Return the referenced type token.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0)
    }
}

macro_rules! named_number_syntax {
    ($name:ident, $keyword:ident) => {
        impl<'tree, 'src> $name<'tree, 'src> {
            /// Return the base type keyword or name.
            pub fn base(self) -> Option<SyntaxToken<'tree, 'src>> {
                first_token(self.0)
            }

            /// Return the opening brace, when present.
            pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::LBrace)
            }

            /// Iterate over named numbers in source order.
            pub fn values(self) -> impl Iterator<Item = NamedNumber<'tree, 'src>> {
                child_nodes(self.0)
            }

            /// Return the closing brace, when present.
            pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::RBrace)
            }

            /// Iterate over malformed portions outside named numbers.
            pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
                child_nodes(self.0)
            }
        }
    };
}

named_number_syntax!(IntegerEnumSyntax, KwInteger);
named_number_syntax!(BitsSyntax, KwBits);

impl<'tree, 'src> NamedNumber<'tree, 'src> {
    /// Return the label, when present.
    pub fn label(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0)
            .filter(|token| token.kind().is_identifier() || token.kind().is_status_access_keyword())
    }

    /// Return the opening parenthesis, when present.
    pub fn l_paren(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LParen)
    }

    /// Return the signed or unsigned numeric token, when present.
    pub fn value(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, |kind| {
            matches!(kind, SyntaxKind::Number | SyntaxKind::NegativeNumber)
        })
    }

    /// Return the closing parenthesis, when present.
    pub fn r_paren(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::RParen)
    }

    /// Iterate over malformed portions of the named number.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> ConstrainedSyntax<'tree, 'src> {
    /// Return the constrained base type node.
    pub fn base(self) -> Option<SyntaxNode<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .find(|node| is_type_syntax_kind(node.kind()))
    }

    /// Return the constraint, when present.
    pub fn constraint(self) -> Option<Constraint<'tree, 'src>> {
        child_node(self.0)
    }
}

impl<'tree, 'src> Constraint<'tree, 'src> {
    /// Return the first opening parenthesis.
    pub fn l_paren(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LParen)
    }

    /// Return the optional `SIZE` keyword.
    pub fn size(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwSize)
    }

    /// Iterate over value or range elements.
    pub fn ranges(self) -> impl Iterator<Item = Range<'tree, 'src>> {
        child_nodes(self.0)
    }

    /// Return the last closing parenthesis, when present.
    pub fn r_paren(self) -> Option<SyntaxToken<'tree, 'src>> {
        last_token(self.0).filter(|token| token.kind() == SyntaxKind::RParen)
    }

    /// Iterate over malformed portions outside ranges.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> Range<'tree, 'src> {
    /// Return the lower or exact value token.
    pub fn min(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0)
    }

    /// Return `..` for a bounded range.
    pub fn dot_dot(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::DotDot)
    }

    /// Return the upper bound, when present.
    pub fn max(self) -> Option<SyntaxToken<'tree, 'src>> {
        let mut after_dot_dot = false;
        self.0.children().find_map(|element| {
            let token = element.as_token()?;
            if token.kind() == SyntaxKind::DotDot {
                after_dot_dot = true;
                return None;
            }
            (after_dot_dot && is_range_value_kind(token.kind())).then_some(token)
        })
    }

    /// Iterate over malformed portions of the range.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> SequenceOfSyntax<'tree, 'src> {
    /// Return `SEQUENCE`.
    pub fn sequence(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwSequence)
    }

    /// Return `OF`.
    pub fn of(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwOf)
    }

    /// Return the entry type, when present.
    pub fn entry_type(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, is_type_reference_kind)
    }

    /// Iterate over malformed portions of the syntax.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

macro_rules! fields_syntax {
    ($name:ident, $keyword:ident) => {
        impl<'tree, 'src> $name<'tree, 'src> {
            /// Return the introducing keyword.
            pub fn keyword(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::$keyword)
            }

            /// Return the opening brace, when present.
            pub fn l_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::LBrace)
            }

            /// Iterate over fields or alternatives in source order.
            pub fn fields(self) -> impl Iterator<Item = SequenceField<'tree, 'src>> {
                child_nodes(self.0)
            }

            /// Return the closing brace, when present.
            pub fn r_brace(self) -> Option<SyntaxToken<'tree, 'src>> {
                child_token(self.0, SyntaxKind::RBrace)
            }

            /// Iterate over malformed portions outside fields.
            pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
                child_nodes(self.0)
            }
        }
    };
}

fields_syntax!(SequenceSyntax, KwSequence);
fields_syntax!(ChoiceSyntax, KwChoice);

impl<'tree, 'src> SequenceField<'tree, 'src> {
    /// Return the field name.
    pub fn name(self) -> Option<SyntaxToken<'tree, 'src>> {
        first_token(self.0).filter(|token| token.kind().is_identifier())
    }

    /// Return the field's type syntax, when present and recognized.
    pub fn type_syntax(self) -> Option<SyntaxNode<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .find(|node| is_type_syntax_kind(node.kind()))
    }

    /// Iterate over malformed portions of the field.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> TaggedSyntax<'tree, 'src> {
    /// Return `[`.
    pub fn l_bracket(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::LBracket)
    }

    /// Return the optional tag-class keyword.
    pub fn tag_class(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token_matching(self.0, |kind| {
            matches!(kind, SyntaxKind::KwApplication | SyntaxKind::KwUniversal)
        })
    }

    /// Return the numeric tag, when present.
    pub fn tag_number(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::Number)
    }

    /// Return `]`, when present.
    pub fn r_bracket(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::RBracket)
    }

    /// Return the optional `IMPLICIT` keyword.
    pub fn implicit(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwImplicit)
    }

    /// Return the tagged inner type, when present and recognized.
    pub fn inner(self) -> Option<SyntaxNode<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .find(|node| is_type_syntax_kind(node.kind()))
    }

    /// Iterate over malformed portions of the tag.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        child_nodes(self.0)
    }
}

impl<'tree, 'src> OctetStringSyntax<'tree, 'src> {
    /// Return `OCTET`.
    pub fn octet(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwOctet)
    }

    /// Return `STRING`, when present.
    pub fn string(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwString)
    }
}

impl<'tree, 'src> ObjectIdentifierSyntax<'tree, 'src> {
    /// Return `OBJECT`.
    pub fn object(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwObject)
    }

    /// Return `IDENTIFIER`, when present.
    pub fn identifier(self) -> Option<SyntaxToken<'tree, 'src>> {
        child_token(self.0, SyntaxKind::KwIdentifier)
    }
}

fn is_type_reference_kind(kind: SyntaxKind) -> bool {
    kind.is_identifier() || kind.is_type_keyword() || kind == SyntaxKind::ForbiddenKeyword
}

fn is_type_syntax_kind(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::TypeRefSyntax
            | SyntaxKind::IntegerEnumSyntax
            | SyntaxKind::BitsSyntax
            | SyntaxKind::ConstrainedSyntax
            | SyntaxKind::SequenceOfSyntax
            | SyntaxKind::SequenceSyntax
            | SyntaxKind::ChoiceSyntax
            | SyntaxKind::TaggedSyntax
            | SyntaxKind::OctetStringSyntax
            | SyntaxKind::ObjectIdentifierSyntax
    )
}

fn is_range_value_kind(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Number
            | SyntaxKind::NegativeNumber
            | SyntaxKind::HexString
            | SyntaxKind::UppercaseIdent
            | SyntaxKind::ForbiddenKeyword
    )
}

fn is_access_value_kind(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::KwReadOnly
            | SyntaxKind::KwReadWrite
            | SyntaxKind::KwReadCreate
            | SyntaxKind::KwNotAccessible
            | SyntaxKind::KwAccessibleForNotify
            | SyntaxKind::KwWriteOnly
            | SyntaxKind::KwNotImplemented
    )
}

fn is_status_value_kind(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::KwCurrent
            | SyntaxKind::KwDeprecated
            | SyntaxKind::KwObsolete
            | SyntaxKind::KwMandatory
            | SyntaxKind::KwOptional
    )
}

fn is_import_symbol(kind: SyntaxKind) -> bool {
    kind.is_identifier() || kind.is_macro_keyword() || kind.is_type_keyword()
}
