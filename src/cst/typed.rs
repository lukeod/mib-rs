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
typed_node!(ErrorRegion, Error);

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

    /// Iterate over immediate module-level recovery regions.
    pub fn recovery_regions(self) -> impl Iterator<Item = ErrorRegion<'tree, 'src>> {
        self.0
            .children()
            .filter_map(SyntaxElement::as_node)
            .filter_map(ErrorRegion::cast)
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

fn is_import_symbol(kind: SyntaxKind) -> bool {
    kind.is_identifier() || kind.is_macro_keyword() || kind.is_type_keyword()
}
