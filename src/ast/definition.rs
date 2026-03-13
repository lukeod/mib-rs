//! AST types for each kind of MIB module definition.

use super::common::{Ident, QuotedString};
use super::oid::OidAssignment;
use super::syntax::*;
use crate::types::Span;

/// A top-level construct in a MIB module body.
///
/// Each variant corresponds to an SMI macro invocation, type/value
/// assignment, or a recovered parse error.
#[derive(Debug, PartialEq, Eq)]
pub enum Definition {
    /// OBJECT-TYPE macro (SMIv1/v2).
    ObjectType(ObjectTypeDef),
    /// MODULE-IDENTITY macro (SMIv2).
    ModuleIdentity(ModuleIdentityDef),
    /// OBJECT-IDENTITY macro (SMIv2).
    ObjectIdentity(ObjectIdentityDef),
    /// NOTIFICATION-TYPE macro (SMIv2).
    NotificationType(NotificationTypeDef),
    /// TRAP-TYPE macro (SMIv1).
    TrapType(TrapTypeDef),
    /// TEXTUAL-CONVENTION definition (SMIv2).
    TextualConvention(TextualConventionDef),
    /// Plain type assignment (`TypeName ::= TypeSyntax`).
    TypeAssignment(TypeAssignmentDef),
    /// OID value assignment (`name OBJECT IDENTIFIER ::= { ... }`).
    ValueAssignment(ValueAssignmentDef),
    /// OBJECT-GROUP macro (SMIv2).
    ObjectGroup(ObjectGroupDef),
    /// NOTIFICATION-GROUP macro (SMIv2).
    NotificationGroup(NotificationGroupDef),
    /// MODULE-COMPLIANCE macro (SMIv2).
    ModuleCompliance(ModuleComplianceDef),
    /// AGENT-CAPABILITIES macro (SMIv2).
    AgentCapabilities(AgentCapabilitiesDef),
    /// MACRO definition (body skipped).
    MacroDefinition(MacroDefinitionDef),
    /// Recovered parse error placeholder.
    Error(ErrorDef),
}

macro_rules! delegate_def {
    (name: $($variant:ident),+ ; no_name: $($no_name:ident),+) => {
        impl Definition {
            /// Returns the definition's name, or `None` for error placeholders.
            pub fn name(&self) -> Option<&Ident> {
                match self {
                    $( Definition::$variant(d) => Some(&d.name), )+
                    $( Definition::$no_name(_) => None, )+
                }
            }
        }
    };
    (span: $($variant:ident),+) => {
        impl Definition {
            /// Returns the source span of this definition.
            pub fn span(&self) -> Span {
                match self {
                    $( Definition::$variant(d) => d.span, )+
                }
            }
        }
    };
}

delegate_def!(name:
    ObjectType, ModuleIdentity, ObjectIdentity, NotificationType,
    TrapType, TextualConvention, TypeAssignment, ValueAssignment,
    ObjectGroup, NotificationGroup, ModuleCompliance, AgentCapabilities,
    MacroDefinition;
    no_name: Error
);

delegate_def!(span:
    ObjectType, ModuleIdentity, ObjectIdentity, NotificationType,
    TrapType, TextualConvention, TypeAssignment, ValueAssignment,
    ObjectGroup, NotificationGroup, ModuleCompliance, AgentCapabilities,
    MacroDefinition, Error
);

/// OBJECT-TYPE macro invocation (SMIv1/v2).
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectTypeDef {
    pub name: Ident,
    pub span: Span,
    pub syntax: Option<SyntaxClause>,
    pub units: Option<QuotedString>,
    pub access: Option<AccessClause>,
    pub status: Option<StatusClause>,
    pub description: Option<QuotedString>,
    pub reference: Option<QuotedString>,
    pub index: Option<IndexClause>,
    pub augments: Option<AugmentsClause>,
    pub defval: Option<DefValClause>,
    pub oid: OidAssignment,
}

/// MODULE-IDENTITY macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleIdentityDef {
    pub name: Ident,
    pub span: Span,
    pub last_updated: QuotedString,
    pub organization: QuotedString,
    pub contact_info: QuotedString,
    pub description: QuotedString,
    pub revisions: Vec<RevisionClause>,
    pub oid: OidAssignment,
}

/// OBJECT-IDENTITY macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectIdentityDef {
    pub name: Ident,
    pub span: Span,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid: OidAssignment,
}

/// NOTIFICATION-TYPE macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct NotificationTypeDef {
    pub name: Ident,
    pub span: Span,
    pub objects: Vec<Ident>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid: OidAssignment,
}

/// TRAP-TYPE macro invocation (SMIv1).
#[derive(Debug, PartialEq, Eq)]
pub struct TrapTypeDef {
    pub name: Ident,
    pub span: Span,
    pub enterprise: Ident,
    pub variables: Vec<Ident>,
    pub description: Option<QuotedString>,
    pub reference: Option<QuotedString>,
    pub trap_number: u32,
}

/// TEXTUAL-CONVENTION definition (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct TextualConventionDef {
    pub name: Ident,
    pub span: Span,
    pub display_hint: Option<QuotedString>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub syntax: SyntaxClause,
}

/// Type assignment (TypeName ::= TypeSyntax).
#[derive(Debug, PartialEq, Eq)]
pub struct TypeAssignmentDef {
    pub name: Ident,
    pub span: Span,
    pub syntax: TypeSyntax,
}

/// OID value assignment (name OBJECT IDENTIFIER ::= { ... }).
#[derive(Debug, PartialEq, Eq)]
pub struct ValueAssignmentDef {
    pub name: Ident,
    pub span: Span,
    pub oid: OidAssignment,
}

/// OBJECT-GROUP macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectGroupDef {
    pub name: Ident,
    pub span: Span,
    pub objects: Vec<Ident>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid: OidAssignment,
}

/// NOTIFICATION-GROUP macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct NotificationGroupDef {
    pub name: Ident,
    pub span: Span,
    pub notifications: Vec<Ident>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid: OidAssignment,
}

/// MODULE-COMPLIANCE macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleComplianceDef {
    pub name: Ident,
    pub span: Span,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub modules: Vec<ComplianceModule>,
    pub oid: OidAssignment,
}

/// A MODULE clause within MODULE-COMPLIANCE.
#[derive(Debug, PartialEq, Eq)]
pub struct ComplianceModule {
    pub module_name: Option<Ident>,
    pub module_oid: Option<OidAssignment>,
    pub mandatory_groups: Vec<Ident>,
    pub compliances: Vec<Compliance>,
    pub span: Span,
}

/// A GROUP or OBJECT refinement in a [`ModuleComplianceDef`].
#[derive(Debug, PartialEq, Eq)]
pub enum Compliance {
    /// A conditionally required group.
    Group(ComplianceGroup),
    /// An object with refined syntax, access, or write-syntax.
    Object(ComplianceObject),
}

/// GROUP clause within MODULE-COMPLIANCE.
#[derive(Debug, PartialEq, Eq)]
pub struct ComplianceGroup {
    pub group: Ident,
    pub description: QuotedString,
    pub span: Span,
}

/// OBJECT refinement within MODULE-COMPLIANCE.
#[derive(Debug, PartialEq, Eq)]
pub struct ComplianceObject {
    pub object: Ident,
    pub syntax: Option<SyntaxClause>,
    pub write_syntax: Option<SyntaxClause>,
    pub min_access: Option<AccessClause>,
    pub description: QuotedString,
    pub span: Span,
}

/// AGENT-CAPABILITIES macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct AgentCapabilitiesDef {
    pub name: Ident,
    pub span: Span,
    pub product_release: QuotedString,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub supports: Vec<SupportsModule>,
    pub oid: OidAssignment,
}

/// A SUPPORTS clause within AGENT-CAPABILITIES.
#[derive(Debug, PartialEq, Eq)]
pub struct SupportsModule {
    pub module_name: Ident,
    pub module_oid: Option<OidAssignment>,
    pub includes: Vec<Ident>,
    pub variations: Vec<Variation>,
    pub span: Span,
}

/// A VARIATION clause within AGENT-CAPABILITIES.
#[derive(Debug, PartialEq, Eq)]
pub struct Variation {
    pub name: Ident,
    pub syntax: Option<SyntaxClause>,
    pub write_syntax: Option<SyntaxClause>,
    pub access: Option<AccessClause>,
    pub creation_requires: Vec<Ident>,
    pub defval: Option<DefValClause>,
    pub description: QuotedString,
    pub span: Span,
}

/// A MACRO definition whose body is skipped.
#[derive(Debug, PartialEq, Eq)]
pub struct MacroDefinitionDef {
    pub name: Ident,
    pub span: Span,
}

/// A parse error from which the parser recovered.
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorDef {
    pub span: Span,
    pub message: String,
}
