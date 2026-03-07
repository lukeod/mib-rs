use super::common::{Ident, QuotedString};
use super::oid::OidAssignment;
use super::syntax::*;
use crate::types::Span;

/// A top-level construct in a MIB module body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    ObjectType(ObjectTypeDef),
    ModuleIdentity(ModuleIdentityDef),
    ObjectIdentity(ObjectIdentityDef),
    NotificationType(NotificationTypeDef),
    TrapType(TrapTypeDef),
    TextualConvention(TextualConventionDef),
    TypeAssignment(TypeAssignmentDef),
    ValueAssignment(ValueAssignmentDef),
    ObjectGroup(ObjectGroupDef),
    NotificationGroup(NotificationGroupDef),
    ModuleCompliance(ModuleComplianceDef),
    AgentCapabilities(AgentCapabilitiesDef),
    MacroDefinition(MacroDefinitionDef),
    Error(ErrorDef),
}

impl Definition {
    pub fn name(&self) -> Option<&Ident> {
        match self {
            Definition::ObjectType(d) => Some(&d.name),
            Definition::ModuleIdentity(d) => Some(&d.name),
            Definition::ObjectIdentity(d) => Some(&d.name),
            Definition::NotificationType(d) => Some(&d.name),
            Definition::TrapType(d) => Some(&d.name),
            Definition::TextualConvention(d) => Some(&d.name),
            Definition::TypeAssignment(d) => Some(&d.name),
            Definition::ValueAssignment(d) => Some(&d.name),
            Definition::ObjectGroup(d) => Some(&d.name),
            Definition::NotificationGroup(d) => Some(&d.name),
            Definition::ModuleCompliance(d) => Some(&d.name),
            Definition::AgentCapabilities(d) => Some(&d.name),
            Definition::MacroDefinition(d) => Some(&d.name),
            Definition::Error(_) => None,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            Definition::ObjectType(d) => d.span,
            Definition::ModuleIdentity(d) => d.span,
            Definition::ObjectIdentity(d) => d.span,
            Definition::NotificationType(d) => d.span,
            Definition::TrapType(d) => d.span,
            Definition::TextualConvention(d) => d.span,
            Definition::TypeAssignment(d) => d.span,
            Definition::ValueAssignment(d) => d.span,
            Definition::ObjectGroup(d) => d.span,
            Definition::NotificationGroup(d) => d.span,
            Definition::ModuleCompliance(d) => d.span,
            Definition::AgentCapabilities(d) => d.span,
            Definition::MacroDefinition(d) => d.span,
            Definition::Error(d) => d.span,
        }
    }
}

/// OBJECT-TYPE macro invocation (SMIv1/v2).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub oid_assignment: OidAssignment,
}

/// MODULE-IDENTITY macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleIdentityDef {
    pub name: Ident,
    pub span: Span,
    pub last_updated: QuotedString,
    pub organization: QuotedString,
    pub contact_info: QuotedString,
    pub description: QuotedString,
    pub revisions: Vec<RevisionClause>,
    pub oid_assignment: OidAssignment,
}

/// OBJECT-IDENTITY macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentityDef {
    pub name: Ident,
    pub span: Span,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid_assignment: OidAssignment,
}

/// NOTIFICATION-TYPE macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationTypeDef {
    pub name: Ident,
    pub span: Span,
    pub objects: Vec<Ident>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid_assignment: OidAssignment,
}

/// TRAP-TYPE macro invocation (SMIv1).
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAssignmentDef {
    pub name: Ident,
    pub span: Span,
    pub syntax: TypeSyntax,
}

/// OID value assignment (name OBJECT IDENTIFIER ::= { ... }).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueAssignmentDef {
    pub name: Ident,
    pub span: Span,
    pub oid_assignment: OidAssignment,
}

/// OBJECT-GROUP macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectGroupDef {
    pub name: Ident,
    pub span: Span,
    pub objects: Vec<Ident>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid_assignment: OidAssignment,
}

/// NOTIFICATION-GROUP macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationGroupDef {
    pub name: Ident,
    pub span: Span,
    pub notifications: Vec<Ident>,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub oid_assignment: OidAssignment,
}

/// MODULE-COMPLIANCE macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleComplianceDef {
    pub name: Ident,
    pub span: Span,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub modules: Vec<ComplianceModule>,
    pub oid_assignment: OidAssignment,
}

/// A MODULE clause within MODULE-COMPLIANCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceModule {
    pub module_name: Option<Ident>,
    pub module_oid: Option<OidAssignment>,
    pub mandatory_groups: Vec<Ident>,
    pub compliances: Vec<Compliance>,
    pub span: Span,
}

/// A GROUP or OBJECT refinement in MODULE-COMPLIANCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compliance {
    Group(ComplianceGroup),
    Object(ComplianceObject),
}

/// GROUP clause within MODULE-COMPLIANCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceGroup {
    pub group: Ident,
    pub description: QuotedString,
    pub span: Span,
}

/// OBJECT refinement within MODULE-COMPLIANCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceObject {
    pub object: Ident,
    pub syntax: Option<SyntaxClause>,
    pub write_syntax: Option<SyntaxClause>,
    pub min_access: Option<AccessClause>,
    pub description: QuotedString,
    pub span: Span,
}

/// AGENT-CAPABILITIES macro invocation (SMIv2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCapabilitiesDef {
    pub name: Ident,
    pub span: Span,
    pub product_release: QuotedString,
    pub status: StatusClause,
    pub description: QuotedString,
    pub reference: Option<QuotedString>,
    pub supports: Vec<SupportsModule>,
    pub oid_assignment: OidAssignment,
}

/// A SUPPORTS clause within AGENT-CAPABILITIES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportsModule {
    pub module_name: Ident,
    pub module_oid: Option<OidAssignment>,
    pub includes: Vec<Ident>,
    pub variations: Vec<Variation>,
    pub span: Span,
}

/// A VARIATION clause within AGENT-CAPABILITIES.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDefinitionDef {
    pub name: Ident,
    pub span: Span,
}

/// A parse error from which the parser recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDef {
    pub span: Span,
    pub message: String,
}
