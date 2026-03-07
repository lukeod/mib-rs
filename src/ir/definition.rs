use crate::types::{Access, AccessKeyword, BaseType, Span, Status};

use super::oid::OidAssignment;
use super::syntax::{DefVal, TypeSyntax};

/// A normalized MIB definition. SMIv1 and SMIv2 forms are unified where
/// appropriate (e.g. TRAP-TYPE and NOTIFICATION-TYPE become Notification).
#[derive(Debug, Clone)]
pub enum Definition {
    ObjectType(ObjectType),
    ModuleIdentity(ModuleIdentity),
    ObjectIdentity(ObjectIdentity),
    Notification(Notification),
    TypeDef(TypeDef),
    ValueAssignment(ValueAssignment),
    ObjectGroup(ObjectGroup),
    NotificationGroup(NotificationGroup),
    ModuleCompliance(ModuleCompliance),
    AgentCapabilities(AgentCapabilities),
}

impl Definition {
    pub fn name(&self) -> &str {
        match self {
            Definition::ObjectType(d) => &d.name,
            Definition::ModuleIdentity(d) => &d.name,
            Definition::ObjectIdentity(d) => &d.name,
            Definition::Notification(d) => &d.name,
            Definition::TypeDef(d) => &d.name,
            Definition::ValueAssignment(d) => &d.name,
            Definition::ObjectGroup(d) => &d.name,
            Definition::NotificationGroup(d) => &d.name,
            Definition::ModuleCompliance(d) => &d.name,
            Definition::AgentCapabilities(d) => &d.name,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            Definition::ObjectType(d) => d.span,
            Definition::ModuleIdentity(d) => d.span,
            Definition::ObjectIdentity(d) => d.span,
            Definition::Notification(d) => d.span,
            Definition::TypeDef(d) => d.span,
            Definition::ValueAssignment(d) => d.span,
            Definition::ObjectGroup(d) => d.span,
            Definition::NotificationGroup(d) => d.span,
            Definition::ModuleCompliance(d) => d.span,
            Definition::AgentCapabilities(d) => d.span,
        }
    }

    pub fn oid(&self) -> Option<&OidAssignment> {
        match self {
            Definition::ObjectType(d) => Some(&d.oid),
            Definition::ModuleIdentity(d) => Some(&d.oid),
            Definition::ObjectIdentity(d) => Some(&d.oid),
            Definition::Notification(d) => d.oid.as_ref(),
            Definition::TypeDef(_) => None,
            Definition::ValueAssignment(d) => Some(&d.oid),
            Definition::ObjectGroup(d) => Some(&d.oid),
            Definition::NotificationGroup(d) => Some(&d.oid),
            Definition::ModuleCompliance(d) => Some(&d.oid),
            Definition::AgentCapabilities(d) => Some(&d.oid),
        }
    }
}

/// OBJECT-TYPE definition.
#[derive(Debug, Clone)]
pub struct ObjectType {
    pub name: String,
    pub span: Span,
    pub syntax: TypeSyntax,
    pub units: String,
    pub access: Access,
    pub access_keyword: AccessKeyword,
    pub status: Status,
    pub description: String,
    pub has_description: bool,
    pub reference: String,
    pub index: Vec<IndexItem>,
    pub augments: String,
    pub defval: Option<DefVal>,
    pub oid: OidAssignment,

    pub syntax_span: Span,
    pub access_span: Span,
    pub status_span: Span,
    pub description_span: Span,
    pub units_span: Span,
    pub reference_span: Span,
    pub index_span: Span,
    pub augments_span: Span,
    pub defval_span: Span,
}

/// An entry in an OBJECT-TYPE INDEX clause.
#[derive(Debug, Clone)]
pub struct IndexItem {
    pub implied: bool,
    pub object: String,
    pub span: Span,
}

/// MODULE-IDENTITY definition.
#[derive(Debug, Clone)]
pub struct ModuleIdentity {
    pub name: String,
    pub span: Span,
    pub last_updated: String,
    pub organization: String,
    pub contact_info: String,
    pub description: String,
    pub revisions: Vec<Revision>,
    pub oid: OidAssignment,
}

/// A REVISION clause within a MODULE-IDENTITY.
#[derive(Debug, Clone)]
pub struct Revision {
    pub date: String,
    pub description: String,
    pub span: Span,
}

/// OBJECT-IDENTITY definition.
#[derive(Debug, Clone)]
pub struct ObjectIdentity {
    pub name: String,
    pub span: Span,
    pub status: Status,
    pub description: String,
    pub reference: String,
    pub oid: OidAssignment,
}

/// Unified representation of TRAP-TYPE (SMIv1) and NOTIFICATION-TYPE (SMIv2).
#[derive(Debug, Clone)]
pub struct Notification {
    pub name: String,
    pub span: Span,
    pub objects: Vec<String>,
    pub status: Status,
    pub description: String,
    pub has_description: bool,
    pub reference: String,
    /// SMIv1 TRAP-TYPE fields. None for NOTIFICATION-TYPE.
    pub trap_info: Option<TrapInfo>,
    /// None for TRAP-TYPE; its OID is derived from enterprise + trap number.
    pub oid: Option<OidAssignment>,
}

/// Fields specific to SMIv1 TRAP-TYPE definitions.
#[derive(Debug, Clone)]
pub struct TrapInfo {
    pub enterprise: String,
    pub trap_number: u32,
}

/// Represents both TEXTUAL-CONVENTION and simple type assignments.
#[derive(Debug, Clone)]
pub struct TypeDef {
    pub name: String,
    pub span: Span,
    pub syntax: TypeSyntax,
    /// Overrides the base type derived from Syntax. Some SMI base types
    /// like IpAddress are syntactically OCTET STRING (SIZE 4) but have
    /// distinct semantic base types.
    pub base_type: Option<BaseType>,
    pub display_hint: String,
    pub status: Status,
    pub description: String,
    pub reference: String,
    pub is_textual_convention: bool,

    pub syntax_span: Span,
    pub status_span: Span,
    pub description_span: Span,
    pub reference_span: Span,
    pub display_hint_span: Span,
}

/// Plain OID value assignment.
#[derive(Debug, Clone)]
pub struct ValueAssignment {
    pub name: String,
    pub span: Span,
    pub oid: OidAssignment,
    pub description: String,
    pub reference: String,
}

/// OBJECT-GROUP definition.
#[derive(Debug, Clone)]
pub struct ObjectGroup {
    pub name: String,
    pub span: Span,
    pub objects: Vec<String>,
    pub status: Status,
    pub description: String,
    pub reference: String,
    pub oid: OidAssignment,
}

/// NOTIFICATION-GROUP definition.
#[derive(Debug, Clone)]
pub struct NotificationGroup {
    pub name: String,
    pub span: Span,
    pub notifications: Vec<String>,
    pub status: Status,
    pub description: String,
    pub reference: String,
    pub oid: OidAssignment,
}

/// MODULE-COMPLIANCE definition.
#[derive(Debug, Clone)]
pub struct ModuleCompliance {
    pub name: String,
    pub span: Span,
    pub status: Status,
    pub description: String,
    pub reference: String,
    pub modules: Vec<ComplianceModule>,
    pub oid: OidAssignment,
}

/// A MODULE clause in MODULE-COMPLIANCE.
#[derive(Debug, Clone)]
pub struct ComplianceModule {
    /// Empty when referring to the current module.
    pub module_name: String,
    pub mandatory_groups: Vec<String>,
    pub groups: Vec<ComplianceGroup>,
    pub objects: Vec<ComplianceObject>,
    pub span: Span,
}

/// GROUP clause within MODULE-COMPLIANCE.
#[derive(Debug, Clone)]
pub struct ComplianceGroup {
    pub group: String,
    pub description: String,
    pub span: Span,
}

/// OBJECT refinement within MODULE-COMPLIANCE.
#[derive(Debug, Clone)]
pub struct ComplianceObject {
    pub object: String,
    pub syntax: Option<TypeSyntax>,
    pub write_syntax: Option<TypeSyntax>,
    pub min_access: Option<Access>,
    pub description: String,
    pub span: Span,
}

/// AGENT-CAPABILITIES definition.
#[derive(Debug, Clone)]
pub struct AgentCapabilities {
    pub name: String,
    pub span: Span,
    pub product_release: String,
    pub status: Status,
    pub description: String,
    pub reference: String,
    pub supports: Vec<SupportsModule>,
    pub oid: OidAssignment,
}

/// A SUPPORTS clause in AGENT-CAPABILITIES.
#[derive(Debug, Clone)]
pub struct SupportsModule {
    pub module_name: String,
    pub includes: Vec<String>,
    pub variations: Vec<Variation>,
    pub span: Span,
}

/// A VARIATION clause in AGENT-CAPABILITIES.
#[derive(Debug, Clone)]
pub struct Variation {
    pub name: String,
    pub syntax: Option<TypeSyntax>,
    pub write_syntax: Option<TypeSyntax>,
    pub access: Option<Access>,
    pub creation_requires: Vec<String>,
    pub defval: Option<DefVal>,
    pub description: String,
    pub span: Span,
}
