//! IR definition types for all MIB constructs.
//!
//! These types mirror the AST definitions but are language-independent.
//! SMIv1 and SMIv2 forms are unified, and all string-valued clauses use
//! `String` (empty for absent clauses) rather than `Option<QuotedString>`.

use crate::types::{Access, AccessKeyword, BaseType, Span, Status};

use super::oid::OidAssignment;
use super::syntax::{DefVal, TypeSyntax};

/// A normalized MIB definition.
///
/// SMIv1 and SMIv2 forms are unified where appropriate (e.g. `TRAP-TYPE`
/// and `NOTIFICATION-TYPE` both become [`Notification`]).
#[derive(Debug, Clone)]
pub enum Definition {
    /// `OBJECT-TYPE` definition.
    ObjectType(ObjectType),
    /// `MODULE-IDENTITY` definition.
    ModuleIdentity(ModuleIdentity),
    /// `OBJECT-IDENTITY` definition.
    ObjectIdentity(ObjectIdentity),
    /// `NOTIFICATION-TYPE` (SMIv2) or `TRAP-TYPE` (SMIv1).
    Notification(Notification),
    /// `TEXTUAL-CONVENTION` or plain type assignment.
    TypeDef(TypeDef),
    /// OID value assignment.
    ValueAssignment(ValueAssignment),
    /// `OBJECT-GROUP` definition.
    ObjectGroup(ObjectGroup),
    /// `NOTIFICATION-GROUP` definition.
    NotificationGroup(NotificationGroup),
    /// `MODULE-COMPLIANCE` definition.
    ModuleCompliance(ModuleCompliance),
    /// `AGENT-CAPABILITIES` definition.
    AgentCapabilities(AgentCapabilities),
}

impl Definition {
    /// Returns the definition's name.
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

    /// Returns the source span of this definition.
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

    /// Returns the OID assignment, if this definition has one.
    ///
    /// [`TypeDef`] definitions have no OID. [`Notification`] OIDs are
    /// optional (TRAP-TYPE derives its OID from enterprise + trap number).
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

/// `OBJECT-TYPE` definition.
#[derive(Debug, Clone)]
pub struct ObjectType {
    /// Object name (the identifier before `OBJECT-TYPE`).
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// The `SYNTAX` clause type expression.
    pub syntax: TypeSyntax,
    /// The `UNITS` clause value. Empty if not specified.
    pub units: String,
    /// Resolved access level (read-only, read-write, etc.).
    pub access: Access,
    /// Which keyword was used: `ACCESS`, `MAX-ACCESS`, or `MIN-ACCESS`.
    pub access_keyword: AccessKeyword,
    /// The `STATUS` clause value.
    pub status: Status,
    /// The `DESCRIPTION` clause text. Empty if not specified.
    pub description: String,
    /// True if the `DESCRIPTION` clause was present (even if empty).
    pub has_description: bool,
    /// The `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// `INDEX` clause entries for table row objects.
    pub index: Vec<IndexItem>,
    /// Name of the table row this object augments, if any.
    pub augments: String,
    /// The `DEFVAL` clause value, if present.
    pub defval: Option<DefVal>,
    /// The OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,

    /// Source span of the `SYNTAX` clause.
    pub syntax_span: Span,
    /// Source span of the `ACCESS`/`MAX-ACCESS` clause.
    pub access_span: Span,
    /// Source span of the `STATUS` clause.
    pub status_span: Span,
    /// Source span of the `DESCRIPTION` clause.
    pub description_span: Span,
    /// Source span of the `UNITS` clause.
    pub units_span: Span,
    /// Source span of the `REFERENCE` clause.
    pub reference_span: Span,
    /// Source span of the `INDEX` clause.
    pub index_span: Span,
    /// Source span of the `AUGMENTS` clause.
    pub augments_span: Span,
    /// Source span of the `DEFVAL` clause.
    pub defval_span: Span,
}

/// An entry in an `OBJECT-TYPE` `INDEX` clause.
#[derive(Debug, Clone)]
pub struct IndexItem {
    /// True if this index object uses the `IMPLIED` keyword.
    pub implied: bool,
    /// Name of the index object.
    pub object: String,
    /// Source span of this index entry.
    pub span: Span,
}

/// `MODULE-IDENTITY` definition.
#[derive(Debug, Clone)]
pub struct ModuleIdentity {
    /// Module identity name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// `LAST-UPDATED` date in ExtUTCTime format.
    pub last_updated: String,
    /// `ORGANIZATION` clause text.
    pub organization: String,
    /// `CONTACT-INFO` clause text.
    pub contact_info: String,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// `REVISION` clauses in source order (should be reverse chronological).
    pub revisions: Vec<Revision>,
    /// The OID value assignment.
    pub oid: OidAssignment,
}

/// A `REVISION` clause within a [`ModuleIdentity`].
#[derive(Debug, Clone)]
pub struct Revision {
    /// Revision date in ExtUTCTime format.
    pub date: String,
    /// Revision description text.
    pub description: String,
    /// Source span of this revision clause.
    pub span: Span,
}

/// `OBJECT-IDENTITY` definition.
#[derive(Debug, Clone)]
pub struct ObjectIdentity {
    /// Object identity name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// The OID value assignment.
    pub oid: OidAssignment,
}

/// Unified representation of `TRAP-TYPE` (SMIv1) and `NOTIFICATION-TYPE` (SMIv2).
#[derive(Debug, Clone)]
pub struct Notification {
    /// Notification name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// `OBJECTS` (SMIv2) or `VARIABLES` (SMIv1) associated with this notification.
    pub objects: Vec<String>,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text. Empty if not specified.
    pub description: String,
    /// True if the `DESCRIPTION` clause was present (even if empty).
    pub has_description: bool,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// SMIv1 `TRAP-TYPE` fields. `None` for `NOTIFICATION-TYPE`.
    pub trap_info: Option<TrapInfo>,
    /// `None` for `TRAP-TYPE`; its OID is derived from enterprise + trap number.
    pub oid: Option<OidAssignment>,
}

/// Fields specific to SMIv1 `TRAP-TYPE` definitions.
#[derive(Debug, Clone)]
pub struct TrapInfo {
    /// Name of the `ENTERPRISE` object.
    pub enterprise: String,
    /// Numeric trap identifier from the `::= number` assignment.
    pub trap_number: u32,
}

/// Represents both `TEXTUAL-CONVENTION` and simple type assignments.
///
/// Plain type assignments (`TypeName ::= ...`) and `TEXTUAL-CONVENTION`
/// macro invocations are both represented by this type. The
/// [`is_textual_convention`](Self::is_textual_convention) field distinguishes them.
#[derive(Debug, Clone)]
pub struct TypeDef {
    /// Type name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// The type expression (`SYNTAX` clause for TCs, right-hand side for assignments).
    pub syntax: TypeSyntax,
    /// Overrides the base type derived from syntax. Some SMI base types
    /// like `IpAddress` are syntactically `OCTET STRING (SIZE 4)` but have
    /// distinct semantic base types.
    pub base_type: Option<BaseType>,
    /// `DISPLAY-HINT` clause text. Empty if not specified.
    pub display_hint: String,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text. Empty if not specified.
    pub description: String,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// True if this was defined using the `TEXTUAL-CONVENTION` macro.
    pub is_textual_convention: bool,

    /// Source span of the `SYNTAX` clause.
    pub syntax_span: Span,
    /// Source span of the `STATUS` clause.
    pub status_span: Span,
    /// Source span of the `DESCRIPTION` clause.
    pub description_span: Span,
    /// Source span of the `REFERENCE` clause.
    pub reference_span: Span,
    /// Source span of the `DISPLAY-HINT` clause.
    pub display_hint_span: Span,
}

/// Plain OID value assignment (`name OBJECT IDENTIFIER ::= { ... }`).
#[derive(Debug, Clone)]
pub struct ValueAssignment {
    /// Object name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// The OID value assignment.
    pub oid: OidAssignment,
    /// Description text. Empty if not supplied by programmatic IR.
    pub description: String,
    /// Reference text. Empty if not supplied by programmatic IR.
    pub reference: String,
}

/// `OBJECT-GROUP` definition.
#[derive(Debug, Clone)]
pub struct ObjectGroup {
    /// Group name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// Names of objects in this group.
    pub objects: Vec<String>,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// The OID value assignment.
    pub oid: OidAssignment,
}

/// `NOTIFICATION-GROUP` definition.
#[derive(Debug, Clone)]
pub struct NotificationGroup {
    /// Group name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// Names of notifications in this group.
    pub notifications: Vec<String>,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// The OID value assignment.
    pub oid: OidAssignment,
}

/// `MODULE-COMPLIANCE` definition.
#[derive(Debug, Clone)]
pub struct ModuleCompliance {
    /// Compliance name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// `MODULE` clauses specifying compliance requirements.
    pub modules: Vec<ComplianceModule>,
    /// The OID value assignment.
    pub oid: OidAssignment,
}

/// A `MODULE` clause in [`ModuleCompliance`].
#[derive(Debug, Clone)]
pub struct ComplianceModule {
    /// Target module name. Empty when referring to the current module.
    pub module_name: String,
    /// Names of mandatory conformance groups.
    pub mandatory_groups: Vec<String>,
    /// Conditionally required `GROUP` clauses.
    pub groups: Vec<ComplianceGroup>,
    /// `OBJECT` refinement clauses.
    pub objects: Vec<ComplianceObject>,
    /// Source span of this `MODULE` clause.
    pub span: Span,
}

/// `GROUP` clause within [`ModuleCompliance`].
#[derive(Debug, Clone)]
pub struct ComplianceGroup {
    /// Name of the conditionally required group.
    pub group: String,
    /// `DESCRIPTION` clause text explaining the condition.
    pub description: String,
    /// Source span of this `GROUP` clause.
    pub span: Span,
}

/// `OBJECT` refinement within [`ModuleCompliance`].
#[derive(Debug, Clone)]
pub struct ComplianceObject {
    /// Name of the refined object.
    pub object: String,
    /// Refined `SYNTAX`, if specified.
    pub syntax: Option<TypeSyntax>,
    /// Refined `WRITE-SYNTAX`, if specified.
    pub write_syntax: Option<TypeSyntax>,
    /// Minimum required access level, if specified.
    pub min_access: Option<Access>,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// Source span of this `OBJECT` clause.
    pub span: Span,
}

/// `AGENT-CAPABILITIES` definition.
#[derive(Debug, Clone)]
pub struct AgentCapabilities {
    /// Agent capabilities name.
    pub name: String,
    /// Source span of the entire definition.
    pub span: Span,
    /// `PRODUCT-RELEASE` clause text.
    pub product_release: String,
    /// `STATUS` clause value.
    pub status: Status,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// `REFERENCE` clause text. Empty if not specified.
    pub reference: String,
    /// `SUPPORTS` clauses listing supported modules.
    pub supports: Vec<SupportsModule>,
    /// The OID value assignment.
    pub oid: OidAssignment,
}

/// A `SUPPORTS` clause in [`AgentCapabilities`].
#[derive(Debug, Clone)]
pub struct SupportsModule {
    /// Name of the supported module.
    pub module_name: String,
    /// Names of included conformance groups.
    pub includes: Vec<String>,
    /// Object/notification variations.
    pub variations: Vec<Variation>,
    /// Source span of this `SUPPORTS` clause.
    pub span: Span,
}

/// A `VARIATION` clause in [`AgentCapabilities`].
#[derive(Debug, Clone)]
pub struct Variation {
    /// Name of the varied object or notification.
    pub name: String,
    /// Restricted `SYNTAX`, if specified.
    pub syntax: Option<TypeSyntax>,
    /// Restricted `WRITE-SYNTAX`, if specified.
    pub write_syntax: Option<TypeSyntax>,
    /// Restricted access level, if specified.
    pub access: Option<Access>,
    /// Objects required for row creation.
    pub creation_requires: Vec<String>,
    /// Default value override, if specified.
    pub defval: Option<DefVal>,
    /// `DESCRIPTION` clause text.
    pub description: String,
    /// Source span of this `VARIATION` clause.
    pub span: Span,
}
