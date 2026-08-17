//! AST types for each kind of MIB module definition.
//!
//! Each struct corresponds to a specific SMI macro invocation or assignment
//! form. The [`Definition`] enum wraps all of them into a single tagged union
//! for storage in [`super::Module::body`].

use super::common::{Ident, QuotedString};
use super::oid::OidAssignment;
use super::syntax::*;
use crate::source::SourceRange;

/// A top-level construct in a MIB module body.
///
/// Each variant corresponds to an SMI macro invocation, type/value
/// assignment, or a recovered parse error.
#[derive(Debug, PartialEq, Eq)]
pub enum Definition {
    /// OBJECT-TYPE macro (SMIv1/v2).
    ObjectType(Box<ObjectTypeDef>),
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
            pub fn span(&self) -> SourceRange {
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
    /// Object name (the identifier before `OBJECT-TYPE`).
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// SYNTAX clause.
    pub syntax: Option<SyntaxClause>,
    /// UNITS clause.
    pub units: Option<QuotedString>,
    /// ACCESS or MAX-ACCESS clause.
    pub access: Option<AccessClause>,
    /// STATUS clause.
    pub status: Option<StatusClause>,
    /// DESCRIPTION clause.
    pub description: Option<QuotedString>,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// INDEX clause (mutually exclusive with `augments`).
    pub index: Option<IndexClause>,
    /// AUGMENTS clause (mutually exclusive with `index`).
    pub augments: Option<AugmentsClause>,
    /// DEFVAL clause.
    pub defval: Option<DefValClause>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// MODULE-IDENTITY macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleIdentityDef {
    /// Object name (the identifier before `MODULE-IDENTITY`).
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// LAST-UPDATED clause (timestamp string).
    pub last_updated: QuotedString,
    /// ORGANIZATION clause.
    pub organization: QuotedString,
    /// CONTACT-INFO clause.
    pub contact_info: QuotedString,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// REVISION clauses (newest first by convention).
    pub revisions: Vec<RevisionClause>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// OBJECT-IDENTITY macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectIdentityDef {
    /// Object name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// NOTIFICATION-TYPE macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct NotificationTypeDef {
    /// Notification name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// OBJECTS clause listing associated varbinds.
    pub objects: Vec<Ident>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// TRAP-TYPE macro invocation (SMIv1).
#[derive(Debug, PartialEq, Eq)]
pub struct TrapTypeDef {
    /// Trap name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// ENTERPRISE clause naming the enterprise OID.
    pub enterprise: Ident,
    /// VARIABLES clause listing associated varbinds.
    pub variables: Vec<Ident>,
    /// Optional DESCRIPTION clause.
    pub description: Option<QuotedString>,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// Numeric trap value from the `::= N` assignment.
    pub trap_number: u32,
}

/// TEXTUAL-CONVENTION definition (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct TextualConventionDef {
    /// Type name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// Optional DISPLAY-HINT clause.
    pub display_hint: Option<QuotedString>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// SYNTAX clause defining the underlying type.
    pub syntax: SyntaxClause,
}

/// Plain type assignment (`TypeName ::= TypeSyntax`).
#[derive(Debug, PartialEq, Eq)]
pub struct TypeAssignmentDef {
    /// Type name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// The type expression on the right-hand side.
    pub syntax: TypeSyntax,
}

/// OID value assignment (`name OBJECT IDENTIFIER ::= { ... }`).
#[derive(Debug, PartialEq, Eq)]
pub struct ValueAssignmentDef {
    /// Object name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// OID value assignment.
    pub oid: OidAssignment,
}

/// OBJECT-GROUP macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectGroupDef {
    /// Group name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// OBJECTS clause listing member objects.
    pub objects: Vec<Ident>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// NOTIFICATION-GROUP macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct NotificationGroupDef {
    /// Group name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// NOTIFICATIONS clause listing member notifications.
    pub notifications: Vec<Ident>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// MODULE-COMPLIANCE macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleComplianceDef {
    /// Compliance statement name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// MODULE clauses specifying compliance requirements.
    pub modules: Vec<ComplianceModule>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// A MODULE clause within [`ModuleComplianceDef`].
#[derive(Debug, PartialEq, Eq)]
pub struct ComplianceModule {
    /// Module name, or `None` for the current module.
    pub module_name: Option<Ident>,
    /// Optional OID identifying the module.
    pub module_oid: Option<OidAssignment>,
    /// MANDATORY-GROUPS clause.
    pub mandatory_groups: Vec<Ident>,
    /// GROUP and OBJECT refinements.
    pub compliances: Vec<Compliance>,
    /// Source span covering the entire MODULE clause.
    pub span: SourceRange,
}

/// A GROUP or OBJECT refinement in a [`ComplianceModule`].
#[derive(Debug, PartialEq, Eq)]
pub enum Compliance {
    /// A conditionally required group.
    Group(ComplianceGroup),
    /// An object with refined syntax, access, or write-syntax.
    Object(Box<ComplianceObject>),
}

/// GROUP clause within MODULE-COMPLIANCE.
#[derive(Debug, PartialEq, Eq)]
pub struct ComplianceGroup {
    /// The group being referenced.
    pub group: Ident,
    /// DESCRIPTION clause explaining the condition.
    pub description: QuotedString,
    /// Source span covering the entire GROUP clause.
    pub span: SourceRange,
}

/// OBJECT refinement within MODULE-COMPLIANCE.
#[derive(Debug, PartialEq, Eq)]
pub struct ComplianceObject {
    /// The object being refined.
    pub object: Ident,
    /// Optional refined SYNTAX.
    pub syntax: Option<SyntaxClause>,
    /// Optional refined WRITE-SYNTAX.
    pub write_syntax: Option<SyntaxClause>,
    /// Optional MIN-ACCESS clause.
    pub min_access: Option<AccessClause>,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Source span covering the entire OBJECT clause.
    pub span: SourceRange,
}

/// AGENT-CAPABILITIES macro invocation (SMIv2).
#[derive(Debug, PartialEq, Eq)]
pub struct AgentCapabilitiesDef {
    /// Capabilities name.
    pub name: Ident,
    /// Source span of the entire definition.
    pub span: SourceRange,
    /// PRODUCT-RELEASE clause.
    pub product_release: QuotedString,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Optional REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// SUPPORTS clauses listing supported modules.
    pub supports: Vec<SupportsModule>,
    /// OID value assignment (`::= { ... }`).
    pub oid: OidAssignment,
}

/// A SUPPORTS clause within [`AgentCapabilitiesDef`].
#[derive(Debug, PartialEq, Eq)]
pub struct SupportsModule {
    /// Name of the supported module.
    pub module_name: Ident,
    /// Optional OID identifying the module.
    pub module_oid: Option<OidAssignment>,
    /// INCLUDES clause listing supported groups.
    pub includes: Vec<Ident>,
    /// VARIATION clauses for individual objects.
    pub variations: Vec<Variation>,
    /// Source span covering the entire SUPPORTS clause.
    pub span: SourceRange,
}

/// A VARIATION clause within [`SupportsModule`].
#[derive(Debug, PartialEq, Eq)]
pub struct Variation {
    /// Name of the object being varied.
    pub name: Ident,
    /// Optional refined SYNTAX.
    pub syntax: Option<SyntaxClause>,
    /// Optional refined WRITE-SYNTAX.
    pub write_syntax: Option<SyntaxClause>,
    /// Optional ACCESS override.
    pub access: Option<AccessClause>,
    /// CREATION-REQUIRES clause listing required columns.
    pub creation_requires: Vec<Ident>,
    /// Optional DEFVAL clause.
    pub defval: Option<DefValClause>,
    /// DESCRIPTION clause.
    pub description: QuotedString,
    /// Source span covering the entire VARIATION clause.
    pub span: SourceRange,
}

/// A MACRO definition whose body was skipped by the lexer.
#[derive(Debug, PartialEq, Eq)]
pub struct MacroDefinitionDef {
    /// Macro name.
    pub name: Ident,
    /// Source span from the name through `END`.
    pub span: SourceRange,
}

/// Placeholder for a definition that failed to parse.
///
/// Created when the parser encounters an error and recovers by
/// scanning forward to the next definition boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorDef {
    /// Source span covering the skipped region.
    pub span: SourceRange,
    /// Diagnostic message describing the parse failure.
    pub message: String,
}
