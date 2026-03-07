use crate::types::Span;

/// A lexed unit with its classification and source location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// Classifies a token (punctuation, keyword, literal, etc.).
///
/// Variant ordering is load-bearing: category predicates rely on contiguous
/// ranges. New keyword variants must preserve range boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TokenKind {
    // -- Special --
    Error,
    Eof,
    ForbiddenKeyword,
    Comment,

    // -- Identifiers --
    UppercaseIdent,
    LowercaseIdent,

    // -- Literals --
    Number,
    NegativeNumber,
    QuotedString,
    HexString,
    BinString,

    // -- Single-character punctuation --
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Semicolon,
    Comma,
    Dot,
    Pipe,
    Minus,

    // -- Multi-character operators --
    DotDot,
    ColonColonEqual,

    // -- Structural keywords (first keyword range) --
    KwDefinitions,
    KwBegin,
    KwEnd,
    KwImports,
    KwExports,
    KwFrom,
    KwObject,
    KwIdentifier,
    KwSequence,
    KwOf,
    KwChoice,
    KwMacro,

    // -- Clause keywords --
    KwSyntax,
    KwMaxAccess,
    KwMinAccess,
    KwAccess,
    KwStatus,
    KwDescription,
    KwReference,
    KwIndex,
    KwDefval,
    KwAugments,
    KwUnits,
    KwDisplayHint,
    KwObjects,
    KwNotifications,
    KwModule,
    KwMandatoryGroups,
    KwGroup,
    KwWriteSyntax,
    KwProductRelease,
    KwSupports,
    KwIncludes,
    KwVariation,
    KwCreationRequires,
    KwRevision,
    KwLastUpdated,
    KwOrganization,
    KwContactInfo,
    KwImplied,
    KwSize,
    KwEnterprise,
    KwVariables,

    // -- MACRO invocation keywords --
    KwModuleIdentity,
    KwModuleCompliance,
    KwObjectGroup,
    KwNotificationGroup,
    KwAgentCapabilities,
    KwObjectType,
    KwObjectIdentity,
    KwNotificationType,
    KwTextualConvention,
    KwTrapType,

    // -- Type keywords --
    KwInteger,
    KwUnsigned32,
    KwCounter32,
    KwCounter64,
    KwGauge32,
    KwIpAddress,
    KwOpaque,
    KwTimeTicks,
    KwBits,
    KwOctet,
    KwString,

    // -- SMIv1 type aliases --
    KwCounter,
    KwGauge,
    KwNetworkAddress,

    // -- ASN.1 tag keywords --
    KwApplication,
    KwImplicit,
    KwUniversal,

    // -- Status/Access value keywords (last keyword range) --
    KwCurrent,
    KwDeprecated,
    KwObsolete,
    KwMandatory,
    KwOptional,
    KwReadOnly,
    KwReadWrite,
    KwReadCreate,
    KwWriteOnly,
    KwNotAccessible,
    KwAccessibleForNotify,
    KwNotImplemented,
}

impl TokenKind {
    fn in_range(self, lo: TokenKind, hi: TokenKind) -> bool {
        (self as u8) >= (lo as u8) && (self as u8) <= (hi as u8)
    }

    /// Any keyword token (structural, clause, macro, type, tag, status/access).
    pub fn is_keyword(self) -> bool {
        self.in_range(TokenKind::KwDefinitions, TokenKind::KwNotImplemented)
    }

    /// UppercaseIdent or LowercaseIdent.
    pub fn is_identifier(self) -> bool {
        matches!(self, TokenKind::UppercaseIdent | TokenKind::LowercaseIdent)
    }

    /// Built-in type keywords: INTEGER through NetworkAddress.
    pub fn is_type_keyword(self) -> bool {
        self.in_range(TokenKind::KwInteger, TokenKind::KwNetworkAddress)
    }

    /// MACRO invocation keywords: MODULE-IDENTITY through TRAP-TYPE.
    pub fn is_macro_keyword(self) -> bool {
        self.in_range(TokenKind::KwModuleIdentity, TokenKind::KwTrapType)
    }

    /// Clause keywords: SYNTAX through VARIABLES.
    pub fn is_clause_keyword(self) -> bool {
        self.in_range(TokenKind::KwSyntax, TokenKind::KwVariables)
    }

    /// ASN.1 tag keywords: APPLICATION, IMPLICIT, UNIVERSAL.
    pub fn is_tag_keyword(self) -> bool {
        self.in_range(TokenKind::KwApplication, TokenKind::KwUniversal)
    }

    /// Status or access value keywords: current through not-implemented.
    pub fn is_status_access_keyword(self) -> bool {
        self.in_range(TokenKind::KwCurrent, TokenKind::KwNotImplemented)
    }

    /// Structural keywords: DEFINITIONS through MACRO.
    pub fn is_structural_keyword(self) -> bool {
        self.in_range(TokenKind::KwDefinitions, TokenKind::KwMacro)
    }

    /// Returns the libsmi-compatible name for this token kind.
    pub fn libsmi_name(self) -> &'static str {
        LIBSMI_NAMES[self as u8 as usize]
    }
}

const LIBSMI_NAMES: &[&str] = &[
    "ERROR",                // Error
    "EOF",                  // Eof
    "FORBIDDEN_KEYWORD",    // ForbiddenKeyword
    "COMMENT",              // Comment
    "UPPERCASE_IDENTIFIER", // UppercaseIdent
    "LOWERCASE_IDENTIFIER", // LowercaseIdent
    "NUMBER",               // Number
    "NEGATIVENUMBER",       // NegativeNumber
    "QUOTED_STRING",        // QuotedString
    "HEX_STRING",           // HexString
    "BIN_STRING",           // BinString
    "LBRACKET",             // LBracket
    "RBRACKET",             // RBracket
    "LBRACE",               // LBrace
    "RBRACE",               // RBrace
    "LPAREN",               // LParen
    "RPAREN",               // RParen
    "COLON",                // Colon
    "SEMICOLON",            // Semicolon
    "COMMA",                // Comma
    "DOT",                  // Dot
    "PIPE",                 // Pipe
    "MINUS",                // Minus
    "DOT_DOT",              // DotDot
    "COLON_COLON_EQUAL",    // ColonColonEqual
    "DEFINITIONS",          // KwDefinitions
    "BEGIN",                // KwBegin
    "END",                  // KwEnd
    "IMPORTS",              // KwImports
    "EXPORTS",              // KwExports
    "FROM",                 // KwFrom
    "OBJECT",               // KwObject
    "IDENTIFIER",           // KwIdentifier
    "SEQUENCE",             // KwSequence
    "OF",                   // KwOf
    "CHOICE",               // KwChoice
    "MACRO",                // KwMacro
    "SYNTAX",               // KwSyntax
    "MAX_ACCESS",           // KwMaxAccess
    "MIN_ACCESS",           // KwMinAccess
    "ACCESS",               // KwAccess
    "STATUS",               // KwStatus
    "DESCRIPTION",          // KwDescription
    "REFERENCE",            // KwReference
    "INDEX",                // KwIndex
    "DEFVAL",               // KwDefval
    "AUGMENTS",             // KwAugments
    "UNITS",                // KwUnits
    "DISPLAY_HINT",         // KwDisplayHint
    "OBJECTS",              // KwObjects
    "NOTIFICATIONS",        // KwNotifications
    "MODULE",               // KwModule
    "MANDATORY_GROUPS",     // KwMandatoryGroups
    "GROUP",                // KwGroup
    "WRITE_SYNTAX",         // KwWriteSyntax
    "PRODUCT_RELEASE",      // KwProductRelease
    "SUPPORTS",             // KwSupports
    "INCLUDES",             // KwIncludes
    "VARIATION",            // KwVariation
    "CREATION_REQUIRES",    // KwCreationRequires
    "REVISION",             // KwRevision
    "LAST_UPDATED",         // KwLastUpdated
    "ORGANIZATION",         // KwOrganization
    "CONTACT_INFO",         // KwContactInfo
    "IMPLIED",              // KwImplied
    "SIZE",                 // KwSize
    "ENTERPRISE",           // KwEnterprise
    "VARIABLES",            // KwVariables
    "MODULE_IDENTITY",      // KwModuleIdentity
    "MODULE_COMPLIANCE",    // KwModuleCompliance
    "OBJECT_GROUP",         // KwObjectGroup
    "NOTIFICATION_GROUP",   // KwNotificationGroup
    "AGENT_CAPABILITIES",   // KwAgentCapabilities
    "OBJECT_TYPE",          // KwObjectType
    "OBJECT_IDENTITY",      // KwObjectIdentity
    "NOTIFICATION_TYPE",    // KwNotificationType
    "TEXTUAL_CONVENTION",   // KwTextualConvention
    "TRAP_TYPE",            // KwTrapType
    "INTEGER",              // KwInteger
    "UNSIGNED32",           // KwUnsigned32
    "COUNTER32",            // KwCounter32
    "COUNTER64",            // KwCounter64
    "GAUGE32",              // KwGauge32
    "IPADDRESS",            // KwIpAddress
    "OPAQUE",               // KwOpaque
    "TIMETICKS",            // KwTimeTicks
    "BITS",                 // KwBits
    "OCTET",                // KwOctet
    "STRING",               // KwString
    "COUNTER",              // KwCounter
    "GAUGE",                // KwGauge
    "NETWORKADDRESS",       // KwNetworkAddress
    "APPLICATION",          // KwApplication
    "IMPLICIT",             // KwImplicit
    "UNIVERSAL",            // KwUniversal
    "CURRENT",              // KwCurrent
    "DEPRECATED",           // KwDeprecated
    "OBSOLETE",             // KwObsolete
    "MANDATORY",            // KwMandatory
    "OPTIONAL",             // KwOptional
    "READ_ONLY",            // KwReadOnly
    "READ_WRITE",           // KwReadWrite
    "READ_CREATE",          // KwReadCreate
    "WRITE_ONLY",           // KwWriteOnly
    "NOT_ACCESSIBLE",       // KwNotAccessible
    "ACCESSIBLE_FOR_NOTIFY", // KwAccessibleForNotify
    "NOT_IMPLEMENTED",      // KwNotImplemented
];

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.libsmi_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libsmi_names_table_complete() {
        // Verify the table has the right number of entries
        assert_eq!(
            LIBSMI_NAMES.len(),
            TokenKind::KwNotImplemented as u8 as usize + 1
        );
    }

    #[test]
    fn keyword_ranges_are_contiguous() {
        assert!(TokenKind::KwDefinitions.is_keyword());
        assert!(TokenKind::KwNotImplemented.is_keyword());
        assert!(TokenKind::KwMacro.is_structural_keyword());
        assert!(!TokenKind::KwSyntax.is_structural_keyword());
        assert!(TokenKind::KwSyntax.is_clause_keyword());
        assert!(TokenKind::KwVariables.is_clause_keyword());
        assert!(!TokenKind::KwModuleIdentity.is_clause_keyword());
        assert!(TokenKind::KwModuleIdentity.is_macro_keyword());
        assert!(TokenKind::KwTrapType.is_macro_keyword());
        assert!(TokenKind::KwInteger.is_type_keyword());
        assert!(TokenKind::KwNetworkAddress.is_type_keyword());
        assert!(TokenKind::KwApplication.is_tag_keyword());
        assert!(TokenKind::KwUniversal.is_tag_keyword());
        assert!(TokenKind::KwCurrent.is_status_access_keyword());
        assert!(TokenKind::KwNotImplemented.is_status_access_keyword());
    }

    #[test]
    fn non_keywords_are_not_keywords() {
        assert!(!TokenKind::Error.is_keyword());
        assert!(!TokenKind::UppercaseIdent.is_keyword());
        assert!(!TokenKind::Number.is_keyword());
        assert!(!TokenKind::LBrace.is_keyword());
        assert!(!TokenKind::ColonColonEqual.is_keyword());
    }

    #[test]
    fn identifier_classification() {
        assert!(TokenKind::UppercaseIdent.is_identifier());
        assert!(TokenKind::LowercaseIdent.is_identifier());
        assert!(!TokenKind::KwObject.is_identifier());
        assert!(!TokenKind::Number.is_identifier());
    }

    #[test]
    fn libsmi_names() {
        assert_eq!(TokenKind::Eof.libsmi_name(), "EOF");
        assert_eq!(TokenKind::KwObjectType.libsmi_name(), "OBJECT_TYPE");
        assert_eq!(
            TokenKind::ColonColonEqual.libsmi_name(),
            "COLON_COLON_EQUAL"
        );
        assert_eq!(TokenKind::KwReadOnly.libsmi_name(), "READ_ONLY");
    }
}
