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

    // -- Structural keywords --
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

    // -- Status/Access value keywords --
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
    /// Any keyword token (structural, clause, macro, type, tag, status/access).
    pub fn is_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwDefinitions as u8)
            && (self as u8) <= (TokenKind::KwNotImplemented as u8)
    }

    /// UppercaseIdent or LowercaseIdent.
    pub fn is_identifier(self) -> bool {
        matches!(self, TokenKind::UppercaseIdent | TokenKind::LowercaseIdent)
    }

    /// Built-in type keywords: INTEGER through NetworkAddress.
    pub fn is_type_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwInteger as u8)
            && (self as u8) <= (TokenKind::KwNetworkAddress as u8)
    }

    /// MACRO invocation keywords: MODULE-IDENTITY through TRAP-TYPE.
    pub fn is_macro_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwModuleIdentity as u8)
            && (self as u8) <= (TokenKind::KwTrapType as u8)
    }

    /// Clause keywords: SYNTAX through VARIABLES.
    pub fn is_clause_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwSyntax as u8)
            && (self as u8) <= (TokenKind::KwVariables as u8)
    }

    /// ASN.1 tag keywords: APPLICATION, IMPLICIT, UNIVERSAL.
    pub fn is_tag_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwApplication as u8)
            && (self as u8) <= (TokenKind::KwUniversal as u8)
    }

    /// Status or access value keywords: current through not-implemented.
    pub fn is_status_access_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwCurrent as u8)
            && (self as u8) <= (TokenKind::KwNotImplemented as u8)
    }

    /// Structural keywords: DEFINITIONS through MACRO.
    pub fn is_structural_keyword(self) -> bool {
        (self as u8) >= (TokenKind::KwDefinitions as u8)
            && (self as u8) <= (TokenKind::KwMacro as u8)
    }

    /// Returns the libsmi-compatible name for this token kind.
    pub fn libsmi_name(self) -> &'static str {
        match self {
            TokenKind::Error => "ERROR",
            TokenKind::Eof => "EOF",
            TokenKind::ForbiddenKeyword => "FORBIDDEN_KEYWORD",
            TokenKind::Comment => "COMMENT",
            TokenKind::UppercaseIdent => "UPPERCASE_IDENTIFIER",
            TokenKind::LowercaseIdent => "LOWERCASE_IDENTIFIER",
            TokenKind::Number => "NUMBER",
            TokenKind::NegativeNumber => "NEGATIVENUMBER",
            TokenKind::QuotedString => "QUOTED_STRING",
            TokenKind::HexString => "HEX_STRING",
            TokenKind::BinString => "BIN_STRING",
            TokenKind::LBracket => "LBRACKET",
            TokenKind::RBracket => "RBRACKET",
            TokenKind::LBrace => "LBRACE",
            TokenKind::RBrace => "RBRACE",
            TokenKind::LParen => "LPAREN",
            TokenKind::RParen => "RPAREN",
            TokenKind::Colon => "COLON",
            TokenKind::Semicolon => "SEMICOLON",
            TokenKind::Comma => "COMMA",
            TokenKind::Dot => "DOT",
            TokenKind::Pipe => "PIPE",
            TokenKind::Minus => "MINUS",
            TokenKind::DotDot => "DOT_DOT",
            TokenKind::ColonColonEqual => "COLON_COLON_EQUAL",
            TokenKind::KwDefinitions => "DEFINITIONS",
            TokenKind::KwBegin => "BEGIN",
            TokenKind::KwEnd => "END",
            TokenKind::KwImports => "IMPORTS",
            TokenKind::KwExports => "EXPORTS",
            TokenKind::KwFrom => "FROM",
            TokenKind::KwObject => "OBJECT",
            TokenKind::KwIdentifier => "IDENTIFIER",
            TokenKind::KwSequence => "SEQUENCE",
            TokenKind::KwOf => "OF",
            TokenKind::KwChoice => "CHOICE",
            TokenKind::KwMacro => "MACRO",
            TokenKind::KwSyntax => "SYNTAX",
            TokenKind::KwMaxAccess => "MAX_ACCESS",
            TokenKind::KwMinAccess => "MIN_ACCESS",
            TokenKind::KwAccess => "ACCESS",
            TokenKind::KwStatus => "STATUS",
            TokenKind::KwDescription => "DESCRIPTION",
            TokenKind::KwReference => "REFERENCE",
            TokenKind::KwIndex => "INDEX",
            TokenKind::KwDefval => "DEFVAL",
            TokenKind::KwAugments => "AUGMENTS",
            TokenKind::KwUnits => "UNITS",
            TokenKind::KwDisplayHint => "DISPLAY_HINT",
            TokenKind::KwObjects => "OBJECTS",
            TokenKind::KwNotifications => "NOTIFICATIONS",
            TokenKind::KwModule => "MODULE",
            TokenKind::KwMandatoryGroups => "MANDATORY_GROUPS",
            TokenKind::KwGroup => "GROUP",
            TokenKind::KwWriteSyntax => "WRITE_SYNTAX",
            TokenKind::KwProductRelease => "PRODUCT_RELEASE",
            TokenKind::KwSupports => "SUPPORTS",
            TokenKind::KwIncludes => "INCLUDES",
            TokenKind::KwVariation => "VARIATION",
            TokenKind::KwCreationRequires => "CREATION_REQUIRES",
            TokenKind::KwRevision => "REVISION",
            TokenKind::KwLastUpdated => "LAST_UPDATED",
            TokenKind::KwOrganization => "ORGANIZATION",
            TokenKind::KwContactInfo => "CONTACT_INFO",
            TokenKind::KwImplied => "IMPLIED",
            TokenKind::KwSize => "SIZE",
            TokenKind::KwEnterprise => "ENTERPRISE",
            TokenKind::KwVariables => "VARIABLES",
            TokenKind::KwModuleIdentity => "MODULE_IDENTITY",
            TokenKind::KwModuleCompliance => "MODULE_COMPLIANCE",
            TokenKind::KwObjectGroup => "OBJECT_GROUP",
            TokenKind::KwNotificationGroup => "NOTIFICATION_GROUP",
            TokenKind::KwAgentCapabilities => "AGENT_CAPABILITIES",
            TokenKind::KwObjectType => "OBJECT_TYPE",
            TokenKind::KwObjectIdentity => "OBJECT_IDENTITY",
            TokenKind::KwNotificationType => "NOTIFICATION_TYPE",
            TokenKind::KwTextualConvention => "TEXTUAL_CONVENTION",
            TokenKind::KwTrapType => "TRAP_TYPE",
            TokenKind::KwInteger => "INTEGER",
            TokenKind::KwUnsigned32 => "UNSIGNED32",
            TokenKind::KwCounter32 => "COUNTER32",
            TokenKind::KwCounter64 => "COUNTER64",
            TokenKind::KwGauge32 => "GAUGE32",
            TokenKind::KwIpAddress => "IPADDRESS",
            TokenKind::KwOpaque => "OPAQUE",
            TokenKind::KwTimeTicks => "TIMETICKS",
            TokenKind::KwBits => "BITS",
            TokenKind::KwOctet => "OCTET",
            TokenKind::KwString => "STRING",
            TokenKind::KwCounter => "COUNTER",
            TokenKind::KwGauge => "GAUGE",
            TokenKind::KwNetworkAddress => "NETWORKADDRESS",
            TokenKind::KwApplication => "APPLICATION",
            TokenKind::KwImplicit => "IMPLICIT",
            TokenKind::KwUniversal => "UNIVERSAL",
            TokenKind::KwCurrent => "CURRENT",
            TokenKind::KwDeprecated => "DEPRECATED",
            TokenKind::KwObsolete => "OBSOLETE",
            TokenKind::KwMandatory => "MANDATORY",
            TokenKind::KwOptional => "OPTIONAL",
            TokenKind::KwReadOnly => "READ_ONLY",
            TokenKind::KwReadWrite => "READ_WRITE",
            TokenKind::KwReadCreate => "READ_CREATE",
            TokenKind::KwWriteOnly => "WRITE_ONLY",
            TokenKind::KwNotAccessible => "NOT_ACCESSIBLE",
            TokenKind::KwAccessibleForNotify => "ACCESSIBLE_FOR_NOTIFY",
            TokenKind::KwNotImplemented => "NOT_IMPLEMENTED",
        }
    }
}

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.libsmi_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
