//! Token types produced by the SMI/MIB [`Lexer`](super::Lexer).
//!
//! Contains the [`Token`] struct (pairing a [`TokenKind`] with a [`Span`])
//! and the [`TokenKind`] enum covering all SMIv1/SMIv2 token categories:
//! identifiers, literals, punctuation, and keywords.

use crate::types::Span;

/// A single lexed token with its classification and source location.
///
/// Use [`TokenKind`] to determine what the token represents, and
/// [`Span`] to index back into the original source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// What kind of token this is (keyword, identifier, literal, etc.).
    pub kind: TokenKind,
    /// Byte range in the source text that produced this token.
    pub span: Span,
}

/// Classification of a [`Token`].
///
/// Variants are grouped into special tokens, identifiers, literals,
/// punctuation, and several keyword categories (structural, clause,
/// macro, type, tag, status/access).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TokenKind {
    // -- Special --
    /// Unrecognized or malformed input.
    Error,
    /// End of input. Always the last token in a stream.
    Eof,
    /// A reserved ASN.1 keyword (e.g. `TRUE`, `FALSE`, `NULL`) that must
    /// not appear as an identifier in MIB files.
    ForbiddenKeyword,
    /// An `--`-delimited comment.
    Comment,

    // -- Identifiers --
    /// An identifier starting with an uppercase letter (type or module name).
    UppercaseIdent,
    /// An identifier starting with a lowercase letter (value reference).
    LowercaseIdent,

    // -- Literals --
    /// A non-negative decimal integer, e.g. `42`.
    Number,
    /// A negative decimal integer, e.g. `-1`.
    NegativeNumber,
    /// A double-quoted string literal, e.g. `"hello"`.
    QuotedString,
    /// A hex string literal, e.g. `'0A1B'H`.
    HexString,
    /// A binary string literal, e.g. `'01010101'B`.
    BinString,

    // -- Single-character punctuation --
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `:`
    Colon,
    /// `;`
    Semicolon,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `|`
    Pipe,
    /// `-` (standalone, not part of a negative number)
    Minus,

    // -- Multi-character operators --
    /// `..` (range separator in SIZE/value constraints)
    DotDot,
    /// `::=` (assignment operator)
    ColonColonEqual,

    // -- Structural keywords (first keyword range) --
    /// `DEFINITIONS`
    KwDefinitions,
    /// `BEGIN`
    KwBegin,
    /// `END`
    KwEnd,
    /// `IMPORTS`
    KwImports,
    /// `EXPORTS` - triggers body-skipping in the lexer.
    KwExports,
    /// `FROM`
    KwFrom,
    /// `OBJECT`
    KwObject,
    /// `IDENTIFIER`
    KwIdentifier,
    /// `SEQUENCE`
    KwSequence,
    /// `OF`
    KwOf,
    /// `CHOICE`
    KwChoice,
    /// `MACRO` - triggers body-skipping in the lexer.
    KwMacro,

    // -- Clause keywords --
    /// `SYNTAX`
    KwSyntax,
    /// `MAX-ACCESS`
    KwMaxAccess,
    /// `MIN-ACCESS`
    KwMinAccess,
    /// `ACCESS` (SMIv1)
    KwAccess,
    /// `STATUS`
    KwStatus,
    /// `DESCRIPTION`
    KwDescription,
    /// `REFERENCE`
    KwReference,
    /// `INDEX`
    KwIndex,
    /// `DEFVAL`
    KwDefval,
    /// `AUGMENTS`
    KwAugments,
    /// `UNITS`
    KwUnits,
    /// `DISPLAY-HINT`
    KwDisplayHint,
    /// `OBJECTS`
    KwObjects,
    /// `NOTIFICATIONS`
    KwNotifications,
    /// `MODULE`
    KwModule,
    /// `MANDATORY-GROUPS`
    KwMandatoryGroups,
    /// `GROUP`
    KwGroup,
    /// `WRITE-SYNTAX`
    KwWriteSyntax,
    /// `PRODUCT-RELEASE`
    KwProductRelease,
    /// `SUPPORTS`
    KwSupports,
    /// `INCLUDES`
    KwIncludes,
    /// `VARIATION`
    KwVariation,
    /// `CREATION-REQUIRES`
    KwCreationRequires,
    /// `REVISION`
    KwRevision,
    /// `LAST-UPDATED`
    KwLastUpdated,
    /// `ORGANIZATION`
    KwOrganization,
    /// `CONTACT-INFO`
    KwContactInfo,
    /// `IMPLIED`
    KwImplied,
    /// `SIZE`
    KwSize,
    /// `ENTERPRISE` (SMIv1 TRAP-TYPE)
    KwEnterprise,
    /// `VARIABLES` (SMIv1 TRAP-TYPE)
    KwVariables,

    // -- MACRO invocation keywords --
    /// `MODULE-IDENTITY` (SMIv2)
    KwModuleIdentity,
    /// `MODULE-COMPLIANCE` (SMIv2)
    KwModuleCompliance,
    /// `OBJECT-GROUP` (SMIv2)
    KwObjectGroup,
    /// `NOTIFICATION-GROUP` (SMIv2)
    KwNotificationGroup,
    /// `AGENT-CAPABILITIES` (SMIv2)
    KwAgentCapabilities,
    /// `OBJECT-TYPE` (SMIv1/v2)
    KwObjectType,
    /// `OBJECT-IDENTITY` (SMIv2)
    KwObjectIdentity,
    /// `NOTIFICATION-TYPE` (SMIv2)
    KwNotificationType,
    /// `TEXTUAL-CONVENTION` (SMIv2)
    KwTextualConvention,
    /// `TRAP-TYPE` (SMIv1)
    KwTrapType,

    // -- Type keywords --
    /// `INTEGER` or `Integer`
    KwInteger,
    /// `Unsigned32`
    KwUnsigned32,
    /// `Counter32`
    KwCounter32,
    /// `Counter64`
    KwCounter64,
    /// `Gauge32`
    KwGauge32,
    /// `IpAddress`
    KwIpAddress,
    /// `Opaque`
    KwOpaque,
    /// `TimeTicks`
    KwTimeTicks,
    /// `BITS`
    KwBits,
    /// `OCTET` (first half of `OCTET STRING`)
    KwOctet,
    /// `STRING` (second half of `OCTET STRING`)
    KwString,

    // -- SMIv1 type aliases --
    /// `Counter` (SMIv1 alias for Counter32)
    KwCounter,
    /// `Gauge` (SMIv1 alias for Gauge32)
    KwGauge,
    /// `NetworkAddress` (SMIv1)
    KwNetworkAddress,

    // -- ASN.1 tag keywords --
    /// `APPLICATION`
    KwApplication,
    /// `IMPLICIT`
    KwImplicit,
    /// `UNIVERSAL`
    KwUniversal,

    // -- Status/Access value keywords (last keyword range) --
    /// `current`
    KwCurrent,
    /// `deprecated`
    KwDeprecated,
    /// `obsolete`
    KwObsolete,
    /// `mandatory` (SMIv1)
    KwMandatory,
    /// `optional` (SMIv1)
    KwOptional,
    /// `read-only`
    KwReadOnly,
    /// `read-write`
    KwReadWrite,
    /// `read-create`
    KwReadCreate,
    /// `write-only` (deprecated)
    KwWriteOnly,
    /// `not-accessible`
    KwNotAccessible,
    /// `accessible-for-notify`
    KwAccessibleForNotify,
    /// `not-implemented` (AGENT-CAPABILITIES)
    KwNotImplemented,
}

impl TokenKind {
    /// Returns `true` if this is any keyword token (structural, clause, macro,
    /// type, tag, or status/access).
    pub fn is_keyword(self) -> bool {
        self.is_structural_keyword()
            || self.is_clause_keyword()
            || self.is_macro_keyword()
            || self.is_type_keyword()
            || self.is_tag_keyword()
            || self.is_status_access_keyword()
    }

    /// Returns `true` for [`UppercaseIdent`](Self::UppercaseIdent) or
    /// [`LowercaseIdent`](Self::LowercaseIdent).
    pub fn is_identifier(self) -> bool {
        matches!(self, TokenKind::UppercaseIdent | TokenKind::LowercaseIdent)
    }

    /// Returns `true` for built-in SMI type keywords (`INTEGER`, `Counter32`,
    /// `OCTET`, `STRING`, `NetworkAddress`, etc.).
    pub fn is_type_keyword(self) -> bool {
        matches!(
            self,
            TokenKind::KwInteger
                | TokenKind::KwUnsigned32
                | TokenKind::KwCounter32
                | TokenKind::KwCounter64
                | TokenKind::KwGauge32
                | TokenKind::KwIpAddress
                | TokenKind::KwOpaque
                | TokenKind::KwTimeTicks
                | TokenKind::KwBits
                | TokenKind::KwOctet
                | TokenKind::KwString
                | TokenKind::KwCounter
                | TokenKind::KwGauge
                | TokenKind::KwNetworkAddress
        )
    }

    /// Returns `true` for SMI macro invocation keywords (`MODULE-IDENTITY`,
    /// `OBJECT-TYPE`, `TRAP-TYPE`, etc.).
    pub fn is_macro_keyword(self) -> bool {
        matches!(
            self,
            TokenKind::KwModuleIdentity
                | TokenKind::KwModuleCompliance
                | TokenKind::KwObjectGroup
                | TokenKind::KwNotificationGroup
                | TokenKind::KwAgentCapabilities
                | TokenKind::KwObjectType
                | TokenKind::KwObjectIdentity
                | TokenKind::KwNotificationType
                | TokenKind::KwTextualConvention
                | TokenKind::KwTrapType
        )
    }

    /// Returns `true` for clause keywords used within macro bodies (`SYNTAX`,
    /// `STATUS`, `DESCRIPTION`, `INDEX`, `DEFVAL`, etc.).
    pub fn is_clause_keyword(self) -> bool {
        matches!(
            self,
            TokenKind::KwSyntax
                | TokenKind::KwMaxAccess
                | TokenKind::KwMinAccess
                | TokenKind::KwAccess
                | TokenKind::KwStatus
                | TokenKind::KwDescription
                | TokenKind::KwReference
                | TokenKind::KwIndex
                | TokenKind::KwDefval
                | TokenKind::KwAugments
                | TokenKind::KwUnits
                | TokenKind::KwDisplayHint
                | TokenKind::KwObjects
                | TokenKind::KwNotifications
                | TokenKind::KwModule
                | TokenKind::KwMandatoryGroups
                | TokenKind::KwGroup
                | TokenKind::KwWriteSyntax
                | TokenKind::KwProductRelease
                | TokenKind::KwSupports
                | TokenKind::KwIncludes
                | TokenKind::KwVariation
                | TokenKind::KwCreationRequires
                | TokenKind::KwRevision
                | TokenKind::KwLastUpdated
                | TokenKind::KwOrganization
                | TokenKind::KwContactInfo
                | TokenKind::KwImplied
                | TokenKind::KwSize
                | TokenKind::KwEnterprise
                | TokenKind::KwVariables
        )
    }

    /// Returns `true` for ASN.1 tag keywords (`APPLICATION`, `IMPLICIT`,
    /// `UNIVERSAL`).
    pub fn is_tag_keyword(self) -> bool {
        matches!(
            self,
            TokenKind::KwApplication | TokenKind::KwImplicit | TokenKind::KwUniversal
        )
    }

    /// Returns `true` for status or access value keywords (`current`,
    /// `deprecated`, `read-only`, `not-accessible`, etc.).
    pub fn is_status_access_keyword(self) -> bool {
        matches!(
            self,
            TokenKind::KwCurrent
                | TokenKind::KwDeprecated
                | TokenKind::KwObsolete
                | TokenKind::KwMandatory
                | TokenKind::KwOptional
                | TokenKind::KwReadOnly
                | TokenKind::KwReadWrite
                | TokenKind::KwReadCreate
                | TokenKind::KwWriteOnly
                | TokenKind::KwNotAccessible
                | TokenKind::KwAccessibleForNotify
                | TokenKind::KwNotImplemented
        )
    }

    /// Returns `true` for structural keywords that frame the module
    /// (`DEFINITIONS`, `BEGIN`, `END`, `IMPORTS`, `FROM`, `MACRO`, etc.).
    pub fn is_structural_keyword(self) -> bool {
        matches!(
            self,
            TokenKind::KwDefinitions
                | TokenKind::KwBegin
                | TokenKind::KwEnd
                | TokenKind::KwImports
                | TokenKind::KwExports
                | TokenKind::KwFrom
                | TokenKind::KwObject
                | TokenKind::KwIdentifier
                | TokenKind::KwSequence
                | TokenKind::KwOf
                | TokenKind::KwChoice
                | TokenKind::KwMacro
        )
    }

    /// Returns a human-readable name suitable for use in error messages.
    ///
    /// Punctuation tokens are shown as quoted characters (e.g. `'{'`),
    /// keywords use their [`libsmi_name`](Self::libsmi_name), and other
    /// tokens use descriptive labels like `"identifier"` or `"number"`.
    pub fn display_name(self) -> &'static str {
        match self {
            TokenKind::Error => "<error>",
            TokenKind::Eof => "end of file",
            TokenKind::ForbiddenKeyword => "reserved keyword",
            TokenKind::Comment => "comment",
            TokenKind::UppercaseIdent => "identifier",
            TokenKind::LowercaseIdent => "identifier",
            TokenKind::Number => "number",
            TokenKind::NegativeNumber => "negative number",
            TokenKind::QuotedString => "quoted string",
            TokenKind::HexString => "hex string",
            TokenKind::BinString => "binary string",
            TokenKind::LBracket => "'['",
            TokenKind::RBracket => "']'",
            TokenKind::LBrace => "'{'",
            TokenKind::RBrace => "'}'",
            TokenKind::LParen => "'('",
            TokenKind::RParen => "')'",
            TokenKind::Colon => "':'",
            TokenKind::Semicolon => "';'",
            TokenKind::Comma => "','",
            TokenKind::Dot => "'.'",
            TokenKind::Pipe => "'|'",
            TokenKind::Minus => "'-'",
            TokenKind::DotDot => "'..'",
            TokenKind::ColonColonEqual => "'::='",
            _ => self.libsmi_name(),
        }
    }

    /// Returns the libsmi-compatible uppercase name for this token kind.
    ///
    /// These names match the token naming conventions used by the libsmi
    /// library, with hyphens replaced by underscores (e.g. `OBJECT_TYPE`,
    /// `READ_ONLY`, `COLON_COLON_EQUAL`).
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
    /// Formats using the [`libsmi_name`](TokenKind::libsmi_name) representation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.libsmi_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_classification() {
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
