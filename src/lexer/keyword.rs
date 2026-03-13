use super::token::TokenKind;

/// Look up a keyword string, returning its [`TokenKind`] if recognized.
///
/// Matching is case-sensitive. For example, `"INTEGER"` and `"Integer"`
/// both map to [`TokenKind::KwInteger`], but `"integer"` returns `None`.
/// Hyphenated keywords like `"OBJECT-TYPE"` and `"read-only"` are matched
/// as single strings.
pub fn lookup_keyword(text: &str) -> Option<TokenKind> {
    match text {
        "ACCESS" => Some(TokenKind::KwAccess),
        "AGENT-CAPABILITIES" => Some(TokenKind::KwAgentCapabilities),
        "APPLICATION" => Some(TokenKind::KwApplication),
        "AUGMENTS" => Some(TokenKind::KwAugments),
        "BEGIN" => Some(TokenKind::KwBegin),
        "BITS" => Some(TokenKind::KwBits),
        "CHOICE" => Some(TokenKind::KwChoice),
        "CONTACT-INFO" => Some(TokenKind::KwContactInfo),
        "CREATION-REQUIRES" => Some(TokenKind::KwCreationRequires),
        "Counter" => Some(TokenKind::KwCounter),
        "Counter32" => Some(TokenKind::KwCounter32),
        "Counter64" => Some(TokenKind::KwCounter64),
        "DEFINITIONS" => Some(TokenKind::KwDefinitions),
        "DEFVAL" => Some(TokenKind::KwDefval),
        "DESCRIPTION" => Some(TokenKind::KwDescription),
        "DISPLAY-HINT" => Some(TokenKind::KwDisplayHint),
        "END" => Some(TokenKind::KwEnd),
        "ENTERPRISE" => Some(TokenKind::KwEnterprise),
        "EXPORTS" => Some(TokenKind::KwExports),
        "FROM" => Some(TokenKind::KwFrom),
        "GROUP" => Some(TokenKind::KwGroup),
        "Gauge" => Some(TokenKind::KwGauge),
        "Gauge32" => Some(TokenKind::KwGauge32),
        "IDENTIFIER" => Some(TokenKind::KwIdentifier),
        "IMPLICIT" => Some(TokenKind::KwImplicit),
        "IMPLIED" => Some(TokenKind::KwImplied),
        "IMPORTS" => Some(TokenKind::KwImports),
        "INCLUDES" => Some(TokenKind::KwIncludes),
        "INDEX" => Some(TokenKind::KwIndex),
        "INTEGER" | "Integer" => Some(TokenKind::KwInteger),
        "IpAddress" => Some(TokenKind::KwIpAddress),
        "LAST-UPDATED" => Some(TokenKind::KwLastUpdated),
        "MACRO" => Some(TokenKind::KwMacro),
        "MANDATORY-GROUPS" => Some(TokenKind::KwMandatoryGroups),
        "MAX-ACCESS" => Some(TokenKind::KwMaxAccess),
        "MIN-ACCESS" => Some(TokenKind::KwMinAccess),
        "MODULE" => Some(TokenKind::KwModule),
        "MODULE-COMPLIANCE" => Some(TokenKind::KwModuleCompliance),
        "MODULE-IDENTITY" => Some(TokenKind::KwModuleIdentity),
        "NOTIFICATION-GROUP" => Some(TokenKind::KwNotificationGroup),
        "NOTIFICATION-TYPE" => Some(TokenKind::KwNotificationType),
        "NOTIFICATIONS" => Some(TokenKind::KwNotifications),
        "NetworkAddress" => Some(TokenKind::KwNetworkAddress),
        "OBJECT" => Some(TokenKind::KwObject),
        "OBJECT-GROUP" => Some(TokenKind::KwObjectGroup),
        "OBJECT-IDENTITY" => Some(TokenKind::KwObjectIdentity),
        "OBJECT-TYPE" => Some(TokenKind::KwObjectType),
        "OBJECTS" => Some(TokenKind::KwObjects),
        "OCTET" => Some(TokenKind::KwOctet),
        "OF" => Some(TokenKind::KwOf),
        "ORGANIZATION" => Some(TokenKind::KwOrganization),
        "Opaque" => Some(TokenKind::KwOpaque),
        "PRODUCT-RELEASE" => Some(TokenKind::KwProductRelease),
        "REFERENCE" => Some(TokenKind::KwReference),
        "REVISION" => Some(TokenKind::KwRevision),
        "SEQUENCE" => Some(TokenKind::KwSequence),
        "SIZE" => Some(TokenKind::KwSize),
        "STATUS" => Some(TokenKind::KwStatus),
        "STRING" => Some(TokenKind::KwString),
        "SUPPORTS" => Some(TokenKind::KwSupports),
        "SYNTAX" => Some(TokenKind::KwSyntax),
        "TEXTUAL-CONVENTION" => Some(TokenKind::KwTextualConvention),
        "TRAP-TYPE" => Some(TokenKind::KwTrapType),
        "TimeTicks" => Some(TokenKind::KwTimeTicks),
        "UNITS" => Some(TokenKind::KwUnits),
        "UNIVERSAL" => Some(TokenKind::KwUniversal),
        "Unsigned32" => Some(TokenKind::KwUnsigned32),
        "VARIABLES" => Some(TokenKind::KwVariables),
        "VARIATION" => Some(TokenKind::KwVariation),
        "WRITE-SYNTAX" => Some(TokenKind::KwWriteSyntax),
        // Status/access value keywords (lowercase, with hyphens)
        "accessible-for-notify" => Some(TokenKind::KwAccessibleForNotify),
        "current" => Some(TokenKind::KwCurrent),
        "deprecated" => Some(TokenKind::KwDeprecated),
        "mandatory" => Some(TokenKind::KwMandatory),
        "not-accessible" => Some(TokenKind::KwNotAccessible),
        "not-implemented" => Some(TokenKind::KwNotImplemented),
        "obsolete" => Some(TokenKind::KwObsolete),
        "optional" => Some(TokenKind::KwOptional),
        "read-create" => Some(TokenKind::KwReadCreate),
        "read-only" => Some(TokenKind::KwReadOnly),
        "read-write" => Some(TokenKind::KwReadWrite),
        "write-only" => Some(TokenKind::KwWriteOnly),
        _ => None,
    }
}

/// Returns true if `text` is a reserved ASN.1 keyword that must not appear
/// as an identifier in MIB files (e.g. `TRUE`, `FALSE`, `NULL`, `OPTIONAL`).
pub fn is_forbidden_keyword(text: &str) -> bool {
    matches!(
        text,
        "ABSENT"
            | "ANY"
            | "BIT"
            | "BOOLEAN"
            | "BY"
            | "COMPONENT"
            | "COMPONENTS"
            | "DEFAULT"
            | "DEFINED"
            | "ENUMERATED"
            | "EXPLICIT"
            | "EXTERNAL"
            | "FALSE"
            | "MAX"
            | "MIN"
            | "MINUS-INFINITY"
            | "NULL"
            | "OPTIONAL"
            | "PLUS-INFINITY"
            | "PRESENT"
            | "PRIVATE"
            | "REAL"
            | "SET"
            | "TAGS"
            | "TRUE"
            | "WITH"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_lookup_case_sensitive() {
        assert_eq!(lookup_keyword("INTEGER"), Some(TokenKind::KwInteger));
        assert_eq!(lookup_keyword("Integer"), Some(TokenKind::KwInteger));
        assert_eq!(lookup_keyword("integer"), None);
        assert_eq!(lookup_keyword("Counter32"), Some(TokenKind::KwCounter32));
        assert_eq!(lookup_keyword("COUNTER32"), None);
        assert_eq!(lookup_keyword("IpAddress"), Some(TokenKind::KwIpAddress));
        assert_eq!(lookup_keyword("IPADDRESS"), None);
    }

    #[test]
    fn keyword_lookup_hyphenated() {
        assert_eq!(lookup_keyword("OBJECT-TYPE"), Some(TokenKind::KwObjectType));
        assert_eq!(lookup_keyword("read-only"), Some(TokenKind::KwReadOnly));
        assert_eq!(
            lookup_keyword("not-accessible"),
            Some(TokenKind::KwNotAccessible)
        );
    }

    #[test]
    fn keyword_lookup_unknown() {
        assert_eq!(lookup_keyword("ifIndex"), None);
        assert_eq!(lookup_keyword(""), None);
        assert_eq!(lookup_keyword("FOOBAR"), None);
    }

    #[test]
    fn forbidden_keywords() {
        assert!(is_forbidden_keyword("ABSENT"));
        assert!(is_forbidden_keyword("TRUE"));
        assert!(is_forbidden_keyword("FALSE"));
        assert!(is_forbidden_keyword("NULL"));
        assert!(is_forbidden_keyword("OPTIONAL"));
        assert!(is_forbidden_keyword("MINUS-INFINITY"));
        assert!(!is_forbidden_keyword("OBJECT"));
        assert!(!is_forbidden_keyword("INTEGER"));
        assert!(!is_forbidden_keyword("foobar"));
    }

    #[test]
    fn optional_uppercase_is_forbidden() {
        // Uppercase OPTIONAL is not in the keyword map (only in forbidden set).
        // Lowercase "optional" is the status/access keyword.
        assert_eq!(lookup_keyword("OPTIONAL"), None);
        assert!(is_forbidden_keyword("OPTIONAL"));
        assert_eq!(lookup_keyword("optional"), Some(TokenKind::KwOptional));
    }
}
