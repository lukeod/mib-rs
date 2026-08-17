//! Syntax kinds and lexical spelling metadata.
//!
//! [`SyntaxKind`] is the shared kind vocabulary for lexer tokens and future
//! lossless syntax-tree nodes. Its inventory, spellings, keyword aliases,
//! categories, display names, and libsmi names are declared together so lexer,
//! parser, and tooling APIs cannot drift apart.
//!
//! [`SyntaxKind::Whitespace`], [`SyntaxKind::OpaqueText`], and
//! [`SyntaxKind::SourceFile`] reserve the first lossless-CST vocabulary. The
//! current lexer does not emit whitespace or skipped opaque bodies yet.

use std::fmt;

/// Broad classification of a [`SyntaxKind`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyntaxCategory {
    /// Lexer control or recovery token.
    Special,
    /// Whitespace or comment trivia.
    Trivia,
    /// Uppercase or lowercase identifier.
    Identifier,
    /// Numeric or string literal.
    Literal,
    /// Fixed punctuation or operator.
    Punctuation,
    /// Recognized SMI or ASN.1 keyword.
    Keyword,
    /// Lossless syntax-tree node.
    Node,
}

/// More specific classification for keyword kinds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeywordCategory {
    /// Keywords framing modules and ASN.1 structures.
    Structural,
    /// Keywords introducing macro clauses.
    Clause,
    /// SMI macro invocation keywords.
    Macro,
    /// Built-in SMI type keywords.
    Type,
    /// ASN.1 tag keywords.
    Tag,
    /// Status and access value keywords.
    StatusAccess,
}

macro_rules! define_syntax_kinds {
    (
        special { $( $special:ident => ($special_libsmi:literal, $special_display:literal); )* }
        trivia { $( $trivia:ident => ($trivia_libsmi:literal, $trivia_display:literal); )* }
        identifiers { $( $identifier:ident => ($identifier_libsmi:literal, $identifier_display:literal); )* }
        literals { $( $literal:ident => ($literal_libsmi:literal, $literal_display:literal); )* }
        punctuation { $( $punctuation:ident => ($byte:literal, $spelling:literal, $punctuation_libsmi:literal, $punctuation_display:literal); )* }
        operators { $( $operator:ident => ($operator_spelling:literal, $operator_libsmi:literal, $operator_display:literal); )* }
        keywords { $( $keyword:ident => ($keyword_category:ident, $canonical:literal, [$($alias:literal),* $(,)?], $keyword_libsmi:literal); )* }
        nodes { $( $node:ident => ($node_libsmi:literal, $node_display:literal); )* }
        forbidden { $( $forbidden:literal ),* $(,)? }
    ) => {
        /// Kind of a lexical token or lossless syntax-tree node.
        ///
        /// Values are stable within a crate release and use a 16-bit
        /// representation so the vocabulary can grow with CST node kinds.
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(u16)]
        pub enum SyntaxKind {
            $( #[doc = concat!("`", $special_display, "`")] $special, )*
            $( #[doc = $trivia_display] $trivia, )*
            $( #[doc = $identifier_display] $identifier, )*
            $( #[doc = $literal_display] $literal, )*
            $( #[doc = $punctuation_display] $punctuation, )*
            $( #[doc = $operator_display] $operator, )*
            $( #[doc = $canonical] $keyword, )*
            $( #[doc = $node_display] $node, )*
        }

        impl SyntaxKind {
            /// Every declared token and node kind in discriminant order.
            pub const ALL: &'static [Self] = &[
                $( Self::$special, )*
                $( Self::$trivia, )*
                $( Self::$identifier, )*
                $( Self::$literal, )*
                $( Self::$punctuation, )*
                $( Self::$operator, )*
                $( Self::$keyword, )*
                $( Self::$node, )*
            ];

            /// Return the kind for a raw discriminant, if it is declared.
            pub const fn from_raw(raw: u16) -> Option<Self> {
                match raw {
                    $( value if value == Self::$special as u16 => Some(Self::$special), )*
                    $( value if value == Self::$trivia as u16 => Some(Self::$trivia), )*
                    $( value if value == Self::$identifier as u16 => Some(Self::$identifier), )*
                    $( value if value == Self::$literal as u16 => Some(Self::$literal), )*
                    $( value if value == Self::$punctuation as u16 => Some(Self::$punctuation), )*
                    $( value if value == Self::$operator as u16 => Some(Self::$operator), )*
                    $( value if value == Self::$keyword as u16 => Some(Self::$keyword), )*
                    $( value if value == Self::$node as u16 => Some(Self::$node), )*
                    _ => None,
                }
            }

            /// Return the 16-bit discriminant for this kind.
            pub const fn to_raw(self) -> u16 {
                self as u16
            }

            /// Return this kind's broad syntax category.
            pub const fn category(self) -> SyntaxCategory {
                match self {
                    $( Self::$special => SyntaxCategory::Special, )*
                    $( Self::$trivia => SyntaxCategory::Trivia, )*
                    $( Self::$identifier => SyntaxCategory::Identifier, )*
                    $( Self::$literal => SyntaxCategory::Literal, )*
                    $( Self::$punctuation => SyntaxCategory::Punctuation, )*
                    $( Self::$operator => SyntaxCategory::Punctuation, )*
                    $( Self::$keyword => SyntaxCategory::Keyword, )*
                    $( Self::$node => SyntaxCategory::Node, )*
                }
            }

            /// Return this kind's keyword category, or `None` for non-keywords.
            pub const fn keyword_category(self) -> Option<KeywordCategory> {
                match self {
                    $( Self::$keyword => Some(KeywordCategory::$keyword_category), )*
                    _ => None,
                }
            }

            /// Return whether this kind is emitted by the lexer.
            pub const fn is_token(self) -> bool {
                !self.is_node()
            }

            /// Return whether this kind represents a syntax-tree node.
            pub const fn is_node(self) -> bool {
                matches!(self.category(), SyntaxCategory::Node)
            }

            /// Return whether this kind is whitespace or comment trivia.
            pub const fn is_trivia(self) -> bool {
                matches!(self.category(), SyntaxCategory::Trivia)
            }

            /// Return whether this kind is an uppercase or lowercase identifier.
            pub const fn is_identifier(self) -> bool {
                matches!(self.category(), SyntaxCategory::Identifier)
            }

            /// Return whether this kind is a numeric or string literal.
            pub const fn is_literal(self) -> bool {
                matches!(self.category(), SyntaxCategory::Literal)
            }

            /// Return whether this kind is fixed punctuation or an operator.
            pub const fn is_punctuation(self) -> bool {
                matches!(self.category(), SyntaxCategory::Punctuation)
            }

            /// Return whether this kind is any recognized keyword.
            pub const fn is_keyword(self) -> bool {
                matches!(self.category(), SyntaxCategory::Keyword)
            }

            /// Return whether this is a structural keyword.
            pub const fn is_structural_keyword(self) -> bool {
                matches!(self.keyword_category(), Some(KeywordCategory::Structural))
            }

            /// Return whether this is a clause keyword.
            pub const fn is_clause_keyword(self) -> bool {
                matches!(self.keyword_category(), Some(KeywordCategory::Clause))
            }

            /// Return whether this is an SMI macro invocation keyword.
            pub const fn is_macro_keyword(self) -> bool {
                matches!(self.keyword_category(), Some(KeywordCategory::Macro))
            }

            /// Return whether this is a built-in SMI type keyword.
            pub const fn is_type_keyword(self) -> bool {
                matches!(self.keyword_category(), Some(KeywordCategory::Type))
            }

            /// Return whether this is an ASN.1 tag keyword.
            pub const fn is_tag_keyword(self) -> bool {
                matches!(self.keyword_category(), Some(KeywordCategory::Tag))
            }

            /// Return whether this is a status or access value keyword.
            pub const fn is_status_access_keyword(self) -> bool {
                matches!(self.keyword_category(), Some(KeywordCategory::StatusAccess))
            }

            /// Return fixed source text for punctuation and canonical keywords.
            pub const fn fixed_text(self) -> Option<&'static str> {
                match self {
                    $( Self::$punctuation => Some($spelling), )*
                    $( Self::$operator => Some($operator_spelling), )*
                    $( Self::$keyword => Some($canonical), )*
                    _ => None,
                }
            }

            /// Return every accepted spelling for a keyword kind.
            pub const fn keyword_spellings(self) -> &'static [&'static str] {
                match self {
                    $( Self::$keyword => &[$canonical, $($alias),*], )*
                    _ => &[],
                }
            }

            /// Look up a recognized keyword using case-sensitive source spelling.
            pub fn from_keyword(text: &str) -> Option<Self> {
                match text {
                    $( $canonical $(| $alias)* => Some(Self::$keyword), )*
                    _ => None,
                }
            }

            /// Look up fixed punctuation or a canonical keyword spelling.
            pub fn from_fixed_text(text: &str) -> Option<Self> {
                match text {
                    $( $spelling => Some(Self::$punctuation), )*
                    $( $operator_spelling => Some(Self::$operator), )*
                    $( $canonical => Some(Self::$keyword), )*
                    _ => None,
                }
            }

            /// Look up a single-byte punctuation kind.
            pub const fn from_punctuation_byte(byte: u8) -> Option<Self> {
                match byte {
                    $( $byte => Some(Self::$punctuation), )*
                    _ => None,
                }
            }

            /// Return a human-readable name suitable for parser diagnostics.
            pub const fn display_name(self) -> &'static str {
                match self {
                    $( Self::$special => $special_display, )*
                    $( Self::$trivia => $trivia_display, )*
                    $( Self::$identifier => $identifier_display, )*
                    $( Self::$literal => $literal_display, )*
                    $( Self::$punctuation => $punctuation_display, )*
                    $( Self::$operator => $operator_display, )*
                    $( Self::$keyword => $keyword_libsmi, )*
                    $( Self::$node => $node_display, )*
                }
            }

            /// Return the libsmi-compatible uppercase kind name.
            pub const fn libsmi_name(self) -> &'static str {
                match self {
                    $( Self::$special => $special_libsmi, )*
                    $( Self::$trivia => $trivia_libsmi, )*
                    $( Self::$identifier => $identifier_libsmi, )*
                    $( Self::$literal => $literal_libsmi, )*
                    $( Self::$punctuation => $punctuation_libsmi, )*
                    $( Self::$operator => $operator_libsmi, )*
                    $( Self::$keyword => $keyword_libsmi, )*
                    $( Self::$node => $node_libsmi, )*
                }
            }
        }

        /// Reserved ASN.1 words rejected when used as MIB identifiers.
        pub const FORBIDDEN_KEYWORDS: &[&str] = &[$($forbidden),*];

        /// Look up a recognized keyword using case-sensitive source spelling.
        pub fn lookup_keyword(text: &str) -> Option<SyntaxKind> {
            SyntaxKind::from_keyword(text)
        }

        /// Return whether text is a reserved ASN.1 keyword forbidden as a MIB identifier.
        pub fn is_forbidden_keyword(text: &str) -> bool {
            matches!(text, $($forbidden)|*)
        }
    };
}

define_syntax_kinds! {
    special {
        ErrorToken => ("ERROR", "<error>");
        EofToken => ("EOF", "end of file");
        ForbiddenKeyword => ("FORBIDDEN_KEYWORD", "reserved keyword");
        OpaqueText => ("OPAQUE_TEXT", "opaque text");
    }
    trivia {
        Whitespace => ("WHITESPACE", "whitespace");
        Comment => ("COMMENT", "comment");
    }
    identifiers {
        UppercaseIdent => ("UPPERCASE_IDENTIFIER", "identifier");
        LowercaseIdent => ("LOWERCASE_IDENTIFIER", "identifier");
    }
    literals {
        Number => ("NUMBER", "number");
        NegativeNumber => ("NEGATIVENUMBER", "negative number");
        QuotedString => ("QUOTED_STRING", "quoted string");
        HexString => ("HEX_STRING", "hex string");
        BinString => ("BIN_STRING", "binary string");
    }
    punctuation {
        LBracket => (b'[', "[", "LBRACKET", "'['");
        RBracket => (b']', "]", "RBRACKET", "']'");
        LBrace => (b'{', "{", "LBRACE", "'{'");
        RBrace => (b'}', "}", "RBRACE", "'}'");
        LParen => (b'(', "(", "LPAREN", "'('");
        RParen => (b')', ")", "RPAREN", "')'");
        Colon => (b':', ":", "COLON", "':'");
        Semicolon => (b';', ";", "SEMICOLON", "';'");
        Comma => (b',', ",", "COMMA", "','");
        Dot => (b'.', ".", "DOT", "'.'");
        Pipe => (b'|', "|", "PIPE", "'|'");
        Minus => (b'-', "-", "MINUS", "'-'");
    }
    operators {
        DotDot => ("..", "DOT_DOT", "'..'");
        ColonColonEqual => ("::=", "COLON_COLON_EQUAL", "'::='");
    }
    keywords {
        KwDefinitions => (Structural, "DEFINITIONS", [], "DEFINITIONS");
        KwBegin => (Structural, "BEGIN", [], "BEGIN");
        KwEnd => (Structural, "END", [], "END");
        KwImports => (Structural, "IMPORTS", [], "IMPORTS");
        KwExports => (Structural, "EXPORTS", [], "EXPORTS");
        KwFrom => (Structural, "FROM", [], "FROM");
        KwObject => (Structural, "OBJECT", [], "OBJECT");
        KwIdentifier => (Structural, "IDENTIFIER", [], "IDENTIFIER");
        KwSequence => (Structural, "SEQUENCE", [], "SEQUENCE");
        KwOf => (Structural, "OF", [], "OF");
        KwChoice => (Structural, "CHOICE", [], "CHOICE");
        KwMacro => (Structural, "MACRO", [], "MACRO");

        KwSyntax => (Clause, "SYNTAX", [], "SYNTAX");
        KwMaxAccess => (Clause, "MAX-ACCESS", [], "MAX_ACCESS");
        KwMinAccess => (Clause, "MIN-ACCESS", [], "MIN_ACCESS");
        KwAccess => (Clause, "ACCESS", [], "ACCESS");
        KwStatus => (Clause, "STATUS", [], "STATUS");
        KwDescription => (Clause, "DESCRIPTION", [], "DESCRIPTION");
        KwReference => (Clause, "REFERENCE", [], "REFERENCE");
        KwIndex => (Clause, "INDEX", [], "INDEX");
        KwDefval => (Clause, "DEFVAL", [], "DEFVAL");
        KwAugments => (Clause, "AUGMENTS", [], "AUGMENTS");
        KwUnits => (Clause, "UNITS", [], "UNITS");
        KwDisplayHint => (Clause, "DISPLAY-HINT", [], "DISPLAY_HINT");
        KwObjects => (Clause, "OBJECTS", [], "OBJECTS");
        KwNotifications => (Clause, "NOTIFICATIONS", [], "NOTIFICATIONS");
        KwModule => (Clause, "MODULE", [], "MODULE");
        KwMandatoryGroups => (Clause, "MANDATORY-GROUPS", [], "MANDATORY_GROUPS");
        KwGroup => (Clause, "GROUP", [], "GROUP");
        KwWriteSyntax => (Clause, "WRITE-SYNTAX", [], "WRITE_SYNTAX");
        KwProductRelease => (Clause, "PRODUCT-RELEASE", [], "PRODUCT_RELEASE");
        KwSupports => (Clause, "SUPPORTS", [], "SUPPORTS");
        KwIncludes => (Clause, "INCLUDES", [], "INCLUDES");
        KwVariation => (Clause, "VARIATION", [], "VARIATION");
        KwCreationRequires => (Clause, "CREATION-REQUIRES", [], "CREATION_REQUIRES");
        KwRevision => (Clause, "REVISION", [], "REVISION");
        KwLastUpdated => (Clause, "LAST-UPDATED", [], "LAST_UPDATED");
        KwOrganization => (Clause, "ORGANIZATION", [], "ORGANIZATION");
        KwContactInfo => (Clause, "CONTACT-INFO", [], "CONTACT_INFO");
        KwImplied => (Clause, "IMPLIED", [], "IMPLIED");
        KwSize => (Clause, "SIZE", [], "SIZE");
        KwEnterprise => (Clause, "ENTERPRISE", [], "ENTERPRISE");
        KwVariables => (Clause, "VARIABLES", [], "VARIABLES");

        KwModuleIdentity => (Macro, "MODULE-IDENTITY", [], "MODULE_IDENTITY");
        KwModuleCompliance => (Macro, "MODULE-COMPLIANCE", [], "MODULE_COMPLIANCE");
        KwObjectGroup => (Macro, "OBJECT-GROUP", [], "OBJECT_GROUP");
        KwNotificationGroup => (Macro, "NOTIFICATION-GROUP", [], "NOTIFICATION_GROUP");
        KwAgentCapabilities => (Macro, "AGENT-CAPABILITIES", [], "AGENT_CAPABILITIES");
        KwObjectType => (Macro, "OBJECT-TYPE", [], "OBJECT_TYPE");
        KwObjectIdentity => (Macro, "OBJECT-IDENTITY", [], "OBJECT_IDENTITY");
        KwNotificationType => (Macro, "NOTIFICATION-TYPE", [], "NOTIFICATION_TYPE");
        KwTextualConvention => (Macro, "TEXTUAL-CONVENTION", [], "TEXTUAL_CONVENTION");
        KwTrapType => (Macro, "TRAP-TYPE", [], "TRAP_TYPE");

        KwInteger => (Type, "INTEGER", ["Integer"], "INTEGER");
        KwUnsigned32 => (Type, "Unsigned32", [], "UNSIGNED32");
        KwCounter32 => (Type, "Counter32", [], "COUNTER32");
        KwCounter64 => (Type, "Counter64", [], "COUNTER64");
        KwGauge32 => (Type, "Gauge32", [], "GAUGE32");
        KwIpAddress => (Type, "IpAddress", [], "IPADDRESS");
        KwOpaque => (Type, "Opaque", [], "OPAQUE");
        KwTimeTicks => (Type, "TimeTicks", [], "TIMETICKS");
        KwBits => (Type, "BITS", [], "BITS");
        KwOctet => (Type, "OCTET", [], "OCTET");
        KwString => (Type, "STRING", [], "STRING");
        KwCounter => (Type, "Counter", [], "COUNTER");
        KwGauge => (Type, "Gauge", [], "GAUGE");
        KwNetworkAddress => (Type, "NetworkAddress", [], "NETWORKADDRESS");

        KwApplication => (Tag, "APPLICATION", [], "APPLICATION");
        KwImplicit => (Tag, "IMPLICIT", [], "IMPLICIT");
        KwUniversal => (Tag, "UNIVERSAL", [], "UNIVERSAL");

        KwCurrent => (StatusAccess, "current", [], "CURRENT");
        KwDeprecated => (StatusAccess, "deprecated", [], "DEPRECATED");
        KwObsolete => (StatusAccess, "obsolete", [], "OBSOLETE");
        KwMandatory => (StatusAccess, "mandatory", [], "MANDATORY");
        KwOptional => (StatusAccess, "optional", [], "OPTIONAL");
        KwReadOnly => (StatusAccess, "read-only", [], "READ_ONLY");
        KwReadWrite => (StatusAccess, "read-write", [], "READ_WRITE");
        KwReadCreate => (StatusAccess, "read-create", [], "READ_CREATE");
        KwWriteOnly => (StatusAccess, "write-only", [], "WRITE_ONLY");
        KwNotAccessible => (StatusAccess, "not-accessible", [], "NOT_ACCESSIBLE");
        KwAccessibleForNotify => (StatusAccess, "accessible-for-notify", [], "ACCESSIBLE_FOR_NOTIFY");
        KwNotImplemented => (StatusAccess, "not-implemented", [], "NOT_IMPLEMENTED");
    }
    nodes {
        SourceFile => ("SOURCE_FILE", "source file");
    }
    forbidden {
        "ABSENT", "ANY", "BIT", "BOOLEAN", "BY", "COMPONENT", "COMPONENTS",
        "DEFAULT", "DEFINED", "ENUMERATED", "EXPLICIT", "EXTERNAL", "FALSE",
        "MAX", "MIN", "MINUS-INFINITY", "NULL", "OPTIONAL", "PLUS-INFINITY",
        "PRESENT", "PRIVATE", "REAL", "SET", "TAGS", "TRUE", "WITH",
    }
}

impl fmt::Display for SyntaxKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.libsmi_name())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;

    #[test]
    fn raw_discriminants_round_trip_exhaustively() {
        for (raw, kind) in SyntaxKind::ALL.iter().copied().enumerate() {
            assert_eq!(usize::from(kind.to_raw()), raw);
            assert_eq!(SyntaxKind::from_raw(kind.to_raw()), Some(kind));
        }
        assert_eq!(
            SyntaxKind::from_raw(u16::try_from(SyntaxKind::ALL.len()).unwrap()),
            None
        );
        assert_eq!(SyntaxKind::from_raw(u16::MAX), None);
    }

    #[test]
    fn inventory_and_categories_are_exhaustive() {
        assert_eq!(SyntaxKind::ALL.len(), 110);
        assert_eq!(
            SyntaxKind::ALL.iter().filter(|kind| kind.is_node()).count(),
            1
        );
        assert_eq!(
            SyntaxKind::ALL
                .iter()
                .filter(|kind| kind.is_token())
                .count(),
            109
        );
        assert_eq!(
            SyntaxKind::ALL
                .iter()
                .filter(|kind| kind.is_trivia())
                .count(),
            2
        );
        assert_eq!(
            SyntaxKind::ALL
                .iter()
                .filter(|kind| kind.is_identifier())
                .count(),
            2
        );
        assert_eq!(
            SyntaxKind::ALL
                .iter()
                .filter(|kind| kind.is_literal())
                .count(),
            5
        );
        assert_eq!(
            SyntaxKind::ALL
                .iter()
                .filter(|kind| kind.is_punctuation())
                .count(),
            14
        );
        assert_eq!(
            SyntaxKind::ALL
                .iter()
                .filter(|kind| kind.is_keyword())
                .count(),
            82
        );
        assert_eq!(SyntaxKind::SourceFile.category(), SyntaxCategory::Node);
        assert!(SyntaxKind::Whitespace.is_trivia());
        assert!(SyntaxKind::Comment.is_trivia());
        assert!(!SyntaxKind::OpaqueText.is_trivia());
    }

    #[test]
    fn keyword_and_fixed_spelling_round_trips_are_exhaustive() {
        for kind in SyntaxKind::ALL.iter().copied() {
            for spelling in kind.keyword_spellings() {
                assert_eq!(SyntaxKind::from_keyword(spelling), Some(kind));
            }
            if let Some(text) = kind.fixed_text() {
                assert_eq!(SyntaxKind::from_fixed_text(text), Some(kind));
            }
        }
        assert_eq!(SyntaxKind::from_keyword("integer"), None);
        assert_eq!(SyntaxKind::from_fixed_text("Integer"), None);
    }

    #[test]
    fn single_byte_punctuation_round_trips_exhaustively() {
        for kind in SyntaxKind::ALL
            .iter()
            .copied()
            .filter(|kind| kind.is_punctuation())
        {
            let spelling = kind.fixed_text().unwrap();
            if let [byte] = spelling.as_bytes() {
                assert_eq!(SyntaxKind::from_punctuation_byte(*byte), Some(kind));
            } else {
                assert!(matches!(
                    kind,
                    SyntaxKind::DotDot | SyntaxKind::ColonColonEqual
                ));
            }
        }
    }

    #[test]
    fn declared_spellings_are_unique() {
        let mut keywords = HashMap::new();
        let mut fixed = HashMap::new();
        for kind in SyntaxKind::ALL.iter().copied() {
            for spelling in kind.keyword_spellings() {
                assert_eq!(
                    keywords.insert(*spelling, kind),
                    None,
                    "duplicate {spelling}"
                );
            }
            if let Some(spelling) = kind.fixed_text() {
                assert_eq!(fixed.insert(spelling, kind), None, "duplicate {spelling}");
            }
        }
        let forbidden: HashSet<_> = FORBIDDEN_KEYWORDS.iter().copied().collect();
        assert_eq!(forbidden.len(), FORBIDDEN_KEYWORDS.len());
        assert!(forbidden.is_disjoint(&keywords.keys().copied().collect()));
    }

    #[test]
    fn forbidden_keyword_lookup_matches_the_declared_inventory() {
        for keyword in FORBIDDEN_KEYWORDS {
            assert!(is_forbidden_keyword(keyword));
            assert_eq!(SyntaxKind::from_keyword(keyword), None);
        }
        assert!(!is_forbidden_keyword("optional"));
        assert_eq!(
            SyntaxKind::from_keyword("optional"),
            Some(SyntaxKind::KwOptional)
        );
    }

    #[test]
    fn keyword_subcategories_cover_exactly_all_keywords() {
        let counts = SyntaxKind::ALL.iter().copied().fold(
            HashMap::<KeywordCategory, usize>::new(),
            |mut counts, kind| {
                if let Some(category) = kind.keyword_category() {
                    *counts.entry(category).or_default() += 1;
                }
                counts
            },
        );
        assert_eq!(counts.values().sum::<usize>(), 82);
        assert_eq!(counts[&KeywordCategory::Structural], 12);
        assert_eq!(counts[&KeywordCategory::Clause], 31);
        assert_eq!(counts[&KeywordCategory::Macro], 10);
        assert_eq!(counts[&KeywordCategory::Type], 14);
        assert_eq!(counts[&KeywordCategory::Tag], 3);
        assert_eq!(counts[&KeywordCategory::StatusAccess], 12);
    }

    #[test]
    fn legacy_display_and_libsmi_names_are_preserved() {
        assert_eq!(SyntaxKind::EofToken.display_name(), "end of file");
        assert_eq!(SyntaxKind::LBrace.display_name(), "'{'");
        assert_eq!(SyntaxKind::KwObjectType.display_name(), "OBJECT_TYPE");
        assert_eq!(SyntaxKind::KwObjectType.libsmi_name(), "OBJECT_TYPE");
        assert_eq!(SyntaxKind::NegativeNumber.libsmi_name(), "NEGATIVENUMBER");
        assert_eq!(SyntaxKind::ColonColonEqual.fixed_text(), Some("::="));
    }
}
