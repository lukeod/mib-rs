//! Diagnostic code definitions.
//!
//! Each [`DiagCode`] variant identifies a specific diagnostic condition with a
//! fixed [`Severity`] and pipeline phase. Codes use stable kebab-case string
//! representations for configuration and filtering.

use super::Severity;

macro_rules! diag_codes {
    ( $( $phase:ident, $variant:ident, $code:literal, $severity:ident; )* ) => {
        /// Identifies a specific diagnostic condition.
        ///
        /// Each code has a fixed [`Severity`] and belongs to a pipeline phase
        /// (lexer, parser, lower, or resolver). Use [`DiagCode::as_code`] for the
        /// stable kebab-case string representation.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum DiagCode {
            $( $variant, )*
        }

        impl DiagCode {
            /// Returns the stable kebab-case string representation (e.g. `"parse-error"`).
            pub fn as_code(self) -> &'static str {
                match self {
                    $( DiagCode::$variant => $code, )*
                }
            }

            /// Parses a kebab-case code string into a [`DiagCode`], returning `None` if unrecognized.
            pub fn from_code(s: &str) -> Option<DiagCode> {
                match s {
                    $( $code => Some(DiagCode::$variant), )*
                    _ => None,
                }
            }

            /// Returns the fixed [`Severity`] for this diagnostic code.
            pub fn severity(self) -> Severity {
                match self {
                    $( DiagCode::$variant => Severity::$severity, )*
                }
            }

            /// Returns the pipeline phase that emits this diagnostic (e.g. `"lexer"`, `"resolver"`).
            pub fn phase(self) -> &'static str {
                match self {
                    $( DiagCode::$variant => stringify!($phase), )*
                }
            }
        }

        /// All diagnostic codes in declaration order.
        const ALL_CODES: &[DiagCode] = &[
            $( DiagCode::$variant, )*
        ];
    };
}

diag_codes! {
    // Lexer
    lexer,      UnexpectedCharacter,        "unexpected-character",                  Error;
    lexer,      UnterminatedString,         "unterminated-string",                   Error;
    lexer,      UnterminatedHexBinStr,      "unterminated-hex-bin-string",           Error;
    lexer,      MissingHexBinSuffix,        "missing-hex-bin-suffix",               Error;
    lexer,      HexStringMul2,              "hex-string-mul2",                       Warning;
    lexer,      BinStringMul8,              "bin-string-mul8",                       Warning;
    lexer,      HexStringInvalidChar,       "hex-string-invalid-char",               Warning;
    lexer,      BinStringInvalidChar,       "bin-string-invalid-char",               Warning;

    // Parser
    parser,     IdentifierUnderscore,       "identifier-underscore",                 Style;
    parser,     IdentifierHyphenEnd,        "identifier-hyphen-end",                 Error;
    parser,     IdentifierLength64,         "identifier-length-64",                  Error;
    parser,     IdentifierLength32,         "identifier-length-32",                  Warning;
    parser,     BadIdentifierCase,          "bad-identifier-case",                   Error;
    parser,     ParseError,                 "parse-error",                           Error;
    parser,     InvalidU32,                 "invalid-u32",                           Error;
    parser,     InvalidI64,                 "invalid-i64",                           Error;
    parser,     KeywordReserved,            "keyword-reserved",                      Severe;
    parser,     InvalidHexRange,            "invalid-hex-range",                     Error;
    parser,     NumberLeadingZero,          "number-leading-zero",                   Minor;
    parser,     MissingComma,              "missing-comma",                         Minor;

    // Lower
    lower,      MissingModuleIdentity,      "missing-module-identity",               Warning;
    lower,      RevisionLastUpdated,        "revision-last-updated",                 Minor;
    lower,      RevisionNotDescending,      "revision-not-descending",               Minor;
    lower,      RevisionAfterUpdate,        "revision-after-update",                 Minor;
    lower,      DateCharacter,              "date-character",                        Error;
    lower,      DateLength,                 "date-length",                           Error;
    lower,      DateMonth,                  "date-month",                            Error;
    lower,      DateDay,                    "date-day",                              Error;
    lower,      DateHour,                   "date-hour",                             Error;
    lower,      DateMinutes,               "date-minutes",                          Error;
    lower,      DateValue,                  "date-value",                            Error;
    lower,      DateYear2Digits,            "date-year-2digits",                     Warning;
    lower,      DateInFuture,               "date-in-future",                        Style;
    lower,      DateInPast,                 "date-in-past",                          Style;
    lower,      UnknownDefinitionType,      "unknown-definition-type",               Warning;
    lower,      UnknownTypeSyntax,          "unknown-type-syntax",                   Warning;
    lower,      UnknownConstraintType,      "unknown-constraint-type",               Warning;
    lower,      UnknownRangeValue,          "unknown-range-value",                   Warning;
    lower,      MinMaxRange,                "min-max-range",                         Warning;
    lower,      UnknownOidComponent,        "unknown-oid-component-type",            Warning;
    lower,      UnknownDefvalType,          "unknown-defval-type",                   Warning;
    lower,      BitsNumberNegative,         "bits-number-negative",                  Error;
    lower,      BitsNumberTooLarge,         "bits-number-too-large",                 Error;
    lower,      BitsNumberLarge,            "bits-number-large",                     Style;
    lower,      EnumZero,                   "enum-zero",                             Error;
    lower,      EnumValueOutOfRange,        "enum-value-out-of-range",                Warning;
    lower,      EnumNameRedefinition,       "enum-name-redefinition",                Error;
    lower,      EnumValueRedefinition,      "enum-value-redefinition",               Error;
    lower,      BitsNameRedefinition,       "bits-name-redefinition",                Error;
    lower,      BitsValueRedefinition,      "bits-value-redefinition",               Error;
    lower,      ModuleIdentityNotFirst,     "module-identity-not-first",             Warning;
    lower,      ModuleIdentityMultiple,     "module-identity-multiple",              Error;
    lower,      MacroNotImported,           "macro-not-imported",                    Minor;
    lower,      EmptyDescription,           "empty-description",                     Style;
    lower,      EmptyRevisionDescription,   "empty-revision-description",            Style;
    lower,      EmptyReference,             "empty-reference",                       Style;
    lower,      EmptyOrganization,          "empty-organization",                    Style;
    lower,      EmptyContact,               "empty-contact",                         Style;
    lower,      EmptyUnits,                 "empty-units",                           Style;
    lower,      EmptyFormat,                "empty-format",                          Style;
    lower,      ModuleNameSuffix,           "module-name-suffix",                    Style;
    lower,      MacroNotAllowed,            "macro-not-allowed",                     Warning;
    lower,      ChoiceNotAllowed,           "choice-not-allowed",                    Warning;
    lower,      TaggedTypeNotAllowed,       "tagged-type-not-allowed",               Warning;

    // Resolver
    resolver,   ImportNotFound,             "import-not-found",                      Error;
    resolver,   ImportModuleNotFound,       "import-module-not-found",               Error;
    resolver,   TypeUnknown,                "type-unknown",                          Error;
    resolver,   TypeCycle,                  "type-cycle",                            Error;
    resolver,   OidOrphan,                  "oid-orphan",                            Error;
    resolver,   TrapNumberOverflow,         "trap-number-overflow",                  Error;
    resolver,   IndexUnresolved,            "index-unresolved",                      Error;
    resolver,   ObjectsUnresolved,          "objects-unresolved",                    Error;
    resolver,   IdentifierHyphenSMIv2,      "identifier-hyphen-smiv2",               Warning;
    resolver,   GroupNotAccessible,          "group-not-accessible",                  Minor;
    resolver,   NotifObjectNotObject,       "notification-object-not-object",        Minor;
    resolver,   NotifObjectAccess,          "notification-object-access",            Minor;
    resolver,   NotifNotReversible,         "notification-not-reversible",           Warning;
    resolver,   NotifIdTooLarge,            "notification-id-too-large",             Warning;
    resolver,   MalformedHexDefval,         "malformed-hex-defval",                  Warning;
    resolver,   MalformedBinDefval,         "malformed-bin-defval",                  Warning;
    resolver,   DefvalUnresolved,           "defval-unresolved",                     Warning;
    resolver,   VariationAccessNotifOnly,   "variation-access-notification-only",    Minor;
    resolver,   GroupMemberUnresolved,       "group-member-unresolved",              Minor;
    resolver,   IndexNotObject,             "index-not-object",                      Minor;
    resolver,   AugmentsNotObject,          "augments-not-object",                   Minor;
    resolver,   AugmentNested,              "augment-nested",                        Error;
    resolver,   NotifNoOid,                 "notification-no-oid",                   Minor;
    resolver,   PrimitiveTypeMissing,       "primitive-type-missing",                Error;
    resolver,   IntegerInSMIv2,             "integer-in-smiv2",                      Warning;
    resolver,   IndexIntegerNoRange,        "index-integer-no-range",                Error;
    resolver,   IndexNegativeRange,         "index-negative-range",                  Error;
    resolver,   DefvalBasetype,             "defval-basetype",                       Warning;
    resolver,   DefvalRange,                "defval-range",                          Warning;
    resolver,   DefvalEnum,                 "defval-enum",                           Warning;
    resolver,   DefvalBits,                 "defval-bits",                           Warning;
    resolver,   CounterDefvalIllegal,       "counter-defval-illegal",                Warning;
    resolver,   IndexCounterIllegal,        "index-counter-illegal",                 Warning;
    resolver,   RangeBounds,                "range-bounds",                          Error;
    resolver,   ConstraintEmptyIntersection,"constraint-empty-intersection",          Warning;
    resolver,   RangeExchanged,             "range-exchanged",                       Error;
    resolver,   RangeOverlap,               "range-overlap",                         Error;
    resolver,   RangeAscending,             "range-ascending",                       Warning;
    resolver,   SizeIllegal,                "size-illegal",                          Error;
    resolver,   RangeIllegal,               "range-illegal",                         Error;
    resolver,   CounterRangeIllegal,        "counter-range-illegal",                 Error;
    resolver,   SubtypeEnumIllegal,         "subtype-enumeration-illegal",           Error;
    resolver,   SubtypeBitsIllegal,         "subtype-bits-illegal",                  Error;
    resolver,   ParentTable,                "parent-table",                          Error;
    resolver,   ParentRow,                  "parent-row",                            Error;
    resolver,   ParentColumn,               "parent-column",                         Error;
    resolver,   ParentScalar,               "parent-scalar",                         Error;
    resolver,   ParentNode,                 "parent-node",                           Error;
    resolver,   ParentNotification,         "parent-notification",                   Error;
    resolver,   ParentGroup,                "parent-group",                          Error;
    resolver,   ParentCompliance,           "parent-compliance",                     Error;
    resolver,   ParentCapabilities,         "parent-capabilities",                   Error;
    resolver,   RowSubidentifierOne,        "row-node-subidentifier-one",            Error;
    resolver,   IndexElementNoSize,         "index-element-no-size",                 Minor;
    resolver,   IndexIllegalBasetype,       "index-illegal-basetype",                Severe;
    resolver,   LastSubidZero,              "last-subid-zero",                       Severe;
    resolver,   OidRecursive,               "oid-recursive",                         Error;
    resolver,   OidRegistered,              "oid-registered",                        Severe;
    resolver,   OidReuse,                   "oid-reuse",                             Warning;
    resolver,   SequenceNoColumn,           "sequence-no-column",                    Minor;
    resolver,   SequenceMissingColumn,      "sequence-missing-column",               Minor;
    resolver,   SequenceOrder,              "sequence-order",                        Warning;
    resolver,   SequenceTypeMismatch,       "sequence-type-mismatch",                Error;
    resolver,   IndexExceedsTooLarge,       "index-exceeds-too-large",               Warning;
    resolver,   AccessInvalidSMIv1,         "access-invalid-smiv1",                  Error;
    resolver,   AccessWriteOnlySMIv2,       "access-write-only-smiv2",               Error;
    resolver,   AccessTableIllegal,         "access-table-illegal",                  Minor;
    resolver,   AccessRowIllegal,           "access-row-illegal",                    Minor;
    resolver,   AccessCounterIllegal,       "access-counter-illegal",                Style;
    resolver,   ScalarNotCreatable,         "scalar-not-creatable",                  Minor;
    resolver,   MaxAccessInSMIv1,           "maxaccess-in-smiv1",                    Error;
    resolver,   AccessInSMIv2,              "access-in-smiv2",                       Error;
    resolver,   StatusInvalidSMIv1,         "status-invalid-smiv1",                  Error;
    resolver,   StatusInvalidSMIv2,         "status-invalid-smiv2",                  Error;
    resolver,   TypeStatusDeprecated,       "type-status-deprecated",                Warning;
    resolver,   TypeStatusObsolete,         "type-status-obsolete",                  Warning;
    resolver,   GroupMembership,            "group-membership",                      Minor;
    resolver,   GroupMemberMixed,           "group-member-mixed",                    Minor;
    resolver,   GroupObjectsNotification,   "group-objects-notification",             Minor;
    resolver,   GroupNotificationsObject,   "group-notifications-object",             Minor;
    resolver,   GroupObjectStatus,          "group-object-status",                   Warning;
    resolver,   ComplianceGroupStatus,      "compliance-group-status",               Warning;
    resolver,   ComplianceObjectStatus,     "compliance-object-status",              Warning;
    resolver,   ComplianceGroupInvalid,     "compliance-group-invalid",              Warning;
    resolver,   RefinementExists,           "refinement-exists",                     Warning;
    resolver,   OptionalGroupExists,        "optional-group-exists",                 Warning;
    resolver,   RefinementNotListed,        "refinement-not-listed",                 Warning;
    resolver,   ComplianceMemberNotLocal,   "compliance-member-not-local",           Warning;
    resolver,   TimeticksRangeIllegal,      "timeticks-range-illegal",               Error;
    resolver,   StatusInvalidCapabilities,  "status-invalid-capabilities",           Error;
    resolver,   ImportDuplicate,            "import-duplicate",                      Minor;
    resolver,   ImportUnused,               "import-unused",                         Style;
    resolver,   BasetypeNotImported,        "basetype-not-imported",                 Minor;
    resolver,   DescriptionMissing,         "description-missing",                   Minor;
    resolver,   TCNested,                   "textual-convention-nested",             Style;
    resolver,   TypeAssignmentSMIv2,        "type-assignment-smiv2",                 Style;
    resolver,   TableNameTable,             "table-name-table",                      Style;
    resolver,   RowNameEntry,               "row-name-entry",                        Style;
    resolver,   RowNameTableName,           "row-name-table-name",                   Style;
    resolver,   NamedNumbersAscending,      "named-numbers-ascending",               Style;
    resolver,   HyphenInLabel,              "hyphen-in-label",                       Style;
    resolver,   OpaqueSMIv2,                "opaque-smiv2",                          Warning;
    resolver,   InvalidFormat,              "invalid-format",                        Error;
    resolver,   TypeWithoutFormat,          "type-without-format",                   Style;
    resolver,   TypeUnreferenced,           "type-unref",                            Style;
    resolver,   GroupUnreferenced,          "group-unref",                           Style;
    resolver,   ObsoleteImport,             "obsolete-import",                       Warning;
    resolver,   IdentifierCaseMatch,        "identifier-case-match",                 Style;
    resolver,   TrapInSMIv2,               "trap-in-smiv2",                         Warning;
    resolver,   NodeImplicit,               "node-implicit",                         Style;
    resolver,   ModuleIdentityReg,          "module-identity-registration",          Warning;
    resolver,   RowStatusDefault,           "rowstatus-default",                     Style;
    resolver,   RowStatusAccess,            "rowstatus-access",                      Style;
    resolver,   StorageTypeDefault,         "storagetype-default",                   Style;
    resolver,   TAddressTDomain,            "taddress-tdomain",                      Warning;
    resolver,   IndexAccessible,            "index-accessible",                      Minor;
    resolver,   IndexNotAccessible,         "index-not-accessible",                  Minor;
    resolver,   IndexDefval,                "index-defval",                          Warning;
    resolver,   AccessWriteOnlySMIv1,       "access-write-only-smiv1",               Style;
    resolver,   IpAddressInSyntax,          "ipaddress-in-syntax",                   Style;
    resolver,   InetAddressPairing,         "inetaddress-inetaddresstype",           Warning;
    resolver,   InetAddressTypeSubtyped,    "inetaddresstype-subtyped",              Warning;
    resolver,   InetAddressSpecific,        "inetaddress-specific",                  Style;
    resolver,   TransportAddressPairing,    "transportaddress-transportaddresstype", Warning;
    resolver,   TransportAddressTypeSubtyped, "transportaddresstype-subtyped",       Warning;
    resolver,   TransportAddressSpecific,   "transportaddress-specific",             Style;
    resolver,   IncludesUnresolved,         "includes-unresolved",                   Warning;
    resolver,   IncludesDuplicate,          "includes-duplicate",                    Warning;
    resolver,   CreationRequiresUnresolved, "creation-requires-unresolved",           Warning;
    resolver,   CreationRequiresDuplicate,  "creation-requires-duplicate",            Warning;
}

impl std::fmt::Display for DiagCode {
    /// Formats as the kebab-case code string (same as [`DiagCode::as_code`]).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_code())
    }
}

/// Returns all known diagnostic codes in declaration order.
pub fn all_diagnostic_codes() -> &'static [DiagCode] {
    ALL_CODES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrip() {
        for &code in ALL_CODES {
            let s = code.as_code();
            let parsed = DiagCode::from_code(s).unwrap_or_else(|| panic!("failed to parse {s}"));
            assert_eq!(parsed, code);
        }
    }

    #[test]
    fn all_codes_have_severity() {
        for &code in ALL_CODES {
            let _ = code.severity();
        }
    }

    #[test]
    fn all_codes_have_phase() {
        for &code in ALL_CODES {
            let phase = code.phase();
            assert!(
                ["lexer", "parser", "lower", "resolver"].contains(&phase),
                "unknown phase {phase} for {code}"
            );
        }
    }
}
