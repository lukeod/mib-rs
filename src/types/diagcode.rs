use super::Severity;

macro_rules! diag_codes {
    ( $( $phase:ident, $variant:ident, $code:literal, $severity:ident; )* ) => {
        /// Diagnostic code identifying a specific diagnostic condition.
        /// Each code has a fixed severity and belongs to a pipeline phase.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum DiagCode {
            $( $variant, )*
        }

        impl DiagCode {
            /// Returns the stable kebab-case string code for fixture comparison and output.
            pub fn as_code(self) -> &'static str {
                match self {
                    $( DiagCode::$variant => $code, )*
                }
            }

            /// Parse a kebab-case code string into a DiagCode.
            pub fn from_code(s: &str) -> Option<DiagCode> {
                match s {
                    $( $code => Some(DiagCode::$variant), )*
                    _ => None,
                }
            }

            /// Returns the fixed severity for this diagnostic code.
            pub fn severity(self) -> Severity {
                match self {
                    $( DiagCode::$variant => Severity::$severity, )*
                }
            }

            /// Returns the pipeline phase that emits this diagnostic.
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

    // Lowering
    lowering,   MissingModuleIdentity,      "missing-module-identity",               Warning;
    lowering,   RevisionLastUpdated,        "revision-last-updated",                 Minor;
    lowering,   RevisionNotDescending,      "revision-not-descending",               Minor;
    lowering,   RevisionAfterUpdate,        "revision-after-update",                 Minor;
    lowering,   DateCharacter,              "date-character",                        Error;
    lowering,   DateLength,                 "date-length",                           Error;
    lowering,   DateMonth,                  "date-month",                            Error;
    lowering,   DateDay,                    "date-day",                              Error;
    lowering,   DateHour,                   "date-hour",                             Error;
    lowering,   DateMinutes,               "date-minutes",                          Error;
    lowering,   DateValue,                  "date-value",                            Error;
    lowering,   DateYear2Digits,            "date-year-2digits",                     Warning;
    lowering,   DateInFuture,               "date-in-future",                        Style;
    lowering,   DateInPast,                 "date-in-past",                          Style;
    lowering,   UnknownDefinitionType,      "unknown-definition-type",               Warning;
    lowering,   UnknownTypeSyntax,          "unknown-type-syntax",                   Warning;
    lowering,   UnknownConstraintType,      "unknown-constraint-type",               Warning;
    lowering,   UnknownRangeValue,          "unknown-range-value",                   Warning;
    lowering,   UnknownOidComponent,        "unknown-oid-component-type",            Warning;
    lowering,   UnknownDefvalType,          "unknown-defval-type",                   Warning;
    lowering,   BitsNumberNegative,         "bits-number-negative",                  Error;
    lowering,   BitsNumberTooLarge,         "bits-number-too-large",                 Error;
    lowering,   BitsNumberLarge,            "bits-number-large",                     Style;
    lowering,   EnumZero,                   "enum-zero",                             Error;
    lowering,   EnumNameRedefinition,       "enum-name-redefinition",                Error;
    lowering,   EnumValueRedefinition,      "enum-value-redefinition",               Error;
    lowering,   BitsNameRedefinition,       "bits-name-redefinition",                Error;
    lowering,   BitsValueRedefinition,      "bits-value-redefinition",               Error;
    lowering,   ModuleIdentityNotFirst,     "module-identity-not-first",             Warning;
    lowering,   ModuleIdentityMultiple,     "module-identity-multiple",              Error;
    lowering,   MacroNotImported,           "macro-not-imported",                    Minor;
    lowering,   EmptyDescription,           "empty-description",                     Style;
    lowering,   EmptyReference,             "empty-reference",                       Style;
    lowering,   EmptyOrganization,          "empty-organization",                    Style;
    lowering,   EmptyContact,               "empty-contact",                         Style;
    lowering,   EmptyUnits,                 "empty-units",                           Style;
    lowering,   EmptyFormat,                "empty-format",                          Style;
    lowering,   ModuleNameSuffix,           "module-name-suffix",                    Style;
    lowering,   MacroNotAllowed,            "macro-not-allowed",                     Warning;
    lowering,   ChoiceNotAllowed,           "choice-not-allowed",                    Warning;
    lowering,   TaggedTypeNotAllowed,       "tagged-type-not-allowed",               Warning;

    // Resolver
    resolver,   ImportNotFound,             "import-not-found",                      Error;
    resolver,   ImportModuleNotFound,       "import-module-not-found",               Error;
    resolver,   TypeUnknown,                "type-unknown",                          Error;
    resolver,   OidOrphan,                  "oid-orphan",                            Error;
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
    resolver,   GroupMemberUnresolved,       "group-member-unresolved",              Error;
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
    resolver,   GroupObjectsNotification,   "group-objects-notification",             Error;
    resolver,   GroupNotificationsObject,   "group-notifications-object",             Error;
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
}

impl std::fmt::Display for DiagCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_code())
    }
}

/// Returns all known diagnostic codes.
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
                ["lexer", "parser", "lowering", "resolver"].contains(&phase),
                "unknown phase {phase} for {code}"
            );
        }
    }
}
