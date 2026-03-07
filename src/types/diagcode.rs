use super::Severity;

/// Diagnostic code identifying a specific diagnostic condition.
/// Each code has a fixed severity and belongs to a pipeline phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagCode {
    // Lexer
    UnexpectedCharacter,
    UnterminatedString,
    UnterminatedHexBinStr,
    MissingHexBinSuffix,
    HexStringMul2,
    BinStringMul8,

    // Parser
    IdentifierUnderscore,
    IdentifierHyphenEnd,
    IdentifierLength64,
    IdentifierLength32,
    BadIdentifierCase,
    ParseError,
    InvalidU32,
    InvalidI64,
    KeywordReserved,
    InvalidHexRange,
    NumberLeadingZero,

    // Lowering
    MissingModuleIdentity,
    RevisionLastUpdated,
    RevisionNotDescending,
    RevisionAfterUpdate,
    DateCharacter,
    DateLength,
    DateMonth,
    DateDay,
    DateHour,
    DateMinutes,
    DateValue,
    DateYear2Digits,
    DateInFuture,
    DateInPast,
    UnknownDefinitionType,
    UnknownTypeSyntax,
    UnknownConstraintType,
    UnknownRangeValue,
    UnknownOidComponent,
    UnknownDefvalType,
    BitsNumberNegative,
    BitsNumberTooLarge,
    BitsNumberLarge,
    EnumZero,
    EnumNameRedefinition,
    EnumValueRedefinition,
    BitsNameRedefinition,
    BitsValueRedefinition,
    ModuleIdentityNotFirst,
    ModuleIdentityMultiple,
    MacroNotImported,
    EmptyDescription,
    EmptyReference,
    EmptyOrganization,
    EmptyContact,
    EmptyUnits,
    EmptyFormat,
    ModuleNameSuffix,
    MacroNotAllowed,
    ChoiceNotAllowed,
    TaggedTypeNotAllowed,

    // Resolver
    ImportNotFound,
    ImportModuleNotFound,
    TypeUnknown,
    OidOrphan,
    IndexUnresolved,
    ObjectsUnresolved,
    IdentifierHyphenSMIv2,
    GroupNotAccessible,
    NotifObjectNotObject,
    NotifObjectAccess,
    NotifNotReversible,
    NotifIdTooLarge,
    MalformedHexDefval,
    MalformedBinDefval,
    DefvalUnresolved,
    VariationAccessNotifOnly,
    GroupMemberUnresolved,
    IndexNotObject,
    AugmentsNotObject,
    AugmentNested,
    NotifNoOid,
    PrimitiveTypeMissing,
    IntegerInSMIv2,
    IndexIntegerNoRange,
    IndexNegativeRange,
    DefvalBasetype,
    DefvalRange,
    DefvalEnum,
    DefvalBits,
    CounterDefvalIllegal,
    IndexCounterIllegal,
    RangeBounds,
    RangeExchanged,
    RangeOverlap,
    RangeAscending,
    SizeIllegal,
    RangeIllegal,
    CounterRangeIllegal,
    SubtypeEnumIllegal,
    SubtypeBitsIllegal,
    ParentTable,
    ParentRow,
    ParentColumn,
    ParentScalar,
    ParentNode,
    ParentNotification,
    ParentGroup,
    ParentCompliance,
    ParentCapabilities,
    RowSubidentifierOne,
    IndexElementNoSize,
    IndexIllegalBasetype,
    LastSubidZero,
    OidRecursive,
    OidRegistered,
    OidReuse,
    SequenceNoColumn,
    SequenceMissingColumn,
    SequenceOrder,
    SequenceTypeMismatch,
    IndexExceedsTooLarge,
    AccessInvalidSMIv1,
    AccessWriteOnlySMIv2,
    AccessTableIllegal,
    AccessRowIllegal,
    AccessCounterIllegal,
    ScalarNotCreatable,
    MaxAccessInSMIv1,
    AccessInSMIv2,
    StatusInvalidSMIv1,
    StatusInvalidSMIv2,
    TypeStatusDeprecated,
    TypeStatusObsolete,
    GroupMembership,
    GroupMemberMixed,
    GroupObjectsNotification,
    GroupNotificationsObject,
    GroupObjectStatus,
    ComplianceGroupStatus,
    ComplianceObjectStatus,
    ComplianceGroupInvalid,
    RefinementExists,
    OptionalGroupExists,
    RefinementNotListed,
    ComplianceMemberNotLocal,
    TimeticksRangeIllegal,
    StatusInvalidCapabilities,
    ImportUnused,
    BasetypeNotImported,
    DescriptionMissing,
    TCNested,
    TypeAssignmentSMIv2,
    TableNameTable,
    RowNameEntry,
    RowNameTableName,
    NamedNumbersAscending,
    HyphenInLabel,
    OpaqueSMIv2,
    InvalidFormat,
    TypeWithoutFormat,
    TypeUnreferenced,
    GroupUnreferenced,
    ObsoleteImport,
    IdentifierCaseMatch,
    TrapInSMIv2,
    NodeImplicit,
    ModuleIdentityReg,
    RowStatusDefault,
    RowStatusAccess,
    StorageTypeDefault,
    TAddressTDomain,
    IndexAccessible,
    IndexNotAccessible,
    IndexDefval,
    AccessWriteOnlySMIv1,
    IpAddressInSyntax,
    InetAddressPairing,
    InetAddressTypeSubtyped,
    InetAddressSpecific,
    TransportAddressPairing,
    TransportAddressTypeSubtyped,
    TransportAddressSpecific,
}

impl DiagCode {
    /// Returns the stable kebab-case string code for fixture comparison and output.
    pub fn as_code(self) -> &'static str {
        match self {
            // Lexer
            DiagCode::UnexpectedCharacter => "unexpected-character",
            DiagCode::UnterminatedString => "unterminated-string",
            DiagCode::UnterminatedHexBinStr => "unterminated-hex-bin-string",
            DiagCode::MissingHexBinSuffix => "missing-hex-bin-suffix",
            DiagCode::HexStringMul2 => "hex-string-mul2",
            DiagCode::BinStringMul8 => "bin-string-mul8",
            // Parser
            DiagCode::IdentifierUnderscore => "identifier-underscore",
            DiagCode::IdentifierHyphenEnd => "identifier-hyphen-end",
            DiagCode::IdentifierLength64 => "identifier-length-64",
            DiagCode::IdentifierLength32 => "identifier-length-32",
            DiagCode::BadIdentifierCase => "bad-identifier-case",
            DiagCode::ParseError => "parse-error",
            DiagCode::InvalidU32 => "invalid-u32",
            DiagCode::InvalidI64 => "invalid-i64",
            DiagCode::KeywordReserved => "keyword-reserved",
            DiagCode::InvalidHexRange => "invalid-hex-range",
            DiagCode::NumberLeadingZero => "number-leading-zero",
            // Lowering
            DiagCode::MissingModuleIdentity => "missing-module-identity",
            DiagCode::RevisionLastUpdated => "revision-last-updated",
            DiagCode::RevisionNotDescending => "revision-not-descending",
            DiagCode::RevisionAfterUpdate => "revision-after-update",
            DiagCode::DateCharacter => "date-character",
            DiagCode::DateLength => "date-length",
            DiagCode::DateMonth => "date-month",
            DiagCode::DateDay => "date-day",
            DiagCode::DateHour => "date-hour",
            DiagCode::DateMinutes => "date-minutes",
            DiagCode::DateValue => "date-value",
            DiagCode::DateYear2Digits => "date-year-2digits",
            DiagCode::DateInFuture => "date-in-future",
            DiagCode::DateInPast => "date-in-past",
            DiagCode::UnknownDefinitionType => "unknown-definition-type",
            DiagCode::UnknownTypeSyntax => "unknown-type-syntax",
            DiagCode::UnknownConstraintType => "unknown-constraint-type",
            DiagCode::UnknownRangeValue => "unknown-range-value",
            DiagCode::UnknownOidComponent => "unknown-oid-component-type",
            DiagCode::UnknownDefvalType => "unknown-defval-type",
            DiagCode::BitsNumberNegative => "bits-number-negative",
            DiagCode::BitsNumberTooLarge => "bits-number-too-large",
            DiagCode::BitsNumberLarge => "bits-number-large",
            DiagCode::EnumZero => "enum-zero",
            DiagCode::EnumNameRedefinition => "enum-name-redefinition",
            DiagCode::EnumValueRedefinition => "enum-value-redefinition",
            DiagCode::BitsNameRedefinition => "bits-name-redefinition",
            DiagCode::BitsValueRedefinition => "bits-value-redefinition",
            DiagCode::ModuleIdentityNotFirst => "module-identity-not-first",
            DiagCode::ModuleIdentityMultiple => "module-identity-multiple",
            DiagCode::MacroNotImported => "macro-not-imported",
            DiagCode::EmptyDescription => "empty-description",
            DiagCode::EmptyReference => "empty-reference",
            DiagCode::EmptyOrganization => "empty-organization",
            DiagCode::EmptyContact => "empty-contact",
            DiagCode::EmptyUnits => "empty-units",
            DiagCode::EmptyFormat => "empty-format",
            DiagCode::ModuleNameSuffix => "module-name-suffix",
            DiagCode::MacroNotAllowed => "macro-not-allowed",
            DiagCode::ChoiceNotAllowed => "choice-not-allowed",
            DiagCode::TaggedTypeNotAllowed => "tagged-type-not-allowed",
            // Resolver
            DiagCode::ImportNotFound => "import-not-found",
            DiagCode::ImportModuleNotFound => "import-module-not-found",
            DiagCode::TypeUnknown => "type-unknown",
            DiagCode::OidOrphan => "oid-orphan",
            DiagCode::IndexUnresolved => "index-unresolved",
            DiagCode::ObjectsUnresolved => "objects-unresolved",
            DiagCode::IdentifierHyphenSMIv2 => "identifier-hyphen-smiv2",
            DiagCode::GroupNotAccessible => "group-not-accessible",
            DiagCode::NotifObjectNotObject => "notification-object-not-object",
            DiagCode::NotifObjectAccess => "notification-object-access",
            DiagCode::NotifNotReversible => "notification-not-reversible",
            DiagCode::NotifIdTooLarge => "notification-id-too-large",
            DiagCode::MalformedHexDefval => "malformed-hex-defval",
            DiagCode::MalformedBinDefval => "malformed-bin-defval",
            DiagCode::DefvalUnresolved => "defval-unresolved",
            DiagCode::VariationAccessNotifOnly => "variation-access-notification-only",
            DiagCode::GroupMemberUnresolved => "group-member-unresolved",
            DiagCode::IndexNotObject => "index-not-object",
            DiagCode::AugmentsNotObject => "augments-not-object",
            DiagCode::AugmentNested => "augment-nested",
            DiagCode::NotifNoOid => "notification-no-oid",
            DiagCode::PrimitiveTypeMissing => "primitive-type-missing",
            DiagCode::IntegerInSMIv2 => "integer-in-smiv2",
            DiagCode::IndexIntegerNoRange => "index-integer-no-range",
            DiagCode::IndexNegativeRange => "index-negative-range",
            DiagCode::DefvalBasetype => "defval-basetype",
            DiagCode::DefvalRange => "defval-range",
            DiagCode::DefvalEnum => "defval-enum",
            DiagCode::DefvalBits => "defval-bits",
            DiagCode::CounterDefvalIllegal => "counter-defval-illegal",
            DiagCode::IndexCounterIllegal => "index-counter-illegal",
            DiagCode::RangeBounds => "range-bounds",
            DiagCode::RangeExchanged => "range-exchanged",
            DiagCode::RangeOverlap => "range-overlap",
            DiagCode::RangeAscending => "range-ascending",
            DiagCode::SizeIllegal => "size-illegal",
            DiagCode::RangeIllegal => "range-illegal",
            DiagCode::CounterRangeIllegal => "counter-range-illegal",
            DiagCode::SubtypeEnumIllegal => "subtype-enumeration-illegal",
            DiagCode::SubtypeBitsIllegal => "subtype-bits-illegal",
            DiagCode::ParentTable => "parent-table",
            DiagCode::ParentRow => "parent-row",
            DiagCode::ParentColumn => "parent-column",
            DiagCode::ParentScalar => "parent-scalar",
            DiagCode::ParentNode => "parent-node",
            DiagCode::ParentNotification => "parent-notification",
            DiagCode::ParentGroup => "parent-group",
            DiagCode::ParentCompliance => "parent-compliance",
            DiagCode::ParentCapabilities => "parent-capabilities",
            DiagCode::RowSubidentifierOne => "row-node-subidentifier-one",
            DiagCode::IndexElementNoSize => "index-element-no-size",
            DiagCode::IndexIllegalBasetype => "index-illegal-basetype",
            DiagCode::LastSubidZero => "last-subid-zero",
            DiagCode::OidRecursive => "oid-recursive",
            DiagCode::OidRegistered => "oid-registered",
            DiagCode::OidReuse => "oid-reuse",
            DiagCode::SequenceNoColumn => "sequence-no-column",
            DiagCode::SequenceMissingColumn => "sequence-missing-column",
            DiagCode::SequenceOrder => "sequence-order",
            DiagCode::SequenceTypeMismatch => "sequence-type-mismatch",
            DiagCode::IndexExceedsTooLarge => "index-exceeds-too-large",
            DiagCode::AccessInvalidSMIv1 => "access-invalid-smiv1",
            DiagCode::AccessWriteOnlySMIv2 => "access-write-only-smiv2",
            DiagCode::AccessTableIllegal => "access-table-illegal",
            DiagCode::AccessRowIllegal => "access-row-illegal",
            DiagCode::AccessCounterIllegal => "access-counter-illegal",
            DiagCode::ScalarNotCreatable => "scalar-not-creatable",
            DiagCode::MaxAccessInSMIv1 => "maxaccess-in-smiv1",
            DiagCode::AccessInSMIv2 => "access-in-smiv2",
            DiagCode::StatusInvalidSMIv1 => "status-invalid-smiv1",
            DiagCode::StatusInvalidSMIv2 => "status-invalid-smiv2",
            DiagCode::TypeStatusDeprecated => "type-status-deprecated",
            DiagCode::TypeStatusObsolete => "type-status-obsolete",
            DiagCode::GroupMembership => "group-membership",
            DiagCode::GroupMemberMixed => "group-member-mixed",
            DiagCode::GroupObjectsNotification => "group-objects-notification",
            DiagCode::GroupNotificationsObject => "group-notifications-object",
            DiagCode::GroupObjectStatus => "group-object-status",
            DiagCode::ComplianceGroupStatus => "compliance-group-status",
            DiagCode::ComplianceObjectStatus => "compliance-object-status",
            DiagCode::ComplianceGroupInvalid => "compliance-group-invalid",
            DiagCode::RefinementExists => "refinement-exists",
            DiagCode::OptionalGroupExists => "optional-group-exists",
            DiagCode::RefinementNotListed => "refinement-not-listed",
            DiagCode::ComplianceMemberNotLocal => "compliance-member-not-local",
            DiagCode::TimeticksRangeIllegal => "timeticks-range-illegal",
            DiagCode::StatusInvalidCapabilities => "status-invalid-capabilities",
            DiagCode::ImportUnused => "import-unused",
            DiagCode::BasetypeNotImported => "basetype-not-imported",
            DiagCode::DescriptionMissing => "description-missing",
            DiagCode::TCNested => "textual-convention-nested",
            DiagCode::TypeAssignmentSMIv2 => "type-assignment-smiv2",
            DiagCode::TableNameTable => "table-name-table",
            DiagCode::RowNameEntry => "row-name-entry",
            DiagCode::RowNameTableName => "row-name-table-name",
            DiagCode::NamedNumbersAscending => "named-numbers-ascending",
            DiagCode::HyphenInLabel => "hyphen-in-label",
            DiagCode::OpaqueSMIv2 => "opaque-smiv2",
            DiagCode::InvalidFormat => "invalid-format",
            DiagCode::TypeWithoutFormat => "type-without-format",
            DiagCode::TypeUnreferenced => "type-unref",
            DiagCode::GroupUnreferenced => "group-unref",
            DiagCode::ObsoleteImport => "obsolete-import",
            DiagCode::IdentifierCaseMatch => "identifier-case-match",
            DiagCode::TrapInSMIv2 => "trap-in-smiv2",
            DiagCode::NodeImplicit => "node-implicit",
            DiagCode::ModuleIdentityReg => "module-identity-registration",
            DiagCode::RowStatusDefault => "rowstatus-default",
            DiagCode::RowStatusAccess => "rowstatus-access",
            DiagCode::StorageTypeDefault => "storagetype-default",
            DiagCode::TAddressTDomain => "taddress-tdomain",
            DiagCode::IndexAccessible => "index-accessible",
            DiagCode::IndexNotAccessible => "index-not-accessible",
            DiagCode::IndexDefval => "index-defval",
            DiagCode::AccessWriteOnlySMIv1 => "access-write-only-smiv1",
            DiagCode::IpAddressInSyntax => "ipaddress-in-syntax",
            DiagCode::InetAddressPairing => "inetaddress-inetaddresstype",
            DiagCode::InetAddressTypeSubtyped => "inetaddresstype-subtyped",
            DiagCode::InetAddressSpecific => "inetaddress-specific",
            DiagCode::TransportAddressPairing => "transportaddress-transportaddresstype",
            DiagCode::TransportAddressTypeSubtyped => "transportaddresstype-subtyped",
            DiagCode::TransportAddressSpecific => "transportaddress-specific",
        }
    }

    /// Parse a kebab-case code string into a DiagCode.
    pub fn from_code(s: &str) -> Option<DiagCode> {
        ALL_CODES.iter().find(|c| c.as_code() == s).copied()
    }

    /// Returns the fixed severity for this diagnostic code.
    pub fn severity(self) -> Severity {
        code_severity(self)
    }

    /// Returns the pipeline phase that emits this diagnostic.
    pub fn phase(self) -> &'static str {
        code_phase(self)
    }
}

impl std::fmt::Display for DiagCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_code())
    }
}

/// Fixed mapping from diagnostic code to severity.
pub fn code_severity(code: DiagCode) -> Severity {
    use DiagCode::*;
    use Severity::*;
    match code {
        // Lexer
        UnexpectedCharacter | UnterminatedString | UnterminatedHexBinStr | MissingHexBinSuffix => {
            Error
        }
        HexStringMul2 | BinStringMul8 => Warning,

        // Parser
        IdentifierUnderscore => Style,
        IdentifierHyphenEnd => Error,
        IdentifierLength64 => Error,
        IdentifierLength32 => Warning,
        BadIdentifierCase => Error,
        ParseError => Error,
        InvalidU32 => Error,
        InvalidI64 => Error,
        KeywordReserved => Severe,
        InvalidHexRange => Error,
        NumberLeadingZero => Minor,

        // Lowering
        MissingModuleIdentity => Warning,
        RevisionLastUpdated | RevisionNotDescending | RevisionAfterUpdate => Minor,
        DateCharacter | DateLength | DateMonth | DateDay | DateHour | DateMinutes | DateValue => {
            Error
        }
        DateYear2Digits => Warning,
        DateInFuture | DateInPast => Style,
        UnknownDefinitionType
        | UnknownTypeSyntax
        | UnknownConstraintType
        | UnknownRangeValue
        | UnknownOidComponent
        | UnknownDefvalType => Warning,
        BitsNumberNegative | BitsNumberTooLarge => Error,
        BitsNumberLarge => Style,
        EnumZero
        | EnumNameRedefinition
        | EnumValueRedefinition
        | BitsNameRedefinition
        | BitsValueRedefinition => Error,
        ModuleIdentityNotFirst => Warning,
        ModuleIdentityMultiple => Error,
        MacroNotImported => Minor,
        EmptyDescription | EmptyReference | EmptyOrganization | EmptyContact | EmptyUnits
        | EmptyFormat | ModuleNameSuffix => Style,
        MacroNotAllowed | ChoiceNotAllowed | TaggedTypeNotAllowed => Warning,

        // Resolver
        ImportNotFound | ImportModuleNotFound => Error,
        TypeUnknown => Error,
        OidOrphan => Error,
        IndexUnresolved | ObjectsUnresolved => Error,
        IdentifierHyphenSMIv2 => Warning,
        GroupNotAccessible => Minor,
        NotifObjectNotObject | NotifObjectAccess => Minor,
        NotifNotReversible | NotifIdTooLarge => Warning,
        MalformedHexDefval | MalformedBinDefval | DefvalUnresolved => Warning,
        VariationAccessNotifOnly => Minor,
        GroupMemberUnresolved => Error,
        IndexNotObject | AugmentsNotObject => Minor,
        AugmentNested => Error,
        NotifNoOid => Minor,
        PrimitiveTypeMissing => Error,
        IntegerInSMIv2 => Warning,
        IndexIntegerNoRange | IndexNegativeRange => Error,
        DefvalBasetype | DefvalRange | DefvalEnum | DefvalBits => Warning,
        CounterDefvalIllegal | IndexCounterIllegal => Warning,
        RangeBounds | RangeExchanged | RangeOverlap => Error,
        RangeAscending => Warning,
        SizeIllegal | RangeIllegal | CounterRangeIllegal | SubtypeEnumIllegal
        | SubtypeBitsIllegal => Error,
        ParentTable | ParentRow | ParentColumn | ParentScalar | ParentNode | ParentNotification
        | ParentGroup | ParentCompliance | ParentCapabilities => Error,
        RowSubidentifierOne => Error,
        IndexElementNoSize => Minor,
        IndexIllegalBasetype => Severe,
        LastSubidZero => Severe,
        OidRecursive => Error,
        OidRegistered => Severe,
        OidReuse => Warning,
        SequenceNoColumn | SequenceMissingColumn => Minor,
        SequenceOrder => Warning,
        SequenceTypeMismatch => Error,
        IndexExceedsTooLarge => Warning,
        AccessInvalidSMIv1 | AccessWriteOnlySMIv2 => Error,
        AccessTableIllegal | AccessRowIllegal => Minor,
        AccessCounterIllegal => Style,
        ScalarNotCreatable => Minor,
        MaxAccessInSMIv1 | AccessInSMIv2 => Error,
        StatusInvalidSMIv1 | StatusInvalidSMIv2 => Error,
        TypeStatusDeprecated | TypeStatusObsolete => Warning,
        GroupMembership => Minor,
        GroupMemberMixed => Minor,
        GroupObjectsNotification | GroupNotificationsObject => Error,
        GroupObjectStatus => Warning,
        ComplianceGroupStatus | ComplianceObjectStatus | ComplianceGroupInvalid => Warning,
        RefinementExists | OptionalGroupExists | RefinementNotListed | ComplianceMemberNotLocal => {
            Warning
        }
        TimeticksRangeIllegal | StatusInvalidCapabilities => Error,
        ImportUnused => Style,
        BasetypeNotImported => Minor,
        DescriptionMissing => Minor,
        TCNested
        | TypeAssignmentSMIv2
        | TableNameTable
        | RowNameEntry
        | RowNameTableName
        | NamedNumbersAscending
        | HyphenInLabel => Style,
        OpaqueSMIv2 => Warning,
        InvalidFormat => Error,
        TypeWithoutFormat | TypeUnreferenced | GroupUnreferenced => Style,
        ObsoleteImport => Warning,
        IdentifierCaseMatch => Style,
        TrapInSMIv2 => Warning,
        NodeImplicit => Style,
        ModuleIdentityReg => Warning,
        RowStatusDefault | RowStatusAccess | StorageTypeDefault => Style,
        TAddressTDomain => Warning,
        IndexAccessible | IndexNotAccessible => Minor,
        IndexDefval => Warning,
        AccessWriteOnlySMIv1 | IpAddressInSyntax => Style,
        InetAddressPairing | InetAddressTypeSubtyped => Warning,
        InetAddressSpecific => Style,
        TransportAddressPairing | TransportAddressTypeSubtyped => Warning,
        TransportAddressSpecific => Style,
    }
}

/// Returns the pipeline phase for a diagnostic code.
pub fn code_phase(code: DiagCode) -> &'static str {
    use DiagCode::*;
    match code {
        UnexpectedCharacter
        | UnterminatedString
        | UnterminatedHexBinStr
        | MissingHexBinSuffix
        | HexStringMul2
        | BinStringMul8 => "lexer",

        IdentifierUnderscore | IdentifierHyphenEnd | IdentifierLength64 | IdentifierLength32
        | BadIdentifierCase | ParseError | InvalidU32 | InvalidI64 | KeywordReserved
        | InvalidHexRange | NumberLeadingZero => "parser",

        MissingModuleIdentity
        | RevisionLastUpdated
        | RevisionNotDescending
        | RevisionAfterUpdate
        | DateCharacter
        | DateLength
        | DateMonth
        | DateDay
        | DateHour
        | DateMinutes
        | DateValue
        | DateYear2Digits
        | DateInFuture
        | DateInPast
        | UnknownDefinitionType
        | UnknownTypeSyntax
        | UnknownConstraintType
        | UnknownRangeValue
        | UnknownOidComponent
        | UnknownDefvalType
        | BitsNumberNegative
        | BitsNumberTooLarge
        | BitsNumberLarge
        | EnumZero
        | EnumNameRedefinition
        | EnumValueRedefinition
        | BitsNameRedefinition
        | BitsValueRedefinition
        | ModuleIdentityNotFirst
        | ModuleIdentityMultiple
        | MacroNotImported
        | EmptyDescription
        | EmptyReference
        | EmptyOrganization
        | EmptyContact
        | EmptyUnits
        | EmptyFormat
        | ModuleNameSuffix
        | MacroNotAllowed
        | ChoiceNotAllowed
        | TaggedTypeNotAllowed => "lowering",

        _ => "resolver",
    }
}

/// All diagnostic codes in declaration order.
const ALL_CODES: &[DiagCode] = &[
    // Lexer
    DiagCode::UnexpectedCharacter,
    DiagCode::UnterminatedString,
    DiagCode::UnterminatedHexBinStr,
    DiagCode::MissingHexBinSuffix,
    DiagCode::HexStringMul2,
    DiagCode::BinStringMul8,
    // Parser
    DiagCode::IdentifierUnderscore,
    DiagCode::IdentifierHyphenEnd,
    DiagCode::IdentifierLength64,
    DiagCode::IdentifierLength32,
    DiagCode::BadIdentifierCase,
    DiagCode::ParseError,
    DiagCode::InvalidU32,
    DiagCode::InvalidI64,
    DiagCode::KeywordReserved,
    DiagCode::InvalidHexRange,
    DiagCode::NumberLeadingZero,
    // Lowering
    DiagCode::MissingModuleIdentity,
    DiagCode::RevisionLastUpdated,
    DiagCode::RevisionNotDescending,
    DiagCode::RevisionAfterUpdate,
    DiagCode::DateCharacter,
    DiagCode::DateLength,
    DiagCode::DateMonth,
    DiagCode::DateDay,
    DiagCode::DateHour,
    DiagCode::DateMinutes,
    DiagCode::DateValue,
    DiagCode::DateYear2Digits,
    DiagCode::DateInFuture,
    DiagCode::DateInPast,
    DiagCode::UnknownDefinitionType,
    DiagCode::UnknownTypeSyntax,
    DiagCode::UnknownConstraintType,
    DiagCode::UnknownRangeValue,
    DiagCode::UnknownOidComponent,
    DiagCode::UnknownDefvalType,
    DiagCode::BitsNumberNegative,
    DiagCode::BitsNumberTooLarge,
    DiagCode::BitsNumberLarge,
    DiagCode::EnumZero,
    DiagCode::EnumNameRedefinition,
    DiagCode::EnumValueRedefinition,
    DiagCode::BitsNameRedefinition,
    DiagCode::BitsValueRedefinition,
    DiagCode::ModuleIdentityNotFirst,
    DiagCode::ModuleIdentityMultiple,
    DiagCode::MacroNotImported,
    DiagCode::EmptyDescription,
    DiagCode::EmptyReference,
    DiagCode::EmptyOrganization,
    DiagCode::EmptyContact,
    DiagCode::EmptyUnits,
    DiagCode::EmptyFormat,
    DiagCode::ModuleNameSuffix,
    DiagCode::MacroNotAllowed,
    DiagCode::ChoiceNotAllowed,
    DiagCode::TaggedTypeNotAllowed,
    // Resolver (all remaining)
    DiagCode::ImportNotFound,
    DiagCode::ImportModuleNotFound,
    DiagCode::TypeUnknown,
    DiagCode::OidOrphan,
    DiagCode::IndexUnresolved,
    DiagCode::ObjectsUnresolved,
    DiagCode::IdentifierHyphenSMIv2,
    DiagCode::GroupNotAccessible,
    DiagCode::NotifObjectNotObject,
    DiagCode::NotifObjectAccess,
    DiagCode::NotifNotReversible,
    DiagCode::NotifIdTooLarge,
    DiagCode::MalformedHexDefval,
    DiagCode::MalformedBinDefval,
    DiagCode::DefvalUnresolved,
    DiagCode::VariationAccessNotifOnly,
    DiagCode::GroupMemberUnresolved,
    DiagCode::IndexNotObject,
    DiagCode::AugmentsNotObject,
    DiagCode::AugmentNested,
    DiagCode::NotifNoOid,
    DiagCode::PrimitiveTypeMissing,
    DiagCode::IntegerInSMIv2,
    DiagCode::IndexIntegerNoRange,
    DiagCode::IndexNegativeRange,
    DiagCode::DefvalBasetype,
    DiagCode::DefvalRange,
    DiagCode::DefvalEnum,
    DiagCode::DefvalBits,
    DiagCode::CounterDefvalIllegal,
    DiagCode::IndexCounterIllegal,
    DiagCode::RangeBounds,
    DiagCode::RangeExchanged,
    DiagCode::RangeOverlap,
    DiagCode::RangeAscending,
    DiagCode::SizeIllegal,
    DiagCode::RangeIllegal,
    DiagCode::CounterRangeIllegal,
    DiagCode::SubtypeEnumIllegal,
    DiagCode::SubtypeBitsIllegal,
    DiagCode::ParentTable,
    DiagCode::ParentRow,
    DiagCode::ParentColumn,
    DiagCode::ParentScalar,
    DiagCode::ParentNode,
    DiagCode::ParentNotification,
    DiagCode::ParentGroup,
    DiagCode::ParentCompliance,
    DiagCode::ParentCapabilities,
    DiagCode::RowSubidentifierOne,
    DiagCode::IndexElementNoSize,
    DiagCode::IndexIllegalBasetype,
    DiagCode::LastSubidZero,
    DiagCode::OidRecursive,
    DiagCode::OidRegistered,
    DiagCode::OidReuse,
    DiagCode::SequenceNoColumn,
    DiagCode::SequenceMissingColumn,
    DiagCode::SequenceOrder,
    DiagCode::SequenceTypeMismatch,
    DiagCode::IndexExceedsTooLarge,
    DiagCode::AccessInvalidSMIv1,
    DiagCode::AccessWriteOnlySMIv2,
    DiagCode::AccessTableIllegal,
    DiagCode::AccessRowIllegal,
    DiagCode::AccessCounterIllegal,
    DiagCode::ScalarNotCreatable,
    DiagCode::MaxAccessInSMIv1,
    DiagCode::AccessInSMIv2,
    DiagCode::StatusInvalidSMIv1,
    DiagCode::StatusInvalidSMIv2,
    DiagCode::TypeStatusDeprecated,
    DiagCode::TypeStatusObsolete,
    DiagCode::GroupMembership,
    DiagCode::GroupMemberMixed,
    DiagCode::GroupObjectsNotification,
    DiagCode::GroupNotificationsObject,
    DiagCode::GroupObjectStatus,
    DiagCode::ComplianceGroupStatus,
    DiagCode::ComplianceObjectStatus,
    DiagCode::ComplianceGroupInvalid,
    DiagCode::RefinementExists,
    DiagCode::OptionalGroupExists,
    DiagCode::RefinementNotListed,
    DiagCode::ComplianceMemberNotLocal,
    DiagCode::TimeticksRangeIllegal,
    DiagCode::StatusInvalidCapabilities,
    DiagCode::ImportUnused,
    DiagCode::BasetypeNotImported,
    DiagCode::DescriptionMissing,
    DiagCode::TCNested,
    DiagCode::TypeAssignmentSMIv2,
    DiagCode::TableNameTable,
    DiagCode::RowNameEntry,
    DiagCode::RowNameTableName,
    DiagCode::NamedNumbersAscending,
    DiagCode::HyphenInLabel,
    DiagCode::OpaqueSMIv2,
    DiagCode::InvalidFormat,
    DiagCode::TypeWithoutFormat,
    DiagCode::TypeUnreferenced,
    DiagCode::GroupUnreferenced,
    DiagCode::ObsoleteImport,
    DiagCode::IdentifierCaseMatch,
    DiagCode::TrapInSMIv2,
    DiagCode::NodeImplicit,
    DiagCode::ModuleIdentityReg,
    DiagCode::RowStatusDefault,
    DiagCode::RowStatusAccess,
    DiagCode::StorageTypeDefault,
    DiagCode::TAddressTDomain,
    DiagCode::IndexAccessible,
    DiagCode::IndexNotAccessible,
    DiagCode::IndexDefval,
    DiagCode::AccessWriteOnlySMIv1,
    DiagCode::IpAddressInSyntax,
    DiagCode::InetAddressPairing,
    DiagCode::InetAddressTypeSubtyped,
    DiagCode::InetAddressSpecific,
    DiagCode::TransportAddressPairing,
    DiagCode::TransportAddressTypeSubtyped,
    DiagCode::TransportAddressSpecific,
];

/// Describes a diagnostic code, its phase, and its severity.
pub struct DiagCodeInfo {
    pub code: DiagCode,
    pub phase: &'static str,
    pub severity: Severity,
}

/// Returns all known diagnostic codes with their phase and severity.
pub fn all_diagnostic_codes() -> Vec<DiagCodeInfo> {
    ALL_CODES
        .iter()
        .map(|&code| DiagCodeInfo {
            code,
            phase: code.phase(),
            severity: code.severity(),
        })
        .collect()
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
