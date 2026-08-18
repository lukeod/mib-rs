//! Shared types used across the resolved MIB model.
//!
//! Contains arena id newtypes ([`NodeId`], [`ObjectId`], [`TypeId`], etc.),
//! supporting data structures ([`Range`], [`NamedValue`], [`DefVal`],
//! [`IndexEntry`]), and SMI clause representations used by compliance and
//! capability definitions.

use std::fmt;

use crate::mib::Oid;
use crate::source::SourceRange;
use crate::types::{Access, BaseType, IndexEncoding};

/// A single imported symbol with its source location.
///
/// Part of an [`Import`] group. The `name` is the symbol as written in the
/// MIB's IMPORTS clause (e.g. `"ifIndex"`, `"DisplayString"`).
#[derive(Debug, Clone)]
pub struct ImportSymbol {
    /// The symbol name as it appears in the IMPORTS clause.
    pub name: String,
    /// Source location of this symbol reference.
    pub range: SourceRange,
}

/// A group of symbols imported from a single source module.
///
/// Each MIB module's IMPORTS section is represented as a list of `Import`
/// entries, one per source module.
#[derive(Debug, Clone)]
pub struct Import {
    /// Name of the module being imported from.
    pub module: String,
    /// Symbols imported from this module.
    pub symbols: Vec<ImportSymbol>,
}

/// Resolver strategy used for one imported symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportResolutionMode {
    /// The selected source module directly defines the complete import group.
    Direct,
    /// A well-known source-module alias selected the defining module.
    Alias,
    /// The declared source module forwarded the complete import group.
    Forwarded,
    /// The symbol was retained while resolving a mixed direct/forwarded group.
    Partial,
    /// No source module candidate could resolve the symbol.
    Unresolved,
    /// No target was selected and at least one candidate path was cyclic.
    Cycle,
}

impl fmt::Display for ImportResolutionMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct => "direct",
            Self::Alias => "alias",
            Self::Forwarded => "forwarded",
            Self::Partial => "partial",
            Self::Unresolved => "unresolved",
            Self::Cycle => "cycle",
        })
    }
}

/// Terminal result of one candidate path attempted during import resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAttemptOutcome {
    /// The path reached a module defining the symbol.
    Resolved,
    /// The path ended at a loaded module that neither defines nor imports the symbol.
    SymbolNotDefined,
    /// The next declared source module was unavailable.
    ModuleNotFound,
    /// The path revisited a module.
    Cycle,
}

/// Import resolver stage that produced a candidate-path attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportResolutionStage {
    /// Aggregate direct-source candidate scoring.
    Direct,
    /// Aggregate well-known module-alias candidate scoring.
    Alias,
    /// Aggregate import-forwarding traversal.
    Forwarding,
    /// Per-symbol partial-resolution traversal.
    Partial,
    /// Terminal failure because the declared source module was unavailable.
    Unresolved,
}

impl fmt::Display for ImportResolutionStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct => "direct",
            Self::Alias => "alias",
            Self::Forwarding => "forwarding",
            Self::Partial => "partial",
            Self::Unresolved => "unresolved",
        })
    }
}

impl fmt::Display for ImportAttemptOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Resolved => "resolved",
            Self::SymbolNotDefined => "symbol-not-defined",
            Self::ModuleNotFound => "module-not-found",
            Self::Cycle => "cycle",
        })
    }
}

/// One exact module-version path observed during live import resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResolutionAttempt {
    /// Live resolver stage that executed this attempt.
    pub stage: ImportResolutionStage,
    /// Loaded module versions visited by the attempt, including a repeated
    /// final module for a detected cycle.
    pub path: Vec<ModuleId>,
    /// Unavailable module named by the last visited module, when applicable.
    pub missing_module: Option<String>,
    /// Terminal result.
    pub outcome: ImportAttemptOutcome,
    /// Whether this attempt supplied the retained resolution.
    pub selected: bool,
}

/// Retained pre-collapse provenance for one IMPORTS symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResolution {
    /// Imported symbol.
    pub symbol: String,
    /// Source module name written in the importing module.
    pub declared_module: String,
    /// Resolver strategy used for the import group.
    pub mode: ImportResolutionMode,
    /// Exact defining module version retained after resolution.
    pub target: Option<ModuleId>,
    /// Exact selected forwarding path, excluding the importing module itself.
    pub selected_path: Vec<ModuleId>,
    /// Candidate paths attempted before the transitive import map was collapsed.
    pub attempts: Vec<ImportResolutionAttempt>,
}

/// An endpoint in a resolved SIZE or value range constraint.
///
/// Signed and unsigned literals remain distinct so values above [`i64::MAX`]
/// are represented exactly. `MIN` and `MAX` are retained when no parent or
/// base-type bound is available to give them a concrete value. Malformed or
/// unsupported literals retain their source text in [`Raw`](Self::Raw).
///
/// The raw representation means this enum is no longer `Copy`; clone endpoints
/// when an owned value is required.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RangeBound {
    /// A signed integer literal.
    Signed(i64),
    /// An unsigned integer literal.
    Unsigned(u64),
    /// The `MIN` keyword.
    Min,
    /// The `MAX` keyword.
    Max,
    /// An unresolved endpoint preserving its source text.
    Raw(String),
}

impl RangeBound {
    /// Return the endpoint as `i64` when it is concrete and representable.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Signed(value) => Some(*value),
            Self::Unsigned(value) => i64::try_from(*value).ok(),
            Self::Min | Self::Max | Self::Raw(_) => None,
        }
    }

    /// Return the endpoint as `u64` when it is concrete and non-negative.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Signed(value) => u64::try_from(*value).ok(),
            Self::Unsigned(value) => Some(*value),
            Self::Min | Self::Max | Self::Raw(_) => None,
        }
    }

    /// Return whether the endpoint is a signed or unsigned number.
    pub fn is_concrete(&self) -> bool {
        matches!(self, Self::Signed(_) | Self::Unsigned(_))
    }

    pub(crate) fn cmp_value(&self, other: &Self) -> Option<std::cmp::Ordering> {
        use std::cmp::Ordering;
        match (self, other) {
            (Self::Raw(_), _) | (_, Self::Raw(_)) => None,
            (Self::Min, Self::Min) | (Self::Max, Self::Max) => Some(Ordering::Equal),
            (Self::Min, _) | (_, Self::Max) => Some(Ordering::Less),
            (Self::Max, _) | (_, Self::Min) => Some(Ordering::Greater),
            (Self::Signed(left), Self::Signed(right)) => Some(left.cmp(right)),
            (Self::Unsigned(left), Self::Unsigned(right)) => Some(left.cmp(right)),
            (Self::Signed(left), Self::Unsigned(right)) => Some(if *left < 0 {
                Ordering::Less
            } else {
                (*left as u64).cmp(right)
            }),
            (Self::Unsigned(left), Self::Signed(right)) => Some(if *right < 0 {
                Ordering::Greater
            } else {
                left.cmp(&(*right as u64))
            }),
        }
    }
}

impl fmt::Display for RangeBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed(value) => write!(f, "{value}"),
            Self::Unsigned(value) => write!(f, "{value}"),
            Self::Min => f.write_str("MIN"),
            Self::Max => f.write_str("MAX"),
            Self::Raw(value) => f.write_str(value),
        }
    }
}

/// A min..max constraint range, used for both SIZE and value constraints.
///
/// For single-value constraints (e.g. `SIZE (6)`), `min` equals `max`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    /// Lower bound (inclusive).
    pub min: RangeBound,
    /// Upper bound (inclusive). Equal to `min` for single-value ranges.
    pub max: RangeBound,
    /// Source location of this constraint.
    pub range: Option<SourceRange>,
}

impl Range {
    /// Return whether both endpoints are concrete numeric values.
    pub fn is_resolved(&self) -> bool {
        self.min.is_concrete() && self.max.is_concrete()
    }

    pub(crate) fn contains_i64(&self, value: i64) -> bool {
        let value = RangeBound::Signed(value);
        self.min
            .cmp_value(&value)
            .is_some_and(|ordering| ordering.is_le())
            && self
                .max
                .cmp_value(&value)
                .is_some_and(|ordering| ordering.is_ge())
    }

    pub(crate) fn contains_u64(&self, value: u64) -> bool {
        let value = RangeBound::Unsigned(value);
        self.min
            .cmp_value(&value)
            .is_some_and(|ordering| ordering.is_le())
            && self
                .max
                .cmp_value(&value)
                .is_some_and(|ordering| ordering.is_ge())
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}..{}", self.min, self.max)
        }
    }
}

/// A labeled integer from an enumeration or BITS definition.
///
/// Used in OBJECT-TYPE SYNTAX enumerations, BITS definitions, and
/// refinement clauses in compliance and capability statements.
#[derive(Debug, Clone)]
pub struct NamedValue {
    /// The textual label.
    pub label: String,
    /// The integer value associated with this label.
    pub value: i64,
    /// Source location of this named value.
    pub range: SourceRange,
}

/// Finds a named value by label in a slice.
pub(crate) fn find_named_value<'a>(
    values: &'a [NamedValue],
    label: &str,
) -> Option<&'a NamedValue> {
    values.iter().find(|nv| nv.label == label)
}

/// A module revision entry from a MODULE-IDENTITY REVISION clause.
#[derive(Debug, Clone)]
pub struct Revision {
    /// Revision timestamp string.
    pub date: String,
    /// Free-text description of what changed.
    pub description: String,
    /// Source location of this revision clause.
    pub range: SourceRange,
}

/// An index component from a table row's INDEX clause.
///
/// Indexes can be object-backed (referencing a column like `ifIndex`) or
/// bare-type indexes (using a type name directly). The
/// [`encoding`](Self::encoding) field indicates how this index component
/// is encoded on the wire (see [`IndexEncoding`]).
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Name of the index object.
    pub name: String,
    /// Resolved object id, if found.
    pub object: Option<ObjectId>,
    /// Resolved type of the index object, if found.
    pub type_id: Option<TypeId>,
    /// True if this index uses the IMPLIED keyword.
    pub implied: bool,
    /// Wire encoding inferred from the index object's type.
    pub encoding: IndexEncoding,
    /// Source location of this index entry.
    pub range: SourceRange,
}

/// Classify the index encoding from the object's resolved base type and size constraints.
pub(crate) fn classify_index_encoding(
    base: BaseType,
    implied: bool,
    sizes: &[Range],
) -> IndexEncoding {
    match base {
        BaseType::Integer32
        | BaseType::Unsigned32
        | BaseType::Gauge32
        | BaseType::TimeTicks
        | BaseType::Counter32
        | BaseType::Counter64 => IndexEncoding::Integer,
        BaseType::IpAddress => IndexEncoding::IpAddress,
        BaseType::OctetString | BaseType::Opaque | BaseType::Bits => {
            if implied {
                IndexEncoding::Implied
            } else if is_fixed_size(sizes) {
                IndexEncoding::FixedString
            } else {
                IndexEncoding::LengthPrefixed
            }
        }
        BaseType::ObjectIdentifier => {
            if implied {
                IndexEncoding::Implied
            } else {
                IndexEncoding::LengthPrefixed
            }
        }
        _ => IndexEncoding::Unknown,
    }
}

pub(crate) fn is_fixed_size(sizes: &[Range]) -> bool {
    sizes.len() == 1
        && sizes[0].min == sizes[0].max
        && sizes[0].min.as_u64().is_some_and(|value| value > 0)
}

/// Discriminant for the kind of value in a [`DefVal`].
///
/// Mirrors the [`DefValValue`] variants but as a simple `Copy` enum,
/// useful for matching or display without borrowing the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DefValKind {
    /// No default value specified.
    Unset = 0,
    /// Signed integer value.
    Int = 1,
    /// Unsigned integer value.
    Uint = 2,
    /// Quoted string value.
    String = 3,
    /// Raw byte sequence (hex string).
    Bytes = 4,
    /// Enumeration label.
    Enum = 5,
    /// Set of BITS labels.
    Bits = 6,
    /// Object identifier value.
    Oid = 7,
}

impl fmt::Display for DefValKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DefValKind::Unset => "unset",
            DefValKind::Int => "int",
            DefValKind::Uint => "uint",
            DefValKind::String => "string",
            DefValKind::Bytes => "bytes",
            DefValKind::Enum => "enum",
            DefValKind::Bits => "bits",
            DefValKind::Oid => "oid",
        })
    }
}

/// A DEFVAL clause value with both the interpreted value and the raw MIB syntax string.
///
/// The [`kind`](DefVal::kind) method returns the discriminant, [`value`](DefVal::value)
/// returns the interpreted value, and [`raw`](DefVal::raw) returns the original
/// syntax as written in the MIB source.
///
/// Constructed via the named constructors ([`DefVal::int`], [`DefVal::string`], etc.).
#[derive(Debug, Clone)]
pub struct DefVal {
    pub(crate) kind: DefValKind,
    pub(crate) value: DefValValue,
    pub(crate) raw: String,
    pub(crate) oid_ref: Option<OidRef>,
}

/// The interpreted value of a DEFVAL clause.
///
/// Each variant corresponds to a [`DefValKind`] discriminant.
#[derive(Debug, Clone)]
pub enum DefValValue {
    /// No value (corresponds to `DefValKind::Unset`).
    None,
    /// Signed integer.
    Int(i64),
    /// Unsigned integer.
    Uint(u64),
    /// Quoted string.
    String(String),
    /// Raw byte sequence.
    Bytes(Vec<u8>),
    /// Enumeration label.
    Enum(String),
    /// Set of BITS labels.
    Bits(Vec<String>),
    /// Object identifier.
    Oid(Oid),
}

impl DefVal {
    /// Create a default value indicating no value was specified.
    pub fn unset() -> Self {
        DefVal {
            kind: DefValKind::Unset,
            value: DefValValue::None,
            raw: String::new(),
            oid_ref: None,
        }
    }

    /// Create a signed integer default value.
    pub fn int(v: i64, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Int,
            value: DefValValue::Int(v),
            raw,
            oid_ref: None,
        }
    }

    /// Create an unsigned integer default value.
    pub fn uint(v: u64, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Uint,
            value: DefValValue::Uint(v),
            raw,
            oid_ref: None,
        }
    }

    /// Create a quoted string default value.
    pub fn string(v: String, raw: String) -> Self {
        DefVal {
            kind: DefValKind::String,
            value: DefValValue::String(v),
            raw,
            oid_ref: None,
        }
    }

    /// Create a raw byte sequence default value (from a hex string).
    pub fn bytes(v: Vec<u8>, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Bytes,
            value: DefValValue::Bytes(v),
            raw,
            oid_ref: None,
        }
    }

    /// Create an enumeration label default value.
    pub fn enumeration(label: String, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Enum,
            value: DefValValue::Enum(label),
            raw,
            oid_ref: None,
        }
    }

    /// Create a BITS set default value.
    pub fn bits(labels: Vec<String>, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Bits,
            value: DefValValue::Bits(labels),
            raw,
            oid_ref: None,
        }
    }

    /// Create an OID default value.
    pub fn oid(oid: Oid, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Oid,
            value: DefValValue::Oid(oid),
            raw,
            oid_ref: None,
        }
    }

    pub(crate) fn oid_with_ref(oid: Oid, raw: String, oid_ref: OidRef) -> Self {
        DefVal {
            kind: DefValKind::Oid,
            value: DefValValue::Oid(oid),
            raw,
            oid_ref: Some(oid_ref),
        }
    }

    /// Return the [`DefValKind`] discriminant.
    pub fn kind(&self) -> DefValKind {
        self.kind
    }

    /// Return the raw MIB syntax string as written in the source.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Return the interpreted [`DefValValue`].
    pub fn value(&self) -> &DefValValue {
        &self.value
    }

    /// Return the exact symbolic OID reference used by this default value.
    pub fn oid_ref(&self) -> Option<&OidRef> {
        self.oid_ref.as_ref()
    }

    /// Return `true` if no default value was specified.
    pub fn is_unset(&self) -> bool {
        self.kind == DefValKind::Unset
    }
}

impl fmt::Display for DefVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            DefValValue::None => Ok(()),
            DefValValue::Int(v) => write!(f, "{v}"),
            DefValValue::Uint(v) => write!(f, "{v}"),
            DefValValue::String(v) => {
                write!(f, "\"{}\"", v.replace('"', "\\\""))
            }
            DefValValue::Bytes(b) => {
                write!(f, "0x")?;
                for byte in b {
                    write!(f, "{byte:02X}")?;
                }
                Ok(())
            }
            DefValValue::Enum(label) => f.write_str(label),
            DefValValue::Bits(labels) => {
                if labels.is_empty() {
                    write!(f, "{{ }}")
                } else {
                    write!(f, "{{ {} }}", labels.join(", "))
                }
            }
            DefValValue::Oid(_) => f.write_str(&self.raw),
        }
    }
}

/// A MODULE clause within a [`ComplianceData`](super::compliance::ComplianceData) definition.
///
/// Specifies the mandatory groups and optional object refinements required
/// for conformance to a particular module.
#[derive(Debug, Clone)]
pub struct ComplianceModule {
    /// Name of the module this clause applies to.
    pub module_name: String,
    /// Groups required for conformance.
    pub mandatory_groups: Vec<String>,
    /// Optional GROUP refinements.
    pub groups: Vec<ComplianceGroup>,
    /// Optional OBJECT refinements.
    pub objects: Vec<ComplianceObject>,
    /// Source location of this MODULE clause.
    pub range: SourceRange,
}

/// A GROUP clause within a [`ComplianceModule`].
///
/// Represents a conditionally required group, with a description of the
/// conditions under which it is required.
#[derive(Debug, Clone)]
pub struct ComplianceGroup {
    /// Name of the conditionally required group.
    pub group: String,
    /// Description of when this group is required.
    pub description: String,
    /// Source location of this GROUP clause.
    pub range: SourceRange,
}

/// An OBJECT refinement within a [`ComplianceModule`].
///
/// May narrow the syntax, write-syntax, or minimum access level for an
/// object beyond what the base OBJECT-TYPE definition requires.
#[derive(Debug, Clone)]
pub struct ComplianceObject {
    /// Name of the refined object.
    pub object: String,
    /// Restricted SYNTAX, if any.
    pub syntax: Option<SyntaxConstraints>,
    /// Restricted WRITE-SYNTAX, if any.
    pub write_syntax: Option<SyntaxConstraints>,
    /// Minimum required access level, if specified.
    pub min_access: Option<Access>,
    /// Description of the refinement.
    pub description: String,
    /// Source location of this OBJECT clause.
    pub range: SourceRange,
}

/// A SUPPORTS clause within a [`CapabilityData`](super::capability::CapabilityData) definition.
///
/// Lists the included groups from a supported module and any object or
/// notification variations the agent implements.
#[derive(Debug, Clone)]
pub struct CapabilitiesModule {
    /// Name of the supported module.
    pub module_name: String,
    /// Groups included from this module.
    pub includes: Vec<String>,
    /// Object VARIATION clauses.
    pub object_variations: Vec<ObjectVariation>,
    /// Notification VARIATION clauses.
    pub notification_variations: Vec<NotificationVariation>,
    /// Source location of this SUPPORTS clause.
    pub range: SourceRange,
}

/// An object VARIATION within a [`CapabilitiesModule`].
///
/// Describes implementation-specific deviations for a single object,
/// including restricted syntax, access overrides, and default values.
#[derive(Debug, Clone)]
pub struct ObjectVariation {
    /// Name of the varied object.
    pub object: String,
    /// Restricted SYNTAX, if any.
    pub syntax: Option<SyntaxConstraints>,
    /// Restricted WRITE-SYNTAX, if any.
    pub write_syntax: Option<SyntaxConstraints>,
    /// Overridden access level, if any.
    pub access: Option<Access>,
    /// Objects required for row creation, with their exact resolved defining
    /// module and OID when available.
    pub creation_requires: Vec<OidRef>,
    /// Implementation-specific default value, if any.
    pub def_val: Option<DefVal>,
    /// Description of this variation.
    pub description: String,
    /// Source location of this VARIATION clause.
    pub range: SourceRange,
}

/// A notification VARIATION within a [`CapabilitiesModule`].
///
/// Describes implementation-specific deviations for a single notification.
#[derive(Debug, Clone)]
pub struct NotificationVariation {
    /// Name of the varied notification.
    pub notification: String,
    /// Overridden access level, if any.
    pub access: Option<Access>,
    /// Description of this variation.
    pub description: String,
    /// Source location of this VARIATION clause.
    pub range: SourceRange,
}

/// Inline syntax constraints from a VARIATION SYNTAX/WRITE-SYNTAX clause
/// or a MODULE-COMPLIANCE OBJECT refinement.
///
/// Represents a restricted view of a type with narrowed ranges, enums, or
/// BITS values.
#[derive(Debug, Clone)]
pub struct SyntaxConstraints {
    /// Resolved type, if any.
    pub type_id: Option<TypeId>,
    /// Effective SIZE constraints after intersection with the resolved type.
    pub sizes: Vec<Range>,
    /// SIZE constraints declared directly in this syntax clause.
    pub declared_sizes: Vec<Range>,
    /// Whether a SIZE constraint was explicitly declared.
    ///
    /// When this is true and `sizes` is empty, the declared constraint has an
    /// empty intersection with the inherited or base-type constraint.
    pub sizes_constrained: bool,
    /// Effective value range constraints after intersection with the resolved type.
    pub ranges: Vec<Range>,
    /// Value range constraints declared directly in this syntax clause.
    pub declared_ranges: Vec<Range>,
    /// Whether a value range constraint was explicitly declared.
    ///
    /// When this is true and `ranges` is empty, the declared constraint has an
    /// empty intersection with the inherited or base-type constraint.
    pub ranges_constrained: bool,
    /// Restricted enumeration values.
    pub enums: Vec<NamedValue>,
    /// Restricted BITS values.
    pub bits: Vec<NamedValue>,
}

/// SMIv1 TRAP-TYPE specific fields.
///
/// Present on [`NotificationData`](super::notification::NotificationData)
/// instances that originate from TRAP-TYPE definitions.
#[derive(Debug, Clone)]
pub struct TrapInfo {
    /// ENTERPRISE OID name from the TRAP-TYPE definition.
    pub enterprise: String,
    /// Numeric trap identifier (the specific-trap number).
    pub trap_number: u32,
}

/// Identifies the category of an unresolved reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UnresolvedKind {
    /// An unresolved IMPORTS symbol.
    Import = 0,
    /// An unresolved type reference.
    Type = 1,
    /// An unresolved OID component.
    Oid = 2,
    /// An unresolved INDEX object.
    Index = 3,
    /// An unresolved OBJECTS member of a notification.
    NotificationObject = 4,
}

impl fmt::Display for UnresolvedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UnresolvedKind::Import => "import",
            UnresolvedKind::Type => "type",
            UnresolvedKind::Oid => "oid",
            UnresolvedKind::Index => "index",
            UnresolvedKind::NotificationObject => "notification-object",
        })
    }
}

/// An unresolved symbol reference collected during resolution.
///
/// Available via [`Mib::unresolved`](super::mib::Mib::unresolved).
#[derive(Debug, Clone)]
pub struct UnresolvedRef {
    /// What kind of reference failed to resolve.
    pub kind: UnresolvedKind,
    /// The symbol name that could not be resolved.
    pub symbol: String,
    /// The module where the reference was used.
    pub module: String,
    /// Human-readable explanation of why resolution failed.
    pub reason: String,
}

/// A symbolic reference to an OID-bearing definition.
///
/// Used both for OID value-assignment components (for example `enterprises` in
/// `{ enterprises 9 }`) and for resolved conformance references that need to
/// retain exact defining-module provenance.
#[derive(Debug, Clone)]
pub struct OidRef {
    /// The symbolic name referenced in the OID assignment.
    pub name: String,
    /// Source location of this reference.
    pub range: SourceRange,
    pub(crate) module: Option<ModuleId>,
    pub(crate) oid: Option<Oid>,
}

impl OidRef {
    /// Return the exact resolved defining module/version, when known.
    pub fn module_id(&self) -> Option<ModuleId> {
        self.module
    }

    /// Return the resolved numeric OID of the referenced symbol, when known.
    pub fn oid(&self) -> Option<&Oid> {
        self.oid.as_ref()
    }
}

// Arena index types for the resolved model.
macro_rules! define_id {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub(crate) u32);

        impl $name {
            pub(crate) fn new(index: u32) -> Self {
                Self(index)
            }

            /// Return the raw arena index as a `u32`.
            pub fn index(self) -> u32 {
                self.0
            }
        }
    };
}

define_id!(
    /// Index into the OidTree's node arena.
    NodeId
);
define_id!(
    /// Index into the Mib's object arena.
    ObjectId
);
define_id!(
    /// Index into the Mib's type arena.
    TypeId
);
define_id!(
    /// Index into the Mib's module arena.
    ModuleId
);
define_id!(
    /// Index into the Mib's notification arena.
    NotificationId
);
define_id!(
    /// Index into the Mib's group arena.
    GroupId
);
define_id!(
    /// Index into the Mib's compliance arena.
    ComplianceId
);
define_id!(
    /// Index into the Mib's capability arena.
    CapabilityId
);
