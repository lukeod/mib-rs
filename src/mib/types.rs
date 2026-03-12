use std::fmt;

use crate::mib::Oid;
use crate::types::{Access, BaseType, IndexEncoding, Span};

/// A single imported symbol with its source location.
#[derive(Debug, Clone)]
pub struct ImportSymbol {
    pub name: String,
    pub span: Span,
}

/// A group of symbols imported from a single source module.
#[derive(Debug, Clone)]
pub struct Import {
    pub module: String,
    pub symbols: Vec<ImportSymbol>,
}

/// A min..max constraint for sizes or values.
#[derive(Debug, Clone, Copy)]
pub struct Range {
    pub min: i64,
    pub max: i64,
    pub span: Span,
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

/// A labeled integer from an enum or BITS definition.
#[derive(Debug, Clone)]
pub struct NamedValue {
    pub label: String,
    pub value: i64,
    pub span: Span,
}

/// Finds a named value by label in a slice.
pub(crate) fn find_named_value<'a>(
    values: &'a [NamedValue],
    label: &str,
) -> Option<&'a NamedValue> {
    values.iter().find(|nv| nv.label == label)
}

/// A module revision entry.
#[derive(Debug, Clone)]
pub struct Revision {
    pub date: String,
    pub description: String,
    pub span: Span,
}

/// An index component for a table row.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub object: Option<ObjectId>,
    pub type_name: String,
    pub implied: bool,
    pub encoding: IndexEncoding,
    pub span: Span,
}

/// Classifies the index encoding from the object's resolved type and effective constraints.
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

fn is_fixed_size(sizes: &[Range]) -> bool {
    sizes.len() == 1 && sizes[0].min == sizes[0].max && sizes[0].min > 0
}

/// Identifies the type of default value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DefValKind {
    Unset = 0,
    Int = 1,
    Uint = 2,
    String = 3,
    Bytes = 4,
    Enum = 5,
    Bits = 6,
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

/// A default value with both interpreted value and raw MIB syntax.
#[derive(Debug, Clone)]
pub struct DefVal {
    pub(crate) kind: DefValKind,
    pub(crate) value: DefValValue,
    pub(crate) raw: String,
}

/// The interpreted value of a DEFVAL clause.
#[derive(Debug, Clone)]
pub enum DefValValue {
    None,
    Int(i64),
    Uint(u64),
    String(String),
    Bytes(Vec<u8>),
    Enum(String),
    Bits(Vec<String>),
    Oid(Oid),
}

impl DefVal {
    pub fn unset() -> Self {
        DefVal {
            kind: DefValKind::Unset,
            value: DefValValue::None,
            raw: String::new(),
        }
    }

    pub fn int(v: i64, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Int,
            value: DefValValue::Int(v),
            raw,
        }
    }

    pub fn uint(v: u64, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Uint,
            value: DefValValue::Uint(v),
            raw,
        }
    }

    pub fn string(v: String, raw: String) -> Self {
        DefVal {
            kind: DefValKind::String,
            value: DefValValue::String(v),
            raw,
        }
    }

    pub fn bytes(v: Vec<u8>, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Bytes,
            value: DefValValue::Bytes(v),
            raw,
        }
    }

    pub fn enumeration(label: String, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Enum,
            value: DefValValue::Enum(label),
            raw,
        }
    }

    pub fn bits(labels: Vec<String>, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Bits,
            value: DefValValue::Bits(labels),
            raw,
        }
    }

    pub fn oid(oid: Oid, raw: String) -> Self {
        DefVal {
            kind: DefValKind::Oid,
            value: DefValValue::Oid(oid),
            raw,
        }
    }

    pub fn kind(&self) -> DefValKind {
        self.kind
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn value(&self) -> &DefValValue {
        &self.value
    }

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
                if b.is_empty() {
                    write!(f, "0")
                } else if b.len() <= 8 {
                    let mut n: u64 = 0;
                    for &byte in b {
                        n = n << 8 | byte as u64;
                    }
                    write!(f, "{n}")
                } else {
                    write!(f, "0x")?;
                    for byte in b {
                        write!(f, "{byte:02X}")?;
                    }
                    Ok(())
                }
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

/// A MODULE clause within a MODULE-COMPLIANCE definition.
#[derive(Debug, Clone)]
pub struct ComplianceModule {
    pub module_name: String,
    pub mandatory_groups: Vec<String>,
    pub groups: Vec<ComplianceGroup>,
    pub objects: Vec<ComplianceObject>,
    pub span: Span,
}

/// A GROUP clause within MODULE-COMPLIANCE.
#[derive(Debug, Clone)]
pub struct ComplianceGroup {
    pub group: String,
    pub description: String,
    pub span: Span,
}

/// An OBJECT refinement within MODULE-COMPLIANCE.
#[derive(Debug, Clone)]
pub struct ComplianceObject {
    pub object: String,
    pub syntax: Option<SyntaxConstraints>,
    pub write_syntax: Option<SyntaxConstraints>,
    pub min_access: Option<Access>,
    pub description: String,
    pub span: Span,
}

/// A SUPPORTS clause within an AGENT-CAPABILITIES definition.
#[derive(Debug, Clone)]
pub struct CapabilitiesModule {
    pub module_name: String,
    pub includes: Vec<String>,
    pub object_variations: Vec<ObjectVariation>,
    pub notification_variations: Vec<NotificationVariation>,
    pub span: Span,
}

/// An object VARIATION within AGENT-CAPABILITIES.
#[derive(Debug, Clone)]
pub struct ObjectVariation {
    pub object: String,
    pub syntax: Option<SyntaxConstraints>,
    pub write_syntax: Option<SyntaxConstraints>,
    pub access: Option<Access>,
    pub creation_requires: Vec<String>,
    pub def_val: Option<DefVal>,
    pub description: String,
    pub span: Span,
}

/// A notification VARIATION within AGENT-CAPABILITIES.
#[derive(Debug, Clone)]
pub struct NotificationVariation {
    pub notification: String,
    pub access: Option<Access>,
    pub description: String,
    pub span: Span,
}

/// A resolved type reference with any inline constraints from a VARIATION
/// SYNTAX/WRITE-SYNTAX clause or MODULE-COMPLIANCE OBJECT refinement.
#[derive(Debug, Clone)]
pub struct SyntaxConstraints {
    pub type_id: Option<TypeId>,
    pub sizes: Vec<Range>,
    pub ranges: Vec<Range>,
    pub enums: Vec<NamedValue>,
    pub bits: Vec<NamedValue>,
}

/// SMIv1 TRAP-TYPE fields.
#[derive(Debug, Clone)]
pub struct TrapInfo {
    pub enterprise: String,
    pub trap_number: u32,
}

/// Identifies the category of an unresolved reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UnresolvedKind {
    Import = 0,
    Type = 1,
    Oid = 2,
    Index = 3,
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

/// An unresolved symbol reference.
#[derive(Debug, Clone)]
pub struct UnresolvedRef {
    pub kind: UnresolvedKind,
    pub symbol: String,
    pub module: String,
    pub reason: String,
}

/// A named symbolic reference from an OID assignment with its source span.
#[derive(Debug, Clone)]
pub struct OidRef {
    pub name: String,
    pub span: Span,
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
