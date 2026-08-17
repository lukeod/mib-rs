//! IR type syntax and constraint types.
//!
//! Parallel to [`crate::ast::syntax`] but simplified for the IR layer.
//! Type references are plain strings, `CHOICE` and `Tagged` variants are
//! eliminated, and `BITS` positions use [`NamedBit`] with a `u32` position
//! instead of reusing `NamedNumber`.

use crate::source::SourceRange;

use super::oid::OidComponent;

/// An unresolved type expression.
///
/// Type references remain as strings until the resolver phase builds
/// the type graph and resolves parent chains.
#[derive(Debug, Clone)]
pub enum TypeSyntax {
    /// Reference to a named type, e.g. `Integer32`.
    TypeRef { name: String, range: SourceRange },
    /// INTEGER with named values, e.g. `INTEGER { up(1), down(2) }`.
    IntegerEnum {
        base: String,
        named_numbers: Vec<NamedNumber>,
        range: SourceRange,
    },
    /// `BITS` type with named bit positions.
    Bits {
        named_bits: Vec<NamedBit>,
        range: SourceRange,
    },
    /// Type with a subtype constraint applied.
    Constrained {
        base: Box<TypeSyntax>,
        constraint: Constraint,
        range: SourceRange,
    },
    /// `SEQUENCE OF` entry-type reference (table types).
    SequenceOf {
        entry_type: String,
        range: SourceRange,
    },
    /// `SEQUENCE` with named fields (table row definition).
    Sequence {
        fields: Vec<SequenceField>,
        range: SourceRange,
    },
    /// Explicit `OCTET STRING` type.
    OctetString { range: SourceRange },
    /// `OBJECT IDENTIFIER` type.
    ObjectIdentifier { range: SourceRange },
}

impl TypeSyntax {
    /// Returns the source range of this type syntax node.
    pub fn range(&self) -> SourceRange {
        match self {
            TypeSyntax::TypeRef { range, .. }
            | TypeSyntax::IntegerEnum { range, .. }
            | TypeSyntax::Bits { range, .. }
            | TypeSyntax::Constrained { range, .. }
            | TypeSyntax::SequenceOf { range, .. }
            | TypeSyntax::Sequence { range, .. }
            | TypeSyntax::OctetString { range }
            | TypeSyntax::ObjectIdentifier { range } => *range,
        }
    }
}

/// A named value in an INTEGER enumeration, e.g. `up(1)`.
#[derive(Debug, Clone)]
pub struct NamedNumber {
    /// Enumeration label.
    pub name: String,
    /// Numeric value assigned to the label.
    pub value: i64,
    /// Source range covering `name(value)`.
    pub range: SourceRange,
}

/// A named bit position in a `BITS` type, e.g. `flag1(0)`.
#[derive(Debug, Clone)]
pub struct NamedBit {
    /// Bit label.
    pub name: String,
    /// Zero-based bit position.
    pub position: u32,
    /// Source range covering `name(position)`.
    pub range: SourceRange,
}

/// A field in a `SEQUENCE` type used for table row entries.
#[derive(Debug, Clone)]
pub struct SequenceField {
    /// Field name (typically matches the columnar `OBJECT-TYPE` name).
    pub name: String,
    /// Field type expression.
    pub syntax: TypeSyntax,
    /// Source range of the field.
    pub range: SourceRange,
}

/// A subtype constraint (`SIZE` or value range).
#[derive(Debug, Clone)]
pub enum Constraint {
    /// `SIZE(...)` constraint on string or sequence length.
    Size {
        ranges: Vec<Range>,
        range: SourceRange,
    },
    /// Value range constraint, e.g. `(0..65535)`.
    Range {
        ranges: Vec<Range>,
        range: SourceRange,
    },
}

impl Constraint {
    /// Returns the source range of this constraint.
    pub fn range(&self) -> SourceRange {
        match self {
            Constraint::Size { range, .. } | Constraint::Range { range, .. } => *range,
        }
    }
}

/// A single range or exact value within a constraint.
///
/// When `max` is `None`, represents an exact value match against `min`.
/// When `max` is `Some`, represents an inclusive range from `min` to `max`.
#[derive(Debug, Clone)]
pub struct Range {
    /// Lower bound (or exact value when `max` is `None`).
    pub min: RangeValue,
    /// Upper bound, if this is a range rather than an exact value.
    pub max: Option<RangeValue>,
    /// Source range of this range element.
    pub range: SourceRange,
}

/// An endpoint in a range constraint.
#[derive(Debug, Clone)]
pub enum RangeValue {
    /// Signed integer literal.
    Signed(i64),
    /// Unsigned integer literal.
    Unsigned(u64),
    /// The `MIN` keyword (smallest possible value for the type).
    Min,
    /// The `MAX` keyword (largest possible value for the type).
    Max,
    /// Endpoint that could not be converted, preserving its source text.
    Raw(String),
}

/// An unresolved `DEFVAL` clause value.
///
/// Symbol references (enum labels, OID names) remain unresolved until the
/// semantic resolver phase.
#[derive(Debug, Clone)]
pub enum DefVal {
    /// Signed integer literal, e.g. `DEFVAL { -1 }`.
    Integer(i64),
    /// Unsigned integer literal, e.g. `DEFVAL { 0 }`.
    Unsigned(u64),
    /// Quoted string literal, e.g. `DEFVAL { "default" }`.
    String(String),
    /// Hex string literal, e.g. `DEFVAL { 'FF00'H }`.
    HexString(String),
    /// Binary string literal, e.g. `DEFVAL { '0101'B }`.
    BinaryString(String),
    /// Named enum value (label only, not yet resolved to numeric).
    Enum(String),
    /// `BITS` value with named bit labels, e.g. `DEFVAL { { flag1, flag2 } }`.
    Bits { labels: Vec<String> },
    /// Single-name OID reference, e.g. `DEFVAL { zeroDotZero }`.
    OidRef(String),
    /// Multi-component OID value, e.g. `DEFVAL { { 0 0 } }`.
    OidValue { components: Vec<OidComponent> },
    /// Value that could not be parsed; content was skipped.
    Unparsed,
}
