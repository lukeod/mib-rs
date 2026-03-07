use crate::types::Span;

use super::oid::OidComponent;

/// An unresolved type representation. Type references remain as strings
/// until the resolver phase.
#[derive(Debug, Clone)]
pub enum TypeSyntax {
    /// Reference to a named type, e.g. Integer32.
    TypeRef { name: String, span: Span },
    /// INTEGER with named values, e.g. INTEGER { up(1), down(2) }.
    IntegerEnum {
        base: String,
        named_numbers: Vec<NamedNumber>,
        span: Span,
    },
    /// BITS type with named bit positions.
    Bits {
        named_bits: Vec<NamedBit>,
        span: Span,
    },
    /// Type with a subtype constraint applied.
    Constrained {
        base: Box<TypeSyntax>,
        constraint: Constraint,
        span: Span,
    },
    /// SEQUENCE OF entry-type reference (table types).
    SequenceOf { entry_type: String, span: Span },
    /// SEQUENCE with named fields (table row definition).
    Sequence {
        fields: Vec<SequenceField>,
        span: Span,
    },
    /// Explicit OCTET STRING type.
    OctetString,
    /// OBJECT IDENTIFIER type.
    ObjectIdentifier,
}

impl TypeSyntax {
    pub fn span(&self) -> Span {
        match self {
            TypeSyntax::TypeRef { span, .. }
            | TypeSyntax::IntegerEnum { span, .. }
            | TypeSyntax::Bits { span, .. }
            | TypeSyntax::Constrained { span, .. }
            | TypeSyntax::SequenceOf { span, .. }
            | TypeSyntax::Sequence { span, .. } => *span,
            TypeSyntax::OctetString | TypeSyntax::ObjectIdentifier => Span::ZERO,
        }
    }
}

/// A named value in an INTEGER enumeration, e.g. up(1).
#[derive(Debug, Clone)]
pub struct NamedNumber {
    pub name: String,
    pub value: i64,
    pub span: Span,
}

/// A named bit position in a BITS type, e.g. flag1(0).
#[derive(Debug, Clone)]
pub struct NamedBit {
    pub name: String,
    pub position: u32,
    pub span: Span,
}

/// A field in a SEQUENCE type used for table row entries.
#[derive(Debug, Clone)]
pub struct SequenceField {
    pub name: String,
    pub syntax: TypeSyntax,
    pub span: Span,
}

/// A subtype constraint (SIZE or value range).
#[derive(Debug, Clone)]
pub enum Constraint {
    Size { ranges: Vec<Range>, span: Span },
    Range { ranges: Vec<Range>, span: Span },
}

impl Constraint {
    pub fn span(&self) -> Span {
        match self {
            Constraint::Size { span, .. } | Constraint::Range { span, .. } => *span,
        }
    }
}

/// A single range or value within a constraint. When max is None,
/// the range represents an exact value match.
#[derive(Debug, Clone)]
pub struct Range {
    pub min: RangeValue,
    pub max: Option<RangeValue>,
    pub span: Span,
}

/// An endpoint in a range (signed, unsigned, MIN, or MAX).
#[derive(Debug, Clone)]
pub enum RangeValue {
    Signed(i64),
    Unsigned(u64),
    Min,
    Max,
}

/// An unresolved DEFVAL clause value. Symbol references remain
/// unresolved until the semantic phase.
#[derive(Debug, Clone)]
pub enum DefVal {
    Integer(i64),
    Unsigned(u64),
    String(String),
    HexString(String),
    BinaryString(String),
    Enum(String),
    Bits { labels: Vec<String> },
    OidRef(String),
    OidValue { components: Vec<OidComponent> },
    Unparsed,
}
