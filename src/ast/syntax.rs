use super::common::{Ident, NamedNumber, QuotedString};
use super::oid::OidComponent;
use crate::types::{Access, AccessKeyword, Span, Status};

/// Wraps a TypeSyntax with its source span.
#[derive(Debug, PartialEq, Eq)]
pub struct SyntaxClause {
    pub syntax: TypeSyntax,
    pub span: Span,
}

/// A type expression in a SYNTAX clause or type assignment.
#[derive(Debug, PartialEq, Eq)]
pub enum TypeSyntax {
    /// Unqualified type name reference.
    TypeRef(Ident),
    /// INTEGER type with enumerated named values.
    IntegerEnum {
        base: Option<Ident>,
        named_numbers: Vec<NamedNumber>,
        span: Span,
    },
    /// BITS type with named bit positions.
    Bits {
        named_bits: Vec<NamedNumber>,
        span: Span,
    },
    /// Type with a SIZE or range constraint.
    Constrained {
        base: Box<TypeSyntax>,
        constraint: Constraint,
        span: Span,
    },
    /// SEQUENCE OF entry-type reference.
    SequenceOf { entry_type: Ident, span: Span },
    /// SEQUENCE with named fields (table row definition).
    Sequence {
        fields: Vec<SequenceField>,
        span: Span,
    },
    /// CHOICE type with named alternatives.
    Choice {
        alternatives: Vec<SequenceField>,
        span: Span,
    },
    /// Tagged type: [APPLICATION n] IMPLICIT Type.
    Tagged {
        underlying: Box<TypeSyntax>,
        span: Span,
    },
    /// Explicit OCTET STRING type.
    OctetString { span: Span },
    /// OBJECT IDENTIFIER type.
    ObjectIdentifier { span: Span },
}

impl TypeSyntax {
    pub fn span(&self) -> Span {
        match self {
            TypeSyntax::TypeRef(ident) => ident.span,
            TypeSyntax::IntegerEnum { span, .. }
            | TypeSyntax::Bits { span, .. }
            | TypeSyntax::Constrained { span, .. }
            | TypeSyntax::SequenceOf { span, .. }
            | TypeSyntax::Sequence { span, .. }
            | TypeSyntax::Choice { span, .. }
            | TypeSyntax::Tagged { span, .. }
            | TypeSyntax::OctetString { span }
            | TypeSyntax::ObjectIdentifier { span } => *span,
        }
    }
}

/// A named field within a SEQUENCE definition.
#[derive(Debug, PartialEq, Eq)]
pub struct SequenceField {
    pub name: Ident,
    pub syntax: TypeSyntax,
    pub span: Span,
}

/// A type sub-typing constraint (SIZE or range).
#[derive(Debug, PartialEq, Eq)]
pub enum Constraint {
    /// SIZE(...) constraint on length.
    Size { ranges: Vec<Range>, span: Span },
    /// Value range constraint, e.g. (0..65535).
    Range { ranges: Vec<Range>, span: Span },
}

impl Constraint {
    pub fn span(&self) -> Span {
        match self {
            Constraint::Size { span, .. } | Constraint::Range { span, .. } => *span,
        }
    }
}

/// A single range element within a constraint (min..max).
#[derive(Debug, PartialEq, Eq)]
pub struct Range {
    pub min: RangeValue,
    pub max: RangeValue,
    pub span: Span,
}

/// An endpoint in a range (numeric literal or MIN/MAX).
#[derive(Debug, PartialEq, Eq)]
pub enum RangeValue {
    Signed(i64),
    Unsigned(u64),
    Named(Ident),
}

/// A parsed ACCESS, MAX-ACCESS, or MIN-ACCESS clause.
#[derive(Debug, PartialEq, Eq)]
pub struct AccessClause {
    pub keyword: AccessKeyword,
    pub value: Access,
    pub span: Span,
}

/// A parsed STATUS clause value and span.
#[derive(Debug, PartialEq, Eq)]
pub struct StatusClause {
    pub value: Status,
    pub span: Span,
}

/// An INDEX clause in OBJECT-TYPE.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexClause {
    pub items: Vec<IndexItem>,
    pub span: Span,
}

/// A single entry in an INDEX clause, possibly IMPLIED.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexItem {
    pub implied: bool,
    pub object: Ident,
    pub span: Span,
}

/// The target row referenced by AUGMENTS.
#[derive(Debug, PartialEq, Eq)]
pub struct AugmentsClause {
    pub target: Ident,
    pub span: Span,
}

/// The default value for an OBJECT-TYPE.
#[derive(Debug, PartialEq, Eq)]
pub struct DefValClause {
    pub value: DefVal,
    pub span: Span,
}

/// The typed content within a DEFVAL { ... } clause.
#[derive(Debug, PartialEq, Eq)]
pub enum DefVal {
    Integer(i64),
    Unsigned(u64),
    String(QuotedString),
    Identifier(Ident),
    Bits {
        labels: Vec<Ident>,
        span: Span,
    },
    HexString {
        content: String,
        span: Span,
    },
    BinaryString {
        content: String,
        span: Span,
    },
    ObjectIdentifier {
        components: Vec<OidComponent>,
        span: Span,
    },
    Unparsed {
        span: Span,
    },
}

/// A REVISION clause within MODULE-IDENTITY.
#[derive(Debug, PartialEq, Eq)]
pub struct RevisionClause {
    pub date: QuotedString,
    pub description: QuotedString,
    pub span: Span,
}
