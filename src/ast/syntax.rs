//! AST types for SYNTAX clauses, constraints, indexes, and DEFVAL.

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
    /// Returns the source span of this type expression.
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
    /// Returns the source span of this constraint.
    pub fn span(&self) -> Span {
        match self {
            Constraint::Size { span, .. } | Constraint::Range { span, .. } => *span,
        }
    }
}

/// A single range element within a constraint (min..max).
/// When max is None, the range represents an exact value match.
#[derive(Debug, PartialEq, Eq)]
pub struct Range {
    pub min: RangeValue,
    pub max: Option<RangeValue>,
    pub span: Span,
}

/// An endpoint in a range constraint.
#[derive(Debug, PartialEq, Eq)]
pub enum RangeValue {
    /// Signed integer literal.
    Signed(i64),
    /// Unsigned integer literal.
    Unsigned(u64),
    /// Named reference (MIN or MAX keyword).
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

/// The typed content within a `DEFVAL { ... }` clause.
#[derive(Debug, PartialEq, Eq)]
pub enum DefVal {
    /// Signed integer literal, e.g. `DEFVAL { -1 }`.
    Integer(i64),
    /// Unsigned integer literal, e.g. `DEFVAL { 0 }`.
    Unsigned(u64),
    /// Quoted string literal, e.g. `DEFVAL { "default" }`.
    String(QuotedString),
    /// Named value reference (enum label or object name).
    Identifier(Ident),
    /// BITS value, e.g. `DEFVAL { { flag1, flag2 } }`.
    Bits { labels: Vec<Ident>, span: Span },
    /// Hex string literal, e.g. `DEFVAL { 'FF00'H }`.
    HexString { content: String, span: Span },
    /// Binary string literal, e.g. `DEFVAL { '0101'B }`.
    BinaryString { content: String, span: Span },
    /// OID value, e.g. `DEFVAL { { 0 0 } }`.
    ObjectIdentifier {
        components: Vec<OidComponent>,
        span: Span,
    },
    /// Value that could not be parsed; content was skipped.
    Unparsed { span: Span },
}

/// A REVISION clause within MODULE-IDENTITY.
#[derive(Debug, PartialEq, Eq)]
pub struct RevisionClause {
    pub date: QuotedString,
    pub description: QuotedString,
    pub span: Span,
}
