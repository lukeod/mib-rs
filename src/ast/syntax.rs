//! AST types for SYNTAX clauses, constraints, indexes, and DEFVAL.
//!
//! These types represent the type system portions of SMI definitions,
//! including type references, enumerated integers, BITS, subtype constraints,
//! SEQUENCE definitions, and default values.

use super::common::{Ident, NamedNumber, QuotedString};
use super::oid::OidComponent;
use crate::source::SourceRange;
use crate::types::{Access, AccessKeyword, Status};

/// A parsed SYNTAX clause, pairing a [`TypeSyntax`] with its source location.
#[derive(Debug, PartialEq, Eq)]
pub struct SyntaxClause {
    /// The type expression.
    pub syntax: TypeSyntax,
    /// Source span covering the entire SYNTAX clause.
    pub span: SourceRange,
}

/// A type expression in a SYNTAX clause or type assignment.
///
/// Covers all type forms that appear in SMI definitions: simple type
/// references, enumerated integers, BITS, constrained types, SEQUENCE,
/// CHOICE, tagged types, and the built-in `OCTET STRING` and
/// `OBJECT IDENTIFIER` types.
#[derive(Debug, PartialEq, Eq)]
pub enum TypeSyntax {
    /// Unqualified type name reference.
    TypeRef(Ident),
    /// INTEGER type with enumerated named values.
    IntegerEnum {
        base: Option<Ident>,
        named_numbers: Vec<NamedNumber>,
        span: SourceRange,
    },
    /// BITS type with named bit positions.
    Bits {
        named_bits: Vec<NamedNumber>,
        span: SourceRange,
    },
    /// Type with a SIZE or range constraint.
    Constrained {
        base: Box<TypeSyntax>,
        constraint: Constraint,
        span: SourceRange,
    },
    /// SEQUENCE OF entry-type reference.
    SequenceOf {
        entry_type: Ident,
        span: SourceRange,
    },
    /// SEQUENCE with named fields (table row definition).
    Sequence {
        fields: Vec<SequenceField>,
        span: SourceRange,
    },
    /// CHOICE type with named alternatives.
    Choice {
        alternatives: Vec<SequenceField>,
        span: SourceRange,
    },
    /// Tagged type, e.g. `[APPLICATION n] IMPLICIT Type`.
    Tagged {
        underlying: Box<TypeSyntax>,
        span: SourceRange,
    },
    /// Explicit OCTET STRING type.
    OctetString { span: SourceRange },
    /// OBJECT IDENTIFIER type.
    ObjectIdentifier { span: SourceRange },
}

impl TypeSyntax {
    /// Returns the source span of this type expression.
    pub fn span(&self) -> SourceRange {
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

/// A named field within a SEQUENCE or CHOICE definition.
#[derive(Debug, PartialEq, Eq)]
pub struct SequenceField {
    /// Field name.
    pub name: Ident,
    /// Field type expression.
    pub syntax: TypeSyntax,
    /// Source span covering the entire field declaration.
    pub span: SourceRange,
}

/// A type sub-typing constraint (SIZE or range).
#[derive(Debug, PartialEq, Eq)]
pub enum Constraint {
    /// SIZE(...) constraint on length.
    Size {
        ranges: Vec<Range>,
        span: SourceRange,
    },
    /// Value range constraint, e.g. (0..65535).
    Range {
        ranges: Vec<Range>,
        span: SourceRange,
    },
}

impl Constraint {
    /// Returns the source span of this constraint.
    pub fn span(&self) -> SourceRange {
        match self {
            Constraint::Size { span, .. } | Constraint::Range { span, .. } => *span,
        }
    }
}

/// A single range element within a constraint.
///
/// When `max` is `None`, this represents an exact value (e.g. `SIZE (4)`).
/// When `max` is `Some`, this represents a range (e.g. `0..255`).
#[derive(Debug, PartialEq, Eq)]
pub struct Range {
    /// Lower bound (or exact value when `max` is `None`).
    pub min: RangeValue,
    /// Upper bound, or `None` for an exact value match.
    pub max: Option<RangeValue>,
    /// Source span covering the range expression.
    pub span: SourceRange,
}

/// An endpoint in a [`Range`] constraint.
#[derive(Debug, PartialEq, Eq)]
pub enum RangeValue {
    /// Signed integer literal.
    Signed(i64),
    /// Unsigned integer literal.
    Unsigned(u64),
    /// Named reference (`MIN` or `MAX` keyword).
    Named(Ident),
    /// Literal that could not be converted, preserving its source text.
    Raw(String),
}

/// A parsed ACCESS, MAX-ACCESS, or MIN-ACCESS clause.
#[derive(Debug, PartialEq, Eq)]
pub struct AccessClause {
    /// Which keyword form was used (`ACCESS`, `MAX-ACCESS`, or `MIN-ACCESS`).
    pub keyword: AccessKeyword,
    /// The access level value.
    pub value: Access,
    /// Source span covering the entire clause.
    pub span: SourceRange,
}

/// A parsed STATUS clause.
#[derive(Debug, PartialEq, Eq)]
pub struct StatusClause {
    /// The status value (e.g. `current`, `deprecated`, `obsolete`).
    pub value: Status,
    /// Source span covering the entire clause.
    pub span: SourceRange,
}

/// An INDEX clause in an OBJECT-TYPE definition.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexClause {
    /// Ordered list of index objects.
    pub items: Vec<IndexItem>,
    /// Source span covering `INDEX { ... }`.
    pub span: SourceRange,
}

/// A single entry in an [`IndexClause`], possibly marked `IMPLIED`.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexItem {
    /// Whether this index object is preceded by the `IMPLIED` keyword.
    pub implied: bool,
    /// The index object name.
    pub object: Ident,
    /// Source span covering this index entry.
    pub span: SourceRange,
}

/// The target row referenced by an AUGMENTS clause.
#[derive(Debug, PartialEq, Eq)]
pub struct AugmentsClause {
    /// Name of the row object being augmented.
    pub target: Ident,
    /// Source span covering `AUGMENTS { ... }`.
    pub span: SourceRange,
}

/// A DEFVAL clause specifying a default value for an OBJECT-TYPE.
#[derive(Debug, PartialEq, Eq)]
pub struct DefValClause {
    /// The parsed default value.
    pub value: DefVal,
    /// Source span covering `DEFVAL { ... }`.
    pub span: SourceRange,
}

/// The typed content within a `DEFVAL { ... }` clause.
#[derive(Debug, PartialEq, Eq)]
pub enum DefVal {
    /// Signed integer literal, e.g. `DEFVAL { -1 }`.
    /// Overflowing numeric literals are retained as zero with an
    /// `invalid-i64` parser diagnostic.
    Integer(i64),
    /// Unsigned integer literal, e.g. `DEFVAL { 0 }`.
    /// Values above `u64::MAX` use the signed zero recovery variant and emit
    /// an `invalid-i64` parser diagnostic.
    Unsigned(u64),
    /// Quoted string literal, e.g. `DEFVAL { "default" }`.
    String(QuotedString),
    /// Named value reference (enum label or object name).
    Identifier(Ident),
    /// BITS value, e.g. `DEFVAL { { flag1, flag2 } }`.
    Bits {
        labels: Vec<Ident>,
        span: SourceRange,
    },
    /// Hex string literal, e.g. `DEFVAL { 'FF00'H }`.
    HexString { content: String, span: SourceRange },
    /// Binary string literal, e.g. `DEFVAL { '0101'B }`.
    BinaryString { content: String, span: SourceRange },
    /// OID value, e.g. `DEFVAL { { 0 0 } }`.
    ObjectIdentifier {
        components: Vec<OidComponent>,
        span: SourceRange,
    },
    /// Value that could not be parsed; content was skipped.
    Unparsed { span: SourceRange },
}

/// A REVISION clause within a [`ModuleIdentityDef`](super::ModuleIdentityDef).
#[derive(Debug, PartialEq, Eq)]
pub struct RevisionClause {
    /// Revision date string (e.g. `"200006140000Z"`).
    pub date: QuotedString,
    /// Description of what changed in this revision.
    pub description: QuotedString,
    /// Source span covering the entire REVISION clause.
    pub span: SourceRange,
}
