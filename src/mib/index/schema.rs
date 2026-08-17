//! Compilation of borrowed MIB metadata into owned index schemas.

use crate::mib::types::{NamedValue, Range};
use crate::mib::{Object, Oid};
use crate::types::BaseType;

use super::constraint::{ConstraintCheck, NormalizedConstraint, normalize_i64, normalize_usize};
use super::value::IndexValueKind;

/// Integer semantics retained by a schema component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IntegerIndexKind {
    Integer32,
    Unsigned32,
    Gauge32,
    TimeTicks,
    Counter32,
}

impl IntegerIndexKind {
    /// Semantic value kind accepted by this integer component.
    #[must_use]
    pub const fn value_kind(self) -> IndexValueKind {
        match self {
            Self::Integer32 => IndexValueKind::Integer32,
            Self::Unsigned32 => IndexValueKind::Unsigned32,
            Self::Gauge32 => IndexValueKind::Gauge32,
            Self::TimeTicks => IndexValueKind::TimeTicks,
            Self::Counter32 => IndexValueKind::Counter32,
        }
    }

    pub(crate) const fn maximum(self) -> i64 {
        match self {
            Self::Integer32 => i32::MAX as i64,
            Self::Unsigned32 | Self::Gauge32 | Self::TimeTicks | Self::Counter32 => u32::MAX as i64,
        }
    }
}

/// Octet-valued SMI type retained by a schema component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OctetIndexKind {
    OctetString,
    Bits,
    Opaque,
}

impl OctetIndexKind {
    /// Semantic value kind accepted by this octet component.
    #[must_use]
    pub const fn value_kind(self) -> IndexValueKind {
        match self {
            Self::OctetString => IndexValueKind::OctetString,
            Self::Bits => IndexValueKind::Bits,
            Self::Opaque => IndexValueKind::Opaque,
        }
    }
}

/// Framing of an octet or OBJECT IDENTIFIER index component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VariableFraming {
    /// Exactly this many value arcs, without a length prefix.
    Fixed(usize),
    /// One length arc followed by the value arcs.
    LengthPrefixed,
    /// The final component consumes the remainder without a prefix.
    Implied,
}

/// Normalized length constraints for octets or OBJECT IDENTIFIER arcs.
pub type LengthConstraint = NormalizedConstraint<usize>;

/// Effective integer range and enumeration restrictions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerConstraint {
    ranges: NormalizedConstraint<i64>,
    enumeration: Option<Box<[i64]>>,
}

impl IntegerConstraint {
    /// Normalized effective range alternatives.
    #[must_use]
    pub const fn ranges(&self) -> &NormalizedConstraint<i64> {
        &self.ranges
    }

    /// Effective accepted enumeration values, when this is an enumeration.
    #[must_use]
    pub fn enumeration(&self) -> Option<&[i64]> {
        self.enumeration.as_deref()
    }

    /// Check both range and enumeration restrictions.
    #[must_use]
    pub fn check(&self, value: i64) -> ConstraintCheck {
        let range_check = self.ranges.check(&value);
        if range_check == ConstraintCheck::Violation {
            return range_check;
        }
        if let Some(enumeration) = &self.enumeration
            && enumeration.binary_search(&value).is_err()
        {
            return ConstraintCheck::Violation;
        }
        range_check
    }
}

/// Algebraic wire representation for one index component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexWireType {
    Integer {
        kind: IntegerIndexKind,
        allowed: IntegerConstraint,
    },
    IpAddress,
    Octets {
        kind: OctetIndexKind,
        framing: VariableFraming,
        lengths: LengthConstraint,
    },
    ObjectIdentifier {
        framing: VariableFraming,
        lengths: LengthConstraint,
    },
}

impl IndexWireType {
    /// Semantic value kind required by this component.
    #[must_use]
    pub const fn value_kind(&self) -> IndexValueKind {
        match self {
            Self::Integer { kind, .. } => kind.value_kind(),
            Self::IpAddress => IndexValueKind::IpAddress,
            Self::Octets { kind, .. } => kind.value_kind(),
            Self::ObjectIdentifier { .. } => IndexValueKind::ObjectIdentifier,
        }
    }

    /// Framing for a variable-kind component.
    #[must_use]
    pub const fn framing(&self) -> Option<VariableFraming> {
        match self {
            Self::Octets { framing, .. } | Self::ObjectIdentifier { framing, .. } => Some(*framing),
            Self::Integer { .. } | Self::IpAddress => None,
        }
    }
}

/// Representable MIB deviations and schema concerns retained during compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexSchemaIssue {
    /// Counter32 is forbidden in INDEX but is mechanically representable.
    Counter32Compatibility,
    /// Part of an integer range or enumeration cannot be encoded in one OID arc.
    UnrepresentableIntegerDomainExcluded,
    /// At least one effective integer-range endpoint is unresolved.
    IncompleteIntegerConstraint,
    /// At least one effective SIZE endpoint is unresolved.
    IncompleteLengthConstraint,
    /// The referenced index object has no resolved numeric OID.
    UnresolvedObjectIdentity,
    /// A fixed-width component consumes no arcs and contributes no identity.
    ZeroWidthComponent,
    /// The complete effective index consumes no arcs and cannot identify rows.
    ZeroWidthIndex,
    /// An implied octet string may be empty, contrary to RFC 2578 section 7.7.
    ImpliedOctetsMayBeEmpty,
}

/// Owned metadata for one effective INDEX component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexComponentSchema {
    name: String,
    object_oid: Option<Oid>,
    wire_type: IndexWireType,
    issues: Box<[IndexSchemaIssue]>,
}

impl IndexComponentSchema {
    /// Identifier written in the effective INDEX clause.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Numeric identity of the referenced object.
    ///
    /// Absent for bare-type indexes and object-backed indexes whose OID could
    /// not be resolved. The latter also records
    /// [`IndexSchemaIssue::UnresolvedObjectIdentity`].
    #[must_use]
    pub const fn object_oid(&self) -> Option<&Oid> {
        self.object_oid.as_ref()
    }

    /// Complete semantic type, framing, and constraints for this component.
    #[must_use]
    pub const fn wire_type(&self) -> &IndexWireType {
        &self.wire_type
    }

    /// Representable deviations discovered during compilation.
    #[must_use]
    pub const fn issues(&self) -> &[IndexSchemaIssue] {
        &self.issues
    }

    /// Semantic value kind required for encoding.
    #[must_use]
    pub const fn value_kind(&self) -> IndexValueKind {
        self.wire_type.value_kind()
    }
}

/// Immutable, owned schema for one effective row INDEX clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexSchema {
    components: Box<[IndexComponentSchema]>,
    minimum_suffix_arcs: usize,
    maximum_suffix_arcs: Option<usize>,
    issues: Box<[IndexSchemaIssue]>,
}

impl IndexSchema {
    /// Compile a row or column's effective INDEX clause into owned metadata.
    pub fn compile(object: Object<'_>) -> Result<Self, IndexSchemaError> {
        if !object.is_row() && !object.is_column() {
            return Err(IndexSchemaError::NotRowOrColumn {
                object: object.name().to_string(),
            });
        }
        let indexes: Vec<_> = object.effective_indexes().collect();
        if indexes.is_empty() {
            return Err(IndexSchemaError::NoEffectiveIndexes {
                object: object.name().to_string(),
            });
        }

        let component_count = indexes.len();
        let mut components = Vec::with_capacity(component_count);
        for (position, index) in indexes.into_iter().enumerate() {
            let Some(ty) = index.ty() else {
                return Err(IndexSchemaError::UnresolvedType {
                    position,
                    component: index.name().to_string(),
                });
            };
            let base = ty.effective_base();
            if base == BaseType::Unknown {
                return Err(IndexSchemaError::UnresolvedType {
                    position,
                    component: index.name().to_string(),
                });
            }
            if index.implied() && position + 1 != component_count {
                return Err(IndexSchemaError::ImpliedNotLast {
                    position,
                    component: index.name().to_string(),
                });
            }

            let source = ConstraintSource::new(index.object(), ty);
            let mut issues = Vec::new();
            let wire_type = compile_wire_type(
                position,
                index.name(),
                base,
                index.implied(),
                &source,
                &mut issues,
            )?;
            let index_object = index.object();
            let object_oid = index_object
                .and_then(Object::node)
                .map(|node| node.oid().clone());
            if index_object.is_some() && object_oid.is_none() {
                issues.push(IndexSchemaIssue::UnresolvedObjectIdentity);
            }
            components.push(IndexComponentSchema {
                name: index.name().to_string(),
                object_oid,
                wire_type,
                issues: issues.into_boxed_slice(),
            });
        }

        let mut minimum_suffix_arcs = 0usize;
        let mut maximum_suffix_arcs = Some(0usize);
        for component in &components {
            minimum_suffix_arcs = minimum_suffix_arcs
                .checked_add(minimum_width(&component.wire_type))
                .ok_or(IndexSchemaError::MetadataOverflow)?;
            maximum_suffix_arcs = maximum_suffix_arcs
                .zip(maximum_width(&component.wire_type))
                .and_then(|(total, width)| total.checked_add(width));
        }

        let issues = if maximum_suffix_arcs == Some(0) {
            vec![IndexSchemaIssue::ZeroWidthIndex].into_boxed_slice()
        } else {
            Box::new([])
        };

        Ok(Self {
            components: components.into_boxed_slice(),
            minimum_suffix_arcs,
            maximum_suffix_arcs,
            issues,
        })
    }

    /// Effective components in INDEX-clause order.
    #[must_use]
    pub const fn components(&self) -> &[IndexComponentSchema] {
        &self.components
    }

    /// Number of effective components.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.components.len()
    }

    /// Whether the schema has no components. Compiled schemas are never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Minimum canonical suffix width admitted by the schema.
    #[must_use]
    pub const fn minimum_suffix_arcs(&self) -> usize {
        self.minimum_suffix_arcs
    }

    /// Maximum canonical suffix width when statically known.
    #[must_use]
    pub const fn maximum_suffix_arcs(&self) -> Option<usize> {
        self.maximum_suffix_arcs
    }

    /// Whole-schema concerns discovered during compilation.
    #[must_use]
    pub const fn issues(&self) -> &[IndexSchemaIssue] {
        &self.issues
    }
}

/// Failure to compile deterministic owned index metadata.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexSchemaError {
    #[error("object {object} is not a table row or column")]
    NotRowOrColumn { object: String },
    #[error("object {object} has no effective INDEX clause")]
    NoEffectiveIndexes { object: String },
    #[error("index component {position} ({component}) has no resolved effective type")]
    UnresolvedType { position: usize, component: String },
    #[error("index component {position} ({component}) has unsupported base type {base}")]
    UnsupportedBaseType {
        position: usize,
        component: String,
        base: BaseType,
    },
    #[error("IMPLIED index component {position} ({component}) is not final")]
    ImpliedNotLast { position: usize, component: String },
    #[error("IMPLIED index component {position} ({component}) is not variable-valued")]
    ImpliedNonVariable { position: usize, component: String },
    #[error("index component {position} ({component}) has no representable values")]
    EmptyRepresentableDomain { position: usize, component: String },
    #[error("arithmetic overflow while compiling index metadata")]
    MetadataOverflow,
}

struct ConstraintSource<'a> {
    sizes: &'a [Range],
    sizes_constrained: bool,
    ranges: &'a [Range],
    ranges_constrained: bool,
    enums: &'a [NamedValue],
}

impl<'a> ConstraintSource<'a> {
    fn new(object: Option<Object<'a>>, ty: crate::mib::Type<'a>) -> Self {
        if let Some(object) = object {
            Self {
                sizes: object.effective_sizes(),
                sizes_constrained: object.effective_sizes_constrained(),
                ranges: object.effective_ranges(),
                ranges_constrained: object.effective_ranges_constrained(),
                enums: object.effective_enums(),
            }
        } else {
            Self {
                sizes: ty.effective_sizes(),
                sizes_constrained: ty.effective_sizes_constrained(),
                ranges: ty.effective_ranges(),
                ranges_constrained: ty.effective_ranges_constrained(),
                enums: ty.effective_enums(),
            }
        }
    }
}

fn compile_wire_type(
    position: usize,
    component: &str,
    base: BaseType,
    implied: bool,
    source: &ConstraintSource<'_>,
    issues: &mut Vec<IndexSchemaIssue>,
) -> Result<IndexWireType, IndexSchemaError> {
    let integer_kind = match base {
        BaseType::Integer32 => Some(IntegerIndexKind::Integer32),
        BaseType::Unsigned32 => Some(IntegerIndexKind::Unsigned32),
        BaseType::Gauge32 => Some(IntegerIndexKind::Gauge32),
        BaseType::TimeTicks => Some(IntegerIndexKind::TimeTicks),
        BaseType::Counter32 => Some(IntegerIndexKind::Counter32),
        _ => None,
    };
    if let Some(kind) = integer_kind {
        if implied {
            return Err(IndexSchemaError::ImpliedNonVariable {
                position,
                component: component.to_string(),
            });
        }
        if kind == IntegerIndexKind::Counter32 {
            issues.push(IndexSchemaIssue::Counter32Compatibility);
        }
        if source.ranges.iter().any(|range| {
            bound_outside_integer_domain(&range.min, kind.maximum())
                || bound_outside_integer_domain(&range.max, kind.maximum())
        }) || source
            .enums
            .iter()
            .any(|value| !(0..=kind.maximum()).contains(&value.value))
        {
            issues.push(IndexSchemaIssue::UnrepresentableIntegerDomainExcluded);
        }
        let ranges = normalize_i64(source.ranges, source.ranges_constrained, 0, kind.maximum());
        if ranges.is_incomplete() {
            issues.push(IndexSchemaIssue::IncompleteIntegerConstraint);
        }
        if matches!(ranges, NormalizedConstraint::Empty) {
            return Err(IndexSchemaError::EmptyRepresentableDomain {
                position,
                component: component.to_string(),
            });
        }
        let mut enumeration = (!source.enums.is_empty()).then(|| {
            source
                .enums
                .iter()
                .map(|value| value.value)
                .filter(|value| (0..=kind.maximum()).contains(value))
                .filter(|value| ranges.check(value) != ConstraintCheck::Violation)
                .collect::<Vec<_>>()
        });
        if let Some(values) = &mut enumeration {
            values.sort_unstable();
            values.dedup();
            if values.is_empty() {
                return Err(IndexSchemaError::EmptyRepresentableDomain {
                    position,
                    component: component.to_string(),
                });
            }
        }
        return Ok(IndexWireType::Integer {
            kind,
            allowed: IntegerConstraint {
                ranges,
                enumeration: enumeration.map(Vec::into_boxed_slice),
            },
        });
    }

    if base == BaseType::IpAddress {
        if implied {
            return Err(IndexSchemaError::ImpliedNonVariable {
                position,
                component: component.to_string(),
            });
        }
        return Ok(IndexWireType::IpAddress);
    }

    if base == BaseType::Counter64 {
        return Err(IndexSchemaError::UnsupportedBaseType {
            position,
            component: component.to_string(),
            base,
        });
    }

    let lengths = normalize_usize(source.sizes, source.sizes_constrained);
    if matches!(lengths, NormalizedConstraint::Empty) {
        return Err(IndexSchemaError::EmptyRepresentableDomain {
            position,
            component: component.to_string(),
        });
    }
    if lengths.is_incomplete() {
        issues.push(IndexSchemaIssue::IncompleteLengthConstraint);
    }

    if implied
        && matches!(
            base,
            BaseType::OctetString | BaseType::Bits | BaseType::Opaque
        )
        && lengths.exact_value().is_some()
    {
        return Err(IndexSchemaError::ImpliedNonVariable {
            position,
            component: component.to_string(),
        });
    }

    let framing = if implied {
        VariableFraming::Implied
    } else if let Some(&size) = lengths.exact_value() {
        VariableFraming::Fixed(size)
    } else {
        VariableFraming::LengthPrefixed
    };
    match base {
        BaseType::OctetString | BaseType::Bits | BaseType::Opaque => {
            if framing == VariableFraming::Fixed(0) {
                issues.push(IndexSchemaIssue::ZeroWidthComponent);
            }
            if implied && lengths.check(&0) != ConstraintCheck::Violation {
                issues.push(IndexSchemaIssue::ImpliedOctetsMayBeEmpty);
            }
            let kind = match base {
                BaseType::OctetString => OctetIndexKind::OctetString,
                BaseType::Bits => OctetIndexKind::Bits,
                BaseType::Opaque => OctetIndexKind::Opaque,
                _ => unreachable!(),
            };
            Ok(IndexWireType::Octets {
                kind,
                framing,
                lengths,
            })
        }
        BaseType::ObjectIdentifier => Ok(IndexWireType::ObjectIdentifier {
            framing: if implied {
                VariableFraming::Implied
            } else {
                VariableFraming::LengthPrefixed
            },
            lengths,
        }),
        _ => Err(IndexSchemaError::UnsupportedBaseType {
            position,
            component: component.to_string(),
            base,
        }),
    }
}

fn bound_outside_integer_domain(bound: &crate::mib::types::RangeBound, maximum: i64) -> bool {
    match bound {
        crate::mib::types::RangeBound::Signed(value) => !(0..=maximum).contains(value),
        crate::mib::types::RangeBound::Unsigned(value) => *value > maximum as u64,
        crate::mib::types::RangeBound::Min
        | crate::mib::types::RangeBound::Max
        | crate::mib::types::RangeBound::Raw(_) => false,
    }
}

fn minimum_width(wire_type: &IndexWireType) -> usize {
    match wire_type {
        IndexWireType::Integer { .. } => 1,
        IndexWireType::IpAddress => 4,
        IndexWireType::Octets {
            framing, lengths, ..
        }
        | IndexWireType::ObjectIdentifier { framing, lengths } => match framing {
            VariableFraming::Fixed(size) => *size,
            VariableFraming::LengthPrefixed => 1 + minimum_length(lengths),
            VariableFraming::Implied => minimum_length(lengths),
        },
    }
}

fn maximum_width(wire_type: &IndexWireType) -> Option<usize> {
    match wire_type {
        IndexWireType::Integer { .. } => Some(1),
        IndexWireType::IpAddress => Some(4),
        IndexWireType::Octets {
            framing, lengths, ..
        }
        | IndexWireType::ObjectIdentifier { framing, lengths } => match framing {
            VariableFraming::Fixed(size) => Some(*size),
            VariableFraming::LengthPrefixed => lengths
                .proven_maximum()
                .and_then(|maximum| maximum.checked_add(1)),
            VariableFraming::Implied => lengths.proven_maximum().copied(),
        },
    }
}

fn minimum_length(lengths: &LengthConstraint) -> usize {
    match lengths {
        NormalizedConstraint::Known(_) | NormalizedConstraint::Incomplete { .. } => {
            lengths.proven_minimum().copied().unwrap_or(0)
        }
        NormalizedConstraint::Unspecified | NormalizedConstraint::Empty => 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::mib::types::{Range, RangeBound};

    use super::*;

    #[test]
    fn zero_length_oid_remains_length_prefixed() {
        let sizes = [Range {
            min: RangeBound::Unsigned(0),
            max: RangeBound::Unsigned(0),
            range: None,
        }];
        let source = ConstraintSource {
            sizes: &sizes,
            sizes_constrained: true,
            ranges: &[],
            ranges_constrained: false,
            enums: &[],
        };
        let mut issues = Vec::new();
        let wire = compile_wire_type(
            0,
            "oidIndex",
            BaseType::ObjectIdentifier,
            false,
            &source,
            &mut issues,
        )
        .unwrap();

        assert!(matches!(
            wire,
            IndexWireType::ObjectIdentifier {
                framing: VariableFraming::LengthPrefixed,
                ..
            }
        ));
        assert!(!issues.contains(&IndexSchemaIssue::ZeroWidthComponent));
    }
}
