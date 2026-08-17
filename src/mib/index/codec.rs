//! Exact decoding, canonical encoding, and object-specific bounds.

use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use crate::mib::Oid;

use super::constraint::ConstraintCheck;
use super::schema::{
    IndexComponentSchema, IndexSchema, IndexWireType, IntegerConstraint, IntegerIndexKind,
    LengthConstraint, VariableFraming,
};
use super::value::{IndexValue, IndexValueKind, IndexValueRef};

/// Maximum subidentifier count of a complete SMI instance OID.
pub const MAX_INSTANCE_OID_ARCS: usize = 128;

/// Whether known MIB constraint violations fail exact decoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConstraintMode {
    /// Reject values that conflict with known effective constraints.
    #[default]
    Enforce,
    /// Return structurally exact values and report constraint violations.
    Report,
}

/// Handling of an encoding value whose validity depends on unresolved metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IncompleteConstraintMode {
    /// Reject values that cannot be proven valid.
    #[default]
    Reject,
    /// Allow values that are not proven invalid.
    Allow,
}

/// Per-operation exact-decode bounds and constraint policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeOptions {
    max_suffix_arcs: usize,
    max_value_arcs: usize,
    max_components: usize,
    constraint_mode: ConstraintMode,
}

impl DecodeOptions {
    /// Construct options bounded by a complete suffix length.
    #[must_use]
    pub const fn new(max_suffix_arcs: usize) -> Self {
        Self {
            max_suffix_arcs,
            max_value_arcs: max_suffix_arcs,
            max_components: usize::MAX,
            constraint_mode: ConstraintMode::Enforce,
        }
    }

    /// Set the maximum arcs copied into one semantic value.
    #[must_use]
    pub const fn with_max_value_arcs(mut self, maximum: usize) -> Self {
        self.max_value_arcs = maximum;
        self
    }

    /// Set the maximum schema component count accepted by this operation.
    #[must_use]
    pub const fn with_max_components(mut self, maximum: usize) -> Self {
        self.max_components = maximum;
        self
    }

    /// Set constraint enforcement or reporting.
    #[must_use]
    pub const fn with_constraint_mode(mut self, mode: ConstraintMode) -> Self {
        self.constraint_mode = mode;
        self
    }

    /// Maximum accepted suffix length.
    #[must_use]
    pub const fn max_suffix_arcs(self) -> usize {
        self.max_suffix_arcs
    }
}

/// Per-operation canonical-encode bounds and incomplete-constraint policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeOptions {
    max_suffix_arcs: usize,
    max_value_arcs: usize,
    incomplete_constraints: IncompleteConstraintMode,
}

impl EncodeOptions {
    /// Construct strict options bounded by a complete suffix length.
    #[must_use]
    pub const fn new(max_suffix_arcs: usize) -> Self {
        Self {
            max_suffix_arcs,
            max_value_arcs: max_suffix_arcs,
            incomplete_constraints: IncompleteConstraintMode::Reject,
        }
    }

    /// Set the maximum arcs read from one semantic value.
    #[must_use]
    pub const fn with_max_value_arcs(mut self, maximum: usize) -> Self {
        self.max_value_arcs = maximum;
        self
    }

    /// Set handling for values not decidable from incomplete metadata.
    #[must_use]
    pub const fn with_incomplete_constraints(mut self, mode: IncompleteConstraintMode) -> Self {
        self.incomplete_constraints = mode;
        self
    }

    /// Maximum emitted suffix length.
    #[must_use]
    pub const fn max_suffix_arcs(self) -> usize {
        self.max_suffix_arcs
    }
}

/// A known conflict between one exact value and effective MIB metadata.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexConstraintViolation {
    #[error("integer value {value} is outside the effective range")]
    IntegerRange { value: i64 },
    #[error("integer value {value} is not in the effective enumeration")]
    IntegerEnumeration { value: i64 },
    #[error("value length {length} is outside the effective SIZE constraint")]
    Length { length: usize },
}

/// A reported constraint violation associated with a component position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportedIndexViolation {
    component_position: usize,
    violation: IndexConstraintViolation,
}

impl ReportedIndexViolation {
    /// Zero-based effective INDEX component position.
    #[must_use]
    pub const fn component_position(&self) -> usize {
        self.component_position
    }

    /// Typed known constraint conflict.
    #[must_use]
    pub const fn violation(&self) -> &IndexConstraintViolation {
        &self.violation
    }
}

/// Complete exact decoding of one suffix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedRowIndex<'schema, 'suffix> {
    schema: &'schema IndexSchema,
    suffix: &'suffix [u32],
    values: Box<[IndexValue]>,
    ranges: Box<[Range<usize>]>,
    violations: Box<[ReportedIndexViolation]>,
}

impl<'schema, 'suffix> DecodedRowIndex<'schema, 'suffix> {
    /// Schema used for the operation.
    #[must_use]
    pub const fn schema(&self) -> &'schema IndexSchema {
        self.schema
    }

    /// Exact input suffix, all of which was consumed.
    #[must_use]
    pub const fn raw_arcs(&self) -> &'suffix [u32] {
        self.suffix
    }

    /// Ordered semantic values.
    #[must_use]
    pub const fn values(&self) -> &[IndexValue] {
        &self.values
    }

    /// Ephemeral component views combining schema, value, and raw arcs.
    #[must_use]
    pub fn components(&self) -> DecodedIndexComponents<'_, 'schema, 'suffix> {
        DecodedIndexComponents {
            decoded: self,
            position: 0,
        }
    }

    /// Known constraint conflicts returned in report mode.
    #[must_use]
    pub const fn violations(&self) -> &[ReportedIndexViolation] {
        &self.violations
    }
}

/// Borrowed view of one successfully decoded component.
#[derive(Clone, Copy, Debug)]
pub struct DecodedIndexComponent<'a, 'schema, 'suffix> {
    schema: &'schema IndexComponentSchema,
    value: &'a IndexValue,
    arc_range: &'a Range<usize>,
    raw_arcs: &'suffix [u32],
}

impl<'a, 'schema, 'suffix> DecodedIndexComponent<'a, 'schema, 'suffix> {
    /// Owned schema metadata for this position.
    #[must_use]
    pub const fn schema(&self) -> &'schema IndexComponentSchema {
        self.schema
    }

    /// Component name.
    #[must_use]
    pub fn name(&self) -> &'schema str {
        self.schema.name()
    }

    /// Decoded semantic value.
    #[must_use]
    pub const fn value(&self) -> &'a IndexValue {
        self.value
    }

    /// Absolute half-open suffix range occupied by this component.
    #[must_use]
    pub fn arc_range(&self) -> Range<usize> {
        self.arc_range.clone()
    }

    /// Exact raw arcs, including a length prefix when present.
    #[must_use]
    pub const fn raw_arcs(&self) -> &'suffix [u32] {
        self.raw_arcs
    }
}

/// Iterator over decoded component views.
pub struct DecodedIndexComponents<'a, 'schema, 'suffix> {
    decoded: &'a DecodedRowIndex<'schema, 'suffix>,
    position: usize,
}

impl<'a, 'schema, 'suffix> Iterator for DecodedIndexComponents<'a, 'schema, 'suffix> {
    type Item = DecodedIndexComponent<'a, 'schema, 'suffix>;

    fn next(&mut self) -> Option<Self::Item> {
        let position = self.position;
        let schema = self.decoded.schema.components().get(position)?;
        let value = &self.decoded.values[position];
        let arc_range = &self.decoded.ranges[position];
        self.position += 1;
        Some(DecodedIndexComponent {
            schema,
            value,
            arc_range,
            raw_arcs: &self.decoded.suffix[arc_range.clone()],
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.decoded.values.len() - self.position;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DecodedIndexComponents<'_, '_, '_> {}

/// Successfully decoded component retained on a later failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPrefixComponent<'suffix> {
    position: usize,
    value: IndexValue,
    arc_range: Range<usize>,
    raw_arcs: &'suffix [u32],
}

impl<'suffix> DecodedPrefixComponent<'suffix> {
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    #[must_use]
    pub const fn value(&self) -> &IndexValue {
        &self.value
    }

    #[must_use]
    pub fn arc_range(&self) -> Range<usize> {
        self.arc_range.clone()
    }

    #[must_use]
    pub const fn raw_arcs(&self) -> &'suffix [u32] {
        self.raw_arcs
    }
}

/// Stable reason exact decoding failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexDecodeErrorKind {
    #[error("suffix has {actual} arcs, exceeding the operation limit of {maximum}")]
    SuffixTooLong { actual: usize, maximum: usize },
    #[error("schema has {actual} components, exceeding the operation limit of {maximum}")]
    TooManyComponents { actual: usize, maximum: usize },
    #[error("component needs {needed} arcs but only {available} remain")]
    Truncated { needed: usize, available: usize },
    #[error("declared length {declared} exceeds the value limit of {maximum}")]
    LengthPrefixTooLarge { declared: u32, maximum: usize },
    #[error("value has {actual} arcs, exceeding the value limit of {maximum}")]
    ValueTooLong { actual: usize, maximum: usize },
    #[error("arc value {value} is not an octet")]
    InvalidOctet { value: u32 },
    #[error("arc value {value} is outside the non-negative Integer32 index domain")]
    Integer32OutOfDomain { value: u32 },
    #[error("{count} trailing arcs remain")]
    TrailingArcs { count: usize },
    #[error("{0}")]
    ConstraintViolation(IndexConstraintViolation),
}

/// Exact-decode failure with typed context and successfully decoded prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDecodeError<'suffix> {
    kind: IndexDecodeErrorKind,
    component_position: Option<usize>,
    component_name: Option<String>,
    arc_offset: usize,
    decoded_prefix: Box<[DecodedPrefixComponent<'suffix>]>,
    remaining: &'suffix [u32],
}

impl<'suffix> IndexDecodeError<'suffix> {
    #[must_use]
    pub const fn kind(&self) -> &IndexDecodeErrorKind {
        &self.kind
    }

    #[must_use]
    pub const fn component_position(&self) -> Option<usize> {
        self.component_position
    }

    #[must_use]
    pub fn component_name(&self) -> Option<&str> {
        self.component_name.as_deref()
    }

    /// Absolute offset in the supplied suffix at which failure was detected.
    #[must_use]
    pub const fn arc_offset(&self) -> usize {
        self.arc_offset
    }

    #[must_use]
    pub const fn decoded_prefix(&self) -> &[DecodedPrefixComponent<'suffix>] {
        &self.decoded_prefix
    }

    #[must_use]
    pub const fn remaining_arcs(&self) -> &'suffix [u32] {
        self.remaining
    }
}

impl fmt::Display for IndexDecodeError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(position), Some(name)) = (self.component_position, &self.component_name) {
            write!(
                f,
                "failed to decode index component {position} ({name}) at suffix arc {}: {}",
                self.arc_offset, self.kind
            )
        } else {
            write!(
                f,
                "failed to decode index suffix at arc {}: {}",
                self.arc_offset, self.kind
            )
        }
    }
}

impl std::error::Error for IndexDecodeError<'_> {}

/// Immutable canonical index suffix.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IndexSuffix(Box<[u32]>);

impl IndexSuffix {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u32]> for IndexSuffix {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl std::ops::Deref for IndexSuffix {
    type Target = [u32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<IndexSuffix> for Oid {
    fn from(value: IndexSuffix) -> Self {
        Oid::from(value.0.into_vec())
    }
}

impl From<&IndexSuffix> for Oid {
    fn from(value: &IndexSuffix) -> Self {
        Oid::from(value.as_ref())
    }
}

/// Stable reason canonical encoding failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexEncodeErrorKind {
    #[error("too few values: expected {expected}, received {actual}")]
    TooFewValues { expected: usize, actual: usize },
    #[error("too many values: expected {expected}")]
    TooManyValues { expected: usize },
    #[error("wrong value kind: expected {expected}, received {actual}")]
    WrongValueKind {
        expected: IndexValueKind,
        actual: IndexValueKind,
    },
    #[error("negative Integer32 value {value} cannot be encoded as an OID arc")]
    NegativeInteger32 { value: i32 },
    #[error("fixed component needs {expected} value arcs, received {actual}")]
    FixedLength { expected: usize, actual: usize },
    #[error("value has {actual} arcs, exceeding the value limit of {maximum}")]
    ValueTooLong { actual: usize, maximum: usize },
    #[error("value length {length} cannot be represented by one OID arc")]
    LengthPrefixOverflow { length: usize },
    #[error("encoded suffix would have {actual} arcs, exceeding the limit of {maximum}")]
    SuffixTooLong { actual: usize, maximum: usize },
    #[error("{0}")]
    ConstraintViolation(IndexConstraintViolation),
    #[error("constraint validity is indeterminate because metadata is unresolved")]
    IndeterminateConstraint,
    #[error("arithmetic overflow while encoding the suffix")]
    ArithmeticOverflow,
}

/// Canonical-encode failure with component context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEncodeError {
    kind: IndexEncodeErrorKind,
    component_position: Option<usize>,
    component_name: Option<String>,
}

impl IndexEncodeError {
    #[must_use]
    pub const fn kind(&self) -> &IndexEncodeErrorKind {
        &self.kind
    }

    #[must_use]
    pub const fn component_position(&self) -> Option<usize> {
        self.component_position
    }

    #[must_use]
    pub fn component_name(&self) -> Option<&str> {
        self.component_name.as_deref()
    }
}

impl fmt::Display for IndexEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(position), Some(name)) = (self.component_position, &self.component_name) {
            write!(
                f,
                "failed to encode index component {position} ({name}): {}",
                self.kind
            )
        } else {
            write!(f, "failed to encode index suffix: {}", self.kind)
        }
    }
}

impl std::error::Error for IndexEncodeError {}

impl IndexSchema {
    /// Decode one complete suffix exactly under this owned schema.
    pub fn decode_exact<'schema, 'suffix>(
        &'schema self,
        suffix: &'suffix [u32],
        options: DecodeOptions,
    ) -> Result<DecodedRowIndex<'schema, 'suffix>, IndexDecodeError<'suffix>> {
        if suffix.len() > options.max_suffix_arcs {
            return Err(IndexDecodeError {
                kind: IndexDecodeErrorKind::SuffixTooLong {
                    actual: suffix.len(),
                    maximum: options.max_suffix_arcs,
                },
                component_position: None,
                component_name: None,
                arc_offset: 0,
                decoded_prefix: Box::new([]),
                remaining: suffix,
            });
        }
        if self.len() > options.max_components {
            return Err(IndexDecodeError {
                kind: IndexDecodeErrorKind::TooManyComponents {
                    actual: self.len(),
                    maximum: options.max_components,
                },
                component_position: None,
                component_name: None,
                arc_offset: 0,
                decoded_prefix: Box::new([]),
                remaining: suffix,
            });
        }

        let mut values = Vec::with_capacity(self.len());
        let mut ranges = Vec::with_capacity(self.len());
        let mut violations = Vec::new();
        let mut position = 0usize;

        for (component_position, component) in self.components().iter().enumerate() {
            let start = position;
            let value = match component.wire_type() {
                IndexWireType::Integer { kind, allowed } => {
                    let Some(&arc) = suffix.get(position) else {
                        return Err(decode_error(
                            IndexDecodeErrorKind::Truncated {
                                needed: 1,
                                available: 0,
                            },
                            component_position,
                            component,
                            start,
                            &values,
                            &ranges,
                            suffix,
                        ));
                    };
                    position += 1;
                    let value = decode_integer(*kind, arc).map_err(|kind| {
                        decode_error(
                            kind,
                            component_position,
                            component,
                            start,
                            &values,
                            &ranges,
                            suffix,
                        )
                    })?;
                    if let Some(violation) = integer_violation(allowed, i64::from(arc)) {
                        handle_decode_violation(
                            options.constraint_mode,
                            component_position,
                            component,
                            start,
                            violation,
                            &mut violations,
                            &values,
                            &ranges,
                            suffix,
                        )?;
                    }
                    value
                }
                IndexWireType::IpAddress => {
                    let data = take_value_arcs(
                        suffix,
                        position,
                        4,
                        options.max_value_arcs,
                        component_position,
                        component,
                        &values,
                        &ranges,
                    )?;
                    if let Some((offset, value)) = invalid_octet(data) {
                        return Err(decode_error_at(
                            IndexDecodeErrorKind::InvalidOctet { value },
                            component_position,
                            component,
                            start + offset,
                            start,
                            &values,
                            &ranges,
                            suffix,
                        ));
                    }
                    position += 4;
                    IndexValue::IpAddress(std::array::from_fn(|offset| data[offset] as u8))
                }
                IndexWireType::Octets {
                    kind,
                    framing,
                    lengths,
                } => {
                    let (data_start, length) = framed_value(
                        *framing,
                        suffix,
                        position,
                        options.max_value_arcs,
                        component_position,
                        component,
                        &values,
                        &ranges,
                    )?;
                    let data = &suffix[data_start..data_start + length];
                    if let Some((offset, value)) = invalid_octet(data) {
                        return Err(decode_error_at(
                            IndexDecodeErrorKind::InvalidOctet { value },
                            component_position,
                            component,
                            data_start + offset,
                            start,
                            &values,
                            &ranges,
                            suffix,
                        ));
                    }
                    if let Some(violation) = length_violation(lengths, length) {
                        handle_decode_violation(
                            options.constraint_mode,
                            component_position,
                            component,
                            start,
                            violation,
                            &mut violations,
                            &values,
                            &ranges,
                            suffix,
                        )?;
                    }
                    position = data_start + length;
                    let bytes: Vec<u8> = data.iter().map(|arc| *arc as u8).collect();
                    match kind {
                        super::schema::OctetIndexKind::OctetString => {
                            IndexValue::OctetString(bytes)
                        }
                        super::schema::OctetIndexKind::Bits => IndexValue::Bits(bytes),
                        super::schema::OctetIndexKind::Opaque => IndexValue::Opaque(bytes),
                    }
                }
                IndexWireType::ObjectIdentifier { framing, lengths } => {
                    let (data_start, length) = framed_value(
                        *framing,
                        suffix,
                        position,
                        options.max_value_arcs,
                        component_position,
                        component,
                        &values,
                        &ranges,
                    )?;
                    if let Some(violation) = length_violation(lengths, length) {
                        handle_decode_violation(
                            options.constraint_mode,
                            component_position,
                            component,
                            start,
                            violation,
                            &mut violations,
                            &values,
                            &ranges,
                            suffix,
                        )?;
                    }
                    position = data_start + length;
                    IndexValue::ObjectIdentifier(Oid::from(&suffix[data_start..position]))
                }
            };
            values.push(value);
            ranges.push(start..position);
        }

        if position != suffix.len() {
            return Err(decode_whole_error(
                IndexDecodeErrorKind::TrailingArcs {
                    count: suffix.len() - position,
                },
                position,
                &values,
                &ranges,
                suffix,
            ));
        }

        Ok(DecodedRowIndex {
            schema: self,
            suffix,
            values: values.into_boxed_slice(),
            ranges: ranges.into_boxed_slice(),
            violations: violations.into_boxed_slice(),
        })
    }

    /// Canonically encode a complete value sequence under this owned schema.
    pub fn encode_canonical<'a>(
        &self,
        values: impl IntoIterator<Item = IndexValueRef<'a>>,
        options: EncodeOptions,
    ) -> Result<IndexSuffix, IndexEncodeError> {
        let mut values = values.into_iter();
        let mut suffix =
            Vec::with_capacity(self.minimum_suffix_arcs().min(options.max_suffix_arcs));

        for (position, component) in self.components().iter().enumerate() {
            let Some(value) = values.next() else {
                return Err(encode_whole_error(IndexEncodeErrorKind::TooFewValues {
                    expected: self.len(),
                    actual: position,
                }));
            };
            if value.kind() != component.value_kind() {
                return Err(encode_error(
                    IndexEncodeErrorKind::WrongValueKind {
                        expected: component.value_kind(),
                        actual: value.kind(),
                    },
                    position,
                    component,
                ));
            }

            match (component.wire_type(), value) {
                (IndexWireType::Integer { allowed, .. }, value) => {
                    let integer = integer_ref(value)
                        .map_err(|kind| encode_error(kind, position, component))?;
                    validate_integer_encode(
                        allowed,
                        integer,
                        options.incomplete_constraints,
                        position,
                        component,
                    )?;
                    push_component(&suffix, 1, options.max_suffix_arcs, position, component)?;
                    suffix.push(integer as u32);
                }
                (IndexWireType::IpAddress, IndexValueRef::IpAddress(address)) => {
                    push_component(&suffix, 4, options.max_suffix_arcs, position, component)?;
                    suffix.extend(address.map(u32::from));
                }
                (
                    IndexWireType::Octets {
                        framing, lengths, ..
                    },
                    IndexValueRef::OctetString(bytes)
                    | IndexValueRef::Bits(bytes)
                    | IndexValueRef::Opaque(bytes),
                ) => encode_variable(
                    &mut suffix,
                    bytes.iter().copied().map(u32::from),
                    bytes.len(),
                    *framing,
                    lengths,
                    options,
                    position,
                    component,
                )?,
                (
                    IndexWireType::ObjectIdentifier { framing, lengths },
                    IndexValueRef::ObjectIdentifier(arcs),
                ) => encode_variable(
                    &mut suffix,
                    arcs.iter().copied(),
                    arcs.len(),
                    *framing,
                    lengths,
                    options,
                    position,
                    component,
                )?,
                _ => unreachable!("value kind checked before encoding"),
            }
        }

        if values.next().is_some() {
            return Err(encode_whole_error(IndexEncodeErrorKind::TooManyValues {
                expected: self.len(),
            }));
        }
        Ok(IndexSuffix(suffix.into_boxed_slice()))
    }
}

/// Object-specific binding of a reusable row schema and suffix budget.
#[derive(Clone, Debug)]
pub struct BoundIndexCodec {
    schema: Arc<IndexSchema>,
    max_suffix_arcs: usize,
}

impl BoundIndexCodec {
    /// Bind a schema to an explicit suffix budget.
    pub fn new(schema: Arc<IndexSchema>, max_suffix_arcs: usize) -> Result<Self, IndexBindError> {
        if schema.minimum_suffix_arcs() > max_suffix_arcs {
            return Err(IndexBindError::MinimumSuffixTooLong {
                minimum: schema.minimum_suffix_arcs(),
                maximum: max_suffix_arcs,
            });
        }
        Ok(Self {
            schema,
            max_suffix_arcs,
        })
    }

    /// Bind using the 128-arc complete instance-OID limit.
    pub fn for_object_oid(
        schema: Arc<IndexSchema>,
        object_oid: &Oid,
    ) -> Result<Self, IndexBindError> {
        let Some(maximum) = MAX_INSTANCE_OID_ARCS.checked_sub(object_oid.len()) else {
            return Err(IndexBindError::ObjectOidTooLong {
                actual: object_oid.len(),
                maximum: MAX_INSTANCE_OID_ARCS,
            });
        };
        Self::new(schema, maximum)
    }

    #[must_use]
    pub fn schema(&self) -> &Arc<IndexSchema> {
        &self.schema
    }

    #[must_use]
    pub const fn max_suffix_arcs(&self) -> usize {
        self.max_suffix_arcs
    }

    /// Decode with this binding's complete suffix limit.
    pub fn decode_exact<'schema, 'suffix>(
        &'schema self,
        suffix: &'suffix [u32],
        mode: ConstraintMode,
    ) -> Result<DecodedRowIndex<'schema, 'suffix>, IndexDecodeError<'suffix>> {
        self.schema.decode_exact(
            suffix,
            DecodeOptions::new(self.max_suffix_arcs).with_constraint_mode(mode),
        )
    }

    /// Encode with this binding's complete suffix limit and strict incomplete
    /// constraint handling.
    pub fn encode_canonical<'a>(
        &self,
        values: impl IntoIterator<Item = IndexValueRef<'a>>,
    ) -> Result<IndexSuffix, IndexEncodeError> {
        self.encode_canonical_with_incomplete_constraints(values, IncompleteConstraintMode::Reject)
    }

    /// Encode with this binding's suffix limit and an explicit policy for
    /// values whose validity depends on unresolved constraint metadata.
    pub fn encode_canonical_with_incomplete_constraints<'a>(
        &self,
        values: impl IntoIterator<Item = IndexValueRef<'a>>,
        mode: IncompleteConstraintMode,
    ) -> Result<IndexSuffix, IndexEncodeError> {
        self.schema.encode_canonical(
            values,
            EncodeOptions::new(self.max_suffix_arcs).with_incomplete_constraints(mode),
        )
    }
}

/// Failure to bind a row schema to an object or explicit operation limit.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexBindError {
    #[error("object OID has {actual} arcs, exceeding the complete limit of {maximum}")]
    ObjectOidTooLong { actual: usize, maximum: usize },
    #[error("schema needs at least {minimum} suffix arcs, exceeding the limit of {maximum}")]
    MinimumSuffixTooLong { minimum: usize, maximum: usize },
}

fn decode_integer(kind: IntegerIndexKind, arc: u32) -> Result<IndexValue, IndexDecodeErrorKind> {
    Ok(match kind {
        IntegerIndexKind::Integer32 => IndexValue::Integer32(
            i32::try_from(arc)
                .map_err(|_| IndexDecodeErrorKind::Integer32OutOfDomain { value: arc })?,
        ),
        IntegerIndexKind::Unsigned32 => IndexValue::Unsigned32(arc),
        IntegerIndexKind::Gauge32 => IndexValue::Gauge32(arc),
        IntegerIndexKind::TimeTicks => IndexValue::TimeTicks(arc),
        IntegerIndexKind::Counter32 => IndexValue::Counter32(arc),
    })
}

fn integer_violation(allowed: &IntegerConstraint, value: i64) -> Option<IndexConstraintViolation> {
    if allowed.ranges().check(&value) == ConstraintCheck::Violation {
        Some(IndexConstraintViolation::IntegerRange { value })
    } else if allowed
        .enumeration()
        .is_some_and(|enumeration| enumeration.binary_search(&value).is_err())
    {
        Some(IndexConstraintViolation::IntegerEnumeration { value })
    } else {
        None
    }
}

fn length_violation(allowed: &LengthConstraint, length: usize) -> Option<IndexConstraintViolation> {
    (allowed.check(&length) == ConstraintCheck::Violation)
        .then_some(IndexConstraintViolation::Length { length })
}

#[allow(clippy::too_many_arguments)]
fn handle_decode_violation<'suffix>(
    mode: ConstraintMode,
    position: usize,
    component: &IndexComponentSchema,
    start: usize,
    violation: IndexConstraintViolation,
    violations: &mut Vec<ReportedIndexViolation>,
    values: &[IndexValue],
    ranges: &[Range<usize>],
    suffix: &'suffix [u32],
) -> Result<(), IndexDecodeError<'suffix>> {
    match mode {
        ConstraintMode::Enforce => Err(decode_error(
            IndexDecodeErrorKind::ConstraintViolation(violation),
            position,
            component,
            start,
            values,
            ranges,
            suffix,
        )),
        ConstraintMode::Report => {
            violations.push(ReportedIndexViolation {
                component_position: position,
                violation,
            });
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn take_value_arcs<'suffix>(
    suffix: &'suffix [u32],
    start: usize,
    length: usize,
    maximum: usize,
    position: usize,
    component: &IndexComponentSchema,
    values: &[IndexValue],
    ranges: &[Range<usize>],
) -> Result<&'suffix [u32], IndexDecodeError<'suffix>> {
    if length > maximum {
        return Err(decode_error(
            IndexDecodeErrorKind::ValueTooLong {
                actual: length,
                maximum,
            },
            position,
            component,
            start,
            values,
            ranges,
            suffix,
        ));
    }
    let available = suffix.len().saturating_sub(start);
    if available < length {
        return Err(decode_error(
            IndexDecodeErrorKind::Truncated {
                needed: length,
                available,
            },
            position,
            component,
            start,
            values,
            ranges,
            suffix,
        ));
    }
    Ok(&suffix[start..start + length])
}

#[allow(clippy::too_many_arguments)]
fn framed_value<'suffix>(
    framing: VariableFraming,
    suffix: &'suffix [u32],
    start: usize,
    maximum: usize,
    position: usize,
    component: &IndexComponentSchema,
    values: &[IndexValue],
    ranges: &[Range<usize>],
) -> Result<(usize, usize), IndexDecodeError<'suffix>> {
    match framing {
        VariableFraming::Fixed(length) => {
            take_value_arcs(
                suffix, start, length, maximum, position, component, values, ranges,
            )?;
            Ok((start, length))
        }
        VariableFraming::LengthPrefixed => {
            let Some(&declared) = suffix.get(start) else {
                return Err(decode_error(
                    IndexDecodeErrorKind::Truncated {
                        needed: 1,
                        available: 0,
                    },
                    position,
                    component,
                    start,
                    values,
                    ranges,
                    suffix,
                ));
            };
            let Ok(length) = usize::try_from(declared) else {
                return Err(decode_error(
                    IndexDecodeErrorKind::LengthPrefixTooLarge { declared, maximum },
                    position,
                    component,
                    start,
                    values,
                    ranges,
                    suffix,
                ));
            };
            if length > maximum {
                return Err(decode_error(
                    IndexDecodeErrorKind::LengthPrefixTooLarge { declared, maximum },
                    position,
                    component,
                    start,
                    values,
                    ranges,
                    suffix,
                ));
            }
            let data_start = start + 1;
            let available = suffix.len().saturating_sub(data_start);
            if available < length {
                return Err(decode_error(
                    IndexDecodeErrorKind::Truncated {
                        needed: length + 1,
                        available: available + 1,
                    },
                    position,
                    component,
                    start,
                    values,
                    ranges,
                    suffix,
                ));
            }
            Ok((data_start, length))
        }
        VariableFraming::Implied => {
            let length = suffix.len().saturating_sub(start);
            if length > maximum {
                return Err(decode_error(
                    IndexDecodeErrorKind::ValueTooLong {
                        actual: length,
                        maximum,
                    },
                    position,
                    component,
                    start,
                    values,
                    ranges,
                    suffix,
                ));
            }
            Ok((start, length))
        }
    }
}

fn invalid_octet(arcs: &[u32]) -> Option<(usize, u32)> {
    arcs.iter()
        .copied()
        .enumerate()
        .find(|(_, arc)| *arc > u32::from(u8::MAX))
}

fn decode_error<'suffix>(
    kind: IndexDecodeErrorKind,
    position: usize,
    component: &IndexComponentSchema,
    start: usize,
    values: &[IndexValue],
    ranges: &[Range<usize>],
    suffix: &'suffix [u32],
) -> IndexDecodeError<'suffix> {
    decode_error_at(
        kind, position, component, start, start, values, ranges, suffix,
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_error_at<'suffix>(
    kind: IndexDecodeErrorKind,
    position: usize,
    component: &IndexComponentSchema,
    offset: usize,
    remaining_start: usize,
    values: &[IndexValue],
    ranges: &[Range<usize>],
    suffix: &'suffix [u32],
) -> IndexDecodeError<'suffix> {
    IndexDecodeError {
        kind,
        component_position: Some(position),
        component_name: Some(component.name().to_string()),
        arc_offset: offset,
        decoded_prefix: make_decoded_prefix(values, ranges, suffix),
        remaining: &suffix[remaining_start..],
    }
}

fn decode_whole_error<'suffix>(
    kind: IndexDecodeErrorKind,
    offset: usize,
    values: &[IndexValue],
    ranges: &[Range<usize>],
    suffix: &'suffix [u32],
) -> IndexDecodeError<'suffix> {
    IndexDecodeError {
        kind,
        component_position: None,
        component_name: None,
        arc_offset: offset,
        decoded_prefix: make_decoded_prefix(values, ranges, suffix),
        remaining: &suffix[offset..],
    }
}

fn make_decoded_prefix<'suffix>(
    values: &[IndexValue],
    ranges: &[Range<usize>],
    suffix: &'suffix [u32],
) -> Box<[DecodedPrefixComponent<'suffix>]> {
    values
        .iter()
        .cloned()
        .zip(ranges.iter().cloned())
        .enumerate()
        .map(|(position, (value, arc_range))| DecodedPrefixComponent {
            position,
            value,
            raw_arcs: &suffix[arc_range.clone()],
            arc_range,
        })
        .collect()
}

fn integer_ref(value: IndexValueRef<'_>) -> Result<i64, IndexEncodeErrorKind> {
    match value {
        IndexValueRef::Integer32(value) if value < 0 => {
            Err(IndexEncodeErrorKind::NegativeInteger32 { value })
        }
        IndexValueRef::Integer32(value) => Ok(i64::from(value)),
        IndexValueRef::Unsigned32(value)
        | IndexValueRef::Gauge32(value)
        | IndexValueRef::TimeTicks(value)
        | IndexValueRef::Counter32(value) => Ok(i64::from(value)),
        _ => unreachable!("value kind checked before integer conversion"),
    }
}

fn validate_integer_encode(
    allowed: &IntegerConstraint,
    value: i64,
    incomplete: IncompleteConstraintMode,
    position: usize,
    component: &IndexComponentSchema,
) -> Result<(), IndexEncodeError> {
    if let Some(violation) = integer_violation(allowed, value) {
        return Err(encode_error(
            IndexEncodeErrorKind::ConstraintViolation(violation),
            position,
            component,
        ));
    }
    if allowed.check(value) == ConstraintCheck::Indeterminate
        && incomplete == IncompleteConstraintMode::Reject
    {
        return Err(encode_error(
            IndexEncodeErrorKind::IndeterminateConstraint,
            position,
            component,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_variable(
    suffix: &mut Vec<u32>,
    arcs: impl IntoIterator<Item = u32>,
    length: usize,
    framing: VariableFraming,
    lengths: &LengthConstraint,
    options: EncodeOptions,
    position: usize,
    component: &IndexComponentSchema,
) -> Result<(), IndexEncodeError> {
    if length > options.max_value_arcs {
        return Err(encode_error(
            IndexEncodeErrorKind::ValueTooLong {
                actual: length,
                maximum: options.max_value_arcs,
            },
            position,
            component,
        ));
    }
    if let VariableFraming::Fixed(expected) = framing
        && length != expected
    {
        return Err(encode_error(
            IndexEncodeErrorKind::FixedLength {
                expected,
                actual: length,
            },
            position,
            component,
        ));
    }
    match lengths.check(&length) {
        ConstraintCheck::Violation => {
            return Err(encode_error(
                IndexEncodeErrorKind::ConstraintViolation(IndexConstraintViolation::Length {
                    length,
                }),
                position,
                component,
            ));
        }
        ConstraintCheck::Indeterminate
            if options.incomplete_constraints == IncompleteConstraintMode::Reject =>
        {
            return Err(encode_error(
                IndexEncodeErrorKind::IndeterminateConstraint,
                position,
                component,
            ));
        }
        ConstraintCheck::Allowed | ConstraintCheck::Indeterminate => {}
    }

    let prefix = usize::from(matches!(framing, VariableFraming::LengthPrefixed));
    let component_length = prefix.checked_add(length).ok_or_else(|| {
        encode_error(
            IndexEncodeErrorKind::ArithmeticOverflow,
            position,
            component,
        )
    })?;
    push_component(
        suffix,
        component_length,
        options.max_suffix_arcs,
        position,
        component,
    )?;
    if prefix != 0 {
        suffix.push(u32::try_from(length).map_err(|_| {
            encode_error(
                IndexEncodeErrorKind::LengthPrefixOverflow { length },
                position,
                component,
            )
        })?);
    }
    suffix.extend(arcs);
    Ok(())
}

fn push_component(
    suffix: &[u32],
    component_length: usize,
    maximum: usize,
    position: usize,
    component: &IndexComponentSchema,
) -> Result<(), IndexEncodeError> {
    let actual = suffix.len().checked_add(component_length).ok_or_else(|| {
        encode_error(
            IndexEncodeErrorKind::ArithmeticOverflow,
            position,
            component,
        )
    })?;
    if actual > maximum {
        return Err(encode_error(
            IndexEncodeErrorKind::SuffixTooLong { actual, maximum },
            position,
            component,
        ));
    }
    Ok(())
}

fn encode_error(
    kind: IndexEncodeErrorKind,
    position: usize,
    component: &IndexComponentSchema,
) -> IndexEncodeError {
    IndexEncodeError {
        kind,
        component_position: Some(position),
        component_name: Some(component.name().to_string()),
    }
}

fn encode_whole_error(kind: IndexEncodeErrorKind) -> IndexEncodeError {
    IndexEncodeError {
        kind,
        component_position: None,
        component_name: None,
    }
}
