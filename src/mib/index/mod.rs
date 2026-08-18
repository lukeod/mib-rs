//! Owned, bidirectional codecs for SNMP table index suffixes.
//!
//! Compile an [`IndexSchema`] while a [`Mib`](crate::Mib) is alive, then use
//! it to decode and encode row indexes without retaining MIB arena handles.

mod codec;
mod constraint;
mod schema;
mod value;

pub use codec::{
    BoundIndexCodec, ConstraintMode, DecodeOptions, DecodedIndexComponent, DecodedIndexComponents,
    DecodedPrefixComponent, DecodedRowIndex, EncodeOptions, IncompleteConstraintMode,
    IndexBindError, IndexConstraintViolation, IndexDecodeError, IndexDecodeErrorKind,
    IndexEncodeError, IndexEncodeErrorKind, IndexSuffix, MAX_INSTANCE_OID_ARCS,
    ReportedIndexViolation,
};
pub use constraint::{ConstraintCheck, InclusiveRange, NormalizedConstraint, PartialRange};
pub use schema::{
    IndexComponentSchema, IndexSchema, IndexSchemaError, IndexSchemaIssue, IndexWireType,
    IntegerConstraint, IntegerIndexKind, LengthConstraint, OctetIndexKind, VariableFraming,
};
pub use value::{IndexValue, IndexValueKind, IndexValueRef};
