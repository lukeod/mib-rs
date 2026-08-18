use std::sync::Arc;

use mib_rs::types::DiagCode;
use mib_rs::{
    BoundIndexCodec, ConstraintMode, DecodeOptions, EncodeOptions, IncompleteConstraintMode,
    IndexBindError, IndexConstraintViolation, IndexDecodeErrorKind, IndexEncodeErrorKind,
    IndexSchema, IndexSchemaError, IndexSchemaIssue, IndexSuffix, IndexValue, IndexValueKind,
    IndexValueRef, IndexWireType, NormalizedConstraint, Oid, VariableFraming,
};
use proptest::prelude::*;

fn load_index_mib() -> mib_rs::Mib {
    let source = mib_rs::source::memory(
        "INDEX-TEST-MIB",
        include_bytes!("data/index-test-mib.txt").as_slice(),
    );
    mib_rs::Loader::new()
        .source(source)
        .modules(["INDEX-TEST-MIB"])
        .load()
        .expect("INDEX-TEST-MIB should load")
}

fn compile(name: &str) -> IndexSchema {
    let mib = load_index_mib();
    IndexSchema::compile(mib.object(name).unwrap()).unwrap()
}

#[test]
fn schema_and_bound_codec_outlive_mib() {
    let (schema, column_oid) = {
        let mib = load_index_mib();
        let column = mib.object("simpleValue").unwrap();
        (
            Arc::new(IndexSchema::compile(column).unwrap()),
            column.node().unwrap().oid().clone(),
        )
    };
    let codec = BoundIndexCodec::for_object_oid(schema, &column_oid).unwrap();

    let encoded = codec
        .encode_canonical([IndexValueRef::Integer32(42)])
        .unwrap();
    let decoded = codec
        .decode_exact(&encoded, ConstraintMode::Enforce)
        .unwrap();

    assert_eq!(encoded.as_ref(), &[42]);
    assert_eq!(decoded.values(), &[IndexValue::Integer32(42)]);
    assert_eq!(decoded.components().next().unwrap().name(), "simpleIndex");
}

#[test]
fn composite_decode_preserves_absolute_ranges_and_raw_arcs() {
    let schema = compile("multiEntry");
    let suffix = [3, 192, 168, 1, 1];
    let decoded = schema
        .decode_exact(&suffix, DecodeOptions::new(suffix.len()))
        .unwrap();
    let components: Vec<_> = decoded.components().collect();

    assert_eq!(components[0].arc_range(), 0..1);
    assert_eq!(components[0].raw_arcs(), &[3]);
    assert_eq!(components[1].arc_range(), 1..5);
    assert_eq!(components[1].raw_arcs(), &[192, 168, 1, 1]);
    assert_eq!(
        components[1].value(),
        &IndexValue::IpAddress([192, 168, 1, 1])
    );
}

#[test]
fn decode_failures_retain_prefix_and_absolute_offsets() {
    let multi = compile("multiEntry");
    let truncated = multi
        .decode_exact(&[3, 10, 0], DecodeOptions::new(8))
        .unwrap_err();
    assert_eq!(
        truncated.kind(),
        &IndexDecodeErrorKind::Truncated {
            needed: 4,
            available: 2,
        }
    );
    assert_eq!(truncated.component_position(), Some(1));
    assert_eq!(truncated.arc_offset(), 1);
    assert_eq!(truncated.decoded_prefix()[0].raw_arcs(), &[3]);
    assert_eq!(truncated.remaining_arcs(), &[10, 0]);

    let variable = compile("varEntry");
    let invalid = variable
        .decode_exact(&[2, 65, 256], DecodeOptions::new(8))
        .unwrap_err();
    assert_eq!(
        invalid.kind(),
        &IndexDecodeErrorKind::InvalidOctet { value: 256 }
    );
    assert_eq!(invalid.arc_offset(), 2);
    assert_eq!(invalid.remaining_arcs(), &[2, 65, 256]);

    let simple = compile("simpleEntry");
    let trailing = simple
        .decode_exact(&[42, 99], DecodeOptions::new(8))
        .unwrap_err();
    assert_eq!(
        trailing.kind(),
        &IndexDecodeErrorKind::TrailingArcs { count: 1 }
    );
    assert_eq!(trailing.component_position(), None);
    assert_eq!(trailing.decoded_prefix()[0].raw_arcs(), &[42]);
}

#[test]
fn decode_enforces_or_reports_constraints_without_relaxing_structure() {
    let schema = compile("simpleEntry");
    let enforced = schema
        .decode_exact(&[0], DecodeOptions::new(1))
        .unwrap_err();
    assert_eq!(
        enforced.kind(),
        &IndexDecodeErrorKind::ConstraintViolation(IndexConstraintViolation::IntegerRange {
            value: 0,
        })
    );

    let reported = schema
        .decode_exact(
            &[0],
            DecodeOptions::new(1).with_constraint_mode(ConstraintMode::Report),
        )
        .unwrap();
    assert_eq!(reported.values(), &[IndexValue::Integer32(0)]);
    assert_eq!(reported.violations().len(), 1);
    assert_eq!(reported.violations()[0].component_position(), 0);

    let still_structural = schema
        .decode_exact(
            &[],
            DecodeOptions::new(1).with_constraint_mode(ConstraintMode::Report),
        )
        .unwrap_err();
    assert!(matches!(
        still_structural.kind(),
        IndexDecodeErrorKind::Truncated { .. }
    ));
}

#[test]
fn integer32_primitive_domain_and_value_kind_are_precise() {
    let schema = compile("simpleEntry");
    let out_of_domain = schema
        .decode_exact(&[i32::MAX as u32 + 1], DecodeOptions::new(1))
        .unwrap_err();
    assert_eq!(
        out_of_domain.kind(),
        &IndexDecodeErrorKind::Integer32OutOfDomain {
            value: i32::MAX as u32 + 1,
        }
    );

    let negative = schema
        .encode_canonical([IndexValueRef::Integer32(-1)], EncodeOptions::new(1))
        .unwrap_err();
    assert_eq!(
        negative.kind(),
        &IndexEncodeErrorKind::NegativeInteger32 { value: -1 }
    );

    let wrong_kind = schema
        .encode_canonical([IndexValueRef::Unsigned32(1)], EncodeOptions::new(1))
        .unwrap_err();
    assert_eq!(
        wrong_kind.kind(),
        &IndexEncodeErrorKind::WrongValueKind {
            expected: IndexValueKind::Integer32,
            actual: IndexValueKind::Unsigned32,
        }
    );
}

#[test]
fn fixed_prefixed_implied_and_oid_framing_are_canonical() {
    let fixed = compile("fixedEntry");
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let encoded = fixed
        .encode_canonical([IndexValueRef::OctetString(&mac)], EncodeOptions::new(8))
        .unwrap();
    assert_eq!(encoded.as_ref(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    let variable = compile("varEntry");
    let encoded = variable
        .encode_canonical([IndexValueRef::OctetString(b"eth0")], EncodeOptions::new(8))
        .unwrap();
    assert_eq!(encoded.as_ref(), &[4, 101, 116, 104, 48]);

    let implied = compile("impliedEntry");
    let encoded = implied
        .encode_canonical([IndexValueRef::OctetString(b"test")], EncodeOptions::new(8))
        .unwrap();
    assert_eq!(encoded.as_ref(), &[116, 101, 115, 116]);

    let oid = compile("oidEntry");
    let oid_value = [1, 256, u32::MAX];
    let encoded = oid
        .encode_canonical(
            [IndexValueRef::ObjectIdentifier(&oid_value)],
            EncodeOptions::new(8),
        )
        .unwrap();
    assert_eq!(encoded.as_ref(), &[3, 1, 256, u32::MAX]);
    let decoded = oid.decode_exact(&encoded, DecodeOptions::new(8)).unwrap();
    assert_eq!(
        decoded.values(),
        &[IndexValue::ObjectIdentifier(Oid::from(
            oid_value.as_slice()
        ))]
    );
}

#[test]
fn complete_instance_oid_boundaries_are_enforced() {
    let schema = Arc::new(compile("simpleEntry"));
    let base_127 = Oid::from(vec![1; 127]);
    let codec = BoundIndexCodec::for_object_oid(schema.clone(), &base_127).unwrap();
    assert_eq!(codec.max_suffix_arcs(), 1);
    assert!(
        codec
            .encode_canonical([IndexValueRef::Integer32(1)])
            .is_ok()
    );
    assert!(matches!(
        codec
            .decode_exact(&[1, 2], ConstraintMode::Enforce)
            .unwrap_err()
            .kind(),
        IndexDecodeErrorKind::SuffixTooLong {
            actual: 2,
            maximum: 1
        }
    ));

    let base_128 = Oid::from(vec![1; 128]);
    assert_eq!(
        BoundIndexCodec::for_object_oid(schema.clone(), &base_128).unwrap_err(),
        IndexBindError::MinimumSuffixTooLong {
            minimum: 1,
            maximum: 0,
        }
    );

    let base_129 = Oid::from(vec![1; 129]);
    assert_eq!(
        BoundIndexCodec::for_object_oid(schema, &base_129).unwrap_err(),
        IndexBindError::ObjectOidTooLong {
            actual: 129,
            maximum: 128,
        }
    );
}

#[test]
fn arity_and_operation_budgets_fail_atomically() {
    let schema = compile("multiEntry");
    assert!(matches!(
        schema
            .encode_canonical([IndexValueRef::Integer32(3)], EncodeOptions::new(8))
            .unwrap_err()
            .kind(),
        IndexEncodeErrorKind::TooFewValues {
            expected: 2,
            actual: 1
        }
    ));
    assert!(matches!(
        schema
            .encode_canonical(
                [
                    IndexValueRef::Integer32(3),
                    IndexValueRef::IpAddress([1, 2, 3, 4]),
                    IndexValueRef::Integer32(9),
                ],
                EncodeOptions::new(8),
            )
            .unwrap_err()
            .kind(),
        IndexEncodeErrorKind::TooManyValues { expected: 2 }
    ));

    let variable = compile("varEntry");
    let hostile = variable
        .decode_exact(&[u32::MAX], DecodeOptions::new(8).with_max_value_arcs(4))
        .unwrap_err();
    assert_eq!(
        hostile.kind(),
        &IndexDecodeErrorKind::LengthPrefixTooLarge {
            declared: u32::MAX,
            maximum: 4,
        }
    );
}

#[test]
fn compilation_preserves_precise_integer_kinds_and_counter_issue() {
    let schema = compile("typedEntry");
    let expected = [
        IndexValueKind::Unsigned32,
        IndexValueKind::Gauge32,
        IndexValueKind::TimeTicks,
        IndexValueKind::Counter32,
    ];
    assert_eq!(
        schema
            .components()
            .iter()
            .map(|component| component.value_kind())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(
        schema.components()[3]
            .issues()
            .contains(&IndexSchemaIssue::Counter32Compatibility)
    );

    let values = [
        IndexValueRef::Unsigned32(u32::MAX),
        IndexValueRef::Gauge32(u32::MAX),
        IndexValueRef::TimeTicks(u32::MAX),
        IndexValueRef::Counter32(u32::MAX),
    ];
    let encoded = schema
        .encode_canonical(values, EncodeOptions::new(4))
        .unwrap();
    assert_eq!(encoded.as_ref(), &[u32::MAX; 4]);
    assert_eq!(
        schema
            .decode_exact(&encoded, DecodeOptions::new(4))
            .unwrap()
            .values(),
        &[
            IndexValue::Unsigned32(u32::MAX),
            IndexValue::Gauge32(u32::MAX),
            IndexValue::TimeTicks(u32::MAX),
            IndexValue::Counter32(u32::MAX),
        ]
    );
}

#[test]
fn enumeration_is_an_effective_accepted_set() {
    let schema = compile("enumEntry");
    let IndexWireType::Integer { allowed, .. } = schema.components()[0].wire_type() else {
        panic!("expected integer component");
    };
    assert_eq!(allowed.enumeration(), Some([1, 3].as_slice()));
    assert!(
        schema.components()[0]
            .issues()
            .contains(&IndexSchemaIssue::UnrepresentableIntegerDomainExcluded)
    );
    assert!(
        schema
            .encode_canonical([IndexValueRef::Integer32(3)], EncodeOptions::new(1))
            .is_ok()
    );
    assert!(matches!(
        schema
            .encode_canonical([IndexValueRef::Integer32(2)], EncodeOptions::new(1))
            .unwrap_err()
            .kind(),
        IndexEncodeErrorKind::ConstraintViolation(IndexConstraintViolation::IntegerEnumeration {
            value: 2
        })
    ));
    let reported = schema
        .decode_exact(
            &[2],
            DecodeOptions::new(1).with_constraint_mode(ConstraintMode::Report),
        )
        .unwrap();
    assert_eq!(reported.violations().len(), 1);
}

#[test]
fn disjoint_sizes_and_zero_width_framing_are_retained() {
    let disjoint = compile("disjointEntry");
    let IndexWireType::Octets {
        framing, lengths, ..
    } = disjoint.components()[0].wire_type()
    else {
        panic!("expected octet component");
    };
    assert_eq!(*framing, VariableFraming::LengthPrefixed);
    let NormalizedConstraint::Known(ranges) = lengths else {
        panic!("expected known lengths");
    };
    assert_eq!(ranges.len(), 2);
    assert_eq!((*ranges[0].start(), *ranges[0].end()), (8, 8));
    assert_eq!((*ranges[1].start(), *ranges[1].end()), (11, 11));
    assert!(
        disjoint
            .encode_canonical(
                [IndexValueRef::OctetString(&[0; 8])],
                EncodeOptions::new(16),
            )
            .is_ok()
    );
    assert!(
        disjoint
            .encode_canonical(
                [IndexValueRef::OctetString(&[0; 11])],
                EncodeOptions::new(16),
            )
            .is_ok()
    );
    assert!(matches!(
        disjoint
            .encode_canonical(
                [IndexValueRef::OctetString(&[0; 9])],
                EncodeOptions::new(16),
            )
            .unwrap_err()
            .kind(),
        IndexEncodeErrorKind::ConstraintViolation(IndexConstraintViolation::Length { length: 9 })
    ));

    let zero = compile("zeroEntry");
    assert_eq!(zero.minimum_suffix_arcs(), 0);
    assert_eq!(zero.maximum_suffix_arcs(), Some(0));
    assert!(matches!(
        zero.components()[0].wire_type(),
        IndexWireType::Octets {
            framing: VariableFraming::Fixed(0),
            ..
        }
    ));
    assert!(
        zero.components()[0]
            .issues()
            .contains(&IndexSchemaIssue::ZeroWidthComponent)
    );
    assert!(zero.issues().contains(&IndexSchemaIssue::ZeroWidthIndex));
    let encoded = zero
        .encode_canonical([IndexValueRef::OctetString(&[])], EncodeOptions::new(0))
        .unwrap();
    assert!(encoded.is_empty());
    assert_eq!(
        zero.decode_exact(&[], DecodeOptions::new(0))
            .unwrap()
            .values(),
        &[IndexValue::OctetString(Vec::new())]
    );
    let bound = BoundIndexCodec::for_object_oid(
        Arc::new(zero.clone()),
        &Oid::from(vec![1; mib_rs::MAX_INSTANCE_OID_ARCS]),
    )
    .unwrap();
    assert_eq!(bound.max_suffix_arcs(), 0);
    assert!(
        bound
            .encode_canonical([IndexValueRef::OctetString(&[])])
            .is_ok()
    );
    assert!(matches!(
        zero.decode_exact(&[1], DecodeOptions::new(1))
            .unwrap_err()
            .kind(),
        IndexDecodeErrorKind::TrailingArcs { count: 1 }
    ));

    let composite = compile("zeroCompositeEntry");
    assert_eq!(composite.minimum_suffix_arcs(), 1);
    assert_eq!(composite.maximum_suffix_arcs(), Some(1));
    assert!(
        !composite
            .issues()
            .contains(&IndexSchemaIssue::ZeroWidthIndex)
    );
    assert!(
        composite.components()[0]
            .issues()
            .contains(&IndexSchemaIssue::ZeroWidthComponent)
    );
    let encoded = composite
        .encode_canonical(
            [IndexValueRef::OctetString(&[]), IndexValueRef::Integer32(7)],
            EncodeOptions::new(1),
        )
        .unwrap();
    assert_eq!(encoded.as_ref(), &[7]);
    let decoded = composite
        .decode_exact(&encoded, DecodeOptions::new(1))
        .unwrap();
    let components: Vec<_> = decoded.components().collect();
    assert_eq!(components[0].arc_range(), 0..0);
    assert_eq!(components[1].arc_range(), 0..1);
}

#[test]
fn incomplete_constraints_distinguish_known_invalid_and_indeterminate_values() {
    let schema = compile("incompleteEntry");
    let IndexWireType::Octets { lengths, .. } = schema.components()[0].wire_type() else {
        panic!("expected octet component");
    };
    assert!(matches!(lengths, NormalizedConstraint::Incomplete { .. }));
    assert!(
        schema.components()[0]
            .issues()
            .contains(&IndexSchemaIssue::IncompleteLengthConstraint)
    );

    let strict = schema
        .encode_canonical(
            [IndexValueRef::OctetString(&[0; 5])],
            EncodeOptions::new(16),
        )
        .unwrap_err();
    assert_eq!(
        strict.kind(),
        &IndexEncodeErrorKind::IndeterminateConstraint
    );
    assert!(
        schema
            .encode_canonical(
                [IndexValueRef::OctetString(&[0; 5])],
                EncodeOptions::new(16).with_incomplete_constraints(IncompleteConstraintMode::Allow),
            )
            .is_ok()
    );

    let invalid_suffix = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        schema
            .decode_exact(&invalid_suffix, DecodeOptions::new(16))
            .unwrap_err()
            .kind(),
        IndexDecodeErrorKind::ConstraintViolation(IndexConstraintViolation::Length { length: 9 })
    ));
}

#[test]
fn compilation_handles_columns_augments_bare_types_and_rejects_counter64() {
    let mib = load_index_mib();
    let row = IndexSchema::compile(mib.object("simpleEntry").unwrap()).unwrap();
    let column = IndexSchema::compile(mib.object("simpleValue").unwrap()).unwrap();
    let augment = IndexSchema::compile(mib.object("augmentEntry").unwrap()).unwrap();
    assert_eq!(row, column);
    assert_eq!(row, augment);

    let bare = IndexSchema::compile(mib.object("bareEntry").unwrap()).unwrap();
    assert_eq!(bare.components()[0].name(), "OCTET STRING");
    assert_eq!(bare.components()[0].object_oid(), None);
    assert!(matches!(
        bare.components()[0].wire_type(),
        IndexWireType::Octets {
            framing: VariableFraming::LengthPrefixed,
            ..
        }
    ));

    assert!(matches!(
        IndexSchema::compile(mib.object("counter64Entry").unwrap()).unwrap_err(),
        IndexSchemaError::UnsupportedBaseType { .. }
    ));
    assert!(matches!(
        IndexSchema::compile(mib.object("simpleTable").unwrap()).unwrap_err(),
        IndexSchemaError::NotRowOrColumn { .. }
    ));

    assert_eq!(
        IndexSchema::compile(mib.object("unresolvedEntry").unwrap()).unwrap_err(),
        IndexSchemaError::UnresolvedType {
            position: 0,
            component: "missingIndex".to_string(),
        }
    );
    assert!(matches!(
        IndexSchema::compile(mib.object("notObjectEntry").unwrap()).unwrap_err(),
        IndexSchemaError::UnresolvedType {
            position: 0,
            component
        } if component == "plainIndexNode"
    ));
    assert!(
        mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::IndexNotObject)
    );
    assert!(
        mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::AugmentsNotObject)
    );

    assert!(matches!(
        IndexSchema::compile(mib.object("badImpliedEntry").unwrap()).unwrap_err(),
        IndexSchemaError::ImpliedNotLast { position: 0, .. }
    ));
    assert!(matches!(
        IndexSchema::compile(mib.object("badIntegerImpliedEntry").unwrap()).unwrap_err(),
        IndexSchemaError::ImpliedNonVariable { position: 0, .. }
    ));
    assert!(matches!(
        IndexSchema::compile(mib.object("badFixedImpliedEntry").unwrap()).unwrap_err(),
        IndexSchemaError::ImpliedNonVariable { position: 0, .. }
    ));

    let broken_oid_object = mib.object("brokenOidIndex").unwrap();
    assert!(broken_oid_object.node().is_none());
    assert_eq!(
        broken_oid_object.ty().unwrap().effective_base(),
        mib_rs::BaseType::Integer32
    );

    let broken_oid = IndexSchema::compile(mib.object("brokenOidEntry").unwrap()).unwrap();
    assert_eq!(broken_oid.components()[0].name(), "brokenOidIndex");
    assert_eq!(broken_oid.components()[0].object_oid(), None);
    assert!(
        broken_oid.components()[0]
            .issues()
            .contains(&IndexSchemaIssue::UnresolvedObjectIdentity)
    );
    assert_eq!(
        broken_oid.components()[0].value_kind(),
        IndexValueKind::Integer32
    );
    let encoded = broken_oid
        .encode_canonical([IndexValueRef::Integer32(7)], EncodeOptions::new(1))
        .unwrap();
    assert_eq!(encoded.as_ref(), &[7]);
    assert!(matches!(
        broken_oid
            .encode_canonical([IndexValueRef::Integer32(11)], EncodeOptions::new(1))
            .unwrap_err()
            .kind(),
        IndexEncodeErrorKind::ConstraintViolation(IndexConstraintViolation::IntegerRange {
            value: 11
        })
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn variable_octets_encode_decode_inverse(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let schema = compile("varEntry");
        let encoded = schema
            .encode_canonical([IndexValueRef::OctetString(&bytes)], EncodeOptions::new(128))
            .unwrap();
        let decoded = schema
            .decode_exact(&encoded, DecodeOptions::new(128))
            .unwrap();
        prop_assert_eq!(decoded.values(), &[IndexValue::OctetString(bytes)]);
        let reencoded = schema
            .encode_canonical(decoded.values().iter().map(IndexValue::as_ref), EncodeOptions::new(128))
            .unwrap();
        prop_assert_eq!(reencoded, encoded);
    }

    #[test]
    fn oid_encode_decode_inverse(arcs in prop::collection::vec(any::<u32>(), 0..64)) {
        let schema = compile("oidEntry");
        let encoded = schema
            .encode_canonical([IndexValueRef::ObjectIdentifier(&arcs)], EncodeOptions::new(128))
            .unwrap();
        let decoded = schema
            .decode_exact(&encoded, DecodeOptions::new(128))
            .unwrap();
        prop_assert_eq!(decoded.values(), &[IndexValue::ObjectIdentifier(Oid::from(arcs))]);
    }
}

#[test]
fn index_suffix_converts_to_oid_without_claiming_complete_oid_semantics() {
    let schema = compile("simpleEntry");
    let suffix: IndexSuffix = schema
        .encode_canonical([IndexValueRef::Integer32(7)], EncodeOptions::new(1))
        .unwrap();
    let oid = Oid::from(suffix);
    assert_eq!(oid.as_ref(), &[7]);
}
