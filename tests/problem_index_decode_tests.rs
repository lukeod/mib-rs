mod common;

use common::{corpus_dir, problems_dir};
use mib_rs::source::{chain, dir as dir_source};
use mib_rs::{
    DecodeOptions, EncodeOptions, IndexSchema, IndexSchemaIssue, IndexValue, IndexWireType,
    IntegerIndexKind, Loader, Module, OctetIndexKind, Oid, SourceOrigin, VariableFraming,
};

const MODULE: &str = "PROBLEM-INDEX-DECODE-MIB";

fn load_fixture() -> mib_rs::Mib {
    let source = chain(vec![
        dir_source(problems_dir()).expect("failed to create problems source"),
        dir_source(corpus_dir()).expect("failed to create primary corpus source"),
    ]);
    Loader::new()
        .source(source)
        .modules([MODULE])
        .load()
        .expect("index-decode problem fixture should load")
}

fn assert_codec_case(
    module: Module<'_>,
    row: &str,
    suffix: &[u32],
    expected_values: &[IndexValue],
) -> IndexSchema {
    let schema = IndexSchema::compile(
        module
            .object(row)
            .unwrap_or_else(|| panic!("missing fixture row {row}")),
    )
    .unwrap_or_else(|error| panic!("failed to compile schema for {row}: {error}"));
    let decoded = schema
        .decode_exact(suffix, DecodeOptions::new(suffix.len()))
        .unwrap_or_else(|error| panic!("failed to decode {row} suffix: {error}"));
    assert_eq!(
        decoded.values(),
        expected_values,
        "decoded values for {row}"
    );

    let encoded = schema
        .encode_canonical(
            decoded.values().iter().map(IndexValue::as_ref),
            EncodeOptions::new(suffix.len()),
        )
        .unwrap_or_else(|error| panic!("failed to re-encode {row} values: {error}"));
    assert_eq!(encoded.as_ref(), suffix, "canonical suffix for {row}");
    schema
}

fn assert_schema(
    schema: &IndexSchema,
    components: &[(&str, Option<&[u32]>)],
    minimum: usize,
    maximum: Option<usize>,
) {
    assert_eq!(schema.components().len(), components.len());
    for (component, (expected_name, expected_oid)) in schema.components().iter().zip(components) {
        assert_eq!(component.name(), *expected_name);
        assert_eq!(
            component.object_oid().map(Oid::as_ref),
            *expected_oid,
            "object OID for {expected_name}"
        );
    }
    assert_eq!(schema.minimum_suffix_arcs(), minimum);
    assert_eq!(schema.maximum_suffix_arcs(), maximum);
}

#[test]
fn problem_fixture_loads_and_all_index_cases_compile_and_round_trip() {
    let mib = load_fixture();
    let module = mib.module(MODULE).expect("missing loaded fixture module");
    assert_eq!(
        module.source_origin(),
        Some(&SourceOrigin::file(
            problems_dir().join("PROBLEM-INDEX-DECODE-MIB.mib")
        ))
    );

    let simple = assert_codec_case(module, "simpleEntry", &[42], &[IndexValue::Integer32(42)]);
    assert_schema(
        &simple,
        &[("simpleIndex", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 1, 1, 1]))],
        1,
        Some(1),
    );
    assert!(matches!(
        simple.components()[0].wire_type(),
        IndexWireType::Integer {
            kind: IntegerIndexKind::Integer32,
            ..
        }
    ));

    let ip = assert_codec_case(
        module,
        "ipEntry",
        &[192, 0, 2, 1],
        &[IndexValue::IpAddress([192, 0, 2, 1])],
    );
    assert_schema(
        &ip,
        &[("ipAddr", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 2, 1, 1]))],
        4,
        Some(4),
    );
    assert!(matches!(
        ip.components()[0].wire_type(),
        IndexWireType::IpAddress
    ));

    let fixed = assert_codec_case(
        module,
        "fixedEntry",
        &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        &[IndexValue::OctetString(vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ])],
    );
    assert_schema(
        &fixed,
        &[("fixedAddr", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 3, 1, 1]))],
        6,
        Some(6),
    );
    assert!(matches!(
        fixed.components()[0].wire_type(),
        IndexWireType::Octets {
            kind: OctetIndexKind::OctetString,
            framing: VariableFraming::Fixed(6),
            ..
        }
    ));

    let variable = assert_codec_case(
        module,
        "varEntry",
        &[3, b'e' as u32, b't' as u32, b'h' as u32],
        &[IndexValue::OctetString(b"eth".to_vec())],
    );
    assert_schema(
        &variable,
        &[("varName", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 4, 1, 1]))],
        1,
        Some(256),
    );
    assert!(matches!(
        variable.components()[0].wire_type(),
        IndexWireType::Octets {
            kind: OctetIndexKind::OctetString,
            framing: VariableFraming::LengthPrefixed,
            ..
        }
    ));

    let composite = assert_codec_case(
        module,
        "multiEntry",
        &[3, 192, 168, 1, 1],
        &[
            IndexValue::Integer32(3),
            IndexValue::IpAddress([192, 168, 1, 1]),
        ],
    );
    assert_schema(
        &composite,
        &[
            ("multiSlot", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 5, 1, 1])),
            ("multiAddr", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 5, 1, 2])),
        ],
        5,
        Some(5),
    );
    assert!(matches!(
        composite.components()[0].wire_type(),
        IndexWireType::Integer {
            kind: IntegerIndexKind::Integer32,
            ..
        }
    ));
    assert!(matches!(
        composite.components()[1].wire_type(),
        IndexWireType::IpAddress
    ));

    let implied = assert_codec_case(
        module,
        "impliedEntry",
        &[b'e' as u32, b't' as u32, b'h' as u32],
        &[IndexValue::OctetString(b"eth".to_vec())],
    );
    assert_schema(
        &implied,
        &[("impliedName", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 6, 1, 1]))],
        1,
        Some(64),
    );
    assert!(matches!(
        implied.components()[0].wire_type(),
        IndexWireType::Octets {
            kind: OctetIndexKind::OctetString,
            framing: VariableFraming::Implied,
            ..
        }
    ));

    let oid = assert_codec_case(
        module,
        "oidEntry",
        &[4, 1, 3, 6, 1],
        &[IndexValue::ObjectIdentifier(Oid::from(&[1, 3, 6, 1][..]))],
    );
    assert_schema(
        &oid,
        &[("oidIndex", Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 7, 1, 1]))],
        1,
        None,
    );
    assert!(matches!(
        oid.components()[0].wire_type(),
        IndexWireType::ObjectIdentifier {
            framing: VariableFraming::LengthPrefixed,
            ..
        }
    ));

    let implied_oid = assert_codec_case(
        module,
        "impliedOidEntry",
        &[1, 3, 6, 1],
        &[IndexValue::ObjectIdentifier(Oid::from(&[1, 3, 6, 1][..]))],
    );
    assert_schema(
        &implied_oid,
        &[(
            "impliedOidIndex",
            Some(&[1, 3, 6, 1, 4, 1, 99997, 1, 8, 1, 1]),
        )],
        0,
        None,
    );
    assert!(matches!(
        implied_oid.components()[0].wire_type(),
        IndexWireType::ObjectIdentifier {
            framing: VariableFraming::Implied,
            ..
        }
    ));

    let unresolved_oid =
        assert_codec_case(module, "brokenOidEntry", &[7], &[IndexValue::Integer32(7)]);
    assert_schema(&unresolved_oid, &[("brokenOidIndex", None)], 1, Some(1));
    assert!(matches!(
        unresolved_oid.components()[0].wire_type(),
        IndexWireType::Integer {
            kind: IntegerIndexKind::Integer32,
            ..
        }
    ));
    assert!(unresolved_oid.components()[0].object_oid().is_none());
    assert!(
        unresolved_oid.components()[0]
            .issues()
            .contains(&IndexSchemaIssue::UnresolvedObjectIdentity)
    );
}
