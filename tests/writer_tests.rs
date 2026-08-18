use std::io::{self, Write};

use mib_rs::writer::{self, Error, Options};
use mib_rs::{
    Access, BaseType, DiagnosticConfig, Kind, Loader, ModuleIdentityKind, Status, source,
};
use pretty_assertions::assert_eq;

fn identity_mib() -> mib_rs::Mib {
    Loader::new()
        .source(source::memory(
            "IDENTITY-ONLY-MIB",
            include_bytes!("data/writer-identity-input.mib").as_slice(),
        ))
        .modules(["IDENTITY-ONLY-MIB"])
        .load()
        .expect("identity-only fixture should load")
}

fn types_objects_mib() -> mib_rs::Mib {
    Loader::new()
        .source(source::memory(
            "WRITER-OBJECTS-MIB",
            include_bytes!("data/writer-types-objects-input.mib").as_slice(),
        ))
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(["WRITER-OBJECTS-MIB"])
        .load()
        .expect("types and objects fixture should load")
}

#[derive(Debug, PartialEq, Eq)]
struct TypeSemantics {
    name: String,
    parent: Option<String>,
    base: BaseType,
    status: Status,
    hint: String,
    description: String,
    reference: String,
    ranges: Vec<String>,
    sizes: Vec<String>,
    effective_ranges: Vec<String>,
    effective_sizes: Vec<String>,
    enums: Vec<(String, i64)>,
    bits: Vec<(String, i64)>,
}

#[derive(Debug, PartialEq, Eq)]
struct ObjectSemantics {
    name: String,
    oid: String,
    kind: Kind,
    type_name: Option<String>,
    base: Option<BaseType>,
    access: Access,
    status: Status,
    units: String,
    description: String,
    reference: String,
    ranges: Vec<String>,
    sizes: Vec<String>,
    effective_ranges: Vec<String>,
    effective_sizes: Vec<String>,
    enums: Vec<(String, i64)>,
    bits: Vec<(String, i64)>,
    declared_enums: Vec<(String, i64)>,
    declared_bits: Vec<(String, i64)>,
    indexes: Vec<(String, bool)>,
    augments: Option<String>,
    sequence_type_name: String,
    declared_table_name: String,
    declared_row_name: String,
    declared_column_names: Vec<String>,
    declared_oid_parent_name: String,
    default: Option<String>,
}

fn named_values(values: &[mib_rs::mib::NamedValue]) -> Vec<(String, i64)> {
    values
        .iter()
        .map(|value| (value.label.clone(), value.value))
        .collect()
}

fn canonical_type_semantics(name: &str) -> String {
    match name {
        "INTEGER" => "Integer32",
        "Counter" => "Counter32",
        "Gauge" => "Gauge32",
        "NetworkAddress" => "IpAddress",
        name => name,
    }
    .to_owned()
}

fn default_semantics(default: &mib_rs::mib::DefVal) -> String {
    use mib_rs::mib::DefValValue;

    match default.value() {
        DefValValue::None => "unset".to_owned(),
        DefValValue::Int(value) => format!("int:{value}"),
        DefValValue::Uint(value) => format!("uint:{value}"),
        DefValValue::String(value) => format!("string:{value:?}"),
        DefValValue::Bytes(value) => format!("bytes:{value:02x?}"),
        DefValValue::Enum(value) => format!("enum:{value}"),
        DefValValue::Bits(value) => format!("bits:{}", value.join(",")),
        DefValValue::Oid(value) => format!("oid:{value}"),
    }
}

fn module_semantics(
    mib: &mib_rs::Mib,
    module_name: &str,
) -> (Vec<TypeSemantics>, Vec<ObjectSemantics>) {
    let module = mib.module(module_name).expect("module should exist");
    let mut types = module
        .types()
        .map(|typ| TypeSemantics {
            name: typ.name().to_owned(),
            parent: typ
                .parent()
                .map(|parent| canonical_type_semantics(parent.name())),
            base: typ.effective_base(),
            status: typ.status(),
            hint: typ.display_hint().to_owned(),
            description: typ.description().to_owned(),
            reference: typ.reference().to_owned(),
            ranges: typ.ranges().iter().map(ToString::to_string).collect(),
            sizes: typ.sizes().iter().map(ToString::to_string).collect(),
            effective_ranges: typ
                .effective_ranges()
                .iter()
                .map(ToString::to_string)
                .collect(),
            effective_sizes: typ
                .effective_sizes()
                .iter()
                .map(ToString::to_string)
                .collect(),
            enums: named_values(typ.enums()),
            bits: named_values(typ.bits()),
        })
        .collect::<Vec<_>>();
    types.sort_by(|left, right| left.name.cmp(&right.name));

    let mut objects = module
        .objects()
        .map(|object| ObjectSemantics {
            name: object.name().to_owned(),
            oid: object.node().unwrap().oid().to_string(),
            kind: object.declared_kind(),
            type_name: object.ty().map(|typ| canonical_type_semantics(typ.name())),
            base: object.ty().map(|typ| typ.effective_base()),
            access: if object.access() == Access::WriteOnly {
                Access::ReadWrite
            } else {
                object.access()
            },
            status: match object.status() {
                Status::Mandatory => Status::Current,
                Status::Optional => Status::Deprecated,
                status => status,
            },
            units: object.units().to_owned(),
            description: object.description().to_owned(),
            reference: object.reference().to_owned(),
            ranges: object
                .declared_ranges()
                .iter()
                .map(ToString::to_string)
                .collect(),
            sizes: object
                .declared_sizes()
                .iter()
                .map(ToString::to_string)
                .collect(),
            effective_ranges: object
                .effective_ranges()
                .iter()
                .map(ToString::to_string)
                .collect(),
            effective_sizes: object
                .effective_sizes()
                .iter()
                .map(ToString::to_string)
                .collect(),
            enums: named_values(object.effective_enums()),
            bits: named_values(object.effective_bits()),
            declared_enums: named_values(object.declared_enums()),
            declared_bits: named_values(object.declared_bits()),
            indexes: object
                .index()
                .map(|index| (index.name().to_owned(), index.implied()))
                .collect(),
            augments: object.augments().map(|augment| augment.name().to_owned()),
            sequence_type_name: object.sequence_type_name().to_owned(),
            declared_table_name: object.declared_table_name().to_owned(),
            declared_row_name: object.declared_row_name().to_owned(),
            declared_column_names: object.declared_column_names().to_vec(),
            declared_oid_parent_name: object.declared_oid_parent_name().to_owned(),
            default: object.default_value().map(default_semantics),
        })
        .collect::<Vec<_>>();
    objects.sort_by(|left, right| left.name.cmp(&right.name));
    (types, objects)
}

#[test]
fn types_objects_output_reparses_with_equivalent_semantics() {
    let mib = types_objects_mib();
    let module = mib.module("WRITER-OBJECTS-MIB").unwrap();
    assert!(matches!(
        module
            .object("writerUint")
            .unwrap()
            .default_value()
            .unwrap()
            .value(),
        mib_rs::mib::DefValValue::Uint(u64::MAX)
    ));
    assert!(matches!(
        module.object("writerHex").unwrap().default_value().unwrap().value(),
        mib_rs::mib::DefValValue::Bytes(bytes) if bytes == &[0xff, 0x00]
    ));
    assert!(matches!(
        module.object("writerBinary").unwrap().default_value().unwrap().value(),
        mib_rs::mib::DefValValue::Bytes(bytes) if bytes == &[0xa5]
    ));
    let mut first = Vec::new();
    writer::write(&mut first, &mib, "WRITER-OBJECTS-MIB").unwrap();
    let mut second = Vec::new();
    writer::write(&mut second, &mib, "WRITER-OBJECTS-MIB").unwrap();
    assert_eq!(first, second);

    let output = String::from_utf8(first).unwrap();
    assert_eq!(output, include_str!("data/writer-types-objects-golden.mib"));
    let reparsed = load_inline(&[("WRITER-OBJECTS-MIB", &output)], &["WRITER-OBJECTS-MIB"]);
    assert_eq!(
        module_semantics(&mib, "WRITER-OBJECTS-MIB"),
        module_semantics(&reparsed, "WRITER-OBJECTS-MIB")
    );

    let mut rewritten = Vec::new();
    writer::write(&mut rewritten, &reparsed, "WRITER-OBJECTS-MIB").unwrap();
    assert_eq!(rewritten, output.as_bytes());
}

#[test]
fn smiv1_types_and_objects_normalize_to_smiv2() {
    let source = r#"WRITER-V1-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises, Gauge, NetworkAddress FROM RFC1155-SMI
        Counter FROM RFC1065-SMI;
writerV1 OBJECT IDENTIFIER ::= { enterprises 424244 }
LegacyMode ::= INTEGER { disabled(0), enabled(1) }
legacyWritable OBJECT-TYPE
    SYNTAX LegacyMode
    ACCESS write-only
    STATUS mandatory
    DESCRIPTION "Legacy writable object."
    DEFVAL { enabled }
    ::= { writerV1 1 }
legacyOptional OBJECT-TYPE
    SYNTAX OCTET STRING (SIZE (0..16))
    ACCESS read-only
    STATUS optional
    DESCRIPTION "Legacy optional object."
    ::= { writerV1 2 }
legacyCounter OBJECT-TYPE
    SYNTAX Counter
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "Legacy counter."
    ::= { writerV1 3 }
legacyGauge OBJECT-TYPE
    SYNTAX Gauge
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "Legacy gauge."
    ::= { writerV1 4 }
legacyAddress OBJECT-TYPE
    SYNTAX NetworkAddress
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "Legacy address."
    ::= { writerV1 5 }
END
"#;
    let mib = load_inline(&[("WRITER-V1-MIB", source)], &["WRITER-V1-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "WRITER-V1-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("LegacyMode ::= TEXTUAL-CONVENTION"));
    assert!(output.contains("MAX-ACCESS read-write"));
    assert!(output.contains("STATUS current"));
    assert!(output.contains("STATUS deprecated"));
    assert!(output.contains("SYNTAX Counter32"));
    assert!(output.contains("SYNTAX Gauge32"));
    assert!(output.contains("SYNTAX IpAddress"));
    assert!(output.contains("Counter32, Gauge32, IpAddress"));
    assert!(!output.contains("ACCESS write-only"));
    assert!(!output.contains("STATUS mandatory"));
    assert!(!output.contains("STATUS optional"));

    let reparsed = load_inline(&[("WRITER-V1-MIB", &output)], &["WRITER-V1-MIB"]);
    assert_eq!(
        module_semantics(&mib, "WRITER-V1-MIB"),
        module_semantics(&reparsed, "WRITER-V1-MIB")
    );
}

#[test]
fn type_object_options_control_descriptions_and_sequences() {
    let mib = types_objects_mib();
    let mut output = Vec::new();
    writer::write_with_options(
        &mut output,
        &mib,
        "WRITER-OBJECTS-MIB",
        Options::default()
            .with_descriptions(false)
            .with_reconstructed_sequences(false),
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(!output.contains("DESCRIPTION"));
    assert!(!output.contains("::= SEQUENCE {"));
    assert!(output.contains("SYNTAX SEQUENCE OF SpecialEntry"));
    assert!(output.contains("writerScalar OBJECT-TYPE"));
}

#[test]
fn unresolved_object_type_is_rejected_before_writing() {
    let source = r#"UNSUPPORTED-WRITER-MIB DEFINITIONS ::= BEGIN
root OBJECT IDENTIFIER ::= { iso 424245 }
broken OBJECT-TYPE
    SYNTAX MissingType
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Unresolved type."
    ::= { root 1 }
END
"#;
    let mib = load_inline(
        &[("UNSUPPORTED-WRITER-MIB", source)],
        &["UNSUPPORTED-WRITER-MIB"],
    );
    let mut output = b"preloaded".to_vec();
    let error = writer::write(&mut output, &mib, "UNSUPPORTED-WRITER-MIB")
        .expect_err("unresolved syntax must not be guessed");

    assert!(matches!(
        error,
        Error::UnsupportedDefinition { definition, reason }
            if definition == "broken" && reason == "has no resolved type"
    ));
    assert_eq!(output, b"preloaded");
}

#[test]
fn unresolved_defval_is_rejected_before_writing() {
    let source = r#"UNSUPPORTED-DEFVAL-MIB DEFINITIONS ::= BEGIN
root OBJECT IDENTIFIER ::= { iso 424246 }
brokenDefault OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Unresolved default."
    DEFVAL { missingOid }
    ::= { root 1 }
END
"#;
    let mib = load_inline(
        &[("UNSUPPORTED-DEFVAL-MIB", source)],
        &["UNSUPPORTED-DEFVAL-MIB"],
    );
    let mut output = Vec::new();
    let error = writer::write(&mut output, &mib, "UNSUPPORTED-DEFVAL-MIB")
        .expect_err("unresolved DEFVAL must not be omitted");

    assert!(matches!(
        error,
        Error::UnsupportedDefinition { definition, reason }
            if definition == "brokenDefault" && reason == "contains an unresolved OID DEFVAL"
    ));
    assert!(output.is_empty());
}

#[test]
fn exact_external_oid_default_is_imported_and_compound_value_is_rejected() {
    let anchor_source = r#"OID-ANCHOR-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, enterprises FROM SNMPv2-SMI;
oidAnchorMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Anchor" CONTACT-INFO "Anchor" DESCRIPTION "Anchor." ::= { enterprises 424251 }
externalAnchor OBJECT IDENTIFIER ::= { oidAnchorMib 1 }
END
"#;
    let exact_source = r#"OID-EXACT-DEFAULT-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE FROM SNMPv2-SMI externalAnchor FROM OID-ANCHOR-MIB;
exactDefault OBJECT-TYPE SYNTAX OBJECT IDENTIFIER MAX-ACCESS read-only STATUS current DESCRIPTION "Exact." DEFVAL { externalAnchor } ::= { externalAnchor 1 }
END
"#;
    let compound_source = r#"OID-COMPOUND-DEFAULT-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE FROM SNMPv2-SMI externalAnchor FROM OID-ANCHOR-MIB;
compoundDefault OBJECT-TYPE SYNTAX OBJECT IDENTIFIER MAX-ACCESS read-only STATUS current DESCRIPTION "Compound." DEFVAL { { externalAnchor 7 } } ::= { externalAnchor 2 }
END
"#;
    let mib = load_inline(
        &[
            ("OID-ANCHOR-MIB", anchor_source),
            ("OID-EXACT-DEFAULT-MIB", exact_source),
            ("OID-COMPOUND-DEFAULT-MIB", compound_source),
        ],
        &[
            "OID-ANCHOR-MIB",
            "OID-EXACT-DEFAULT-MIB",
            "OID-COMPOUND-DEFAULT-MIB",
        ],
    );

    let mut exact = Vec::new();
    writer::write(&mut exact, &mib, "OID-EXACT-DEFAULT-MIB").unwrap();
    let exact = String::from_utf8(exact).unwrap();
    assert!(exact.contains("externalAnchor\n        FROM OID-ANCHOR-MIB"));
    assert!(exact.contains("DEFVAL { externalAnchor }"));
    let reparsed = load_inline(
        &[
            ("OID-ANCHOR-MIB", anchor_source),
            ("OID-EXACT-DEFAULT-MIB", &exact),
        ],
        &["OID-ANCHOR-MIB", "OID-EXACT-DEFAULT-MIB"],
    );
    assert_eq!(
        module_semantics(&mib, "OID-EXACT-DEFAULT-MIB"),
        module_semantics(&reparsed, "OID-EXACT-DEFAULT-MIB")
    );

    let mut compound = b"preloaded".to_vec();
    let error = writer::write(&mut compound, &mib, "OID-COMPOUND-DEFAULT-MIB")
        .expect_err("compound OID default lacks an exact anchor");
    assert!(matches!(
        error,
        Error::UnsupportedDefinition { definition, reason }
            if definition == "compoundDefault"
                && reason == "contains an OID DEFVAL without a symbolic anchor"
    ));
    assert_eq!(compound, b"preloaded");
}

#[test]
fn zero_column_sequence_is_emitted_and_sequence_omission_is_explicit() {
    let source = r#"EMPTY-SEQUENCE-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
root OBJECT IDENTIFIER ::= { enterprises 424252 }
baseTable OBJECT-TYPE SYNTAX SEQUENCE OF BaseEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Base table." ::= { root 1 }
baseEntry OBJECT-TYPE SYNTAX BaseEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Base row." INDEX { baseIndex } ::= { baseTable 1 }
baseIndex OBJECT-TYPE SYNTAX Integer32 (1..10) MAX-ACCESS not-accessible STATUS current DESCRIPTION "Index." ::= { baseEntry 1 }
emptyTable OBJECT-TYPE SYNTAX SEQUENCE OF EmptyEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Table." ::= { root 2 }
emptyEntry OBJECT-TYPE SYNTAX EmptyEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Row." AUGMENTS { baseEntry } ::= { emptyTable 1 }
BaseEntry ::= SEQUENCE { baseIndex Integer32 }
EmptyEntry ::= SEQUENCE { }
END
"#;
    let mib = load_inline(&[("EMPTY-SEQUENCE-MIB", source)], &["EMPTY-SEQUENCE-MIB"]);

    let mut output = Vec::new();
    writer::write(&mut output, &mib, "EMPTY-SEQUENCE-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("EmptyEntry ::= SEQUENCE {\n}"));
    let reparsed = load_inline(&[("EMPTY-SEQUENCE-MIB", &output)], &["EMPTY-SEQUENCE-MIB"]);
    assert_eq!(
        module_semantics(&mib, "EMPTY-SEQUENCE-MIB"),
        module_semantics(&reparsed, "EMPTY-SEQUENCE-MIB")
    );

    let mut omitted = Vec::new();
    writer::write_with_options(
        &mut omitted,
        &mib,
        "EMPTY-SEQUENCE-MIB",
        Options::default().with_reconstructed_sequences(false),
    )
    .unwrap();
    let omitted = String::from_utf8(omitted).unwrap();
    assert!(!omitted.contains("::= SEQUENCE {"));
    assert!(omitted.contains("SYNTAX SEQUENCE OF EmptyEntry"));
    let reparsed_omitted =
        load_inline(&[("EMPTY-SEQUENCE-MIB", &omitted)], &["EMPTY-SEQUENCE-MIB"]);
    assert_eq!(
        module_semantics(&mib, "EMPTY-SEQUENCE-MIB"),
        module_semantics(&reparsed_omitted, "EMPTY-SEQUENCE-MIB")
    );
}

#[test]
fn malformed_index_augment_and_byte_default_are_rejected_before_writing() {
    let cases = [
        (
            "UNSUPPORTED-INDEX-MIB",
            r#"UNSUPPORTED-INDEX-MIB DEFINITIONS ::= BEGIN
root OBJECT IDENTIFIER ::= { iso 424247 }
badTable OBJECT-TYPE SYNTAX SEQUENCE OF BadEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Table." ::= { root 1 }
badEntry OBJECT-TYPE SYNTAX BadEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Row." INDEX { missingIndex } ::= { badTable 1 }
BadEntry ::= SEQUENCE { }
END
"#,
            "badEntry",
            "contains an unresolved INDEX component",
        ),
        (
            "UNSUPPORTED-AUGMENT-MIB",
            r#"UNSUPPORTED-AUGMENT-MIB DEFINITIONS ::= BEGIN
root OBJECT IDENTIFIER ::= { iso 424248 }
badTable OBJECT-TYPE SYNTAX SEQUENCE OF BadEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Table." ::= { root 1 }
badEntry OBJECT-TYPE SYNTAX BadEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Row." AUGMENTS { missingRow } ::= { badTable 1 }
BadEntry ::= SEQUENCE { }
END
"#,
            "badEntry",
            "contains an unresolved AUGMENTS target",
        ),
        (
            "UNSUPPORTED-BYTES-MIB",
            r#"UNSUPPORTED-BYTES-MIB DEFINITIONS ::= BEGIN
root OBJECT IDENTIFIER ::= { iso 424249 }
badBytes OBJECT-TYPE
    SYNTAX OCTET STRING
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Bytes."
    DEFVAL { '102'B }
    ::= { root 1 }
END
"#,
            "badBytes",
            "contains a malformed byte-string DEFVAL",
        ),
        (
            "UNSUPPORTED-BARE-INDEX-MIB",
            r#"UNSUPPORTED-BARE-INDEX-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM RFC1155-SMI;
root OBJECT IDENTIFIER ::= { enterprises 424250 }
badTable OBJECT-TYPE SYNTAX SEQUENCE OF BadEntry ACCESS not-accessible STATUS mandatory DESCRIPTION "Table." ::= { root 1 }
badEntry OBJECT-TYPE SYNTAX BadEntry ACCESS not-accessible STATUS mandatory DESCRIPTION "Row." INDEX { INTEGER } ::= { badTable 1 }
BadEntry ::= SEQUENCE { }
END
"#,
            "badEntry",
            "uses an SMIv1 bare-type INDEX component",
        ),
    ];

    for (module_name, source, expected_definition, expected_reason) in cases {
        let mib = load_inline(&[(module_name, source)], &[module_name]);
        let mut output = b"preloaded".to_vec();
        let error = writer::write(&mut output, &mib, module_name)
            .expect_err("malformed semantics must not be emitted");
        assert!(
            matches!(
                error,
                Error::UnsupportedDefinition { definition, reason }
                    if definition == expected_definition && reason == expected_reason
            ),
            "module={module_name}"
        );
        assert_eq!(output, b"preloaded", "module={module_name}");
    }
}

#[test]
fn identity_only_module_matches_golden_output() {
    let mib = identity_mib();

    let mut first = Vec::new();
    writer::write(&mut first, &mib, "IDENTITY-ONLY-MIB").expect("first write should succeed");
    let mut second = Vec::new();
    writer::write(&mut second, &mib, "IDENTITY-ONLY-MIB").expect("second write should succeed");

    assert_eq!(first, second, "repeated writes must be deterministic");
    let output = String::from_utf8(first).expect("writer output should be UTF-8");
    assert_eq!(output, include_str!("data/writer-identity-golden.mib"));

    let reparsed = Loader::new()
        .source(source::memory("IDENTITY-ONLY-MIB", output.as_bytes()))
        .modules(["IDENTITY-ONLY-MIB"])
        .load()
        .expect("golden output should reparse");
    assert_eq!(
        identity_semantics(&mib, "IDENTITY-ONLY-MIB"),
        identity_semantics(&reparsed, "IDENTITY-ONLY-MIB")
    );

    let mut rewritten = Vec::new();
    writer::write(&mut rewritten, &reparsed, "IDENTITY-ONLY-MIB")
        .expect("reparsed module should rewrite");
    assert_eq!(rewritten, output.as_bytes());
}

#[derive(Debug, PartialEq, Eq)]
struct IdentitySemantics {
    name: String,
    kind: ModuleIdentityKind,
    oid: String,
    status: Option<Status>,
    description: String,
    reference: String,
    last_updated: String,
    organization: String,
    contact_info: String,
    revisions: Vec<(String, String)>,
}

fn identity_semantics(mib: &mib_rs::Mib, module_name: &str) -> Vec<IdentitySemantics> {
    let mut identities = mib
        .module(module_name)
        .expect("module should exist")
        .identities()
        .iter()
        .map(|identity| IdentitySemantics {
            name: identity.name().to_owned(),
            kind: identity.kind(),
            oid: identity.oid().to_string(),
            status: identity.status(),
            description: identity.description().to_owned(),
            reference: identity.reference().to_owned(),
            last_updated: identity.last_updated().to_owned(),
            organization: identity.organization().to_owned(),
            contact_info: identity.contact_info().to_owned(),
            revisions: identity
                .revisions()
                .iter()
                .map(|revision| (revision.date.clone(), revision.description.clone()))
                .collect(),
        })
        .collect::<Vec<_>>();
    identities.sort_by(|left, right| left.name.cmp(&right.name));
    identities
}

#[test]
fn description_option_applies_to_identity_clauses() {
    let mib = identity_mib();
    let mut output = Vec::new();
    writer::write_with_options(
        &mut output,
        &mib,
        "IDENTITY-ONLY-MIB",
        Options::default().with_descriptions(false),
    )
    .expect("write should succeed");

    let output = String::from_utf8(output).expect("writer output should be UTF-8");
    assert!(!output.contains("DESCRIPTION"));
    assert!(output.contains("ORGANIZATION"));
    assert!(output.contains("identityFirst OBJECT-IDENTITY"));
}

#[test]
fn missing_module_is_a_typed_error_and_writes_nothing() {
    let mib = identity_mib();
    let mut output = Vec::new();
    let error = writer::write(&mut output, &mib, "ABSENT-MIB").expect_err("module is absent");

    assert!(matches!(error, Error::ModuleNotFound(name) if name == "ABSENT-MIB"));
    assert!(output.is_empty());
}

#[test]
fn missing_module_preserves_preloaded_destination() {
    let mib = identity_mib();
    let mut output = b"preloaded".to_vec();
    let error = writer::write(&mut output, &mib, "ABSENT-MIB").expect_err("module is absent");

    assert!(matches!(error, Error::ModuleNotFound(_)));
    assert_eq!(output, b"preloaded");
}

struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "test failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn destination_failure_is_a_typed_io_error() {
    let mib = identity_mib();
    let error = writer::write(BrokenWriter, &mib, "IDENTITY-ONLY-MIB")
        .expect_err("destination should fail");

    assert!(matches!(error, Error::Io(source) if source.kind() == io::ErrorKind::BrokenPipe));
}

struct FailAfter {
    remaining: usize,
    bytes: Vec<u8>,
}

impl Write for FailAfter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "limit reached"));
        }
        let written = buffer.len().min(self.remaining);
        self.bytes.extend_from_slice(&buffer[..written]);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn io_failure_can_leave_a_documented_partial_prefix() {
    let mib = identity_mib();
    let mut destination = FailAfter {
        remaining: 37,
        bytes: Vec::new(),
    };
    let error = writer::write(&mut destination, &mib, "IDENTITY-ONLY-MIB")
        .expect_err("destination should stop mid-module");

    assert!(matches!(error, Error::Io(_)));
    assert_eq!(destination.bytes.len(), 37);
    assert!(include_bytes!("data/writer-identity-golden.mib").starts_with(&destination.bytes));
}

fn load_inline(modules: &[(&str, &str)], requested: &[&str]) -> mib_rs::Mib {
    Loader::new()
        .source(source::memory_modules(modules.iter().map(
            |(name, text)| ((*name).to_owned(), text.as_bytes().to_vec()),
        )))
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(requested.iter().copied())
        .load()
        .expect("inline modules should load")
}

#[test]
fn cross_module_shared_oid_uses_each_exact_declaration() {
    let module_a = r#"COLLISION-A-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
aMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "A"
    CONTACT-INFO "A"
    DESCRIPTION "Module A."
    ::= { enterprises 424260 }
aIdentity OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "Identity A."
    ::= { enterprises 424262 }
END
"#;
    let module_b = r#"COLLISION-B-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
bMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "B"
    CONTACT-INFO "B"
    DESCRIPTION "Module B."
    ::= { enterprises 424261 }
bIdentity OBJECT-IDENTITY
    STATUS deprecated
    DESCRIPTION "Identity B."
    ::= { enterprises 424262 }
END
"#;
    let mib = load_inline(
        &[("COLLISION-A-MIB", module_a), ("COLLISION-B-MIB", module_b)],
        &["COLLISION-A-MIB", "COLLISION-B-MIB"],
    );

    let mut a = Vec::new();
    writer::write(&mut a, &mib, "COLLISION-A-MIB").unwrap();
    let a = String::from_utf8(a).unwrap();
    assert!(a.contains("aIdentity OBJECT-IDENTITY"));
    assert!(a.contains("\"Identity A.\""));
    assert!(!a.contains("bIdentity"));

    let mut b = Vec::new();
    writer::write(&mut b, &mib, "COLLISION-B-MIB").unwrap();
    let b = String::from_utf8(b).unwrap();
    assert!(b.contains("bIdentity OBJECT-IDENTITY"));
    assert!(b.contains("STATUS deprecated"));
    assert!(b.contains("\"Identity B.\""));
    assert!(!b.contains("aIdentity"));
}

#[test]
fn same_module_same_oid_aliases_are_each_emitted_once() {
    let source = r#"ALIAS-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
aliasMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Aliases"
    CONTACT-INFO "Aliases"
    DESCRIPTION "Aliases."
    ::= { enterprises 424270 }
aliasOne OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "One."
    ::= { aliasMib 1 }
aliasTwo OBJECT-IDENTITY
    STATUS obsolete
    DESCRIPTION "Two."
    ::= { aliasMib 1 }
END
"#;
    let mib = load_inline(&[("ALIAS-MIB", source)], &["ALIAS-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "ALIAS-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert_eq!(output.matches("aliasOne OBJECT-IDENTITY").count(), 1);
    assert_eq!(output.matches("aliasTwo OBJECT-IDENTITY").count(), 1);
    assert!(output.contains("STATUS current"));
    assert!(output.contains("STATUS obsolete"));
}

#[test]
fn losing_shared_oid_table_uses_exact_module_object_metadata() {
    let losing = r#"LOSING-TABLE-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM RFC1155-SMI;
losingRoot OBJECT IDENTIFIER ::= { enterprises 424253 }
losingTable OBJECT-TYPE SYNTAX SEQUENCE OF LosingEntry ACCESS not-accessible STATUS mandatory DESCRIPTION "Losing table." ::= { losingRoot 1 }
losingEntry OBJECT-TYPE SYNTAX LosingEntry ACCESS not-accessible STATUS mandatory DESCRIPTION "Losing row." INDEX { losingIndex } ::= { losingTable 1 }
losingIndex OBJECT-TYPE SYNTAX INTEGER (1..10) ACCESS read-only STATUS mandatory DESCRIPTION "Losing index." ::= { losingEntry 1 }
losingValue OBJECT-TYPE SYNTAX OCTET STRING (SIZE (0..8)) ACCESS read-only STATUS optional DESCRIPTION "Losing value." ::= { losingEntry 2 }
LosingEntry ::= SEQUENCE { losingIndex INTEGER, losingValue OCTET STRING }
END
"#;
    let winning = r#"WINNING-COLLISION-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI OBJECT-GROUP FROM SNMPv2-CONF;
winningMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Winner" CONTACT-INFO "Winner" DESCRIPTION "Winner." ::= { enterprises 424254 }
collisionRoot OBJECT IDENTIFIER ::= { enterprises 424253 }
winningTableOidScalar OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "Winning scalar." ::= { collisionRoot 1 }
winningRowOidScalar OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "Winning scalar." ::= { winningTableOidScalar 1 }
winningColumnGroup OBJECT-GROUP OBJECTS { winningTableOidScalar } STATUS current DESCRIPTION "Winning group." ::= { winningRowOidScalar 1 }
winningColumnScalar OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "Winning scalar." ::= { winningRowOidScalar 2 }
END
"#;
    let mib = load_inline(
        &[
            ("LOSING-TABLE-MIB", losing),
            ("WINNING-COLLISION-MIB", winning),
        ],
        &["LOSING-TABLE-MIB", "WINNING-COLLISION-MIB"],
    );
    let losing_module = mib.module("LOSING-TABLE-MIB").unwrap();
    assert_eq!(
        losing_module.object("losingTable").unwrap().declared_kind(),
        Kind::Table
    );
    assert_eq!(
        losing_module.object("losingEntry").unwrap().declared_kind(),
        Kind::Row
    );
    assert_eq!(
        losing_module.object("losingIndex").unwrap().declared_kind(),
        Kind::Column
    );

    let mut output = Vec::new();
    writer::write(&mut output, &mib, "LOSING-TABLE-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("losingTable OBJECT-TYPE\n    SYNTAX SEQUENCE OF LosingEntry"));
    assert!(output.contains("losingEntry OBJECT-TYPE\n    SYNTAX LosingEntry"));
    assert!(output.contains("INDEX { losingIndex }"));
    assert!(output.contains("LosingEntry ::= SEQUENCE {\n    losingIndex INTEGER,"));
    assert!(!output.contains("winningTableOidScalar"));

    let reparsed = load_inline(&[("LOSING-TABLE-MIB", &output)], &["LOSING-TABLE-MIB"]);
    assert_eq!(
        module_semantics(&mib, "LOSING-TABLE-MIB"),
        module_semantics(&reparsed, "LOSING-TABLE-MIB")
    );
}

#[test]
fn identity_collisions_ignore_winning_object_and_group_metadata() {
    let source = r#"KIND-COLLISION-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    OBJECT-GROUP
        FROM SNMPv2-CONF;
collisionMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Collisions"
    CONTACT-INFO "Collisions"
    DESCRIPTION "Collisions."
    ::= { enterprises 424280 }
collisionObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Winning object."
    ::= { collisionMib 2 }
objectIdentity OBJECT-IDENTITY
    STATUS deprecated
    DESCRIPTION "Exact object-collision identity."
    ::= { collisionMib 2 }
collisionGroup OBJECT-GROUP
    OBJECTS { collisionObject }
    STATUS current
    DESCRIPTION "Winning group."
    ::= { collisionMib 3 }
groupIdentity OBJECT-IDENTITY
    STATUS obsolete
    DESCRIPTION "Exact group-collision identity."
    ::= { collisionMib 3 }
parentObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Unsupported local parent."
    ::= { collisionMib 4 }
childOid OBJECT IDENTIFIER ::= { parentObject 1 }
END
"#;
    let mib = load_inline(&[("KIND-COLLISION-MIB", source)], &["KIND-COLLISION-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "KIND-COLLISION-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("objectIdentity OBJECT-IDENTITY"));
    assert!(output.contains("STATUS deprecated"));
    assert!(output.contains("\"Exact object-collision identity.\""));
    assert!(output.contains("groupIdentity OBJECT-IDENTITY"));
    assert!(output.contains("STATUS obsolete"));
    assert!(output.contains("\"Exact group-collision identity.\""));
    assert!(output.contains("collisionObject OBJECT-TYPE"));
    assert!(!output.contains("collisionGroup OBJECT-GROUP"));
    assert!(output.contains("parentObject OBJECT-TYPE"));
    assert!(output.contains("childOid OBJECT IDENTIFIER ::= { parentObject 1 }"));

    let reparsed = load_inline(&[("KIND-COLLISION-MIB", &output)], &["KIND-COLLISION-MIB"]);
    assert_eq!(
        reparsed.resolve_oid("childOid").unwrap().to_string(),
        "1.3.6.1.4.1.424280.4.1"
    );
}

#[test]
fn external_root_parent_is_imported_and_symbolic() {
    let source = r#"ROOT-CHILD-MIB DEFINITIONS ::= BEGIN
rootChild OBJECT IDENTIFIER ::= { iso 9 }
END
"#;
    let mib = load_inline(&[("ROOT-CHILD-MIB", source)], &["ROOT-CHILD-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "ROOT-CHILD-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("iso\n        FROM SNMPv2-SMI;"));
    assert!(output.contains("rootChild OBJECT IDENTIFIER ::= { iso 9 }"));
}

#[test]
fn same_spelled_local_types_are_not_smiv1_normalized() {
    let source = r#"LOCAL-ALIASES-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, enterprises FROM SNMPv2-SMI
        TEXTUAL-CONVENTION FROM SNMPv2-TC;
localAliasesMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Local" CONTACT-INFO "Local" DESCRIPTION "Local aliases." ::= { enterprises 424291 }
Counter ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Local octets." SYNTAX OCTET STRING (SIZE (2))
Gauge ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Local enum." SYNTAX INTEGER { low(0), high(1) }
NetworkAddress ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Local bits." SYNTAX BITS { v4(0), v6(1) }
localCounter OBJECT-TYPE SYNTAX Counter MAX-ACCESS read-only STATUS current DESCRIPTION "Counter." ::= { localAliasesMib 1 }
localGauge OBJECT-TYPE SYNTAX Gauge MAX-ACCESS read-only STATUS current DESCRIPTION "Gauge." ::= { localAliasesMib 2 }
localNetwork OBJECT-TYPE SYNTAX NetworkAddress MAX-ACCESS read-only STATUS current DESCRIPTION "Network." ::= { localAliasesMib 3 }
END
"#;
    let mib = load_inline(&[("LOCAL-ALIASES-MIB", source)], &["LOCAL-ALIASES-MIB"]);
    let module = mib.module("LOCAL-ALIASES-MIB").unwrap();
    assert_eq!(
        module.r#type("Counter").unwrap().effective_base(),
        BaseType::OctetString
    );
    assert_eq!(
        module.r#type("Gauge").unwrap().effective_base(),
        BaseType::Integer32
    );
    assert_eq!(
        module.r#type("NetworkAddress").unwrap().effective_base(),
        BaseType::Bits
    );

    let mut output = Vec::new();
    writer::write(&mut output, &mib, "LOCAL-ALIASES-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("localCounter OBJECT-TYPE\n    SYNTAX Counter"));
    assert!(output.contains("localGauge OBJECT-TYPE\n    SYNTAX Gauge"));
    assert!(output.contains("localNetwork OBJECT-TYPE\n    SYNTAX NetworkAddress"));
    assert!(!output.contains("Counter32"));
    assert!(!output.contains("Gauge32"));
    assert!(!output.contains("IpAddress"));

    let reparsed = load_inline(&[("LOCAL-ALIASES-MIB", &output)], &["LOCAL-ALIASES-MIB"]);
    assert_eq!(
        module_semantics(&mib, "LOCAL-ALIASES-MIB"),
        module_semantics(&reparsed, "LOCAL-ALIASES-MIB")
    );
}

#[test]
fn same_spelled_vendor_types_keep_vendor_imports() {
    let vendor = r#"VENDOR-ALIASES-MIB DEFINITIONS ::= BEGIN
IMPORTS TEXTUAL-CONVENTION FROM SNMPv2-TC;
Counter ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Vendor octets." SYNTAX OCTET STRING
Gauge ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Vendor enum." SYNTAX INTEGER { low(0), high(1) }
NetworkAddress ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Vendor bits." SYNTAX BITS { one(0) }
END
"#;
    let consumer = r#"VENDOR-CONSUMER-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, enterprises FROM SNMPv2-SMI
        Counter, Gauge, NetworkAddress FROM VENDOR-ALIASES-MIB;
vendorConsumerMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Vendor" CONTACT-INFO "Vendor" DESCRIPTION "Vendor aliases." ::= { enterprises 424292 }
vendorCounter OBJECT-TYPE SYNTAX Counter MAX-ACCESS read-only STATUS current DESCRIPTION "Counter." ::= { vendorConsumerMib 1 }
vendorGauge OBJECT-TYPE SYNTAX Gauge MAX-ACCESS read-only STATUS current DESCRIPTION "Gauge." ::= { vendorConsumerMib 2 }
vendorNetwork OBJECT-TYPE SYNTAX NetworkAddress MAX-ACCESS read-only STATUS current DESCRIPTION "Network." ::= { vendorConsumerMib 3 }
END
"#;
    let mib = load_inline(
        &[
            ("VENDOR-ALIASES-MIB", vendor),
            ("VENDOR-CONSUMER-MIB", consumer),
        ],
        &["VENDOR-CONSUMER-MIB"],
    );
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "VENDOR-CONSUMER-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Counter, Gauge, NetworkAddress\n        FROM VENDOR-ALIASES-MIB;"));
    assert!(output.contains("SYNTAX Counter"));
    assert!(output.contains("SYNTAX Gauge"));
    assert!(output.contains("SYNTAX NetworkAddress"));
    assert!(!output.contains("Counter32"));
    assert!(!output.contains("Gauge32"));
    assert!(!output.contains("IpAddress"));
}

#[test]
fn named_bits_refinements_remain_bits_and_keep_their_parent() {
    let source = r#"BITS-REFINEMENT-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, enterprises FROM SNMPv2-SMI
        TEXTUAL-CONVENTION FROM SNMPv2-TC;
bitsRefinementMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Bits" CONTACT-INFO "Bits" DESCRIPTION "Bits." ::= { enterprises 424293 }
ParentBits ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Parent." SYNTAX BITS { first(0), second(1) }
ChildBits ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "Child." SYNTAX ParentBits { second(1) }
bitsObject OBJECT-TYPE SYNTAX ParentBits { first(0) } MAX-ACCESS read-only STATUS current DESCRIPTION "Object." ::= { bitsRefinementMib 1 }
END
"#;
    let mib = load_inline(&[("BITS-REFINEMENT-MIB", source)], &["BITS-REFINEMENT-MIB"]);
    let module = mib.module("BITS-REFINEMENT-MIB").unwrap();
    let child = module.r#type("ChildBits").unwrap();
    assert!(child.enums().is_empty());
    assert_eq!(named_values(child.bits()), vec![("second".to_owned(), 1)]);
    let object = module.object("bitsObject").unwrap();
    assert!(object.declared_enums().is_empty());
    assert_eq!(
        named_values(object.declared_bits()),
        vec![("first".to_owned(), 0)]
    );

    let mut output = Vec::new();
    writer::write(&mut output, &mib, "BITS-REFINEMENT-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("SYNTAX ParentBits { second(1) }"));
    assert!(output.contains("bitsObject OBJECT-TYPE\n    SYNTAX ParentBits { first(0) }"));
    let reparsed = load_inline(
        &[("BITS-REFINEMENT-MIB", &output)],
        &["BITS-REFINEMENT-MIB"],
    );
    assert_eq!(
        module_semantics(&mib, "BITS-REFINEMENT-MIB"),
        module_semantics(&reparsed, "BITS-REFINEMENT-MIB")
    );
}

#[test]
fn duplicate_oid_tables_keep_exact_named_relationships() {
    let source = r#"DUPLICATE-TABLES-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
duplicateTablesMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Tables" CONTACT-INFO "Tables" DESCRIPTION "Tables." ::= { enterprises 424294 }
ta OBJECT-TYPE SYNTAX SEQUENCE OF Ae MAX-ACCESS not-accessible STATUS current DESCRIPTION "A table." ::= { duplicateTablesMib 1 }
tb OBJECT-TYPE SYNTAX SEQUENCE OF Be MAX-ACCESS not-accessible STATUS current DESCRIPTION "B table." ::= { duplicateTablesMib 1 }
ae OBJECT-TYPE SYNTAX Ae MAX-ACCESS not-accessible STATUS current DESCRIPTION "A row." INDEX { ac } ::= { ta 1 }
be OBJECT-TYPE SYNTAX Be MAX-ACCESS not-accessible STATUS current DESCRIPTION "B row." INDEX { bc } ::= { tb 1 }
ac OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "A column." ::= { ae 1 }
bc OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "B column." ::= { be 1 }
Ae ::= SEQUENCE { ac Integer32 }
Be ::= SEQUENCE { bc Integer32 }
END
"#;
    let mib = load_inline(
        &[("DUPLICATE-TABLES-MIB", source)],
        &["DUPLICATE-TABLES-MIB"],
    );
    let module = mib.module("DUPLICATE-TABLES-MIB").unwrap();
    assert_eq!(module.object("ta").unwrap().declared_row_name(), "ae");
    assert_eq!(module.object("tb").unwrap().declared_row_name(), "be");
    assert_eq!(
        module.object("ae").unwrap().declared_column_names(),
        &["ac"]
    );
    assert_eq!(
        module.object("be").unwrap().declared_column_names(),
        &["bc"]
    );

    let mut output = Vec::new();
    writer::write(&mut output, &mib, "DUPLICATE-TABLES-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("ae OBJECT-TYPE\n    SYNTAX Ae"));
    assert!(output.contains("    ::= { ta 1 }"));
    assert!(output.contains("be OBJECT-TYPE\n    SYNTAX Be"));
    assert!(output.contains("    ::= { tb 1 }"));
    assert!(output.contains("Ae ::= SEQUENCE {\n    ac Integer32\n}"));
    assert!(output.contains("Be ::= SEQUENCE {\n    bc Integer32\n}"));

    let reparsed = load_inline(
        &[("DUPLICATE-TABLES-MIB", &output)],
        &["DUPLICATE-TABLES-MIB"],
    );
    assert_eq!(
        module_semantics(&mib, "DUPLICATE-TABLES-MIB"),
        module_semantics(&reparsed, "DUPLICATE-TABLES-MIB")
    );
}

#[test]
fn structural_row_without_index_is_classified_then_rejected_atomically() {
    let source = r#"MISSING-INDEX-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
missingIndexMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Tables" CONTACT-INFO "Tables" DESCRIPTION "Tables." ::= { enterprises 424295 }
missingTable OBJECT-TYPE SYNTAX SEQUENCE OF MissingEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Table." ::= { missingIndexMib 1 }
missingEntry OBJECT-TYPE SYNTAX MissingEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Row." ::= { missingTable 1 }
missingColumn OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "Column." ::= { missingEntry 1 }
MissingEntry ::= SEQUENCE { missingColumn Integer32 }
END
"#;
    let mib = load_inline(&[("MISSING-INDEX-MIB", source)], &["MISSING-INDEX-MIB"]);
    let module = mib.module("MISSING-INDEX-MIB").unwrap();
    assert_eq!(
        module.object("missingEntry").unwrap().declared_kind(),
        Kind::Row
    );
    assert_eq!(
        module.object("missingColumn").unwrap().declared_kind(),
        Kind::Column
    );
    let mut output = b"sentinel".to_vec();
    let error = writer::write(&mut output, &mib, "MISSING-INDEX-MIB").unwrap_err();
    assert_eq!(output, b"sentinel");
    assert!(matches!(
        error,
        Error::UnsupportedDefinition { definition, reason }
            if definition == "missingEntry" && reason.contains("without INDEX or AUGMENTS")
    ));
}

#[test]
fn ambiguous_duplicate_oid_relationships_are_rejected_atomically() {
    let source = r#"AMBIGUOUS-TABLES-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
ambiguousTablesMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Tables" CONTACT-INFO "Tables" DESCRIPTION "Tables." ::= { enterprises 424296 }
ta OBJECT-TYPE SYNTAX SEQUENCE OF Entry MAX-ACCESS not-accessible STATUS current DESCRIPTION "A table." ::= { ambiguousTablesMib 1 }
tb OBJECT-TYPE SYNTAX SEQUENCE OF Entry MAX-ACCESS not-accessible STATUS current DESCRIPTION "B table." ::= { ambiguousTablesMib 1 }
ae OBJECT-TYPE SYNTAX Entry MAX-ACCESS not-accessible STATUS current DESCRIPTION "A row." INDEX { ac } ::= { 1 3 6 1 4 1 424296 1 1 }
be OBJECT-TYPE SYNTAX Entry MAX-ACCESS not-accessible STATUS current DESCRIPTION "B row." INDEX { bc } ::= { 1 3 6 1 4 1 424296 1 1 }
ac OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "A column." ::= { ae 1 }
bc OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "B column." ::= { be 1 }
Entry ::= SEQUENCE { ac Integer32, bc Integer32 }
END
"#;
    let mib = load_inline(
        &[("AMBIGUOUS-TABLES-MIB", source)],
        &["AMBIGUOUS-TABLES-MIB"],
    );
    let mut output = b"sentinel".to_vec();
    let error = writer::write(&mut output, &mib, "AMBIGUOUS-TABLES-MIB").unwrap_err();
    assert_eq!(output, b"sentinel");
    assert!(matches!(
        error,
        Error::UnsupportedDefinition { reason, .. } if reason.contains("ambiguous row declarations")
    ));
}

#[test]
fn oid_assignments_and_defaults_preserve_declared_alias_provenance() {
    let module_a = r#"ANCHOR-A-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM SNMPv2-SMI;
aRoot OBJECT IDENTIFIER ::= { enterprises 424297 }
END
"#;
    let module_b = r#"ANCHOR-B-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM SNMPv2-SMI;
bRoot OBJECT IDENTIFIER ::= { enterprises 424297 }
END
"#;
    let consumer = r#"ANCHOR-CONSUMER-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, enterprises FROM SNMPv2-SMI
        bRoot FROM ANCHOR-B-MIB;
anchorConsumerMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Anchors" CONTACT-INFO "Anchors" DESCRIPTION "Anchors." ::= { enterprises 424298 }
aLocal OBJECT IDENTIFIER ::= { anchorConsumerMib 1 }
zLocal OBJECT IDENTIFIER ::= { anchorConsumerMib 1 }
localObject OBJECT-TYPE SYNTAX OBJECT IDENTIFIER MAX-ACCESS read-only STATUS current DESCRIPTION "Local." DEFVAL { zLocal } ::= { zLocal 1 }
externalObject OBJECT-TYPE SYNTAX OBJECT IDENTIFIER MAX-ACCESS read-only STATUS current DESCRIPTION "External." DEFVAL { bRoot } ::= { bRoot 1 }
END
"#;
    let mib = load_inline(
        &[
            ("ANCHOR-A-MIB", module_a),
            ("ANCHOR-B-MIB", module_b),
            ("ANCHOR-CONSUMER-MIB", consumer),
        ],
        &["ANCHOR-A-MIB", "ANCHOR-B-MIB", "ANCHOR-CONSUMER-MIB"],
    );
    let consumer_module = mib.module("ANCHOR-CONSUMER-MIB").unwrap();
    let local = consumer_module.object("localObject").unwrap();
    assert_eq!(local.declared_oid_parent_name(), "zLocal");
    assert_eq!(
        local.declared_oid_parent().unwrap().module_id(),
        Some(consumer_module.id())
    );
    assert_eq!(
        local.default_value().unwrap().oid_ref().unwrap().name,
        "zLocal"
    );
    assert_eq!(
        local
            .default_value()
            .unwrap()
            .oid_ref()
            .unwrap()
            .module_id(),
        Some(consumer_module.id())
    );
    let external = consumer_module.object("externalObject").unwrap();
    let module_b_id = mib.module("ANCHOR-B-MIB").unwrap().id();
    assert_eq!(external.declared_oid_parent_name(), "bRoot");
    assert_eq!(
        external.declared_oid_parent().unwrap().module_id(),
        Some(module_b_id)
    );
    assert_eq!(
        external
            .default_value()
            .unwrap()
            .oid_ref()
            .unwrap()
            .module_id(),
        Some(module_b_id)
    );
    assert_eq!(
        consumer_module
            .identities()
            .iter()
            .find(|identity| identity.name() == "zLocal")
            .unwrap()
            .declared_oid_parent_name(),
        "anchorConsumerMib"
    );

    let mut output = Vec::new();
    writer::write(&mut output, &mib, "ANCHOR-CONSUMER-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(
        output.contains("bRoot\n        FROM ANCHOR-B-MIB"),
        "{output}"
    );
    assert!(!output.contains("aRoot"));
    assert!(output.contains("localObject OBJECT-TYPE"));
    assert!(output.contains("DEFVAL { zLocal }"));
    assert!(output.contains("::= { zLocal 1 }"));
    assert!(output.contains("externalObject OBJECT-TYPE"));
    assert!(output.contains("DEFVAL { bRoot }"));
    assert!(output.contains("::= { bRoot 1 }"));
}

#[test]
fn duplicate_numeric_row_parent_without_sequence_fields_is_rejected_atomically() {
    let source = r#"AMBIGUOUS-COLUMNS-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
ambiguousColumnsMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Columns" CONTACT-INFO "Columns" DESCRIPTION "Columns." ::= { enterprises 424301 }
ta OBJECT-TYPE SYNTAX SEQUENCE OF Ae MAX-ACCESS not-accessible STATUS current DESCRIPTION "A table." ::= { ambiguousColumnsMib 1 }
tb OBJECT-TYPE SYNTAX SEQUENCE OF Be MAX-ACCESS not-accessible STATUS current DESCRIPTION "B table." ::= { ambiguousColumnsMib 1 }
ae OBJECT-TYPE SYNTAX Ae MAX-ACCESS not-accessible STATUS current DESCRIPTION "A row." INDEX { ac } ::= { ta 1 }
be OBJECT-TYPE SYNTAX Be MAX-ACCESS not-accessible STATUS current DESCRIPTION "B row." INDEX { bc } ::= { tb 1 }
ac OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "A column." ::= { 1 3 6 1 4 1 424301 1 1 1 }
bc OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "B column." ::= { 1 3 6 1 4 1 424301 1 1 2 }
Ae ::= SEQUENCE { }
Be ::= SEQUENCE { }
END
"#;
    let mib = load_inline(
        &[("AMBIGUOUS-COLUMNS-MIB", source)],
        &["AMBIGUOUS-COLUMNS-MIB"],
    );
    let mut output = b"sentinel".to_vec();
    let error = writer::write(&mut output, &mib, "AMBIGUOUS-COLUMNS-MIB").unwrap_err();
    assert_eq!(output, b"sentinel");
    assert!(matches!(
        error,
        Error::UnsupportedDefinition { reason, .. }
            if reason.contains("ambiguous numeric child declaration")
                || reason.contains("ambiguous numeric row parent")
    ));
}

#[test]
fn sequence_field_with_conflicting_topology_is_rejected_atomically() {
    let source = r#"CONFLICTING-SEQUENCE-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
conflictingSequenceMib MODULE-IDENTITY LAST-UPDATED "202608180000Z" ORGANIZATION "Columns" CONTACT-INFO "Columns" DESCRIPTION "Columns." ::= { enterprises 424302 }
ta OBJECT-TYPE SYNTAX SEQUENCE OF Ae MAX-ACCESS not-accessible STATUS current DESCRIPTION "A table." ::= { conflictingSequenceMib 1 }
ae OBJECT-TYPE SYNTAX Ae MAX-ACCESS not-accessible STATUS current DESCRIPTION "A row." INDEX { ac } ::= { ta 1 }
ac OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "A column." ::= { ae 1 }
tb OBJECT-TYPE SYNTAX SEQUENCE OF Be MAX-ACCESS not-accessible STATUS current DESCRIPTION "B table." ::= { conflictingSequenceMib 2 }
be OBJECT-TYPE SYNTAX Be MAX-ACCESS not-accessible STATUS current DESCRIPTION "B row." INDEX { bc } ::= { tb 1 }
bc OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "B column." ::= { be 1 }
Ae ::= SEQUENCE { be Integer32 }
Be ::= SEQUENCE { bc Integer32 }
END
"#;
    let mib = load_inline(
        &[("CONFLICTING-SEQUENCE-MIB", source)],
        &["CONFLICTING-SEQUENCE-MIB"],
    );
    let mut output = b"sentinel".to_vec();
    let error = writer::write(&mut output, &mib, "CONFLICTING-SEQUENCE-MIB").unwrap_err();
    assert_eq!(output, b"sentinel");
    assert!(matches!(
        error,
        Error::UnsupportedDefinition { reason, .. }
            if reason.contains("table or row declaration")
                || reason.contains("conflicting topology")
    ));
}
