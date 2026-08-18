// Integration tests: lower the shared MIB corpus and verify basic properties.

mod common;

use mib_rs::types::{DiagCode, DiagnosticConfig, Severity};
use mib_rs::{SourceOrigin, SourceSet};
use std::path::Path;
use std::sync::Arc;

use common::{collect_mib_files, corpus_dir, problems_dir};

fn lower_source(source: &[u8], config: &DiagnosticConfig) -> Vec<mib_rs::ir::Module> {
    let mut sources = SourceSet::new();
    let id = sources
        .insert(
            SourceOrigin::memory("lower-corpus"),
            "lower-corpus",
            Arc::from(source),
        )
        .unwrap();
    let document = sources.get(id).unwrap();
    mib_rs::parser::parse(document, config)
        .into_iter()
        .map(|module| mib_rs::lower::lower(module, document, config))
        .collect()
}

fn parse_and_lower(path: &Path) -> Vec<mib_rs::ir::Module> {
    let content = std::fs::read(path).unwrap();
    let config = DiagnosticConfig::default();
    lower_source(&content, &config)
}

#[test]
fn primary_corpus_lowering_no_panics() {
    let dir = corpus_dir();
    if !dir.exists() {
        eprintln!("corpus dir not found, skipping: {}", dir.display());
        return;
    }

    let files = collect_mib_files(&dir);
    assert!(!files.is_empty(), "no MIB files found in corpus");

    let mut total_modules = 0;
    let mut total_defs = 0;

    for file in &files {
        let modules = parse_and_lower(file);
        for module in &modules {
            total_modules += 1;
            total_defs += module.definitions.len();
            // Every module should have a name
            assert!(
                !module.name.is_empty(),
                "module has empty name in {:?}",
                file
            );
            assert!(
                matches!(
                    module.language,
                    mib_rs::types::Language::Unknown
                        | mib_rs::types::Language::SMIv1
                        | mib_rs::types::Language::SMIv2
                ),
                "module {} has unsupported language in {:?}",
                module.name,
                file
            );
        }
    }

    eprintln!(
        "lowered {} modules with {} definitions from {} files",
        total_modules,
        total_defs,
        files.len()
    );
}

#[test]
fn integral_overflow_fixture_lowers_with_zero_placeholders() {
    let path = problems_dir().join("PROBLEM-INTEGRAL-OVERFLOW-MIB.mib");
    let module = parse_and_lower(&path).into_iter().next().unwrap();
    assert_eq!(module.name, "PROBLEM-INTEGRAL-OVERFLOW-MIB");

    let definition = |name: &str| {
        module
            .definitions
            .iter()
            .find(|definition| definition.name() == name)
            .unwrap_or_else(|| panic!("missing lowered definition {name}"))
    };

    for name in ["ProblemOverflowEnum", "ProblemOverflowBits"] {
        let values: Vec<i64> = match definition(name) {
            mib_rs::ir::Definition::TypeDef(definition) => match &definition.syntax {
                mib_rs::ir::TypeSyntax::IntegerEnum { named_numbers, .. } => {
                    named_numbers.iter().map(|value| value.value).collect()
                }
                mib_rs::ir::TypeSyntax::Bits { named_bits, .. } => named_bits
                    .iter()
                    .map(|value| i64::from(value.position))
                    .collect(),
                other => panic!("expected named-number syntax, got {other:?}"),
            },
            other => panic!("expected type definition, got {other:?}"),
        };
        assert_eq!(
            values,
            [0, 0, if name == "ProblemOverflowEnum" { 1 } else { 2 }]
        );
    }

    for (name, expected_kind) in [
        ("problemOverflowPlain", "plain"),
        ("problemOverflowNamed", "named"),
        ("problemOverflowQualified", "qualified"),
    ] {
        let components = definition(name).oid().unwrap().components.as_slice();
        let last = components.last().unwrap();
        match (expected_kind, last) {
            ("plain", mib_rs::ir::OidComponent::Number { value: 0, .. })
            | ("named", mib_rs::ir::OidComponent::NamedNumber { number: 0, .. })
            | ("qualified", mib_rs::ir::OidComponent::QualifiedNamedNumber { number: 0, .. }) => {}
            _ => panic!("unexpected lowered OID component for {name}: {last:?}"),
        }
    }

    for name in [
        "problemOverflowPositiveDefault",
        "problemOverflowNegativeDefault",
    ] {
        match definition(name) {
            mib_rs::ir::Definition::ObjectType(definition) => assert!(matches!(
                definition.defval,
                Some(mib_rs::ir::DefVal::Integer(0))
            )),
            other => panic!("expected object type, got {other:?}"),
        }
    }
    match definition("problemValidUnsignedDefault") {
        mib_rs::ir::Definition::ObjectType(definition) => assert!(matches!(
            definition.defval,
            Some(mib_rs::ir::DefVal::Unsigned(u64::MAX))
        )),
        other => panic!("expected object type, got {other:?}"),
    }

    let oid_default = match definition("problemOverflowOidDefault") {
        mib_rs::ir::Definition::ObjectType(definition) => definition.defval.as_ref().unwrap(),
        other => panic!("expected object type, got {other:?}"),
    };
    assert!(matches!(
        oid_default,
        mib_rs::ir::DefVal::OidValue { components }
            if matches!(
                components.as_slice(),
                [
                    mib_rs::ir::OidComponent::NamedNumber { number: 0, .. },
                    mib_rs::ir::OidComponent::Number { value: 0, .. },
                    mib_rs::ir::OidComponent::QualifiedNamedNumber { number: 0, .. },
                    mib_rs::ir::OidComponent::NamedNumber { number: 0, .. }
                ]
            )
    ));

    let numeric_first_oid_default = match definition("problemOverflowNumericFirstOidDefault") {
        mib_rs::ir::Definition::ObjectType(definition) => definition.defval.as_ref().unwrap(),
        other => panic!("expected object type, got {other:?}"),
    };
    assert!(matches!(
        numeric_first_oid_default,
        mib_rs::ir::DefVal::OidValue { components }
            if matches!(
                components.as_slice(),
                [
                    mib_rs::ir::OidComponent::Number { value: 0, .. },
                    mib_rs::ir::OidComponent::NamedNumber { number: 0, .. }
                ]
            )
    ));

    match definition("problemOverflowTrap") {
        mib_rs::ir::Definition::Notification(definition) => {
            assert_eq!(definition.trap_info.as_ref().unwrap().trap_number, 0);
        }
        other => panic!("expected notification, got {other:?}"),
    }
    assert!(matches!(
        definition("problemAfterOverflow"),
        mib_rs::ir::Definition::ValueAssignment(_)
    ));

    assert_eq!(
        module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagCode::InvalidI64)
            .count(),
        6
    );
    assert_eq!(
        module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagCode::InvalidU32)
            .count(),
        10
    );
}

#[test]
fn base_modules_have_definitions() {
    use mib_rs::lower::base_modules::base_module_names;

    assert_eq!(base_module_names().len(), 7);
    let mib = mib_rs::Loader::new()
        .modules(base_module_names().iter().copied())
        .load()
        .expect("embedded foundation load failed");

    // SNMPv2-SMI should have OIDs and type definitions
    let smi = mib.module("SNMPv2-SMI").expect("missing SNMPv2-SMI");
    assert_eq!(smi.name(), "SNMPv2-SMI");
    assert_eq!(smi.language(), mib_rs::types::Language::SMIv2);
    // Should have iso, internet, enterprises, etc. and Integer32, Counter32, etc.
    for name in ["iso", "internet", "enterprises"] {
        assert!(smi.node(name).is_some(), "missing {name} OID");
    }
    for name in ["Integer32", "Counter32", "Counter64", "IpAddress"] {
        assert!(smi.r#type(name).is_some(), "missing {name} type");
    }

    // SNMPv2-TC should have textual conventions
    let tc = mib.module("SNMPv2-TC").expect("missing SNMPv2-TC");
    assert_eq!(tc.name(), "SNMPv2-TC");
    for name in ["DisplayString", "TruthValue", "RowStatus", "MacAddress"] {
        assert!(tc.r#type(name).is_some(), "missing {name}");
    }

    // SNMPv2-CONF should be empty (MACROs only)
    let conf = mib.module("SNMPv2-CONF").expect("missing SNMPv2-CONF");
    assert_eq!(conf.name(), "SNMPv2-CONF");
    assert_eq!(conf.types().count(), 0);
    assert_eq!(conf.nodes().count(), 0);
    assert_eq!(conf.objects().count(), 0);

    // RFC1155-SMI should have SMIv1 types
    let rfc1155 = mib.module("RFC1155-SMI").expect("missing RFC1155-SMI");
    assert_eq!(rfc1155.name(), "RFC1155-SMI");
    assert_eq!(rfc1155.language(), mib_rs::types::Language::SMIv1);
    assert!(rfc1155.r#type("Counter").is_some(), "missing Counter type");
    assert!(rfc1155.r#type("Gauge").is_some(), "missing Gauge type");
    assert!(rfc1155.node("internet").is_some(), "missing internet OID");

    // Embedded foundations are parsed source, so their definitions retain
    // checked source ranges and their typed embedded origin.
    assert!(
        smi.r#type("Counter32")
            .expect("missing Counter32")
            .range()
            .is_some()
    );
    assert_eq!(smi.source_label(), Some("embedded:SNMPv2-SMI"));

    // RFC-1212 contains ordinary type assignments around its macro body;
    // RFC-1215 contains only its macro definition.
    let rfc1212 = mib.module("RFC-1212").expect("missing RFC-1212");
    assert!(rfc1212.r#type("IndexSyntax").is_some());
    let rfc1215 = mib.module("RFC-1215").expect("missing RFC-1215");
    assert_eq!(rfc1215.types().count(), 0);
    assert_eq!(rfc1215.nodes().count(), 0);
    assert_eq!(rfc1215.objects().count(), 0);
}

#[test]
fn base_module_lookup() {
    assert!(mib_rs::lower::base_modules::is_base_module("SNMPv2-SMI"));
    assert!(mib_rs::lower::base_modules::is_base_module("RFC1155-SMI"));
    assert!(mib_rs::lower::base_modules::is_base_module("RFC-1215"));
    assert!(!mib_rs::lower::base_modules::is_base_module("IF-MIB"));
    assert!(!mib_rs::lower::base_modules::is_base_module(""));
}

#[test]
fn lower_smiv2_module_detects_language() {
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI;

testMIB MODULE-IDENTITY
    LAST-UPDATED "200901080000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "test"
    DESCRIPTION  "test module"
    REVISION     "200901080000Z"
    DESCRIPTION  "Initial version"
    ::= { enterprises 99999 }

END
"#;
    let config = DiagnosticConfig::default();
    let modules = lower_source(source, &config);
    assert_eq!(modules.len(), 1);
    let module = modules.into_iter().next().unwrap();
    assert_eq!(module.language, mib_rs::types::Language::SMIv2);
    assert_eq!(module.name, "TEST-MIB");
    // Should have flattened imports
    assert_eq!(module.imports.len(), 3);
}

#[test]
fn lower_module_identity_without_imports_detects_smiv2_and_runs_checks() {
    let source = br#"
BROKEN-MIB DEFINITIONS ::= BEGIN

brokenMIB MODULE-IDENTITY
    LAST-UPDATED "200901080000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "test"
    DESCRIPTION "test module"
    REVISION "200901080000Z"
    DESCRIPTION "Initial version"
    ::= { enterprises 99999 }

END
"#;
    let config = DiagnosticConfig::default();
    let modules = lower_source(source, &config);
    assert_eq!(modules.len(), 1);
    let module = modules.into_iter().next().unwrap();

    assert_eq!(module.language, mib_rs::types::Language::SMIv2);
    assert_eq!(
        module.definitions.len(),
        1,
        "module should still be lowered"
    );
    assert!(
        module.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == mib_rs::types::DiagCode::MacroNotImported
                && diagnostic.message.contains("MODULE-IDENTITY")
        }),
        "expected the SMIv2 macro import check, got {:?}",
        module.diagnostics
    );
}

#[test]
fn lower_mixed_language_module_runs_identity_date_checks_only() {
    let source = br#"
RAPID-CITY-LIKE DEFINITIONS ::= BEGIN

IMPORTS
    enterprises FROM RFC1155-SMI;

earlyNode OBJECT IDENTIFIER ::= { enterprises 99998 }

hybridMIB MODULE-IDENTITY
    LAST-UPDATED "200901080000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "test"
    DESCRIPTION "test module"
    ::= { enterprises 99999 }

END
"#;
    let config = DiagnosticConfig::default();
    let modules = lower_source(source, &config);
    assert_eq!(modules.len(), 1);
    let module = modules.into_iter().next().unwrap();

    assert_eq!(module.language, mib_rs::types::Language::Unknown);
    assert!(
        module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::RevisionLastUpdated),
        "MODULE-IDENTITY date checks should run despite mixed language evidence: {:?}",
        module.diagnostics
    );

    for smiv2_only in [
        DiagCode::MacroNotImported,
        DiagCode::ModuleNameSuffix,
        DiagCode::ModuleIdentityNotFirst,
    ] {
        assert!(
            module
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != smiv2_only),
            "mixed language evidence should not run {smiv2_only}: {:?}",
            module.diagnostics
        );
    }
}

#[test]
fn lower_unknown_module_validates_each_module_identity_date() {
    let source = br#"
UNKNOWN-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises FROM RFC1155-SMI;

firstIdentity MODULE-IDENTITY
    LAST-UPDATED "invalid"
    ORGANIZATION "Test"
    CONTACT-INFO "test"
    DESCRIPTION "first identity"
    ::= { enterprises 99998 }

secondIdentity MODULE-IDENTITY
    LAST-UPDATED "200901080000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "test"
    DESCRIPTION "second identity"
    ::= { enterprises 99999 }

END
"#;
    let config = DiagnosticConfig::default();
    let modules = lower_source(source, &config);
    assert_eq!(modules.len(), 1);
    let module = modules.into_iter().next().unwrap();

    assert_eq!(module.language, mib_rs::types::Language::Unknown);
    assert_eq!(
        module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagCode::RevisionLastUpdated)
            .count(),
        2,
        "each MODULE-IDENTITY should be checked for a matching revision"
    );
    assert!(
        module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::DateLength),
        "each MODULE-IDENTITY should receive date-format validation"
    );
    assert!(
        module
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != DiagCode::ModuleIdentityMultiple),
        "multiple identity validation remains SMIv2-specific"
    );
}

#[test]
fn lower_other_smiv2_syntax_alone_stays_unknown() {
    let source = br#"
UNKNOWN-MIB DEFINITIONS ::= BEGIN

root OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "An SMIv2-associated construct without conclusive module evidence"
    ::= { iso 3 }

END
"#;
    let config = DiagnosticConfig::default();
    let modules = lower_source(source, &config);
    assert_eq!(modules.len(), 1);
    let module = modules.into_iter().next().unwrap();

    assert_eq!(module.language, mib_rs::types::Language::Unknown);
}

#[test]
fn lower_parsed_base_modules_use_explicit_language() {
    for (name, expected) in [
        ("SNMPv2-SMI", mib_rs::types::Language::SMIv2),
        ("RFC1155-SMI", mib_rs::types::Language::SMIv1),
    ] {
        let source = format!("{name} DEFINITIONS ::= BEGIN\nEND\n");
        let config = DiagnosticConfig::default();
        let modules = lower_source(source.as_bytes(), &config);
        assert_eq!(modules.len(), 1);
        let module = modules.into_iter().next().unwrap();

        assert_eq!(module.language, expected, "base module {name}");
    }
}

#[test]
fn lower_smiv1_module_detects_language() {
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises
        FROM RFC1155-SMI;

testObject OBJECT-TYPE
    SYNTAX INTEGER
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "A test object"
    ::= { enterprises 1 }

END
"#;
    let config = DiagnosticConfig::default();
    let modules = lower_source(source, &config);
    assert_eq!(modules.len(), 1);
    let module = modules.into_iter().next().unwrap();
    assert_eq!(module.language, mib_rs::types::Language::SMIv1);
}

#[test]
fn integer_enum_bounds_are_diagnosed_without_changing_values() {
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN

Boundary ::= INTEGER {
    minimum(-2147483648),
    maximum(2147483647),
    below(-2147483649),
    above(2147483648),
    vendorSentinel(4294967295)
}

END
"#;
    let config = DiagnosticConfig::verbose();
    let module = lower_source(source, &config).into_iter().next().unwrap();

    let syntax = match &module.definitions[0] {
        mib_rs::ir::Definition::TypeDef(def) => &def.syntax,
        other => panic!("expected TypeDef, got {other:?}"),
    };
    let named_numbers = match syntax {
        mib_rs::ir::TypeSyntax::IntegerEnum { named_numbers, .. } => named_numbers,
        other => panic!("expected IntegerEnum, got {other:?}"),
    };
    assert_eq!(
        named_numbers
            .iter()
            .map(|number| number.value)
            .collect::<Vec<_>>(),
        vec![
            i32::MIN.into(),
            i32::MAX.into(),
            -2_147_483_649,
            2_147_483_648,
            4_294_967_295,
        ]
    );

    let diagnostics = module
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagCode::EnumValueOutOfRange)
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 3);
    assert!(
        diagnostics
            .iter()
            .all(|diagnostic| diagnostic.severity == Severity::Warning)
    );
    for value in ["-2147483649", "2147483648", "4294967295"] {
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains(value)),
            "missing bounds diagnostic for {value}: {diagnostics:?}"
        );
    }
}

#[test]
fn integer_enum_bounds_diagnostic_respects_policy() {
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN
VendorEnum ::= INTEGER { vendorSentinel(4294967295) }
END
"#;

    let default_config = DiagnosticConfig::default();
    let default_module = lower_source(source, &default_config)
        .into_iter()
        .next()
        .unwrap();
    assert!(
        default_module
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != DiagCode::EnumValueOutOfRange),
        "warning-level bounds diagnostic should be hidden by default"
    );

    let mut overridden_config = DiagnosticConfig::default();
    overridden_config
        .overrides
        .insert(DiagCode::EnumValueOutOfRange, Severity::Minor);
    let overridden_module = lower_source(source, &overridden_config)
        .into_iter()
        .next()
        .unwrap();
    let diagnostic = overridden_module
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == DiagCode::EnumValueOutOfRange)
        .expect("severity override should collect bounds diagnostic");
    assert_eq!(diagnostic.severity, Severity::Minor);

    let mut ignored_config = DiagnosticConfig::verbose();
    ignored_config
        .ignore
        .push("enum-value-out-of-range".to_string());
    let ignored_module = lower_source(source, &ignored_config)
        .into_iter()
        .next()
        .unwrap();
    assert!(
        ignored_module
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != DiagCode::EnumValueOutOfRange)
    );
}

#[test]
fn lower_trap_type_without_imports_detects_smiv1_and_becomes_notification() {
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN

testTrap TRAP-TYPE
    ENTERPRISE enterprises
    DESCRIPTION "A test trap"
    ::= 1

END
"#;
    let config = DiagnosticConfig::default();
    let module = lower_source(source, &config).into_iter().next().unwrap();

    assert_eq!(module.language, mib_rs::types::Language::SMIv1);
    assert_eq!(module.definitions.len(), 1);
    match &module.definitions[0] {
        mib_rs::ir::Definition::Notification(n) => {
            assert_eq!(n.name, "testTrap");
            assert!(n.trap_info.is_some());
            let info = n.trap_info.as_ref().unwrap();
            assert_eq!(info.enterprise, "enterprises");
            assert_eq!(info.trap_number, 1);
            assert!(n.oid.is_none());
        }
        other => panic!("expected Notification, got {:?}", other),
    }
}
