use mib_rs::Loader;

#[test]
fn loading_nothing_still_requires_a_source() {
    assert!(matches!(
        Loader::new().load(),
        Err(mib_rs::LoadError::NoSources)
    ));
}

#[test]
fn requested_foundation_module_loads_without_configured_sources() {
    let mib = Loader::new()
        .modules(["SNMPv2-SMI"])
        .load()
        .expect("embedded foundation load failed");

    let module = mib.module("SNMPv2-SMI").expect("SNMPv2-SMI not loaded");
    assert!(module.is_base());
    assert_eq!(module.source_path(), "embedded:SNMPv2-SMI");
    assert!(module.r#type("Counter32").is_some());
    assert!(module.node("enterprises").is_some());
}

#[test]
fn configured_foundation_module_overrides_embedded_fallback() {
    let content = include_bytes!("../testdata/corpus/primary/ietf/SNMPv2-SMI.mib");
    let mib = Loader::new()
        .source(mib_rs::source::memory("SNMPv2-SMI", content.as_slice()))
        .modules(["SNMPv2-SMI"])
        .load()
        .expect("configured foundation load failed");

    let module = mib.module("SNMPv2-SMI").expect("SNMPv2-SMI not loaded");
    assert_eq!(module.source_path(), "<memory:SNMPv2-SMI>");
    assert_eq!(
        mib.node("iso")
            .expect("well-known root not loaded")
            .module()
            .expect("well-known root has no owner")
            .name(),
        "SNMPv2-SMI"
    );
}

#[test]
fn imports_use_embedded_foundations_as_fallbacks() {
    let content = br#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises, OBJECT-TYPE
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

testRoot OBJECT IDENTIFIER ::= { enterprises 99999 }

testValue OBJECT-TYPE
    SYNTAX      DisplayString
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "test"
    ::= { testRoot 1 }

END
"#;
    let mib = Loader::new()
        .source(mib_rs::source::memory("TEST-MIB", content.as_slice()))
        .modules(["TEST-MIB"])
        .load()
        .expect("load with embedded dependencies failed");

    assert!(mib.module("TEST-MIB").is_some());
    assert_eq!(
        mib.module("SNMPv2-TC")
            .expect("SNMPv2-TC not loaded")
            .source_path(),
        "embedded:SNMPv2-TC"
    );
    assert!(mib.object("testValue").is_some());
}

#[test]
fn parsed_application_types_keep_their_semantic_kinds() {
    let mib = Loader::new()
        .modules(["SNMPv2-SMI"])
        .load()
        .expect("embedded foundation load failed");
    let module = mib.module("SNMPv2-SMI").expect("SNMPv2-SMI not loaded");

    let cases = [
        ("Counter32", mib_rs::types::BaseType::Counter32),
        ("Counter64", mib_rs::types::BaseType::Counter64),
        ("Gauge32", mib_rs::types::BaseType::Gauge32),
        ("Unsigned32", mib_rs::types::BaseType::Unsigned32),
        ("TimeTicks", mib_rs::types::BaseType::TimeTicks),
        ("IpAddress", mib_rs::types::BaseType::IpAddress),
        ("Opaque", mib_rs::types::BaseType::Opaque),
    ];
    for (name, expected) in cases {
        let ty = module
            .r#type(name)
            .unwrap_or_else(|| panic!("missing type {name}"));
        assert_eq!(ty.effective_base(), expected, "type {name}");
    }
}

#[test]
fn embedded_smiv1_choice_types_parse_without_errors() {
    let mib = Loader::new()
        .modules(["RFC1155-SMI", "RFC1065-SMI"])
        .load()
        .expect("embedded foundation load failed");

    for name in ["RFC1155-SMI", "RFC1065-SMI"] {
        let module = mib.module(name).unwrap_or_else(|| panic!("missing {name}"));
        assert!(module.r#type("SimpleSyntax").is_some(), "module {name}");
        assert!(
            module
                .r#type("ObjectSyntax")
                .expect("missing ObjectSyntax")
                .effective_ranges()
                .is_empty(),
            "module {name}"
        );
    }
}
