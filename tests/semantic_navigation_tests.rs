use mib_rs::mib::Symbol;
use mib_rs::source::{ByteOffset, Position, PositionEncoding, memory_modules};
use mib_rs::{DiagnosticConfig, Loader, ResolverStrictness, SemanticSpan, SemanticSpanKind};

fn accepts_root_reexport(_: SemanticSpan<'_>, _: SemanticSpanKind) {}

const BASE: &[u8] = br#"NAV-BASE-MIB DEFINITIONS ::= BEGIN
IMPORTS
    enterprises
        FROM SNMPv2-SMI;

NavText ::= OCTET STRING
NavInteger ::= INTEGER

baseRoot OBJECT IDENTIFIER ::= { enterprises 91000 }

END
"#;

const FORWARD: &[u8] = br#"NAV-FORWARD-MIB DEFINITIONS ::= BEGIN
IMPORTS
    baseRoot
        FROM NAV-BASE-MIB;
END
"#;

const USER_TEXT: &str = r#"-- 😀 navigation fixture
NAV-USER-MIB DEFINITIONS ::= BEGIN
IMPORTS
    baseRoot
        FROM NAV-FORWARD-MIB
    NavText
        FROM NAV-BASE-MIB
    NavInteger
        FROM NAV-BASE-MIB
    MissingSymbol
        FROM NAV-BASE-MIB;

userRoot OBJECT IDENTIFIER ::= { baseRoot 1 }

qualifiedRoot OBJECT IDENTIFIER ::= { NAV-BASE-MIB.baseRoot 2 }

numberedRoot OBJECT IDENTIFIER ::= { iso(1) 3 }

qualifiedNumbered OBJECT IDENTIFIER ::= { NAV-BASE-MIB.baseRoot(91000) 4 }

unknownQualified OBJECT IDENTIFIER ::= { NAV-BASE-MIB.missingQualified 3 }

typedValue OBJECT-TYPE
    SYNTAX NavText
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "typed"
    ::= { userRoot 1 }

restrictedValue OBJECT-TYPE
    SYNTAX NavInteger { one(1), two(2) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "restricted"
    ::= { userRoot 11 }

wrongKindTyped OBJECT-TYPE
    SYNTAX baseRoot
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "wrong kind type"
    ::= { userRoot 16 }

missingImportedTyped OBJECT-TYPE
    SYNTAX MissingSymbol
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "missing imported type"
    ::= { userRoot 17 }

unknownTyped OBJECT-TYPE
    SYNTAX MissingType
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "unknown type"
    ::= { userRoot 2 }

resolvedDefault OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "resolved default"
    DEFVAL { { baseRoot 7 } }
    ::= { userRoot 12 }

annotatedDefault OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "annotated default"
    DEFVAL { { baseRoot(91000) 8 } }
    ::= { userRoot 13 }

qualifiedDefault OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "qualified default"
    DEFVAL { { iso(1) NAV-BASE-MIB.baseRoot 9 } }
    ::= { userRoot 14 }

unresolvedDefault OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "unresolved default"
    DEFVAL { { missingDefaultRoot 10 } }
    ::= { userRoot 15 }

unknownOid OBJECT IDENTIFIER ::= { missingRoot 1 }
wrongKindOid OBJECT IDENTIFIER ::= { NavText 1 }
missingImportedOid OBJECT IDENTIFIER ::= { MissingSymbol 1 }

END
"#;
const USER: &[u8] = USER_TEXT.as_bytes();

const UNIMPORTED_ROOT: &[u8] = br#"NAV-UNIMPORTED-MIB DEFINITIONS ::= BEGIN
unimportedRoot OBJECT IDENTIFIER ::= { enterprises 91919 }
END
"#;

const REFERENCE_TARGET: &[u8] = br#"NAV-REF-TARGET-MIB DEFINITIONS ::= BEGIN
IMPORTS
    enterprises, OBJECT-TYPE, NOTIFICATION-TYPE, Integer32
        FROM SNMPv2-SMI
    OBJECT-GROUP, NOTIFICATION-GROUP
        FROM SNMPv2-CONF;

targetRoot OBJECT IDENTIFIER ::= { enterprises 92000 }

targetObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-create
    STATUS current
    DESCRIPTION "object"
    ::= { targetRoot 1 }

targetNotification NOTIFICATION-TYPE
    STATUS current
    DESCRIPTION "notification"
    ::= { targetRoot 2 }

targetObjectGroup OBJECT-GROUP
    OBJECTS { targetObject }
    STATUS current
    DESCRIPTION "objects"
    ::= { targetRoot 3 }

targetNotificationGroup NOTIFICATION-GROUP
    NOTIFICATIONS { targetNotification }
    STATUS current
    DESCRIPTION "notifications"
    ::= { targetRoot 4 }
END
"#;

const REFERENCE_USER: &[u8] = br#"NAV-REF-USER-MIB DEFINITIONS ::= BEGIN
IMPORTS
    enterprises, OBJECT-TYPE, NOTIFICATION-TYPE, Integer32
        FROM SNMPv2-SMI
    OBJECT-GROUP, NOTIFICATION-GROUP, MODULE-COMPLIANCE, AGENT-CAPABILITIES
        FROM SNMPv2-CONF
    targetRoot, targetObject, targetNotification,
    targetObjectGroup, targetNotificationGroup
        FROM NAV-REF-TARGET-MIB;

userRefRoot OBJECT IDENTIFIER ::= { enterprises 92001 }

LocalAlias ::= Integer32

localNotification NOTIFICATION-TYPE
    STATUS current
    DESCRIPTION "shares targetObject OID"
    ::= { enterprises 92000 1 }

localObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "shares targetNotification OID"
    ::= { enterprises 92000 2 }

mixedObjectGroup OBJECT-GROUP
    OBJECTS { localNotification, targetObject, targetNotification, missingMember }
    STATUS current
    DESCRIPTION "mixed"
    ::= { userRefRoot 1 }

mixedNotificationGroup NOTIFICATION-GROUP
    NOTIFICATIONS { localObject, targetNotification, targetObject, missingNotification }
    STATUS current
    DESCRIPTION "mixed"
    ::= { userRefRoot 2 }

referenceCapabilities AGENT-CAPABILITIES
    PRODUCT-RELEASE "test"
    STATUS current
    DESCRIPTION "references"
    SUPPORTS NAV-REF-TARGET-MIB
        INCLUDES { targetObjectGroup, targetObject, missingInclude }
        VARIATION targetObject
            SYNTAX Integer32
            CREATION-REQUIRES { targetObject, targetNotification, missingCreation }
            DEFVAL { { iso(1) targetRoot(92000) NAV-REF-TARGET-MIB.targetRoot missingVariationRoot 21 } }
            DESCRIPTION "variation"
    ::= { userRefRoot 3 }

referenceCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "nested type references"
    MODULE NAV-REF-TARGET-MIB
        OBJECT targetObject
            SYNTAX Integer32
            WRITE-SYNTAX Integer32
            MIN-ACCESS read-only
            DESCRIPTION "refinement"
    ::= { userRefRoot 4 }
END
"#;

fn load_fixture() -> mib_rs::Mib {
    Loader::new()
        .source(memory_modules([
            ("NAV-BASE-MIB", BASE),
            ("NAV-FORWARD-MIB", FORWARD),
            ("NAV-USER-MIB", USER),
        ]))
        .modules(["NAV-USER-MIB"])
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("navigation fixture should load")
}

fn load_reference_fixture() -> mib_rs::Mib {
    Loader::new()
        .source(memory_modules([
            ("NAV-REF-TARGET-MIB", REFERENCE_TARGET),
            ("NAV-REF-USER-MIB", REFERENCE_USER),
        ]))
        .modules(["NAV-REF-USER-MIB"])
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("reference navigation fixture should load")
}

fn offset(source: &[u8], needle: &[u8], occurrence: usize) -> ByteOffset {
    let start = source
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .nth(occurrence)
        .map(|(index, _)| index)
        .unwrap_or_else(|| panic!("missing occurrence {occurrence} of {:?}", needle));
    ByteOffset::try_from(start).unwrap()
}

#[test]
fn resolves_definitions_imports_oid_components_and_type_references() {
    let mib = load_fixture();
    let module = mib.module("NAV-USER-MIB").unwrap();

    let definition = module.semantic_at(offset(USER, b"typedValue", 0)).unwrap();
    accepts_root_reexport(definition, definition.kind);
    assert_eq!(definition.kind, SemanticSpanKind::Definition);
    assert_eq!(definition.declared_name, "typedValue");
    assert!(matches!(definition.symbol, Some(Symbol::Object(_))));
    assert_eq!(
        definition.module.map(|id| mib.raw().module(id).name()),
        Some("NAV-USER-MIB")
    );

    let forwarded_import = module.semantic_at(offset(USER, b"baseRoot", 0)).unwrap();
    assert_eq!(forwarded_import.kind, SemanticSpanKind::Import);
    assert_eq!(forwarded_import.declared_name, "baseRoot");
    assert_eq!(forwarded_import.symbol.unwrap().name(&mib), "baseRoot");
    assert_eq!(
        forwarded_import
            .module
            .map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let direct_import = module.semantic_at(offset(USER, b"NavText", 0)).unwrap();
    assert_eq!(direct_import.kind, SemanticSpanKind::Import);
    assert!(matches!(direct_import.symbol, Some(Symbol::Type(_))));
    assert_eq!(
        direct_import.module.map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let oid = module.semantic_at(offset(USER, b"baseRoot", 1)).unwrap();
    assert_eq!(oid.kind, SemanticSpanKind::OidReference);
    assert_eq!(oid.declared_name, "baseRoot");
    assert_eq!(oid.symbol.unwrap().name(&mib), "baseRoot");

    let qualified = module
        .semantic_at(offset(USER, b"NAV-BASE-MIB.baseRoot", 0))
        .unwrap();
    assert_eq!(qualified.kind, SemanticSpanKind::OidReference);
    assert_eq!(qualified.declared_name, "NAV-BASE-MIB.baseRoot");
    assert_eq!(
        module.source().unwrap().slice(qualified.range).unwrap(),
        b"NAV-BASE-MIB.baseRoot"
    );
    assert_eq!(qualified.symbol.unwrap().name(&mib), "baseRoot");
    assert_eq!(
        qualified.module.map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let named_number = module.semantic_at(offset(USER, b"iso(1)", 0)).unwrap();
    assert_eq!(named_number.kind, SemanticSpanKind::OidReference);
    assert_eq!(named_number.declared_name, "iso");
    assert_eq!(
        module.source().unwrap().slice(named_number.range).unwrap(),
        b"iso"
    );

    let qualified_number = module
        .semantic_at(offset(USER, b"NAV-BASE-MIB.baseRoot(91000)", 0))
        .unwrap();
    assert_eq!(qualified_number.kind, SemanticSpanKind::OidReference);
    assert_eq!(qualified_number.declared_name, "NAV-BASE-MIB.baseRoot");
    assert_eq!(
        module
            .source()
            .unwrap()
            .slice(qualified_number.range)
            .unwrap(),
        b"NAV-BASE-MIB.baseRoot"
    );

    let type_reference = module.semantic_at(offset(USER, b"NavText", 1)).unwrap();
    assert_eq!(type_reference.kind, SemanticSpanKind::TypeReference);
    assert_eq!(type_reference.declared_name, "NavText");
    assert!(matches!(type_reference.symbol, Some(Symbol::Type(_))));
    assert_eq!(
        module
            .source()
            .unwrap()
            .slice(type_reference.range)
            .unwrap(),
        b"NavText"
    );

    let restricted_base = module.semantic_at(offset(USER, b"NavInteger", 1)).unwrap();
    assert_eq!(restricted_base.kind, SemanticSpanKind::TypeReference);
    assert_eq!(restricted_base.declared_name, "NavInteger");
    assert!(matches!(restricted_base.symbol, Some(Symbol::Type(_))));
    assert_eq!(
        module
            .source()
            .unwrap()
            .slice(restricted_base.range)
            .unwrap(),
        b"NavInteger"
    );
}

#[test]
fn unresolved_references_keep_exact_declared_name_and_range() {
    let mib = load_fixture();
    let module = mib.module("NAV-USER-MIB").unwrap();
    let source = module.source().unwrap();

    let missing_import = module
        .semantic_at(offset(USER, b"MissingSymbol", 0))
        .unwrap();
    assert_eq!(missing_import.kind, SemanticSpanKind::Import);
    assert_eq!(missing_import.declared_name, "MissingSymbol");
    assert_eq!(
        source.slice(missing_import.range).unwrap(),
        b"MissingSymbol"
    );
    assert_eq!(missing_import.symbol, None);
    assert_eq!(
        missing_import.module.map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let missing_type = module.semantic_at(offset(USER, b"MissingType", 0)).unwrap();
    assert_eq!(missing_type.kind, SemanticSpanKind::TypeReference);
    assert_eq!(missing_type.declared_name, "MissingType");
    assert_eq!(source.slice(missing_type.range).unwrap(), b"MissingType");
    assert_eq!(missing_type.symbol, None);
    assert_eq!(missing_type.module, None);

    let missing_oid = module.semantic_at(offset(USER, b"missingRoot", 0)).unwrap();
    assert_eq!(missing_oid.kind, SemanticSpanKind::OidReference);
    assert_eq!(missing_oid.declared_name, "missingRoot");
    assert_eq!(source.slice(missing_oid.range).unwrap(), b"missingRoot");
    assert_eq!(missing_oid.symbol, None);
    assert_eq!(missing_oid.module, None);

    let wrong_type = module
        .semantic_at(offset(USER, b"baseRoot\n    MAX-ACCESS", 0))
        .unwrap();
    assert_eq!(wrong_type.kind, SemanticSpanKind::TypeReference);
    assert!(matches!(wrong_type.symbol, Some(Symbol::Node(_))));
    assert_eq!(
        wrong_type.module.map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let missing_imported_type = module
        .semantic_at(offset(USER, b"MissingSymbol\n    MAX-ACCESS", 0))
        .unwrap();
    assert_eq!(missing_imported_type.kind, SemanticSpanKind::TypeReference);
    assert_eq!(missing_imported_type.symbol, None);
    assert_eq!(
        missing_imported_type
            .module
            .map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let wrong_oid = module.semantic_at(offset(USER, b"NavText 1 }", 0)).unwrap();
    assert_eq!(wrong_oid.kind, SemanticSpanKind::OidReference);
    assert!(matches!(wrong_oid.symbol, Some(Symbol::Type(_))));
    assert_eq!(
        wrong_oid.module.map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let missing_imported_oid = module
        .semantic_at(offset(USER, b"MissingSymbol 1 }", 0))
        .unwrap();
    assert_eq!(missing_imported_oid.kind, SemanticSpanKind::OidReference);
    assert_eq!(missing_imported_oid.symbol, None);
    assert_eq!(
        missing_imported_oid
            .module
            .map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );

    let missing_qualified = module
        .semantic_at(offset(USER, b"NAV-BASE-MIB.missingQualified", 0))
        .unwrap();
    assert_eq!(missing_qualified.kind, SemanticSpanKind::OidReference);
    assert_eq!(
        missing_qualified.declared_name,
        "NAV-BASE-MIB.missingQualified"
    );
    assert_eq!(missing_qualified.symbol, None);
    assert_eq!(
        missing_qualified
            .module
            .map(|id| mib.raw().module(id).name()),
        Some("NAV-BASE-MIB")
    );
}

#[test]
fn object_type_defval_oid_components_are_indexed() {
    let mib = load_fixture();
    let module = mib.module("NAV-USER-MIB").unwrap();
    let source = module.source().unwrap();

    let resolved = module.semantic_at(offset(USER, b"baseRoot 7", 0)).unwrap();
    assert_eq!(resolved.kind, SemanticSpanKind::OidReference);
    assert_eq!(resolved.declared_name, "baseRoot");
    assert_eq!(resolved.symbol.unwrap().name(&mib), "baseRoot");

    let annotated = module
        .semantic_at(offset(USER, b"baseRoot(91000) 8", 0))
        .unwrap();
    assert_eq!(annotated.kind, SemanticSpanKind::OidReference);
    assert_eq!(source.slice(annotated.range).unwrap(), b"baseRoot");

    let qualified = module
        .semantic_at(offset(USER, b"NAV-BASE-MIB.baseRoot 9", 0))
        .unwrap();
    assert_eq!(qualified.kind, SemanticSpanKind::OidReference);
    assert_eq!(qualified.declared_name, "NAV-BASE-MIB.baseRoot");
    assert_eq!(qualified.symbol.unwrap().name(&mib), "baseRoot");

    let unresolved = module
        .semantic_at(offset(USER, b"missingDefaultRoot", 0))
        .unwrap();
    assert_eq!(unresolved.kind, SemanticSpanKind::OidReference);
    assert_eq!(unresolved.declared_name, "missingDefaultRoot");
    assert_eq!(
        source.slice(unresolved.range).unwrap(),
        b"missingDefaultRoot"
    );
    assert_eq!(unresolved.symbol, None);
}

#[test]
fn oid_navigation_mirrors_constrained_smi_root_fallbacks() {
    let load = |strictness| {
        Loader::new()
            .source(mib_rs::source::memory(
                "NAV-UNIMPORTED-MIB",
                UNIMPORTED_ROOT,
            ))
            .modules(["NAV-UNIMPORTED-MIB"])
            .resolver_strictness(strictness)
            .diagnostic_config(DiagnosticConfig::silent())
            .load()
            .unwrap()
    };

    for strictness in [ResolverStrictness::Normal, ResolverStrictness::Permissive] {
        let mib = load(strictness);
        let span = mib
            .module("NAV-UNIMPORTED-MIB")
            .unwrap()
            .semantic_at(offset(UNIMPORTED_ROOT, b"enterprises", 0))
            .unwrap();
        assert_eq!(span.kind, SemanticSpanKind::OidReference);
        assert_eq!(span.symbol.unwrap().name(&mib), "enterprises");
        assert_eq!(
            span.module.map(|id| mib.raw().module(id).name()),
            Some("SNMPv2-SMI")
        );
    }

    let strict = load(ResolverStrictness::Strict);
    let span = strict
        .module("NAV-UNIMPORTED-MIB")
        .unwrap()
        .semantic_at(offset(UNIMPORTED_ROOT, b"enterprises", 0))
        .unwrap();
    assert_eq!(span.symbol, None);
    assert_eq!(span.module, None);
}

#[test]
fn retained_name_refs_keep_exact_identity_scope_kind_and_order() {
    let mib = load_reference_fixture();
    let module = mib.module("NAV-REF-USER-MIB").unwrap();
    let target_module = mib.module("NAV-REF-TARGET-MIB").unwrap().id();

    let cases = [
        ("localNotification", 1, "localNotification", "Notification"),
        ("targetObject", 3, "targetObject", "Object"),
        (
            "targetNotification",
            3,
            "targetNotification",
            "Notification",
        ),
        ("missingMember", 0, "missingMember", "Missing"),
        ("localObject", 1, "localObject", "Object"),
        (
            "targetNotification",
            4,
            "targetNotification",
            "Notification",
        ),
        ("targetObject", 4, "targetObject", "Object"),
        ("missingNotification", 0, "missingNotification", "Missing"),
        ("targetObjectGroup", 1, "targetObjectGroup", "Group"),
        ("targetObject", 6, "targetObject", "Object"),
        ("missingInclude", 0, "missingInclude", "MissingTarget"),
        ("targetObject", 8, "targetObject", "Object"),
        (
            "targetNotification",
            5,
            "targetNotification",
            "Notification",
        ),
        ("missingCreation", 0, "missingCreation", "MissingTarget"),
    ];

    for (needle, occurrence, expected_name, expected_kind) in cases {
        let span = module
            .semantic_at(offset(REFERENCE_USER, needle.as_bytes(), occurrence))
            .unwrap_or_else(|| panic!("missing span for {needle} occurrence {occurrence}"));
        assert_eq!(
            span.kind,
            SemanticSpanKind::SymbolReference,
            "{needle} occurrence {occurrence}"
        );
        assert_eq!(span.declared_name, expected_name);
        assert_eq!(
            module.source().unwrap().slice(span.range).unwrap(),
            expected_name.as_bytes()
        );
        match expected_kind {
            "Object" => assert!(matches!(span.symbol, Some(Symbol::Object(_)))),
            "Notification" => {
                assert!(matches!(span.symbol, Some(Symbol::Notification(_))))
            }
            "Group" => assert!(matches!(span.symbol, Some(Symbol::Group(_)))),
            "Missing" => {
                assert_eq!(span.symbol, None);
                assert_eq!(span.module, None);
            }
            "MissingTarget" => {
                assert_eq!(span.symbol, None);
                assert_eq!(span.module, Some(target_module));
            }
            _ => unreachable!(),
        }
    }

    let variation_defval = module
        .semantic_at(offset(
            REFERENCE_USER,
            b"NAV-REF-TARGET-MIB.targetRoot missingVariationRoot",
            0,
        ))
        .unwrap();
    assert_eq!(variation_defval.kind, SemanticSpanKind::OidReference);
    assert_eq!(
        variation_defval.declared_name,
        "NAV-REF-TARGET-MIB.targetRoot"
    );
    assert_eq!(variation_defval.module, Some(target_module));
    assert_eq!(variation_defval.symbol.unwrap().name(&mib), "targetRoot");

    let variation_annotated = module
        .semantic_at(offset(REFERENCE_USER, b"targetRoot(92000)", 0))
        .unwrap();
    assert_eq!(variation_annotated.kind, SemanticSpanKind::OidReference);
    assert_eq!(variation_annotated.declared_name, "targetRoot");
    assert_eq!(variation_annotated.module, Some(target_module));
    assert_eq!(
        module
            .source()
            .unwrap()
            .slice(variation_annotated.range)
            .unwrap(),
        b"targetRoot"
    );

    let variation_unresolved = module
        .semantic_at(offset(REFERENCE_USER, b"missingVariationRoot", 0))
        .unwrap();
    assert_eq!(variation_unresolved.kind, SemanticSpanKind::OidReference);
    assert_eq!(variation_unresolved.declared_name, "missingVariationRoot");
    assert_eq!(variation_unresolved.symbol, None);
    assert_eq!(variation_unresolved.module, None);

    for needle in [
        b"LocalAlias ::= Integer32".as_slice(),
        b"SYNTAX Integer32\n            CREATION".as_slice(),
        b"SYNTAX Integer32\n            WRITE-SYNTAX".as_slice(),
        b"WRITE-SYNTAX Integer32".as_slice(),
    ] {
        let offset = offset(REFERENCE_USER, needle, 0);
        let integer = needle
            .windows(b"Integer32".len())
            .position(|window| window == b"Integer32")
            .unwrap();
        let span = module
            .semantic_at(ByteOffset::new(offset.get() + integer as u32))
            .unwrap();
        assert_eq!(span.kind, SemanticSpanKind::TypeReference);
        assert_eq!(span.declared_name, "Integer32");
        assert!(matches!(span.symbol, Some(Symbol::Type(_))));
    }
}

#[test]
fn boundaries_source_identity_and_editor_positions_are_explicit() {
    let mib = load_fixture();
    let module = mib.module("NAV-USER-MIB").unwrap();
    let source = module.source().unwrap();
    let target = offset(USER, b"NavText", 1);
    let context = module.semantic_at(target).unwrap();

    assert_eq!(
        module.semantic_at(context.range.end()).unwrap().kind,
        SemanticSpanKind::Definition
    );
    assert!(module.semantic_at(source.len()).is_none());
    assert!(
        module
            .semantic_at(ByteOffset::new(source.len().get() + 1))
            .is_none()
    );
    assert!(module.semantic_at(ByteOffset::new(0)).is_none());

    let foreign_source = mib.module("NAV-BASE-MIB").unwrap().source_id().unwrap();
    assert!(module.semantic_at_source(foreign_source, target).is_none());
    assert_eq!(
        module
            .semantic_at_source(module.source_id().unwrap(), target)
            .unwrap()
            .declared_name,
        "NavText"
    );

    let target_position = source.position(target, PositionEncoding::Utf16).unwrap();
    assert_eq!(
        module
            .semantic_at_source_position(
                foreign_source,
                Position::new(u32::MAX, u32::MAX),
                PositionEncoding::Utf16,
            )
            .unwrap(),
        None,
        "a source mismatch is reported before position conversion"
    );
    assert_eq!(
        module
            .semantic_at_source_position(
                module.source_id().unwrap(),
                target_position,
                PositionEncoding::Utf16,
            )
            .unwrap()
            .unwrap()
            .declared_name,
        "NavText"
    );

    for encoding in [
        PositionEncoding::Utf8,
        PositionEncoding::Utf16,
        PositionEncoding::Utf32,
    ] {
        let position = source.position(target, encoding).unwrap();
        assert_eq!(
            module
                .semantic_at_position(position, encoding)
                .unwrap()
                .unwrap()
                .declared_name,
            "NavText"
        );
    }

    assert!(
        module
            .semantic_at_position(Position::new(0, 4), PositionEncoding::Utf8)
            .is_err(),
        "a UTF-8 position in the middle of the emoji must be rejected"
    );
    assert!(
        module
            .semantic_at_position(Position::new(u32::MAX, 0), PositionEncoding::Utf16)
            .is_err()
    );
}

#[test]
fn module_header_trivia_and_embedded_sources_have_defined_behavior() {
    let mib = load_fixture();
    let module = mib.module("NAV-USER-MIB").unwrap();
    assert!(
        module
            .semantic_at(offset(USER, b"NAV-USER-MIB", 0))
            .is_none()
    );
    assert!(module.semantic_at(ByteOffset::new(1)).is_none());
    let between_definitions = offset(USER, b"\n\nqualifiedRoot", 0);
    assert!(
        module
            .semantic_at(ByteOffset::new(between_definitions.get() + 1))
            .is_none()
    );
    assert!(module.semantic_at(offset(USER, b"END", 0)).is_none());

    let embedded = Loader::new()
        .modules(["SNMPv2-SMI"])
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("embedded base module should load");
    let base = embedded.module("SNMPv2-SMI").unwrap();
    let source = base.source().expect("embedded source is retained");
    let enterprises = source
        .bytes()
        .windows(b"enterprises".len())
        .position(|window| window == b"enterprises")
        .unwrap();
    assert!(
        base.semantic_at(ByteOffset::try_from(enterprises).unwrap())
            .is_some()
    );
}
