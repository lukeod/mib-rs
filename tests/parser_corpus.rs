// Integration tests: parse the shared MIB corpus and verify no parse errors.

mod common;

use mib_rs::ast::Definition;
use mib_rs::types::{DiagCode, DiagnosticConfig};
use std::path::Path;

use common::{collect_mib_files, corpus_dir, problems_dir};

fn parse_file(path: &Path) -> Vec<mib_rs::ast::Module> {
    let content = std::fs::read(path).unwrap();
    mib_rs::parser::parse(&content, &DiagnosticConfig::default())
}

fn parse_errors(modules: &[mib_rs::ast::Module]) -> Vec<String> {
    modules
        .iter()
        .flat_map(|m| m.diagnostics.iter())
        .filter(|d| d.code == DiagCode::ParseError)
        .map(|d| d.message.clone())
        .collect()
}

// --- Corpus tests ---

#[test]
fn primary_corpus_no_parse_errors() {
    let dir = corpus_dir();
    if !dir.exists() {
        eprintln!("corpus dir not found, skipping: {}", dir.display());
        return;
    }

    let files = collect_mib_files(&dir);
    assert!(!files.is_empty(), "no MIB files found in corpus");

    let mut failures = Vec::new();
    let mut total_defs = 0;

    for path in &files {
        let modules = parse_file(path);
        total_defs += modules.iter().map(|m| m.body.len()).sum::<usize>();
        let errors = parse_errors(&modules);
        if !errors.is_empty() {
            let rel = path.strip_prefix(&dir).unwrap_or(path);
            failures.push(format!(
                "{}: {:?}",
                rel.display(),
                &errors[..errors.len().min(3)]
            ));
        }
    }

    assert!(
        total_defs > 80000,
        "expected 80k+ definitions, got {total_defs}"
    );

    if !failures.is_empty() {
        panic!(
            "{}/{} files had parse errors:\n{}",
            failures.len(),
            files.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn problems_corpus_no_parse_errors() {
    let dir = problems_dir();
    if !dir.exists() {
        eprintln!("problems dir not found, skipping: {}", dir.display());
        return;
    }

    let files = collect_mib_files(&dir);
    assert!(!files.is_empty(), "no MIB files found in problems corpus");

    let mut failures = Vec::new();

    for path in &files {
        let modules = parse_file(path);
        let errors = parse_errors(&modules);
        if !errors.is_empty() {
            let rel = path.strip_prefix(&dir).unwrap_or(path);
            failures.push(format!(
                "{}: {:?}",
                rel.display(),
                &errors[..errors.len().min(3)]
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} problem files had parse errors:\n{}",
            failures.len(),
            files.len(),
            failures.join("\n")
        );
    }
}

// --- Key MIB-specific tests ---

#[test]
fn parse_snmpv2_smi() {
    let path = corpus_dir().join("ietf/SNMPv2-SMI.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "SNMPv2-SMI");
    assert!(
        parse_errors(&modules).is_empty(),
        "SNMPv2-SMI had parse errors"
    );

    // SNMPv2-SMI defines type assignments with type keywords on LHS
    // (IpAddress, Counter32, Gauge32, etc.)
    let type_assignments: Vec<_> = modules[0]
        .body
        .iter()
        .filter_map(|d| match d {
            Definition::TypeAssignment(ta) => Some(ta.name.name.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        type_assignments.contains(&"IpAddress"),
        "should parse IpAddress type assignment"
    );
    assert!(
        type_assignments.contains(&"Counter32"),
        "should parse Counter32 type assignment"
    );
    assert!(
        type_assignments.contains(&"Gauge32"),
        "should parse Gauge32 type assignment"
    );
    assert!(
        type_assignments.contains(&"TimeTicks"),
        "should parse TimeTicks type assignment"
    );
    assert!(
        type_assignments.contains(&"Opaque"),
        "should parse Opaque type assignment"
    );
    assert!(
        type_assignments.contains(&"Counter64"),
        "should parse Counter64 type assignment"
    );
}

#[test]
fn parse_if_mib() {
    let path = corpus_dir().join("ietf/IF-MIB.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "IF-MIB");
    assert!(parse_errors(&modules).is_empty());

    // IF-MIB has MODULE-IDENTITY, many OBJECT-TYPEs, OBJECT-GROUPs, MODULE-COMPLIANCE
    let has_module_identity = modules[0]
        .body
        .iter()
        .any(|d| matches!(d, Definition::ModuleIdentity(_)));
    assert!(has_module_identity, "IF-MIB should have MODULE-IDENTITY");

    let object_count = modules[0]
        .body
        .iter()
        .filter(|d| matches!(d, Definition::ObjectType(_)))
        .count();
    assert!(
        object_count > 20,
        "IF-MIB should have 20+ OBJECT-TYPEs, got {object_count}"
    );
}

#[test]
fn parse_snmpv2_tc() {
    let path = corpus_dir().join("ietf/SNMPv2-TC.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "SNMPv2-TC");
    assert!(parse_errors(&modules).is_empty());

    // SNMPv2-TC defines many TEXTUAL-CONVENTIONs
    let tc_count = modules[0]
        .body
        .iter()
        .filter(|d| matches!(d, Definition::TextualConvention(_)))
        .count();
    assert!(tc_count > 5, "SNMPv2-TC should have TCs, got {tc_count}");
}

#[test]
fn parse_snmpv2_conf() {
    let path = corpus_dir().join("ietf/SNMPv2-CONF.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "SNMPv2-CONF");
    assert!(parse_errors(&modules).is_empty());

    // SNMPv2-CONF defines MACRO definitions
    let macro_count = modules[0]
        .body
        .iter()
        .filter(|d| matches!(d, Definition::MacroDefinition(_)))
        .count();
    assert!(
        macro_count > 0,
        "SNMPv2-CONF should have MACRO definitions, got {macro_count}"
    );
}

#[test]
fn parse_rfc1155_smi() {
    let path = corpus_dir().join("ietf/RFC1155-SMI.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "RFC1155-SMI");
    assert!(parse_errors(&modules).is_empty());
}

#[test]
fn parse_entity_mib() {
    let path = corpus_dir().join("ietf/ENTITY-MIB.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "ENTITY-MIB");
    assert!(parse_errors(&modules).is_empty());

    // ENTITY-MIB has AGENT-CAPABILITIES
    // Not all versions have AGENT-CAPABILITIES, just check no errors
    let _has_agent_caps = modules[0]
        .body
        .iter()
        .any(|d| matches!(d, Definition::AgentCapabilities(_)));
}

#[test]
fn parse_cisco_smi() {
    let path = corpus_dir().join("cisco/CISCO-SMI.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "CISCO-SMI");
    assert!(parse_errors(&modules).is_empty());
}

#[test]
fn parse_juniper_mibs() {
    let dir = corpus_dir().join("juniper");
    if !dir.exists() {
        return;
    }
    let files = collect_mib_files(&dir);
    for path in &files {
        let modules = parse_file(path);
        let errors = parse_errors(&modules);
        assert!(
            errors.is_empty(),
            "juniper/{} had parse errors: {:?}",
            path.file_name().unwrap().to_string_lossy(),
            errors
        );
    }
}

#[test]
fn parse_multimodule_file() {
    let path = problems_dir().join("PROBLEM-MULTIMOD.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert!(
        modules.len() >= 2,
        "PROBLEM-MULTIMOD should contain multiple modules, got {}",
        modules.len()
    );
    for m in &modules {
        assert!(
            m.name.is_some(),
            "all modules should parse successfully"
        );
    }
}

#[test]
fn parse_fs_mib_tolerates_missing_commas() {
    let path = corpus_dir().join("misc/FS-MIB.mib");
    if !path.exists() {
        return;
    }
    let modules = parse_file(&path);
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name.as_ref().unwrap().name, "FS-MIB");
    assert!(
        parse_errors(&modules).is_empty(),
        "FS-MIB should parse without errors (missing commas tolerated)"
    );
    // FS-MIB has 2000+ definitions
    assert!(
        modules[0].body.len() > 2000,
        "expected 2000+ defs, got {}",
        modules[0].body.len()
    );
}

// --- Parser feature tests with synthetic input ---

#[test]
fn type_keyword_as_type_assignment_name() {
    // Type keywords like IpAddress, Counter32 etc. can appear on LHS of ::=
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
Gauge32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING
Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)
Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());
    assert_eq!(modules[0].body.len(), 7);

    // All should be TypeAssignment
    for def in &modules[0].body {
        assert!(
            matches!(def, Definition::TypeAssignment(_)),
            "expected TypeAssignment, got {:?}",
            def.name()
        );
    }
}

#[test]
fn named_number_missing_comma_tolerated() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX INTEGER { alpha(1) beta(2) gamma(3) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Missing commas in enum."
    ::= { test 1 }
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());

    match &modules[0].body[0] {
        Definition::ObjectType(d) => {
            let syntax = d.syntax.as_ref().unwrap();
            match &syntax.syntax {
                mib_rs::ast::TypeSyntax::IntegerEnum { named_numbers, .. } => {
                    assert_eq!(named_numbers.len(), 3, "should parse all 3 named numbers");
                    assert_eq!(named_numbers[0].name.name, "alpha");
                    assert_eq!(named_numbers[1].name.name, "beta");
                    assert_eq!(named_numbers[2].name.name, "gamma");
                }
                other => panic!("expected IntegerEnum, got {:?}", other),
            }
        }
        other => panic!("expected ObjectType, got {:?}", other),
    }
}

#[test]
fn bits_named_numbers_missing_comma() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
TestBits ::= TEXTUAL-CONVENTION
    STATUS current
    DESCRIPTION "Bits with missing commas."
    SYNTAX BITS { alpha(0) beta(1) gamma(2) }
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());

    match &modules[0].body[0] {
        Definition::TextualConvention(d) => match &d.syntax.syntax {
            mib_rs::ast::TypeSyntax::Bits { named_bits, .. } => {
                assert_eq!(named_bits.len(), 3);
            }
            other => panic!("expected Bits, got {:?}", other),
        },
        other => panic!("expected TextualConvention, got {:?}", other),
    }
}

#[test]
fn tagged_type_with_constraint() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
TestTagged ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());

    match &modules[0].body[0] {
        Definition::TypeAssignment(d) => {
            assert_eq!(d.name.name, "TestTagged");
            // Should be Tagged -> Constrained -> OctetString
            match &d.syntax {
                mib_rs::ast::TypeSyntax::Tagged { underlying, .. } => {
                    assert!(
                        matches!(
                            underlying.as_ref(),
                            mib_rs::ast::TypeSyntax::Constrained { .. }
                        ),
                        "expected constrained underlying type"
                    );
                }
                other => panic!("expected Tagged, got {:?}", other),
            }
        }
        other => panic!("expected TypeAssignment, got {:?}", other),
    }
}

#[test]
fn module_compliance_with_refinements() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
testCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "Test compliance."
    MODULE
        MANDATORY-GROUPS { testGroup }
        GROUP testOptGroup
            DESCRIPTION "Optional group."
        OBJECT testObj
            SYNTAX INTEGER (0..100)
            MIN-ACCESS read-only
            DESCRIPTION "Object refinement."
    ::= { test 1 }
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());

    match &modules[0].body[0] {
        Definition::ModuleCompliance(d) => {
            assert_eq!(d.modules.len(), 1);
            assert_eq!(d.modules[0].mandatory_groups.len(), 1);
            assert_eq!(d.modules[0].compliances.len(), 2);
        }
        other => panic!("expected ModuleCompliance, got {:?}", other),
    }
}

#[test]
fn agent_capabilities_with_variations() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
testAgent AGENT-CAPABILITIES
    PRODUCT-RELEASE "1.0"
    STATUS current
    DESCRIPTION "Test agent."
    SUPPORTS IF-MIB
        INCLUDES { ifGeneralGroup }
        VARIATION ifAdminStatus
            SYNTAX INTEGER { up(1), down(2) }
            ACCESS read-only
            DESCRIPTION "Limited."
    ::= { test 1 }
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());

    match &modules[0].body[0] {
        Definition::AgentCapabilities(d) => {
            assert_eq!(d.supports.len(), 1);
            assert_eq!(d.supports[0].variations.len(), 1);
        }
        other => panic!("expected AgentCapabilities, got {:?}", other),
    }
}

#[test]
fn error_recovery_preserves_subsequent_definitions() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
brokenDef OBJECT-TYPE
    SYNTAX !!!GARBAGE!!!
    ::= { test 1 }
goodDef OBJECT IDENTIFIER ::= { iso 3 }
anotherGood OBJECT-TYPE
    SYNTAX INTEGER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Good."
    ::= { test 2 }
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);

    // Should have recovered and parsed subsequent definitions
    let good_defs: Vec<_> = modules[0]
        .body
        .iter()
        .filter(|d| !matches!(d, Definition::Error(_)))
        .collect();
    assert!(
        good_defs.len() >= 2,
        "should recover and parse 2+ good defs, got {}",
        good_defs.len()
    );
}

#[test]
fn defval_variants() {
    let input = br#"TEST-MIB DEFINITIONS ::= BEGIN
intDef OBJECT-TYPE
    SYNTAX INTEGER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Integer DEFVAL."
    DEFVAL { 42 }
    ::= { test 1 }
strDef OBJECT-TYPE
    SYNTAX OCTET STRING
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "String DEFVAL."
    DEFVAL { "hello" }
    ::= { test 2 }
bitsDef OBJECT-TYPE
    SYNTAX BITS { alpha(0), beta(1) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Bits DEFVAL."
    DEFVAL { { alpha, beta } }
    ::= { test 3 }
oidDef OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "OID DEFVAL."
    DEFVAL { { 1 3 6 1 } }
    ::= { test 4 }
END
"#;
    let modules = mib_rs::parser::parse(input, &DiagnosticConfig::default());
    assert_eq!(modules.len(), 1);
    assert!(parse_errors(&modules).is_empty());
    assert_eq!(modules[0].body.len(), 4);
}
