// Integration tests: lower the shared MIB corpus and verify basic properties.

use mib_rs::types::DiagnosticConfig;
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

fn collect_mib_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some("mib" | "smi" | "txt" | "my") = path.extension().and_then(|e| e.to_str()) {
            files.push(path.to_path_buf());
        }
    }
    files
}

fn parse_and_lower(path: &Path) -> Vec<mib_rs::ir::Module> {
    let content = std::fs::read(path).unwrap();
    let config = DiagnosticConfig::default();
    let ast_modules = mib_rs::parser::parse(&content, config.clone());
    ast_modules
        .into_iter()
        .map(|m| mib_rs::lower::lower(m, &content, &config))
        .collect()
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
            // Language should be detected
            assert_ne!(
                module.language,
                mib_rs::types::Language::Unknown,
                "module {} has unknown language in {:?}",
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
fn base_modules_have_definitions() {
    let base_modules = mib_rs::lower::base_modules::create_base_modules();
    assert_eq!(base_modules.len(), 7);

    // SNMPv2-SMI should have OIDs and type definitions
    let smi = &base_modules[0];
    assert_eq!(smi.name, "SNMPv2-SMI");
    assert_eq!(smi.language, mib_rs::types::Language::SMIv2);
    assert!(!smi.definitions.is_empty());
    // Should have iso, internet, enterprises, etc. and Integer32, Counter32, etc.
    let names: Vec<&str> = smi.definitions.iter().map(|d| d.name()).collect();
    assert!(names.contains(&"iso"), "missing iso OID");
    assert!(names.contains(&"internet"), "missing internet OID");
    assert!(names.contains(&"enterprises"), "missing enterprises OID");
    assert!(names.contains(&"Integer32"), "missing Integer32 type");
    assert!(names.contains(&"Counter32"), "missing Counter32 type");
    assert!(names.contains(&"Counter64"), "missing Counter64 type");
    assert!(names.contains(&"IpAddress"), "missing IpAddress type");

    // SNMPv2-TC should have textual conventions
    let tc = &base_modules[1];
    assert_eq!(tc.name, "SNMPv2-TC");
    let tc_names: Vec<&str> = tc.definitions.iter().map(|d| d.name()).collect();
    assert!(tc_names.contains(&"DisplayString"), "missing DisplayString");
    assert!(tc_names.contains(&"TruthValue"), "missing TruthValue");
    assert!(tc_names.contains(&"RowStatus"), "missing RowStatus");
    assert!(tc_names.contains(&"MacAddress"), "missing MacAddress");

    // SNMPv2-CONF should be empty (MACROs only)
    let conf = &base_modules[2];
    assert_eq!(conf.name, "SNMPv2-CONF");
    assert!(conf.definitions.is_empty());

    // RFC1155-SMI should have SMIv1 types
    let rfc1155 = &base_modules[3];
    assert_eq!(rfc1155.name, "RFC1155-SMI");
    assert_eq!(rfc1155.language, mib_rs::types::Language::SMIv1);
    let rfc1155_names: Vec<&str> = rfc1155.definitions.iter().map(|d| d.name()).collect();
    assert!(rfc1155_names.contains(&"Counter"), "missing Counter type");
    assert!(rfc1155_names.contains(&"Gauge"), "missing Gauge type");
    assert!(rfc1155_names.contains(&"iso"), "missing iso OID");

    // RFC-1212 and RFC-1215 should be empty
    assert!(base_modules[5].definitions.is_empty());
    assert!(base_modules[6].definitions.is_empty());
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
    let ast_modules = mib_rs::parser::parse(source, config.clone());
    assert_eq!(ast_modules.len(), 1);
    let module = mib_rs::lower::lower(ast_modules.into_iter().next().unwrap(), source, &config);
    assert_eq!(module.language, mib_rs::types::Language::SMIv2);
    assert_eq!(module.name, "TEST-MIB");
    // Should have flattened imports
    assert_eq!(module.imports.len(), 3);
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
    let ast_modules = mib_rs::parser::parse(source, config.clone());
    assert_eq!(ast_modules.len(), 1);
    let module = mib_rs::lower::lower(ast_modules.into_iter().next().unwrap(), source, &config);
    assert_eq!(module.language, mib_rs::types::Language::SMIv1);
}

#[test]
fn lower_trap_type_becomes_notification() {
    let source = br#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises
        FROM RFC1155-SMI;

testTrap TRAP-TYPE
    ENTERPRISE enterprises
    DESCRIPTION "A test trap"
    ::= 1

END
"#;
    let config = DiagnosticConfig::default();
    let ast_modules = mib_rs::parser::parse(source, config.clone());
    let module = mib_rs::lower::lower(ast_modules.into_iter().next().unwrap(), source, &config);

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
