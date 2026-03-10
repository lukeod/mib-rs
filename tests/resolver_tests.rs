// Integration tests: full pipeline from source files through resolution.

use gomib::load::{LoadOptions, load};
use gomib::mib::Oid;
use gomib::source::dir_source;
use gomib::types::{
    Access, BaseType, DiagCode, DiagnosticConfig, Kind, Language, ResolverStrictness,
};
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

fn problems_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/problems")
}

fn load_corpus(modules: &[&str]) -> gomib::load::LoadResult {
    let dir = corpus_dir();
    if !dir.exists() {
        panic!("corpus dir not found: {}", dir.display());
    }
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(modules.iter().copied());
    load(opts).expect("load failed")
}

fn load_all_corpus() -> gomib::load::LoadResult {
    let dir = corpus_dir();
    if !dir.exists() {
        panic!("corpus dir not found: {}", dir.display());
    }
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent());
    load(opts).expect("load failed")
}

// --- Basic loading tests ---

#[test]
fn load_single_module() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // IF-MIB should be present
    let mod_id = mib.module_by_name("IF-MIB").expect("IF-MIB not found");
    let module = mib.module(mod_id);
    assert_eq!(module.name(), "IF-MIB");
    assert_eq!(module.language(), Language::SMIv2);

    // Its dependencies should also be loaded
    assert!(
        mib.module_by_name("SNMPv2-SMI").is_some(),
        "SNMPv2-SMI should be loaded as dependency"
    );
    assert!(
        mib.module_by_name("SNMPv2-TC").is_some(),
        "SNMPv2-TC should be loaded as dependency"
    );
}

#[test]
fn load_multiple_modules() {
    let r = load_corpus(&["IF-MIB", "SNMPv2-MIB"]);
    assert!(r.mib.module_by_name("IF-MIB").is_some());
    assert!(r.mib.module_by_name("SNMPv2-MIB").is_some());
}

// --- OID resolution tests ---

#[test]
fn well_known_oids() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // iso = 1
    let iso = mib.resolve("iso").expect("iso not found");
    let iso_oid = mib.tree().oid_of(iso);
    assert_eq!(iso_oid.to_string(), "1");

    // internet = 1.3.6.1
    let internet = mib.resolve("internet").expect("internet not found");
    let internet_oid = mib.tree().oid_of(internet);
    assert_eq!(internet_oid.to_string(), "1.3.6.1");

    // enterprises = 1.3.6.1.4.1
    let enterprises = mib.resolve("enterprises").expect("enterprises not found");
    let enterprises_oid = mib.tree().oid_of(enterprises);
    assert_eq!(enterprises_oid.to_string(), "1.3.6.1.4.1");
}

#[test]
fn if_mib_oids() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // ifIndex = 1.3.6.1.2.1.2.2.1.1
    let if_index = mib.resolve("ifIndex").expect("ifIndex not found");
    let oid = mib.tree().oid_of(if_index);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.1");

    // ifDescr = 1.3.6.1.2.1.2.2.1.2
    let if_descr = mib.resolve("ifDescr").expect("ifDescr not found");
    let oid = mib.tree().oid_of(if_descr);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.2");

    // ifTable = 1.3.6.1.2.1.2.2
    let if_table = mib.resolve("ifTable").expect("ifTable not found");
    let oid = mib.tree().oid_of(if_table);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2");
}

#[test]
fn oid_numeric_lookup() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
    let node = mib.node_by_oid(&oid).expect("OID not found");
    let name = mib.tree().get(node).name();
    assert_eq!(name, "ifIndex");
}

#[test]
fn resolve_qualified_name() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let node = mib
        .resolve("IF-MIB::ifIndex")
        .expect("qualified name not found");
    let oid = mib.tree().oid_of(node);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.1");
}

#[test]
fn format_oid_with_module() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
    let formatted = mib.format_oid(&oid);
    assert!(
        formatted.contains("ifIndex"),
        "expected ifIndex in format, got: {formatted}"
    );
}

#[test]
fn longest_prefix_lookup() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // 1.3.6.1.2.1.2.2.1.1.5 - ifIndex instance .5 (doesn't exist in tree)
    let oid: Oid = "1.3.6.1.2.1.2.2.1.1.5".parse().unwrap();
    let node = mib.longest_prefix_by_oid(&oid);
    let name = mib.tree().get(node).name();
    assert_eq!(name, "ifIndex");
}

#[test]
fn resolve_oid_from_name() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let oid = mib.resolve_oid("ifIndex").expect("resolve_oid failed");
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.1");

    // With suffix
    let oid = mib
        .resolve_oid("ifIndex.5")
        .expect("resolve_oid with suffix failed");
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.1.5");
}

// --- Object type tests ---

#[test]
fn object_types_resolved() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // ifIndex should be a column with InterfaceIndex type
    let obj_id = mib
        .object_by_name("ifIndex")
        .expect("ifIndex object not found");
    let obj = mib.object(obj_id);
    assert_eq!(obj.name(), "ifIndex");
    assert_eq!(obj.kind(mib.tree()), Kind::Column);
    assert_eq!(obj.access(), Access::ReadOnly);

    // Should have a resolved type
    let type_id = obj.type_id().expect("ifIndex should have a type");
    let type_data = mib.type_(type_id);
    assert_eq!(type_data.name(), "InterfaceIndex");
}

#[test]
fn table_structure() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // ifTable should be a table
    let table_id = mib.object_by_name("ifTable").expect("ifTable not found");
    let table = mib.object(table_id);
    assert_eq!(table.kind(mib.tree()), Kind::Table);

    // ifEntry should be a row
    let entry_id = mib.object_by_name("ifEntry").expect("ifEntry not found");
    let entry = mib.object(entry_id);
    assert_eq!(entry.kind(mib.tree()), Kind::Row);

    // ifEntry should have indexes
    assert!(
        !entry.index().is_empty(),
        "ifEntry should have index entries"
    );
}

#[test]
fn scalar_objects() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // ifNumber should be a scalar
    let obj_id = mib.object_by_name("ifNumber").expect("ifNumber not found");
    let obj = mib.object(obj_id);
    assert_eq!(obj.kind(mib.tree()), Kind::Scalar);
}

// --- Type resolution tests ---

#[test]
fn type_parent_chain() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // DisplayString should ultimately be OCTET STRING
    let ds_id = mib
        .type_by_name("DisplayString")
        .expect("DisplayString not found");
    let ds = mib.type_(ds_id);
    let effective = ds.effective_base(mib.types_slice());
    assert_eq!(effective, BaseType::OctetString);
}

#[test]
fn textual_convention_display_hint() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // DisplayString is a TC with display hint "255a"
    let ds_id = mib
        .type_by_name("DisplayString")
        .expect("DisplayString not found");
    let ds = mib.type_(ds_id);
    assert!(ds.is_textual_convention());
    assert_eq!(ds.effective_display_hint(mib.types_slice()), "255a");
}

#[test]
fn integer_enum_type() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // ifAdminStatus should have enum values (up/down/testing)
    let obj_id = mib
        .object_by_name("ifAdminStatus")
        .expect("ifAdminStatus not found");
    let obj = mib.object(obj_id);
    let enums = obj.effective_enums();
    assert!(
        enums.len() >= 3,
        "ifAdminStatus should have 3+ enum values, got {}",
        enums.len()
    );
    assert!(
        enums.iter().any(|e| e.label == "up"),
        "should have 'up' value"
    );
    assert!(
        enums.iter().any(|e| e.label == "down"),
        "should have 'down' value"
    );
}

// --- Notification tests ---

#[test]
fn notification_resolved() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    // linkDown should be a notification
    let notif_id = mib
        .notification_by_name("linkDown")
        .expect("linkDown not found");
    let notif = mib.notification(notif_id);
    assert_eq!(notif.name(), "linkDown");
}

// --- Group and compliance tests ---

#[test]
fn groups_resolved() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    assert!(
        !mib.groups_slice().is_empty(),
        "IF-MIB should define groups"
    );
}

#[test]
fn compliances_resolved() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    assert!(
        !mib.compliances_slice().is_empty(),
        "IF-MIB should define compliances"
    );
}

// --- Collection queries ---

#[test]
fn filter_tables() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let tables = mib.tables();
    assert!(!tables.is_empty(), "IF-MIB should have at least one table");
    for t in &tables {
        assert_eq!(mib.object(*t).kind(mib.tree()), Kind::Table);
    }
}

#[test]
fn filter_by_base_type() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let counters = mib.objects_by_base_type(BaseType::Counter32);
    assert!(!counters.is_empty(), "IF-MIB should have counter objects");
}

// --- Module metadata ---

#[test]
fn module_metadata() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let mod_id = mib.module_by_name("IF-MIB").unwrap();
    let module = mib.module(mod_id);
    assert!(!module.description().is_empty(), "should have description");
    assert!(
        !module.organization().is_empty(),
        "should have organization"
    );
}

// --- Base modules ---

#[test]
fn base_modules_always_present() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    for name in &[
        "SNMPv2-SMI",
        "SNMPv2-TC",
        "SNMPv2-CONF",
        "RFC1155-SMI",
        "RFC1065-SMI",
        "RFC-1212",
        "RFC-1215",
    ] {
        assert!(
            mib.module_by_name(name).is_some(),
            "base module {name} should be present"
        );
    }
}

#[test]
fn base_types_available() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    for name in &["DisplayString", "TruthValue", "RowStatus", "MacAddress"] {
        assert!(
            mib.type_by_name(name).is_some(),
            "type {name} should be available"
        );
    }
}

// --- Diagnostics ---

#[test]
fn no_fatal_diagnostics() {
    let r = load_corpus(&["IF-MIB"]);
    assert!(!r.mib.has_errors(), "IF-MIB should load without errors");
}

// --- Multi-module tests ---

#[test]
fn snmpv2_mib_objects() {
    let r = load_corpus(&["SNMPv2-MIB"]);
    let mib = &r.mib;

    // sysDescr = 1.3.6.1.2.1.1.1
    let node = mib.resolve("sysDescr").expect("sysDescr not found");
    let oid = mib.tree().oid_of(node);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1");

    // sysUpTime = 1.3.6.1.2.1.1.3
    let node = mib.resolve("sysUpTime").expect("sysUpTime not found");
    let oid = mib.tree().oid_of(node);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.3");
}

#[test]
fn host_resources_mib() {
    let r = load_corpus(&["HOST-RESOURCES-MIB"]);
    let mib = &r.mib;

    assert!(mib.module_by_name("HOST-RESOURCES-MIB").is_some());
    // hrSystem is an object group root
    let node = mib.resolve("hrSystem");
    assert!(node.is_some(), "hrSystem should exist");
}

// --- Corpus smoke tests ---

#[test]
fn full_corpus_no_panics() {
    let dir = corpus_dir();
    if !dir.exists() {
        eprintln!("corpus dir not found, skipping");
        return;
    }

    let r = load_all_corpus();
    let mib = &r.mib;

    eprintln!(
        "resolved: {} modules, {} objects, {} types, {} notifications, {} nodes",
        mib.modules_slice().len(),
        mib.objects_slice().len(),
        mib.types_slice().len(),
        mib.notifications_slice().len(),
        mib.node_count(),
    );

    // Should have loaded a significant number of modules
    assert!(
        mib.modules_slice().len() > 100,
        "expected 100+ modules from corpus, got {}",
        mib.modules_slice().len()
    );

    // Should have many objects
    assert!(
        mib.objects_slice().len() > 1000,
        "expected 1000+ objects from corpus, got {}",
        mib.objects_slice().len()
    );

    // Should have many nodes
    assert!(
        mib.node_count() > 1000,
        "expected 1000+ nodes, got {}",
        mib.node_count()
    );
}

#[test]
fn problems_corpus_no_panics() {
    let dir = problems_dir();
    if !dir.exists() {
        eprintln!("problems dir not found, skipping");
        return;
    }
    let src = dir_source(&dir).expect("failed to create problems source");
    // Also add the primary corpus for dependencies
    let primary = corpus_dir();
    let primary_src = dir_source(&primary).expect("failed to create primary source");
    let opts = LoadOptions::new()
        .source(src)
        .source(primary_src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent());
    let r = load(opts).expect("load failed");
    eprintln!(
        "problems corpus: {} modules, {} objects",
        r.mib.modules_slice().len(),
        r.mib.objects_slice().len()
    );
}

// --- SMIv1 tests ---

#[test]
fn smiv1_module() {
    // RFC1213-MIB is an SMIv1 module present in the IETF corpus
    let dir = corpus_dir();
    if !dir.exists() {
        return;
    }
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(["RFC1213-MIB"]);
    let r = match load(opts) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("RFC1213-MIB not found in corpus, skipping");
            return;
        }
    };
    let mib = &r.mib;

    if let Some(mod_id) = mib.module_by_name("RFC1213-MIB") {
        let module = mib.module(mod_id);
        assert_eq!(module.language(), Language::SMIv1);
    }
}

// --- Modules defining/importing ---

#[test]
fn modules_defining_symbol() {
    let r = load_corpus(&["IF-MIB", "SNMPv2-MIB"]);
    let mib = &r.mib;

    let definers = mib.modules_defining("ifIndex");
    assert!(
        !definers.is_empty(),
        "ifIndex should be defined by at least one module"
    );
}

#[test]
fn modules_importing_symbol() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r.mib;

    let importers = mib.modules_importing("DisplayString");
    assert!(
        !importers.is_empty(),
        "DisplayString should be imported by IF-MIB"
    );
}

// --- Base module priority ---

#[test]
fn base_module_ownership() {
    // Load vendor MIBs that redeclare well-known OIDs as path prefixes:
    //   IEEE8023-LAG-MIB: { iso(1) member-body(2) us(840) ... }
    //   RAPID-CITY: { iso org(3) dod(6) ... }
    let r = load_corpus(&["IEEE8023-LAG-MIB", "RAPID-CITY"]);
    let mib = &r.mib;

    // These OIDs are defined by multiple base modules (SNMPv2-SMI and
    // RFC1155-SMI both define org, dod, internet, etc.). Either base module
    // is acceptable; the key invariant is that no vendor module owns them.
    let well_known = ["iso", "org", "dod", "internet", "mgmt", "enterprises"];

    for name in &well_known {
        let node_id = mib
            .node_by_name(name)
            .unwrap_or_else(|| panic!("node {name} not found"));
        let mod_id = mib
            .tree()
            .get(node_id)
            .module()
            .unwrap_or_else(|| panic!("module not set for {name}"));
        let module = mib.module(mod_id);
        assert!(
            module.is_base(),
            "{name}: expected base module, got {}",
            module.name()
        );
    }
}

#[test]
fn base_module_beats_vendor_with_newer_timestamp() {
    // RAPID-CITY is SMIv2 with a recent LAST-UPDATED. Base modules (SMIv1,
    // no timestamp) should still win for well-known OIDs.
    let r = load_corpus(&["RAPID-CITY"]);
    let mib = &r.mib;

    for name in &["org", "dod"] {
        let node_id = mib
            .node_by_name(name)
            .unwrap_or_else(|| panic!("node {name} not found"));
        let mod_id = mib
            .tree()
            .get(node_id)
            .module()
            .unwrap_or_else(|| panic!("module not set for {name}"));
        let module = mib.module(mod_id);
        assert!(
            module.is_base(),
            "{name}: expected base module, got {}",
            module.name()
        );
    }
}

#[test]
fn snmp_oid_owned_by_snmpv2_mib() {
    // The snmp OID (mib-2.11) belongs to SNMPv2-MIB, not the synthetic
    // SNMPv2-SMI. Verify the synthetic base doesn't claim it.
    let r = load_corpus(&["SNMPv2-MIB"]);
    let mib = &r.mib;

    let node_id = mib.node_by_name("snmp").expect("snmp node not found");
    let mod_id = mib
        .tree()
        .get(node_id)
        .module()
        .expect("module not set for snmp");
    let module = mib.module(mod_id);
    assert_eq!(
        module.name(),
        "SNMPv2-MIB",
        "snmp OID should be owned by SNMPv2-MIB"
    );
}

// --- Duplicate import diagnostic tests ---

fn load_problems(modules: &[&str]) -> gomib::load::LoadResult {
    let dir = problems_dir();
    let corpus = corpus_dir();
    let src = gomib::source::multi_source(vec![
        dir_source(&dir).expect("failed to create problems source"),
        dir_source(&corpus).expect("failed to create corpus source"),
    ]);
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Normal)
        .diagnostic_config(DiagnosticConfig::verbose())
        .modules(modules.iter().copied());
    load(opts).expect("load failed")
}

#[test]
fn duplicate_import_from_different_modules_emits_diagnostic() {
    let r = load_problems(&["PROBLEM-DUPLICATE-IMPORT-MIB"]);
    let diags = r.mib.diagnostics();
    let dup = diags
        .iter()
        .find(|d| d.code == DiagCode::ImportDuplicate)
        .expect("expected import-duplicate diagnostic");
    assert!(
        dup.message.contains("RFC1213-MIB"),
        "diagnostic should mention first module: {}",
        dup.message
    );
    assert!(
        dup.message.contains("SNMPv2-TC"),
        "diagnostic should mention second module: {}",
        dup.message
    );
}

#[test]
fn duplicate_import_first_wins() {
    // DisplayString imported from RFC1213-MIB first, then SNMPv2-TC.
    // The resolved import should point to RFC1213-MIB's version.
    let r = load_problems(&["PROBLEM-DUPLICATE-IMPORT-MIB"]);
    let mib = &r.mib;

    let mod_id = mib
        .module_by_name("PROBLEM-DUPLICATE-IMPORT-MIB")
        .expect("module not found");
    let module = mib.module(mod_id);
    let imports = module.imports();
    // Find the import group that contains DisplayString.
    let ds_import = imports
        .iter()
        .find(|imp| imp.symbols.iter().any(|s| s.name == "DisplayString"))
        .expect("DisplayString import not found");
    assert_eq!(ds_import.module, "RFC1213-MIB", "first import should win");
}

#[test]
fn timestamp_normalization_in_module_preference() {
    // IEEE802dot11-MIB has LAST-UPDATED "0208300000Z" (SMIv1 10-digit, means 2002-08-30).
    // IEEE8023-LAG-MIB has LAST-UPDATED "200006270000Z" (SMIv2 12-digit, means 2000-06-27).
    // Both define member-body(1.2) and us(1.2.840). IEEE802dot11-MIB is newer, so it
    // should win after normalizing the timestamps. Without normalization, raw string
    // comparison picks IEEE8023-LAG-MIB (wrong: "0" < "2" in ASCII).
    let r = load_corpus(&["IEEE802dot11-MIB", "IEEE8023-LAG-MIB"]);
    let mib = &r.mib;

    for name in &["member-body", "us"] {
        let node_id = mib
            .node_by_name(name)
            .unwrap_or_else(|| panic!("node {name} not found"));
        let mod_id = mib
            .tree()
            .get(node_id)
            .module()
            .unwrap_or_else(|| panic!("module not set for {name}"));
        let module = mib.module(mod_id);
        assert_eq!(
            module.name(),
            "IEEE802dot11-MIB",
            "{name}: expected IEEE802dot11-MIB (newer after timestamp normalization), got {}",
            module.name()
        );
    }
}
