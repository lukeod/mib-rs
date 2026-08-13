// Integration tests: full pipeline from source files through resolution.

mod common;

use mib_rs::load::{Loader, load};
use mib_rs::mib::{Oid, Range, RangeBound, Symbol, UnresolvedKind};
use mib_rs::source::{chain, dir as dir_source, memory_modules};
use mib_rs::types::{
    Access, BaseType, DiagCode, DiagnosticConfig, IndexEncoding, Kind, Language,
    ResolverStrictness, Severity,
};

use common::{corpus_dir, problems_dir};

fn load_corpus(modules: &[&str]) -> mib_rs::Mib {
    let dir = corpus_dir();
    if !dir.exists() {
        panic!("corpus dir not found: {}", dir.display());
    }
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = Loader::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(modules.iter().copied());
    load(opts).expect("load failed")
}

fn load_all_corpus() -> mib_rs::Mib {
    let dir = corpus_dir();
    if !dir.exists() {
        panic!("corpus dir not found: {}", dir.display());
    }
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = Loader::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent());
    load(opts).expect("load failed")
}

fn load_corpus_with_diags(modules: &[&str], strictness: ResolverStrictness) -> mib_rs::Mib {
    let dir = corpus_dir();
    if !dir.exists() {
        panic!("corpus dir not found: {}", dir.display());
    }
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = Loader::new()
        .source(src)
        .resolver_strictness(strictness)
        .diagnostic_config(DiagnosticConfig::verbose())
        .modules(modules.iter().copied());
    load(opts).expect("load failed")
}

// --- Basic loading tests ---

#[test]
fn load_single_module() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // IF-MIB should be present
    let mod_id = mib.module_by_name("IF-MIB").expect("IF-MIB not found");
    let module = mib.raw().module(mod_id);
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
    assert!(r.module_by_name("IF-MIB").is_some());
    assert!(r.module_by_name("SNMPv2-MIB").is_some());
}

// --- OID resolution tests ---

#[test]
fn well_known_oids() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // iso = 1
    let iso = mib.raw().resolve("iso").expect("iso not found");
    let iso_oid = mib.raw().tree().oid_of(iso);
    assert_eq!(iso_oid.to_string(), "1");

    // internet = 1.3.6.1
    let internet = mib.raw().resolve("internet").expect("internet not found");
    let internet_oid = mib.raw().tree().oid_of(internet);
    assert_eq!(internet_oid.to_string(), "1.3.6.1");

    // enterprises = 1.3.6.1.4.1
    let enterprises = mib
        .raw()
        .resolve("enterprises")
        .expect("enterprises not found");
    let enterprises_oid = mib.raw().tree().oid_of(enterprises);
    assert_eq!(enterprises_oid.to_string(), "1.3.6.1.4.1");
}

#[test]
fn if_mib_oids() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifIndex = 1.3.6.1.2.1.2.2.1.1
    let if_index = mib.raw().resolve("ifIndex").expect("ifIndex not found");
    let oid = mib.raw().tree().oid_of(if_index);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.1");

    // ifDescr = 1.3.6.1.2.1.2.2.1.2
    let if_descr = mib.raw().resolve("ifDescr").expect("ifDescr not found");
    let oid = mib.raw().tree().oid_of(if_descr);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.2");

    // ifTable = 1.3.6.1.2.1.2.2
    let if_table = mib.raw().resolve("ifTable").expect("ifTable not found");
    let oid = mib.raw().tree().oid_of(if_table);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2");
}

#[test]
fn oid_numeric_lookup() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
    let node = mib.exact_node_by_oid(&oid).expect("OID not found");
    assert_eq!(node.name(), "ifIndex");
}

#[test]
fn resolve_node_from_instance_oid() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let node = mib
        .resolve_node("1.3.6.1.2.1.2.2.1.1.5")
        .expect("instance OID should resolve to its base node");
    assert_eq!(node.name(), "ifIndex");
}

#[test]
fn resolve_qualified_name() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let node = mib
        .raw()
        .resolve("IF-MIB::ifIndex")
        .expect("qualified name not found");
    let oid = mib.raw().tree().oid_of(node);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.1");
}

#[test]
fn format_oid_with_module() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
    let formatted = mib.format_oid(&oid);
    assert!(
        formatted.contains("ifIndex"),
        "expected ifIndex in format, got: {formatted}"
    );
}

#[test]
fn lookup_oid_matches_instance_prefix() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // 1.3.6.1.2.1.2.2.1.1.5 - ifIndex instance .5 (doesn't exist in tree)
    let oid: Oid = "1.3.6.1.2.1.2.2.1.1.5".parse().unwrap();
    let node = mib.lookup_oid(&oid);
    assert_eq!(node.name(), "ifIndex");
}

#[test]
fn node_subtree() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifEntry subtree should include ifEntry itself plus all its columns.
    let entry_id = mib.node_by_name("ifEntry").expect("ifEntry not found");
    let subtree_names: Vec<&str> = mib
        .subtree(entry_id)
        .map(|id| mib.raw().tree().get(id).name())
        .filter(|n| !n.is_empty())
        .collect();
    assert!(subtree_names[0] == "ifEntry");
    assert!(subtree_names.contains(&"ifIndex"));
    assert!(subtree_names.contains(&"ifDescr"));
    assert!(subtree_names.contains(&"ifType"));
    assert!(subtree_names.len() > 5); // ifEntry has many columns
}

#[test]
fn node_longest_prefix() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // Start from ifTable (1.3.6.1.2.1.2.2) and look up relative OID 1.1.5
    // which should match ifIndex (ifEntry.1 = arc 1 under ifTable child 1).
    let table_id = mib.node_by_name("ifTable").expect("ifTable not found");
    let suffix: Oid = "1.1.5".parse().unwrap();
    let matched = mib.longest_prefix_from(table_id, &suffix);
    let name = mib.raw().tree().get(matched).name();
    assert_eq!(name, "ifIndex");
}

#[test]
fn resolve_oid_from_name() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

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
    let mib = &r;

    // ifIndex should be a column with InterfaceIndex type
    let obj_id = mib
        .object_by_name("ifIndex")
        .expect("ifIndex object not found");
    let obj = mib.raw().object(obj_id);
    assert_eq!(obj.name(), "ifIndex");
    assert_eq!(obj.kind(mib.raw().tree()), Kind::Column);
    assert_eq!(obj.access(), Access::ReadOnly);

    // Should have a resolved type
    let type_id = obj.type_id().expect("ifIndex should have a type");
    let type_data = mib.raw().type_(type_id);
    assert_eq!(type_data.name(), "InterfaceIndex");
}

#[test]
fn table_structure() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifTable should be a table
    let table_id = mib.object_by_name("ifTable").expect("ifTable not found");
    let table = mib.raw().object(table_id);
    assert_eq!(table.kind(mib.raw().tree()), Kind::Table);

    // ifEntry should be a row
    let entry_id = mib.object_by_name("ifEntry").expect("ifEntry not found");
    let entry = mib.raw().object(entry_id);
    assert_eq!(entry.kind(mib.raw().tree()), Kind::Row);

    // ifEntry should have indexes
    assert!(
        !entry.index().is_empty(),
        "ifEntry should have index entries"
    );
}

#[test]
fn scalar_objects() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifNumber should be a scalar
    let obj_id = mib.object_by_name("ifNumber").expect("ifNumber not found");
    let obj = mib.raw().object(obj_id);
    assert_eq!(obj.kind(mib.raw().tree()), Kind::Scalar);
}

// --- Type resolution tests ---

#[test]
fn type_parent_chain() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // DisplayString should ultimately be OCTET STRING
    let ds_id = mib
        .type_by_name("DisplayString")
        .expect("DisplayString not found");
    let ds = mib.raw().type_(ds_id);
    let effective = ds.effective_base(mib.raw().types_slice());
    assert_eq!(effective, BaseType::OctetString);
}

#[test]
fn large_flat_type_set_links_all_parents() {
    const DERIVED_TYPE_COUNT: usize = 4096;

    let mut module_source = String::from("LARGE-TYPE-MIB DEFINITIONS ::= BEGIN\n");
    module_source.push_str("BaseType ::= INTEGER\n");
    for index in 0..DERIVED_TYPE_COUNT {
        module_source.push_str(&format!("DerivedType{index} ::= BaseType\n"));
    }
    module_source.push_str("END\n");

    let mib = load(
        Loader::new()
            .source(memory_modules([("LARGE-TYPE-MIB", module_source)]))
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent())
            .modules(["LARGE-TYPE-MIB"]),
    )
    .expect("load failed");

    let module = mib.module("LARGE-TYPE-MIB").expect("module not found");
    let derived_types: Vec<_> = module
        .types()
        .filter(|typ| typ.name().starts_with("DerivedType"))
        .collect();
    assert_eq!(derived_types.len(), DERIVED_TYPE_COUNT);
    for typ in derived_types {
        assert_eq!(
            typ.parent().map(|parent| parent.name()),
            Some("BaseType"),
            "{} has the wrong parent",
            typ.name()
        );
        assert_eq!(typ.effective_base(), BaseType::Integer32);
    }
}

#[test]
fn type_cycles_leave_parents_unlinked_and_record_cycle_metadata() {
    let source = memory_modules([(
        "TYPE-CYCLE-MIB",
        br#"TYPE-CYCLE-MIB DEFINITIONS ::= BEGIN
TypeA ::= TypeB
TypeB ::= TypeA
SelfType ::= SelfType
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["TYPE-CYCLE-MIB"]),
    )
    .expect("load failed");

    let module = mib.module("TYPE-CYCLE-MIB").expect("module not found");
    for name in ["TypeA", "TypeB", "SelfType"] {
        let typ = module.r#type(name).expect("type not found");
        assert!(typ.parent().is_none(), "{name} retained a cycle parent");
        assert_eq!(typ.effective_base(), BaseType::Unknown);
    }

    let unresolved: Vec<_> = mib
        .unresolved()
        .iter()
        .filter(|unresolved| {
            unresolved.kind == UnresolvedKind::Type && unresolved.module == "TYPE-CYCLE-MIB"
        })
        .collect();
    assert_eq!(unresolved.len(), 3);
    for (referrer, referenced) in [
        ("TypeA", "TypeB"),
        ("TypeB", "TypeA"),
        ("SelfType", "SelfType"),
    ] {
        assert!(unresolved.iter().any(|unresolved| {
            unresolved.symbol == referenced && unresolved.reason == "dependency_cycle"
        }));
        assert!(mib.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == DiagCode::TypeCycle
                && diagnostic.module.as_deref() == Some("TYPE-CYCLE-MIB")
                && diagnostic.message.contains(referrer)
                && diagnostic.message.contains(referenced)
        }));
    }
    assert!(!mib.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagCode::TypeUnknown
            && diagnostic.module.as_deref() == Some("TYPE-CYCLE-MIB")
    }));
}

#[test]
fn cross_module_type_cycle_marks_imports_used_without_linking_parents() {
    let source = memory_modules([
        (
            "TYPE-CYCLE-A-MIB",
            &br#"TYPE-CYCLE-A-MIB DEFINITIONS ::= BEGIN
IMPORTS
    BType FROM TYPE-CYCLE-B-MIB;
AType ::= BType
END
"#[..],
        ),
        (
            "TYPE-CYCLE-B-MIB",
            &br#"TYPE-CYCLE-B-MIB DEFINITIONS ::= BEGIN
IMPORTS
    AType FROM TYPE-CYCLE-A-MIB;
BType ::= AType
END
"#[..],
        ),
    ]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["TYPE-CYCLE-A-MIB", "TYPE-CYCLE-B-MIB"]),
    )
    .expect("load failed");

    for (module_name, type_name, referenced_name) in [
        ("TYPE-CYCLE-A-MIB", "AType", "BType"),
        ("TYPE-CYCLE-B-MIB", "BType", "AType"),
    ] {
        let module = mib.module(module_name).expect("module not found");
        let typ = module.r#type(type_name).expect("type not found");
        assert!(
            typ.parent().is_none(),
            "{type_name} retained a cycle parent"
        );
        assert_eq!(typ.effective_base(), BaseType::Unknown);
        assert!(
            mib.raw()
                .module(module.id())
                .is_import_used(referenced_name),
            "{module_name} import of {referenced_name} was not marked used"
        );
        assert!(mib.unresolved().iter().any(|unresolved| {
            unresolved.kind == UnresolvedKind::Type
                && unresolved.module == module_name
                && unresolved.symbol == referenced_name
                && unresolved.reason == "dependency_cycle"
        }));
        assert!(!mib.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == DiagCode::ImportUnused
                && diagnostic.module.as_deref() == Some(module_name)
                && diagnostic.message.contains(referenced_name)
        }));
    }
}

#[test]
fn type_cycle_diagnostic_respects_diagnostic_config() {
    let source = memory_modules([(
        "SILENT-TYPE-CYCLE-MIB",
        br#"SILENT-TYPE-CYCLE-MIB DEFINITIONS ::= BEGIN
TypeA ::= TypeB
TypeB ::= TypeA
END
"#,
    )]);
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent())
            .modules(["SILENT-TYPE-CYCLE-MIB"]),
    )
    .expect("load failed");

    assert!(mib.diagnostics().is_empty());
    assert_eq!(
        mib.unresolved()
            .iter()
            .filter(|unresolved| {
                unresolved.kind == UnresolvedKind::Type && unresolved.reason == "dependency_cycle"
            })
            .count(),
        2
    );
}

#[test]
fn hex_range_literals_normalize_whitespace_and_preserve_malformed_bounds() {
    let source = memory_modules([(
        "HEX-RANGE-MIB",
        b"HEX-RANGE-MIB DEFINITIONS ::= BEGIN\n\
Valid ::= INTEGER ('7f ff'H..'80\t00'H)\n\
Malformed ::= INTEGER ('0G'H..'10000000000000000'H)\n\
END\n",
    )]);
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::verbose()),
    )
    .expect("load failed");
    let module = mib.module("HEX-RANGE-MIB").expect("module missing");

    let valid = module.r#type("Valid").expect("Valid missing");
    assert_eq!(valid.ranges()[0].min, RangeBound::Unsigned(0x7fff));
    assert_eq!(valid.ranges()[0].max, RangeBound::Unsigned(0x8000));
    assert!(valid.ranges()[0].is_resolved());

    let malformed = module.r#type("Malformed").expect("Malformed missing");
    assert_eq!(
        malformed.ranges()[0].min,
        RangeBound::Raw("'0G'H".to_string())
    );
    assert_eq!(
        malformed.ranges()[0].max,
        RangeBound::Raw("'10000000000000000'H".to_string())
    );
    assert!(!malformed.ranges()[0].is_resolved());
    assert_eq!(
        mib.diagnostics()
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == DiagCode::InvalidHexRange
                    && diagnostic.module.as_deref() == Some("HEX-RANGE-MIB")
            })
            .count(),
        2
    );
}

#[test]
fn unresolved_range_endpoints_preserve_known_intersections() {
    let source = memory_modules([(
        "RAW-RANGE-INTERSECTION-MIB",
        br#"RAW-RANGE-INTERSECTION-MIB DEFINITIONS ::= BEGIN
KnownParent ::= INTEGER (0..10)
RawParent ::= INTEGER ('0G'H..10)
RawChild ::= KnownParent ('1G'H..5)
KnownChild ::= RawParent (0..5)
DisjointChild ::= RawParent (20..30)
DisjointRawChild ::= KnownParent (20..'2G'H)
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["RAW-RANGE-INTERSECTION-MIB"]),
    )
    .expect("load failed");
    let module = mib
        .module("RAW-RANGE-INTERSECTION-MIB")
        .expect("module missing");

    let raw_child = module.r#type("RawChild").expect("RawChild missing");
    assert_eq!(
        raw_child.effective_ranges(),
        &[Range {
            min: RangeBound::Raw("'1G'H".to_string()),
            max: RangeBound::Unsigned(5),
            span: raw_child.ranges()[0].span,
        }]
    );

    let known_child = module.r#type("KnownChild").expect("KnownChild missing");
    assert_eq!(
        known_child.effective_ranges(),
        &[Range {
            min: RangeBound::Raw("'0G'H".to_string()),
            max: RangeBound::Unsigned(5),
            span: known_child.ranges()[0].span,
        }]
    );

    for name in ["DisjointChild", "DisjointRawChild"] {
        let disjoint = module.r#type(name).expect("disjoint type missing");
        assert!(disjoint.effective_ranges_constrained());
        assert!(disjoint.effective_ranges().is_empty());
        assert!(mib.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == DiagCode::ConstraintEmptyIntersection
                && diagnostic.message.contains(name)
        }));
    }
}

#[test]
fn range_endpoints_preserve_semantics_and_intersect_parent_constraints() {
    let source = memory_modules([(
        "RANGE-SEMANTICS-MIB",
        br#"RANGE-SEMANTICS-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, Counter64
        FROM SNMPv2-SMI;

rangeSemantics MODULE-IDENTITY
    LAST-UPDATED "202603210000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test"
    ::= { 1 3 6 1 4 1 99997 }

ParentRange ::= Integer32 (-10..20)
ChildRange ::= ParentRange (MIN..MAX)
NarrowRange ::= ParentRange (0..MAX)
DisjointRange ::= ParentRange (30..40)
DisjointDerived ::= DisjointRange
MultiRange ::= Integer32 (0..10 | 20..30)
MaxOnly ::= MultiRange (MAX)
MinOnly ::= MultiRange (MIN)
MinUpper ::= MultiRange (MIN..25)
MaxLower ::= MultiRange (5..MAX)
OpenRange ::= INTEGER (MIN..MAX)
OpenSize ::= OCTET STRING (SIZE (MIN..MAX))
HugeRange ::= Counter64 (0..18446744073709551615)

rangeObject OBJECT-TYPE
    SYNTAX ChildRange (MIN..10)
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Range test"
    ::= { rangeSemantics 1 }

hugeObject OBJECT-TYPE
    SYNTAX HugeRange
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Unsigned range and DEFVAL test"
    DEFVAL { 18446744073709551615 }
    ::= { rangeSemantics 2 }

disjointObject OBJECT-TYPE
    SYNTAX ParentRange (30..40)
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Empty intersection and DEFVAL test"
    DEFVAL { 5 }
    ::= { rangeSemantics 3 }

openObject OBJECT-TYPE
    SYNTAX INTEGER (MIN..MAX)
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Primitive range fallback test"
    ::= { rangeSemantics 4 }

openSizeObject OBJECT-TYPE
    SYNTAX OCTET STRING (SIZE (MIN..MAX))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Primitive size fallback test"
    ::= { rangeSemantics 5 }
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["RANGE-SEMANTICS-MIB"]),
    )
    .expect("load failed");
    let module = mib.module("RANGE-SEMANTICS-MIB").expect("module missing");

    let child = module.r#type("ChildRange").expect("ChildRange missing");
    assert_eq!(child.ranges()[0].min, RangeBound::Min);
    assert_eq!(child.ranges()[0].max, RangeBound::Max);
    assert_eq!(child.effective_ranges()[0].min.as_i64(), Some(-10));
    assert_eq!(child.effective_ranges()[0].max.as_i64(), Some(20));

    let narrow = module.r#type("NarrowRange").expect("NarrowRange missing");
    assert_eq!(narrow.effective_ranges()[0].min.as_i64(), Some(0));
    assert_eq!(narrow.effective_ranges()[0].max.as_i64(), Some(20));

    let disjoint = module
        .r#type("DisjointRange")
        .expect("DisjointRange missing");
    assert!(disjoint.effective_ranges().is_empty());
    assert!(disjoint.effective_ranges_constrained());
    let disjoint_derived = module
        .r#type("DisjointDerived")
        .expect("DisjointDerived missing");
    assert!(disjoint_derived.effective_ranges().is_empty());
    assert!(disjoint_derived.effective_ranges_constrained());

    let max_only = module.r#type("MaxOnly").expect("MaxOnly missing");
    assert_eq!(max_only.effective_ranges().len(), 1);
    assert_eq!(max_only.effective_ranges()[0].min.as_i64(), Some(30));
    assert_eq!(max_only.effective_ranges()[0].max.as_i64(), Some(30));
    let min_only = module.r#type("MinOnly").expect("MinOnly missing");
    assert_eq!(min_only.effective_ranges().len(), 1);
    assert_eq!(min_only.effective_ranges()[0].min.as_i64(), Some(0));
    assert_eq!(min_only.effective_ranges()[0].max.as_i64(), Some(0));
    let min_upper = module.r#type("MinUpper").expect("MinUpper missing");
    assert_eq!(min_upper.effective_ranges().len(), 2);
    assert_eq!(min_upper.effective_ranges()[0].min.as_i64(), Some(0));
    assert_eq!(min_upper.effective_ranges()[0].max.as_i64(), Some(10));
    assert_eq!(min_upper.effective_ranges()[1].min.as_i64(), Some(20));
    assert_eq!(min_upper.effective_ranges()[1].max.as_i64(), Some(25));
    let max_lower = module.r#type("MaxLower").expect("MaxLower missing");
    assert_eq!(max_lower.effective_ranges().len(), 2);
    assert_eq!(max_lower.effective_ranges()[0].min.as_i64(), Some(5));
    assert_eq!(max_lower.effective_ranges()[0].max.as_i64(), Some(10));
    assert_eq!(max_lower.effective_ranges()[1].min.as_i64(), Some(20));
    assert_eq!(max_lower.effective_ranges()[1].max.as_i64(), Some(30));

    let open = module.r#type("OpenRange").expect("OpenRange missing");
    assert_eq!(open.ranges()[0].min, RangeBound::Min);
    assert_eq!(open.ranges()[0].max, RangeBound::Max);
    assert_eq!(
        open.effective_ranges()[0].min.as_i64(),
        Some(i64::from(i32::MIN))
    );
    assert_eq!(
        open.effective_ranges()[0].max.as_i64(),
        Some(i64::from(i32::MAX))
    );
    let size = module.r#type("OpenSize").expect("OpenSize missing");
    assert_eq!(size.sizes()[0].min, RangeBound::Min);
    assert_eq!(size.sizes()[0].max, RangeBound::Max);
    assert_eq!(size.effective_sizes()[0].min.as_u64(), Some(0));
    assert_eq!(size.effective_sizes()[0].max.as_u64(), Some(65535));

    let huge = module.r#type("HugeRange").expect("HugeRange missing");
    assert_eq!(huge.effective_ranges()[0].min.as_u64(), Some(0));
    assert_eq!(huge.effective_ranges()[0].max.as_u64(), Some(u64::MAX));
    assert_eq!(huge.effective_ranges()[0].max.as_i64(), None);

    let object = mib.object("rangeObject").expect("rangeObject missing");
    assert_eq!(object.ranges()[0].min, RangeBound::Min);
    assert_eq!(object.ranges()[0].max, RangeBound::Unsigned(10));
    assert_eq!(object.effective_ranges()[0].min.as_i64(), Some(-10));
    assert_eq!(object.effective_ranges()[0].max.as_i64(), Some(10));
    let huge_object = mib.object("hugeObject").expect("hugeObject missing");
    assert_eq!(
        huge_object.effective_ranges()[0].max.as_u64(),
        Some(u64::MAX)
    );
    assert!(!mib.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagCode::DefvalRange && diagnostic.message.contains("hugeObject")
    }));

    let disjoint_object = mib
        .object("disjointObject")
        .expect("disjointObject missing");
    assert!(disjoint_object.effective_ranges().is_empty());
    assert!(disjoint_object.effective_ranges_constrained());
    assert!(mib.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagCode::DefvalRange && diagnostic.message.contains("disjointObject")
    }));

    let empty_intersection_diags = mib
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagCode::ConstraintEmptyIntersection)
        .collect::<Vec<_>>();
    assert_eq!(empty_intersection_diags.len(), 2);
    assert!(empty_intersection_diags.iter().any(|diagnostic| {
        diagnostic.message.contains("DisjointRange")
            && diagnostic
                .message
                .contains("range constraint has an empty intersection")
    }));
    assert!(empty_intersection_diags.iter().any(|diagnostic| {
        diagnostic.message.contains("disjointObject")
            && diagnostic
                .message
                .contains("range constraint has an empty intersection")
    }));
    assert!(
        empty_intersection_diags
            .iter()
            .all(|diagnostic| diagnostic.severity == Severity::Warning)
    );

    let open_object = mib.object("openObject").expect("openObject missing");
    assert_eq!(open_object.ranges()[0].min, RangeBound::Min);
    assert_eq!(open_object.ranges()[0].max, RangeBound::Max);
    assert_eq!(
        open_object.effective_ranges()[0].min.as_i64(),
        Some(i64::from(i32::MIN))
    );
    assert_eq!(
        open_object.effective_ranges()[0].max.as_i64(),
        Some(i64::from(i32::MAX))
    );
    let open_size_object = mib
        .object("openSizeObject")
        .expect("openSizeObject missing");
    assert_eq!(open_size_object.sizes()[0].min, RangeBound::Min);
    assert_eq!(open_size_object.sizes()[0].max, RangeBound::Max);
    assert_eq!(open_size_object.effective_sizes()[0].min.as_u64(), Some(0));
    assert_eq!(
        open_size_object.effective_sizes()[0].max.as_u64(),
        Some(65535)
    );

    let min_max_diags = mib
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagCode::MinMaxRange)
        .count();
    assert_eq!(min_max_diags, 16);
}

#[test]
fn min_max_range_diagnostic_obeys_policy() {
    let source = memory_modules([(
        "SILENT-RANGE-MIB",
        br#"SILENT-RANGE-MIB DEFINITIONS ::= BEGIN
OpenRange ::= INTEGER (MIN..MAX)
ParentRange ::= INTEGER (0..10)
EmptyRange ::= ParentRange (20..30)
END
"#,
    )]);
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent())
            .modules(["SILENT-RANGE-MIB"]),
    )
    .expect("load failed");

    assert!(mib.diagnostics().is_empty());
    let typ = mib
        .module("SILENT-RANGE-MIB")
        .and_then(|module| module.r#type("OpenRange"))
        .expect("OpenRange missing");
    assert_eq!(typ.ranges()[0].min, RangeBound::Min);
    assert_eq!(typ.ranges()[0].max, RangeBound::Max);
    assert_eq!(
        typ.effective_ranges()[0].min.as_i64(),
        Some(i64::from(i32::MIN))
    );
    assert_eq!(
        typ.effective_ranges()[0].max.as_i64(),
        Some(i64::from(i32::MAX))
    );
    let empty = mib
        .module("SILENT-RANGE-MIB")
        .and_then(|module| module.r#type("EmptyRange"))
        .expect("EmptyRange missing");
    assert!(empty.effective_ranges_constrained());
    assert!(empty.effective_ranges().is_empty());
}

#[test]
fn empty_intersection_diagnostic_can_be_ignored() {
    let source = memory_modules([(
        "IGNORED-RANGE-MIB",
        br#"IGNORED-RANGE-MIB DEFINITIONS ::= BEGIN
ParentRange ::= INTEGER (0..10)
EmptyRange ::= ParentRange (20..30)
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    diagnostics
        .ignore
        .push("constraint-empty-intersection".to_string());
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["IGNORED-RANGE-MIB"]),
    )
    .expect("load failed");

    assert!(
        !mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::ConstraintEmptyIntersection)
    );
    let empty = mib
        .module("IGNORED-RANGE-MIB")
        .and_then(|module| module.r#type("EmptyRange"))
        .expect("EmptyRange missing");
    assert!(empty.effective_ranges_constrained());
    assert!(empty.effective_ranges().is_empty());
}

#[test]
fn duplicate_oid_empty_intersection_uses_declared_object() {
    let source = memory_modules([(
        "DUPLICATE-CONSTRAINT-MIB",
        br#"DUPLICATE-CONSTRAINT-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE
        FROM SNMPv2-SMI;

duplicateConstraintMIB MODULE-IDENTITY
    LAST-UPDATED "202603220000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test"
    ::= { 1 3 6 1 4 1 99995 }

ParentRange ::= INTEGER (0..10)

firstObject OBJECT-TYPE
    SYNTAX ParentRange (0..5)
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Satisfiable declaration"
    ::= { duplicateConstraintMIB 1 }

secondObject OBJECT-TYPE
    SYNTAX ParentRange (20..30)
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Empty declaration"
    ::= { duplicateConstraintMIB 1 }
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["DUPLICATE-CONSTRAINT-MIB"]),
    )
    .expect("load failed");

    let empty_intersections = mib
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagCode::ConstraintEmptyIntersection)
        .collect::<Vec<_>>();
    assert_eq!(empty_intersections.len(), 1);
    assert!(empty_intersections[0].message.contains("secondObject"));
    assert!(!empty_intersections[0].message.contains("firstObject"));
    assert!(
        mib.module("DUPLICATE-CONSTRAINT-MIB")
            .and_then(|module| module.object("secondObject"))
            .expect("secondObject missing")
            .effective_ranges()
            .is_empty()
    );

    let first_id = mib
        .object_by_name("firstObject")
        .expect("firstObject missing");
    let second_id = mib
        .object_by_name("secondObject")
        .expect("secondObject missing");
    let first = mib.raw().object(first_id);
    let second = mib.raw().object(second_id);
    assert_ne!(first_id, second_id);
    assert_eq!(first.name(), "firstObject");
    assert_eq!(second.name(), "secondObject");
    assert_eq!(first.description(), "Satisfiable declaration");
    assert_eq!(second.description(), "Empty declaration");
    assert_eq!(first.node(), second.node(), "the NodeId must remain shared");
    assert_eq!(mib.object("secondObject").unwrap().name(), "secondObject");
    assert_eq!(
        mib.symbol_by_name("secondObject"),
        Some(Symbol::Object(second_id))
    );
}

#[test]
fn textual_convention_display_hint() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // DisplayString is a TC with display hint "255a"
    let ds_id = mib
        .type_by_name("DisplayString")
        .expect("DisplayString not found");
    let ds = mib.raw().type_(ds_id);
    assert!(ds.is_textual_convention());
    assert_eq!(ds.effective_display_hint(mib.raw().types_slice()), "255a");
}

#[test]
fn integer_enum_type() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifAdminStatus should have enum values (up/down/testing)
    let obj_id = mib
        .object_by_name("ifAdminStatus")
        .expect("ifAdminStatus not found");
    let obj = mib.raw().object(obj_id);
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
    let mib = &r;

    // linkDown should be a notification
    let notif_id = mib
        .notification_by_name("linkDown")
        .expect("linkDown not found");
    let notif = mib.raw().notification(notif_id);
    assert_eq!(notif.name(), "linkDown");
}

#[test]
fn import_forwarding_requires_an_ultimate_definer() {
    let source = memory_modules([
        (
            "FORWARD-IMPORTER-MIB",
            &br#"FORWARD-IMPORTER-MIB DEFINITIONS ::= BEGIN
IMPORTS
    missing FROM FORWARD-RELAY-MIB;
END
"#[..],
        ),
        (
            "FORWARD-RELAY-MIB",
            &br#"FORWARD-RELAY-MIB DEFINITIONS ::= BEGIN
IMPORTS
    missing FROM FORWARD-DEAD-END-MIB;
END
"#[..],
        ),
        (
            "FORWARD-DEAD-END-MIB",
            &br#"FORWARD-DEAD-END-MIB DEFINITIONS ::= BEGIN
END
"#[..],
        ),
    ]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["FORWARD-IMPORTER-MIB"]),
    )
    .expect("load failed");

    let importer = mib
        .module("FORWARD-IMPORTER-MIB")
        .expect("importer module not found");
    assert!(importer.import_source("missing").is_none());
    assert!(mib.unresolved().iter().any(|unresolved| {
        unresolved.kind == UnresolvedKind::Import
            && unresolved.module == "FORWARD-IMPORTER-MIB"
            && unresolved.symbol == "missing"
            && unresolved.reason == "symbol_not_exported"
    }));
    assert!(mib.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagCode::ImportNotFound
            && diagnostic.module.as_deref() == Some("FORWARD-IMPORTER-MIB")
            && diagnostic.message.contains("FORWARD-RELAY-MIB")
    }));
    assert!(!mib.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagCode::ImportUnused
            && diagnostic.module.as_deref() == Some("FORWARD-IMPORTER-MIB")
    }));
}

#[test]
fn cyclic_import_forwarding_is_rejected() {
    let source = memory_modules([
        (
            "CYCLE-IMPORTER-MIB",
            &br#"CYCLE-IMPORTER-MIB DEFINITIONS ::= BEGIN
IMPORTS
    missing FROM CYCLE-B-MIB;
END
"#[..],
        ),
        (
            "CYCLE-B-MIB",
            &br#"CYCLE-B-MIB DEFINITIONS ::= BEGIN
IMPORTS
    missing FROM CYCLE-C-MIB;
END
"#[..],
        ),
        (
            "CYCLE-C-MIB",
            &br#"CYCLE-C-MIB DEFINITIONS ::= BEGIN
IMPORTS
    missing FROM CYCLE-B-MIB;
END
"#[..],
        ),
    ]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Strict)
            .diagnostic_config(diagnostics)
            .modules(["CYCLE-IMPORTER-MIB"]),
    )
    .expect("load failed");

    let importer = mib
        .module("CYCLE-IMPORTER-MIB")
        .expect("importer module not found");
    assert!(importer.import_source("missing").is_none());
    assert!(mib.unresolved().iter().any(|unresolved| {
        unresolved.kind == UnresolvedKind::Import
            && unresolved.module == "CYCLE-IMPORTER-MIB"
            && unresolved.symbol == "missing"
            && unresolved.reason == "symbol_not_exported"
    }));
}

#[test]
fn multi_hop_import_forwarding_records_the_definer() {
    let source = memory_modules([
        (
            "MULTI-IMPORTER-MIB",
            &br#"MULTI-IMPORTER-MIB DEFINITIONS ::= BEGIN
IMPORTS
    ForwardedType FROM MULTI-B-MIB;
END
"#[..],
        ),
        (
            "MULTI-B-MIB",
            &br#"MULTI-B-MIB DEFINITIONS ::= BEGIN
IMPORTS
    ForwardedType FROM MULTI-C-MIB;
END
"#[..],
        ),
        (
            "MULTI-C-MIB",
            &br#"MULTI-C-MIB DEFINITIONS ::= BEGIN
IMPORTS
    ForwardedType FROM MULTI-DEFINER-MIB;
END
"#[..],
        ),
        (
            "MULTI-DEFINER-MIB",
            &br#"MULTI-DEFINER-MIB DEFINITIONS ::= BEGIN
ForwardedType ::= OCTET STRING
END
"#[..],
        ),
    ]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Strict)
            .diagnostic_config(diagnostics)
            .modules(["MULTI-IMPORTER-MIB"]),
    )
    .expect("load failed");

    let importer = mib
        .module("MULTI-IMPORTER-MIB")
        .expect("importer module not found");
    assert_eq!(
        importer
            .import_source("ForwardedType")
            .expect("forwarded source not found")
            .name(),
        "MULTI-DEFINER-MIB"
    );
    assert!(!mib.unresolved().iter().any(|unresolved| {
        unresolved.kind == UnresolvedKind::Import
            && unresolved.module == "MULTI-IMPORTER-MIB"
            && unresolved.symbol == "ForwardedType"
    }));
}

#[test]
fn maximum_generic_trap_number_is_unresolved() {
    let source = memory_modules([(
        "MAX-TRAP-MIB",
        br#"MAX-TRAP-MIB DEFINITIONS ::= BEGIN
IMPORTS
    TRAP-TYPE FROM RFC-1215;

snmpTraps OBJECT IDENTIFIER ::= { iso 3 6 1 6 3 1 1 5 }

maximumValidTrap TRAP-TYPE
    ENTERPRISE snmpTraps
    ::= 4294967294

maximumTrap TRAP-TYPE
    ENTERPRISE snmpTraps
    ::= 4294967295

END
"#,
    )]);
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::verbose())
            .modules(["MAX-TRAP-MIB"]),
    )
    .expect("load failed");

    let diagnostic = mib
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == DiagCode::TrapNumberOverflow)
        .expect("trap-number-overflow diagnostic not found");
    assert_eq!(diagnostic.module.as_deref(), Some("MAX-TRAP-MIB"));
    assert!(diagnostic.message.contains("maximumTrap"));

    let unresolved = mib
        .unresolved()
        .iter()
        .find(|unresolved| unresolved.symbol == "maximumTrap")
        .expect("overflowing trap not recorded as unresolved");
    assert_eq!(unresolved.kind, UnresolvedKind::Oid);
    assert_eq!(unresolved.module, "MAX-TRAP-MIB");
    assert_eq!(unresolved.reason, "trap_number_overflow");

    assert!(mib.notification_by_name("maximumTrap").is_none());
    assert!(mib.node_by_name("maximumTrap").is_none());
    let wrapped_oid: Oid = "1.3.6.1.6.3.1.1.5.0".parse().unwrap();
    assert!(mib.exact_node_by_oid(&wrapped_oid).is_none());

    let maximum_oid: Oid = "1.3.6.1.6.3.1.1.5.4294967295".parse().unwrap();
    let maximum_node = mib
        .exact_node_by_oid(&maximum_oid)
        .expect("maximum non-overflowing trap should resolve");
    assert_eq!(maximum_node.name(), "maximumValidTrap");
    assert!(mib.notification_by_name("maximumValidTrap").is_some());
}

// --- Group and compliance tests ---

#[test]
fn groups_resolved() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    assert!(
        !mib.raw().groups_slice().is_empty(),
        "IF-MIB should define groups"
    );
}

#[test]
fn compliances_resolved() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    assert!(
        !mib.raw().compliances_slice().is_empty(),
        "IF-MIB should define compliances"
    );
}

// --- Collection queries ---

#[test]
fn filter_tables() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let tables: Vec<_> = mib.tables().collect();
    assert!(!tables.is_empty(), "IF-MIB should have at least one table");
    for t in &tables {
        assert_eq!(t.kind(), Kind::Table);
    }
}

#[test]
fn filter_by_base_type() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let counters = mib.objects_by_base_type(BaseType::Counter32);
    assert!(!counters.is_empty(), "IF-MIB should have counter objects");
}

// --- Module metadata ---

#[test]
fn module_metadata() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let mod_id = mib.module_by_name("IF-MIB").unwrap();
    let module = mib.raw().module(mod_id);
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
    let mib = &r;

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
    let mib = &r;

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
    assert!(!r.has_errors(), "IF-MIB should load without errors");
}

// --- Multi-module tests ---

#[test]
fn snmpv2_mib_objects() {
    let r = load_corpus(&["SNMPv2-MIB"]);
    let mib = &r;

    // sysDescr = 1.3.6.1.2.1.1.1
    let node = mib.raw().resolve("sysDescr").expect("sysDescr not found");
    let oid = mib.raw().tree().oid_of(node);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1");

    // sysUpTime = 1.3.6.1.2.1.1.3
    let node = mib.raw().resolve("sysUpTime").expect("sysUpTime not found");
    let oid = mib.raw().tree().oid_of(node);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.3");
}

#[test]
fn host_resources_mib() {
    let r = load_corpus(&["HOST-RESOURCES-MIB"]);
    let mib = &r;

    assert!(mib.module_by_name("HOST-RESOURCES-MIB").is_some());
    // hrSystem is an object group root
    let node = mib.raw().resolve("hrSystem");
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
    let mib = &r;

    eprintln!(
        "resolved: {} modules, {} objects, {} types, {} notifications, {} nodes",
        mib.raw().modules_slice().len(),
        mib.raw().objects_slice().len(),
        mib.raw().types_slice().len(),
        mib.raw().notifications_slice().len(),
        mib.node_count(),
    );

    // Should have loaded a significant number of modules
    assert!(
        mib.raw().modules_slice().len() > 100,
        "expected 100+ modules from corpus, got {}",
        mib.raw().modules_slice().len()
    );

    // Should have many objects
    assert!(
        mib.raw().objects_slice().len() > 1000,
        "expected 1000+ objects from corpus, got {}",
        mib.raw().objects_slice().len()
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
    let opts = Loader::new()
        .source(src)
        .source(primary_src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent());
    let r = load(opts).expect("load failed");
    eprintln!(
        "problems corpus: {} modules, {} objects",
        r.raw().modules_slice().len(),
        r.raw().objects_slice().len()
    );
}

// --- ComplianceObject syntax/write_syntax tests ---

#[test]
fn compliance_object_syntax_and_write_syntax() {
    // DIFFSERV-MIB diffServMIBFullCompliance has OBJECT clauses with both
    // SYNTAX and WRITE-SYNTAX refinements (e.g. diffServDataPathStatus).
    let r = load_corpus(&["DIFFSERV-MIB"]);
    let mib = &r;

    let comp_id = mib
        .compliance_by_name("diffServMIBFullCompliance")
        .expect("compliance not found");
    let comp = mib.raw().compliance(comp_id);

    // Find the self-module (DIFFSERV-MIB) compliance module.
    let self_mod = comp
        .modules()
        .iter()
        .find(|m| m.module_name.is_empty() || m.module_name == "DIFFSERV-MIB")
        .expect("self module not found in compliance");

    // diffServDataPathStatus: SYNTAX INTEGER { active(1) },
    //                         WRITE-SYNTAX INTEGER { createAndGo(4), destroy(6) }
    let obj = self_mod
        .objects
        .iter()
        .find(|o| o.object == "diffServDataPathStatus")
        .expect("diffServDataPathStatus not found in compliance objects");

    let syntax = obj.syntax.as_ref().expect("syntax should be resolved");
    assert!(!syntax.enums.is_empty(), "syntax should have enum values");
    assert!(
        syntax
            .enums
            .iter()
            .any(|e| e.label == "active" && e.value == 1),
        "syntax should contain active(1), got: {:?}",
        syntax.enums
    );

    let ws = obj
        .write_syntax
        .as_ref()
        .expect("write_syntax should be resolved");
    assert!(
        ws.enums.len() >= 2,
        "write_syntax should have 2+ enum values, got {}",
        ws.enums.len()
    );
    assert!(
        ws.enums
            .iter()
            .any(|e| e.label == "createAndGo" && e.value == 4),
        "write_syntax should contain createAndGo(4), got: {:?}",
        ws.enums
    );
    assert!(
        ws.enums
            .iter()
            .any(|e| e.label == "destroy" && e.value == 6),
        "write_syntax should contain destroy(6), got: {:?}",
        ws.enums
    );
}

#[test]
fn compliance_object_syntax_with_size_constraint() {
    // DIFFSERV-MIB diffServMIBFullCompliance has:
    //   OBJECT diffServMultiFieldClfrDstAddr
    //   SYNTAX InetAddress (SIZE(0|4|16))
    let r = load_corpus(&["DIFFSERV-MIB"]);
    let mib = &r;

    let comp_id = mib
        .compliance_by_name("diffServMIBFullCompliance")
        .expect("compliance not found");
    let comp = mib.raw().compliance(comp_id);

    let self_mod = comp
        .modules()
        .iter()
        .find(|m| m.module_name.is_empty() || m.module_name == "DIFFSERV-MIB")
        .expect("self module not found");

    let obj = self_mod
        .objects
        .iter()
        .find(|o| o.object == "diffServMultiFieldClfrDstAddr")
        .expect("diffServMultiFieldClfrDstAddr not found");

    let syntax = obj.syntax.as_ref().expect("syntax should be resolved");
    assert!(
        syntax.type_id.is_some(),
        "syntax should have a resolved type"
    );
    assert!(
        !syntax.sizes.is_empty(),
        "syntax should have size constraints"
    );
    // SIZE(0|4|16) produces three single-value ranges
    assert!(
        syntax
            .sizes
            .iter()
            .any(|r| r.min.as_i64() == Some(0) && r.max.as_i64() == Some(0)),
        "should have size 0"
    );
    assert!(
        syntax
            .sizes
            .iter()
            .any(|r| r.min.as_i64() == Some(4) && r.max.as_i64() == Some(4)),
        "should have size 4"
    );
    assert!(
        syntax
            .sizes
            .iter()
            .any(|r| r.min.as_i64() == Some(16) && r.max.as_i64() == Some(16)),
        "should have size 16"
    );

    // This object has SYNTAX only, no WRITE-SYNTAX
    assert!(
        obj.write_syntax.is_none(),
        "write_syntax should be None for this object"
    );
}

#[test]
fn compliance_object_syntax_only_enum() {
    // DIFFSERV-MIB diffServMIBFullCompliance has:
    //   OBJECT diffServMultiFieldClfrAddrType
    //   SYNTAX INTEGER { unknown(0), ipv4(1), ipv6(2) }
    // (no WRITE-SYNTAX)
    let r = load_corpus(&["DIFFSERV-MIB"]);
    let mib = &r;

    let comp_id = mib
        .compliance_by_name("diffServMIBFullCompliance")
        .expect("compliance not found");
    let comp = mib.raw().compliance(comp_id);

    let self_mod = comp
        .modules()
        .iter()
        .find(|m| m.module_name.is_empty() || m.module_name == "DIFFSERV-MIB")
        .expect("self module not found");

    let obj = self_mod
        .objects
        .iter()
        .find(|o| o.object == "diffServMultiFieldClfrAddrType")
        .expect("diffServMultiFieldClfrAddrType not found");

    let syntax = obj.syntax.as_ref().expect("syntax should be resolved");
    assert_eq!(syntax.enums.len(), 3, "should have 3 enum values");
    assert!(
        syntax
            .enums
            .iter()
            .any(|e| e.label == "unknown" && e.value == 0),
        "should have unknown(0)"
    );
    assert!(
        syntax
            .enums
            .iter()
            .any(|e| e.label == "ipv4" && e.value == 1),
        "should have ipv4(1)"
    );
    assert!(
        syntax
            .enums
            .iter()
            .any(|e| e.label == "ipv6" && e.value == 2),
        "should have ipv6(2)"
    );

    assert!(obj.write_syntax.is_none(), "write_syntax should be None");
}

// --- ObjectVariation syntax/write_syntax/defval tests ---

#[test]
fn variation_syntax_and_write_syntax() {
    // PROBLEM-VARIATION-SYNTAX-MIB has VARIATION problemVarStatus with:
    //   SYNTAX INTEGER { active(1), notInService(2) }
    //   WRITE-SYNTAX INTEGER { createAndGo(4), destroy(6) }
    let r = load_problems(&["PROBLEM-VARIATION-SYNTAX-MIB"]);
    let mib = &r;

    let cap_id = mib
        .capability_by_name("problemVarCapability")
        .expect("capability not found");
    let cap = mib.raw().capability(cap_id);
    assert_eq!(cap.supports().len(), 1);

    let support = &cap.supports()[0];
    let var = support
        .object_variations
        .iter()
        .find(|v| v.object == "problemVarStatus")
        .expect("problemVarStatus variation not found");

    let syntax = var.syntax.as_ref().expect("syntax should be resolved");
    assert_eq!(syntax.enums.len(), 2, "syntax should have 2 enum values");
    assert!(
        syntax
            .enums
            .iter()
            .any(|e| e.label == "active" && e.value == 1),
        "should have active(1)"
    );
    assert!(
        syntax
            .enums
            .iter()
            .any(|e| e.label == "notInService" && e.value == 2),
        "should have notInService(2)"
    );

    let ws = var
        .write_syntax
        .as_ref()
        .expect("write_syntax should be resolved");
    assert_eq!(ws.enums.len(), 2, "write_syntax should have 2 enum values");
    assert!(
        ws.enums
            .iter()
            .any(|e| e.label == "createAndGo" && e.value == 4),
        "should have createAndGo(4)"
    );
    assert!(
        ws.enums
            .iter()
            .any(|e| e.label == "destroy" && e.value == 6),
        "should have destroy(6)"
    );
}

#[test]
fn variation_syntax_with_range_and_defval() {
    // PROBLEM-VARIATION-SYNTAX-MIB has VARIATION problemVarValue with:
    //   SYNTAX Integer32 (0..50)
    //   WRITE-SYNTAX Integer32 (1..25)
    //   DEFVAL { 10 }
    let r = load_problems(&["PROBLEM-VARIATION-SYNTAX-MIB"]);
    let mib = &r;

    let cap_id = mib
        .capability_by_name("problemVarCapability")
        .expect("capability not found");
    let cap = mib.raw().capability(cap_id);
    let support = &cap.supports()[0];

    let var = support
        .object_variations
        .iter()
        .find(|v| v.object == "problemVarValue")
        .expect("problemVarValue variation not found");

    // SYNTAX Integer32 (0..50)
    let syntax = var.syntax.as_ref().expect("syntax should be resolved");
    assert!(syntax.type_id.is_some(), "syntax should have resolved type");
    assert_eq!(syntax.ranges.len(), 1, "syntax should have 1 range");
    assert_eq!(syntax.ranges[0].min.as_i64(), Some(0));
    assert_eq!(syntax.ranges[0].max.as_i64(), Some(50));

    // WRITE-SYNTAX Integer32 (1..25)
    let ws = var
        .write_syntax
        .as_ref()
        .expect("write_syntax should be resolved");
    assert!(
        ws.type_id.is_some(),
        "write_syntax should have resolved type"
    );
    assert_eq!(ws.ranges.len(), 1, "write_syntax should have 1 range");
    assert_eq!(ws.ranges[0].min.as_i64(), Some(1));
    assert_eq!(ws.ranges[0].max.as_i64(), Some(25));

    // DEFVAL { 10 }
    let dv = var.def_val.as_ref().expect("def_val should be resolved");
    assert!(!dv.is_unset(), "def_val should not be unset");
    assert_eq!(dv.to_string(), "10");
}

#[test]
fn compliance_and_variation_primitive_min_max_use_base_bounds() {
    let source = memory_modules([(
        "INLINE-PRIMITIVE-MIB",
        br#"INLINE-PRIMITIVE-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE
        FROM SNMPv2-SMI
    MODULE-COMPLIANCE, AGENT-CAPABILITIES
        FROM SNMPv2-CONF;

inlinePrimitive MODULE-IDENTITY
    LAST-UPDATED "202603210000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test"
    ::= { 1 3 6 1 4 1 99996 }

inlineInteger OBJECT-TYPE
    SYNTAX INTEGER
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "Integer test"
    ::= { inlinePrimitive 1 }

inlineOctets OBJECT-TYPE
    SYNTAX OCTET STRING
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "Size test"
    ::= { inlinePrimitive 2 }

inlineCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "Compliance test"
    MODULE
        MANDATORY-GROUPS { }
        OBJECT inlineInteger
            SYNTAX INTEGER (MIN..MAX)
            DESCRIPTION "Integer refinement"
        OBJECT inlineOctets
            SYNTAX OCTET STRING (SIZE (MIN..MAX))
            DESCRIPTION "Size refinement"
    ::= { inlinePrimitive 3 }

inlineCapability AGENT-CAPABILITIES
    PRODUCT-RELEASE "test"
    STATUS current
    DESCRIPTION "Variation test"
    SUPPORTS INLINE-PRIMITIVE-MIB
        INCLUDES { }
        VARIATION inlineInteger
            SYNTAX INTEGER (MIN..MAX)
            DESCRIPTION "Integer variation"
        VARIATION inlineOctets
            SYNTAX OCTET STRING (SIZE (MIN..MAX))
            DESCRIPTION "Size variation"
    ::= { inlinePrimitive 4 }
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["INLINE-PRIMITIVE-MIB"]),
    )
    .expect("load failed");

    let compliance = mib.raw().compliance(
        mib.compliance_by_name("inlineCompliance")
            .expect("compliance missing"),
    );
    let compliance_objects = &compliance.modules()[0].objects;
    let compliance_integer = compliance_objects
        .iter()
        .find(|object| object.object == "inlineInteger")
        .and_then(|object| object.syntax.as_ref())
        .expect("compliance integer syntax missing");
    assert_eq!(compliance_integer.declared_ranges[0].min, RangeBound::Min);
    assert_eq!(compliance_integer.declared_ranges[0].max, RangeBound::Max);
    assert_eq!(
        compliance_integer.ranges[0].min.as_i64(),
        Some(i64::from(i32::MIN))
    );
    assert_eq!(
        compliance_integer.ranges[0].max.as_i64(),
        Some(i64::from(i32::MAX))
    );
    let compliance_octets = compliance_objects
        .iter()
        .find(|object| object.object == "inlineOctets")
        .and_then(|object| object.syntax.as_ref())
        .expect("compliance octet syntax missing");
    assert_eq!(compliance_octets.declared_sizes[0].min, RangeBound::Min);
    assert_eq!(compliance_octets.declared_sizes[0].max, RangeBound::Max);
    assert_eq!(compliance_octets.sizes[0].min.as_u64(), Some(0));
    assert_eq!(compliance_octets.sizes[0].max.as_u64(), Some(65535));

    let capability = mib.raw().capability(
        mib.capability_by_name("inlineCapability")
            .expect("capability missing"),
    );
    let variations = &capability.supports()[0].object_variations;
    let variation_integer = variations
        .iter()
        .find(|variation| variation.object == "inlineInteger")
        .and_then(|variation| variation.syntax.as_ref())
        .expect("variation integer syntax missing");
    assert_eq!(variation_integer.declared_ranges[0].min, RangeBound::Min);
    assert_eq!(variation_integer.declared_ranges[0].max, RangeBound::Max);
    assert_eq!(
        variation_integer.ranges[0].min.as_i64(),
        Some(i64::from(i32::MIN))
    );
    assert_eq!(
        variation_integer.ranges[0].max.as_i64(),
        Some(i64::from(i32::MAX))
    );
    let variation_octets = variations
        .iter()
        .find(|variation| variation.object == "inlineOctets")
        .and_then(|variation| variation.syntax.as_ref())
        .expect("variation octet syntax missing");
    assert_eq!(variation_octets.declared_sizes[0].min, RangeBound::Min);
    assert_eq!(variation_octets.declared_sizes[0].max, RangeBound::Max);
    assert_eq!(variation_octets.sizes[0].min.as_u64(), Some(0));
    assert_eq!(variation_octets.sizes[0].max.as_u64(), Some(65535));
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
    let opts = Loader::new()
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
    let mib = &r;

    if let Some(mod_id) = mib.module_by_name("RFC1213-MIB") {
        let module = mib.raw().module(mod_id);
        assert_eq!(module.language(), Language::SMIv1);
    }
}

// --- Modules defining/importing ---

#[test]
fn modules_defining_symbol() {
    let r = load_corpus(&["IF-MIB", "SNMPv2-MIB"]);
    let mib = &r;

    let definers = mib.modules_defining("ifIndex");
    assert!(
        !definers.is_empty(),
        "ifIndex should be defined by at least one module"
    );
}

#[test]
fn modules_importing_symbol() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

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
    let mib = &r;

    // These OIDs are defined by multiple base modules (SNMPv2-SMI and
    // RFC1155-SMI both define org, dod, internet, etc.). Either base module
    // is acceptable; the key invariant is that no vendor module owns them.
    let well_known = ["iso", "org", "dod", "internet", "mgmt", "enterprises"];

    for name in &well_known {
        let node_id = mib
            .node_by_name(name)
            .unwrap_or_else(|| panic!("node {name} not found"));
        let mod_id = mib
            .raw()
            .tree()
            .get(node_id)
            .module()
            .unwrap_or_else(|| panic!("module not set for {name}"));
        let module = mib.raw().module(mod_id);
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
    let mib = &r;

    for name in &["org", "dod"] {
        let node_id = mib
            .node_by_name(name)
            .unwrap_or_else(|| panic!("node {name} not found"));
        let mod_id = mib
            .raw()
            .tree()
            .get(node_id)
            .module()
            .unwrap_or_else(|| panic!("module not set for {name}"));
        let module = mib.raw().module(mod_id);
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
    let mib = &r;

    let node_id = mib.node_by_name("snmp").expect("snmp node not found");
    let mod_id = mib
        .raw()
        .tree()
        .get(node_id)
        .module()
        .expect("module not set for snmp");
    let module = mib.raw().module(mod_id);
    assert_eq!(
        module.name(),
        "SNMPv2-MIB",
        "snmp OID should be owned by SNMPv2-MIB"
    );
}

// --- Duplicate import diagnostic tests ---

fn load_problems(modules: &[&str]) -> mib_rs::Mib {
    let dir = problems_dir();
    let corpus = corpus_dir();
    let src = chain(vec![
        dir_source(&dir).expect("failed to create problems source"),
        dir_source(&corpus).expect("failed to create corpus source"),
    ]);
    let opts = Loader::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Normal)
        .diagnostic_config(DiagnosticConfig::verbose())
        .modules(modules.iter().copied());
    load(opts).expect("load failed")
}

#[test]
fn duplicate_import_from_different_modules_emits_diagnostic() {
    let r = load_problems(&["PROBLEM-DUPLICATE-IMPORT-MIB"]);
    let diags = r.diagnostics();
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
    let mib = &r;

    let mod_id = mib
        .module_by_name("PROBLEM-DUPLICATE-IMPORT-MIB")
        .expect("module not found");
    let module = mib.raw().module(mod_id);
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
    let mib = &r;

    for name in &["member-body", "us"] {
        let node_id = mib
            .node_by_name(name)
            .unwrap_or_else(|| panic!("node {name} not found"));
        let mod_id = mib
            .raw()
            .tree()
            .get(node_id)
            .module()
            .unwrap_or_else(|| panic!("module not set for {name}"));
        let module = mib.raw().module(mod_id);
        assert_eq!(
            module.name(),
            "IEEE802dot11-MIB",
            "{name}: expected IEEE802dot11-MIB (newer after timestamp normalization), got {}",
            module.name()
        );
    }
}

#[test]
fn malformed_utf8_timestamp_does_not_influence_module_preference() {
    let module = |name: &str, timestamp: &str| {
        format!(
            r#"{name} DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, enterprises FROM SNMPv2-SMI;

sharedIdentity MODULE-IDENTITY
    LAST-UPDATED "{timestamp}"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test"
    ::= {{ enterprises 99999 }}

END
"#
        )
        .into_bytes()
    };
    let source = memory_modules([
        (
            "MALFORMED-TIMESTAMP-MIB",
            module("MALFORMED-TIMESTAMP-MIB", "aé1234567Z"),
        ),
        (
            "VALID-TIMESTAMP-MIB",
            module("VALID-TIMESTAMP-MIB", "202001010000Z"),
        ),
    ]);
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::verbose())
            .modules(["MALFORMED-TIMESTAMP-MIB", "VALID-TIMESTAMP-MIB"]),
    )
    .expect("load failed");

    let oid: Oid = "1.3.6.1.4.1.99999".parse().unwrap();
    let node = mib.exact_node_by_oid(&oid).expect("shared OID not found");
    assert_eq!(node.module().unwrap().name(), "VALID-TIMESTAMP-MIB");
    assert!(
        mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::DateCharacter),
        "malformed timestamp should retain its configured date diagnostic"
    );
}

// --- Object table navigation tests ---

#[test]
fn table_navigation_if_table() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifTable is a table
    let table_id = mib.object_by_name("ifTable").expect("ifTable not found");
    assert!(mib.is_table(table_id));
    assert!(!mib.is_row(table_id));
    assert!(!mib.is_column(table_id));
    assert!(!mib.is_scalar(table_id));

    // row() returns the row for a table
    let entry_id = mib.object_row(table_id).expect("ifEntry not found");
    assert_eq!(mib.raw().object(entry_id).name(), "ifEntry");
    assert!(mib.is_row(entry_id));

    // table() returns itself for tables
    let table_again = mib.object_table(table_id).expect("table from table");
    assert_eq!(table_again, table_id);

    // Row's table() returns the table
    let back_to_table = mib.object_table(entry_id).expect("table from row");
    assert_eq!(back_to_table, table_id);

    // row() returns itself for rows
    let row_again = mib.object_row(entry_id).expect("row from row");
    assert_eq!(row_again, entry_id);

    // Columns of the table
    let cols = mib.object_columns(table_id);
    assert!(!cols.is_empty(), "ifTable should have columns");

    // Columns of the row should be the same
    let cols_from_row = mib.object_columns(entry_id);
    assert_eq!(cols, cols_from_row);

    // First column should be ifIndex
    let first_col = mib.raw().object(cols[0]);
    assert_eq!(first_col.name(), "ifIndex");
    assert!(mib.is_column(cols[0]));

    // Column's row() returns the row
    let col_row = mib.object_row(cols[0]).expect("row from column");
    assert_eq!(col_row, entry_id);

    // Column's table() returns the table
    let col_table = mib.object_table(cols[0]).expect("table from column");
    assert_eq!(col_table, table_id);

    // ifIndex is an index column
    assert!(mib.is_index(cols[0]), "ifIndex should be an index");

    // Sequence type name on the table (stored on table in mib-rs)
    assert_eq!(mib.raw().object(table_id).sequence_type_name(), "IfEntry");
}

#[test]
fn table_navigation_scalars() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifNumber is a scalar
    let scalar_id = mib.object_by_name("ifNumber").expect("ifNumber not found");
    assert!(mib.is_scalar(scalar_id));
    assert!(!mib.is_table(scalar_id));

    // Scalars have no table/row/columns
    assert!(mib.object_table(scalar_id).is_none());
    assert!(mib.object_row(scalar_id).is_none());
    assert!(mib.object_columns(scalar_id).is_empty());
    assert!(!mib.is_index(scalar_id));
}

#[test]
fn effective_indexes_basic() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let entry_id = mib.object_by_name("ifEntry").expect("ifEntry not found");
    let indexes = mib.effective_indexes(entry_id);
    assert_eq!(indexes.len(), 1, "ifEntry should have 1 index");
    let idx_obj = indexes[0].object.expect("index should reference an object");
    assert_eq!(mib.raw().object(idx_obj).name(), "ifIndex");
}

#[test]
fn effective_indexes_augments() {
    // ifXEntry AUGMENTS ifEntry, so effective indexes should come from ifEntry
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    let ifx_entry = mib.object_by_name("ifXEntry").expect("ifXEntry not found");
    assert!(mib.is_row(ifx_entry));

    // ifXEntry has no INDEX of its own
    assert!(
        mib.raw().object(ifx_entry).index().is_empty(),
        "ifXEntry should have no direct INDEX"
    );

    // But effective indexes follow the AUGMENTS chain
    let indexes = mib.effective_indexes(ifx_entry);
    assert_eq!(
        indexes.len(),
        1,
        "ifXEntry effective indexes should have 1 entry"
    );
    let idx_obj = indexes[0].object.expect("index should reference an object");
    assert_eq!(mib.raw().object(idx_obj).name(), "ifIndex");
}

#[test]
fn non_index_column() {
    let r = load_corpus(&["IF-MIB"]);
    let mib = &r;

    // ifDescr is a column but not an index
    let descr_id = mib.object_by_name("ifDescr").expect("ifDescr not found");
    assert!(mib.is_column(descr_id));
    assert!(!mib.is_index(descr_id), "ifDescr should not be an index");
}

#[test]
fn effective_indexes_augments_cycle() {
    let r = load_problems(&["PROBLEM-SEMANTICS-MIB"]);
    let mib = &r;

    // Two rows that AUGMENT each other, neither has INDEX.
    let entry_a = mib
        .object_by_name("problemCycleEntryA")
        .expect("problemCycleEntryA not found");
    let entry_b = mib
        .object_by_name("problemCycleEntryB")
        .expect("problemCycleEntryB not found");
    assert!(mib.is_row(entry_a));
    assert!(mib.is_row(entry_b));

    // effective_indexes should return empty, not loop forever.
    let indexes_a = mib.effective_indexes(entry_a);
    assert!(
        indexes_a.is_empty(),
        "AUGMENTS cycle should yield empty indexes, got {}",
        indexes_a.len()
    );
    let indexes_b = mib.effective_indexes(entry_b);
    assert!(
        indexes_b.is_empty(),
        "AUGMENTS cycle should yield empty indexes, got {}",
        indexes_b.len()
    );
}

#[test]
fn effective_indexes_bare_type() {
    let r = load_problems(&["PROBLEM-SEMANTICS-MIB"]);
    let mib = &r;

    let entry = mib
        .object_by_name("problemBareEntry")
        .expect("problemBareEntry not found");
    assert!(mib.is_row(entry));

    let indexes = mib.effective_indexes(entry);
    assert_eq!(
        indexes.len(),
        1,
        "bare type table should have 1 index entry"
    );
    assert!(
        indexes[0].object.is_none(),
        "bare type index should have no object reference"
    );
    assert_eq!(
        indexes[0].name, "INTEGER",
        "bare type index should preserve its source name"
    );
    assert_eq!(
        mib.raw()
            .type_(indexes[0].type_id.expect("base type should resolve"))
            .name(),
        "INTEGER"
    );
}

#[test]
fn juniper_integer64_size_is_accepted() {
    let r = load_corpus_with_diags(&["JUNIPER-SMI"], ResolverStrictness::Strict);
    let count = r
        .diagnostics()
        .iter()
        .filter(|d| {
            d.module.as_deref() == Some("JUNIPER-SMI")
                && d.code == DiagCode::SizeIllegal
                && d.message.contains("Integer64")
        })
        .count();
    assert_eq!(count, 0, "Integer64 should not emit size-illegal");
}

#[test]
fn cm_common_decimal32_requires_display_hint() {
    let r = load_corpus_with_diags(&["CM-COMMON-MIB"], ResolverStrictness::Strict);
    let count = r
        .diagnostics()
        .iter()
        .filter(|d| {
            d.module.as_deref() == Some("CM-COMMON-MIB")
                && d.code == DiagCode::TypeWithoutFormat
                && d.message.contains("Decimal32")
        })
        .count();
    assert_eq!(count, 1, "Decimal32 should emit type-without-format");
}

#[test]
fn fs_alarm_input_bits_index_is_accepted() {
    let r = load_corpus_with_diags(&["FS-MIB"], ResolverStrictness::Strict);
    let count = r
        .diagnostics()
        .iter()
        .filter(|d| {
            d.module.as_deref() == Some("FS-MIB")
                && d.code == DiagCode::IndexIllegalBasetype
                && d.message.contains("switchAlarmInputEntry")
                && d.message.contains("alarmInputStatus")
        })
        .count();
    assert_eq!(count, 0, "BITS-based alarm input index should not emit");
}

#[test]
fn column_effective_indexes() {
    let mib = load_corpus(&["IF-MIB"]);

    let col = mib.object("ifDescr").expect("ifDescr");
    assert_eq!(col.kind(), Kind::Column, "ifDescr should be a column");

    let indexes: Vec<_> = col.effective_indexes().collect();
    assert_eq!(indexes.len(), 1, "column should yield 1 index from row");
    assert_eq!(indexes[0].name(), "ifIndex");
}

#[test]
fn nodes_by_name() {
    let mib = load_corpus(&["IF-MIB"]);

    let nodes = mib.nodes_by_name("ifIndex");
    assert!(
        !nodes.is_empty(),
        "nodes_by_name(ifIndex) should not be empty"
    );

    let empty = mib.nodes_by_name("totallyFakeName");
    assert!(empty.is_empty(), "unknown name should return empty slice");
}

#[test]
fn effective_tc() {
    let mib = load_corpus(&["IF-MIB"]);

    let obj = mib.object("ifDescr").expect("ifDescr");
    let ty = obj.ty().expect("ifDescr type");
    let tc = ty.effective_tc().expect("ifDescr should have a TC");
    assert_eq!(
        tc.name(),
        "DisplayString",
        "ifDescr TC should be DisplayString"
    );
}

#[test]
fn effective_tc_no_tc_in_chain() {
    let mib = load_corpus(&["IF-MIB"]);

    let obj = mib.object("ifIndex").expect("ifIndex");
    let ty = obj.ty().expect("ifIndex type");
    // ifIndex is InterfaceIndex which is a TC
    let tc = ty.effective_tc();
    assert!(tc.is_some(), "ifIndex should have InterfaceIndex TC");
    assert_eq!(tc.unwrap().name(), "InterfaceIndex");
}

#[test]
fn index_fixed_size() {
    let mib = load_corpus(&["IF-MIB"]);

    let row = mib.object("ifEntry").expect("ifEntry");
    let indexes: Vec<_> = row.effective_indexes().collect();
    assert_eq!(indexes.len(), 1);
    // ifIndex is an integer index, fixed size = 1
    let (size, ok) = indexes[0].fixed_size();
    assert!(ok, "integer index should have fixed size");
    assert_eq!(size, 1, "integer index fixed size should be 1");
}

#[test]
fn disjoint_inline_index_constraints_are_not_reported_as_missing() {
    let source = memory_modules([(
        "INDEX-CONSTRAINT-MIB",
        br#"INDEX-CONSTRAINT-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, enterprises
        FROM SNMPv2-SMI;

indexConstraintMIB MODULE-IDENTITY
    LAST-UPDATED "202603220000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test"
    ::= { enterprises 99996 }

ParentSize ::= OCTET STRING (SIZE (4))
ParentInteger ::= INTEGER (0..10)

indexConstraintTable OBJECT-TYPE
    SYNTAX SEQUENCE OF IndexConstraintEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Table"
    ::= { indexConstraintMIB 1 }

indexConstraintEntry OBJECT-TYPE
    SYNTAX IndexConstraintEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Entry"
    INDEX { indexSizeIndex, indexIntegerIndex }
    ::= { indexConstraintTable 1 }

IndexConstraintEntry ::= SEQUENCE {
    indexSizeIndex ParentSize,
    indexIntegerIndex ParentInteger
}

indexSizeIndex OBJECT-TYPE
    SYNTAX ParentSize (SIZE (5))
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Size index"
    ::= { indexConstraintEntry 1 }

indexIntegerIndex OBJECT-TYPE
    SYNTAX ParentInteger (20..30)
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Integer index"
    ::= { indexConstraintEntry 2 }
END
"#,
    )]);
    let mut diagnostics = DiagnosticConfig::verbose();
    diagnostics.fail_at = Severity::Fatal;
    let mib = load(
        Loader::new()
            .source(source)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(diagnostics)
            .modules(["INDEX-CONSTRAINT-MIB"]),
    )
    .expect("load failed");

    let size_index = mib
        .object("indexSizeIndex")
        .expect("indexSizeIndex missing");
    assert!(size_index.effective_sizes_constrained());
    assert!(size_index.effective_sizes().is_empty());
    let integer_index = mib
        .object("indexIntegerIndex")
        .expect("indexIntegerIndex missing");
    assert!(integer_index.effective_ranges_constrained());
    assert!(integer_index.effective_ranges().is_empty());

    for name in ["indexSizeIndex", "indexIntegerIndex"] {
        assert!(mib.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == DiagCode::ConstraintEmptyIntersection
                && diagnostic.message.contains(name)
        }));
    }
    assert!(
        !mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::IndexElementNoSize)
    );
    assert!(
        !mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::IndexIntegerNoRange)
    );

    let row = mib
        .object("indexConstraintEntry")
        .expect("indexConstraintEntry missing");
    let index = row
        .effective_indexes()
        .next()
        .expect("indexSizeIndex missing from INDEX");
    assert_eq!(index.encoding(), IndexEncoding::LengthPrefixed);
    assert_eq!(index.fixed_size(), (0, false));
}

#[test]
fn is_index_uses_column_effective_indexes() {
    let mib = load_corpus(&["IF-MIB"]);

    // ifIndex is an index column
    let idx = mib.object("ifIndex").expect("ifIndex");
    assert!(idx.is_index(), "ifIndex should be an index");

    // ifDescr is a column but not an index
    let descr = mib.object("ifDescr").expect("ifDescr");
    assert!(!descr.is_index(), "ifDescr should not be an index");
}
