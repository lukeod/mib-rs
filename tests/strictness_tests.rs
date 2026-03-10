use std::path::{Path, PathBuf};

use mib_rs::load::{LoadOptions, load};
use mib_rs::mib::object::ObjectData;
use mib_rs::mib::{Mib, NodeId, UnresolvedKind};
use mib_rs::source::{dir_source, multi_source};
use mib_rs::types::{BaseType, DiagCode, DiagnosticConfig, ResolverStrictness, Severity};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

fn problems_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/problems")
}

fn violations_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/strictness/violations")
}

fn load_at_strictness(module: &str, strictness: ResolverStrictness) -> Mib {
    let src = multi_source(vec![
        dir_source(&corpus_dir()).expect("failed to create corpus source"),
        dir_source(&problems_dir()).expect("failed to create problems source"),
    ]);
    let mut diag = DiagnosticConfig::verbose();
    diag.fail_at = Severity::Fatal;
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(strictness)
        .diagnostic_config(diag)
        .modules([module]);
    load(opts).expect("load failed").mib
}

fn load_violation_mib(module: &str, strictness: ResolverStrictness) -> Mib {
    let src = multi_source(vec![
        dir_source(&corpus_dir()).expect("failed to create corpus source"),
        dir_source(&violations_dir()).expect("failed to create violations source"),
    ]);
    let mut diag = DiagnosticConfig::verbose();
    diag.fail_at = Severity::Fatal;
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(strictness)
        .diagnostic_config(diag)
        .modules([module]);
    load(opts).expect("load failed").mib
}

fn unresolved_symbols<'a>(mib: &'a Mib, module: &str, kind: UnresolvedKind) -> Vec<&'a str> {
    mib.unresolved()
        .iter()
        .filter(|u| u.module == module && u.kind == kind)
        .map(|u| u.symbol.as_str())
        .collect()
}

fn has_unresolved(mib: &Mib, module: &str, kind: UnresolvedKind, symbol: &str) -> bool {
    unresolved_symbols(mib, module, kind).contains(&symbol)
}

fn count_diagnostics(mib: &Mib, code: DiagCode) -> usize {
    mib.diagnostics().iter().filter(|d| d.code == code).count()
}

fn count_module_diagnostics(mib: &Mib, module: &str, code: DiagCode) -> usize {
    mib.diagnostics()
        .iter()
        .filter(|d| d.code == code && d.module.as_deref() == Some(module))
        .count()
}

fn require_object<'a>(mib: &'a Mib, name: &str) -> &'a ObjectData {
    let id = mib
        .object_by_name(name)
        .unwrap_or_else(|| panic!("object {name} not found"));
    mib.object(id)
}

fn require_node(mib: &Mib, name: &str) -> NodeId {
    mib.node_by_name(name)
        .unwrap_or_else(|| panic!("node {name} not found"))
}

fn normalize_base_type(base: BaseType) -> &'static str {
    match base {
        BaseType::OctetString => "OCTET STRING",
        BaseType::Integer32 => "Integer32",
        BaseType::Unsigned32 => "Unsigned32",
        BaseType::Gauge32 => "Gauge32",
        BaseType::TimeTicks => "TimeTicks",
        BaseType::Counter64 => "Counter64",
        _ => panic!("unexpected base type {base:?}"),
    }
}

#[test]
fn resolver_strictness_boundaries() {
    assert!(!ResolverStrictness::Strict.allow_constrained_fallbacks());
    assert!(!ResolverStrictness::Strict.allow_global_fallbacks());
    assert!(ResolverStrictness::Normal.allow_constrained_fallbacks());
    assert!(!ResolverStrictness::Normal.allow_global_fallbacks());
    assert!(ResolverStrictness::Permissive.allow_constrained_fallbacks());
    assert!(ResolverStrictness::Permissive.allow_global_fallbacks());
}

#[test]
fn oid_global_root_strictness() {
    for (strictness, want_unresolved, want_object) in [
        (ResolverStrictness::Strict, true, false),
        (ResolverStrictness::Normal, false, true),
        (ResolverStrictness::Permissive, false, true),
    ] {
        let mib = load_violation_mib("MISSING-IMPORT-TEST-MIB", strictness);
        assert_eq!(
            has_unresolved(
                &mib,
                "MISSING-IMPORT-TEST-MIB",
                UnresolvedKind::Oid,
                "enterprises"
            ),
            want_unresolved
        );

        let obj = mib.object_by_name("testObject");
        assert_eq!(
            obj.is_some(),
            want_object,
            "unexpected object state at {strictness}"
        );
        if let Some(obj_id) = obj {
            let node = mib.object(obj_id).node().expect("node missing");
            assert_eq!(mib.tree().oid_of(node).to_string(), "1.3.6.1.4.1.99999.1");
        }
    }
}

#[test]
fn type_fallback_strictness() {
    for (strictness, want_resolved) in [
        (ResolverStrictness::Strict, false),
        (ResolverStrictness::Normal, true),
        (ResolverStrictness::Permissive, true),
    ] {
        let mib = load_at_strictness("PROBLEM-IMPORTS-MIB", strictness);
        for (object, symbol, want_base) in [
            ("problemMissingCounter64", "Counter64", BaseType::Counter64),
            ("problemMissingGauge32", "Gauge32", BaseType::Gauge32),
            (
                "problemMissingUnsigned32",
                "Unsigned32",
                BaseType::Unsigned32,
            ),
            ("problemMissingTimeTicks", "TimeTicks", BaseType::TimeTicks),
        ] {
            let obj = require_object(&mib, object);
            assert_eq!(
                obj.type_id().is_some(),
                want_resolved,
                "{object} at {strictness}"
            );
            assert_eq!(
                has_unresolved(&mib, "PROBLEM-IMPORTS-MIB", UnresolvedKind::Type, symbol),
                !want_resolved
            );
            if let Some(type_id) = obj.type_id() {
                assert_eq!(
                    mib.type_(type_id).effective_base(mib.types_slice()),
                    want_base
                );
            }
        }
    }
}

#[test]
fn tc_fallback_strictness() {
    for (strictness, want_resolved) in [
        (ResolverStrictness::Strict, false),
        (ResolverStrictness::Normal, true),
        (ResolverStrictness::Permissive, true),
    ] {
        let mib = load_at_strictness("PROBLEM-IMPORTS-MIB", strictness);
        for (object, want_type) in [
            ("problemMissingDisplayString", "OCTET STRING"),
            ("problemMissingTruthValue", "Integer32"),
        ] {
            let obj = require_object(&mib, object);
            assert_eq!(
                obj.type_id().is_some(),
                want_resolved,
                "{object} at {strictness}"
            );
            if let Some(type_id) = obj.type_id() {
                let base = mib.type_(type_id).effective_base(mib.types_slice());
                assert_eq!(normalize_base_type(base), want_type);
            }
        }
    }
}

#[test]
fn module_alias_strictness() {
    for (strictness, want_resolved) in [
        (ResolverStrictness::Strict, false),
        (ResolverStrictness::Normal, true),
        (ResolverStrictness::Permissive, true),
    ] {
        let mib = load_at_strictness("PROBLEM-IMPORTS-ALIAS-MIB", strictness);
        assert_eq!(
            unresolved_symbols(&mib, "PROBLEM-IMPORTS-ALIAS-MIB", UnresolvedKind::Import)
                .is_empty(),
            want_resolved
        );

        let str_obj = mib.object_by_name("problemAliasString");
        let int_obj = mib.object_by_name("problemAliasInteger");
        assert_eq!(
            str_obj.is_some(),
            want_resolved,
            "problemAliasString at {strictness}"
        );
        assert_eq!(
            int_obj.is_some(),
            want_resolved,
            "problemAliasInteger at {strictness}"
        );
    }
}

#[test]
fn import_forwarding_type_resolution() {
    let mib = load_at_strictness("PROBLEM-FORWARDING-MIB", ResolverStrictness::Normal);
    let obj = require_object(&mib, "problemForwardedTypeObject");
    let type_id = obj.type_id().expect("type missing");
    assert_eq!(
        mib.type_(type_id).effective_base(mib.types_slice()),
        BaseType::OctetString
    );
}

#[test]
fn import_forwarding_all_levels() {
    for strictness in [
        ResolverStrictness::Strict,
        ResolverStrictness::Normal,
        ResolverStrictness::Permissive,
    ] {
        let mib = load_at_strictness("PROBLEM-FORWARDING-MIB", strictness);
        assert!(
            unresolved_symbols(&mib, "PROBLEM-FORWARDING-MIB", UnresolvedKind::Import).is_empty(),
            "imports should resolve at {strictness}"
        );
    }
}

#[test]
fn partial_resolution_in_strict_mode() {
    let mib = load_at_strictness("PROBLEM-IMPORTS-MIB", ResolverStrictness::Strict);
    assert!(!has_unresolved(
        &mib,
        "PROBLEM-IMPORTS-MIB",
        UnresolvedKind::Import,
        "Integer32"
    ));
    assert!(!has_unresolved(
        &mib,
        "PROBLEM-IMPORTS-MIB",
        UnresolvedKind::Import,
        "enterprises"
    ));
}

#[test]
fn strict_partial_import_resolution_per_symbol() {
    let mib = load_at_strictness("PROBLEM-PARTIAL-IMPORTS-MIB", ResolverStrictness::Strict);
    assert!(has_unresolved(
        &mib,
        "PROBLEM-PARTIAL-IMPORTS-MIB",
        UnresolvedKind::Import,
        "MissingType"
    ));
    assert!(has_unresolved(
        &mib,
        "PROBLEM-PARTIAL-IMPORTS-MIB",
        UnresolvedKind::Import,
        "missingParent"
    ));
    assert!(!has_unresolved(
        &mib,
        "PROBLEM-PARTIAL-IMPORTS-MIB",
        UnresolvedKind::Import,
        "DisplayString"
    ));
    assert!(!has_unresolved(
        &mib,
        "PROBLEM-PARTIAL-IMPORTS-MIB",
        UnresolvedKind::Import,
        "enterprises"
    ));
    assert!(!has_unresolved(
        &mib,
        "PROBLEM-PARTIAL-IMPORTS-MIB",
        UnresolvedKind::Import,
        "Integer32"
    ));

    let str_obj = require_object(&mib, "problemPartialString");
    let str_type = mib.type_(str_obj.type_id().expect("type missing"));
    assert_eq!(
        str_type.effective_base(mib.types_slice()),
        BaseType::OctetString
    );

    let int_obj = require_object(&mib, "problemPartialInteger");
    let node = int_obj.node().expect("node missing");
    assert_eq!(
        mib.tree().oid_of(node).to_string(),
        "1.3.6.1.4.1.99998.38.2"
    );
}

#[test]
fn strict_imported_metadata_preserved() {
    let mib = load_at_strictness("PROBLEM-STRICT-METADATA-MIB", ResolverStrictness::Strict);

    let display = require_object(&mib, "problemStrictDisplayString");
    assert_eq!(
        mib.type_(display.type_id().expect("type missing"))
            .effective_base(mib.types_slice()),
        BaseType::OctetString
    );
    assert_eq!(display.effective_display_hint(), "255a");
    assert_eq!(display.effective_sizes().len(), 1);
    assert_eq!(display.effective_sizes()[0].min, 0);
    assert_eq!(display.effective_sizes()[0].max, 255);

    let row_status = require_object(&mib, "problemStrictRowStatus");
    assert!(row_status.enum_by_label("active").is_some());
    assert_eq!(row_status.enum_by_label("active").unwrap().value, 1);
    assert!(row_status.enum_by_label("createAndWait").is_some());
    assert_eq!(row_status.enum_by_label("createAndWait").unwrap().value, 5);

    let mac = require_object(&mib, "problemStrictMacAddress");
    assert_eq!(mac.effective_display_hint(), "1x:");
    assert_eq!(mac.effective_sizes().len(), 1);
    assert_eq!(mac.effective_sizes()[0].min, 6);
    assert_eq!(mac.effective_sizes()[0].max, 6);

    let bridge = require_object(&mib, "problemStrictBridgeId");
    assert_eq!(bridge.effective_sizes().len(), 1);
    assert_eq!(bridge.effective_sizes()[0].min, 8);
    assert_eq!(bridge.effective_sizes()[0].max, 8);

    let timeout = require_object(&mib, "problemStrictTimeout");
    assert_eq!(timeout.effective_display_hint(), "d");
    assert_eq!(timeout.effective_ranges().len(), 1);
    assert_eq!(timeout.effective_ranges()[0].min, 100);
    assert_eq!(timeout.effective_ranges()[0].max, 1000);
}

#[test]
fn semantic_global_lookup_strictness_boundaries() {
    for (
        strictness,
        want_notif_objects,
        want_objects_unresolved,
        want_group_unresolved,
        want_member_not_local,
        want_compliance_group_status,
    ) in [
        (ResolverStrictness::Strict, 0, 1, 1, 1, 0),
        (ResolverStrictness::Normal, 0, 1, 1, 1, 0),
        (ResolverStrictness::Permissive, 1, 0, 0, 1, 1),
    ] {
        let mib = load_at_strictness("PROBLEM-SEMANTIC-GLOBAL-MIB", strictness);
        let notif_id = mib
            .notification_by_name("problemGlobalNotification")
            .expect("notification not found");
        let notif = mib.notification(notif_id);
        assert_eq!(notif.objects().len(), want_notif_objects);
        assert_eq!(
            count_diagnostics(&mib, DiagCode::ObjectsUnresolved),
            want_objects_unresolved
        );
        assert_eq!(
            count_diagnostics(&mib, DiagCode::GroupMemberUnresolved),
            want_group_unresolved
        );
        assert_eq!(
            count_diagnostics(&mib, DiagCode::ComplianceMemberNotLocal),
            want_member_not_local
        );
        assert_eq!(
            count_diagnostics(&mib, DiagCode::ComplianceGroupStatus),
            want_compliance_group_status
        );
    }
}

#[test]
fn capability_variation_global_lookup_strictness_boundaries() {
    for (
        strictness,
        want_object_variations,
        want_notification_variations,
        want_access_diag_count,
    ) in [
        (ResolverStrictness::Strict, 0, 1, 1),
        (ResolverStrictness::Normal, 0, 1, 1),
        (ResolverStrictness::Permissive, 1, 0, 0),
    ] {
        let mib = load_at_strictness("PROBLEM-SEMANTIC-GLOBAL-MIB", strictness);
        let cap_id = mib
            .capability_by_name("problemGlobalCapability")
            .expect("capability not found");
        let cap = mib.capability(cap_id);
        assert_eq!(cap.supports().len(), 1);
        let support = &cap.supports()[0];
        assert_eq!(support.object_variations.len(), want_object_variations);
        assert_eq!(
            support.notification_variations.len(),
            want_notification_variations
        );
        assert_eq!(
            count_diagnostics(&mib, DiagCode::VariationAccessNotifOnly),
            want_access_diag_count
        );
    }
}

#[test]
fn import_forwarding_oid_resolution() {
    let mib = load_at_strictness("PROBLEM-FORWARDING-MIB", ResolverStrictness::Normal);
    let node = require_node(&mib, "problemForwardedOidObject");
    assert_eq!(
        mib.tree().oid_of(node).to_string(),
        "1.3.6.1.4.1.99998.20.1.10"
    );
}

#[test]
fn strict_mode_index_resolution() {
    for strictness in [
        ResolverStrictness::Strict,
        ResolverStrictness::Normal,
        ResolverStrictness::Permissive,
    ] {
        let mib = load_at_strictness("RADLAN-MIB", strictness);
        for entry in ["rlPortGvrpTimersEntry", "rlStormCtrlEntry"] {
            let obj = require_object(&mib, entry);
            assert!(
                !obj.index().is_empty(),
                "{entry} should keep index at {strictness}"
            );
            let first = obj.index()[0].object.expect("index object missing");
            assert_eq!(mib.object(first).name(), "dot1dBasePort");
        }
    }
}

#[test]
fn real_corpus_strict_semantic_resolution() {
    let mib = load_at_strictness("HUAWEI-DISMAN-PING-MIB", ResolverStrictness::Strict);
    let obj = require_object(&mib, "hwPingCtlEntry");
    let augment = obj.augments().expect("augment missing");
    assert_eq!(mib.object(augment).name(), "pingCtlEntry");
    let augment_module = mib
        .object(augment)
        .module()
        .expect("augment module missing");
    assert_eq!(mib.module(augment_module).name(), "DISMAN-PING-MIB");

    let mib = load_at_strictness("TIMETRA-MPLS-MIB", ResolverStrictness::Strict);
    let comp_id = mib
        .compliance_by_name("tmnxMplsV22v0Compliance")
        .expect("compliance missing");
    let comp = mib.compliance(comp_id);
    assert_eq!(comp.modules().len(), 1);
    assert_eq!(comp.modules()[0].mandatory_groups.len(), 4);
    assert_eq!(
        count_module_diagnostics(&mib, "TIMETRA-MPLS-MIB", DiagCode::GroupMemberUnresolved),
        0
    );
    assert_eq!(
        count_module_diagnostics(&mib, "TIMETRA-MPLS-MIB", DiagCode::ComplianceGroupStatus),
        0
    );
}
