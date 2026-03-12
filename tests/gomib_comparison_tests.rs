// Exhaustive integration tests comparing mib-rs resolution output against
// gomib (Go) golden fixtures in testdata/fixtures/gomib/.
//
// Every field is compared with strict equality. No equivalence helpers,
// no normalization beyond what the Go fixture generator itself does.
// Any divergence is a potential bug in mib-rs.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mib_rs::load::{Loader, load};
use mib_rs::mib::{Mib, NodeId, Oid};
use mib_rs::source::dir_source;
use mib_rs::types::{DiagnosticConfig, ResolverStrictness};

use common::{FixtureNode, corpus_dir};

// -- Loading --

const GOMIB_MODULES: &[&str] = &[
    "HOST-RESOURCES-MIB",
    "SNMP-FRAMEWORK-MIB",
    "BGP4-MIB",
    "TCP-MIB",
    "UDP-MIB",
    "RMON-MIB",
    "LLDP-MIB",
    "OSPF-MIB",
    "ATM-MIB",
    "DISMAN-EVENT-MIB",
];

fn fixture_path(module: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/fixtures/gomib")
        .join(format!("{module}.json"))
}

fn load_fixture(module: &str) -> HashMap<String, FixtureNode> {
    let path = fixture_path(module);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()))
}

fn load_gomib_mib() -> Mib {
    let dir = corpus_dir();
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = Loader::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(GOMIB_MODULES.iter().copied());
    load(opts).expect("load failed")
}

// -- Extraction: mirrors gomib-fixturegen/main.go extractNodes exactly --

/// Extracted fields from mib-rs, in the same string format as gomib-fixturegen.
#[derive(Debug)]
struct ExtractedNode {
    oid: String,
    name: String,
    module: String,
    typ: String,
    access: String,
    status: String,
    hint: String,
    tc_name: String,
    units: String,
    enum_values: HashMap<i64, String>,
    indexes: Vec<(String, bool)>,
    augments: String,
    ranges: Vec<(i64, i64)>,
    default_value: String,
    kind: String,
    varbinds: Vec<String>,
    node_type: String,
    bit_values: HashMap<i64, String>,
    reference: String,
}

fn extract_node(mib: &Mib, node_id: NodeId) -> ExtractedNode {
    let tree = mib.tree();
    let node = tree.get(node_id);

    let mut e = ExtractedNode {
        oid: tree.oid_of(node_id).to_string(),
        name: node.name().to_string(),
        module: String::new(),
        typ: String::new(),
        access: String::new(),
        status: String::new(),
        hint: String::new(),
        tc_name: String::new(),
        units: String::new(),
        enum_values: HashMap::new(),
        indexes: Vec::new(),
        augments: String::new(),
        ranges: Vec::new(),
        default_value: String::new(),
        kind: String::new(),
        varbinds: Vec::new(),
        node_type: String::new(),
        bit_values: HashMap::new(),
        reference: String::new(),
    };

    // Module: Go does `if mod := node.Module(); mod != nil { n.Module = mod.Name() }`
    if let Some(mod_id) = mib.effective_module(node_id) {
        e.module = mib.raw().module(mod_id).name().to_string();
    }

    // Object fields: Go does `if obj := node.Object(); obj != nil { ... }`
    if let Some(obj_id) = node.object() {
        let obj = mib.raw().object(obj_id);

        // Type: Go does `normalizeType(obj.Type())` which returns "" for nil,
        // else `t.EffectiveBase().String()`
        e.typ = match obj.type_id() {
            Some(tid) => mib.raw().type_(tid).effective_base(mib.types_slice()).to_string(),
            None => String::new(),
        };

        e.access = obj.access().to_string();
        e.status = obj.status().to_string();
        e.units = obj.units().to_string();
        e.hint = obj.effective_display_hint().to_string();
        e.node_type = "OBJECT-TYPE".to_string();
        e.reference = obj.reference().to_string();

        // Kind: Go does `normalizeKind(obj.Kind())` which returns k.String()
        // for object-type kinds, else ""
        let k = obj.kind(mib.tree());
        e.kind = if k.is_object_type() {
            k.to_string()
        } else {
            String::new()
        };

        // TC name: Go does `if t := obj.Type(); t != nil && t.IsTextualConvention() { n.TCName = t.Name() }`
        if let Some(tid) = obj.type_id() {
            let t = mib.raw().type_(tid);
            if t.is_textual_convention() {
                e.tc_name = t.name().to_string();
            }
        }

        // Enums
        for nv in obj.effective_enums() {
            e.enum_values.insert(nv.value, nv.label.clone());
        }

        // Bits
        for nv in obj.effective_bits() {
            e.bit_values.insert(nv.value, nv.label.clone());
        }

        // Ranges: Go appends EffectiveRanges then EffectiveSizes (order matters)
        for r in obj.effective_ranges() {
            e.ranges.push((r.min, r.max));
        }
        for r in obj.effective_sizes() {
            e.ranges.push((r.min, r.max));
        }

        // DefaultValue: Go does `if dv := obj.DefaultValue(); !dv.IsZero() { n.DefaultValue = dv.String() }`
        if let Some(dv) = obj.default_value()
            && !dv.is_unset()
        {
            e.default_value = dv.to_string();
        }

        // Indexes
        for idx in obj.index() {
            if let Some(idx_obj_id) = idx.object {
                e.indexes
                    .push((mib.raw().object(idx_obj_id).name().to_string(), idx.implied));
            } else if !idx.name.is_empty() {
                e.indexes.push((idx.name.clone(), idx.implied));
            }
        }

        // Augments
        if let Some(aug_id) = obj.augments() {
            e.augments = mib.raw().object(aug_id).name().to_string();
        }
    }

    // Notification fields: Go does `if notif := node.Notification(); notif != nil { ... }`
    if let Some(notif_id) = node.notification() {
        let notif = mib.raw().notification(notif_id);
        e.status = notif.status().to_string();
        e.reference = notif.reference().to_string();
        e.node_type = "NOTIFICATION-TYPE".to_string();
        for &obj_id in notif.objects() {
            e.varbinds.push(mib.raw().object(obj_id).name().to_string());
        }
    }

    e
}

// -- Comparison: strict field-by-field equality --

fn fixture_int_map(m: &HashMap<String, String>) -> HashMap<i64, String> {
    m.iter()
        .map(|(k, v)| (k.parse::<i64>().unwrap(), v.clone()))
        .collect()
}

fn compare_nodes(got: &ExtractedNode, expected: &FixtureNode) -> Vec<String> {
    let mut failures = Vec::new();
    let id = format!("{} ({})", expected.name, expected.oid);

    macro_rules! check {
        ($field:literal, $got:expr, $exp:expr) => {
            if $got != $exp {
                failures.push(format!(
                    "{}: {}: got={:?} expected={:?}",
                    id, $field, $got, $exp
                ));
            }
        };
    }

    check!("Name", got.name, expected.name);
    check!("OID", got.oid, expected.oid);
    check!("Module", got.module, expected.module);
    check!("NodeType", got.node_type, expected.node_type);
    check!("Type", got.typ, expected.typ);
    check!("Access", got.access, expected.access);
    check!("Status", got.status, expected.status);
    check!("Hint", got.hint, expected.hint);
    check!("TCName", got.tc_name, expected.tc_name);
    check!("Units", got.units, expected.units);
    check!("Kind", got.kind, expected.kind);
    check!("DefaultValue", got.default_value, expected.default_value);
    check!("Augments", got.augments, expected.augments);
    check!("Reference", got.reference, expected.reference);

    // EnumValues
    let expected_enums = fixture_int_map(&expected.enum_values);
    if got.enum_values != expected_enums {
        failures.push(format!(
            "{}: EnumValues: got={:?} expected={:?}",
            id, got.enum_values, expected_enums
        ));
    }

    // BitValues
    let expected_bits = fixture_int_map(&expected.bit_values);
    if got.bit_values != expected_bits {
        failures.push(format!(
            "{}: BitValues: got={:?} expected={:?}",
            id, got.bit_values, expected_bits
        ));
    }

    // Indexes
    let expected_indexes: Vec<(String, bool)> = expected
        .indexes
        .as_ref()
        .map(|v| v.iter().map(|i| (i.name.clone(), i.implied)).collect())
        .unwrap_or_default();
    if got.indexes != expected_indexes {
        failures.push(format!(
            "{}: Indexes: got={:?} expected={:?}",
            id, got.indexes, expected_indexes
        ));
    }

    // Ranges
    let expected_ranges: Vec<(i64, i64)> = expected
        .ranges
        .as_ref()
        .map(|v| v.iter().map(|r| (r.low, r.high)).collect())
        .unwrap_or_default();
    if got.ranges != expected_ranges {
        failures.push(format!(
            "{}: Ranges: got={:?} expected={:?}",
            id, got.ranges, expected_ranges
        ));
    }

    // Varbinds
    let expected_varbinds: Vec<String> = expected.varbinds.clone().unwrap_or_default();
    if got.varbinds != expected_varbinds {
        failures.push(format!(
            "{}: Varbinds: got={:?} expected={:?}",
            id, got.varbinds, expected_varbinds
        ));
    }

    failures
}

// -- Tests --

#[test]
fn gomib_exhaustive_comparison() {
    let mib = load_gomib_mib();
    let mut failures = Vec::new();
    let mut total_checked = 0;

    for &module in GOMIB_MODULES {
        let fixture = load_fixture(module);

        // Forward: every fixture node must exist in mib-rs and match exactly
        for (fixture_oid, expected) in &fixture {
            total_checked += 1;

            let oid: Oid = fixture_oid
                .parse()
                .unwrap_or_else(|e| panic!("invalid OID in fixture {module}: {fixture_oid}: {e}"));

            let Some(node_id) = mib.node_by_oid(&oid) else {
                failures.push(format!(
                    "{} ({}): node not found in mib-rs",
                    expected.name, fixture_oid
                ));
                continue;
            };

            let got = extract_node(&mib, node_id);
            failures.extend(compare_nodes(&got, expected));
        }

        // Reverse: every mib-rs node in this module must exist in the fixture.
        // Build a set of fixture OIDs for this module.
        let fixture_oids: std::collections::HashSet<&str> =
            fixture.keys().map(|s| s.as_str()).collect();

        for node_id in mib.tree().all_nodes() {
            if let Some(mod_id) = mib.effective_module(node_id)
                && mib.raw().module(mod_id).name() == module
            {
                let oid = mib.tree().oid_of(node_id).to_string();
                if !fixture_oids.contains(oid.as_str()) {
                    let name = mib.tree().get(node_id).name();
                    failures.push(format!(
                        "{name} ({oid}): node exists in mib-rs module {module} but not in fixture"
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} divergences across {} fixture nodes:\n{}",
            failures.len(),
            total_checked,
            failures.join("\n")
        );
    }
}
