// Integration tests comparing mib-rs resolution output against net-snmp
// ground-truth fixtures in testdata/fixtures/netsnmp/.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use gomib::load::{LoadOptions, load};
use gomib::mib::Mib;
use gomib::source::dir_source;
use gomib::types::{BaseType, DiagnosticConfig, Kind, Language, ResolverStrictness};
use serde::Deserialize;

// -- Fixture schema --

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct FixtureNode {
    #[serde(rename = "OID")]
    oid: String,
    name: String,
    module: String,
    #[serde(rename = "Type")]
    typ: String,
    access: String,
    status: String,
    hint: String,
    #[serde(rename = "TCName")]
    tc_name: String,
    units: String,
    enum_values: HashMap<String, String>,
    indexes: Option<Vec<IndexInfo>>,
    augments: String,
    ranges: Option<Vec<RangeInfo>>,
    default_value: String,
    kind: String,
    varbinds: Option<Vec<String>>,
    node_type: String,
    bit_values: HashMap<String, String>,
    reference: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IndexInfo {
    name: String,
    implied: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RangeInfo {
    low: i64,
    high: i64,
}

// -- Fixture loading --

const FIXTURE_MODULES: &[&str] = &["IF-MIB", "SNMPv2-MIB", "IP-MIB", "ENTITY-MIB", "BRIDGE-MIB"];

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

fn fixture_path(module: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/fixtures/netsnmp")
        .join(format!("{module}.json"))
}

fn load_fixture(module: &str) -> HashMap<String, FixtureNode> {
    let path = fixture_path(module);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()))
}

fn load_fixture_mib() -> Mib {
    let dir = corpus_dir();
    let src = dir_source(&dir).expect("failed to create corpus source");
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(ResolverStrictness::Permissive)
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(FIXTURE_MODULES.iter().copied());
    load(opts).expect("load failed").mib
}

// -- Normalization --

fn normalize_base_type(base: BaseType) -> &'static str {
    match base {
        BaseType::Integer32 => "Integer32",
        BaseType::Unsigned32 => "Unsigned32",
        BaseType::Counter32 => "Counter32",
        BaseType::Counter64 => "Counter64",
        BaseType::Gauge32 => "Gauge32",
        BaseType::TimeTicks => "TimeTicks",
        BaseType::IpAddress => "IpAddress",
        BaseType::OctetString => "OCTET STRING",
        BaseType::ObjectIdentifier => "OBJECT IDENTIFIER",
        BaseType::Bits => "BITS",
        BaseType::Opaque => "Opaque",
        BaseType::Sequence => "OTHER",
        _ => "unknown",
    }
}

fn normalize_node_type(mib: &Mib, name: &str) -> String {
    if let Some(obj_id) = mib.object_by_name(name) {
        let obj = mib.object(obj_id);
        match obj.type_id() {
            Some(tid) => {
                let base = mib.type_(tid).effective_base(mib.types_slice());
                normalize_base_type(base).to_string()
            }
            None => "OTHER".to_string(),
        }
    } else if mib.notification_by_name(name).is_some() {
        "NOTIFICATION-TYPE".to_string()
    } else if let Some(gid) = mib.group_by_name(name) {
        if mib.group(gid).is_notification_group() {
            "NOTIFICATION-GROUP".to_string()
        } else {
            "OBJECT-GROUP".to_string()
        }
    } else if mib.compliance_by_name(name).is_some() {
        "MODULE-COMPLIANCE".to_string()
    } else if mib.capability_by_name(name).is_some() {
        "AGENT-CAPABILITIES".to_string()
    } else if let Some(node_id) = mib.node_by_name(name) {
        // Check for MODULE-IDENTITY: module OID matches node OID.
        if let Some(mod_id) = mib.effective_module(node_id) {
            let module = mib.module(mod_id);
            if let Some(mod_oid) = module.oid() {
                let node_oid = mib.tree().oid_of(node_id);
                if mod_oid == node_oid {
                    return "MODULE-IDENTITY".to_string();
                }
            }
        }
        "OTHER".to_string()
    } else {
        "OTHER".to_string()
    }
}

fn normalize_kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Table => "table",
        Kind::Row => "row",
        Kind::Column => "column",
        Kind::Scalar => "scalar",
        _ => "",
    }
}

fn normalize_enums(nvs: &[gomib::mib::NamedValue]) -> HashMap<i64, String> {
    nvs.iter().map(|nv| (nv.value, nv.label.clone())).collect()
}

fn fixture_enum_map(m: &HashMap<String, String>) -> HashMap<i64, String> {
    m.iter()
        .map(|(k, v)| (k.parse::<i64>().unwrap(), v.clone()))
        .collect()
}

// -- Equivalence helpers --

fn normalize_type_name(t: &str) -> &str {
    match t {
        "INTEGER" | "Integer32" => "Integer32",
        "COUNTER" | "Counter" | "Counter32" => "Counter32",
        "GAUGE" | "Gauge" | "Gauge32" => "Gauge32",
        "UNSIGNED32" | "Unsigned32" | "UInteger32" => "Unsigned32",
        "TIMETICKS" | "TimeTicks" => "TimeTicks",
        "IPADDR" | "IpAddress" => "IpAddress",
        "OCTETSTR" | "OCTET STRING" | "OctetString" => "OCTET STRING",
        "OBJID" | "OBJECT IDENTIFIER" | "ObjectIdentifier" => "OBJECT IDENTIFIER",
        "COUNTER64" | "Counter64" => "Counter64",
        "BITS" | "BITSTRING" => "BITS",
        "OPAQUE" | "Opaque" => "Opaque",
        other => other,
    }
}

fn types_equivalent(a: &str, b: &str) -> bool {
    a == b || normalize_type_name(a) == normalize_type_name(b)
}

fn signed_equiv(a: i64, b: i64) -> bool {
    if a == b {
        return true;
    }
    if a >= 0 && b < 0 && a == b.wrapping_add(1 << 32) {
        return true;
    }
    if b >= 0 && a < 0 && b == a.wrapping_add(1 << 32) {
        return true;
    }
    false
}

fn ranges_equivalent(gomib_ranges: &[(i64, i64)], fixture_ranges: &[(i64, i64)]) -> bool {
    if gomib_ranges.len() != fixture_ranges.len() {
        return false;
    }
    let mut g: Vec<_> = gomib_ranges.to_vec();
    let mut f: Vec<_> = fixture_ranges.to_vec();
    g.sort();
    f.sort();
    g.iter().zip(f.iter()).all(|(a, b)| {
        (a.0 == b.0 && a.1 == b.1) || (signed_equiv(a.0, b.0) && signed_equiv(a.1, b.1))
    })
}

fn status_equivalent(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    matches!((a, b), ("mandatory", "current") | ("current", "mandatory"))
}

fn access_equivalent(a: &str, b: &str, is_smiv1: bool) -> bool {
    if a == b {
        return true;
    }
    if is_smiv1 {
        return matches!(
            (a, b),
            ("read-write", "read-create") | ("read-create", "read-write")
        );
    }
    false
}

fn hints_equivalent(a: &str, b: &str) -> bool {
    a == b || a.trim().eq_ignore_ascii_case(b.trim())
}

fn defval_equivalent(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let a_norm = a.trim().trim_matches(|c| c == '"' || c == '\'');
    let b_norm = b.trim().trim_matches(|c| c == '"' || c == '\'');
    if a_norm == b_norm {
        return true;
    }
    if (is_hex_zeros(a_norm) && b_norm == "0") || (is_hex_zeros(b_norm) && a_norm == "0") {
        return true;
    }
    if (is_hex_all_ones(a_norm) && b_norm == "-1") || (is_hex_all_ones(b_norm) && a_norm == "-1") {
        return true;
    }
    false
}

fn is_hex_zeros(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
        return false;
    };
    !hex.is_empty() && hex.chars().all(|c| c == '0')
}

fn is_hex_all_ones(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
        return false;
    };
    !hex.is_empty() && hex.chars().all(|c| c == 'F' || c == 'f')
}

fn reference_equivalent(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    normalize_whitespace(a) == normalize_whitespace(b)
}

fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// -- Filters --

fn is_object_type_node(fn_: &FixtureNode) -> bool {
    !matches!(
        fn_.typ.as_str(),
        "" | "OTHER"
            | "NOTIFICATION-TYPE"
            | "TRAP-TYPE"
            | "MODULE-IDENTITY"
            | "MODULE-COMPLIANCE"
            | "OBJECT-GROUP"
            | "NOTIFICATION-GROUP"
            | "AGENT-CAPABILITIES"
            | "OBJECT-IDENTITY"
    )
}

fn is_notification_node(fn_: &FixtureNode) -> bool {
    fn_.node_type == "NOTIFICATION-TYPE" || fn_.node_type == "TRAP-TYPE"
}

// -- Test runner --

fn for_each_fixture_node(
    mib: &Mib,
    filter: impl Fn(&FixtureNode) -> bool,
    check: impl Fn(&Mib, &str, &FixtureNode, &mut Vec<String>),
) -> Vec<String> {
    let mut failures = Vec::new();
    for &module in FIXTURE_MODULES {
        let fixture = load_fixture(module);
        for (_, fn_) in &fixture {
            if !filter(fn_) {
                continue;
            }
            check(mib, module, fn_, &mut failures);
        }
    }
    failures
}

// -- Tests --

#[test]
fn fixture_node_type() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |_| true,
        |mib, _, fn_, failures| {
            let got = normalize_node_type(mib, &fn_.name);
            if !types_equivalent(&got, &fn_.node_type) {
                failures.push(format!(
                    "{}: node type: got={got:?} fixture={:?}",
                    fn_.name, fn_.node_type
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "node type divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_oids() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |_| true,
        |mib, _, fn_, failures| {
            let Some(node_id) = mib.node_by_name(&fn_.name) else {
                failures.push(format!("{}: not found in mib-rs", fn_.name));
                return;
            };
            let got = mib.tree().oid_of(node_id).to_string();
            if got != fn_.oid {
                failures.push(format!("{}: OID: got={got} fixture={}", fn_.name, fn_.oid));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "OID divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_types() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(&mib, is_object_type_node, |mib, _, fn_, failures| {
        let Some(obj_id) = mib.object_by_name(&fn_.name) else {
            failures.push(format!("{}: object not found", fn_.name));
            return;
        };
        let obj = mib.object(obj_id);

        // Base type
        let got_type = match obj.type_id() {
            Some(tid) => {
                let base = mib.type_(tid).effective_base(mib.types_slice());
                normalize_base_type(base).to_string()
            }
            None => String::new(),
        };
        if !types_equivalent(&got_type, &fn_.typ) {
            failures.push(format!(
                "{}: type: got={got_type:?} fixture={:?}",
                fn_.name, fn_.typ
            ));
        }

        // TC name
        let got_tc = match obj.type_id() {
            Some(tid) => {
                let t = mib.type_(tid);
                if t.is_textual_convention() {
                    t.name().to_string()
                } else {
                    String::new()
                }
            }
            None => String::new(),
        };
        if !fn_.tc_name.is_empty() || !got_tc.is_empty() {
            if got_tc != fn_.tc_name {
                failures.push(format!(
                    "{}: TC name: got={got_tc:?} fixture={:?}",
                    fn_.name, fn_.tc_name
                ));
            }
        }

        // Display hint
        let got_hint = obj.effective_display_hint();
        if !fn_.hint.is_empty() || !got_hint.is_empty() {
            if !hints_equivalent(got_hint, &fn_.hint) {
                failures.push(format!(
                    "{}: hint: got={got_hint:?} fixture={:?}",
                    fn_.name, fn_.hint
                ));
            }
        }
    });
    assert!(
        failures.is_empty(),
        "type divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_enums() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| is_object_type_node(fn_) && !fn_.enum_values.is_empty(),
        |mib, _, fn_, failures| {
            let Some(obj_id) = mib.object_by_name(&fn_.name) else {
                failures.push(format!("{}: object not found", fn_.name));
                return;
            };
            let obj = mib.object(obj_id);
            let got = normalize_enums(obj.effective_enums());
            let expected = fixture_enum_map(&fn_.enum_values);
            if got != expected {
                failures.push(format!(
                    "{}: enums: got={got:?} fixture={expected:?}",
                    fn_.name
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "enum divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_bits() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| is_object_type_node(fn_) && !fn_.bit_values.is_empty(),
        |mib, _, fn_, failures| {
            let Some(obj_id) = mib.object_by_name(&fn_.name) else {
                failures.push(format!("{}: object not found", fn_.name));
                return;
            };
            let obj = mib.object(obj_id);
            let got = normalize_enums(obj.effective_bits());
            let expected = fixture_enum_map(&fn_.bit_values);
            if got != expected {
                failures.push(format!(
                    "{}: bits: got={got:?} fixture={expected:?}",
                    fn_.name
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "bits divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_tables() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| !fn_.kind.is_empty() || fn_.indexes.is_some() || !fn_.augments.is_empty(),
        |mib, _, fn_, failures| {
            let Some(obj_id) = mib.object_by_name(&fn_.name) else {
                failures.push(format!("{}: object not found", fn_.name));
                return;
            };
            let obj = mib.object(obj_id);

            // Kind
            if !fn_.kind.is_empty() {
                let got_kind = normalize_kind(obj.kind(mib.tree()));
                if got_kind != fn_.kind {
                    failures.push(format!(
                        "{}: kind: got={got_kind:?} fixture={:?}",
                        fn_.name, fn_.kind
                    ));
                }
            }

            // Indexes
            if let Some(ref fix_indexes) = fn_.indexes {
                let got_indexes: Vec<_> = obj
                    .index()
                    .iter()
                    .filter_map(|e| {
                        let name = if let Some(oid) = e.object {
                            mib.object(oid).name().to_string()
                        } else if !e.type_name.is_empty() {
                            e.type_name.clone()
                        } else {
                            return None;
                        };
                        Some((name, e.implied))
                    })
                    .collect();
                let fix: Vec<_> = fix_indexes
                    .iter()
                    .map(|i| (i.name.clone(), i.implied))
                    .collect();
                if got_indexes != fix {
                    failures.push(format!(
                        "{}: indexes: got={got_indexes:?} fixture={fix:?}",
                        fn_.name
                    ));
                }
            }

            // Augments
            if !fn_.augments.is_empty() {
                let got_aug = match obj.augments() {
                    Some(aug_id) => mib.object(aug_id).name().to_string(),
                    None => String::new(),
                };
                if got_aug != fn_.augments {
                    failures.push(format!(
                        "{}: augments: got={got_aug:?} fixture={:?}",
                        fn_.name, fn_.augments
                    ));
                }
            }
        },
    );
    assert!(
        failures.is_empty(),
        "table divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_access() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| !fn_.access.is_empty(),
        |mib, _, fn_, failures| {
            let Some(obj_id) = mib.object_by_name(&fn_.name) else {
                failures.push(format!("{}: object not found", fn_.name));
                return;
            };
            let obj = mib.object(obj_id);
            let got = obj.access().to_string();
            let is_smiv1 = obj
                .module()
                .map(|mid| mib.module(mid).language() == Language::SMIv1)
                .unwrap_or(false);
            if !access_equivalent(&got, &fn_.access, is_smiv1) {
                failures.push(format!(
                    "{}: access: got={got:?} fixture={:?}",
                    fn_.name, fn_.access
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "access divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_status() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| !fn_.status.is_empty(),
        |mib, _, fn_, failures| {
            let got = if let Some(obj_id) = mib.object_by_name(&fn_.name) {
                mib.object(obj_id).status().to_string()
            } else if let Some(notif_id) = mib.notification_by_name(&fn_.name) {
                mib.notification(notif_id).status().to_string()
            } else {
                failures.push(format!("{}: not found", fn_.name));
                return;
            };
            if !status_equivalent(&got, &fn_.status) {
                failures.push(format!(
                    "{}: status: got={got:?} fixture={:?}",
                    fn_.name, fn_.status
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "status divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_ranges() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| is_object_type_node(fn_) && fn_.ranges.as_ref().is_some_and(|r| !r.is_empty()),
        |mib, _, fn_, failures| {
            let Some(obj_id) = mib.object_by_name(&fn_.name) else {
                failures.push(format!("{}: object not found", fn_.name));
                return;
            };
            let obj = mib.object(obj_id);
            let mut got: Vec<(i64, i64)> = Vec::new();
            for r in obj.effective_ranges() {
                got.push((r.min, r.max));
            }
            for r in obj.effective_sizes() {
                got.push((r.min, r.max));
            }
            let fix: Vec<(i64, i64)> = fn_
                .ranges
                .as_ref()
                .unwrap()
                .iter()
                .map(|r| (r.low, r.high))
                .collect();
            if !ranges_equivalent(&got, &fix) {
                failures.push(format!("{}: ranges: got={got:?} fixture={fix:?}", fn_.name));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "range divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_notifications() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(&mib, is_notification_node, |mib, _, fn_, failures| {
        let Some(notif_id) = mib.notification_by_name(&fn_.name) else {
            failures.push(format!("{}: notification not found", fn_.name));
            return;
        };
        let notif = mib.notification(notif_id);

        // OID
        if let Some(node_id) = notif.node() {
            let got_oid = mib.tree().oid_of(node_id).to_string();
            if got_oid != fn_.oid {
                failures.push(format!(
                    "{}: notification OID: got={got_oid} fixture={}",
                    fn_.name, fn_.oid
                ));
            }
        }

        // Varbinds
        if let Some(ref fix_varbinds) = fn_.varbinds {
            let got: Vec<String> = notif
                .objects()
                .iter()
                .map(|&oid| mib.object(oid).name().to_string())
                .collect();
            if got != *fix_varbinds {
                failures.push(format!(
                    "{}: varbinds: got={got:?} fixture={fix_varbinds:?}",
                    fn_.name
                ));
            }
        }

        // Status
        if !fn_.status.is_empty() {
            let got = notif.status().to_string();
            if !status_equivalent(&got, &fn_.status) {
                failures.push(format!(
                    "{}: notification status: got={got:?} fixture={:?}",
                    fn_.name, fn_.status
                ));
            }
        }
    });
    assert!(
        failures.is_empty(),
        "notification divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_units() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| is_object_type_node(fn_) && !fn_.units.is_empty(),
        |mib, _, fn_, failures| {
            let Some(obj_id) = mib.object_by_name(&fn_.name) else {
                failures.push(format!("{}: object not found", fn_.name));
                return;
            };
            let got = mib.object(obj_id).units();
            if got != fn_.units {
                failures.push(format!(
                    "{}: units: got={got:?} fixture={:?}",
                    fn_.name, fn_.units
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "units divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_defval() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(&mib, is_object_type_node, |mib, _, fn_, failures| {
        let Some(obj_id) = mib.object_by_name(&fn_.name) else {
            failures.push(format!("{}: object not found", fn_.name));
            return;
        };
        let obj = mib.object(obj_id);
        let got = match obj.default_value() {
            Some(dv) if !dv.is_unset() => dv.to_string(),
            _ => String::new(),
        };
        if fn_.default_value.is_empty() && got.is_empty() {
            return;
        }
        if !fn_.default_value.is_empty() && got.is_empty() {
            failures.push(format!(
                "{}: defval: mib-rs has none, fixture={:?}",
                fn_.name, fn_.default_value
            ));
            return;
        }
        if fn_.default_value.is_empty() && !got.is_empty() {
            failures.push(format!(
                "{}: defval: mib-rs={got:?}, fixture has none",
                fn_.name
            ));
            return;
        }
        if !defval_equivalent(&got, &fn_.default_value) {
            failures.push(format!(
                "{}: defval: got={got:?} fixture={:?}",
                fn_.name, fn_.default_value
            ));
        }
    });
    assert!(
        failures.is_empty(),
        "defval divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_reference() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| !fn_.reference.is_empty(),
        |mib, _, fn_, failures| {
            let got = if let Some(obj_id) = mib.object_by_name(&fn_.name) {
                mib.object(obj_id).reference().to_string()
            } else if let Some(notif_id) = mib.notification_by_name(&fn_.name) {
                mib.notification(notif_id).reference().to_string()
            } else {
                failures.push(format!("{}: not found", fn_.name));
                return;
            };
            if !reference_equivalent(&got, &fn_.reference) {
                failures.push(format!(
                    "{}: reference: got={got:?} fixture={:?}",
                    fn_.name, fn_.reference
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "reference divergences:\n{}",
        failures.join("\n")
    );
}

#[test]
fn fixture_module() {
    let mib = load_fixture_mib();
    let failures = for_each_fixture_node(
        &mib,
        |fn_| !fn_.module.is_empty(),
        |mib, _, fn_, failures| {
            let Some(node_id) = mib.node_by_name(&fn_.name) else {
                failures.push(format!("{}: not found", fn_.name));
                return;
            };
            let got = match mib.effective_module(node_id) {
                Some(mid) => mib.module(mid).name().to_string(),
                None => String::new(),
            };
            if got != fn_.module {
                failures.push(format!(
                    "{}: module: got={got:?} fixture={:?}",
                    fn_.name, fn_.module
                ));
            }
        },
    );
    assert!(
        failures.is_empty(),
        "module divergences:\n{}",
        failures.join("\n")
    );
}
