// Cross-implementation tests: run gomib (Go) and mib-rs (Rust) against the
// same MIB corpus at each strictness level, comparing resolved output
// field-by-field. No static fixture files - gomib-fixturegen is built and
// invoked as a subprocess, producing JSON on stdout.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use gomib::load::{LoadOptions, load};
use gomib::mib::{Mib, NodeId, Oid};
use gomib::source::dir_source;
use gomib::types::{DiagnosticConfig, ResolverStrictness, Severity};
use serde::Deserialize;

// -- Fixture schema (matches gomib-fixturegen JSON output) --

#[derive(Debug, Deserialize)]
struct FixtureNode {
    #[serde(rename = "OID")]
    oid: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Module")]
    module: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Type")]
    typ: String,
    #[serde(rename = "Access")]
    access: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Hint")]
    hint: String,
    #[serde(rename = "TCName")]
    tc_name: String,
    #[serde(rename = "Units")]
    units: String,
    #[serde(rename = "EnumValues")]
    enum_values: HashMap<String, String>,
    #[serde(rename = "Indexes")]
    indexes: Option<Vec<IndexInfo>>,
    #[serde(rename = "Augments")]
    augments: String,
    #[serde(rename = "Ranges")]
    ranges: Option<Vec<RangeInfo>>,
    #[serde(rename = "DefaultValue")]
    default_value: String,
    #[serde(rename = "Kind")]
    kind: String,
    #[serde(rename = "Varbinds")]
    varbinds: Option<Vec<String>>,
    #[serde(rename = "GroupMembers")]
    group_members: Option<Vec<String>>,
    #[serde(rename = "NodeType")]
    node_type: String,
    #[serde(rename = "BitValues")]
    bit_values: HashMap<String, String>,
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "ProductRelease")]
    product_release: String,
}

#[derive(Debug, Deserialize)]
struct FixtureModule {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "OID")]
    oid: String,
    #[serde(rename = "Organization")]
    organization: String,
    #[serde(rename = "ContactInfo")]
    contact_info: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "LastUpdated")]
    last_updated: String,
    #[serde(rename = "Revisions")]
    revisions: Option<Vec<FixtureRevision>>,
}

#[derive(Debug, Deserialize)]
struct FixtureRevision {
    #[serde(rename = "Date")]
    date: String,
    #[serde(rename = "Description")]
    description: String,
}

#[derive(Debug, Deserialize)]
struct FixturePayload {
    #[serde(rename = "Nodes")]
    nodes: HashMap<String, FixtureNode>,
    #[serde(rename = "Modules")]
    modules: HashMap<String, FixtureModule>,
}

#[derive(Debug, Deserialize)]
struct IndexInfo {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Implied")]
    implied: bool,
}

#[derive(Debug, Deserialize)]
struct RangeInfo {
    #[serde(rename = "Low")]
    low: i64,
    #[serde(rename = "High")]
    high: i64,
}

// -- Paths --

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

fn gomib_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("gomib")
}

// -- Build and run gomib-fixturegen --

static FIXTUREGEN_BIN: OnceLock<PathBuf> = OnceLock::new();

fn fixturegen_bin() -> &'static PathBuf {
    FIXTUREGEN_BIN.get_or_init(|| {
        let gomib = gomib_dir();
        let bin_path = gomib.join("gomib-fixturegen");

        let output = Command::new("go")
            .args([
                "build",
                "-o",
                bin_path.to_str().unwrap(),
                "./cmd/gomib-fixturegen/",
            ])
            .current_dir(&gomib)
            .output()
            .expect("failed to run go build");

        assert!(
            output.status.success(),
            "go build gomib-fixturegen failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        bin_path
    })
}

fn run_fixturegen(strictness: &str) -> FixturePayload {
    let bin = fixturegen_bin();
    let corpus = corpus_dir();

    let output = Command::new(bin)
        .args([
            "-corpus",
            corpus.to_str().unwrap(),
            "-strictness",
            strictness,
            "-include-modules",
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run gomib-fixturegen: {e}"));

    assert!(
        output.status.success(),
        "gomib-fixturegen -strictness {strictness} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!("failed to parse gomib-fixturegen output for strictness {strictness}: {e}")
    })
}

// -- Load mib-rs at a given strictness --

fn load_mibrs(strictness: ResolverStrictness) -> Mib {
    let dir = corpus_dir();
    let src = dir_source(&dir).expect("failed to create corpus source");
    // Never fail on diagnostics, matching Go's behavior where Load always
    // returns a valid Mib.
    let mut diag = DiagnosticConfig::default();
    diag.fail_at = Severity::Fatal;
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(strictness)
        .diagnostic_config(diag);
    load(opts).expect("load failed").mib
}

// -- Extraction (mirrors gomib-fixturegen extractNodes) --

#[derive(Debug)]
struct ExtractedNode {
    oid: String,
    name: String,
    module: String,
    description: String,
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
    group_members: Vec<String>,
    node_type: String,
    bit_values: HashMap<i64, String>,
    reference: String,
    product_release: String,
}

#[derive(Debug)]
struct ExtractedModule {
    name: String,
    oid: String,
    organization: String,
    contact_info: String,
    description: String,
    last_updated: String,
    revisions: Vec<(String, String)>,
}

fn extract_node(mib: &Mib, node_id: NodeId) -> ExtractedNode {
    let tree = mib.tree();
    let node = tree.get(node_id);

    let mut e = ExtractedNode {
        oid: tree.oid_of(node_id).to_string(),
        name: node.name().to_string(),
        module: String::new(),
        description: node.description().to_string(),
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
        group_members: Vec::new(),
        node_type: String::new(),
        bit_values: HashMap::new(),
        reference: node.reference().to_string(),
        product_release: String::new(),
    };

    if let Some(mod_id) = mib.effective_module(node_id) {
        let module = mib.module(mod_id);
        e.module = module.name().to_string();
        if module
            .oid()
            .is_some_and(|mod_oid| mod_oid == mib.tree().oid_of(node_id))
        {
            e.node_type = "MODULE-IDENTITY".to_string();
        }
    }

    if let Some(obj_id) = node.object() {
        let obj = mib.object(obj_id);

        e.typ = match obj.type_id() {
            Some(tid) => mib.type_(tid).effective_base(mib.types_slice()).to_string(),
            None => String::new(),
        };

        e.access = obj.access().to_string();
        e.status = obj.status().to_string();
        e.units = obj.units().to_string();
        e.hint = obj.effective_display_hint().to_string();
        e.node_type = "OBJECT-TYPE".to_string();
        e.description = obj.description().to_string();
        e.reference = obj.reference().to_string();

        let k = obj.kind(mib.tree());
        e.kind = if k.is_object_type() {
            k.to_string()
        } else {
            String::new()
        };

        if let Some(tid) = obj.type_id() {
            let t = mib.type_(tid);
            if t.is_textual_convention() {
                e.tc_name = t.name().to_string();
            }
        }

        for nv in obj.effective_enums() {
            e.enum_values.insert(nv.value, nv.label.clone());
        }
        for nv in obj.effective_bits() {
            e.bit_values.insert(nv.value, nv.label.clone());
        }

        for r in obj.effective_ranges() {
            e.ranges.push((r.min, r.max));
        }
        for r in obj.effective_sizes() {
            e.ranges.push((r.min, r.max));
        }

        if let Some(dv) = obj.default_value() {
            if !dv.is_unset() {
                e.default_value = dv.to_string();
            }
        }

        for idx in obj.index() {
            if let Some(idx_obj_id) = idx.object {
                e.indexes
                    .push((mib.object(idx_obj_id).name().to_string(), idx.implied));
            } else if !idx.type_name.is_empty() {
                e.indexes.push((idx.type_name.clone(), idx.implied));
            }
        }

        if let Some(aug_id) = obj.augments() {
            e.augments = mib.object(aug_id).name().to_string();
        }
    }

    if let Some(notif_id) = node.notification() {
        let notif = mib.notification(notif_id);
        e.status = notif.status().to_string();
        e.description = notif.description().to_string();
        e.reference = notif.reference().to_string();
        e.node_type = "NOTIFICATION-TYPE".to_string();
        for &obj_id in notif.objects() {
            e.varbinds.push(mib.object(obj_id).name().to_string());
        }
    }

    if let Some(group_id) = node.group() {
        let group = mib.group(group_id);
        e.status = group.status().to_string();
        e.description = group.description().to_string();
        e.reference = group.reference().to_string();
        e.node_type = if group.is_notification_group() {
            "NOTIFICATION-GROUP".to_string()
        } else {
            "OBJECT-GROUP".to_string()
        };
        for &member_id in group.members() {
            e.group_members
                .push(mib.tree().get(member_id).name().to_string());
        }
    }

    if let Some(comp_id) = node.compliance() {
        let compliance = mib.compliance(comp_id);
        e.status = compliance.status().to_string();
        e.description = compliance.description().to_string();
        e.reference = compliance.reference().to_string();
        e.node_type = "MODULE-COMPLIANCE".to_string();
    }

    if let Some(cap_id) = node.capability() {
        let capability = mib.capability(cap_id);
        e.status = capability.status().to_string();
        e.description = capability.description().to_string();
        e.reference = capability.reference().to_string();
        e.node_type = "AGENT-CAPABILITIES".to_string();
        e.product_release = capability.product_release().to_string();
    }

    e
}

fn extract_module(mib: &Mib, mod_id: gomib::mib::ModuleId) -> ExtractedModule {
    let module = mib.module(mod_id);
    let revisions = module
        .revisions()
        .iter()
        .map(|r| (r.date.clone(), r.description.clone()))
        .collect();

    ExtractedModule {
        name: module.name().to_string(),
        oid: module.oid().map(|oid| oid.to_string()).unwrap_or_default(),
        organization: module.organization().to_string(),
        contact_info: module.contact_info().to_string(),
        description: module.description().to_string(),
        last_updated: module.last_updated().to_string(),
        revisions,
    }
}

// -- Comparison --

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
    check!("Description", got.description, expected.description);
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
    check!(
        "ProductRelease",
        got.product_release,
        expected.product_release
    );

    let expected_enums = fixture_int_map(&expected.enum_values);
    if got.enum_values != expected_enums {
        failures.push(format!(
            "{}: EnumValues: got={:?} expected={:?}",
            id, got.enum_values, expected_enums
        ));
    }

    let expected_bits = fixture_int_map(&expected.bit_values);
    if got.bit_values != expected_bits {
        failures.push(format!(
            "{}: BitValues: got={:?} expected={:?}",
            id, got.bit_values, expected_bits
        ));
    }

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

    let expected_varbinds: Vec<String> = expected.varbinds.clone().unwrap_or_default();
    if got.varbinds != expected_varbinds {
        failures.push(format!(
            "{}: Varbinds: got={:?} expected={:?}",
            id, got.varbinds, expected_varbinds
        ));
    }

    let expected_group_members: Vec<String> = expected.group_members.clone().unwrap_or_default();
    if got.group_members != expected_group_members {
        failures.push(format!(
            "{}: GroupMembers: got={:?} expected={:?}",
            id, got.group_members, expected_group_members
        ));
    }

    failures
}

fn compare_modules(got: &ExtractedModule, expected: &FixtureModule) -> Vec<String> {
    let mut failures = Vec::new();
    let id = expected.name.as_str();

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
    check!("Organization", got.organization, expected.organization);
    check!("ContactInfo", got.contact_info, expected.contact_info);
    check!("Description", got.description, expected.description);
    check!("LastUpdated", got.last_updated, expected.last_updated);

    let expected_revisions: Vec<(String, String)> = expected
        .revisions
        .as_ref()
        .map(|revisions| {
            revisions
                .iter()
                .map(|r| (r.date.clone(), r.description.clone()))
                .collect()
        })
        .unwrap_or_default();
    if got.revisions != expected_revisions {
        failures.push(format!(
            "{}: Revisions: got={:?} expected={:?}",
            id, got.revisions, expected_revisions
        ));
    }

    failures
}

// -- Core comparison logic --

fn compare_at_strictness(strictness_name: &str, strictness: ResolverStrictness) -> Vec<String> {
    let payload = run_fixturegen(strictness_name);
    let gomib_nodes = payload.nodes;
    let gomib_modules = payload.modules;
    let mib = load_mibrs(strictness);

    let mut failures = Vec::new();
    let mut total_checked = 0;

    // Forward: every gomib node must exist in mib-rs and match
    for (fixture_oid, expected) in &gomib_nodes {
        total_checked += 1;

        let oid: Oid = match fixture_oid.parse() {
            Ok(o) => o,
            Err(e) => {
                failures.push(format!(
                    "[{strictness_name}] invalid OID in gomib output: {fixture_oid}: {e}"
                ));
                continue;
            }
        };

        let Some(node_id) = mib.node_by_oid(&oid) else {
            failures.push(format!(
                "[{strictness_name}] {} ({}): node not found in mib-rs",
                expected.name, fixture_oid
            ));
            continue;
        };

        let got = extract_node(&mib, node_id);
        for f in compare_nodes(&got, expected) {
            failures.push(format!("[{strictness_name}] {f}"));
        }
    }

    // Reverse: collect all mib-rs modules present in gomib output,
    // then check every mib-rs node in those modules exists in gomib
    let gomib_node_modules: std::collections::HashSet<&str> = gomib_nodes
        .values()
        .map(|n| n.module.as_str())
        .filter(|m| !m.is_empty())
        .collect();
    let gomib_oids: std::collections::HashSet<&str> =
        gomib_nodes.keys().map(|s| s.as_str()).collect();

    for node_id in mib.tree().all_nodes() {
        if let Some(mod_id) = mib.effective_module(node_id) {
            let mod_name = mib.module(mod_id).name();
            if gomib_node_modules.contains(mod_name) {
                let oid = mib.tree().oid_of(node_id).to_string();
                if !gomib_oids.contains(oid.as_str()) {
                    let name = mib.tree().get(node_id).name();
                    failures.push(format!(
                        "[{strictness_name}] {name} ({oid}): in mib-rs module {mod_name} but not in gomib"
                    ));
                }
            }
        }
    }

    for (module_name, expected) in &gomib_modules {
        let Some(mod_id) = mib.module_by_name(module_name) else {
            failures.push(format!(
                "[{strictness_name}] module {module_name}: present in gomib but not in mib-rs"
            ));
            continue;
        };
        let got = extract_module(&mib, mod_id);
        for f in compare_modules(&got, expected) {
            failures.push(format!("[{strictness_name}] {f}"));
        }
    }

    for module in mib.modules_slice() {
        if !gomib_modules.contains_key(module.name()) {
            failures.push(format!(
                "[{strictness_name}] module {}: present in mib-rs but not in gomib",
                module.name()
            ));
        }
    }

    eprintln!(
        "[{strictness_name}] checked {} gomib nodes, {} divergences",
        total_checked,
        failures.len()
    );

    failures
}

// -- Tests --

fn assert_no_divergences(level: &str, strictness: ResolverStrictness) {
    let failures = compare_at_strictness(level, strictness);
    if !failures.is_empty() {
        panic!(
            "{} divergences at {level}:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn cross_permissive() {
    assert_no_divergences("permissive", ResolverStrictness::Permissive);
}

#[test]
fn cross_normal() {
    assert_no_divergences("normal", ResolverStrictness::Normal);
}

#[test]
fn cross_strict() {
    assert_no_divergences("strict", ResolverStrictness::Strict);
}
