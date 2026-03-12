// Cross-implementation tests: run gomib (Go) and mib-rs (Rust) against the
// same MIB corpus at each strictness level, comparing resolved output
// field-by-field. No static fixture files - gomib-fixturegen is built and
// invoked as a subprocess, producing JSON on stdout.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use mib_rs::load::{LoadOptions, load};
use mib_rs::mib::{Mib, NodeId, Oid};
use mib_rs::source::dir_source;
use mib_rs::types::{BaseType, DiagnosticConfig, ResolverStrictness, Severity};
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
    #[serde(rename = "ComplianceModules", default)]
    compliance_modules: Vec<FixtureComplianceModule>,
    #[serde(rename = "CapabilitySupports", default)]
    capability_supports: Vec<FixtureCapabilityModule>,
}

#[derive(Debug, Deserialize)]
struct FixtureComplianceModule {
    #[serde(rename = "ModuleName")]
    module_name: String,
    #[serde(rename = "MandatoryGroups", default)]
    mandatory_groups: Vec<String>,
    #[serde(rename = "Groups", default)]
    groups: Vec<FixtureComplianceGroup>,
    #[serde(rename = "Objects", default)]
    objects: Vec<FixtureComplianceObject>,
}

#[derive(Debug, Deserialize)]
struct FixtureComplianceGroup {
    #[serde(rename = "Group")]
    group: String,
    #[serde(rename = "Description")]
    description: String,
}

#[derive(Debug, Deserialize)]
struct FixtureComplianceObject {
    #[serde(rename = "Object")]
    object: String,
    #[serde(rename = "Syntax")]
    syntax: Option<FixtureSyntaxConstraints>,
    #[serde(rename = "WriteSyntax")]
    write_syntax: Option<FixtureSyntaxConstraints>,
    #[serde(rename = "MinAccess")]
    min_access: String,
    #[serde(rename = "Description")]
    description: String,
}

#[derive(Debug, Deserialize)]
struct FixtureCapabilityModule {
    #[serde(rename = "ModuleName")]
    module_name: String,
    #[serde(rename = "Includes", default)]
    includes: Vec<String>,
    #[serde(rename = "ObjectVariations", default)]
    object_variations: Vec<FixtureObjectVariation>,
    #[serde(rename = "NotificationVariations", default)]
    notification_variations: Vec<FixtureNotificationVariation>,
}

#[derive(Debug, Deserialize)]
struct FixtureObjectVariation {
    #[serde(rename = "Object")]
    object: String,
    #[serde(rename = "Syntax")]
    syntax: Option<FixtureSyntaxConstraints>,
    #[serde(rename = "WriteSyntax")]
    write_syntax: Option<FixtureSyntaxConstraints>,
    #[serde(rename = "Access")]
    access: String,
    #[serde(rename = "CreationRequires", default)]
    creation_requires: Vec<String>,
    #[serde(rename = "DefaultValue")]
    default_value: String,
    #[serde(rename = "Description")]
    description: String,
}

#[derive(Debug, Deserialize)]
struct FixtureNotificationVariation {
    #[serde(rename = "Notification")]
    notification: String,
    #[serde(rename = "Access")]
    access: String,
    #[serde(rename = "Description")]
    description: String,
}

#[derive(Debug, Deserialize)]
struct FixtureSyntaxConstraints {
    #[serde(rename = "TypeName")]
    type_name: String,
    #[serde(rename = "Sizes", default)]
    sizes: Vec<RangeInfo>,
    #[serde(rename = "Ranges", default)]
    ranges: Vec<RangeInfo>,
    #[serde(rename = "Enums", default)]
    enums: HashMap<String, String>,
    #[serde(rename = "Bits", default)]
    bits: HashMap<String, String>,
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
struct FixtureType {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Module")]
    module: String,
    #[serde(rename = "Parent")]
    parent: String,
    #[serde(rename = "Base")]
    base: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "DisplayHint")]
    display_hint: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "IsTextualConvention")]
    is_textual_convention: bool,
    #[serde(rename = "Sizes", default)]
    sizes: Vec<RangeInfo>,
    #[serde(rename = "Ranges", default)]
    ranges: Vec<RangeInfo>,
    #[serde(rename = "Enums", default)]
    enums: HashMap<String, String>,
    #[serde(rename = "Bits", default)]
    bits: HashMap<String, String>,
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
    #[serde(rename = "Types", default)]
    types: HashMap<String, FixtureType>,
    #[serde(rename = "Diagnostics", default)]
    diagnostics: Vec<FixtureDiagnostic>,
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

#[derive(Debug, Deserialize)]
struct FixtureDiagnostic {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "Module", default)]
    module: String,
    #[serde(rename = "Line", default)]
    line: usize,
    #[serde(rename = "Column", default)]
    column: usize,
    #[serde(rename = "Message")]
    message: String,
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

fn run_fixturegen(strictness: &str, include_diagnostics: bool) -> FixturePayload {
    let bin = fixturegen_bin();
    let corpus = corpus_dir();

    let mut cmd = Command::new(bin);
    cmd.args([
        "-corpus",
        corpus.to_str().unwrap(),
        "-strictness",
        strictness,
        "-include-modules",
    ]);
    if include_diagnostics {
        cmd.arg("-include-diagnostics");
    }
    let output = cmd
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
    let diag = DiagnosticConfig {
        fail_at: Severity::Fatal,
        ..Default::default()
    };
    let opts = LoadOptions::new()
        .source(src)
        .resolver_strictness(strictness)
        .diagnostic_config(diag);
    load(opts).expect("load failed").mib
}

fn load_mibrs_with_diagnostics(strictness: ResolverStrictness) -> Mib {
    let dir = corpus_dir();
    let src = dir_source(&dir).expect("failed to create corpus source");
    let mut diag = DiagnosticConfig::verbose();
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
    compliance_modules: Vec<ExtractedComplianceModule>,
    capability_supports: Vec<ExtractedCapabilityModule>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedComplianceModule {
    module_name: String,
    mandatory_groups: Vec<String>,
    groups: Vec<ExtractedComplianceGroup>,
    objects: Vec<ExtractedComplianceObject>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedComplianceGroup {
    group: String,
    description: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedComplianceObject {
    object: String,
    syntax: Option<ExtractedSyntaxConstraints>,
    write_syntax: Option<ExtractedSyntaxConstraints>,
    min_access: String,
    description: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedCapabilityModule {
    module_name: String,
    includes: Vec<String>,
    object_variations: Vec<ExtractedObjectVariation>,
    notification_variations: Vec<ExtractedNotificationVariation>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedObjectVariation {
    object: String,
    syntax: Option<ExtractedSyntaxConstraints>,
    write_syntax: Option<ExtractedSyntaxConstraints>,
    access: String,
    creation_requires: Vec<String>,
    default_value: String,
    description: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedNotificationVariation {
    notification: String,
    access: String,
    description: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedSyntaxConstraints {
    type_name: String,
    sizes: Vec<(i64, i64)>,
    ranges: Vec<(i64, i64)>,
    enums: HashMap<i64, String>,
    bits: HashMap<i64, String>,
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

#[derive(Debug, PartialEq, Eq)]
struct ExtractedType {
    name: String,
    module: String,
    parent: String,
    base: String,
    status: String,
    display_hint: String,
    description: String,
    reference: String,
    is_textual_convention: bool,
    sizes: Vec<(i64, i64)>,
    ranges: Vec<(i64, i64)>,
    enums: HashMap<i64, String>,
    bits: HashMap<i64, String>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExtractedDiagnostic {
    code: String,
    severity: String,
    module: String,
    line: usize,
    column: usize,
    message: String,
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
        compliance_modules: Vec::new(),
        capability_supports: Vec::new(),
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

        if let Some(dv) = obj.default_value()
            && !dv.is_unset()
        {
            e.default_value = dv.to_string();
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
        e.compliance_modules = compliance
            .modules()
            .iter()
            .map(|cm| extract_compliance_module(mib, &e.module, cm))
            .collect();
    }

    if let Some(cap_id) = node.capability() {
        let capability = mib.capability(cap_id);
        e.status = capability.status().to_string();
        e.description = capability.description().to_string();
        e.reference = capability.reference().to_string();
        e.node_type = "AGENT-CAPABILITIES".to_string();
        e.product_release = capability.product_release().to_string();
        e.capability_supports = capability
            .supports()
            .iter()
            .map(|cm| extract_capability_module(mib, cm))
            .collect();
    }

    e
}

fn extract_compliance_module(
    mib: &Mib,
    owning_module: &str,
    cm: &mib_rs::mib::ComplianceModule,
) -> ExtractedComplianceModule {
    ExtractedComplianceModule {
        module_name: normalize_current_module_name(owning_module, &cm.module_name),
        mandatory_groups: cm.mandatory_groups.clone(),
        groups: cm
            .groups
            .iter()
            .map(|group| ExtractedComplianceGroup {
                group: group.group.clone(),
                description: group.description.clone(),
            })
            .collect(),
        objects: cm
            .objects
            .iter()
            .map(|obj| ExtractedComplianceObject {
                object: obj.object.clone(),
                syntax: obj
                    .syntax
                    .as_ref()
                    .map(|sc| extract_syntax_constraints(mib, sc)),
                write_syntax: obj
                    .write_syntax
                    .as_ref()
                    .map(|sc| extract_syntax_constraints(mib, sc)),
                min_access: obj.min_access.map(|a| a.to_string()).unwrap_or_default(),
                description: obj.description.clone(),
            })
            .collect(),
    }
}

fn extract_capability_module(
    mib: &Mib,
    cm: &mib_rs::mib::CapabilitiesModule,
) -> ExtractedCapabilityModule {
    ExtractedCapabilityModule {
        module_name: cm.module_name.clone(),
        includes: cm.includes.clone(),
        object_variations: cm
            .object_variations
            .iter()
            .map(|variation| ExtractedObjectVariation {
                object: variation.object.clone(),
                syntax: variation
                    .syntax
                    .as_ref()
                    .map(|sc| extract_syntax_constraints(mib, sc)),
                write_syntax: variation
                    .write_syntax
                    .as_ref()
                    .map(|sc| extract_syntax_constraints(mib, sc)),
                access: variation.access.map(|a| a.to_string()).unwrap_or_default(),
                creation_requires: variation.creation_requires.clone(),
                default_value: variation
                    .def_val
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                description: variation.description.clone(),
            })
            .collect(),
        notification_variations: cm
            .notification_variations
            .iter()
            .map(|variation| ExtractedNotificationVariation {
                notification: variation.notification.clone(),
                access: variation.access.map(|a| a.to_string()).unwrap_or_default(),
                description: variation.description.clone(),
            })
            .collect(),
    }
}

fn normalize_current_module_name(owning_module: &str, module_name: &str) -> String {
    if module_name.is_empty() || module_name == owning_module {
        String::new()
    } else {
        module_name.to_string()
    }
}

fn extract_syntax_constraints(
    mib: &Mib,
    sc: &mib_rs::mib::SyntaxConstraints,
) -> ExtractedSyntaxConstraints {
    ExtractedSyntaxConstraints {
        type_name: syntax_constraint_type_name(mib, sc),
        sizes: sc.sizes.iter().map(|r| (r.min, r.max)).collect(),
        ranges: sc.ranges.iter().map(|r| (r.min, r.max)).collect(),
        enums: sc
            .enums
            .iter()
            .map(|nv| (nv.value, nv.label.clone()))
            .collect(),
        bits: sc
            .bits
            .iter()
            .map(|nv| (nv.value, nv.label.clone()))
            .collect(),
    }
}

fn syntax_constraint_type_name(mib: &Mib, sc: &mib_rs::mib::SyntaxConstraints) -> String {
    let Some(type_id) = sc.type_id else {
        return String::new();
    };
    let type_ = mib.type_(type_id);
    if !type_.name().is_empty() {
        return type_.name().to_string();
    }
    base_type_syntax(type_.effective_base(mib.types_slice()))
}

fn base_type_syntax(base: BaseType) -> String {
    match base {
        BaseType::Integer32 => "Integer32".to_string(),
        BaseType::Unsigned32 => "Unsigned32".to_string(),
        BaseType::Counter32 => "Counter32".to_string(),
        BaseType::Counter64 => "Counter64".to_string(),
        BaseType::Gauge32 => "Gauge32".to_string(),
        BaseType::TimeTicks => "TimeTicks".to_string(),
        BaseType::IpAddress => "IpAddress".to_string(),
        BaseType::OctetString => "OCTET STRING".to_string(),
        BaseType::ObjectIdentifier => "OBJECT IDENTIFIER".to_string(),
        BaseType::Bits => "BITS".to_string(),
        BaseType::Opaque => "Opaque".to_string(),
        _ => base.to_string(),
    }
}

fn extract_module(mib: &Mib, mod_id: mib_rs::mib::ModuleId) -> ExtractedModule {
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

fn extract_type(mib: &Mib, type_id: mib_rs::mib::TypeId) -> ExtractedType {
    let type_ = mib.type_(type_id);

    ExtractedType {
        name: type_.name().to_string(),
        module: type_
            .module()
            .map(|mod_id| mib.module(mod_id).name().to_string())
            .unwrap_or_default(),
        parent: type_
            .parent()
            .map(|parent_id| normalized_parent_type_name(mib, parent_id))
            .unwrap_or_else(|| fallback_parent_type_name(type_.name()).to_string()),
        base: type_.effective_base(mib.types_slice()).to_string(),
        status: type_.status().to_string(),
        display_hint: type_.effective_display_hint(mib.types_slice()).to_string(),
        description: type_.description().to_string(),
        reference: type_.reference().to_string(),
        is_textual_convention: type_.is_textual_convention(),
        sizes: type_
            .effective_sizes(mib.types_slice())
            .iter()
            .map(|r| (r.min, r.max))
            .collect(),
        ranges: type_
            .effective_ranges(mib.types_slice())
            .iter()
            .map(|r| (r.min, r.max))
            .collect(),
        enums: type_
            .effective_enums(mib.types_slice())
            .iter()
            .map(|nv| (nv.value, nv.label.clone()))
            .collect(),
        bits: type_
            .effective_bits(mib.types_slice())
            .iter()
            .map(|nv| (nv.value, nv.label.clone()))
            .collect(),
    }
}

// -- Comparison --

fn fixture_int_map(m: &HashMap<String, String>) -> HashMap<i64, String> {
    m.iter()
        .map(|(k, v)| (k.parse::<i64>().unwrap(), v.clone()))
        .collect()
}

fn fixture_syntax_constraints(
    sc: &Option<FixtureSyntaxConstraints>,
) -> Option<ExtractedSyntaxConstraints> {
    sc.as_ref().map(|sc| ExtractedSyntaxConstraints {
        type_name: sc.type_name.clone(),
        sizes: sc.sizes.iter().map(|r| (r.low, r.high)).collect(),
        ranges: sc.ranges.iter().map(|r| (r.low, r.high)).collect(),
        enums: fixture_int_map(&sc.enums),
        bits: fixture_int_map(&sc.bits),
    })
}

fn fixture_compliance_modules(mods: &[FixtureComplianceModule]) -> Vec<ExtractedComplianceModule> {
    mods.iter()
        .map(|module| ExtractedComplianceModule {
            module_name: module.module_name.clone(),
            mandatory_groups: module.mandatory_groups.clone(),
            groups: module
                .groups
                .iter()
                .map(|group| ExtractedComplianceGroup {
                    group: group.group.clone(),
                    description: group.description.clone(),
                })
                .collect(),
            objects: module
                .objects
                .iter()
                .map(|obj| ExtractedComplianceObject {
                    object: obj.object.clone(),
                    syntax: fixture_syntax_constraints(&obj.syntax),
                    write_syntax: fixture_syntax_constraints(&obj.write_syntax),
                    min_access: obj.min_access.clone(),
                    description: obj.description.clone(),
                })
                .collect(),
        })
        .collect()
}

fn fixture_capability_modules(mods: &[FixtureCapabilityModule]) -> Vec<ExtractedCapabilityModule> {
    mods.iter()
        .map(|module| ExtractedCapabilityModule {
            module_name: module.module_name.clone(),
            includes: module.includes.clone(),
            object_variations: module
                .object_variations
                .iter()
                .map(|variation| ExtractedObjectVariation {
                    object: variation.object.clone(),
                    syntax: fixture_syntax_constraints(&variation.syntax),
                    write_syntax: fixture_syntax_constraints(&variation.write_syntax),
                    access: variation.access.clone(),
                    creation_requires: variation.creation_requires.clone(),
                    default_value: variation.default_value.clone(),
                    description: variation.description.clone(),
                })
                .collect(),
            notification_variations: module
                .notification_variations
                .iter()
                .map(|variation| ExtractedNotificationVariation {
                    notification: variation.notification.clone(),
                    access: variation.access.clone(),
                    description: variation.description.clone(),
                })
                .collect(),
        })
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

    let expected_compliance_modules = fixture_compliance_modules(&expected.compliance_modules);
    if got.compliance_modules != expected_compliance_modules {
        failures.push(format!(
            "{}: ComplianceModules: got={:?} expected={:?}",
            id, got.compliance_modules, expected_compliance_modules
        ));
    }

    let expected_capability_supports = fixture_capability_modules(&expected.capability_supports);
    if got.capability_supports != expected_capability_supports {
        failures.push(format!(
            "{}: CapabilitySupports: got={:?} expected={:?}",
            id, got.capability_supports, expected_capability_supports
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

fn fixture_type(expected: &FixtureType) -> ExtractedType {
    ExtractedType {
        name: expected.name.clone(),
        module: expected.module.clone(),
        parent: expected.parent.clone(),
        base: expected.base.clone(),
        status: expected.status.clone(),
        display_hint: expected.display_hint.clone(),
        description: expected.description.clone(),
        reference: expected.reference.clone(),
        is_textual_convention: expected.is_textual_convention,
        sizes: expected.sizes.iter().map(|r| (r.low, r.high)).collect(),
        ranges: expected.ranges.iter().map(|r| (r.low, r.high)).collect(),
        enums: fixture_int_map(&expected.enums),
        bits: fixture_int_map(&expected.bits),
    }
}

fn compare_types(got: &ExtractedType, expected: &FixtureType) -> Vec<String> {
    let mut failures = Vec::new();
    let id = qualified_type_name(&expected.module, &expected.name);
    let expected = fixture_type(expected);

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
    check!("Module", got.module, expected.module);
    check!("Parent", got.parent, expected.parent);
    check!("Base", got.base, expected.base);
    check!("Status", got.status, expected.status);
    check!("DisplayHint", got.display_hint, expected.display_hint);
    check!("Description", got.description, expected.description);
    check!("Reference", got.reference, expected.reference);
    check!(
        "IsTextualConvention",
        got.is_textual_convention,
        expected.is_textual_convention
    );
    check!("Sizes", got.sizes, expected.sizes);
    check!("Ranges", got.ranges, expected.ranges);
    check!("Enums", got.enums, expected.enums);
    check!("Bits", got.bits, expected.bits);

    failures
}

fn extract_diagnostics(mib: &Mib) -> Vec<ExtractedDiagnostic> {
    let mut diags: Vec<_> = mib
        .diagnostics()
        .iter()
        .map(|d| ExtractedDiagnostic {
            code: d.code.as_code().to_string(),
            severity: d.severity.to_string(),
            module: d.module.clone().unwrap_or_default(),
            line: d.line.unwrap_or(0),
            column: d.column.unwrap_or(0),
            message: normalize_diagnostic_message(&d.message),
        })
        .collect();

    diags.sort_by(|a, b| {
        a.code
            .cmp(&b.code)
            .then_with(|| a.severity.cmp(&b.severity))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.message.cmp(&b.message))
    });

    diags
}

fn normalize_diagnostic_message(message: &str) -> String {
    message.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn compare_diagnostics(
    strictness_name: &str,
    got: &[ExtractedDiagnostic],
    expected: &[FixtureDiagnostic],
) -> Vec<String> {
    let expected: Vec<_> = expected
        .iter()
        .map(|d| ExtractedDiagnostic {
            code: d.code.clone(),
            severity: d.severity.clone(),
            module: d.module.clone(),
            line: d.line,
            column: d.column,
            message: normalize_diagnostic_message(&d.message),
        })
        .collect();

    let got_counts = diagnostic_counts(got);
    let expected_counts = diagnostic_counts(&expected);
    let mut failures = Vec::new();
    let all_keys: std::collections::BTreeSet<_> = got_counts
        .keys()
        .chain(expected_counts.keys())
        .cloned()
        .collect();
    for key in all_keys {
        let got_count = got_counts.get(&key).copied().unwrap_or(0);
        let expected_count = expected_counts.get(&key).copied().unwrap_or(0);
        if got_count != expected_count {
            failures.push(format!(
                "[{strictness_name}] diagnostic count mismatch for module={} code={} severity={}: got={} expected={}",
                key.module, key.code, key.severity, got_count, expected_count
            ));
        }
    }
    failures
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DiagnosticCountKey {
    code: String,
    severity: String,
    module: String,
}

fn diagnostic_counts(diags: &[ExtractedDiagnostic]) -> BTreeMap<DiagnosticCountKey, usize> {
    let mut counts = BTreeMap::new();
    for d in diags {
        let key = DiagnosticCountKey {
            code: d.code.clone(),
            severity: d.severity.clone(),
            module: d.module.clone(),
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

fn qualified_type_name(module: &str, name: &str) -> String {
    if module.is_empty() {
        name.to_string()
    } else {
        format!("{module}::{name}")
    }
}

fn normalized_parent_type_name(mib: &Mib, type_id: mib_rs::mib::TypeId) -> String {
    let type_ = mib.type_(type_id);
    if !type_.name().is_empty() {
        return type_.name().to_string();
    }
    base_type_syntax(type_.effective_base(mib.types_slice()))
}

fn fallback_parent_type_name(type_name: &str) -> &'static str {
    match type_name {
        "Counter" | "Counter32" | "Counter64" | "Gauge" | "Gauge32" | "Unsigned32"
        | "TimeTicks" => "INTEGER",
        "IpAddress" | "Opaque" => "OCTET STRING",
        "NetworkAddress" => "IpAddress",
        _ => "",
    }
}

// -- Core comparison logic --

fn compare_at_strictness(strictness_name: &str, strictness: ResolverStrictness) -> Vec<String> {
    let payload = run_fixturegen(strictness_name, false);
    let gomib_nodes = payload.nodes;
    let gomib_modules = payload.modules;
    let gomib_types = payload.types;
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

    let mib_types_by_key: HashMap<String, mib_rs::mib::TypeId> = mib
        .modules_slice()
        .iter()
        .flat_map(|module| {
            module.types().iter().filter_map(|&type_id| {
                let type_ = mib.type_(type_id);
                if type_.name().is_empty() {
                    return None;
                }
                Some((qualified_type_name(module.name(), type_.name()), type_id))
            })
        })
        .collect();

    for (type_name, expected) in &gomib_types {
        let Some(&type_id) = mib_types_by_key.get(type_name) else {
            failures.push(format!(
                "[{strictness_name}] type {type_name}: present in gomib but not in mib-rs"
            ));
            continue;
        };
        let got = extract_type(&mib, type_id);
        for f in compare_types(&got, expected) {
            failures.push(format!("[{strictness_name}] {f}"));
        }
    }

    let gomib_type_modules: std::collections::HashSet<&str> = gomib_types
        .values()
        .map(|t| t.module.as_str())
        .filter(|m| !m.is_empty())
        .collect();
    let gomib_type_keys: std::collections::HashSet<&str> =
        gomib_types.keys().map(|s| s.as_str()).collect();

    for (index, type_) in mib.types_slice().iter().enumerate() {
        if type_.name().is_empty() {
            continue;
        }

        let module_name = type_
            .module()
            .map(|mod_id| mib.module(mod_id).name())
            .unwrap_or_default();
        if !module_name.is_empty() && gomib_type_modules.contains(module_name) {
            let key = qualified_type_name(module_name, type_.name());
            if !gomib_type_keys.contains(key.as_str()) {
                failures.push(format!(
                    "[{strictness_name}] type {} (index {}): in mib-rs module {} but not in gomib",
                    key, index, module_name
                ));
            }
        }
    }

    eprintln!(
        "[{strictness_name}] checked {} gomib nodes, {} divergences",
        total_checked,
        failures.len()
    );

    failures
}

fn compare_diagnostics_at_strictness(
    strictness_name: &str,
    strictness: ResolverStrictness,
) -> Vec<String> {
    let payload = run_fixturegen(strictness_name, true);
    let got = extract_diagnostics(&load_mibrs_with_diagnostics(strictness));
    compare_diagnostics(strictness_name, &got, &payload.diagnostics)
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

fn assert_no_diagnostic_divergences(level: &str, strictness: ResolverStrictness) {
    let failures = compare_diagnostics_at_strictness(level, strictness);
    if !failures.is_empty() {
        panic!(
            "{} diagnostic divergences at {level}:\n{}",
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

#[test]
fn diagnostics_cross_permissive() {
    assert_no_diagnostic_divergences("permissive", ResolverStrictness::Permissive);
}

#[test]
fn diagnostics_cross_normal() {
    assert_no_diagnostic_divergences("normal", ResolverStrictness::Normal);
}

#[test]
fn diagnostics_cross_strict() {
    assert_no_diagnostic_divergences("strict", ResolverStrictness::Strict);
}
