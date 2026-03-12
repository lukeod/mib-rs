use std::cmp::Ordering;

use serde::Serialize;

use crate::mib::Mib;
use crate::mib::Oid;
use crate::mib::typedef::TypeData;
use crate::mib::types::*;
use crate::types::{Access, BaseType, Kind, Language, ResolverStrictness, Severity, Status};

/// Top-level payload for the schema v1 resolved-mib export.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPayload {
    pub schema_version: u32,
    pub export_kind: &'static str,
    pub strictness: String,
    pub exporter: Exporter,
    pub modules: Vec<ExportModule>,
    pub types: Vec<ExportType>,
    pub nodes: Vec<ExportNode>,
    pub objects: Vec<ExportObject>,
    pub notifications: Vec<ExportNotification>,
    pub groups: Vec<ExportGroup>,
    pub compliances: Vec<ExportCompliance>,
    pub capabilities: Vec<ExportCapability>,
    pub diagnostics: Vec<ExportDiagnostic>,
}

#[derive(Serialize)]
pub struct Exporter {
    pub implementation: &'static str,
    pub version: String,
    pub commit: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportModule {
    pub name: String,
    pub oid: Option<String>,
    pub language: Option<String>,
    pub organization: Option<String>,
    pub contact_info: Option<String>,
    pub description: Option<String>,
    pub last_updated: Option<String>,
    pub revisions: Vec<ExportRevision>,
}

#[derive(Serialize)]
pub struct ExportRevision {
    pub date: String,
    pub description: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportType {
    pub key: String,
    pub name: String,
    pub module: String,
    pub parent: Option<String>,
    pub base: String,
    pub status: Option<String>,
    pub display_hint: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub is_textual_convention: bool,
    pub constraints: ExportConstraints,
}

#[derive(Serialize)]
pub struct ExportConstraints {
    pub sizes: Vec<ExportRange>,
    pub ranges: Vec<ExportRange>,
    pub enums: Vec<ExportEnum>,
    pub bits: Vec<ExportBit>,
}

#[derive(Serialize)]
pub struct ExportRange {
    pub min: String,
    pub max: String,
}

#[derive(Serialize)]
pub struct ExportEnum {
    pub name: String,
    pub value: i64,
}

#[derive(Serialize)]
pub struct ExportBit {
    pub name: String,
    pub position: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportEffectiveSyntax {
    pub type_ref: Option<String>,
    pub base: String,
    pub display_hint: Option<String>,
    pub constraints: ExportConstraints,
}

#[derive(Serialize)]
pub struct ExportOidRef {
    pub name: String,
    pub module: String,
    pub oid: String,
}

#[derive(Serialize)]
pub struct ExportNode {
    pub key: String,
    pub oid: String,
    pub name: String,
    pub module: String,
    pub kind: String,
    pub status: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportObject {
    pub key: String,
    pub oid: String,
    pub name: String,
    pub module: String,
    pub kind: String,
    pub status: String,
    pub access: String,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub units: Option<String>,
    pub default_value: Option<ExportDefVal>,
    pub syntax: Option<ExportEffectiveSyntax>,
    pub indexes: Vec<ExportIndex>,
    pub effective_indexes: Vec<ExportIndex>,
    pub augments: Option<ExportOidRef>,
    pub augmented_by: Vec<ExportOidRef>,
    pub table: Option<ExportOidRef>,
    pub row: Option<ExportOidRef>,
    pub columns: Vec<ExportOidRef>,
}

#[derive(Serialize)]
pub struct ExportDefVal {
    pub kind: String,
    pub value: serde_json::Value,
    pub raw: String,
}

#[derive(Serialize)]
pub struct ExportIndex {
    pub object: Option<ExportOidRef>,
    pub implied: bool,
    pub syntax: Option<ExportEffectiveSyntax>,
}

#[derive(Serialize)]
pub struct ExportNotification {
    pub key: String,
    pub oid: String,
    pub name: String,
    pub module: String,
    pub status: String,
    pub kind: String,
    pub trap: Option<ExportTrap>,
    pub description: String,
    pub reference: Option<String>,
    pub objects: Vec<ExportOidRef>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportTrap {
    pub enterprise: ExportOidRef,
    pub trap_number: u32,
}

#[derive(Serialize)]
pub struct ExportGroup {
    pub key: String,
    pub oid: String,
    pub name: String,
    pub module: String,
    pub kind: String,
    pub status: String,
    pub description: String,
    pub reference: Option<String>,
    pub members: Vec<ExportOidRef>,
}

#[derive(Serialize)]
pub struct ExportCompliance {
    pub key: String,
    pub oid: String,
    pub name: String,
    pub module: String,
    pub status: String,
    pub description: String,
    pub reference: Option<String>,
    pub modules: Vec<ExportComplianceModule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportComplianceModule {
    pub module: String,
    pub is_current_module: bool,
    pub mandatory_groups: Vec<ExportOidRef>,
    pub groups: Vec<ExportComplianceGroup>,
    pub objects: Vec<ExportComplianceObject>,
}

#[derive(Serialize)]
pub struct ExportComplianceGroup {
    pub group: ExportOidRef,
    pub description: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportComplianceObject {
    pub object: ExportOidRef,
    pub syntax: Option<ExportEffectiveSyntax>,
    pub write_syntax: Option<ExportEffectiveSyntax>,
    pub min_access: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportCapability {
    pub key: String,
    pub oid: String,
    pub name: String,
    pub module: String,
    pub status: String,
    pub product_release: Option<String>,
    pub description: String,
    pub reference: Option<String>,
    pub supports: Vec<ExportCapabilitySupports>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportCapabilitySupports {
    pub module: String,
    pub includes: Vec<ExportOidRef>,
    pub object_variations: Vec<ExportObjectVariation>,
    pub notification_variations: Vec<ExportNotificationVariation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportObjectVariation {
    pub object: ExportOidRef,
    pub syntax: Option<ExportEffectiveSyntax>,
    pub write_syntax: Option<ExportEffectiveSyntax>,
    pub access: Option<String>,
    pub creation_requires: Vec<ExportOidRef>,
    pub default_value: Option<ExportDefVal>,
    pub description: Option<String>,
}

#[derive(Serialize)]
pub struct ExportNotificationVariation {
    pub notification: ExportOidRef,
    pub access: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize)]
pub struct ExportDiagnostic {
    pub phase: String,
    pub code: String,
    pub severity: String,
    pub module: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
}

// --- Schema-canonical string mappings ---

fn base_type_str(b: BaseType) -> &'static str {
    match b {
        BaseType::Unknown => "Unknown",
        BaseType::Integer32 => "Integer32",
        BaseType::Unsigned32 => "Unsigned32",
        BaseType::Counter32 => "Counter32",
        BaseType::Counter64 => "Counter64",
        BaseType::Gauge32 => "Gauge32",
        BaseType::TimeTicks => "TimeTicks",
        BaseType::IpAddress => "IpAddress",
        BaseType::OctetString => "OctetString",
        BaseType::ObjectIdentifier => "ObjectIdentifier",
        BaseType::Bits => "Bits",
        BaseType::Opaque => "Opaque",
        BaseType::Sequence => "Unknown",
        BaseType::Integer64 => "Integer64",
        BaseType::Unsigned64 => "Unsigned64",
    }
}

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Current => "current",
        Status::Deprecated => "deprecated",
        Status::Obsolete => "obsolete",
        Status::Mandatory => "mandatory",
        Status::Optional => "optional",
    }
}

fn access_str(a: Access) -> &'static str {
    match a {
        Access::NotAccessible => "not-accessible",
        Access::AccessibleForNotify => "accessible-for-notify",
        Access::ReadOnly => "read-only",
        Access::ReadWrite => "read-write",
        Access::ReadCreate => "read-create",
        Access::WriteOnly => "write-only",
        Access::NotImplemented => "not-implemented",
    }
}

fn language_str(l: Language) -> Option<&'static str> {
    match l {
        Language::Unknown => None,
        Language::SMIv1 => Some("SMIv1"),
        Language::SMIv2 => Some("SMIv2"),
        Language::SPPI => Some("SPPI"),
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Fatal | Severity::Severe | Severity::Error => "error",
        Severity::Minor => "warning",
        Severity::Warning => "warning",
        Severity::Info => "info",
        Severity::Style => "style",
    }
}

fn object_kind_str(k: Kind) -> &'static str {
    match k {
        Kind::Scalar => "scalar",
        Kind::Table => "table",
        Kind::Row => "row",
        Kind::Column => "column",
        _ => "object",
    }
}

fn opt_string(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn is_user_defined_type(mib: &Mib, td: &TypeData) -> bool {
    if td.is_textual_convention() {
        return true;
    }
    !matches!(td.module(), Some(mid) if mib.raw().module(mid).is_base())
}

// --- Export building ---

fn make_constraints(
    sizes: &[Range],
    ranges: &[Range],
    enums: &[NamedValue],
    bits: &[NamedValue],
) -> ExportConstraints {
    ExportConstraints {
        sizes: sizes
            .iter()
            .map(|r| ExportRange {
                min: r.min.to_string(),
                max: r.max.to_string(),
            })
            .collect(),
        ranges: ranges
            .iter()
            .map(|r| ExportRange {
                min: r.min.to_string(),
                max: r.max.to_string(),
            })
            .collect(),
        enums: enums
            .iter()
            .map(|e| ExportEnum {
                name: e.label.clone(),
                value: e.value,
            })
            .collect(),
        bits: bits
            .iter()
            .map(|b| ExportBit {
                name: b.label.clone(),
                position: b.value,
            })
            .collect(),
    }
}

fn make_oid_ref(name: &str, module: &str, oid: &str) -> ExportOidRef {
    ExportOidRef {
        name: name.to_string(),
        module: module.to_string(),
        oid: oid.to_string(),
    }
}

fn resolve_object_ref(mib: &Mib, name: &str, fallback_module: &str) -> ExportOidRef {
    if let Some(obj_id) = mib.object_by_name(name) {
        let obj = mib.raw().object(obj_id);
        let mod_name = obj.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid_str = obj
            .node()
            .map(|nid| mib.tree().oid_of(nid).to_string())
            .unwrap_or_default();
        make_oid_ref(name, mod_name, &oid_str)
    } else {
        make_oid_ref(name, fallback_module, "")
    }
}

fn resolve_node_ref(mib: &Mib, name: &str) -> ExportOidRef {
    resolve_node_ref_with_fallback(mib, name, "")
}

fn resolve_node_ref_with_fallback(mib: &Mib, name: &str, fallback_module: &str) -> ExportOidRef {
    if let Some(node_id) = mib.node_by_name(name) {
        let node = mib.tree().get(node_id);
        let mod_name = mib
            .effective_module(node_id)
            .map(|mid| mib.raw().module(mid).name())
            .unwrap_or("");
        let oid_str = mib.tree().oid_of(node_id).to_string();
        make_oid_ref(
            if node.name().is_empty() {
                name
            } else {
                node.name()
            },
            mod_name,
            &oid_str,
        )
    } else {
        make_oid_ref(name, fallback_module, "")
    }
}

fn resolve_notification_ref(mib: &Mib, name: &str, fallback_module: &str) -> ExportOidRef {
    if let Some(notif_id) = mib.notification_by_name(name) {
        let notif = mib.raw().notification(notif_id);
        let mod_name = notif
            .module()
            .map(|mid| mib.raw().module(mid).name())
            .unwrap_or("");
        let oid_str = notif
            .node()
            .map(|nid| mib.tree().oid_of(nid).to_string())
            .unwrap_or_default();
        make_oid_ref(name, mod_name, &oid_str)
    } else {
        // Fall back to generic node lookup (the variation may reference a
        // non-notification object that the syntactic heuristic classified
        // as a notification variation).
        resolve_node_ref_with_fallback(mib, name, fallback_module)
    }
}

fn object_id_to_ref(mib: &Mib, obj_id: ObjectId) -> ExportOidRef {
    let obj = mib.raw().object(obj_id);
    let mod_name = obj.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
    let oid_str = obj
        .node()
        .map(|nid| mib.tree().oid_of(nid).to_string())
        .unwrap_or_default();
    make_oid_ref(obj.name(), mod_name, &oid_str)
}

fn make_defval(dv: &DefVal) -> Option<ExportDefVal> {
    let (kind_str, value) = match &dv.value {
        DefValValue::None => return None,
        DefValValue::Int(v) => ("int", serde_json::Value::String(v.to_string())),
        DefValValue::Uint(v) => ("uint", serde_json::Value::String(v.to_string())),
        DefValValue::String(v) => ("string", serde_json::Value::String(v.clone())),
        DefValValue::Bytes(b) => {
            let hex: String = b.iter().map(|byte| format!("{byte:02X}")).collect();
            ("bytes", serde_json::Value::String(hex))
        }
        DefValValue::Enum(label) => ("enum", serde_json::Value::String(label.clone())),
        DefValValue::Bits(labels) => {
            let arr: Vec<serde_json::Value> = labels
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect();
            ("bits", serde_json::Value::Array(arr))
        }
        DefValValue::Oid(oid) => ("oid", serde_json::Value::String(oid.to_string())),
    };
    Some(ExportDefVal {
        kind: kind_str.to_string(),
        value,
        raw: dv.raw().to_string(),
    })
}

fn make_effective_syntax_from_object(mib: &Mib, obj_id: ObjectId) -> Option<ExportEffectiveSyntax> {
    let obj = mib.raw().object(obj_id);
    let type_id = obj.type_id()?;
    let td = mib.raw().type_(type_id);
    let types = mib.types_slice();
    let base = td.effective_base(types);

    let type_ref = if td.name().is_empty() || !is_user_defined_type(mib, td) {
        None
    } else {
        let mod_name = td.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        Some(format!("{mod_name}::{}", td.name()))
    };

    let display_hint = {
        let h = obj.effective_display_hint();
        if h.is_empty() {
            let h2 = td.effective_display_hint(types);
            opt_string(h2)
        } else {
            Some(h.to_string())
        }
    };

    Some(ExportEffectiveSyntax {
        type_ref,
        base: base_type_str(base).to_string(),
        display_hint,
        constraints: make_constraints(
            obj.effective_sizes(),
            obj.effective_ranges(),
            obj.effective_enums(),
            obj.effective_bits(),
        ),
    })
}

fn make_syntax_constraints(mib: &Mib, sc: &SyntaxConstraints) -> ExportEffectiveSyntax {
    let (type_ref, base, display_hint) = if let Some(tid) = sc.type_id {
        let td = mib.raw().type_(tid);
        let types = mib.types_slice();
        let mod_name = td.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let tr = if td.name().is_empty() || !is_user_defined_type(mib, td) {
            None
        } else {
            Some(format!("{mod_name}::{}", td.name()))
        };
        let b = td.effective_base(types);
        let h = td.effective_display_hint(types);
        (tr, b, opt_string(h))
    } else {
        (None, BaseType::Unknown, None)
    };

    ExportEffectiveSyntax {
        type_ref,
        base: base_type_str(base).to_string(),
        display_hint,
        constraints: make_constraints(&sc.sizes, &sc.ranges, &sc.enums, &sc.bits),
    }
}

/// Compare two OIDs numerically for sorting.
fn cmp_oid(a: &Oid, b: &Oid) -> Ordering {
    for (aa, bb) in a.iter().zip(b.iter()) {
        match aa.cmp(bb) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

fn sort_keyed_values<K, T, F>(mut items: Vec<(K, T)>, mut cmp: F) -> Vec<T>
where
    F: FnMut(&(K, T), &(K, T)) -> Ordering,
{
    items.sort_by(|a, b| cmp(a, b));
    items.into_iter().map(|(_, value)| value).collect()
}

fn sort_oid_keyed_values<T, F>(items: Vec<(Oid, T)>, mut tie_break: F) -> Vec<T>
where
    F: FnMut(&T, &T) -> Ordering,
{
    sort_keyed_values(items, |a, b| {
        cmp_oid(&a.0, &b.0).then_with(|| tie_break(&a.1, &b.1))
    })
}

/// Build the complete schema v1 export payload from a resolved Mib.
pub fn export_v1(mib: &Mib, strictness: ResolverStrictness) -> ExportPayload {
    let tree = mib.tree();

    // --- Modules ---
    let mut modules: Vec<ExportModule> = mib
        .modules_slice()
        .iter()
        .map(|m| ExportModule {
            name: m.name().to_string(),
            oid: m.oid().map(|o| o.to_string()),
            language: language_str(m.language()).map(|s| s.to_string()),
            organization: opt_string(m.organization()),
            contact_info: opt_string(m.contact_info()),
            description: opt_string(m.description()),
            last_updated: opt_string(m.last_updated()),
            revisions: m
                .revisions()
                .iter()
                .map(|r| ExportRevision {
                    date: r.date.clone(),
                    description: r.description.clone(),
                })
                .collect(),
        })
        .collect();
    modules.sort_by(|a, b| a.name.cmp(&b.name));

    // --- Types ---
    let mut types: Vec<ExportType> = mib
        .types_slice()
        .iter()
        .map(|t| {
            let mod_name = t.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
            let parent = t.parent().and_then(|pid| {
                let pt = mib.raw().type_(pid);
                if pt.name().is_empty() || !is_user_defined_type(mib, pt) {
                    return None;
                }
                let pm = pt.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
                Some(format!("{pm}::{}", pt.name()))
            });
            let all_types = mib.types_slice();
            let eff_base = t.effective_base(all_types);

            ExportType {
                key: format!("{mod_name}::{}", t.name()),
                name: t.name().to_string(),
                module: mod_name.to_string(),
                parent,
                base: base_type_str(eff_base).to_string(),
                status: if t.is_textual_convention() {
                    Some(status_str(t.status()).to_string())
                } else {
                    None
                },
                display_hint: opt_string(t.display_hint()),
                description: opt_string(t.description()),
                reference: opt_string(t.reference()),
                is_textual_convention: t.is_textual_convention(),
                constraints: make_constraints(t.sizes(), t.ranges(), t.enums(), t.bits()),
            }
        })
        .collect();
    types.sort_by(|a, b| a.module.cmp(&b.module).then(a.name.cmp(&b.name)));

    // --- Nodes ---
    // Nodes are plain OID-bearing definitions that are NOT objects, notifications,
    // groups, compliances, or capabilities.
    let mut nodes: Vec<ExportNode> = Vec::new();
    for node_id in tree.all_nodes() {
        let nd = tree.get(node_id);
        if nd.name().is_empty() {
            continue;
        }
        // Skip nodes that have attached entities exported elsewhere
        if nd.object.is_some()
            || nd.notification.is_some()
            || nd.group.is_some()
            || nd.compliance.is_some()
            || nd.capability.is_some()
        {
            continue;
        }
        let mod_id = mib.effective_module(node_id);
        let mod_name = mod_id.map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid_str = tree.oid_of(node_id).to_string();

        let kind = match nd.kind() {
            Kind::ModuleIdentity => "module-identity",
            Kind::ObjectIdentity => "object-identity",
            _ => "node",
        };

        let status = match nd.kind() {
            Kind::ModuleIdentity | Kind::ObjectIdentity => {
                nd.status().map(|s| status_str(s).to_string())
            }
            _ => None,
        };

        nodes.push(ExportNode {
            key: format!("{mod_name}::{}", nd.name()),
            oid: oid_str,
            name: nd.name().to_string(),
            module: mod_name.to_string(),
            kind: kind.to_string(),
            status,
            description: opt_string(nd.description()),
            reference: opt_string(nd.reference()),
        });
    }
    nodes.sort_by(|a, b| a.module.cmp(&b.module).then(a.name.cmp(&b.name)));

    // --- Objects ---
    let mut objects: Vec<(Oid, ExportObject)> = Vec::new();
    for (i, obj) in mib.objects_slice().iter().enumerate() {
        let obj_id = ObjectId::new(i as u32);
        let node_id = match obj.node() {
            Some(id) => id,
            None => continue,
        };
        let mod_id = obj.module();
        let mod_name = mod_id.map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid = tree.oid_of(node_id).clone();
        let oid_str = oid.to_string();
        let kind = obj.kind(tree);

        let syntax = make_effective_syntax_from_object(mib, obj_id);

        let default_value = obj
            .default_value()
            .and_then(|dv| if dv.is_unset() { None } else { make_defval(dv) });

        let indexes: Vec<ExportIndex> = obj
            .index()
            .iter()
            .map(|idx| make_index_entry(mib, idx))
            .collect();

        let eff_indexes: Vec<ExportIndex> = mib
            .effective_indexes(obj_id)
            .iter()
            .map(|idx| make_index_entry(mib, idx))
            .collect();

        let augments = obj.augments().map(|aid| object_id_to_ref(mib, aid));

        let augmented_by: Vec<ExportOidRef> = obj
            .augmented_by()
            .iter()
            .map(|&aid| object_id_to_ref(mib, aid))
            .collect();

        let table = match kind {
            Kind::Row | Kind::Column => mib
                .object_table(obj_id)
                .map(|tid| object_id_to_ref(mib, tid)),
            _ => None,
        };

        let row = match kind {
            Kind::Table => mib
                .object_entry(obj_id)
                .map(|rid| object_id_to_ref(mib, rid)),
            Kind::Column => mib.object_row(obj_id).map(|rid| object_id_to_ref(mib, rid)),
            _ => None,
        };

        let columns: Vec<ExportOidRef> = match kind {
            Kind::Table | Kind::Row => {
                let cols: Vec<(Oid, ExportOidRef)> = mib
                    .object_columns(obj_id)
                    .into_iter()
                    .map(|cid| {
                        let col_oid = mib
                            .raw()
                            .object(cid)
                            .node()
                            .map(|nid| tree.oid_of(nid).clone())
                            .unwrap_or_default();
                        (col_oid, object_id_to_ref(mib, cid))
                    })
                    .collect();
                sort_oid_keyed_values(cols, |a, b| {
                    a.module.cmp(&b.module).then(a.name.cmp(&b.name))
                })
            }
            _ => Vec::new(),
        };

        // Sort augmented_by by OID
        let augmented_sorted: Vec<(Oid, ExportOidRef)> = augmented_by
            .into_iter()
            .map(|r| {
                let o: Oid = r.oid.parse().unwrap_or_default();
                (o, r)
            })
            .collect();
        let augmented_by = sort_oid_keyed_values(augmented_sorted, |a, b| {
            a.module.cmp(&b.module).then(a.name.cmp(&b.name))
        });

        objects.push((
            oid.clone(),
            ExportObject {
                key: format!("{mod_name}::{}", obj.name()),
                oid: oid_str,
                name: obj.name().to_string(),
                module: mod_name.to_string(),
                kind: object_kind_str(kind).to_string(),
                status: status_str(obj.status()).to_string(),
                access: access_str(obj.access()).to_string(),
                description: opt_string(obj.description()),
                reference: opt_string(obj.reference()),
                units: opt_string(obj.units()),
                default_value,
                syntax,
                indexes,
                effective_indexes: eff_indexes,
                augments,
                augmented_by,
                table,
                row,
                columns,
            },
        ));
    }
    let objects = sort_oid_keyed_values(objects, |a, b| {
        a.module.cmp(&b.module).then(a.name.cmp(&b.name))
    });

    // --- Notifications ---
    let mut notifications: Vec<(Oid, ExportNotification)> = Vec::new();
    for notif in mib.notifications_slice() {
        let mod_id = notif.module();
        let mod_name = mod_id.map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid = notif
            .node()
            .map(|nid| tree.oid_of(nid).clone())
            .unwrap_or_default();
        let oid_str = oid.to_string();

        let kind = if notif.trap_info().is_some() {
            "trap"
        } else {
            "notification"
        };

        let trap = notif.trap_info().map(|ti| {
            let enterprise_ref = resolve_node_ref(mib, &ti.enterprise);
            ExportTrap {
                enterprise: enterprise_ref,
                trap_number: ti.trap_number,
            }
        });

        let notif_objects: Vec<ExportOidRef> = notif
            .objects()
            .iter()
            .map(|&oid| object_id_to_ref(mib, oid))
            .collect();

        notifications.push((
            oid.clone(),
            ExportNotification {
                key: format!("{mod_name}::{}", notif.name()),
                oid: oid_str,
                name: notif.name().to_string(),
                module: mod_name.to_string(),
                status: status_str(notif.status()).to_string(),
                kind: kind.to_string(),
                trap,
                description: notif.description().to_string(),
                reference: opt_string(notif.reference()),
                objects: notif_objects,
            },
        ));
    }
    let notifications = sort_oid_keyed_values(notifications, |a, b| {
        a.module
            .cmp(&b.module)
            .then(a.name.cmp(&b.name))
            // "notification" < "trap" alphabetically, preferring NOTIFICATION-TYPE over TRAP-TYPE
            .then(a.kind.cmp(&b.kind))
    });

    // --- Groups ---
    let mut groups: Vec<(Oid, ExportGroup)> = Vec::new();
    for group in mib.groups_slice() {
        let mod_id = group.module();
        let mod_name = mod_id.map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid = group
            .node()
            .map(|nid| tree.oid_of(nid).clone())
            .unwrap_or_default();
        let oid_str = oid.to_string();

        let kind = if group.is_notification_group() {
            "notification-group"
        } else {
            "object-group"
        };

        let members: Vec<ExportOidRef> = group
            .members()
            .iter()
            .map(|&nid| {
                let nd = tree.get(nid);
                let m = mib
                    .effective_module(nid)
                    .map(|mid| mib.raw().module(mid).name())
                    .unwrap_or("");
                make_oid_ref(nd.name(), m, &tree.oid_of(nid).to_string())
            })
            .collect();

        groups.push((
            oid.clone(),
            ExportGroup {
                key: format!("{mod_name}::{}", group.name()),
                oid: oid_str,
                name: group.name().to_string(),
                module: mod_name.to_string(),
                kind: kind.to_string(),
                status: status_str(group.status()).to_string(),
                description: group.description().to_string(),
                reference: opt_string(group.reference()),
                members,
            },
        ));
    }
    let groups = sort_oid_keyed_values(groups, |a, b| {
        a.module
            .cmp(&b.module)
            .then(a.name.cmp(&b.name))
            // Prefer larger groups first for duplicate keys
            .then(b.members.len().cmp(&a.members.len()))
    });

    // --- Compliances ---
    let mut compliances: Vec<(Oid, ExportCompliance)> = Vec::new();
    for comp in mib.compliances_slice() {
        let mod_id = comp.module();
        let comp_mod_name = mod_id.map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid = comp
            .node()
            .map(|nid| tree.oid_of(nid).clone())
            .unwrap_or_default();
        let oid_str = oid.to_string();

        let comp_modules: Vec<ExportComplianceModule> = comp
            .modules()
            .iter()
            .map(|cm| {
                let is_current = cm.module_name.is_empty() || cm.module_name == comp_mod_name;
                let effective_module = if cm.module_name.is_empty() {
                    comp_mod_name.to_string()
                } else {
                    cm.module_name.clone()
                };

                let mandatory_groups: Vec<ExportOidRef> = cm
                    .mandatory_groups
                    .iter()
                    .map(|name| resolve_node_ref_with_fallback(mib, name, &effective_module))
                    .collect();

                let grps: Vec<ExportComplianceGroup> = cm
                    .groups
                    .iter()
                    .map(|cg| ExportComplianceGroup {
                        group: resolve_node_ref_with_fallback(mib, &cg.group, &effective_module),
                        description: opt_string(&cg.description),
                    })
                    .collect();

                let objs: Vec<ExportComplianceObject> = cm
                    .objects
                    .iter()
                    .map(|co| ExportComplianceObject {
                        object: resolve_object_ref(mib, &co.object, &effective_module),
                        syntax: co
                            .syntax
                            .as_ref()
                            .map(|sc| make_syntax_constraints(mib, sc)),
                        write_syntax: co
                            .write_syntax
                            .as_ref()
                            .map(|sc| make_syntax_constraints(mib, sc)),
                        min_access: co.min_access.map(|a| access_str(a).to_string()),
                        description: opt_string(&co.description),
                    })
                    .collect();

                ExportComplianceModule {
                    module: effective_module,
                    is_current_module: is_current,
                    mandatory_groups,
                    groups: grps,
                    objects: objs,
                }
            })
            .collect();

        compliances.push((
            oid.clone(),
            ExportCompliance {
                key: format!("{comp_mod_name}::{}", comp.name()),
                oid: oid_str,
                name: comp.name().to_string(),
                module: comp_mod_name.to_string(),
                status: status_str(comp.status()).to_string(),
                description: comp.description().to_string(),
                reference: opt_string(comp.reference()),
                modules: comp_modules,
            },
        ));
    }
    let compliances = sort_oid_keyed_values(compliances, |a, b| {
        a.module.cmp(&b.module).then(a.name.cmp(&b.name))
    });

    // --- Capabilities ---
    let mut capabilities: Vec<(Oid, ExportCapability)> = Vec::new();
    for cap in mib.capabilities_slice() {
        let mod_id = cap.module();
        let mod_name = mod_id.map(|mid| mib.raw().module(mid).name()).unwrap_or("");
        let oid = cap
            .node()
            .map(|nid| tree.oid_of(nid).clone())
            .unwrap_or_default();
        let oid_str = oid.to_string();

        let supports: Vec<ExportCapabilitySupports> = cap
            .supports()
            .iter()
            .map(|sm| {
                let includes: Vec<ExportOidRef> = sm
                    .includes
                    .iter()
                    .map(|name| resolve_node_ref_with_fallback(mib, name, &sm.module_name))
                    .collect();

                let obj_vars: Vec<ExportObjectVariation> =
                    sm.object_variations
                        .iter()
                        .map(|ov| {
                            let creation_req: Vec<ExportOidRef> = ov
                                .creation_requires
                                .iter()
                                .map(|name| resolve_object_ref(mib, name, &sm.module_name))
                                .collect();

                            ExportObjectVariation {
                                object: resolve_object_ref(mib, &ov.object, &sm.module_name),
                                syntax: ov
                                    .syntax
                                    .as_ref()
                                    .map(|sc| make_syntax_constraints(mib, sc)),
                                write_syntax: ov
                                    .write_syntax
                                    .as_ref()
                                    .map(|sc| make_syntax_constraints(mib, sc)),
                                access: ov.access.map(|a| access_str(a).to_string()),
                                creation_requires: creation_req,
                                default_value: ov.def_val.as_ref().and_then(|dv| {
                                    if dv.is_unset() { None } else { make_defval(dv) }
                                }),
                                description: opt_string(&ov.description),
                            }
                        })
                        .collect();

                let notif_vars: Vec<ExportNotificationVariation> = sm
                    .notification_variations
                    .iter()
                    .map(|nv| ExportNotificationVariation {
                        notification: resolve_notification_ref(
                            mib,
                            &nv.notification,
                            &sm.module_name,
                        ),
                        access: nv.access.map(|a| access_str(a).to_string()),
                        description: opt_string(&nv.description),
                    })
                    .collect();

                ExportCapabilitySupports {
                    module: sm.module_name.clone(),
                    includes,
                    object_variations: obj_vars,
                    notification_variations: notif_vars,
                }
            })
            .collect();

        capabilities.push((
            oid.clone(),
            ExportCapability {
                key: format!("{mod_name}::{}", cap.name()),
                oid: oid_str,
                name: cap.name().to_string(),
                module: mod_name.to_string(),
                status: status_str(cap.status()).to_string(),
                product_release: opt_string(cap.product_release()),
                description: cap.description().to_string(),
                reference: opt_string(cap.reference()),
                supports,
            },
        ));
    }
    let capabilities = sort_oid_keyed_values(capabilities, |a, b| {
        a.module.cmp(&b.module).then(a.name.cmp(&b.name))
    });

    // --- Diagnostics ---
    let mut diagnostics: Vec<ExportDiagnostic> = mib
        .diagnostics()
        .iter()
        .map(|d| {
            let phase = d.code.phase().to_string();
            ExportDiagnostic {
                phase,
                code: d.code.as_code().to_string(),
                severity: severity_str(d.severity).to_string(),
                module: d.module.clone(),
                line: d.line,
                column: d.column,
                message: d.message.replace("\r\n", "\n"),
            }
        })
        .collect();
    diagnostics.sort_by(|a, b| {
        a.phase
            .cmp(&b.phase)
            .then(a.code.cmp(&b.code))
            .then(a.severity.cmp(&b.severity))
            .then(a.module.cmp(&b.module))
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.message.cmp(&b.message))
    });

    ExportPayload {
        schema_version: 1,
        export_kind: "resolved-mib",
        strictness: strictness.to_string(),
        exporter: Exporter {
            implementation: "mib-rs",
            version: String::new(),
            commit: String::new(),
        },
        modules,
        types,
        nodes,
        objects,
        notifications,
        groups,
        compliances,
        capabilities,
        diagnostics,
    }
}

fn make_index_entry(mib: &Mib, idx: &IndexEntry) -> ExportIndex {
    match idx.object {
        Some(oid) => ExportIndex {
            object: Some(object_id_to_ref(mib, oid)),
            implied: idx.implied,
            syntax: None,
        },
        None => {
            // Type-backed index - build effective syntax from type name lookup
            let syntax = if let Some(tid) = mib.type_by_name(&idx.type_name) {
                let td = mib.raw().type_(tid);
                let types = mib.types_slice();
                let base = td.effective_base(types);
                let mod_name = td.module().map(|mid| mib.raw().module(mid).name()).unwrap_or("");
                let type_ref = if td.name().is_empty() {
                    None
                } else {
                    Some(format!("{mod_name}::{}", td.name()))
                };
                Some(ExportEffectiveSyntax {
                    type_ref,
                    base: base_type_str(base).to_string(),
                    display_hint: opt_string(td.effective_display_hint(types)),
                    constraints: make_constraints(
                        td.effective_sizes(types),
                        td.effective_ranges(types),
                        td.effective_enums(types),
                        td.effective_bits(types),
                    ),
                })
            } else {
                Some(ExportEffectiveSyntax {
                    type_ref: None,
                    base: "Unknown".to_string(),
                    display_hint: None,
                    constraints: make_constraints(&[], &[], &[], &[]),
                })
            };
            ExportIndex {
                object: None,
                implied: idx.implied,
                syntax,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::load::{Loader, load};
    use crate::source::dir_source;
    use crate::types::{DiagnosticConfig, ResolverStrictness};

    use super::export_v1;

    fn corpus_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
    }

    fn load_corpus(modules: &[&str]) -> crate::mib::Mib {
        let src = dir_source(corpus_dir()).expect("failed to create corpus source");
        let opts = Loader::new()
            .source(src)
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent())
            .modules(modules.iter().copied());
        load(opts).expect("load failed")
    }

    #[test]
    fn export_includes_base_modules_and_builtins() {
        let mib = load_corpus(&["IF-MIB"]);
        let payload = export_v1(&mib, ResolverStrictness::Permissive);

        assert!(
            payload.modules.iter().any(|m| m.name == "SNMPv2-SMI"),
            "expected SNMPv2-SMI in exported modules"
        );
        assert!(
            payload.types.iter().any(|t| t.module == "SNMPv2-SMI"),
            "expected SNMPv2-SMI types in exported types"
        );
        assert!(
            payload
                .nodes
                .iter()
                .any(|n| n.module == "SNMPv2-SMI" && n.name == "internet"),
            "expected SNMPv2-SMI::internet in exported nodes"
        );
    }

    #[test]
    fn export_uppercases_byte_defval_hex() {
        let mib = load_corpus(&["SYNTHETIC-MIB"]);
        let payload = export_v1(&mib, ResolverStrictness::Permissive);
        let object = payload
            .objects
            .iter()
            .find(|obj| obj.name == "syntheticDefvalHex")
            .expect("syntheticDefvalHex not exported");
        let defval = object
            .default_value
            .as_ref()
            .expect("syntheticDefvalHex missing default value");

        assert_eq!(defval.kind, "bytes");
        assert_eq!(
            defval.value,
            serde_json::Value::String("DEADBEEF".to_string())
        );
    }
}
