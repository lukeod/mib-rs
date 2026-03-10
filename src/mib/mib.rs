use std::collections::HashMap;
use std::fmt;

use crate::mib::Oid;
use crate::types::{BaseType, Diagnostic, Kind, Severity};

use super::capability::CapabilityData;
use super::compliance::ComplianceData;
use super::group::GroupData;
use super::module::ModuleData;
use super::node::OidTree;
use super::notification::NotificationData;
use super::object::ObjectData;
use super::symbol::Symbol;
use super::typedef::TypeData;
use super::types::*;

/// Top-level container for all resolved MIB data.
///
/// Holds the OID tree, all entity arenas, lookup indices, and diagnostics.
/// Built once during resolution and safe for concurrent reads.
pub struct Mib {
    pub(crate) tree: OidTree,

    // Entity arenas
    pub(crate) objects: Vec<ObjectData>,
    pub(crate) types: Vec<TypeData>,
    pub(crate) notifications: Vec<NotificationData>,
    pub(crate) groups: Vec<GroupData>,
    pub(crate) compliances: Vec<ComplianceData>,
    pub(crate) capabilities: Vec<CapabilityData>,
    pub(crate) modules: Vec<ModuleData>,

    // Lookup indices
    pub(crate) module_by_name: HashMap<String, ModuleId>,
    pub(crate) name_to_nodes: HashMap<String, Vec<NodeId>>,
    pub(crate) type_by_name: HashMap<String, TypeId>,

    pub(crate) node_count: usize,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) unresolved: Vec<UnresolvedRef>,
}

impl Mib {
    pub fn new() -> Self {
        Self {
            tree: OidTree::new(),
            objects: Vec::new(),
            types: Vec::new(),
            notifications: Vec::new(),
            groups: Vec::new(),
            compliances: Vec::new(),
            capabilities: Vec::new(),
            modules: Vec::new(),
            module_by_name: HashMap::new(),
            name_to_nodes: HashMap::new(),
            type_by_name: HashMap::new(),
            node_count: 0,
            diagnostics: Vec::new(),
            unresolved: Vec::new(),
        }
    }

    // --- Tree access ---

    pub fn tree(&self) -> &OidTree {
        &self.tree
    }

    pub fn root(&self) -> NodeId {
        self.tree.root()
    }

    // --- Entity accessors ---

    pub fn object(&self, id: ObjectId) -> &ObjectData {
        &self.objects[id.0 as usize]
    }

    pub fn type_(&self, id: TypeId) -> &TypeData {
        &self.types[id.0 as usize]
    }

    pub fn notification(&self, id: NotificationId) -> &NotificationData {
        &self.notifications[id.0 as usize]
    }

    pub fn group(&self, id: GroupId) -> &GroupData {
        &self.groups[id.0 as usize]
    }

    pub fn compliance(&self, id: ComplianceId) -> &ComplianceData {
        &self.compliances[id.0 as usize]
    }

    pub fn capability(&self, id: CapabilityId) -> &CapabilityData {
        &self.capabilities[id.0 as usize]
    }

    pub fn module(&self, id: ModuleId) -> &ModuleData {
        &self.modules[id.0 as usize]
    }

    // --- Mutable entity access (for resolver) ---

    pub(crate) fn object_mut(&mut self, id: ObjectId) -> &mut ObjectData {
        &mut self.objects[id.0 as usize]
    }

    pub(crate) fn type_mut(&mut self, id: TypeId) -> &mut TypeData {
        &mut self.types[id.0 as usize]
    }

    pub(crate) fn notification_mut(&mut self, id: NotificationId) -> &mut NotificationData {
        &mut self.notifications[id.0 as usize]
    }

    pub(crate) fn group_mut(&mut self, id: GroupId) -> &mut GroupData {
        &mut self.groups[id.0 as usize]
    }

    pub(crate) fn compliance_mut(&mut self, id: ComplianceId) -> &mut ComplianceData {
        &mut self.compliances[id.0 as usize]
    }

    pub(crate) fn capability_mut(&mut self, id: CapabilityId) -> &mut CapabilityData {
        &mut self.capabilities[id.0 as usize]
    }

    pub(crate) fn module_mut(&mut self, id: ModuleId) -> &mut ModuleData {
        &mut self.modules[id.0 as usize]
    }

    // --- Name lookups ---

    /// Look up a node by name. Prefers nodes with objects, then notifications.
    pub fn node_by_name(&self, name: &str) -> Option<NodeId> {
        let nodes = self.name_to_nodes.get(name)?;
        for &id in nodes {
            if self.tree.get(id).object.is_some() {
                return Some(id);
            }
        }
        for &id in nodes {
            if self.tree.get(id).notification.is_some() {
                return Some(id);
            }
        }
        nodes.first().copied()
    }

    /// Look up an object by name.
    pub fn object_by_name(&self, name: &str) -> Option<ObjectId> {
        for &id in self.name_to_nodes.get(name)? {
            if let Some(obj_id) = self.tree.get(id).object {
                return Some(obj_id);
            }
        }
        None
    }

    /// Look up a type by name.
    pub fn type_by_name(&self, name: &str) -> Option<TypeId> {
        self.type_by_name.get(name).copied()
    }

    /// Look up a notification by name.
    pub fn notification_by_name(&self, name: &str) -> Option<NotificationId> {
        for &id in self.name_to_nodes.get(name)? {
            if let Some(notif_id) = self.tree.get(id).notification {
                return Some(notif_id);
            }
        }
        None
    }

    /// Look up a group by name.
    pub fn group_by_name(&self, name: &str) -> Option<GroupId> {
        for &id in self.name_to_nodes.get(name)? {
            if let Some(group_id) = self.tree.get(id).group {
                return Some(group_id);
            }
        }
        None
    }

    /// Look up a compliance by name.
    pub fn compliance_by_name(&self, name: &str) -> Option<ComplianceId> {
        for &id in self.name_to_nodes.get(name)? {
            if let Some(comp_id) = self.tree.get(id).compliance {
                return Some(comp_id);
            }
        }
        None
    }

    /// Look up a capability by name.
    pub fn capability_by_name(&self, name: &str) -> Option<CapabilityId> {
        for &id in self.name_to_nodes.get(name)? {
            if let Some(cap_id) = self.tree.get(id).capability {
                return Some(cap_id);
            }
        }
        None
    }

    /// Look up a module by name.
    pub fn module_by_name(&self, name: &str) -> Option<ModuleId> {
        self.module_by_name.get(name).copied()
    }

    /// Look up a symbol by name. Priority: objects, notifications, groups,
    /// compliances, capabilities, plain nodes, then types.
    pub fn symbol_by_name(&self, name: &str) -> Option<Symbol> {
        if let Some(nodes) = self.name_to_nodes.get(name) {
            for &id in nodes {
                if let Some(obj_id) = self.tree.get(id).object {
                    return Some(Symbol::Object(obj_id));
                }
            }
            for &id in nodes {
                if let Some(notif_id) = self.tree.get(id).notification {
                    return Some(Symbol::Notification(notif_id));
                }
            }
            for &id in nodes {
                if let Some(group_id) = self.tree.get(id).group {
                    return Some(Symbol::Group(group_id));
                }
            }
            for &id in nodes {
                if let Some(comp_id) = self.tree.get(id).compliance {
                    return Some(Symbol::Compliance(comp_id));
                }
            }
            for &id in nodes {
                if let Some(cap_id) = self.tree.get(id).capability {
                    return Some(Symbol::Capability(cap_id));
                }
            }
            if let Some(&id) = nodes.first() {
                return Some(Symbol::Node(id));
            }
        }
        if let Some(&id) = self.type_by_name.get(name) {
            return Some(Symbol::Type(id));
        }
        None
    }

    // --- OID lookups ---

    /// Look up a node at an exact numeric OID.
    pub fn node_by_oid(&self, oid: &Oid) -> Option<NodeId> {
        let (id, exact) = self.tree.walk_oid(self.tree.root(), oid);
        if exact { Some(id) } else { None }
    }

    /// Find the deepest node matching a prefix of the OID.
    pub fn longest_prefix_by_oid(&self, oid: &Oid) -> NodeId {
        self.tree.longest_prefix(oid)
    }

    /// Returns the effective module for a node, using entity priority:
    /// object > notification > group > compliance > capability > base module.
    pub fn effective_module(&self, id: NodeId) -> Option<ModuleId> {
        let node = self.tree.get(id);
        if let Some(obj_id) = node.object {
            return self.objects[obj_id.0 as usize].entity.module;
        }
        if let Some(notif_id) = node.notification {
            return self.notifications[notif_id.0 as usize].entity.module;
        }
        if let Some(group_id) = node.group {
            return self.groups[group_id.0 as usize].entity.module;
        }
        if let Some(comp_id) = node.compliance {
            return self.compliances[comp_id.0 as usize].entity.module;
        }
        if let Some(cap_id) = node.capability {
            return self.capabilities[cap_id.0 as usize].entity.module;
        }
        node.module
    }

    /// Format a numeric OID as "MODULE::name.suffix".
    pub fn format_oid(&self, oid: &Oid) -> String {
        if oid.is_empty() {
            return String::new();
        }
        let matched_id = self.tree.longest_prefix(oid);
        let matched = self.tree.get(matched_id);
        if matched.name.is_empty() {
            return oid.to_string();
        }

        let node_oid = self.tree.oid_of(matched_id);
        let suffix = &oid[node_oid.len()..];

        let mut result = String::new();
        if let Some(mod_id) = self.effective_module(matched_id) {
            result.push_str(&self.modules[mod_id.0 as usize].name);
            result.push_str("::");
        }
        result.push_str(&matched.name);
        for arc in suffix {
            result.push('.');
            result.push_str(&arc.to_string());
        }
        result
    }

    /// Look up a node by name, qualified name (MODULE::name), or numeric OID string.
    pub fn resolve(&self, query: &str) -> Option<NodeId> {
        // Qualified name: MODULE::name
        if let Some((mod_name, item_name)) = query.split_once("::") {
            let mod_id = self.module_by_name.get(mod_name)?;
            return self.modules[mod_id.0 as usize].node_by_name(item_name);
        }

        // Numeric OID
        let q = query.strip_prefix('.').unwrap_or(query);
        if q.starts_with(|c: char| c.is_ascii_digit()) {
            let oid: Oid = q.parse().ok()?;
            return self.node_by_oid(&oid);
        }

        // Plain name
        self.node_by_name(query)
    }

    /// Convert a symbolic or numeric OID string to a numeric OID.
    pub fn resolve_oid(&self, query: &str) -> Result<Oid, String> {
        if query.is_empty() {
            return Err("empty query".into());
        }

        let q = query.strip_prefix('.').unwrap_or(query);
        if q.starts_with(|c: char| c.is_ascii_digit()) {
            return q.parse::<Oid>().map_err(|e| format!("invalid OID: {e}"));
        }

        // Qualified name: MODULE::name[.suffix]
        if let Some((mod_name, rest)) = query.split_once("::") {
            let (name, suffix) = split_name_suffix(rest);
            let mod_id = self
                .module_by_name
                .get(mod_name)
                .ok_or_else(|| format!("module not found: {mod_name}"))?;
            let node_id = self.modules[mod_id.0 as usize]
                .node_by_name(name)
                .ok_or_else(|| format!("node not found: {mod_name}::{name}"))?;
            let base = self.tree.oid_of(node_id).clone();
            return append_suffix(base, suffix);
        }

        // Plain name[.suffix]
        let (name, suffix) = split_name_suffix(query);
        let node_id = self
            .node_by_name(name)
            .ok_or_else(|| format!("node not found: {name}"))?;
        let base = self.tree.oid_of(node_id).clone();
        append_suffix(base, suffix)
    }

    // --- Collection accessors ---

    pub fn modules_slice(&self) -> &[ModuleData] {
        &self.modules
    }

    pub fn objects_slice(&self) -> &[ObjectData] {
        &self.objects
    }

    pub fn types_slice(&self) -> &[TypeData] {
        &self.types
    }

    pub fn notifications_slice(&self) -> &[NotificationData] {
        &self.notifications
    }

    pub fn groups_slice(&self) -> &[GroupData] {
        &self.groups
    }

    pub fn compliances_slice(&self) -> &[ComplianceData] {
        &self.compliances
    }

    pub fn capabilities_slice(&self) -> &[CapabilityData] {
        &self.capabilities
    }

    /// Returns all modules that define a symbol with the given name (non-base only).
    pub fn modules_defining(&self, name: &str) -> Vec<ModuleId> {
        self.modules
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.is_base && m.defines_symbol(name))
            .map(|(i, _)| ModuleId::new(i as u32))
            .collect()
    }

    /// Returns all modules that import a symbol with the given name (non-base only).
    pub fn modules_importing(&self, name: &str) -> Vec<ModuleId> {
        self.modules
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.is_base && m.imports_symbol(name))
            .map(|(i, _)| ModuleId::new(i as u32))
            .collect()
    }

    /// Returns objects filtered by node kind.
    pub fn objects_by_kind(&self, kind: Kind) -> Vec<ObjectId> {
        self.objects
            .iter()
            .enumerate()
            .filter(|(_, obj)| {
                obj.entity
                    .node
                    .is_some_and(|id| self.tree.get(id).kind == kind)
            })
            .map(|(i, _)| ObjectId::new(i as u32))
            .collect()
    }

    pub fn tables(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Table)
    }

    pub fn scalars(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Scalar)
    }

    pub fn columns(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Column)
    }

    pub fn rows(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Row)
    }

    /// Returns all objects whose resolved type has the given name.
    pub fn objects_by_type_name(&self, type_name: &str) -> Vec<ObjectId> {
        self.objects
            .iter()
            .enumerate()
            .filter(|(_, obj)| {
                obj.typ
                    .is_some_and(|id| self.types[id.0 as usize].name == type_name)
            })
            .map(|(i, _)| ObjectId::new(i as u32))
            .collect()
    }

    /// Returns all objects whose effective base type matches.
    pub fn objects_by_base_type(&self, base: BaseType) -> Vec<ObjectId> {
        self.objects
            .iter()
            .enumerate()
            .filter(|(_, obj)| {
                obj.typ
                    .is_some_and(|id| self.types[id.0 as usize].effective_base(&self.types) == base)
            })
            .map(|(i, _)| ObjectId::new(i as u32))
            .collect()
    }

    // --- Diagnostics ---

    pub fn node_count(&self) -> usize {
        self.node_count
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn unresolved(&self) -> &[UnresolvedRef] {
        &self.unresolved
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity.at_least(Severity::Error))
    }

    // --- Builder methods (used by resolver) ---

    pub(crate) fn set_node_count(&mut self, n: usize) {
        self.node_count = n;
    }

    pub(crate) fn add_module(&mut self, data: ModuleData) -> ModuleId {
        let id = ModuleId::new(self.modules.len() as u32);
        if !data.name.is_empty() {
            self.module_by_name.insert(data.name.clone(), id);
        }
        self.modules.push(data);
        id
    }

    pub(crate) fn add_object(&mut self, data: ObjectData) -> ObjectId {
        let id = ObjectId::new(self.objects.len() as u32);
        self.objects.push(data);
        id
    }

    pub(crate) fn add_type(&mut self, data: TypeData) -> TypeId {
        let id = TypeId::new(self.types.len() as u32);
        if !data.name.is_empty() && !self.type_by_name.contains_key(&data.name) {
            self.type_by_name.insert(data.name.clone(), id);
        }
        self.types.push(data);
        id
    }

    pub(crate) fn add_notification(&mut self, data: NotificationData) -> NotificationId {
        let id = NotificationId::new(self.notifications.len() as u32);
        self.notifications.push(data);
        id
    }

    pub(crate) fn add_group(&mut self, data: GroupData) -> GroupId {
        let id = GroupId::new(self.groups.len() as u32);
        self.groups.push(data);
        id
    }

    pub(crate) fn add_compliance(&mut self, data: ComplianceData) -> ComplianceId {
        let id = ComplianceId::new(self.compliances.len() as u32);
        self.compliances.push(data);
        id
    }

    pub(crate) fn add_capability(&mut self, data: CapabilityData) -> CapabilityId {
        let id = CapabilityId::new(self.capabilities.len() as u32);
        self.capabilities.push(data);
        id
    }

    pub(crate) fn register_node(&mut self, name: &str, id: NodeId) {
        if !name.is_empty() {
            self.name_to_nodes
                .entry(name.to_string())
                .or_default()
                .push(id);
        }
    }

    pub(crate) fn add_diagnostic(&mut self, d: Diagnostic) {
        self.diagnostics.push(d);
    }

    pub(crate) fn add_unresolved(&mut self, r: UnresolvedRef) {
        self.unresolved.push(r);
    }
}

impl Default for Mib {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Mib {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mib")
            .field("modules", &self.modules.len())
            .field("objects", &self.objects.len())
            .field("types", &self.types.len())
            .field("notifications", &self.notifications.len())
            .field("node_count", &self.node_count)
            .finish()
    }
}

fn split_name_suffix(s: &str) -> (&str, &str) {
    match s.find('.') {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

fn append_suffix(base: Oid, suffix: &str) -> Result<Oid, String> {
    if suffix.is_empty() {
        return Ok(base);
    }
    let extra: Oid = suffix
        .parse()
        .map_err(|e| format!("invalid instance suffix {suffix:?}: {e}"))?;
    Ok(base.child_oid(&extra))
}

// Extension method for building child OIDs with multiple arcs.
impl Oid {
    fn child_oid(&self, suffix: &Oid) -> Oid {
        let mut arcs = Vec::with_capacity(self.len() + suffix.len());
        arcs.extend_from_slice(self);
        arcs.extend_from_slice(suffix);
        Oid::from(arcs)
    }
}
