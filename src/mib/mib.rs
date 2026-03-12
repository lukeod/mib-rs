use std::collections::HashMap;
use std::fmt;

use crate::mib::{Oid, ParseOidError};
use crate::types::{BaseType, Diagnostic, Kind, Severity};

use super::capability::CapabilityData;
use super::compliance::ComplianceData;
use super::group::GroupData;
use super::handle::{
    Capability, Compliance, Group, HandleIter, Module, Node, Notification, Object, Type,
};
use super::module::ModuleData;
use super::node::{NodeData, OidTree};
use super::notification::NotificationData;
use super::object::ObjectData;
use super::raw::RawMib;
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

    pub fn raw(&self) -> RawMib<'_> {
        RawMib::new(self)
    }

    pub fn node_data(&self, id: NodeId) -> &NodeData {
        self.tree.get(id)
    }

    #[must_use]
    pub fn root(&self) -> NodeId {
        self.tree.root()
    }

    #[must_use]
    pub fn root_node(&self) -> Node<'_> {
        Node::new(self, self.root())
    }

    // --- Entity accessors ---

    pub fn object_data(&self, id: ObjectId) -> &ObjectData {
        &self.objects[id.0 as usize]
    }

    #[must_use]
    pub fn type_data(&self, id: TypeId) -> &TypeData {
        &self.types[id.0 as usize]
    }

    pub fn notification_data(&self, id: NotificationId) -> &NotificationData {
        &self.notifications[id.0 as usize]
    }

    pub fn group_data(&self, id: GroupId) -> &GroupData {
        &self.groups[id.0 as usize]
    }

    pub fn compliance_data(&self, id: ComplianceId) -> &ComplianceData {
        &self.compliances[id.0 as usize]
    }

    pub fn capability_data(&self, id: CapabilityId) -> &CapabilityData {
        &self.capabilities[id.0 as usize]
    }

    pub fn module_data(&self, id: ModuleId) -> &ModuleData {
        &self.modules[id.0 as usize]
    }

    // --- Mutable entity access (for resolver) ---

    pub(crate) fn object_mut(&mut self, id: ObjectId) -> &mut ObjectData {
        &mut self.objects[id.0 as usize]
    }

    pub(crate) fn type_mut(&mut self, id: TypeId) -> &mut TypeData {
        &mut self.types[id.0 as usize]
    }

    pub(crate) fn module_mut(&mut self, id: ModuleId) -> &mut ModuleData {
        &mut self.modules[id.0 as usize]
    }

    // --- Name lookups ---

    /// Search nodes associated with `name` for the first one where `get`
    /// returns Some.
    fn find_in_nodes<T>(&self, name: &str, get: impl Fn(&NodeData) -> Option<T>) -> Option<T> {
        for &id in self.name_to_nodes.get(name)? {
            if let Some(val) = get(self.tree.get(id)) {
                return Some(val);
            }
        }
        None
    }

    /// Look up a node by name. Prefers nodes with objects, then notifications.
    #[must_use]
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
    #[must_use]
    pub fn object_by_name(&self, name: &str) -> Option<ObjectId> {
        self.find_in_nodes(name, |n| n.object)
    }

    #[must_use]
    pub fn object(&self, name: &str) -> Option<Object<'_>> {
        self.object_by_name(name).map(|id| Object::new(self, id))
    }

    /// Look up a type by name.
    #[must_use]
    pub fn type_by_name(&self, name: &str) -> Option<TypeId> {
        self.type_by_name.get(name).copied()
    }

    #[must_use]
    pub fn r#type(&self, name: &str) -> Option<Type<'_>> {
        self.type_by_name(name).map(|id| Type::new(self, id))
    }

    /// Look up a notification by name.
    #[must_use]
    pub fn notification_by_name(&self, name: &str) -> Option<NotificationId> {
        self.find_in_nodes(name, |n| n.notification)
    }

    #[must_use]
    pub fn notification(&self, name: &str) -> Option<Notification<'_>> {
        self.notification_by_name(name)
            .map(|id| Notification::new(self, id))
    }

    /// Look up a group by name.
    #[must_use]
    pub fn group_by_name(&self, name: &str) -> Option<GroupId> {
        self.find_in_nodes(name, |n| n.group)
    }

    #[must_use]
    pub fn group(&self, name: &str) -> Option<Group<'_>> {
        self.group_by_name(name).map(|id| Group::new(self, id))
    }

    /// Look up a compliance by name.
    #[must_use]
    pub fn compliance_by_name(&self, name: &str) -> Option<ComplianceId> {
        self.find_in_nodes(name, |n| n.compliance)
    }

    #[must_use]
    pub fn compliance(&self, name: &str) -> Option<Compliance<'_>> {
        self.compliance_by_name(name)
            .map(|id| Compliance::new(self, id))
    }

    /// Look up a capability by name.
    #[must_use]
    pub fn capability_by_name(&self, name: &str) -> Option<CapabilityId> {
        self.find_in_nodes(name, |n| n.capability)
    }

    #[must_use]
    pub fn capability(&self, name: &str) -> Option<Capability<'_>> {
        self.capability_by_name(name)
            .map(|id| Capability::new(self, id))
    }

    /// Look up a module by name.
    #[must_use]
    pub fn module_by_name(&self, name: &str) -> Option<ModuleId> {
        self.module_by_name.get(name).copied()
    }

    #[must_use]
    pub fn module(&self, name: &str) -> Option<Module<'_>> {
        self.module_by_name(name).map(|id| Module::new(self, id))
    }

    /// Look up a symbol by name. Priority: objects, notifications, groups,
    /// compliances, capabilities, plain nodes, then types.
    #[must_use]
    pub fn symbol_by_name(&self, name: &str) -> Option<Symbol> {
        if let Some(nodes) = self.name_to_nodes.get(name) {
            let mut notification = None;
            let mut group = None;
            let mut compliance = None;
            let mut capability = None;
            let mut node = None;

            for &id in nodes {
                let entry = self.tree.get(id);
                node.get_or_insert(id);
                if let Some(object) = entry.object {
                    return Some(Symbol::Object(object));
                }
                notification = notification.or(entry.notification);
                group = group.or(entry.group);
                compliance = compliance.or(entry.compliance);
                capability = capability.or(entry.capability);
            }

            if let Some(id) = notification {
                return Some(Symbol::Notification(id));
            }
            if let Some(id) = group {
                return Some(Symbol::Group(id));
            }
            if let Some(id) = compliance {
                return Some(Symbol::Compliance(id));
            }
            if let Some(id) = capability {
                return Some(Symbol::Capability(id));
            }
            if let Some(id) = node {
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
    #[must_use]
    pub fn node_by_oid(&self, oid: &Oid) -> Option<NodeId> {
        let (id, exact) = self.tree.walk_oid(self.tree.root(), oid);
        if exact { Some(id) } else { None }
    }

    #[must_use]
    pub fn node(&self, name: &str) -> Option<Node<'_>> {
        self.node_by_name(name).map(|id| Node::new(self, id))
    }

    #[must_use]
    pub fn node_by_oid_handle(&self, oid: &Oid) -> Option<Node<'_>> {
        self.node_by_oid(oid).map(|id| Node::new(self, id))
    }

    /// Find the deepest node matching a prefix of the OID, starting from root.
    #[must_use]
    pub fn longest_prefix_by_oid(&self, oid: &Oid) -> NodeId {
        self.tree.longest_prefix(oid)
    }

    #[must_use]
    pub fn longest_prefix(&self, oid: &Oid) -> Node<'_> {
        Node::new(self, self.longest_prefix_by_oid(oid))
    }

    /// Depth-first iterator over a subtree rooted at `id`.
    pub fn subtree(&self, id: NodeId) -> super::node::SubtreeIter<'_> {
        self.tree.subtree(id)
    }

    /// Find the deepest descendant of `start` matching a prefix of `oid`.
    #[must_use]
    pub fn longest_prefix_from(&self, start: NodeId, oid: &Oid) -> NodeId {
        self.tree.longest_prefix_from(start, oid)
    }

    /// Returns the effective module for a node, using entity priority:
    /// object > notification > group > compliance > capability > base module.
    #[must_use]
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
    pub fn resolve_node(&self, query: &str) -> Option<Node<'_>> {
        self.resolve(query).map(|id| Node::new(self, id))
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
    pub fn resolve_oid(&self, query: &str) -> Result<Oid, ResolveOidError> {
        if query.is_empty() {
            return Err(ResolveOidError::EmptyQuery);
        }

        let q = query.strip_prefix('.').unwrap_or(query);
        if q.starts_with(|c: char| c.is_ascii_digit()) {
            return q.parse::<Oid>().map_err(ResolveOidError::InvalidOid);
        }

        // Qualified name: MODULE::name[.suffix]
        if let Some((mod_name, rest)) = query.split_once("::") {
            let (name, suffix) = split_name_suffix(rest);
            let mod_id = self
                .module_by_name
                .get(mod_name)
                .ok_or_else(|| ResolveOidError::ModuleNotFound(mod_name.to_string()))?;
            let node_id = self.modules[mod_id.0 as usize]
                .node_by_name(name)
                .ok_or_else(|| ResolveOidError::QualifiedNodeNotFound {
                    module: mod_name.to_string(),
                    name: name.to_string(),
                })?;
            let base = self.tree.oid_of(node_id).clone();
            return append_suffix(base, suffix);
        }

        // Plain name[.suffix]
        let (name, suffix) = split_name_suffix(query);
        let node_id = self
            .node_by_name(name)
            .ok_or_else(|| ResolveOidError::NodeNotFound(name.to_string()))?;
        let base = self.tree.oid_of(node_id).clone();
        append_suffix(base, suffix)
    }

    /// Returns all symbols defined across all modules.
    /// Iterates modules in order, yielding each module's definitions.
    pub fn all_symbols(&self) -> Vec<Symbol> {
        let mut result = Vec::new();
        for module in &self.modules {
            result.extend(module.definitions());
        }
        result
    }

    /// Returns all symbols available in a module's scope: own definitions
    /// first, then imported symbols resolved from their source modules.
    /// Names that are also own definitions are yielded only once.
    pub fn available_symbols(&self, mod_id: ModuleId) -> Vec<Symbol> {
        let module = self.module_data(mod_id);
        let mut result = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Own definitions first.
        for sym in module.definitions() {
            seen.insert(sym.name(self).to_string());
            result.push(sym);
        }

        // Imported symbols in IMPORTS declaration order.
        for imp in &module.imports {
            for is in &imp.symbols {
                if seen.contains(&is.name) {
                    continue;
                }
                seen.insert(is.name.clone());
                let Some(&source_mod_id) = module.resolved_imports.get(&is.name) else {
                    continue;
                };
                let source = self.module_data(source_mod_id);
                if let Some(sym) = source.symbol(&is.name) {
                    result.push(sym);
                }
            }
        }

        result
    }

    // --- Collection accessors ---

    pub fn modules(&self) -> HandleIter<'_, Module<'_>, impl Iterator<Item = ModuleId>> {
        HandleIter::new(
            self,
            (0..self.modules.len()).map(|i| ModuleId::new(i as u32)),
        )
    }

    pub fn objects(&self) -> HandleIter<'_, Object<'_>, impl Iterator<Item = ObjectId>> {
        HandleIter::new(
            self,
            (0..self.objects.len()).map(|i| ObjectId::new(i as u32)),
        )
    }

    pub fn types(&self) -> HandleIter<'_, Type<'_>, impl Iterator<Item = TypeId>> {
        HandleIter::new(self, (0..self.types.len()).map(|i| TypeId::new(i as u32)))
    }

    pub fn nodes(&self) -> HandleIter<'_, Node<'_>, impl Iterator<Item = NodeId>> {
        HandleIter::new(self, self.tree.all_nodes())
    }

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

    pub fn table_objects(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.tables().into_iter().map(|id| Object::new(self, id))
    }

    pub fn scalars(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Scalar)
    }

    pub fn scalar_objects(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.scalars().into_iter().map(|id| Object::new(self, id))
    }

    pub fn columns(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Column)
    }

    pub fn column_objects(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.columns().into_iter().map(|id| Object::new(self, id))
    }

    pub fn rows(&self) -> Vec<ObjectId> {
        self.objects_by_kind(Kind::Row)
    }

    pub fn row_objects(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.rows().into_iter().map(|id| Object::new(self, id))
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

    // --- Object table navigation ---

    /// Returns the table object containing a row or column, or None.
    pub fn object_table(&self, id: ObjectId) -> Option<ObjectId> {
        let node_id = self.object_data(id).node()?;
        let node = self.tree.get(node_id);
        match node.kind {
            Kind::Row => {
                let parent = self.tree.get(node.parent?);
                parent.object
            }
            Kind::Column => {
                let parent = self.tree.get(node.parent?);
                let grandparent = self.tree.get(parent.parent?);
                grandparent.object
            }
            _ => None,
        }
    }

    /// Returns the parent row object for a column, or None.
    pub fn object_row(&self, id: ObjectId) -> Option<ObjectId> {
        let node_id = self.object_data(id).node()?;
        let node = self.tree.get(node_id);
        if node.kind != Kind::Column {
            return None;
        }
        let parent = self.tree.get(node.parent?);
        parent.object
    }

    /// Returns the row entry for a table, or None.
    pub fn object_entry(&self, id: ObjectId) -> Option<ObjectId> {
        let node_id = self.object_data(id).node()?;
        let node = self.tree.get(node_id);
        if node.kind != Kind::Table {
            return None;
        }
        for &child_id in node.children.values() {
            let child = self.tree.get(child_id);
            if child.kind == Kind::Row {
                return child.object;
            }
        }
        None
    }

    /// Returns column objects for a table or row in arc order, or empty.
    pub fn object_columns(&self, id: ObjectId) -> Vec<ObjectId> {
        let Some(node_id) = self.object_data(id).node() else {
            return Vec::new();
        };
        let node = self.tree.get(node_id);
        let row_node = match node.kind {
            Kind::Table => {
                let mut found = None;
                for &child_id in node.children.values() {
                    if self.tree.get(child_id).kind == Kind::Row {
                        found = Some(child_id);
                        break;
                    }
                }
                match found {
                    Some(id) => self.tree.get(id),
                    None => return Vec::new(),
                }
            }
            Kind::Row => node,
            _ => return Vec::new(),
        };
        let mut cols = Vec::new();
        for &child_id in row_node.children.values() {
            let child = self.tree.get(child_id);
            if let Some(obj_id) = child.object.filter(|_| child.kind == Kind::Column) {
                cols.push(obj_id);
            }
        }
        cols
    }

    /// Returns INDEX entries for a row, following AUGMENTS if the row has none.
    pub fn effective_indexes(&self, id: ObjectId) -> Vec<IndexEntry> {
        let mut visited = Vec::new();
        self.effective_indexes_inner(id, &mut visited)
    }

    pub(crate) fn effective_indexes_source(&self, id: ObjectId) -> Option<ObjectId> {
        let mut visited = Vec::new();
        self.effective_indexes_source_inner(id, &mut visited)
    }

    fn effective_indexes_inner(
        &self,
        id: ObjectId,
        visited: &mut Vec<ObjectId>,
    ) -> Vec<IndexEntry> {
        let obj = self.object_data(id);
        let Some(node_id) = obj.node() else {
            return Vec::new();
        };
        if self.tree.get(node_id).kind != Kind::Row {
            return Vec::new();
        }
        if !obj.index.is_empty() {
            return obj.index.clone();
        }
        if let Some(aug_id) = obj.augments {
            if visited.contains(&id) {
                return Vec::new();
            }
            visited.push(id);
            return self.effective_indexes_inner(aug_id, visited);
        }
        Vec::new()
    }

    fn effective_indexes_source_inner(
        &self,
        id: ObjectId,
        visited: &mut Vec<ObjectId>,
    ) -> Option<ObjectId> {
        let obj = self.object_data(id);
        let node_id = obj.node()?;
        if self.tree.get(node_id).kind != Kind::Row {
            return None;
        }
        if !obj.index.is_empty() {
            return Some(id);
        }
        let aug_id = obj.augments?;
        if visited.contains(&id) {
            return None;
        }
        visited.push(id);
        self.effective_indexes_source_inner(aug_id, visited)
    }

    // --- Object kind predicates ---

    /// Returns true if the object is a table.
    pub fn is_table(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Table
    }

    /// Returns true if the object is a table row (entry).
    pub fn is_row(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Row
    }

    /// Returns true if the object is a table column.
    pub fn is_column(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Column
    }

    /// Returns true if the object is a scalar.
    pub fn is_scalar(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Scalar
    }

    /// Returns true if a column appears in its parent row's effective indexes.
    pub fn is_index(&self, id: ObjectId) -> bool {
        if self.object_kind(id) != Kind::Column {
            return false;
        }
        let Some(row_id) = self.object_row(id) else {
            return false;
        };
        self.effective_indexes(row_id)
            .iter()
            .any(|idx| idx.object == Some(id))
    }

    fn object_kind(&self, id: ObjectId) -> Kind {
        match self.object_data(id).node() {
            Some(node_id) => self.tree.get(node_id).kind,
            None => Kind::Unknown,
        }
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

fn append_suffix(base: Oid, suffix: &str) -> Result<Oid, ResolveOidError> {
    if suffix.is_empty() {
        return Ok(base);
    }
    let extra: Oid = suffix
        .parse()
        .map_err(|source| ResolveOidError::InvalidSuffix {
            suffix: suffix.to_string(),
            source,
        })?;
    Ok(base.child_oid(&extra))
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolveOidError {
    #[error("empty query")]
    EmptyQuery,
    #[error("invalid OID: {0}")]
    InvalidOid(#[source] ParseOidError),
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    #[error("node not found: {0}")]
    NodeNotFound(String),
    #[error("node not found: {module}::{name}")]
    QualifiedNodeNotFound { module: String, name: String },
    #[error("invalid instance suffix {suffix:?}: {source}")]
    InvalidSuffix {
        suffix: String,
        #[source]
        source: ParseOidError,
    },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mib::module::ModuleData;
    use crate::mib::object::ObjectData;
    use crate::mib::typedef::TypeData;

    fn make_mib_with_two_modules() -> Mib {
        let mut mib = Mib::new();

        // Module A with an object and a type.
        let mut mod_a = ModuleData::new("MOD-A".to_string());
        let obj_data = ObjectData::new("objA".to_string());
        let obj_id = mib.add_object(obj_data);
        mod_a.add_object("objA", obj_id);

        let type_data = TypeData::new("TypeA".to_string());
        let type_id = mib.add_type(type_data);
        mod_a.add_type("TypeA", type_id);
        let _mod_a_id = mib.add_module(mod_a);

        // Module B with an object.
        let mut mod_b = ModuleData::new("MOD-B".to_string());
        let obj_data2 = ObjectData::new("objB".to_string());
        let obj_id2 = mib.add_object(obj_data2);
        mod_b.add_object("objB", obj_id2);
        let _mod_b_id = mib.add_module(mod_b);

        mib
    }

    #[test]
    fn all_symbols_across_modules() {
        let mib = make_mib_with_two_modules();
        let syms = mib.all_symbols();
        let names: Vec<&str> = syms.iter().map(|s| s.name(&mib)).collect();

        assert!(names.contains(&"objA"));
        assert!(names.contains(&"TypeA"));
        assert!(names.contains(&"objB"));
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn available_symbols_own_only() {
        let mib = make_mib_with_two_modules();
        let mod_a_id = *mib.module_by_name.get("MOD-A").unwrap();

        let syms = mib.available_symbols(mod_a_id);
        let names: Vec<&str> = syms.iter().map(|s| s.name(&mib)).collect();

        assert!(names.contains(&"objA"));
        assert!(names.contains(&"TypeA"));
        assert!(!names.contains(&"objB"));
    }

    #[test]
    fn available_symbols_with_imports() {
        let mut mib = Mib::new();

        // Source module with an object.
        let mut source_mod = ModuleData::new("SOURCE-MIB".to_string());
        let obj_data = ObjectData::new("srcObj".to_string());
        let obj_id = mib.add_object(obj_data);
        source_mod.add_object("srcObj", obj_id);
        let source_mod_id = mib.add_module(source_mod);

        // Consumer module that imports srcObj.
        let mut consumer = ModuleData::new("CONSUMER-MIB".to_string());
        let own_type = TypeData::new("OwnType".to_string());
        let own_type_id = mib.add_type(own_type);
        consumer.add_type("OwnType", own_type_id);
        consumer.imports.push(crate::mib::types::Import {
            module: "SOURCE-MIB".to_string(),
            symbols: vec![crate::mib::types::ImportSymbol {
                name: "srcObj".to_string(),
                span: crate::types::Span::SYNTHETIC,
            }],
        });
        consumer
            .resolved_imports
            .insert("srcObj".to_string(), source_mod_id);
        let consumer_id = mib.add_module(consumer);

        let syms = mib.available_symbols(consumer_id);
        let names: Vec<&str> = syms.iter().map(|s| s.name(&mib)).collect();

        assert_eq!(names, vec!["OwnType", "srcObj"]);
    }

    #[test]
    fn available_symbols_dedup_own_over_import() {
        let mut mib = Mib::new();

        // Source module defines "shared".
        let mut source_mod = ModuleData::new("SOURCE-MIB".to_string());
        let src_type = TypeData::new("shared".to_string());
        let src_type_id = mib.add_type(src_type);
        source_mod.add_type("shared", src_type_id);
        let source_mod_id = mib.add_module(source_mod);

        // Consumer also defines "shared" and imports it.
        let mut consumer = ModuleData::new("CONSUMER-MIB".to_string());
        let own_type = TypeData::new("shared".to_string());
        let own_type_id = mib.add_type(own_type);
        consumer.add_type("shared", own_type_id);
        consumer.imports.push(crate::mib::types::Import {
            module: "SOURCE-MIB".to_string(),
            symbols: vec![crate::mib::types::ImportSymbol {
                name: "shared".to_string(),
                span: crate::types::Span::SYNTHETIC,
            }],
        });
        consumer
            .resolved_imports
            .insert("shared".to_string(), source_mod_id);
        let consumer_id = mib.add_module(consumer);

        let syms = mib.available_symbols(consumer_id);
        let names: Vec<&str> = syms.iter().map(|s| s.name(&mib)).collect();

        // "shared" appears only once (own definition wins).
        assert_eq!(names, vec!["shared"]);
    }
}
