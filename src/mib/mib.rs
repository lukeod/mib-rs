//! Top-level MIB container and query methods.
//!
//! [`Mib`] is the central type in the resolved model. It owns all arena
//! storage, the OID tree, lookup indices, and diagnostics. After resolution
//! it is immutable and safe for concurrent reads behind `&Mib`.

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
/// Holds the OID tree, all entity arenas, lookup indices, and diagnostics
/// produced during resolution. Built once and then immutable, so it is safe
/// for concurrent reads behind `&Mib`.
///
/// Use the handle-oriented methods ([`Mib::node`], [`Mib::object`],
/// [`Mib::module`], etc.) for most queries. For lower-level arena access,
/// see [`Mib::raw`].
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
    pub(crate) objects_by_name: HashMap<String, Vec<ObjectId>>,
    pub(crate) type_by_name: HashMap<String, TypeId>,
    pub(crate) notifications_by_name: HashMap<String, Vec<NotificationId>>,
    pub(crate) groups_by_name: HashMap<String, Vec<GroupId>>,
    pub(crate) compliances_by_name: HashMap<String, Vec<ComplianceId>>,
    pub(crate) capabilities_by_name: HashMap<String, Vec<CapabilityId>>,

    pub(crate) node_count: usize,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) unresolved: Vec<UnresolvedRef>,
}

impl Mib {
    pub(crate) fn new() -> Self {
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
            objects_by_name: HashMap::new(),
            type_by_name: HashMap::new(),
            notifications_by_name: HashMap::new(),
            groups_by_name: HashMap::new(),
            compliances_by_name: HashMap::new(),
            capabilities_by_name: HashMap::new(),
            node_count: 0,
            diagnostics: Vec::new(),
            unresolved: Vec::new(),
        }
    }

    // --- Tree access ---

    pub(crate) fn tree(&self) -> &OidTree {
        &self.tree
    }

    /// Return a low-level view of this MIB.
    ///
    /// Exposes arena-backed ids and data structures. Most callers should
    /// prefer the high-level borrowed handles instead.
    pub fn raw(&self) -> RawMib<'_> {
        RawMib::new(self)
    }

    pub(crate) fn node_data(&self, id: NodeId) -> &NodeData {
        self.tree.get(id)
    }

    /// Return a handle to the synthetic root of the OID tree.
    ///
    /// The root has no name and no OID arcs. All top-level OID branches
    /// (`iso`, etc.) are children of this node.
    #[must_use]
    pub fn root_node(&self) -> Node<'_> {
        Node::new(self, self.tree.root())
    }

    // --- Entity accessors ---

    pub(crate) fn object_data(&self, id: ObjectId) -> &ObjectData {
        &self.objects[id.0 as usize]
    }

    #[must_use]
    pub(crate) fn type_data(&self, id: TypeId) -> &TypeData {
        &self.types[id.0 as usize]
    }

    pub(crate) fn notification_data(&self, id: NotificationId) -> &NotificationData {
        &self.notifications[id.0 as usize]
    }

    pub(crate) fn group_data(&self, id: GroupId) -> &GroupData {
        &self.groups[id.0 as usize]
    }

    pub(crate) fn compliance_data(&self, id: ComplianceId) -> &ComplianceData {
        &self.compliances[id.0 as usize]
    }

    pub(crate) fn capability_data(&self, id: CapabilityId) -> &CapabilityData {
        &self.capabilities[id.0 as usize]
    }

    pub(crate) fn module_data(&self, id: ModuleId) -> &ModuleData {
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

    fn find_entity_by_name<T: Copy + PartialEq>(
        &self,
        name: &str,
        entities: &HashMap<String, Vec<T>>,
        attached: impl Fn(&NodeData) -> Option<T>,
    ) -> Option<T> {
        let candidates = entities.get(name)?;
        self.name_to_nodes
            .get(name)
            .into_iter()
            .flatten()
            .find_map(|&node| attached(self.tree.get(node)).filter(|id| candidates.contains(id)))
            .or_else(|| candidates.first().copied())
    }

    /// Return all nodes registered under the given name, or an empty slice.
    ///
    /// Unlike [`Mib::node_by_name`], which returns a single preferred node,
    /// this returns every node across all loaded modules that shares the name.
    #[must_use]
    pub fn nodes_by_name(&self, name: &str) -> &[NodeId] {
        self.name_to_nodes
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Look up a node by name, returning the [`NodeId`].
    ///
    /// When multiple nodes share the same name (which can happen when
    /// different modules define overlapping OID assignments), uses a 6-tier
    /// priority matching [`Mib::symbol_by_name`]: object, notification,
    /// group, compliance, capability, then any remaining node.
    #[must_use]
    pub fn node_by_name(&self, name: &str) -> Option<NodeId> {
        let nodes = self.name_to_nodes.get(name)?;

        let mut notification = None;
        let mut group = None;
        let mut compliance = None;
        let mut capability = None;
        let mut fallback = None;

        for &id in nodes {
            let entry = self.tree.get(id);
            fallback.get_or_insert(id);
            if entry.object.is_some() {
                return Some(id);
            }
            if notification.is_none() && entry.notification.is_some() {
                notification = Some(id);
            }
            if group.is_none() && entry.group.is_some() {
                group = Some(id);
            }
            if compliance.is_none() && entry.compliance.is_some() {
                compliance = Some(id);
            }
            if capability.is_none() && entry.capability.is_some() {
                capability = Some(id);
            }
        }

        notification
            .or(group)
            .or(compliance)
            .or(capability)
            .or(fallback)
    }

    /// Look up an object by name, returning the [`ObjectId`].
    #[must_use]
    pub fn object_by_name(&self, name: &str) -> Option<ObjectId> {
        self.find_entity_by_name(name, &self.objects_by_name, |node| node.object)
    }

    /// Look up an object by name and return an [`Object`] handle.
    #[must_use]
    pub fn object(&self, name: &str) -> Option<Object<'_>> {
        self.object_by_name(name).map(|id| Object::new(self, id))
    }

    /// Look up a type by name, returning the [`TypeId`].
    #[must_use]
    pub fn type_by_name(&self, name: &str) -> Option<TypeId> {
        self.type_by_name.get(name).copied()
    }

    /// Look up a type by name and return a [`Type`] handle.
    #[must_use]
    pub fn r#type(&self, name: &str) -> Option<Type<'_>> {
        self.type_by_name(name).map(|id| Type::new(self, id))
    }

    /// Look up a notification by name, returning the [`NotificationId`].
    #[must_use]
    pub fn notification_by_name(&self, name: &str) -> Option<NotificationId> {
        self.find_entity_by_name(name, &self.notifications_by_name, |node| node.notification)
    }

    /// Look up a notification by name and return a [`Notification`] handle.
    #[must_use]
    pub fn notification(&self, name: &str) -> Option<Notification<'_>> {
        self.notification_by_name(name)
            .map(|id| Notification::new(self, id))
    }

    /// Look up a group by name, returning the [`GroupId`].
    #[must_use]
    pub fn group_by_name(&self, name: &str) -> Option<GroupId> {
        self.find_entity_by_name(name, &self.groups_by_name, |node| node.group)
    }

    /// Look up a group by name and return a [`Group`] handle.
    #[must_use]
    pub fn group(&self, name: &str) -> Option<Group<'_>> {
        self.group_by_name(name).map(|id| Group::new(self, id))
    }

    /// Look up a compliance statement by name, returning the [`ComplianceId`].
    #[must_use]
    pub fn compliance_by_name(&self, name: &str) -> Option<ComplianceId> {
        self.find_entity_by_name(name, &self.compliances_by_name, |node| node.compliance)
    }

    /// Look up a compliance statement by name and return a [`Compliance`] handle.
    #[must_use]
    pub fn compliance(&self, name: &str) -> Option<Compliance<'_>> {
        self.compliance_by_name(name)
            .map(|id| Compliance::new(self, id))
    }

    /// Look up a capability statement by name, returning the [`CapabilityId`].
    #[must_use]
    pub fn capability_by_name(&self, name: &str) -> Option<CapabilityId> {
        self.find_entity_by_name(name, &self.capabilities_by_name, |node| node.capability)
    }

    /// Look up a capability statement by name and return a [`Capability`] handle.
    #[must_use]
    pub fn capability(&self, name: &str) -> Option<Capability<'_>> {
        self.capability_by_name(name)
            .map(|id| Capability::new(self, id))
    }

    /// Look up a module by name, returning the [`ModuleId`].
    #[must_use]
    pub fn module_by_name(&self, name: &str) -> Option<ModuleId> {
        self.module_by_name.get(name).copied()
    }

    /// Look up a module by name and return a [`Module`] handle.
    #[must_use]
    pub fn module(&self, name: &str) -> Option<Module<'_>> {
        self.module_by_name(name).map(|id| Module::new(self, id))
    }

    /// Look up a symbol by name, returning a [`Symbol`] variant.
    ///
    /// Priority: objects, notifications, groups, compliances, capabilities,
    /// plain nodes, then types.
    #[must_use]
    pub fn symbol_by_name(&self, name: &str) -> Option<Symbol> {
        if let Some(id) = self.object_by_name(name) {
            return Some(Symbol::Object(id));
        }
        if let Some(id) = self.notification_by_name(name) {
            return Some(Symbol::Notification(id));
        }
        if let Some(id) = self.group_by_name(name) {
            return Some(Symbol::Group(id));
        }
        if let Some(id) = self.compliance_by_name(name) {
            return Some(Symbol::Compliance(id));
        }
        if let Some(id) = self.capability_by_name(name) {
            return Some(Symbol::Capability(id));
        }
        if let Some(&id) = self.name_to_nodes.get(name).and_then(|nodes| nodes.first()) {
            return Some(Symbol::Node(id));
        }
        if let Some(&id) = self.type_by_name.get(name) {
            return Some(Symbol::Type(id));
        }
        None
    }

    // --- OID lookups ---

    /// Look up a node at an exact numeric [`Oid`], returning the [`NodeId`].
    ///
    /// Returns `None` if no tree node exists at that exact OID.
    #[must_use]
    pub fn node_by_oid(&self, oid: &Oid) -> Option<NodeId> {
        let (id, exact) = self.tree.walk_oid(self.tree.root(), oid);
        if exact { Some(id) } else { None }
    }

    /// Look up a node by name and return a [`Node`] handle.
    #[must_use]
    pub fn node(&self, name: &str) -> Option<Node<'_>> {
        self.node_by_name(name).map(|id| Node::new(self, id))
    }

    /// Look up a node only when the numeric OID exactly matches a tree node.
    ///
    /// For instance OIDs such as `ifIndex.5`, use [`Mib::lookup_oid`] or
    /// [`Mib::resolve_node`] instead.
    #[must_use]
    pub fn exact_node_by_oid(&self, oid: &Oid) -> Option<Node<'_>> {
        self.node_by_oid(oid).map(|id| Node::new(self, id))
    }

    /// Find the deepest node matching a prefix of the OID, starting from root.
    #[must_use]
    pub fn longest_prefix_by_oid(&self, oid: &Oid) -> NodeId {
        self.tree.longest_prefix(oid)
    }

    /// Look up the deepest node matching a numeric OID prefix as a [`Node`] handle.
    ///
    /// This is the handle-oriented entry point for instance OIDs such as
    /// `ifIndex.5`. Always returns a node (at minimum the root).
    ///
    /// When you also need the instance suffix (the arcs after the matched
    /// node), use [`lookup_instance`](Mib::lookup_instance) instead.
    #[must_use]
    pub fn lookup_oid(&self, oid: &Oid) -> Node<'_> {
        Node::new(self, self.longest_prefix_by_oid(oid))
    }

    /// Look up a numeric OID and return both the matched node and the
    /// instance suffix.
    ///
    /// This is the standard pattern for processing SNMP varbinds, where
    /// you need the base node (for metadata, type info, formatting) and
    /// the trailing arcs (the instance index that identifies which row
    /// or scalar instance the value belongs to).
    ///
    /// # Examples
    ///
    /// ```
    /// # fn example_mib() -> mib_rs::Mib {
    /// #     let source = mib_rs::source::memory(
    /// #         "DOC-EXAMPLE-MIB",
    /// #         include_bytes!("../../tests/data/doc-example-mib.txt").as_slice(),
    /// #     );
    /// #     mib_rs::Loader::new()
    /// #         .source(source)
    /// #         .modules(["DOC-EXAMPLE-MIB"])
    /// #         .load()
    /// #         .expect("example MIB should load")
    /// # }
    /// let mib = example_mib();
    /// let instance_oid = mib.resolve_oid("docDescr.7").unwrap();
    /// let lookup = mib.lookup_instance(&instance_oid);
    /// assert_eq!(lookup.node().name(), "docDescr");
    /// assert_eq!(lookup.suffix(), &[7]);
    /// ```
    #[must_use]
    pub fn lookup_instance(&self, oid: &Oid) -> OidLookup<'_> {
        let id = self.longest_prefix_by_oid(oid);
        let node_oid = self.tree.oid_of(id);
        let suffix = oid[node_oid.len()..].to_vec();
        OidLookup {
            node: Node::new(self, id),
            suffix,
        }
    }

    /// Depth-first iterator over a subtree rooted at `id`, yielding [`NodeId`]s.
    pub fn subtree(&self, id: NodeId) -> super::node::SubtreeIter<'_> {
        self.tree.subtree(id)
    }

    /// Find the deepest descendant of `start` matching a prefix of `oid`.
    #[must_use]
    pub fn longest_prefix_from(&self, start: NodeId, oid: &Oid) -> NodeId {
        self.tree.longest_prefix_from(start, oid)
    }

    pub(crate) fn effective_module(&self, id: NodeId) -> Option<ModuleId> {
        self.tree.get(id).module
    }

    /// Format a numeric [`Oid`] as `MODULE::name.suffix`.
    ///
    /// Uses longest-prefix matching to find the deepest named node, then
    /// appends any remaining arcs as a dotted numeric suffix. Returns the
    /// raw numeric string if no named node matches.
    pub fn format_oid(&self, oid: &Oid) -> String {
        if oid.is_empty() {
            return String::new();
        }
        let lookup = self.lookup_instance(oid);
        let matched = self.tree.get(lookup.node.id);
        if matched.name.is_empty() {
            return oid.to_string();
        }

        let mut result = String::new();
        if let Some(mod_id) = self.effective_module(lookup.node.id) {
            result.push_str(&self.modules[mod_id.0 as usize].name);
            result.push_str("::");
        }
        result.push_str(&matched.name);
        for arc in lookup.suffix() {
            result.push('.');
            result.push_str(&arc.to_string());
        }
        result
    }

    /// Look up a node by name, qualified name (`MODULE::name`), or OID query,
    /// returning a [`Node`] handle.
    ///
    /// Symbolic and numeric instance OIDs resolve to the deepest matching node
    /// rather than requiring an exact tree match. See [`Mib::resolve_oid`] for the
    /// accepted query forms.
    pub fn resolve_node(&self, query: &str) -> Option<Node<'_>> {
        self.resolve(query).map(|id| Node::new(self, id))
    }

    pub(crate) fn resolve(&self, query: &str) -> Option<NodeId> {
        // Numeric OID
        let q = query.strip_prefix('.').unwrap_or(query);
        if q.starts_with(|c: char| c.is_ascii_digit()) {
            let oid: Oid = q.parse().ok()?;
            return Some(self.longest_prefix_by_oid(&oid));
        }

        self.resolve_oid(query)
            .ok()
            .map(|oid| self.longest_prefix_by_oid(&oid))
    }

    /// Convert a symbolic or numeric OID query to a numeric [`Oid`].
    ///
    /// Accepted forms include plain names, qualified names, symbolic suffixes,
    /// and numeric OIDs.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveOidError`] if the query is empty, the referenced module
    /// or node name is not found, or a numeric suffix fails to parse.
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

    /// Return all symbols defined across all modules.
    ///
    /// Iterates modules in load order, yielding each module's definitions.
    pub fn all_symbols(&self) -> Vec<Symbol> {
        let mut result = Vec::new();
        for module in &self.modules {
            result.extend(module.definitions());
        }
        result
    }

    /// Return all symbols available in a module's scope.
    ///
    /// Own definitions come first, then imported symbols resolved from their
    /// source modules. A name that is both defined and imported is yielded
    /// only once (the own definition wins).
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

    /// Iterate all resolved modules as [`Module`] handles.
    ///
    /// This includes the seven synthetic base modules (SNMPv2-SMI, etc.)
    /// which are always present. Use [`Module::is_base`] to filter them out
    /// when you only want user-supplied modules.
    pub fn modules(&self) -> HandleIter<'_, Module<'_>, impl Iterator<Item = ModuleId>> {
        HandleIter::new(
            self,
            (0..self.modules.len()).map(|i| ModuleId::new(i as u32)),
        )
    }

    /// Iterate user-supplied (non-base) modules as [`Module`] handles.
    ///
    /// Excludes the seven synthetic base modules. Equivalent to
    /// `self.modules().filter(|m| !m.is_base())` but more convenient.
    pub fn user_modules(&self) -> impl Iterator<Item = Module<'_>> + '_ {
        self.modules
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.is_base())
            .map(|(i, _)| Module::new(self, ModuleId::new(i as u32)))
    }

    /// Iterate all resolved objects as [`Object`] handles.
    ///
    /// Includes objects from base modules. Use [`Object::module`] and
    /// [`Module::is_base`] to filter if needed.
    pub fn objects(&self) -> HandleIter<'_, Object<'_>, impl Iterator<Item = ObjectId>> {
        HandleIter::new(
            self,
            (0..self.objects.len()).map(|i| ObjectId::new(i as u32)),
        )
    }

    /// Iterate all resolved types as [`Type`] handles.
    ///
    /// Includes types from base modules (e.g. `Counter32`, `DisplayString`).
    /// Use [`Type::module`] and [`Module::is_base`] to filter if needed.
    pub fn types(&self) -> HandleIter<'_, Type<'_>, impl Iterator<Item = TypeId>> {
        HandleIter::new(self, (0..self.types.len()).map(|i| TypeId::new(i as u32)))
    }

    /// Iterate all OID tree nodes (excluding root) as [`Node`] handles.
    ///
    /// Includes nodes from base modules (e.g. `iso`, `internet`, `enterprises`).
    /// Use [`Node::module`] and [`Module::is_base`] to filter if needed.
    pub fn nodes(&self) -> HandleIter<'_, Node<'_>, impl Iterator<Item = NodeId>> {
        HandleIter::new(self, self.tree.all_nodes())
    }

    /// Iterate all resolved notifications as [`Notification`] handles.
    pub fn notifications(
        &self,
    ) -> HandleIter<'_, Notification<'_>, impl Iterator<Item = NotificationId>> {
        HandleIter::new(
            self,
            (0..self.notifications.len()).map(|i| NotificationId::new(i as u32)),
        )
    }

    /// Iterate all resolved groups as [`Group`] handles.
    pub fn groups(&self) -> HandleIter<'_, Group<'_>, impl Iterator<Item = GroupId>> {
        HandleIter::new(self, (0..self.groups.len()).map(|i| GroupId::new(i as u32)))
    }

    /// Iterate all resolved compliance statements as [`Compliance`] handles.
    pub fn compliances(
        &self,
    ) -> HandleIter<'_, Compliance<'_>, impl Iterator<Item = ComplianceId>> {
        HandleIter::new(
            self,
            (0..self.compliances.len()).map(|i| ComplianceId::new(i as u32)),
        )
    }

    /// Iterate all resolved capability statements as [`Capability`] handles.
    pub fn capabilities(
        &self,
    ) -> HandleIter<'_, Capability<'_>, impl Iterator<Item = CapabilityId>> {
        HandleIter::new(
            self,
            (0..self.capabilities.len()).map(|i| CapabilityId::new(i as u32)),
        )
    }

    /// Return a [`Node`] handle for the given [`NodeId`].
    pub fn node_by_id(&self, id: NodeId) -> Node<'_> {
        Node::new(self, id)
    }

    /// Return an [`Object`] handle for the given [`ObjectId`].
    pub fn object_by_id(&self, id: ObjectId) -> Object<'_> {
        Object::new(self, id)
    }

    /// Return a [`Type`] handle for the given [`TypeId`].
    pub fn type_by_id(&self, id: TypeId) -> Type<'_> {
        Type::new(self, id)
    }

    /// Return a [`Module`] handle for the given [`ModuleId`].
    pub fn module_by_id(&self, id: ModuleId) -> Module<'_> {
        Module::new(self, id)
    }

    /// Return a [`Notification`] handle for the given [`NotificationId`].
    pub fn notification_by_id(&self, id: NotificationId) -> Notification<'_> {
        Notification::new(self, id)
    }

    /// Return a [`Group`] handle for the given [`GroupId`].
    pub fn group_by_id(&self, id: GroupId) -> Group<'_> {
        Group::new(self, id)
    }

    /// Return a [`Compliance`] handle for the given [`ComplianceId`].
    pub fn compliance_by_id(&self, id: ComplianceId) -> Compliance<'_> {
        Compliance::new(self, id)
    }

    /// Return a [`Capability`] handle for the given [`CapabilityId`].
    pub fn capability_by_id(&self, id: CapabilityId) -> Capability<'_> {
        Capability::new(self, id)
    }

    pub(crate) fn modules_slice(&self) -> &[ModuleData] {
        &self.modules
    }

    pub(crate) fn objects_slice(&self) -> &[ObjectData] {
        &self.objects
    }

    pub(crate) fn types_slice(&self) -> &[TypeData] {
        &self.types
    }

    pub(crate) fn notifications_slice(&self) -> &[NotificationData] {
        &self.notifications
    }

    pub(crate) fn groups_slice(&self) -> &[GroupData] {
        &self.groups
    }

    pub(crate) fn compliances_slice(&self) -> &[ComplianceData] {
        &self.compliances
    }

    pub(crate) fn capabilities_slice(&self) -> &[CapabilityData] {
        &self.capabilities
    }

    /// Return all non-base modules that define a symbol with the given name.
    ///
    /// Synthetic base modules (SNMPv2-SMI, etc.) are excluded from the results.
    pub fn modules_defining(&self, name: &str) -> Vec<ModuleId> {
        self.modules
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.is_base && m.defines_symbol(name))
            .map(|(i, _)| ModuleId::new(i as u32))
            .collect()
    }

    /// Return all non-base modules that import a symbol with the given name.
    ///
    /// Synthetic base modules (SNMPv2-SMI, etc.) are excluded from the results.
    pub fn modules_importing(&self, name: &str) -> Vec<ModuleId> {
        self.modules
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.is_base && m.imports_symbol(name))
            .map(|(i, _)| ModuleId::new(i as u32))
            .collect()
    }

    /// Return all objects whose OID tree node has the given [`Kind`].
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

    /// Iterate all table objects as [`Object`] handles.
    pub fn tables(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.objects_with_kind(Kind::Table)
    }

    /// Iterate all scalar objects as [`Object`] handles.
    pub fn scalars(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.objects_with_kind(Kind::Scalar)
    }

    /// Iterate all column objects as [`Object`] handles.
    pub fn columns(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.objects_with_kind(Kind::Column)
    }

    /// Iterate all row (entry) objects as [`Object`] handles.
    pub fn rows(&self) -> impl Iterator<Item = Object<'_>> + '_ {
        self.objects_with_kind(Kind::Row)
    }

    /// Return all objects whose resolved type has the given name.
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

    /// Return all objects whose effective [`BaseType`] matches.
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

    /// Return the containing table object for a table, row, or column.
    ///
    /// Tables return themselves. Scalars and non-tabular objects return `None`.
    pub fn object_table(&self, id: ObjectId) -> Option<ObjectId> {
        let node_id = self.object_data(id).node()?;
        let node = self.tree.get(node_id);
        match node.kind {
            Kind::Table => Some(id),
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

    /// Return the associated row object for a table, row, or column.
    ///
    /// Tables return their child row entry. Rows return themselves. Columns
    /// return their parent row. Scalars and non-tabular objects return `None`.
    pub fn object_row(&self, id: ObjectId) -> Option<ObjectId> {
        let node_id = self.object_data(id).node()?;
        let node = self.tree.get(node_id);
        match node.kind {
            Kind::Table => {
                for &child_id in node.children.values() {
                    let child = self.tree.get(child_id);
                    if child.kind == Kind::Row {
                        return child.object;
                    }
                }
                None
            }
            Kind::Row => Some(id),
            Kind::Column => {
                let parent = self.tree.get(node.parent?);
                parent.object
            }
            _ => None,
        }
    }

    /// Return column objects for a table or row in arc order.
    ///
    /// Non-tabular objects return an empty vector.
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

    /// Return [`IndexEntry`] items for a row, following the AUGMENTS chain if needed.
    ///
    /// Returns an empty vector for non-row objects. For handle-level access,
    /// see [`Object::effective_indexes`](super::handle::Object::effective_indexes).
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
        let kind = self.tree.get(node_id).kind;
        if kind == Kind::Column {
            if let Some(row_id) = self.object_row(id) {
                return self.effective_indexes_inner(row_id, visited);
            }
            return Vec::new();
        }
        if kind != Kind::Row {
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
        let kind = self.tree.get(node_id).kind;
        if kind == Kind::Column {
            let row_id = self.object_row(id)?;
            return self.effective_indexes_source_inner(row_id, visited);
        }
        if kind != Kind::Row {
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

    /// Return `true` if the object is a table.
    pub fn is_table(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Table
    }

    /// Return `true` if the object is a table row (entry).
    pub fn is_row(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Row
    }

    /// Return `true` if the object is a table column.
    pub fn is_column(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Column
    }

    /// Return `true` if the object is a scalar.
    pub fn is_scalar(&self, id: ObjectId) -> bool {
        self.object_kind(id) == Kind::Scalar
    }

    /// Return `true` if a column appears in its parent row's effective indexes.
    pub fn is_index(&self, id: ObjectId) -> bool {
        if self.object_kind(id) != Kind::Column {
            return false;
        }
        self.effective_indexes(id)
            .iter()
            .any(|idx| idx.object == Some(id))
    }

    fn objects_with_kind(&self, kind: Kind) -> impl Iterator<Item = Object<'_>> + '_ {
        self.objects.iter().enumerate().filter_map(move |(i, obj)| {
            let node_id = obj.entity.node?;
            if self.tree.get(node_id).kind == kind {
                Some(Object::new(self, ObjectId::new(i as u32)))
            } else {
                None
            }
        })
    }

    fn object_kind(&self, id: ObjectId) -> Kind {
        match self.object_data(id).node() {
            Some(node_id) => self.tree.get(node_id).kind,
            None => Kind::Unknown,
        }
    }

    // --- Diagnostics ---

    /// Return the total number of OID tree nodes created during resolution.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Return all diagnostics collected during loading and resolution.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Return all unresolved symbol references collected during resolution.
    pub fn unresolved(&self) -> &[UnresolvedRef] {
        &self.unresolved
    }

    /// Return `true` if any diagnostic has [`Severity::Error`] or higher.
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
        if !data.entity.name.is_empty() {
            self.objects_by_name
                .entry(data.entity.name.clone())
                .or_default()
                .push(id);
        }
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
        if !data.entity.name.is_empty() {
            self.notifications_by_name
                .entry(data.entity.name.clone())
                .or_default()
                .push(id);
        }
        self.notifications.push(data);
        id
    }

    pub(crate) fn add_group(&mut self, data: GroupData) -> GroupId {
        let id = GroupId::new(self.groups.len() as u32);
        if !data.entity.name.is_empty() {
            self.groups_by_name
                .entry(data.entity.name.clone())
                .or_default()
                .push(id);
        }
        self.groups.push(data);
        id
    }

    pub(crate) fn add_compliance(&mut self, data: ComplianceData) -> ComplianceId {
        let id = ComplianceId::new(self.compliances.len() as u32);
        if !data.entity.name.is_empty() {
            self.compliances_by_name
                .entry(data.entity.name.clone())
                .or_default()
                .push(id);
        }
        self.compliances.push(data);
        id
    }

    pub(crate) fn add_capability(&mut self, data: CapabilityData) -> CapabilityId {
        let id = CapabilityId::new(self.capabilities.len() as u32);
        if !data.entity.name.is_empty() {
            self.capabilities_by_name
                .entry(data.entity.name.clone())
                .or_default()
                .push(id);
        }
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

/// Result of [`Mib::lookup_instance`], containing the matched node and
/// any remaining instance suffix arcs.
pub struct OidLookup<'a> {
    node: Node<'a>,
    suffix: Vec<u32>,
}

impl<'a> OidLookup<'a> {
    /// The deepest tree node matching the OID prefix.
    #[must_use]
    pub fn node(&self) -> Node<'a> {
        self.node
    }

    /// The instance suffix: arcs from the input OID that follow the
    /// matched node's OID.
    ///
    /// Empty when the input OID exactly matches a tree node.
    #[must_use]
    pub fn suffix(&self) -> &[u32] {
        &self.suffix
    }

    /// Decode the instance suffix into typed index values.
    ///
    /// Uses the matched node's row INDEX clause to interpret the suffix
    /// arcs per RFC 2578 section 7.7. Returns an empty Vec if the node
    /// has no associated object, is not part of a table, or the row has
    /// no index definitions.
    ///
    /// See [`index::decode_suffix`](super::index::decode_suffix) for
    /// the standalone function and encoding details.
    #[must_use]
    pub fn decode_indexes(&self) -> Vec<super::index::DecodedIndex> {
        let Some(obj) = self.node.object() else {
            return Vec::new();
        };
        let mut indexes = obj.effective_indexes().peekable();
        if indexes.peek().is_none() {
            return Vec::new();
        }
        super::index::decode_suffix(indexes, &self.suffix)
    }
}

/// Error returned by [`Mib::resolve_oid`] when a query cannot be resolved.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolveOidError {
    /// The query string was empty.
    #[error("empty query")]
    EmptyQuery,
    /// The query looked numeric but could not be parsed as a valid OID.
    #[error("invalid OID: {0}")]
    InvalidOid(#[source] ParseOidError),
    /// The module part of a qualified name was not found.
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    /// The plain name was not found in any loaded module.
    #[error("node not found: {0}")]
    NodeNotFound(String),
    /// The name was not found within the specified module.
    #[error("node not found: {module}::{name}")]
    QualifiedNodeNotFound {
        /// Module name from the query.
        module: String,
        /// Node name from the query.
        name: String,
    },
    /// The trailing instance suffix could not be parsed as numeric arcs.
    #[error("invalid instance suffix {suffix:?}: {source}")]
    InvalidSuffix {
        /// The suffix string that failed to parse.
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
