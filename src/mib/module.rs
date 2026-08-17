//! Loaded MIB module data and per-module symbol indices.
//!
//! [`ModuleData`] stores module-level metadata (organization, description,
//! revisions, imports) along with per-entity name indices for fast lookup
//! within a single module.
//!
//! For handle-oriented access, see [`Module`](super::handle::Module).

use std::collections::{HashMap, HashSet};

use crate::mib::Oid;
use crate::source::SourceId;
use crate::types::Language;

use super::symbol::Symbol;
use super::types::*;

/// A loaded and resolved MIB module.
///
/// Contains module-level metadata (organization, description, revisions),
/// import declarations, and per-entity name indices. Access through the
/// public accessor methods or the [`Module`](super::handle::Module) handle.
pub struct ModuleData {
    pub(crate) name: String,
    pub(crate) language: Language,
    pub(crate) source_id: Option<SourceId>,
    pub(crate) is_base: bool,
    pub(crate) oid: Option<Oid>,
    pub(crate) organization: String,
    pub(crate) contact_info: String,
    pub(crate) description: String,
    pub(crate) last_updated: String,
    pub(crate) revisions: Vec<Revision>,
    pub(crate) imports: Vec<Import>,

    pub(crate) objects: Vec<ObjectId>,
    pub(crate) types: Vec<TypeId>,
    pub(crate) notifications: Vec<NotificationId>,
    pub(crate) groups: Vec<GroupId>,
    pub(crate) compliances: Vec<ComplianceId>,
    pub(crate) capabilities: Vec<CapabilityId>,
    pub(crate) nodes: Vec<NodeId>,

    pub(crate) used_import_names: HashSet<String>,
    pub(crate) resolved_imports: HashMap<String, ModuleId>,

    pub(crate) objects_by_name: HashMap<String, ObjectId>,
    pub(crate) types_by_name: HashMap<String, TypeId>,
    pub(crate) notifications_by_name: HashMap<String, NotificationId>,
    pub(crate) groups_by_name: HashMap<String, GroupId>,
    pub(crate) compliances_by_name: HashMap<String, ComplianceId>,
    pub(crate) capabilities_by_name: HashMap<String, CapabilityId>,
    pub(crate) nodes_by_name: HashMap<String, NodeId>,
}

impl ModuleData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            name,
            language: Language::Unknown,
            source_id: None,
            is_base: false,
            oid: None,
            organization: String::new(),
            contact_info: String::new(),
            description: String::new(),
            last_updated: String::new(),
            revisions: Vec::new(),
            imports: Vec::new(),
            objects: Vec::new(),
            types: Vec::new(),
            notifications: Vec::new(),
            groups: Vec::new(),
            compliances: Vec::new(),
            capabilities: Vec::new(),
            nodes: Vec::new(),
            used_import_names: HashSet::new(),
            resolved_imports: HashMap::new(),
            objects_by_name: HashMap::new(),
            types_by_name: HashMap::new(),
            notifications_by_name: HashMap::new(),
            groups_by_name: HashMap::new(),
            compliances_by_name: HashMap::new(),
            capabilities_by_name: HashMap::new(),
            nodes_by_name: HashMap::new(),
        }
    }

    /// Return the module name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the SMI language version.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Return the compilation-local source identity, if this module came from source text.
    pub fn source_id(&self) -> Option<SourceId> {
        self.source_id
    }

    /// Return `true` if this is an SMI foundation module.
    ///
    /// See [`Module::is_base`](super::Module::is_base) for details.
    pub fn is_base(&self) -> bool {
        self.is_base
    }

    /// Return the module's MODULE-IDENTITY OID, if any.
    pub fn oid(&self) -> Option<&Oid> {
        self.oid.as_ref()
    }

    /// Return the ORGANIZATION clause text.
    pub fn organization(&self) -> &str {
        &self.organization
    }

    /// Return the CONTACT-INFO clause text.
    pub fn contact_info(&self) -> &str {
        &self.contact_info
    }

    /// Return the DESCRIPTION clause text.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Return the LAST-UPDATED timestamp string.
    pub fn last_updated(&self) -> &str {
        &self.last_updated
    }

    /// Return the REVISION entries.
    pub fn revisions(&self) -> &[Revision] {
        &self.revisions
    }

    /// Return the IMPORTS declarations.
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// Return the object ids defined by this module.
    pub fn objects(&self) -> &[ObjectId] {
        &self.objects
    }

    /// Return the type ids defined by this module.
    pub fn types(&self) -> &[TypeId] {
        &self.types
    }

    /// Return the notification ids defined by this module.
    pub fn notifications(&self) -> &[NotificationId] {
        &self.notifications
    }

    /// Return the group ids defined by this module.
    pub fn groups(&self) -> &[GroupId] {
        &self.groups
    }

    /// Return the compliance ids defined by this module.
    pub fn compliances(&self) -> &[ComplianceId] {
        &self.compliances
    }

    /// Return the capability ids defined by this module.
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }

    /// Return the node ids defined by this module.
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// Look up an object by name within this module.
    pub fn object_by_name(&self, name: &str) -> Option<ObjectId> {
        self.objects_by_name.get(name).copied()
    }

    /// Look up a type by name within this module.
    pub fn type_by_name(&self, name: &str) -> Option<TypeId> {
        self.types_by_name.get(name).copied()
    }

    /// Look up a notification by name within this module.
    pub fn notification_by_name(&self, name: &str) -> Option<NotificationId> {
        self.notifications_by_name.get(name).copied()
    }

    /// Look up a group by name within this module.
    pub fn group_by_name(&self, name: &str) -> Option<GroupId> {
        self.groups_by_name.get(name).copied()
    }

    /// Look up a compliance statement by name within this module.
    pub fn compliance_by_name(&self, name: &str) -> Option<ComplianceId> {
        self.compliances_by_name.get(name).copied()
    }

    /// Look up a capability statement by name within this module.
    pub fn capability_by_name(&self, name: &str) -> Option<CapabilityId> {
        self.capabilities_by_name.get(name).copied()
    }

    /// Look up a node by name within this module.
    pub fn node_by_name(&self, name: &str) -> Option<NodeId> {
        self.nodes_by_name.get(name).copied()
    }

    /// Look up a symbol by name. Priority: objects, types, notifications,
    /// groups, compliances, capabilities, then plain nodes.
    pub fn symbol(&self, name: &str) -> Option<Symbol> {
        if let Some(&id) = self.objects_by_name.get(name) {
            return Some(Symbol::Object(id));
        }
        if let Some(&id) = self.types_by_name.get(name) {
            return Some(Symbol::Type(id));
        }
        if let Some(&id) = self.notifications_by_name.get(name) {
            return Some(Symbol::Notification(id));
        }
        if let Some(&id) = self.groups_by_name.get(name) {
            return Some(Symbol::Group(id));
        }
        if let Some(&id) = self.compliances_by_name.get(name) {
            return Some(Symbol::Compliance(id));
        }
        if let Some(&id) = self.capabilities_by_name.get(name) {
            return Some(Symbol::Capability(id));
        }
        if let Some(&id) = self.nodes_by_name.get(name) {
            return Some(Symbol::Node(id));
        }
        None
    }

    /// Return `true` if this module defines a symbol with the given name.
    pub fn defines_symbol(&self, name: &str) -> bool {
        self.symbol(name).is_some()
    }

    /// Return `true` if this module imports a symbol with the given name.
    pub fn imports_symbol(&self, name: &str) -> bool {
        self.imports
            .iter()
            .any(|imp| imp.symbols.iter().any(|s| s.name == name))
    }

    /// Return `true` if the named import was actually used during resolution.
    pub fn is_import_used(&self, name: &str) -> bool {
        self.used_import_names.contains(name)
    }

    /// Return the resolved source module for an imported name.
    pub fn import_source(&self, name: &str) -> Option<ModuleId> {
        self.resolved_imports.get(name).copied()
    }

    // Builder methods used during resolution.

    pub(crate) fn add_object(&mut self, name: impl Into<String>, id: ObjectId) {
        self.objects.push(id);
        self.objects_by_name.entry(name.into()).or_insert(id);
    }

    pub(crate) fn add_type(&mut self, name: impl Into<String>, id: TypeId) {
        self.types.push(id);
        self.types_by_name.entry(name.into()).or_insert(id);
    }

    pub(crate) fn add_notification(&mut self, name: impl Into<String>, id: NotificationId) {
        self.notifications.push(id);
        self.notifications_by_name.entry(name.into()).or_insert(id);
    }

    pub(crate) fn add_group(&mut self, name: impl Into<String>, id: GroupId) {
        self.groups.push(id);
        self.groups_by_name.entry(name.into()).or_insert(id);
    }

    pub(crate) fn add_compliance(&mut self, name: impl Into<String>, id: ComplianceId) {
        self.compliances.push(id);
        self.compliances_by_name.entry(name.into()).or_insert(id);
    }

    pub(crate) fn add_capability(&mut self, name: impl Into<String>, id: CapabilityId) {
        self.capabilities.push(id);
        self.capabilities_by_name.entry(name.into()).or_insert(id);
    }

    pub(crate) fn add_node(&mut self, name: impl Into<String>, id: NodeId) {
        self.nodes.push(id);
        self.nodes_by_name.entry(name.into()).or_insert(id);
    }

    /// Yield all definitions in this module as [`Symbol`] values.
    ///
    /// Entity-backed definitions (objects, types, notifications, groups,
    /// compliances, capabilities) come first. Plain nodes (not attached to
    /// any entity) are yielded last.
    pub fn definitions(&self) -> impl Iterator<Item = Symbol> + '_ {
        // Covered node IDs: nodes whose names also appear in an entity map.
        let covered_node_ids: HashSet<NodeId> = self
            .nodes_by_name
            .iter()
            .filter_map(|(name, &id)| {
                (self.objects_by_name.contains_key(name)
                    || self.notifications_by_name.contains_key(name)
                    || self.groups_by_name.contains_key(name)
                    || self.compliances_by_name.contains_key(name)
                    || self.capabilities_by_name.contains_key(name))
                .then_some(id)
            })
            .collect();

        self.objects
            .iter()
            .map(|&id| Symbol::Object(id))
            .chain(self.types.iter().map(|&id| Symbol::Type(id)))
            .chain(
                self.notifications
                    .iter()
                    .map(|&id| Symbol::Notification(id)),
            )
            .chain(self.groups.iter().map(|&id| Symbol::Group(id)))
            .chain(self.compliances.iter().map(|&id| Symbol::Compliance(id)))
            .chain(self.capabilities.iter().map(|&id| Symbol::Capability(id)))
            .chain(
                self.nodes
                    .iter()
                    .filter(move |id| !covered_node_ids.contains(id))
                    .map(|&id| Symbol::Node(id)),
            )
    }
}

impl std::fmt::Debug for ModuleData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleData")
            .field("name", &self.name)
            .field("language", &self.language)
            .field("is_base", &self.is_base)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definitions_include_only_plain_nodes() {
        let mut module = ModuleData::new("TEST-MIB".to_string());

        let object_id = ObjectId::new(0);
        let object_node = NodeId::new(10);
        let plain_node = NodeId::new(11);

        module.add_object("ifIndex", object_id);
        module.add_node("ifIndex", object_node);
        module.add_node("internet", plain_node);

        let defs: Vec<_> = module.definitions().collect();

        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0], Symbol::Object(object_id));
        assert_eq!(defs[1], Symbol::Node(plain_node));
    }

    #[test]
    fn definitions_keep_plain_nodes_on_type_name_collision() {
        let mut module = ModuleData::new("TEST-MIB".to_string());

        let type_id = TypeId::new(0);
        let plain_node = NodeId::new(11);

        module.add_type("DisplayString", type_id);
        module.add_node("DisplayString", plain_node);

        let defs: Vec<_> = module.definitions().collect();

        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0], Symbol::Type(type_id));
        assert_eq!(defs[1], Symbol::Node(plain_node));
    }
}
