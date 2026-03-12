use std::collections::{HashMap, HashSet};

use crate::mib::Oid;
use crate::types::Language;

use super::symbol::Symbol;
use super::types::*;

/// A loaded and resolved MIB module.
pub struct ModuleData {
    pub(crate) name: String,
    pub(crate) language: Language,
    pub(crate) source_path: String,
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

    pub(crate) line_table: Vec<usize>,

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
            source_path: String::new(),
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
            line_table: Vec::new(),
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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }

    pub fn line_col(&self, offset: crate::types::ByteOffset) -> (usize, usize) {
        crate::types::line_col_from_table(&self.line_table, offset)
    }

    pub fn oid(&self) -> Option<&Oid> {
        self.oid.as_ref()
    }

    pub fn organization(&self) -> &str {
        &self.organization
    }

    pub fn contact_info(&self) -> &str {
        &self.contact_info
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn last_updated(&self) -> &str {
        &self.last_updated
    }

    pub fn revisions(&self) -> &[Revision] {
        &self.revisions
    }

    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    pub fn objects(&self) -> &[ObjectId] {
        &self.objects
    }

    pub fn types(&self) -> &[TypeId] {
        &self.types
    }

    pub fn notifications(&self) -> &[NotificationId] {
        &self.notifications
    }

    pub fn groups(&self) -> &[GroupId] {
        &self.groups
    }

    pub fn compliances(&self) -> &[ComplianceId] {
        &self.compliances
    }

    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }

    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    pub fn object_by_name(&self, name: &str) -> Option<ObjectId> {
        self.objects_by_name.get(name).copied()
    }

    pub fn type_by_name(&self, name: &str) -> Option<TypeId> {
        self.types_by_name.get(name).copied()
    }

    pub fn notification_by_name(&self, name: &str) -> Option<NotificationId> {
        self.notifications_by_name.get(name).copied()
    }

    pub fn group_by_name(&self, name: &str) -> Option<GroupId> {
        self.groups_by_name.get(name).copied()
    }

    pub fn compliance_by_name(&self, name: &str) -> Option<ComplianceId> {
        self.compliances_by_name.get(name).copied()
    }

    pub fn capability_by_name(&self, name: &str) -> Option<CapabilityId> {
        self.capabilities_by_name.get(name).copied()
    }

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

    pub fn defines_symbol(&self, name: &str) -> bool {
        self.symbol(name).is_some()
    }

    pub fn imports_symbol(&self, name: &str) -> bool {
        self.imports
            .iter()
            .any(|imp| imp.symbols.iter().any(|s| s.name == name))
    }

    pub fn is_import_used(&self, name: &str) -> bool {
        self.used_import_names.contains(name)
    }

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

    /// Yield all definitions in this module as Symbol values.
    ///
    /// Plain nodes (nodes not attached to an object/notification/group/
    /// compliance/capability entity) are yielded last.
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
