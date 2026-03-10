use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::mib::Oid;
use crate::types::{Kind, Span};

use super::types::*;

/// A single node in the OID tree.
///
/// All fields are pub(crate) - external access goes through the Mib API.
pub struct NodeData {
    pub(crate) arc: u32,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) reference: String,
    pub(crate) kind: Kind,
    pub(crate) span: Span,
    pub(crate) parent: Option<NodeId>,
    pub(crate) children: BTreeMap<u32, NodeId>,
    pub(crate) module: Option<ModuleId>,
    pub(crate) object: Option<ObjectId>,
    pub(crate) notification: Option<NotificationId>,
    pub(crate) group: Option<GroupId>,
    pub(crate) compliance: Option<ComplianceId>,
    pub(crate) capability: Option<CapabilityId>,
    pub(crate) oid_cache: OnceLock<Oid>,
}

impl NodeData {
    pub(crate) fn new(arc: u32, parent: Option<NodeId>) -> Self {
        Self {
            arc,
            name: String::new(),
            description: String::new(),
            reference: String::new(),
            kind: Kind::Internal,
            span: Span::SYNTHETIC,
            parent,
            children: BTreeMap::new(),
            module: None,
            object: None,
            notification: None,
            group: None,
            compliance: None,
            capability: None,
            oid_cache: OnceLock::new(),
        }
    }

    pub(crate) fn root() -> Self {
        Self::new(0, None)
    }
}

impl NodeData {
    pub fn arc(&self) -> u32 {
        self.arc
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    pub fn children(&self) -> &BTreeMap<u32, NodeId> {
        &self.children
    }

    pub fn module(&self) -> Option<ModuleId> {
        self.module
    }

    pub fn object(&self) -> Option<ObjectId> {
        self.object
    }

    pub fn notification(&self) -> Option<NotificationId> {
        self.notification
    }

    pub fn group(&self) -> Option<GroupId> {
        self.group
    }

    pub fn compliance(&self) -> Option<ComplianceId> {
        self.compliance
    }

    pub fn capability(&self) -> Option<CapabilityId> {
        self.capability
    }

    /// Reports whether this is the unnamed root node (no parent).
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }
}

/// Arena-allocated OID tree.
///
/// All nodes are stored in a contiguous Vec. The tree is built during
/// resolution via get_or_create_child / set_name / attach_* methods,
/// then accessed read-only through the Mib API.
pub struct OidTree {
    nodes: Vec<NodeData>,
    root: NodeId,
}

impl OidTree {
    pub fn new() -> Self {
        Self {
            nodes: vec![NodeData::root()],
            root: NodeId::new(0),
        }
    }

    pub fn root(&self) -> NodeId {
        self.root
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, id: NodeId) -> &NodeData {
        &self.nodes[id.0 as usize]
    }

    pub(crate) fn get_mut(&mut self, id: NodeId) -> &mut NodeData {
        &mut self.nodes[id.0 as usize]
    }

    fn alloc(&mut self, data: NodeData) -> NodeId {
        let id = NodeId::new(self.nodes.len() as u32);
        self.nodes.push(data);
        id
    }

    /// Return the child at `arc` under `parent`, creating it if absent.
    pub(crate) fn get_or_create_child(&mut self, parent: NodeId, arc: u32) -> NodeId {
        if let Some(&child_id) = self.nodes[parent.0 as usize].children.get(&arc) {
            return child_id;
        }
        let child_id = self.alloc(NodeData::new(arc, Some(parent)));
        self.nodes[parent.0 as usize].children.insert(arc, child_id);
        child_id
    }

    pub(crate) fn set_name(&mut self, id: NodeId, name: String) {
        self.nodes[id.0 as usize].name = name;
    }

    pub(crate) fn set_kind(&mut self, id: NodeId, kind: Kind) {
        self.nodes[id.0 as usize].kind = kind;
    }

    pub(crate) fn set_description(&mut self, id: NodeId, desc: String) {
        self.nodes[id.0 as usize].description = desc;
    }

    pub(crate) fn set_reference(&mut self, id: NodeId, reference: String) {
        self.nodes[id.0 as usize].reference = reference;
    }

    pub(crate) fn set_span(&mut self, id: NodeId, span: Span) {
        self.nodes[id.0 as usize].span = span;
    }

    pub(crate) fn set_module(&mut self, id: NodeId, module: ModuleId) {
        self.nodes[id.0 as usize].module = Some(module);
    }

    pub(crate) fn attach_object(&mut self, id: NodeId, obj: ObjectId) {
        self.nodes[id.0 as usize].object = Some(obj);
    }

    pub(crate) fn attach_notification(&mut self, id: NodeId, notif: NotificationId) {
        self.nodes[id.0 as usize].notification = Some(notif);
    }

    pub(crate) fn attach_group(&mut self, id: NodeId, group: GroupId) {
        self.nodes[id.0 as usize].group = Some(group);
    }

    pub(crate) fn attach_compliance(&mut self, id: NodeId, compliance: ComplianceId) {
        self.nodes[id.0 as usize].compliance = Some(compliance);
    }

    pub(crate) fn attach_capability(&mut self, id: NodeId, cap: CapabilityId) {
        self.nodes[id.0 as usize].capability = Some(cap);
    }

    /// Walk the tree from `start` following arcs in `oid`.
    /// Returns (last_matched_node, whether_full_oid_matched).
    pub fn walk_oid(&self, start: NodeId, oid: &Oid) -> (NodeId, bool) {
        let mut current = start;
        for &arc in oid.iter() {
            match self.nodes[current.0 as usize].children.get(&arc) {
                Some(&child) => current = child,
                None => return (current, false),
            }
        }
        (current, true)
    }

    fn compute_oid(&self, id: NodeId) -> Oid {
        let node = &self.nodes[id.0 as usize];
        if node.parent.is_none() {
            return Oid::default();
        }
        let mut arcs = Vec::new();
        let mut current = id;
        loop {
            let n = &self.nodes[current.0 as usize];
            match n.parent {
                Some(parent) => {
                    arcs.push(n.arc);
                    current = parent;
                }
                None => break,
            }
        }
        arcs.reverse();
        Oid::from(arcs)
    }

    /// Return the OID for a node, using the per-node cache.
    pub fn oid_of(&self, id: NodeId) -> &Oid {
        self.nodes[id.0 as usize]
            .oid_cache
            .get_or_init(|| self.compute_oid(id))
    }

    /// Depth-first iterator over a subtree rooted at `start`.
    pub fn subtree(&self, start: NodeId) -> SubtreeIter<'_> {
        SubtreeIter {
            tree: self,
            stack: vec![start],
        }
    }

    /// Depth-first iterator over all nodes (excluding root).
    pub fn all_nodes(&self) -> SubtreeIter<'_> {
        let root = &self.nodes[self.root.0 as usize];
        let stack: Vec<NodeId> = root.children.values().rev().copied().collect();
        SubtreeIter { tree: self, stack }
    }

    /// Find the deepest node matching a prefix of `oid`.
    pub fn longest_prefix(&self, oid: &Oid) -> NodeId {
        let (matched, _) = self.walk_oid(self.root, oid);
        matched
    }
}

impl Default for OidTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-first iterator over an OID subtree.
pub struct SubtreeIter<'a> {
    tree: &'a OidTree,
    stack: Vec<NodeId>,
}

impl<'a> Iterator for SubtreeIter<'a> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        let id = self.stack.pop()?;
        let node = &self.tree.nodes[id.0 as usize];
        // Push children in reverse order so smallest arc is popped first.
        for (_, &child_id) in node.children.iter().rev() {
            self.stack.push(child_id);
        }
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_construction() {
        let mut tree = OidTree::new();
        let root = tree.root();

        let iso = tree.get_or_create_child(root, 1);
        tree.set_name(iso, "iso".into());

        let org = tree.get_or_create_child(iso, 3);
        tree.set_name(org, "org".into());

        let dod = tree.get_or_create_child(org, 6);
        tree.set_name(dod, "dod".into());

        assert_eq!(tree.len(), 4); // root + 3 nodes
        assert_eq!(tree.get(iso).name, "iso");
        assert_eq!(tree.get(org).name, "org");
        assert_eq!(tree.get(dod).name, "dod");

        let oid = tree.oid_of(dod);
        assert_eq!(&**oid, &[1, 3, 6]);
    }

    #[test]
    fn get_or_create_idempotent() {
        let mut tree = OidTree::new();
        let root = tree.root();

        let a = tree.get_or_create_child(root, 1);
        let b = tree.get_or_create_child(root, 1);
        assert_eq!(a, b);
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn walk_oid_exact() {
        let mut tree = OidTree::new();
        let root = tree.root();
        let a = tree.get_or_create_child(root, 1);
        let b = tree.get_or_create_child(a, 3);
        let c = tree.get_or_create_child(b, 6);

        let oid: Oid = "1.3.6".parse().unwrap();
        let (matched, exact) = tree.walk_oid(root, &oid);
        assert!(exact);
        assert_eq!(matched, c);
    }

    #[test]
    fn walk_oid_partial() {
        let mut tree = OidTree::new();
        let root = tree.root();
        let a = tree.get_or_create_child(root, 1);
        let _b = tree.get_or_create_child(a, 3);

        let oid: Oid = "1.3.6.1".parse().unwrap();
        let (_, exact) = tree.walk_oid(root, &oid);
        assert!(!exact);
    }

    #[test]
    fn subtree_iteration() {
        let mut tree = OidTree::new();
        let root = tree.root();
        let a = tree.get_or_create_child(root, 1);
        let b = tree.get_or_create_child(a, 2);
        let c = tree.get_or_create_child(a, 3);

        let nodes: Vec<NodeId> = tree.subtree(a).collect();
        assert_eq!(nodes, vec![a, b, c]);
    }

    #[test]
    fn all_nodes_excludes_root() {
        let mut tree = OidTree::new();
        let root = tree.root();
        let a = tree.get_or_create_child(root, 1);
        let b = tree.get_or_create_child(root, 2);

        let nodes: Vec<NodeId> = tree.all_nodes().collect();
        assert_eq!(nodes, vec![a, b]);
    }

    #[test]
    fn oid_caching() {
        let mut tree = OidTree::new();
        let root = tree.root();
        let a = tree.get_or_create_child(root, 1);
        let b = tree.get_or_create_child(a, 3);

        let oid1 = tree.oid_of(b);
        let oid2 = tree.oid_of(b);
        assert!(std::ptr::eq(oid1, oid2));
    }

    #[test]
    fn root_oid_is_empty() {
        let tree = OidTree::new();
        let root = tree.root();
        assert!(tree.oid_of(root).is_empty());
    }

    #[test]
    fn is_root() {
        let mut tree = OidTree::new();
        let root = tree.root();
        let child = tree.get_or_create_child(root, 1);

        assert!(tree.get(root).is_root());
        assert!(!tree.get(child).is_root());
    }
}
