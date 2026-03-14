//! Low-level arena-id-based access to the resolved MIB.
//!
//! [`RawMib`] is a thin borrowed wrapper over [`Mib`] that
//! exposes entity data records directly by arena id. Use this when you need
//! to work with ids obtained from [`super::Symbol`] or other id-returning APIs.
//! For most queries, prefer the handle API instead.

use crate::mib::Oid;

use super::capability::CapabilityData;
use super::compliance::ComplianceData;
use super::group::GroupData;
use super::mib::Mib;
use super::module::ModuleData;
use super::node::{NodeData, OidTree};
use super::notification::NotificationData;
use super::object::ObjectData;
use super::typedef::TypeData;
use super::types::*;

/// Low-level view into the resolved MIB data.
///
/// Provides direct access to arena-backed data records and the OID tree
/// by arena id. Most callers should prefer the high-level handle API
/// ([`Node`](super::Node), [`Object`](super::Object), etc.).
///
/// Obtained via [`Mib::raw`](super::mib::Mib::raw).
#[derive(Clone, Copy)]
pub struct RawMib<'a> {
    mib: &'a Mib,
}

impl<'a> RawMib<'a> {
    pub(crate) fn new(mib: &'a Mib) -> Self {
        Self { mib }
    }

    /// Return the underlying OID tree.
    pub fn tree(self) -> &'a OidTree {
        self.mib.tree()
    }

    /// Return the root [`NodeId`].
    pub fn root(self) -> NodeId {
        self.mib.tree().root()
    }

    /// Look up a [`NodeData`] by its [`NodeId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid node in this MIB.
    pub fn node(self, id: NodeId) -> &'a NodeData {
        self.mib.node_data(id)
    }

    /// Look up an [`ObjectData`] by its [`ObjectId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid object in this MIB.
    pub fn object(self, id: ObjectId) -> &'a ObjectData {
        self.mib.object_data(id)
    }

    /// Look up a [`TypeData`] by its [`TypeId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid type in this MIB.
    pub fn type_(self, id: TypeId) -> &'a TypeData {
        self.mib.type_data(id)
    }

    /// Look up a [`NotificationData`] by its [`NotificationId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid notification in this MIB.
    pub fn notification(self, id: NotificationId) -> &'a NotificationData {
        self.mib.notification_data(id)
    }

    /// Look up a [`GroupData`] by its [`GroupId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid group in this MIB.
    pub fn group(self, id: GroupId) -> &'a GroupData {
        self.mib.group_data(id)
    }

    /// Look up a [`ComplianceData`] by its [`ComplianceId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid compliance statement in this MIB.
    pub fn compliance(self, id: ComplianceId) -> &'a ComplianceData {
        self.mib.compliance_data(id)
    }

    /// Look up a [`CapabilityData`] by its [`CapabilityId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid capability statement in this MIB.
    pub fn capability(self, id: CapabilityId) -> &'a CapabilityData {
        self.mib.capability_data(id)
    }

    /// Look up a [`ModuleData`] by its [`ModuleId`].
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid module in this MIB.
    pub fn module(self, id: ModuleId) -> &'a ModuleData {
        self.mib.module_data(id)
    }

    /// Find the node at an exact numeric [`Oid`], if any.
    pub fn node_by_oid(self, oid: &Oid) -> Option<NodeId> {
        let (id, exact) = self.mib.tree().walk_oid(self.mib.tree().root(), oid);
        if exact { Some(id) } else { None }
    }

    /// Find the deepest node matching a prefix of the given [`Oid`].
    ///
    /// Always returns a valid [`NodeId`] (at minimum the root node).
    pub fn longest_prefix_by_oid(self, oid: &Oid) -> NodeId {
        self.mib.tree().longest_prefix(oid)
    }

    /// Direct slice access to the module arena.
    pub fn modules_slice(self) -> &'a [ModuleData] {
        self.mib.modules_slice()
    }

    /// Direct slice access to the object arena.
    pub fn objects_slice(self) -> &'a [ObjectData] {
        self.mib.objects_slice()
    }

    /// Direct slice access to the type arena.
    pub fn types_slice(self) -> &'a [TypeData] {
        self.mib.types_slice()
    }

    /// Direct slice access to the notification arena.
    pub fn notifications_slice(self) -> &'a [NotificationData] {
        self.mib.notifications_slice()
    }

    /// Direct slice access to the group arena.
    pub fn groups_slice(self) -> &'a [GroupData] {
        self.mib.groups_slice()
    }

    /// Direct slice access to the compliance arena.
    pub fn compliances_slice(self) -> &'a [ComplianceData] {
        self.mib.compliances_slice()
    }

    /// Direct slice access to the capability arena.
    pub fn capabilities_slice(self) -> &'a [CapabilityData] {
        self.mib.capabilities_slice()
    }

    /// Return the effective owning module for a node.
    ///
    /// When multiple modules register the same OID, ownership is determined
    /// by the resolver's tiebreaker rules. Entity-backed ownership takes
    /// priority over plain node assignments.
    pub fn effective_module(self, id: NodeId) -> Option<ModuleId> {
        self.mib.effective_module(id)
    }

    /// Resolve a query to the matching [`NodeId`].
    ///
    /// Accepted forms include:
    /// - plain names such as `ifIndex`
    /// - qualified names such as `IF-MIB::ifIndex`
    /// - symbolic instance OIDs such as `ifIndex.5`
    /// - numeric OIDs such as `1.3.6.1.2.1.2.2.1.1.5`
    ///
    /// OID-like queries resolve to the deepest matching node, so instance OIDs
    /// like `ifIndex.5` resolve to the `ifIndex` node.
    pub fn resolve(self, query: &str) -> Option<NodeId> {
        self.mib.resolve(query)
    }
}
