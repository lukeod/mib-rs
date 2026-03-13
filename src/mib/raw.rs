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

    /// Return the root node id.
    pub fn root(self) -> NodeId {
        self.mib.tree().root()
    }

    /// Look up a node by id.
    pub fn node(self, id: NodeId) -> &'a NodeData {
        self.mib.node_data(id)
    }

    /// Look up an object by id.
    pub fn object(self, id: ObjectId) -> &'a ObjectData {
        self.mib.object_data(id)
    }

    /// Look up a type by id.
    pub fn type_(self, id: TypeId) -> &'a TypeData {
        self.mib.type_data(id)
    }

    /// Look up a notification by id.
    pub fn notification(self, id: NotificationId) -> &'a NotificationData {
        self.mib.notification_data(id)
    }

    /// Look up a group by id.
    pub fn group(self, id: GroupId) -> &'a GroupData {
        self.mib.group_data(id)
    }

    /// Look up a compliance statement by id.
    pub fn compliance(self, id: ComplianceId) -> &'a ComplianceData {
        self.mib.compliance_data(id)
    }

    /// Look up a capability statement by id.
    pub fn capability(self, id: CapabilityId) -> &'a CapabilityData {
        self.mib.capability_data(id)
    }

    /// Look up a module by id.
    pub fn module(self, id: ModuleId) -> &'a ModuleData {
        self.mib.module_data(id)
    }

    /// Find the node at an exact numeric OID, if any.
    pub fn node_by_oid(self, oid: &Oid) -> Option<NodeId> {
        let (id, exact) = self.mib.tree().walk_oid(self.mib.tree().root(), oid);
        if exact { Some(id) } else { None }
    }

    /// Find the deepest node matching a prefix of the OID.
    pub fn longest_prefix_by_oid(self, oid: &Oid) -> NodeId {
        self.mib.tree().longest_prefix(oid)
    }
}
