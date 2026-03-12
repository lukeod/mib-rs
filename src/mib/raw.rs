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

#[derive(Clone, Copy)]
pub struct RawMib<'a> {
    mib: &'a Mib,
}

impl<'a> RawMib<'a> {
    pub(crate) fn new(mib: &'a Mib) -> Self {
        Self { mib }
    }

    pub fn tree(self) -> &'a OidTree {
        self.mib.tree()
    }

    pub fn root(self) -> NodeId {
        self.mib.tree().root()
    }

    pub fn node(self, id: NodeId) -> &'a NodeData {
        self.mib.node_data(id)
    }

    pub fn object(self, id: ObjectId) -> &'a ObjectData {
        self.mib.object_data(id)
    }

    pub fn type_(self, id: TypeId) -> &'a TypeData {
        self.mib.type_data(id)
    }

    pub fn notification(self, id: NotificationId) -> &'a NotificationData {
        self.mib.notification_data(id)
    }

    pub fn group(self, id: GroupId) -> &'a GroupData {
        self.mib.group_data(id)
    }

    pub fn compliance(self, id: ComplianceId) -> &'a ComplianceData {
        self.mib.compliance_data(id)
    }

    pub fn capability(self, id: CapabilityId) -> &'a CapabilityData {
        self.mib.capability_data(id)
    }

    pub fn module(self, id: ModuleId) -> &'a ModuleData {
        self.mib.module_data(id)
    }

    pub fn node_by_oid(self, oid: &Oid) -> Option<NodeId> {
        let (id, exact) = self.mib.tree().walk_oid(self.mib.tree().root(), oid);
        if exact { Some(id) } else { None }
    }

    pub fn longest_prefix_by_oid(self, oid: &Oid) -> NodeId {
        self.mib.tree().longest_prefix(oid)
    }
}
