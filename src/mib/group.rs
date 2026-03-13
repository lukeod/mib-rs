use crate::types::Span;

use super::object::EntityData;
use super::types::*;

/// An OBJECT-GROUP or NOTIFICATION-GROUP definition.
#[derive(Debug, Clone)]
pub struct GroupData {
    pub(crate) entity: EntityData,
    pub(crate) members: Vec<NodeId>,
    pub(crate) is_notification_group: bool,
}

impl GroupData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            entity: EntityData::new(name),
            members: Vec::new(),
            is_notification_group: false,
        }
    }

    /// Return the group name.
    pub fn name(&self) -> &str {
        &self.entity.name
    }

    /// Return the source span.
    pub fn span(&self) -> Span {
        self.entity.span
    }

    /// Return the OID tree node id, if resolved.
    pub fn node(&self) -> Option<NodeId> {
        self.entity.node
    }

    /// Return the defining module id.
    pub fn module(&self) -> Option<ModuleId> {
        self.entity.module
    }

    /// Return the status.
    pub fn status(&self) -> crate::types::Status {
        self.entity.status
    }

    /// Return the DESCRIPTION clause text.
    pub fn description(&self) -> &str {
        &self.entity.description
    }

    /// Return the REFERENCE clause text.
    pub fn reference(&self) -> &str {
        &self.entity.reference
    }

    /// Return symbolic OID references.
    pub fn oid_refs(&self) -> &[OidRef] {
        &self.entity.oid_refs
    }

    /// Return the member node ids.
    pub fn members(&self) -> &[NodeId] {
        &self.members
    }

    /// Return `true` if this is a NOTIFICATION-GROUP.
    pub fn is_notification_group(&self) -> bool {
        self.is_notification_group
    }
}
