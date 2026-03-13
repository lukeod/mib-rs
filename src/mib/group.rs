//! OBJECT-GROUP and NOTIFICATION-GROUP definitions.
//!
//! [`GroupData`] holds the member list and a flag distinguishing
//! OBJECT-GROUPs from NOTIFICATION-GROUPs.
//!
//! For handle-oriented access, see [`Group`](super::handle::Group).

use crate::types::Span;

use super::object::EntityData;
use super::types::*;

/// An OBJECT-GROUP or NOTIFICATION-GROUP definition.
///
/// Use [`is_notification_group`](Self::is_notification_group) to distinguish
/// NOTIFICATION-GROUPs from OBJECT-GROUPs.
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

    /// Return the OID tree [`NodeId`], if resolved.
    pub fn node(&self) -> Option<NodeId> {
        self.entity.node
    }

    /// Return the defining [`ModuleId`].
    pub fn module(&self) -> Option<ModuleId> {
        self.entity.module
    }

    /// Return the [`Status`](crate::types::Status).
    pub fn status(&self) -> crate::types::Status {
        self.entity.status
    }

    /// Return the DESCRIPTION clause text, or an empty string if absent.
    pub fn description(&self) -> &str {
        &self.entity.description
    }

    /// Return the REFERENCE clause text, or an empty string if absent.
    pub fn reference(&self) -> &str {
        &self.entity.reference
    }

    /// Return the symbolic OID references from the value assignment.
    pub fn oid_refs(&self) -> &[OidRef] {
        &self.entity.oid_refs
    }

    /// Return the member [`NodeId`]s.
    pub fn members(&self) -> &[NodeId] {
        &self.members
    }

    /// Return `true` if this is a NOTIFICATION-GROUP.
    pub fn is_notification_group(&self) -> bool {
        self.is_notification_group
    }
}
