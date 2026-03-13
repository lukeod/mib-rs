use crate::types::Span;

use super::object::EntityData;
use super::types::*;

/// A NOTIFICATION-TYPE or TRAP-TYPE definition.
#[derive(Debug, Clone)]
pub struct NotificationData {
    pub(crate) entity: EntityData,
    pub(crate) objects: Vec<ObjectId>,
    pub(crate) trap_info: Option<TrapInfo>,
}

impl NotificationData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            entity: EntityData::new(name),
            objects: Vec::new(),
            trap_info: None,
        }
    }

    /// Return the notification name.
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

    /// Return the OBJECTS clause entries (object ids).
    pub fn objects(&self) -> &[ObjectId] {
        &self.objects
    }

    /// Return SMIv1 TRAP-TYPE fields, if this is a trap.
    pub fn trap_info(&self) -> Option<&TrapInfo> {
        self.trap_info.as_ref()
    }
}
