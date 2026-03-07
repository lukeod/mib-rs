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

    pub fn name(&self) -> &str {
        &self.entity.name
    }

    pub fn span(&self) -> Span {
        self.entity.span
    }

    pub fn node(&self) -> Option<NodeId> {
        self.entity.node
    }

    pub fn module(&self) -> Option<ModuleId> {
        self.entity.module
    }

    pub fn status(&self) -> crate::types::Status {
        self.entity.status
    }

    pub fn description(&self) -> &str {
        &self.entity.description
    }

    pub fn reference(&self) -> &str {
        &self.entity.reference
    }

    pub fn oid_refs(&self) -> &[OidRef] {
        &self.entity.oid_refs
    }

    pub fn objects(&self) -> &[ObjectId] {
        &self.objects
    }

    pub fn trap_info(&self) -> Option<&TrapInfo> {
        self.trap_info.as_ref()
    }
}
