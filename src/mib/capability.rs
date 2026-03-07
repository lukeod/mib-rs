use crate::types::Span;

use super::object::EntityData;
use super::types::*;

/// An AGENT-CAPABILITIES definition.
#[derive(Debug, Clone)]
pub struct CapabilityData {
    pub(crate) entity: EntityData,
    pub(crate) product_release: String,
    pub(crate) supports: Vec<CapabilitiesModule>,
}

impl CapabilityData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            entity: EntityData::new(name),
            product_release: String::new(),
            supports: Vec::new(),
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

    pub fn product_release(&self) -> &str {
        &self.product_release
    }

    pub fn supports(&self) -> &[CapabilitiesModule] {
        &self.supports
    }
}
