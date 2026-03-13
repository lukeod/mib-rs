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

    /// Return the capabilities statement name.
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

    /// Return the PRODUCT-RELEASE string.
    pub fn product_release(&self) -> &str {
        &self.product_release
    }

    /// Return the SUPPORTS clauses.
    pub fn supports(&self) -> &[CapabilitiesModule] {
        &self.supports
    }
}
