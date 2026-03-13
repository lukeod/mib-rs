//! AGENT-CAPABILITIES definitions.
//!
//! [`CapabilityData`] holds the PRODUCT-RELEASE string and SUPPORTS clauses
//! from an AGENT-CAPABILITIES statement.
//!
//! For handle-oriented access, see [`Capability`](super::handle::Capability).

use crate::types::Span;

use super::object::EntityData;
use super::types::*;

/// An AGENT-CAPABILITIES definition.
///
/// Holds the PRODUCT-RELEASE string and a list of [`CapabilitiesModule`]
/// SUPPORTS clauses describing which module groups and object variations
/// an agent implements.
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

    /// Return the PRODUCT-RELEASE string from the definition.
    pub fn product_release(&self) -> &str {
        &self.product_release
    }

    /// Return the [`CapabilitiesModule`] SUPPORTS clauses.
    pub fn supports(&self) -> &[CapabilitiesModule] {
        &self.supports
    }
}
