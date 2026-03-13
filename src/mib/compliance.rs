use crate::types::Span;

use super::object::EntityData;
use super::types::*;

/// A MODULE-COMPLIANCE definition.
#[derive(Debug, Clone)]
pub struct ComplianceData {
    pub(crate) entity: EntityData,
    pub(crate) modules: Vec<ComplianceModule>,
}

impl ComplianceData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            entity: EntityData::new(name),
            modules: Vec::new(),
        }
    }

    /// Return the compliance statement name.
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

    /// Return the MODULE clauses.
    pub fn modules(&self) -> &[ComplianceModule] {
        &self.modules
    }
}
