//! MODULE-COMPLIANCE definitions.
//!
//! [`ComplianceData`] holds the MODULE clauses from a MODULE-COMPLIANCE
//! statement, each specifying mandatory groups and optional object refinements.
//!
//! For handle-oriented access, see [`Compliance`](super::handle::Compliance).

use crate::source::SourceRange;

use super::object::EntityData;
use super::types::*;

/// A MODULE-COMPLIANCE definition.
///
/// Contains one or more [`ComplianceModule`] clauses, each specifying
/// mandatory groups and optional object refinements for a target module.
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

    /// Return the source range, if this compliance came from source text.
    pub fn range(&self) -> Option<SourceRange> {
        self.entity.range
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

    /// Return the [`ComplianceModule`] clauses.
    pub fn modules(&self) -> &[ComplianceModule] {
        &self.modules
    }
}
