//! OBJECT-TYPE definitions and the shared entity base type.
//!
//! [`ObjectData`] holds all fields from an SMIv1 or SMIv2 OBJECT-TYPE
//! definition, including the resolved type, access level, INDEX clause,
//! DEFVAL, and effective (inherited) constraint values computed during
//! resolution.
//!
//! [`EntityData`] is the shared base for all OID-bearing entity types
//! (objects, notifications, groups, compliances, capabilities).
//!
//! For handle-oriented access, see [`Object`](super::handle::Object).

use crate::types::{Access, Kind, Span};

use super::types::*;

/// Common fields shared by all OID-bearing entity definitions.
///
/// Embedded in [`ObjectData`], [`NotificationData`](super::notification::NotificationData),
/// [`GroupData`](super::group::GroupData), [`ComplianceData`](super::compliance::ComplianceData),
/// and [`CapabilityData`](super::capability::CapabilityData). Not accessed
/// directly by callers; each containing type re-exposes the relevant fields
/// through its own accessor methods.
#[derive(Debug, Clone)]
pub struct EntityData {
    pub(crate) name: String,
    pub(crate) span: Span,
    pub(crate) node: Option<NodeId>,
    pub(crate) module: Option<ModuleId>,
    pub(crate) status: crate::types::Status,
    pub(crate) description: String,
    pub(crate) reference: String,
    pub(crate) status_span: Span,
    pub(crate) desc_span: Span,
    pub(crate) ref_span: Span,
    pub(crate) oid_refs: Vec<OidRef>,
}

impl EntityData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            name,
            span: Span::SYNTHETIC,
            node: None,
            module: None,
            status: crate::types::Status::Current,
            description: String::new(),
            reference: String::new(),
            status_span: Span::SYNTHETIC,
            desc_span: Span::SYNTHETIC,
            ref_span: Span::SYNTHETIC,
            oid_refs: Vec::new(),
        }
    }
}

/// An OBJECT-TYPE definition from an SMIv1 or SMIv2 module.
///
/// Contains both the raw definition fields and effective (inherited) values
/// computed during resolution. Access through [`ObjectData`] methods or the
/// [`Object`](super::handle::Object) handle type.
#[derive(Debug, Clone)]
pub struct ObjectData {
    pub(crate) entity: EntityData,
    pub(crate) typ: Option<TypeId>,
    pub(crate) access: Access,
    pub(crate) units: String,
    pub(crate) def_val: Option<DefVal>,
    pub(crate) augments: Option<ObjectId>,
    pub(crate) augmented_by: Vec<ObjectId>,
    pub(crate) syntax_span: Span,
    pub(crate) access_span: Span,
    pub(crate) units_span: Span,
    pub(crate) augments_span: Span,
    pub(crate) def_val_span: Span,
    pub(crate) index: Vec<IndexEntry>,
    pub(crate) hint: String,
    pub(crate) sizes: Vec<Range>,
    pub(crate) ranges: Vec<Range>,
    pub(crate) enums: Vec<NamedValue>,
    pub(crate) bits: Vec<NamedValue>,
    pub(crate) sequence_type_name: String,
}

impl ObjectData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            entity: EntityData::new(name),
            typ: None,
            access: Access::NotAccessible,
            units: String::new(),
            def_val: None,
            augments: None,
            augmented_by: Vec::new(),
            syntax_span: Span::SYNTHETIC,
            access_span: Span::SYNTHETIC,
            units_span: Span::SYNTHETIC,
            augments_span: Span::SYNTHETIC,
            def_val_span: Span::SYNTHETIC,
            index: Vec::new(),
            hint: String::new(),
            sizes: Vec::new(),
            ranges: Vec::new(),
            enums: Vec::new(),
            bits: Vec::new(),
            sequence_type_name: String::new(),
        }
    }
}

/// Public accessor methods for [`ObjectData`].
impl ObjectData {
    /// Return the object name.
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

    /// Return the status (current, deprecated, obsolete).
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

    /// Return symbolic OID references from the definition.
    pub fn oid_refs(&self) -> &[OidRef] {
        &self.entity.oid_refs
    }

    /// Return the resolved type id, if any.
    pub fn type_id(&self) -> Option<TypeId> {
        self.typ
    }

    /// Return the access level.
    pub fn access(&self) -> Access {
        self.access
    }

    /// Return the UNITS clause text.
    pub fn units(&self) -> &str {
        &self.units
    }

    /// Return the DEFVAL clause, if present.
    pub fn default_value(&self) -> Option<&DefVal> {
        self.def_val.as_ref()
    }

    /// Return the AUGMENTS target row id, if this row augments another.
    pub fn augments(&self) -> Option<ObjectId> {
        self.augments
    }

    /// Return rows that augment this row.
    pub fn augmented_by(&self) -> &[ObjectId] {
        &self.augmented_by
    }

    /// Return the node [`Kind`] by looking up the [`OidTree`](super::node::OidTree).
    ///
    /// Returns [`Kind::Unknown`] if the object's OID was not resolved.
    /// Callers using the [`Object`](super::handle::Object) handle do not need
    /// this method; use [`Object::kind`](super::handle::Object::kind) instead.
    pub fn kind(&self, tree: &super::node::OidTree) -> Kind {
        match self.entity.node {
            Some(id) => tree.get(id).kind,
            None => Kind::Unknown,
        }
    }

    /// Return the effective display hint, inherited from the resolved type chain.
    ///
    /// This is pre-computed during resolution, so it does not require
    /// walking the type chain at query time.
    pub fn effective_display_hint(&self) -> &str {
        &self.hint
    }

    /// Return the effective SIZE constraints, inherited from the resolved type chain.
    pub fn effective_sizes(&self) -> &[Range] {
        &self.sizes
    }

    /// Return the effective range constraints, inherited from the resolved type chain.
    pub fn effective_ranges(&self) -> &[Range] {
        &self.ranges
    }

    /// Return the effective enumeration values, inherited from the resolved type chain.
    pub fn effective_enums(&self) -> &[NamedValue] {
        &self.enums
    }

    /// Return the effective BITS definitions, inherited from the resolved type chain.
    pub fn effective_bits(&self) -> &[NamedValue] {
        &self.bits
    }

    /// Return the SEQUENCE type name from the table definition.
    pub fn sequence_type_name(&self) -> &str {
        &self.sequence_type_name
    }

    /// Return the INDEX clause entries.
    pub fn index(&self) -> &[IndexEntry] {
        &self.index
    }

    /// Return the source span of the SYNTAX clause.
    pub fn syntax_span(&self) -> Span {
        self.syntax_span
    }

    /// Return the source span of the ACCESS/MAX-ACCESS clause.
    pub fn access_span(&self) -> Span {
        self.access_span
    }

    /// Return the source span of the UNITS clause.
    pub fn units_span(&self) -> Span {
        self.units_span
    }

    /// Return the source span of the AUGMENTS clause.
    pub fn augments_span(&self) -> Span {
        self.augments_span
    }

    /// Return the source span of the DEFVAL clause.
    pub fn default_value_span(&self) -> Span {
        self.def_val_span
    }

    /// Look up an enumeration value by label name.
    pub fn enum_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.enums, label)
    }

    /// Look up a BITS value by label name.
    pub fn bit_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.bits, label)
    }
}
