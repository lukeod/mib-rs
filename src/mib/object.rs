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

use crate::source::SourceRange;
use crate::types::{Access, Kind};

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
    pub(crate) range: Option<SourceRange>,
    pub(crate) node: Option<NodeId>,
    pub(crate) module: Option<ModuleId>,
    pub(crate) status: crate::types::Status,
    pub(crate) description: String,
    pub(crate) reference: String,
    pub(crate) status_range: Option<SourceRange>,
    pub(crate) description_range: Option<SourceRange>,
    pub(crate) reference_range: Option<SourceRange>,
    pub(crate) oid_refs: Vec<OidRef>,
}

impl EntityData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            name,
            range: None,
            node: None,
            module: None,
            status: crate::types::Status::Current,
            description: String::new(),
            reference: String::new(),
            status_range: None,
            description_range: None,
            reference_range: None,
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
    pub(crate) declared_kind: Kind,
    pub(crate) typ: Option<TypeId>,
    pub(crate) access: Access,
    pub(crate) units: String,
    pub(crate) def_val: Option<DefVal>,
    pub(crate) augments: Option<ObjectId>,
    pub(crate) augmented_by: Vec<ObjectId>,
    pub(crate) syntax_range: Option<SourceRange>,
    pub(crate) access_range: Option<SourceRange>,
    pub(crate) units_range: Option<SourceRange>,
    pub(crate) augments_range: Option<SourceRange>,
    pub(crate) default_value_range: Option<SourceRange>,
    pub(crate) index: Vec<IndexEntry>,
    pub(crate) hint: String,
    pub(crate) sizes: Vec<Range>,
    pub(crate) ranges: Vec<Range>,
    pub(crate) declared_sizes: Vec<Range>,
    pub(crate) declared_ranges: Vec<Range>,
    pub(crate) sizes_constrained: bool,
    pub(crate) ranges_constrained: bool,
    pub(crate) enums: Vec<NamedValue>,
    pub(crate) bits: Vec<NamedValue>,
    pub(crate) declared_enums: Vec<NamedValue>,
    pub(crate) declared_bits: Vec<NamedValue>,
    pub(crate) sequence_type_name: String,
    pub(crate) declared_table_name: String,
    pub(crate) declared_row_name: String,
    pub(crate) declared_column_names: Vec<String>,
    pub(crate) declared_oid_parent: Option<OidRef>,
    pub(crate) declared_structure_error: String,
}

impl ObjectData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            entity: EntityData::new(name),
            declared_kind: Kind::Unknown,
            typ: None,
            access: Access::NotAccessible,
            units: String::new(),
            def_val: None,
            augments: None,
            augmented_by: Vec::new(),
            syntax_range: None,
            access_range: None,
            units_range: None,
            augments_range: None,
            default_value_range: None,
            index: Vec::new(),
            hint: String::new(),
            sizes: Vec::new(),
            ranges: Vec::new(),
            declared_sizes: Vec::new(),
            declared_ranges: Vec::new(),
            sizes_constrained: false,
            ranges_constrained: false,
            enums: Vec::new(),
            bits: Vec::new(),
            declared_enums: Vec::new(),
            declared_bits: Vec::new(),
            sequence_type_name: String::new(),
            declared_table_name: String::new(),
            declared_row_name: String::new(),
            declared_column_names: Vec::new(),
            declared_oid_parent: None,
            declared_structure_error: String::new(),
        }
    }
}

/// Public accessor methods for [`ObjectData`].
impl ObjectData {
    /// Return the object name.
    pub fn name(&self) -> &str {
        &self.entity.name
    }

    /// Return the source range, if this object came from source text.
    pub fn range(&self) -> Option<SourceRange> {
        self.entity.range
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

    /// Return this module declaration's exact structural kind.
    ///
    /// Unlike [`Self::kind`], this value is independent of which declaration
    /// won a shared-OID collision in the global OID tree.
    pub fn declared_kind(&self) -> Kind {
        self.declared_kind
    }

    /// Return the effective display hint, inherited from the resolved type chain.
    ///
    /// This is pre-computed during resolution, so it does not require
    /// walking the type chain at query time.
    pub fn effective_display_hint(&self) -> &str {
        &self.hint
    }

    /// Return SIZE constraints declared directly on this object.
    #[allow(clippy::misnamed_getters)] // Compatibility alias for declared_sizes().
    pub fn sizes(&self) -> &[Range] {
        &self.declared_sizes
    }

    /// Return SIZE constraints declared directly on this object.
    pub fn declared_sizes(&self) -> &[Range] {
        &self.declared_sizes
    }

    /// Return the effective SIZE constraints, inherited from the resolved type chain.
    pub fn effective_sizes(&self) -> &[Range] {
        &self.sizes
    }

    /// Return whether this object has an effective SIZE constraint.
    ///
    /// A true result with an empty effective constraint slice means the
    /// declared constraints have an empty intersection.
    pub fn effective_sizes_constrained(&self) -> bool {
        self.sizes_constrained
    }

    /// Return value range constraints declared directly on this object.
    #[allow(clippy::misnamed_getters)] // Compatibility alias for declared_ranges().
    pub fn ranges(&self) -> &[Range] {
        &self.declared_ranges
    }

    /// Return value range constraints declared directly on this object.
    pub fn declared_ranges(&self) -> &[Range] {
        &self.declared_ranges
    }

    /// Return the effective range constraints, inherited from the resolved type chain.
    pub fn effective_ranges(&self) -> &[Range] {
        &self.ranges
    }

    /// Return whether this object has an effective value range constraint.
    ///
    /// A true result with an empty effective constraint slice means the
    /// declared constraints have an empty intersection.
    pub fn effective_ranges_constrained(&self) -> bool {
        self.ranges_constrained
    }

    /// Return the effective enumeration values, inherited from the resolved type chain.
    pub fn effective_enums(&self) -> &[NamedValue] {
        &self.enums
    }

    /// Return the effective BITS definitions, inherited from the resolved type chain.
    pub fn effective_bits(&self) -> &[NamedValue] {
        &self.bits
    }

    /// Return enumeration values declared directly in this object's syntax.
    pub fn declared_enums(&self) -> &[NamedValue] {
        &self.declared_enums
    }

    /// Return BITS values declared directly in this object's syntax.
    pub fn declared_bits(&self) -> &[NamedValue] {
        &self.declared_bits
    }

    /// Return the SEQUENCE type name from the table definition.
    pub fn sequence_type_name(&self) -> &str {
        &self.sequence_type_name
    }

    /// Return the exact table declaration associated with this row.
    pub fn declared_table_name(&self) -> &str {
        &self.declared_table_name
    }

    /// Return the exact row declaration associated with this table.
    pub fn declared_row_name(&self) -> &str {
        &self.declared_row_name
    }

    /// Return the exact column declarations associated with this row.
    pub fn declared_column_names(&self) -> &[String] {
        &self.declared_column_names
    }

    /// Return the exact symbolic OID parent used by this declaration.
    pub fn declared_oid_parent(&self) -> Option<&OidRef> {
        self.declared_oid_parent.as_ref()
    }

    /// Return the exact symbolic OID parent name, or an empty string when the
    /// assignment used no exact symbolic parent.
    pub fn declared_oid_parent_name(&self) -> &str {
        self.declared_oid_parent
            .as_ref()
            .map_or("", |reference| reference.name.as_str())
    }

    pub(crate) fn declared_structure_error(&self) -> &str {
        &self.declared_structure_error
    }

    /// Return the INDEX clause entries.
    pub fn index(&self) -> &[IndexEntry] {
        &self.index
    }

    /// Return the source range of the SYNTAX clause, if present.
    pub fn syntax_range(&self) -> Option<SourceRange> {
        self.syntax_range
    }

    /// Return the source range of the ACCESS/MAX-ACCESS clause, if present.
    pub fn access_range(&self) -> Option<SourceRange> {
        self.access_range
    }

    /// Return the source range of the UNITS clause, if present.
    pub fn units_range(&self) -> Option<SourceRange> {
        self.units_range
    }

    /// Return the source range of the AUGMENTS clause, if present.
    pub fn augments_range(&self) -> Option<SourceRange> {
        self.augments_range
    }

    /// Return the source range of the DEFVAL clause, if present.
    pub fn default_value_range(&self) -> Option<SourceRange> {
        self.default_value_range
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
