use crate::types::{Access, Kind, Span};

use super::types::*;

/// Common fields for all OID-bearing entity definitions.
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

/// Accessor methods for ObjectData, used through the Mib.
impl ObjectData {
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

    pub fn type_id(&self) -> Option<TypeId> {
        self.typ
    }

    pub fn access(&self) -> Access {
        self.access
    }

    pub fn units(&self) -> &str {
        &self.units
    }

    pub fn default_value(&self) -> Option<&DefVal> {
        self.def_val.as_ref()
    }

    pub fn augments(&self) -> Option<ObjectId> {
        self.augments
    }

    pub fn augmented_by(&self) -> &[ObjectId] {
        &self.augmented_by
    }

    pub fn kind(&self, tree: &super::node::OidTree) -> Kind {
        match self.entity.node {
            Some(id) => tree.get(id).kind,
            None => Kind::Unknown,
        }
    }

    pub fn effective_display_hint(&self) -> &str {
        &self.hint
    }

    pub fn effective_sizes(&self) -> &[Range] {
        &self.sizes
    }

    pub fn effective_ranges(&self) -> &[Range] {
        &self.ranges
    }

    pub fn effective_enums(&self) -> &[NamedValue] {
        &self.enums
    }

    pub fn effective_bits(&self) -> &[NamedValue] {
        &self.bits
    }

    pub fn sequence_type_name(&self) -> &str {
        &self.sequence_type_name
    }

    pub fn index(&self) -> &[IndexEntry] {
        &self.index
    }

    pub fn syntax_span(&self) -> Span {
        self.syntax_span
    }

    pub fn access_span(&self) -> Span {
        self.access_span
    }

    pub fn units_span(&self) -> Span {
        self.units_span
    }

    pub fn augments_span(&self) -> Span {
        self.augments_span
    }

    pub fn default_value_span(&self) -> Span {
        self.def_val_span
    }

    pub fn enum_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.enums, label)
    }

    pub fn bit_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.bits, label)
    }
}
