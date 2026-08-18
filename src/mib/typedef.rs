//! Type definitions and TEXTUAL-CONVENTIONs.
//!
//! [`TypeData`] represents a named type definition from an SMI module. Types
//! form parent chains via [`TypeData::parent`]; the chain terminates at a
//! base SMI type such as `INTEGER` or `OCTET STRING`.
//!
//! The `effective_*` constraint methods return constraints intersected across
//! the parent chain. Other effective values use the nearest non-empty value.
//! These require a reference to the full type arena (`&[TypeData]`).
//!
//! For handle-oriented access with automatic arena threading, see
//! [`Type`](super::handle::Type).

use crate::source::SourceRange;
use crate::types::{BaseType, Status};

use super::types::*;

const MAX_TYPE_CHAIN_DEPTH: usize = 1000;

/// A named type definition, either a TEXTUAL-CONVENTION or an inline type
/// refinement.
///
/// Types form parent chains via [`TypeData::parent`]; the chain terminates at
/// a base SMI type. Effective SIZE and range constraints are intersected
/// across this chain; other effective values use the first non-empty value.
/// Access through [`TypeData`] methods or the [`Type`](super::handle::Type)
/// handle.
#[derive(Debug, Clone)]
pub struct TypeData {
    pub(crate) name: String,
    pub(crate) range: Option<SourceRange>,
    pub(crate) syntax_range: Option<SourceRange>,
    pub(crate) module: Option<ModuleId>,
    pub(crate) base: BaseType,
    pub(crate) parent: Option<TypeId>,
    pub(crate) status: Status,
    pub(crate) hint: String,
    pub(crate) description: String,
    pub(crate) reference: String,
    pub(crate) sizes: Vec<Range>,
    pub(crate) ranges: Vec<Range>,
    pub(crate) effective_sizes: Vec<Range>,
    pub(crate) effective_ranges: Vec<Range>,
    pub(crate) effective_sizes_constrained: bool,
    pub(crate) effective_ranges_constrained: bool,
    pub(crate) enums: Vec<NamedValue>,
    pub(crate) bits: Vec<NamedValue>,
    pub(crate) is_tc: bool,
}

impl TypeData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            name,
            range: None,
            syntax_range: None,
            module: None,
            base: BaseType::Unknown,
            parent: None,
            status: Status::Current,
            hint: String::new(),
            description: String::new(),
            reference: String::new(),
            sizes: Vec::new(),
            ranges: Vec::new(),
            effective_sizes: Vec::new(),
            effective_ranges: Vec::new(),
            effective_sizes_constrained: false,
            effective_ranges_constrained: false,
            enums: Vec::new(),
            bits: Vec::new(),
            is_tc: false,
        }
    }
}

impl TypeData {
    /// Return the type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the source range, if this type came from source text.
    pub fn range(&self) -> Option<SourceRange> {
        self.range
    }

    /// Return the source range of the SYNTAX clause, if present.
    pub fn syntax_range(&self) -> Option<SourceRange> {
        self.syntax_range
    }

    /// Return the defining module id.
    pub fn module(&self) -> Option<ModuleId> {
        self.module
    }

    /// Return the directly assigned base type.
    pub fn base(&self) -> BaseType {
        self.base
    }

    /// Return the parent type id, if this is a derived type.
    pub fn parent(&self) -> Option<TypeId> {
        self.parent
    }

    /// Return the status (current, deprecated, obsolete).
    pub fn status(&self) -> Status {
        self.status
    }

    /// Return this type's own DISPLAY-HINT string.
    pub fn display_hint(&self) -> &str {
        &self.hint
    }

    /// Return the DESCRIPTION clause text.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Return the REFERENCE clause text.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Return this type's own SIZE constraints.
    pub fn sizes(&self) -> &[Range] {
        &self.sizes
    }

    /// Return this type's own range constraints.
    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    /// Return this type's own enumeration values.
    pub fn enums(&self) -> &[NamedValue] {
        &self.enums
    }

    /// Return this type's own BITS definitions.
    pub fn bits(&self) -> &[NamedValue] {
        &self.bits
    }

    /// Return `true` if defined as a TEXTUAL-CONVENTION.
    pub fn is_textual_convention(&self) -> bool {
        self.is_tc
    }

    /// Look up an enumeration value by label.
    pub fn enum_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.enums, label)
    }

    /// Look up a BITS value by label.
    pub fn bit_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.bits, label)
    }
}

/// Methods that walk the parent type chain.
///
/// These require a reference to the full type arena (`&[TypeData]`).
/// Callers using the [`Type`](super::handle::Type) handle do not need to
/// pass the arena; the handle threads it automatically.
impl TypeData {
    /// Walk the parent type chain (starting from `self.parent`) and return
    /// the [`TypeId`] of the first type that is a TEXTUAL-CONVENTION, or
    /// `None` if none in the chain is a TC.
    ///
    /// Does **not** check `self` - the caller is responsible for checking
    /// the starting type when it has the id available (see
    /// [`Type::effective_tc`](super::handle::Type::effective_tc)).
    pub(crate) fn effective_tc_in_parents(&self, types: &[TypeData]) -> Option<TypeId> {
        let mut current_id = self.parent;
        let mut depth = 1;
        while let Some(id) = current_id {
            if depth >= MAX_TYPE_CHAIN_DEPTH {
                break;
            }
            let t = &types[id.0 as usize];
            if t.is_tc {
                return Some(id);
            }
            current_id = t.parent;
            depth += 1;
        }
        None
    }

    /// Walk the parent type chain and return the first non-[`Unknown`](BaseType::Unknown)
    /// base type.
    pub fn effective_base(&self, types: &[TypeData]) -> BaseType {
        walk_type_chain_ref(self, types, |t| {
            if t.base != BaseType::Unknown {
                Some(&t.base)
            } else {
                None
            }
        })
        .copied()
        .unwrap_or(BaseType::Unknown)
    }

    /// Walk the parent type chain and return the first non-empty display hint.
    pub fn effective_display_hint<'a>(&'a self, types: &'a [TypeData]) -> &'a str {
        walk_type_chain_ref(self, types, |t| {
            if t.hint.is_empty() {
                None
            } else {
                Some(t.hint.as_str())
            }
        })
        .unwrap_or("")
    }

    /// Return SIZE constraints intersected across the resolved parent chain.
    ///
    /// An empty slice means either that no SIZE constraint exists or that the
    /// declared constraints have an empty intersection. Use
    /// [`Self::effective_sizes_constrained`] to distinguish those cases.
    pub fn effective_sizes<'a>(&'a self, _types: &'a [TypeData]) -> &'a [Range] {
        &self.effective_sizes
    }

    /// Return whether an effective SIZE constraint was explicitly declared.
    pub fn effective_sizes_constrained(&self) -> bool {
        self.effective_sizes_constrained
    }

    /// Return value ranges intersected across the resolved parent chain.
    ///
    /// An empty slice means either that no range constraint exists or that the
    /// declared constraints have an empty intersection. Use
    /// [`Self::effective_ranges_constrained`] to distinguish those cases.
    pub fn effective_ranges<'a>(&'a self, _types: &'a [TypeData]) -> &'a [Range] {
        &self.effective_ranges
    }

    /// Return whether an effective value range constraint was explicitly declared.
    pub fn effective_ranges_constrained(&self) -> bool {
        self.effective_ranges_constrained
    }

    /// Walk the parent type chain and return the first non-empty enumeration values.
    pub fn effective_enums<'a>(&'a self, types: &'a [TypeData]) -> &'a [NamedValue] {
        self.effective_slice(types, |t| &t.enums)
    }

    /// Walk the parent type chain and return the first non-empty BITS definitions.
    pub fn effective_bits<'a>(&'a self, types: &'a [TypeData]) -> &'a [NamedValue] {
        self.effective_slice(types, |t| &t.bits)
    }

    /// Walk the parent type chain, returning the first non-empty slice from `get`.
    fn effective_slice<'a, T>(
        &'a self,
        types: &'a [TypeData],
        get: impl Fn(&'a TypeData) -> &'a [T],
    ) -> &'a [T] {
        walk_type_chain_ref(self, types, |t| {
            let s = get(t);
            if s.is_empty() { None } else { Some(s) }
        })
        .unwrap_or(&[])
    }

    /// Return `true` if the effective base type is Counter32 or Counter64.
    pub fn is_counter(&self, types: &[TypeData]) -> bool {
        let b = self.effective_base(types);
        b == BaseType::Counter32 || b == BaseType::Counter64
    }

    /// Return `true` if the effective base type is Gauge32.
    pub fn is_gauge(&self, types: &[TypeData]) -> bool {
        self.effective_base(types) == BaseType::Gauge32
    }

    /// Return `true` if the effective base type is OCTET STRING.
    pub fn is_string(&self, types: &[TypeData]) -> bool {
        self.effective_base(types) == BaseType::OctetString
    }

    /// Return `true` if this is an Integer32 with enumeration values.
    pub fn is_enumeration(&self, types: &[TypeData]) -> bool {
        self.effective_base(types) == BaseType::Integer32
            && walk_type_chain_has_slice(self, types, |t| &t.enums)
    }

    /// Return `true` if this type has BITS definitions in the chain.
    pub fn is_bits(&self, types: &[TypeData]) -> bool {
        walk_type_chain_has_slice(self, types, |t| &t.bits)
    }
}

/// Walk the type chain, returning the first Some reference from `get`.
fn walk_type_chain_ref<'a, T: ?Sized>(
    start: &'a TypeData,
    types: &'a [TypeData],
    get: impl Fn(&'a TypeData) -> Option<&'a T>,
) -> Option<&'a T> {
    if let Some(v) = get(start) {
        return Some(v);
    }
    let mut current_id = start.parent;
    let mut depth = 1;
    while let Some(id) = current_id {
        if depth >= MAX_TYPE_CHAIN_DEPTH {
            break;
        }
        let t = &types[id.0 as usize];
        if let Some(v) = get(t) {
            return Some(v);
        }
        current_id = t.parent;
        depth += 1;
    }
    None
}

/// Walk the type chain and report whether any type has a non-empty slice.
fn walk_type_chain_has_slice(
    start: &TypeData,
    types: &[TypeData],
    get: impl Fn(&TypeData) -> &[NamedValue],
) -> bool {
    walk_type_chain_ref(start, types, |t| {
        let s = get(t);
        if s.is_empty() { None } else { Some(s) }
    })
    .is_some()
}
