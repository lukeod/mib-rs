use crate::types::{BaseType, Span, Status};

use super::types::*;

const MAX_TYPE_CHAIN_DEPTH: usize = 1000;

/// A named type definition, either a TEXTUAL-CONVENTION or an inline type
/// refinement. Types form chains via parent; the chain terminates at a base
/// SMI type.
#[derive(Debug, Clone)]
pub struct TypeData {
    pub(crate) name: String,
    pub(crate) span: Span,
    pub(crate) syntax_span: Span,
    pub(crate) module: Option<ModuleId>,
    pub(crate) base: BaseType,
    pub(crate) parent: Option<TypeId>,
    pub(crate) status: Status,
    pub(crate) hint: String,
    pub(crate) description: String,
    pub(crate) reference: String,
    pub(crate) sizes: Vec<Range>,
    pub(crate) ranges: Vec<Range>,
    pub(crate) enums: Vec<NamedValue>,
    pub(crate) bits: Vec<NamedValue>,
    pub(crate) is_tc: bool,
}

impl TypeData {
    pub(crate) fn new(name: String) -> Self {
        Self {
            name,
            span: Span::SYNTHETIC,
            syntax_span: Span::SYNTHETIC,
            module: None,
            base: BaseType::Unknown,
            parent: None,
            status: Status::Current,
            hint: String::new(),
            description: String::new(),
            reference: String::new(),
            sizes: Vec::new(),
            ranges: Vec::new(),
            enums: Vec::new(),
            bits: Vec::new(),
            is_tc: false,
        }
    }
}

impl TypeData {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn syntax_span(&self) -> Span {
        self.syntax_span
    }

    pub fn module(&self) -> Option<ModuleId> {
        self.module
    }

    pub fn base(&self) -> BaseType {
        self.base
    }

    pub fn parent(&self) -> Option<TypeId> {
        self.parent
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn display_hint(&self) -> &str {
        &self.hint
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn sizes(&self) -> &[Range] {
        &self.sizes
    }

    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    pub fn enums(&self) -> &[NamedValue] {
        &self.enums
    }

    pub fn bits(&self) -> &[NamedValue] {
        &self.bits
    }

    pub fn is_textual_convention(&self) -> bool {
        self.is_tc
    }

    pub fn enum_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.enums, label)
    }

    pub fn bit_by_label(&self, label: &str) -> Option<&NamedValue> {
        find_named_value(&self.bits, label)
    }
}

/// Methods that walk the type chain. These require access to the type arena.
impl TypeData {
    /// Walk the parent type chain and return the first non-default base type.
    pub fn effective_base(&self, types: &[TypeData]) -> BaseType {
        walk_type_chain(self, types, |t| {
            if t.base != BaseType::Unknown {
                Some(t.base)
            } else {
                None
            }
        })
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

    /// Walk the parent type chain and return the first non-empty size constraints.
    pub fn effective_sizes<'a>(&'a self, types: &'a [TypeData]) -> &'a [Range] {
        walk_type_chain_ref(self, types, |t| {
            if t.sizes.is_empty() {
                None
            } else {
                Some(t.sizes.as_slice())
            }
        })
        .unwrap_or(&[])
    }

    /// Walk the parent type chain and return the first non-empty range constraints.
    pub fn effective_ranges<'a>(&'a self, types: &'a [TypeData]) -> &'a [Range] {
        walk_type_chain_ref(self, types, |t| {
            if t.ranges.is_empty() {
                None
            } else {
                Some(t.ranges.as_slice())
            }
        })
        .unwrap_or(&[])
    }

    /// Walk the parent type chain and return the first non-empty enumeration values.
    pub fn effective_enums<'a>(&'a self, types: &'a [TypeData]) -> &'a [NamedValue] {
        walk_type_chain_ref(self, types, |t| {
            if t.enums.is_empty() {
                None
            } else {
                Some(t.enums.as_slice())
            }
        })
        .unwrap_or(&[])
    }

    /// Walk the parent type chain and return the first non-empty BITS definitions.
    pub fn effective_bits<'a>(&'a self, types: &'a [TypeData]) -> &'a [NamedValue] {
        walk_type_chain_ref(self, types, |t| {
            if t.bits.is_empty() {
                None
            } else {
                Some(t.bits.as_slice())
            }
        })
        .unwrap_or(&[])
    }

    pub fn is_counter(&self, types: &[TypeData]) -> bool {
        let b = self.effective_base(types);
        b == BaseType::Counter32 || b == BaseType::Counter64
    }

    pub fn is_gauge(&self, types: &[TypeData]) -> bool {
        self.effective_base(types) == BaseType::Gauge32
    }

    pub fn is_string(&self, types: &[TypeData]) -> bool {
        self.effective_base(types) == BaseType::OctetString
    }

    pub fn is_enumeration(&self, types: &[TypeData]) -> bool {
        self.effective_base(types) == BaseType::Integer32
            && walk_type_chain_has_slice(self, types, |t| &t.enums)
    }

    pub fn is_bits(&self, types: &[TypeData]) -> bool {
        walk_type_chain_has_slice(self, types, |t| &t.bits)
    }
}

/// Walk the type chain, returning the first Some value from `get`.
fn walk_type_chain<T>(
    start: &TypeData,
    types: &[TypeData],
    get: impl Fn(&TypeData) -> Option<T>,
) -> Option<T> {
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
    if !get(start).is_empty() {
        return true;
    }
    let mut current_id = start.parent;
    let mut depth = 1;
    while let Some(id) = current_id {
        if depth >= MAX_TYPE_CHAIN_DEPTH {
            break;
        }
        let t = &types[id.0 as usize];
        if !get(t).is_empty() {
            return true;
        }
        current_id = t.parent;
        depth += 1;
    }
    false
}
