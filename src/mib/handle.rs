//! Lightweight borrowed handles for navigating the resolved MIB model.
//!
//! Each handle type ([`Node`], [`Object`], [`Type`], [`Module`], etc.) wraps
//! an arena id together with a `&Mib` reference. Methods on handles return
//! further handles, so you can navigate the model without touching arena ids
//! directly.
//!
//! Handles are `Copy` and inexpensive to pass around. Two handles are equal
//! when they point to the same arena slot in the same [`Mib`].

use std::fmt;
use std::marker::PhantomData;
use std::ptr;

use crate::types::{Access, BaseType, ByteOffset, Kind, Language, Span, Status};

use super::capability::CapabilityData;
use super::compliance::ComplianceData;
use super::group::GroupData;
use super::mib::Mib;
use super::module::ModuleData;
use super::node::NodeData;
use super::notification::NotificationData;
use super::object::ObjectData;
use super::typedef::TypeData;
use super::types::*;

macro_rules! define_handle {
    ($name:ident, $id:ident, $data:ident, $getter:ident) => {
        #[derive(Clone, Copy)]
        #[doc = concat!("Borrowed handle to a resolved [`", stringify!($data), "`].")]
        ///
        /// Wraps a [`Mib`] reference and an arena id. Handles are `Copy` and
        /// cheap to pass around. Two handles are equal when they point to the
        /// same arena slot in the same [`Mib`].
        pub struct $name<'a> {
            pub(crate) mib: &'a Mib,
            pub(crate) id: $id,
        }

        impl<'a> $name<'a> {
            pub(crate) fn new(mib: &'a Mib, id: $id) -> Self {
                Self { mib, id }
            }

            pub(crate) fn data(self) -> &'a $data {
                self.mib.$getter(self.id)
            }

            /// Return the arena ID for this handle.
            ///
            /// Use IDs when you need deduplication, storage in collections,
            /// or to call [`RawMib`](super::RawMib) methods.
            pub fn id(self) -> $id {
                self.id
            }
        }

        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id && ptr::eq(self.mib, other.mib)
            }
        }

        impl Eq for $name<'_> {}

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("id", &self.id)
                    .field("name", &self.data().name())
                    .finish()
            }
        }
    };
}

define_handle!(Module, ModuleId, ModuleData, module_data);
define_handle!(Object, ObjectId, ObjectData, object_data);
define_handle!(Type, TypeId, TypeData, type_data);
define_handle!(
    Notification,
    NotificationId,
    NotificationData,
    notification_data
);
define_handle!(Group, GroupId, GroupData, group_data);
define_handle!(Compliance, ComplianceId, ComplianceData, compliance_data);
define_handle!(Capability, CapabilityId, CapabilityData, capability_data);

/// Borrowed handle to a resolved node in the OID tree.
///
/// A node represents a single position in the OID hierarchy. It may be a
/// plain structural node (e.g. `iso`, `org`) or carry an attached entity
/// such as an [`Object`], [`Notification`], [`Group`], [`Compliance`], or
/// [`Capability`].
///
/// Use [`Node::object`], [`Node::notification`], etc. to access attached
/// entities, and [`Node::children`] or [`Node::subtree`] for tree traversal.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    pub(crate) mib: &'a Mib,
    pub(crate) id: NodeId,
}

impl<'a> Node<'a> {
    pub(crate) fn new(mib: &'a Mib, id: NodeId) -> Self {
        Self { mib, id }
    }

    pub(crate) fn data(self) -> &'a NodeData {
        self.mib.node_data(self.id)
    }

    /// Return the arena ID for this node.
    pub fn id(self) -> NodeId {
        self.id
    }

    /// Return the node's numeric OID arc relative to its parent.
    pub fn arc(self) -> u32 {
        self.data().arc()
    }

    /// Return the node's local symbolic name.
    pub fn name(self) -> &'a str {
        self.data().name()
    }

    /// Return the DESCRIPTION text for this node.
    pub fn description(self) -> &'a str {
        self.data().description()
    }

    /// Return the REFERENCE text for this node, or empty if absent.
    pub fn reference(self) -> &'a str {
        self.data().reference()
    }

    /// Return the status if set on this node.
    pub fn status(self) -> Option<Status> {
        self.data().status()
    }

    /// Return the node kind (scalar, table, internal, etc.).
    pub fn kind(self) -> Kind {
        self.data().kind()
    }

    /// Return the source span of this node's definition.
    pub fn span(self) -> Span {
        self.data().span()
    }

    /// Return the node's full numeric OID.
    pub fn oid(self) -> &'a super::oid::Oid {
        self.mib.tree().oid_of(self.id)
    }

    /// Return the parent node, or `None` for the synthetic root.
    pub fn parent(self) -> Option<Node<'a>> {
        self.data().parent().map(|id| Node::new(self.mib, id))
    }

    /// Return the effective owning module for this node.
    ///
    /// When multiple modules define the same OID, ownership is resolved by
    /// preferring base modules over user modules, then SMIv2 over SMIv1,
    /// then newer `LAST-UPDATED` timestamps. See the crate-level "OID
    /// ownership" docs for details.
    ///
    /// If multiple entity kinds could conceptually own the node, entity-backed
    /// ownership takes precedence over plain base-module ownership.
    pub fn module(self) -> Option<Module<'a>> {
        self.mib
            .effective_module(self.id)
            .map(|id| Module::new(self.mib, id))
    }

    /// Return the object attached to this node, if any.
    pub fn object(self) -> Option<Object<'a>> {
        self.data().object().map(|id| Object::new(self.mib, id))
    }

    /// Return the notification attached to this node, if any.
    pub fn notification(self) -> Option<Notification<'a>> {
        self.data()
            .notification()
            .map(|id| Notification::new(self.mib, id))
    }

    /// Return the group attached to this node, if any.
    pub fn group(self) -> Option<Group<'a>> {
        self.data().group().map(|id| Group::new(self.mib, id))
    }

    /// Return the compliance statement attached to this node, if any.
    pub fn compliance(self) -> Option<Compliance<'a>> {
        self.data()
            .compliance()
            .map(|id| Compliance::new(self.mib, id))
    }

    /// Return the capabilities statement attached to this node, if any.
    pub fn capability(self) -> Option<Capability<'a>> {
        self.data()
            .capability()
            .map(|id| Capability::new(self.mib, id))
    }

    /// Iterate the node's direct children in arc order.
    pub fn children(self) -> impl Iterator<Item = Node<'a>> + 'a {
        self.data()
            .children()
            .values()
            .copied()
            .map(|id| Node::new(self.mib, id))
    }

    /// Iterate the full subtree rooted at this node in depth-first order.
    pub fn subtree(self) -> impl Iterator<Item = Node<'a>> + 'a {
        self.mib.subtree(self.id).map(|id| Node::new(self.mib, id))
    }
}

impl PartialEq for Node<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && ptr::eq(self.mib, other.mib)
    }
}

impl Eq for Node<'_> {}

impl fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &self.id)
            .field("name", &self.data().name())
            .field("kind", &self.data().kind())
            .finish()
    }
}

/// A resolved index component for a table row.
///
/// Indexes may be object-backed (e.g. `INDEX { ifIndex }`) or bare-type
/// indexes (e.g. `INDEX { INTEGER }`). Obtained from
/// [`Object::effective_indexes`]. For the underlying data, see
/// [`IndexEntry`].
#[derive(Clone, Copy)]
pub struct Index<'a> {
    mib: &'a Mib,
    row_id: ObjectId,
    entry: &'a IndexEntry,
}

impl<'a> Index<'a> {
    fn new(mib: &'a Mib, row_id: ObjectId, entry: &'a IndexEntry) -> Self {
        Self { mib, row_id, entry }
    }

    /// Return the row whose effective index list this entry belongs to.
    pub fn row(self) -> Object<'a> {
        Object::new(self.mib, self.row_id)
    }

    /// Return the referenced index object when the index is object-backed.
    pub fn object(self) -> Option<Object<'a>> {
        self.entry.object.map(|id| Object::new(self.mib, id))
    }

    /// Return the source identifier written in the `INDEX` clause.
    ///
    /// For object-backed indexes this is the object name. For bare-type indexes
    /// this is the type name as written in the clause.
    pub fn name(self) -> &'a str {
        &self.entry.name
    }

    /// Return the resolved type for this index component when available.
    pub fn ty(self) -> Option<Type<'a>> {
        self.entry.type_id.map(|id| Type::new(self.mib, id))
    }

    /// Return `true` if this index uses the IMPLIED keyword.
    pub fn implied(self) -> bool {
        self.entry.implied
    }

    /// Return the derived index encoding strategy.
    pub fn encoding(self) -> crate::types::IndexEncoding {
        self.entry.encoding
    }

    /// Return the fixed encoding width for this index entry, if determinable.
    ///
    /// Returns the width in sub-identifiers and `true` for fixed-width
    /// encodings (integer = 1, IP address = 4, fixed-size string = SIZE value).
    /// Returns `(0, false)` for variable-length or unknown encodings.
    pub fn fixed_size(self) -> (usize, bool) {
        match self.entry.encoding {
            crate::types::IndexEncoding::Integer => (1, true),
            crate::types::IndexEncoding::IpAddress => (4, true),
            crate::types::IndexEncoding::FixedString => {
                if let Some(obj) = self.object() {
                    let sizes = obj.effective_sizes();
                    if super::types::is_fixed_size(sizes) {
                        return (sizes[0].min as usize, true);
                    }
                }
                (0, false)
            }
            _ => (0, false),
        }
    }

    /// Return the source span of this index component.
    pub fn span(self) -> Span {
        self.entry.span
    }

    /// Return the underlying raw index entry.
    ///
    /// Most callers should prefer the typed accessors on [`Index`] directly.
    pub fn entry(self) -> &'a IndexEntry {
        self.entry
    }
}

impl<'a> Module<'a> {
    /// Return the module name.
    pub fn name(self) -> &'a str {
        self.data().name()
    }

    /// Return the SMI language version (SMIv1 or SMIv2).
    pub fn language(self) -> Language {
        self.data().language()
    }

    /// Return the file path this module was loaded from.
    pub fn source_path(self) -> &'a str {
        self.data().source_path()
    }

    /// Return the ORGANIZATION clause text from MODULE-IDENTITY.
    pub fn organization(self) -> &'a str {
        self.data().organization()
    }

    /// Return the CONTACT-INFO clause text from MODULE-IDENTITY.
    pub fn contact_info(self) -> &'a str {
        self.data().contact_info()
    }

    /// Return the DESCRIPTION clause text from MODULE-IDENTITY.
    pub fn description(self) -> &'a str {
        self.data().description()
    }

    /// Return the LAST-UPDATED timestamp string from MODULE-IDENTITY.
    pub fn last_updated(self) -> &'a str {
        self.data().last_updated()
    }

    /// Return the REVISION entries from MODULE-IDENTITY.
    pub fn revisions(self) -> &'a [super::types::Revision] {
        self.data().revisions()
    }

    /// Return the IMPORTS declarations.
    pub fn imports(self) -> &'a [super::types::Import] {
        self.data().imports()
    }

    /// Return `true` if this is a synthetic base module (SNMPv2-SMI, etc.).
    ///
    /// Base modules define the SMI language itself and are constructed
    /// programmatically rather than parsed from files. They have no real
    /// source text, so spans are [`Span::SYNTHETIC`](crate::types::Span::SYNTHETIC)
    /// and `source_path()` returns an empty string. See the crate-level
    /// docs for the full list of base modules and their contents.
    pub fn is_base(self) -> bool {
        self.data().is_base()
    }

    /// Return the module's registered OID from its MODULE-IDENTITY, if any.
    pub fn oid(self) -> Option<&'a super::oid::Oid> {
        self.data().oid()
    }

    /// Convert a byte offset within this module's source to a line and column number.
    pub fn line_col(self, offset: ByteOffset) -> (usize, usize) {
        self.data().line_col(offset)
    }

    /// Look up an object defined by this module.
    pub fn object(self, name: &str) -> Option<Object<'a>> {
        self.data()
            .object_by_name(name)
            .map(|id| Object::new(self.mib, id))
    }

    /// Look up a type defined by this module.
    pub fn r#type(self, name: &str) -> Option<Type<'a>> {
        self.data()
            .type_by_name(name)
            .map(|id| Type::new(self.mib, id))
    }

    /// Look up any node defined by this module.
    pub fn node(self, name: &str) -> Option<Node<'a>> {
        self.data()
            .node_by_name(name)
            .map(|id| Node::new(self.mib, id))
    }

    /// Look up a notification defined by this module.
    pub fn notification(self, name: &str) -> Option<Notification<'a>> {
        self.data()
            .notification_by_name(name)
            .map(|id| Notification::new(self.mib, id))
    }

    /// Look up a group defined by this module.
    pub fn group(self, name: &str) -> Option<Group<'a>> {
        self.data()
            .group_by_name(name)
            .map(|id| Group::new(self.mib, id))
    }

    /// Look up a compliance statement defined by this module.
    pub fn compliance(self, name: &str) -> Option<Compliance<'a>> {
        self.data()
            .compliance_by_name(name)
            .map(|id| Compliance::new(self.mib, id))
    }

    /// Look up a capabilities statement defined by this module.
    pub fn capability(self, name: &str) -> Option<Capability<'a>> {
        self.data()
            .capability_by_name(name)
            .map(|id| Capability::new(self.mib, id))
    }

    /// Iterate objects defined by this module.
    pub fn objects(self) -> impl Iterator<Item = Object<'a>> + 'a {
        self.data()
            .objects()
            .iter()
            .copied()
            .map(|id| Object::new(self.mib, id))
    }

    /// Iterate types defined by this module.
    pub fn types(self) -> impl Iterator<Item = Type<'a>> + 'a {
        self.data()
            .types()
            .iter()
            .copied()
            .map(|id| Type::new(self.mib, id))
    }

    /// Iterate nodes defined by this module.
    pub fn nodes(self) -> impl Iterator<Item = Node<'a>> + 'a {
        self.data()
            .nodes()
            .iter()
            .copied()
            .map(|id| Node::new(self.mib, id))
    }
}

impl<'a> Object<'a> {
    /// Return the object name.
    pub fn name(self) -> &'a str {
        self.data().name()
    }

    /// Return the source span of this object definition.
    pub fn span(self) -> Span {
        self.data().span()
    }

    /// Return the module that defines this object.
    pub fn module(self) -> Option<Module<'a>> {
        self.data().module().map(|id| Module::new(self.mib, id))
    }

    /// Return the OID tree node for this object.
    ///
    /// # Panics
    ///
    /// Panics if the object's OID was not resolved during loading. This should
    /// not happen for objects obtained from a fully resolved [`Mib`].
    pub fn node(self) -> Node<'a> {
        Node::new(
            self.mib,
            self.data().node().expect("resolved object missing node"),
        )
    }

    /// Return the status (current, deprecated, obsolete).
    pub fn status(self) -> Status {
        self.data().status()
    }

    /// Return the DESCRIPTION clause text.
    pub fn description(self) -> &'a str {
        self.data().description()
    }

    /// Return the REFERENCE clause text, or empty if absent.
    pub fn reference(self) -> &'a str {
        self.data().reference()
    }

    /// Return the resolved type of this object, if it has one.
    pub fn ty(self) -> Option<Type<'a>> {
        self.data().type_id().map(|id| Type::new(self.mib, id))
    }

    /// Return the access level (read-only, read-write, etc.).
    pub fn access(self) -> Access {
        self.data().access()
    }

    /// Return the UNITS clause text, or empty if absent.
    pub fn units(self) -> &'a str {
        self.data().units()
    }

    /// Return the DEFVAL clause, if present.
    pub fn default_value(self) -> Option<&'a DefVal> {
        self.data().default_value()
    }

    /// Return the node kind (scalar, table, row, column).
    pub fn kind(self) -> Kind {
        self.data().kind(self.mib.tree())
    }

    /// Return the effective display hint from the type chain.
    pub fn effective_display_hint(self) -> &'a str {
        self.data().effective_display_hint()
    }

    /// Return the effective SIZE constraints from the type chain.
    pub fn effective_sizes(self) -> &'a [Range] {
        self.data().effective_sizes()
    }

    /// Return the effective range constraints from the type chain.
    pub fn effective_ranges(self) -> &'a [Range] {
        self.data().effective_ranges()
    }

    /// Return the effective enumeration values from the type chain.
    pub fn effective_enums(self) -> &'a [NamedValue] {
        self.data().effective_enums()
    }

    /// Return the effective BITS definitions from the type chain.
    pub fn effective_bits(self) -> &'a [NamedValue] {
        self.data().effective_bits()
    }

    /// Parse and validate this object's effective DISPLAY-HINT, returning a
    /// structured [`DisplayHint`](super::display_hint::DisplayHint).
    ///
    /// Returns `None` if the object has no display hint or the hint is
    /// malformed.
    pub fn parsed_display_hint(self) -> Option<super::display_hint::DisplayHint> {
        let hint = self.data().effective_display_hint();
        if hint.is_empty() {
            return None;
        }
        super::display_hint::DisplayHint::parse(hint)
    }

    /// Format an integer value using this object's effective DISPLAY-HINT.
    ///
    /// Returns `None` if the object has no display hint or the hint is
    /// not a valid integer hint.
    pub fn format_integer(
        self,
        value: i64,
        hex_case: super::display_hint::HexCase,
    ) -> Option<String> {
        let hint = self.data().effective_display_hint();
        if hint.is_empty() {
            return None;
        }
        super::display_hint::format_integer(hint, value, hex_case)
    }

    /// Apply this object's DISPLAY-HINT as numeric scaling, returning `f64`.
    ///
    /// Only `d` and `d-N` hints produce a result (e.g. `d-2` on 1234
    /// returns 12.34). Returns `None` if the hint is absent, non-decimal,
    /// or malformed.
    pub fn scale_integer(self, value: i64) -> Option<f64> {
        let hint = self.data().effective_display_hint();
        if hint.is_empty() {
            return None;
        }
        super::display_hint::scale_integer(hint, value)
    }

    /// Format an octet string using this object's effective DISPLAY-HINT.
    ///
    /// Returns `None` if the object has no display hint, the hint is
    /// malformed, or the data is empty.
    pub fn format_octets(
        self,
        data: &[u8],
        hex_case: super::display_hint::HexCase,
    ) -> Option<String> {
        let hint = self.data().effective_display_hint();
        if hint.is_empty() {
            return None;
        }
        super::display_hint::format_octets(hint, data, hex_case)
    }

    /// Return the containing table for a table, row, or column.
    ///
    /// Scalars return `None`.
    pub fn table(self) -> Option<Object<'a>> {
        self.mib
            .object_table(self.id)
            .map(|id| Object::new(self.mib, id))
    }

    /// Return the associated row for a table, row, or column.
    ///
    /// For tables this returns the child row entry. For rows it returns the row
    /// itself. For columns it returns the parent row. Scalars return `None`.
    pub fn row(self) -> Option<Object<'a>> {
        self.mib
            .object_row(self.id)
            .map(|id| Object::new(self.mib, id))
    }

    /// Iterate the columns belonging to this table or row.
    ///
    /// Scalars and standalone objects yield an empty iterator.
    pub fn columns(self) -> impl Iterator<Item = Object<'a>> + 'a {
        self.mib
            .object_columns(self.id)
            .into_iter()
            .map(|id| Object::new(self.mib, id))
    }

    /// Return the object this row augments, if any.
    pub fn augments(self) -> Option<Object<'a>> {
        self.data().augments().map(|id| Object::new(self.mib, id))
    }

    /// Iterate rows that augment this row.
    pub fn augmented_by(self) -> impl Iterator<Item = Object<'a>> + 'a {
        self.data()
            .augmented_by()
            .iter()
            .copied()
            .map(|id| Object::new(self.mib, id))
    }

    /// Iterate the effective indexes for this row, column, or augmented row.
    ///
    /// For columns, delegates to the parent row. For rows that use
    /// `AUGMENTS`, follows the augment chain to the source row that owns
    /// the effective `INDEX` clause.
    pub fn effective_indexes(self) -> impl Iterator<Item = Index<'a>> + 'a {
        self.mib
            .effective_indexes_source(self.id)
            .into_iter()
            .flat_map(move |id| {
                self.mib
                    .object_data(id)
                    .index()
                    .iter()
                    .map(move |entry| Index::new(self.mib, self.id, entry))
            })
    }

    /// Return `true` if this object is a table.
    pub fn is_table(self) -> bool {
        self.mib.is_table(self.id)
    }

    /// Return `true` if this object is a table row.
    pub fn is_row(self) -> bool {
        self.mib.is_row(self.id)
    }

    /// Return `true` if this object is a table column.
    pub fn is_column(self) -> bool {
        self.mib.is_column(self.id)
    }

    /// Return `true` if this object is a scalar.
    pub fn is_scalar(self) -> bool {
        self.mib.is_scalar(self.id)
    }

    /// Return `true` if this object appears in its row's effective index list.
    pub fn is_index(self) -> bool {
        self.mib.is_index(self.id)
    }
}

impl<'a> Type<'a> {
    /// Return the type name.
    pub fn name(self) -> &'a str {
        self.data().name()
    }

    /// Return the source span of this type definition.
    pub fn span(self) -> Span {
        self.data().span()
    }

    /// Return the source span of the SYNTAX clause.
    pub fn syntax_span(self) -> Span {
        self.data().syntax_span()
    }

    /// Return the module that defines this type.
    pub fn module(self) -> Option<Module<'a>> {
        self.data().module().map(|id| Module::new(self.mib, id))
    }

    /// Return the directly assigned base type.
    pub fn base(self) -> BaseType {
        self.data().base()
    }

    /// Return the immediate parent type, if this is a derived type.
    pub fn parent(self) -> Option<Type<'a>> {
        self.data().parent().map(|id| Type::new(self.mib, id))
    }

    /// Return the status (current, deprecated, obsolete).
    pub fn status(self) -> Status {
        self.data().status()
    }

    /// Return this type's own DISPLAY-HINT, or empty if absent.
    pub fn display_hint(self) -> &'a str {
        self.data().display_hint()
    }

    /// Return the DESCRIPTION clause text.
    pub fn description(self) -> &'a str {
        self.data().description()
    }

    /// Return the REFERENCE clause text, or empty if absent.
    pub fn reference(self) -> &'a str {
        self.data().reference()
    }

    /// Return this type's own SIZE constraints (not inherited).
    pub fn sizes(self) -> &'a [Range] {
        self.data().sizes()
    }

    /// Return this type's own range constraints (not inherited).
    pub fn ranges(self) -> &'a [Range] {
        self.data().ranges()
    }

    /// Return this type's own enumeration values (not inherited).
    pub fn enums(self) -> &'a [NamedValue] {
        self.data().enums()
    }

    /// Return this type's own BITS definitions (not inherited).
    pub fn bits(self) -> &'a [NamedValue] {
        self.data().bits()
    }

    /// Return `true` if this type was defined as a TEXTUAL-CONVENTION.
    pub fn is_textual_convention(self) -> bool {
        self.data().is_textual_convention()
    }

    /// Walk the parent type chain and return the first type that is a
    /// TEXTUAL-CONVENTION, or `None` if no type in the chain is a TC.
    pub fn effective_tc(self) -> Option<Type<'a>> {
        if self.data().is_textual_convention() {
            return Some(self);
        }
        self.data()
            .effective_tc_in_parents(self.mib.types_slice())
            .map(|id| Type::new(self.mib, id))
    }

    /// Return the effective [`BaseType`] after following the parent type chain.
    ///
    /// Returns the first non-[`Unknown`](BaseType::Unknown) base type
    /// encountered when walking from this type toward the root of the chain.
    pub fn effective_base(self) -> BaseType {
        self.data().effective_base(self.mib.types_slice())
    }

    /// Return the effective display hint after following parent type chains.
    pub fn effective_display_hint(self) -> &'a str {
        self.data().effective_display_hint(self.mib.types_slice())
    }

    /// Parse and validate the effective display hint, returning a structured
    /// [`DisplayHint`](super::display_hint::DisplayHint).
    ///
    /// Returns `None` if there is no display hint in the type chain or the
    /// hint is malformed.
    pub fn parsed_display_hint(self) -> Option<super::display_hint::DisplayHint> {
        let hint = self.data().effective_display_hint(self.mib.types_slice());
        if hint.is_empty() {
            return None;
        }
        super::display_hint::DisplayHint::parse(hint)
    }

    /// Return the effective SIZE constraints from the type chain.
    pub fn effective_sizes(self) -> &'a [Range] {
        self.data().effective_sizes(self.mib.types_slice())
    }

    /// Return the effective range constraints from the type chain.
    pub fn effective_ranges(self) -> &'a [Range] {
        self.data().effective_ranges(self.mib.types_slice())
    }

    /// Return the effective enumeration values from the type chain.
    pub fn effective_enums(self) -> &'a [NamedValue] {
        self.data().effective_enums(self.mib.types_slice())
    }

    /// Return the effective BITS definitions from the type chain.
    pub fn effective_bits(self) -> &'a [NamedValue] {
        self.data().effective_bits(self.mib.types_slice())
    }

    /// Return `true` if the effective base type is Counter32 or Counter64.
    pub fn is_counter(self) -> bool {
        self.data().is_counter(self.mib.types_slice())
    }

    /// Return `true` if the effective base type is Gauge32.
    pub fn is_gauge(self) -> bool {
        self.data().is_gauge(self.mib.types_slice())
    }

    /// Return `true` if the effective base type is OCTET STRING.
    pub fn is_string(self) -> bool {
        self.data().is_string(self.mib.types_slice())
    }

    /// Return `true` if this is an Integer32 type with enumeration values.
    pub fn is_enumeration(self) -> bool {
        self.data().is_enumeration(self.mib.types_slice())
    }

    /// Return `true` if this type has BITS definitions.
    pub fn is_bits(self) -> bool {
        self.data().is_bits(self.mib.types_slice())
    }
}

macro_rules! entity_handle_impl {
    ($name:ident) => {
        impl<'a> $name<'a> {
            /// Return the definition name.
            pub fn name(self) -> &'a str {
                self.data().name()
            }

            /// Return the source span.
            pub fn span(self) -> Span {
                self.data().span()
            }

            /// Return the defining module.
            pub fn module(self) -> Option<Module<'a>> {
                self.data().module().map(|id| Module::new(self.mib, id))
            }

            /// Return the OID tree node, if resolved.
            pub fn node(self) -> Option<Node<'a>> {
                self.data().node().map(|id| Node::new(self.mib, id))
            }

            /// Return the status.
            pub fn status(self) -> Status {
                self.data().status()
            }

            /// Return the DESCRIPTION clause text.
            pub fn description(self) -> &'a str {
                self.data().description()
            }

            /// Return the REFERENCE clause text.
            pub fn reference(self) -> &'a str {
                self.data().reference()
            }

            /// Return the symbolic OID references from the definition.
            pub fn oid_refs(self) -> &'a [OidRef] {
                self.data().oid_refs()
            }
        }
    };
}

entity_handle_impl!(Notification);
entity_handle_impl!(Group);
entity_handle_impl!(Compliance);
entity_handle_impl!(Capability);

impl<'a> Notification<'a> {
    /// Iterate the OBJECTS clause entries.
    pub fn objects(self) -> impl Iterator<Item = Object<'a>> + 'a {
        self.data()
            .objects()
            .iter()
            .copied()
            .map(|id| Object::new(self.mib, id))
    }

    /// Return SMIv1 TRAP-TYPE fields (enterprise, trap number), if this is a trap.
    pub fn trap_info(self) -> Option<&'a TrapInfo> {
        self.data().trap_info()
    }
}

impl<'a> Group<'a> {
    /// Iterate the group's member nodes.
    pub fn members(self) -> impl Iterator<Item = Node<'a>> + 'a {
        self.data()
            .members()
            .iter()
            .copied()
            .map(|id| Node::new(self.mib, id))
    }

    /// Return `true` if this is a NOTIFICATION-GROUP (vs OBJECT-GROUP).
    pub fn is_notification_group(self) -> bool {
        self.data().is_notification_group()
    }
}

impl<'a> Compliance<'a> {
    /// Return the MODULE clauses in this compliance statement.
    pub fn modules(self) -> &'a [ComplianceModule] {
        self.data().modules()
    }
}

impl<'a> Capability<'a> {
    /// Return the PRODUCT-RELEASE string.
    pub fn product_release(self) -> &'a str {
        self.data().product_release()
    }

    /// Return the SUPPORTS clauses.
    pub fn supports(self) -> &'a [CapabilitiesModule] {
        self.data().supports()
    }
}

/// Iterator adapter that converts arena id iteration into borrowed handles.
///
/// Returned by collection methods on [`Mib`] such as [`Mib::modules`],
/// [`Mib::objects`], [`Mib::types`], and [`Mib::nodes`]. Implements
/// [`Iterator`] for the corresponding handle type.
pub struct HandleIter<'a, H, I> {
    mib: &'a Mib,
    ids: I,
    _marker: PhantomData<H>,
}

impl<'a, H, I> HandleIter<'a, H, I> {
    pub(crate) fn new(mib: &'a Mib, ids: I) -> Self {
        Self {
            mib,
            ids,
            _marker: PhantomData,
        }
    }
}

impl<'a, I> Iterator for HandleIter<'a, Module<'a>, I>
where
    I: Iterator<Item = ModuleId>,
{
    type Item = Module<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Module::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Object<'a>, I>
where
    I: Iterator<Item = ObjectId>,
{
    type Item = Object<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Object::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Type<'a>, I>
where
    I: Iterator<Item = TypeId>,
{
    type Item = Type<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Type::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Node<'a>, I>
where
    I: Iterator<Item = NodeId>,
{
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Node::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Notification<'a>, I>
where
    I: Iterator<Item = NotificationId>,
{
    type Item = Notification<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Notification::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Group<'a>, I>
where
    I: Iterator<Item = GroupId>,
{
    type Item = Group<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Group::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Compliance<'a>, I>
where
    I: Iterator<Item = ComplianceId>,
{
    type Item = Compliance<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Compliance::new(self.mib, id))
    }
}

impl<'a, I> Iterator for HandleIter<'a, Capability<'a>, I>
where
    I: Iterator<Item = CapabilityId>,
{
    type Item = Capability<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|id| Capability::new(self.mib, id))
    }
}
