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
        #[doc = concat!("Borrowed handle to a resolved ", stringify!($name), ".")]
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

#[derive(Clone, Copy)]
/// Borrowed handle to a resolved node in the OID tree.
///
/// A node may represent a plain tree node or an entity-backed node such as an
/// object or notification.
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

    /// Return the node's numeric OID arc relative to its parent.
    pub fn arc(self) -> u32 {
        self.data().arc()
    }

    /// Return the node's local symbolic name.
    pub fn name(self) -> &'a str {
        self.data().name()
    }

    pub fn description(self) -> &'a str {
        self.data().description()
    }

    pub fn reference(self) -> &'a str {
        self.data().reference()
    }

    pub fn status(self) -> Option<Status> {
        self.data().status()
    }

    pub fn kind(self) -> Kind {
        self.data().kind()
    }

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

#[derive(Clone, Copy)]
/// A resolved index component for a table row.
///
/// Indexes may be object-backed, such as `INDEX { ifIndex }`, or bare-type
/// indexes, such as `INDEX { INTEGER }`.
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

    pub fn implied(self) -> bool {
        self.entry.implied
    }

    /// Return the derived index encoding strategy.
    pub fn encoding(self) -> crate::types::IndexEncoding {
        self.entry.encoding
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

    pub fn language(self) -> Language {
        self.data().language()
    }

    pub fn source_path(self) -> &'a str {
        self.data().source_path()
    }

    pub fn is_base(self) -> bool {
        self.data().is_base()
    }

    pub fn oid(self) -> Option<&'a super::oid::Oid> {
        self.data().oid()
    }

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

    pub fn notification(self, name: &str) -> Option<Notification<'a>> {
        self.data()
            .notification_by_name(name)
            .map(|id| Notification::new(self.mib, id))
    }

    pub fn group(self, name: &str) -> Option<Group<'a>> {
        self.data()
            .group_by_name(name)
            .map(|id| Group::new(self.mib, id))
    }

    pub fn compliance(self, name: &str) -> Option<Compliance<'a>> {
        self.data()
            .compliance_by_name(name)
            .map(|id| Compliance::new(self.mib, id))
    }

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

    pub fn span(self) -> Span {
        self.data().span()
    }

    pub fn module(self) -> Option<Module<'a>> {
        self.data().module().map(|id| Module::new(self.mib, id))
    }

    pub fn node(self) -> Node<'a> {
        Node::new(
            self.mib,
            self.data().node().expect("resolved object missing node"),
        )
    }

    pub fn status(self) -> Status {
        self.data().status()
    }

    pub fn description(self) -> &'a str {
        self.data().description()
    }

    pub fn reference(self) -> &'a str {
        self.data().reference()
    }

    /// Return the resolved type of this object, if it has one.
    pub fn ty(self) -> Option<Type<'a>> {
        self.data().type_id().map(|id| Type::new(self.mib, id))
    }

    pub fn access(self) -> Access {
        self.data().access()
    }

    pub fn units(self) -> &'a str {
        self.data().units()
    }

    pub fn default_value(self) -> Option<&'a DefVal> {
        self.data().default_value()
    }

    pub fn kind(self) -> Kind {
        self.data().kind(self.mib.tree())
    }

    pub fn effective_display_hint(self) -> &'a str {
        self.data().effective_display_hint()
    }

    pub fn effective_sizes(self) -> &'a [Range] {
        self.data().effective_sizes()
    }

    pub fn effective_ranges(self) -> &'a [Range] {
        self.data().effective_ranges()
    }

    pub fn effective_enums(self) -> &'a [NamedValue] {
        self.data().effective_enums()
    }

    pub fn effective_bits(self) -> &'a [NamedValue] {
        self.data().effective_bits()
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

    /// Iterate the effective indexes for this row or augmented row.
    ///
    /// For rows that use `AUGMENTS`, this follows the augment chain to the
    /// source row that owns the effective `INDEX` clause.
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

    pub fn span(self) -> Span {
        self.data().span()
    }

    pub fn syntax_span(self) -> Span {
        self.data().syntax_span()
    }

    pub fn module(self) -> Option<Module<'a>> {
        self.data().module().map(|id| Module::new(self.mib, id))
    }

    pub fn base(self) -> BaseType {
        self.data().base()
    }

    /// Return the immediate parent type, if this is a derived type.
    pub fn parent(self) -> Option<Type<'a>> {
        self.data().parent().map(|id| Type::new(self.mib, id))
    }

    pub fn status(self) -> Status {
        self.data().status()
    }

    pub fn display_hint(self) -> &'a str {
        self.data().display_hint()
    }

    pub fn description(self) -> &'a str {
        self.data().description()
    }

    pub fn reference(self) -> &'a str {
        self.data().reference()
    }

    pub fn sizes(self) -> &'a [Range] {
        self.data().sizes()
    }

    pub fn ranges(self) -> &'a [Range] {
        self.data().ranges()
    }

    pub fn enums(self) -> &'a [NamedValue] {
        self.data().enums()
    }

    pub fn bits(self) -> &'a [NamedValue] {
        self.data().bits()
    }

    pub fn is_textual_convention(self) -> bool {
        self.data().is_textual_convention()
    }

    /// Return the effective base type after following parent type chains.
    pub fn effective_base(self) -> BaseType {
        self.data().effective_base(self.mib.types_slice())
    }

    /// Return the effective display hint after following parent type chains.
    pub fn effective_display_hint(self) -> &'a str {
        self.data().effective_display_hint(self.mib.types_slice())
    }

    pub fn effective_sizes(self) -> &'a [Range] {
        self.data().effective_sizes(self.mib.types_slice())
    }

    pub fn effective_ranges(self) -> &'a [Range] {
        self.data().effective_ranges(self.mib.types_slice())
    }

    pub fn effective_enums(self) -> &'a [NamedValue] {
        self.data().effective_enums(self.mib.types_slice())
    }

    pub fn effective_bits(self) -> &'a [NamedValue] {
        self.data().effective_bits(self.mib.types_slice())
    }

    pub fn is_counter(self) -> bool {
        self.data().is_counter(self.mib.types_slice())
    }

    pub fn is_gauge(self) -> bool {
        self.data().is_gauge(self.mib.types_slice())
    }

    pub fn is_string(self) -> bool {
        self.data().is_string(self.mib.types_slice())
    }

    pub fn is_enumeration(self) -> bool {
        self.data().is_enumeration(self.mib.types_slice())
    }

    pub fn is_bits(self) -> bool {
        self.data().is_bits(self.mib.types_slice())
    }
}

macro_rules! entity_handle_impl {
    ($name:ident) => {
        impl<'a> $name<'a> {
            pub fn name(self) -> &'a str {
                self.data().name()
            }

            pub fn span(self) -> Span {
                self.data().span()
            }

            pub fn module(self) -> Option<Module<'a>> {
                self.data().module().map(|id| Module::new(self.mib, id))
            }

            pub fn node(self) -> Option<Node<'a>> {
                self.data().node().map(|id| Node::new(self.mib, id))
            }

            pub fn status(self) -> Status {
                self.data().status()
            }

            pub fn description(self) -> &'a str {
                self.data().description()
            }

            pub fn reference(self) -> &'a str {
                self.data().reference()
            }

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
    pub fn objects(self) -> impl Iterator<Item = Object<'a>> + 'a {
        self.data()
            .objects()
            .iter()
            .copied()
            .map(|id| Object::new(self.mib, id))
    }

    pub fn trap_info(self) -> Option<&'a TrapInfo> {
        self.data().trap_info()
    }
}

impl<'a> Group<'a> {
    pub fn members(self) -> impl Iterator<Item = Node<'a>> + 'a {
        self.data()
            .members()
            .iter()
            .copied()
            .map(|id| Node::new(self.mib, id))
    }

    pub fn is_notification_group(self) -> bool {
        self.data().is_notification_group()
    }
}

impl<'a> Compliance<'a> {
    pub fn modules(self) -> &'a [ComplianceModule] {
        self.data().modules()
    }
}

impl<'a> Capability<'a> {
    pub fn product_release(self) -> &'a str {
        self.data().product_release()
    }

    pub fn supports(self) -> &'a [CapabilitiesModule] {
        self.data().supports()
    }
}

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
