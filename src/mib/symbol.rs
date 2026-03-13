//! Untyped symbol references into the resolved MIB.
//!
//! [`Symbol`] is a tagged union of all possible definition kinds. It wraps
//! the arena id for the definition and provides uniform access to common
//! properties (name, span, module, node, status) without requiring the
//! caller to know the definition kind upfront.

use crate::types::{Span, Status};

use super::types::*;

/// A reference to any resolved MIB definition.
///
/// Returned by name-lookup methods on [`Mib`](super::mib::Mib) and
/// [`ModuleData`](super::module::ModuleData). Each variant wraps the
/// corresponding arena id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbol {
    /// An OBJECT-TYPE definition.
    Object(ObjectId),
    /// A NOTIFICATION-TYPE or TRAP-TYPE definition.
    Notification(NotificationId),
    /// An OBJECT-GROUP or NOTIFICATION-GROUP definition.
    Group(GroupId),
    /// A MODULE-COMPLIANCE definition.
    Compliance(ComplianceId),
    /// An AGENT-CAPABILITIES definition.
    Capability(CapabilityId),
    /// A type or TEXTUAL-CONVENTION definition.
    Type(TypeId),
    /// A plain OID tree node with no entity attached.
    Node(NodeId),
}

impl Symbol {
    /// Return the name of this symbol by looking it up in the appropriate arena.
    #[must_use]
    pub fn name<'a>(&self, mib: &'a super::mib::Mib) -> &'a str {
        match self {
            Symbol::Object(id) => mib.raw().object(*id).name(),
            Symbol::Notification(id) => mib.raw().notification(*id).name(),
            Symbol::Group(id) => mib.raw().group(*id).name(),
            Symbol::Compliance(id) => mib.raw().compliance(*id).name(),
            Symbol::Capability(id) => mib.raw().capability(*id).name(),
            Symbol::Type(id) => mib.raw().type_(*id).name(),
            Symbol::Node(id) => &mib.tree.get(*id).name,
        }
    }

    /// Return the source span of this symbol's definition.
    #[must_use]
    pub fn span(&self, mib: &super::mib::Mib) -> Span {
        match self {
            Symbol::Object(id) => mib.raw().object(*id).span(),
            Symbol::Notification(id) => mib.raw().notification(*id).span(),
            Symbol::Group(id) => mib.raw().group(*id).span(),
            Symbol::Compliance(id) => mib.raw().compliance(*id).span(),
            Symbol::Capability(id) => mib.raw().capability(*id).span(),
            Symbol::Type(id) => mib.raw().type_(*id).span(),
            Symbol::Node(id) => mib.tree.get(*id).span,
        }
    }

    /// Return the [`ModuleId`] that defines this symbol.
    #[must_use]
    pub fn module(&self, mib: &super::mib::Mib) -> Option<ModuleId> {
        match self {
            Symbol::Object(id) => mib.raw().object(*id).module(),
            Symbol::Notification(id) => mib.raw().notification(*id).module(),
            Symbol::Group(id) => mib.raw().group(*id).module(),
            Symbol::Compliance(id) => mib.raw().compliance(*id).module(),
            Symbol::Capability(id) => mib.raw().capability(*id).module(),
            Symbol::Type(id) => mib.raw().type_(*id).module(),
            Symbol::Node(id) => mib.effective_module(*id),
        }
    }

    /// Return the OID tree [`NodeId`] for this symbol.
    ///
    /// Returns `None` for `Type` variants, which have no OID tree position.
    #[must_use]
    pub fn node(&self, mib: &super::mib::Mib) -> Option<NodeId> {
        match self {
            Symbol::Object(id) => mib.raw().object(*id).node(),
            Symbol::Notification(id) => mib.raw().notification(*id).node(),
            Symbol::Group(id) => mib.raw().group(*id).node(),
            Symbol::Compliance(id) => mib.raw().compliance(*id).node(),
            Symbol::Capability(id) => mib.raw().capability(*id).node(),
            Symbol::Type(_) => None,
            Symbol::Node(id) => Some(*id),
        }
    }

    /// Return the [`Status`] of this symbol.
    ///
    /// Plain nodes return `Status::default()` since they have no explicit status.
    #[must_use]
    pub fn status(&self, mib: &super::mib::Mib) -> Status {
        match self {
            Symbol::Object(id) => mib.raw().object(*id).status(),
            Symbol::Notification(id) => mib.raw().notification(*id).status(),
            Symbol::Group(id) => mib.raw().group(*id).status(),
            Symbol::Compliance(id) => mib.raw().compliance(*id).status(),
            Symbol::Capability(id) => mib.raw().capability(*id).status(),
            Symbol::Type(id) => mib.raw().type_(*id).status(),
            Symbol::Node(_) => Status::default(),
        }
    }

    /// Return the [`ObjectId`] if this is an `Object` variant.
    #[must_use]
    pub fn as_object(&self) -> Option<ObjectId> {
        match self {
            Symbol::Object(id) => Some(*id),
            _ => None,
        }
    }

    /// Return the [`NotificationId`] if this is a `Notification` variant.
    #[must_use]
    pub fn as_notification(&self) -> Option<NotificationId> {
        match self {
            Symbol::Notification(id) => Some(*id),
            _ => None,
        }
    }

    /// Return the [`GroupId`] if this is a `Group` variant.
    #[must_use]
    pub fn as_group(&self) -> Option<GroupId> {
        match self {
            Symbol::Group(id) => Some(*id),
            _ => None,
        }
    }

    /// Return the [`ComplianceId`] if this is a `Compliance` variant.
    #[must_use]
    pub fn as_compliance(&self) -> Option<ComplianceId> {
        match self {
            Symbol::Compliance(id) => Some(*id),
            _ => None,
        }
    }

    /// Return the [`CapabilityId`] if this is a `Capability` variant.
    #[must_use]
    pub fn as_capability(&self) -> Option<CapabilityId> {
        match self {
            Symbol::Capability(id) => Some(*id),
            _ => None,
        }
    }

    /// Return the [`TypeId`] if this is a `Type` variant.
    #[must_use]
    pub fn as_type(&self) -> Option<TypeId> {
        match self {
            Symbol::Type(id) => Some(*id),
            _ => None,
        }
    }
}
