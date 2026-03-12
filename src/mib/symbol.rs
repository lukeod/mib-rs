use crate::types::{Span, Status};

use super::types::*;

/// A reference to any resolved MIB definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbol {
    Object(ObjectId),
    Notification(NotificationId),
    Group(GroupId),
    Compliance(ComplianceId),
    Capability(CapabilityId),
    Type(TypeId),
    Node(NodeId),
}

impl Symbol {
    /// Returns the name of this symbol, looking it up in the appropriate arena.
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

    /// Returns the span of this symbol.
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

    /// Returns the module that defines this symbol.
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

    /// Returns the OID tree node for this symbol, or None for Type symbols.
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

    /// Returns the status of this symbol.
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

    #[must_use]
    pub fn as_object(&self) -> Option<ObjectId> {
        match self {
            Symbol::Object(id) => Some(*id),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_notification(&self) -> Option<NotificationId> {
        match self {
            Symbol::Notification(id) => Some(*id),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_group(&self) -> Option<GroupId> {
        match self {
            Symbol::Group(id) => Some(*id),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_compliance(&self) -> Option<ComplianceId> {
        match self {
            Symbol::Compliance(id) => Some(*id),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_capability(&self) -> Option<CapabilityId> {
        match self {
            Symbol::Capability(id) => Some(*id),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_type(&self) -> Option<TypeId> {
        match self {
            Symbol::Type(id) => Some(*id),
            _ => None,
        }
    }
}
