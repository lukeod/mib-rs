//! Resolved MIB model and query API.
//!
//! The top-level [`Mib`] container holds the OID tree, all entity arenas,
//! and lookup indices built during resolution. Query it through borrowed
//! handle types ([`Node`], [`Object`], [`Type`], [`Module`], etc.) or
//! drop to the [`raw`] view for arena-id-level access.
//!
//! # Handle types
//!
//! Most interaction goes through lightweight borrowed handles that carry a
//! `&Mib` reference. They provide navigation methods that return further
//! handles, so you rarely need to work with arena ids directly.
//!
//! The available handles are:
//! - [`Node`] - an OID tree node (may carry an object, notification, etc.)
//! - [`Object`] - an OBJECT-TYPE definition
//! - [`Type`] - a type or TEXTUAL-CONVENTION definition
//! - [`Module`] - a loaded MIB module
//! - [`Notification`] - a NOTIFICATION-TYPE or TRAP-TYPE definition
//! - [`Group`] - an OBJECT-GROUP or NOTIFICATION-GROUP
//! - [`Compliance`] - a MODULE-COMPLIANCE definition
//! - [`Capability`] - an AGENT-CAPABILITIES definition
//! - [`Index`] - an index component of a table row

pub mod capability;
pub mod compliance;
pub mod group;
pub mod handle;
#[allow(clippy::module_inception)]
pub mod mib;
pub mod module;
pub mod node;
pub mod notification;
pub mod object;
pub mod oid;
pub mod raw;
pub mod symbol;
pub mod typedef;
pub mod types;

pub(crate) mod resolver;

pub use handle::{Capability, Compliance, Group, Index, Module, Node, Notification, Object, Type};
pub use mib::{Mib, ResolveOidError};
pub use module::ModuleData;
pub use node::{NodeData, OidTree};
pub use notification::NotificationData;
pub use object::ObjectData;
pub use oid::{Oid, ParseOidError};
pub use raw::RawMib;
pub use symbol::Symbol;
pub use typedef::TypeData;
pub use types::*;
pub use {capability::CapabilityData, compliance::ComplianceData, group::GroupData};
