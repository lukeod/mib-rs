//! Enumerations for SMI concepts.
//!
//! Defines the core enums used throughout the MIB parsing and resolution pipeline:
//! severity levels, node kinds, access levels, status values, base types, and
//! configuration knobs for resolver strictness and diagnostic reporting.

use std::fmt;

macro_rules! impl_display {
    ($ty:ident { $($variant:ident => $s:literal),* $(,)? }) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $($ty::$variant => $s),*
                })
            }
        }
    }
}

/// Severity indicates how serious a diagnostic issue is (libsmi-compatible).
/// Lower values are more severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Severity {
    /// Unrecoverable failure that halts processing.
    Fatal = 0,
    /// Serious issue that likely produces incorrect results.
    Severe = 1,
    /// Standard error in the MIB definition.
    Error = 2,
    /// Minor issue that may indicate a problem.
    Minor = 3,
    /// Stylistic deviation from best practice.
    Style = 4,
    /// Potential issue worth noting.
    Warning = 5,
    /// Informational message.
    Info = 6,
}

impl Severity {
    /// Reports whether this severity is at least as severe as `threshold`.
    pub fn at_least(self, threshold: Severity) -> bool {
        self <= threshold
    }
}

impl_display!(Severity {
    Fatal => "fatal",
    Severe => "severe",
    Error => "error",
    Minor => "minor",
    Style => "style",
    Warning => "warning",
    Info => "info",
});

/// Controls resolver fallback behavior when resolving cross-module references.
///
/// Ordered from strictest (fewest fallbacks) to most permissive.
/// See also [`ReportingLevel`] which controls diagnostic output separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResolverStrictness {
    /// No fallbacks. Unresolved references produce errors.
    Strict = 0,
    /// Tier-2 constrained fallbacks enabled (e.g. searching related modules).
    Normal = 1,
    /// All fallbacks enabled, including global symbol search.
    Permissive = 2,
}

impl ResolverStrictness {
    /// Reports whether tier-2 constrained fallbacks are enabled (Normal+).
    pub fn allow_constrained_fallbacks(self) -> bool {
        self != ResolverStrictness::Strict
    }

    /// Reports whether tier-3 global fallbacks are enabled (Permissive only).
    pub fn allow_global_fallbacks(self) -> bool {
        self == ResolverStrictness::Permissive
    }
}

impl_display!(ResolverStrictness {
    Strict => "strict",
    Normal => "normal",
    Permissive => "permissive",
});

/// Controls diagnostic reporting verbosity.
///
/// See also [`ResolverStrictness`] which controls resolver fallback behavior separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReportingLevel {
    /// Suppress all diagnostics except fatal errors.
    Silent = 0,
    /// Report errors and above only.
    Quiet = 1,
    /// Report minor issues and above.
    Default = 2,
    /// Report all diagnostics including style and info.
    Verbose = 3,
}

impl_display!(ReportingLevel {
    Silent => "silent",
    Quiet => "quiet",
    Default => "default",
    Verbose => "verbose",
});

/// Identifies what an OID node represents in the MIB tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Kind {
    /// Kind not yet determined.
    #[default]
    Unknown = 0,
    /// Synthetic internal node (e.g. root of the OID tree).
    Internal = 1,
    /// Plain OID registration (OBJECT IDENTIFIER value assignment).
    Node = 2,
    /// Scalar OBJECT-TYPE (single-instance managed object).
    Scalar = 3,
    /// Table OBJECT-TYPE (SEQUENCE OF).
    Table = 4,
    /// Row OBJECT-TYPE (conceptual row / SEQUENCE entry).
    Row = 5,
    /// Column OBJECT-TYPE (leaf within a row).
    Column = 6,
    /// NOTIFICATION-TYPE or TRAP-TYPE definition.
    Notification = 7,
    /// OBJECT-GROUP or NOTIFICATION-GROUP.
    Group = 8,
    /// MODULE-COMPLIANCE definition.
    Compliance = 9,
    /// AGENT-CAPABILITIES definition.
    Capability = 10,
    /// MODULE-IDENTITY definition.
    ModuleIdentity = 11,
    /// OBJECT-IDENTITY definition.
    ObjectIdentity = 12,
}

impl Kind {
    /// Reports whether this is a scalar/table/row/column.
    pub fn is_object_type(self) -> bool {
        matches!(self, Kind::Scalar | Kind::Table | Kind::Row | Kind::Column)
    }

    /// Reports whether this is a group/compliance/capabilities node.
    pub fn is_conformance(self) -> bool {
        matches!(self, Kind::Group | Kind::Compliance | Kind::Capability)
    }

    /// Reports whether this is a plain node-like kind (node, module-identity, object-identity).
    pub fn is_node_like(self) -> bool {
        matches!(
            self,
            Kind::Node | Kind::ModuleIdentity | Kind::ObjectIdentity
        )
    }
}

impl_display!(Kind {
    Unknown => "unknown",
    Internal => "internal",
    Node => "node",
    Scalar => "scalar",
    Table => "table",
    Row => "row",
    Column => "column",
    Notification => "notification",
    Group => "group",
    Compliance => "compliance",
    Capability => "capabilities",
    ModuleIdentity => "module-identity",
    ObjectIdentity => "object-identity",
});

/// Access level for OBJECT-TYPE definitions.
///
/// Covers both SMIv1 ACCESS and SMIv2 MAX-ACCESS values.
/// See [`AccessKeyword`] for which keyword was used in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Access {
    /// Object cannot be read or written.
    #[default]
    NotAccessible = 0,
    /// Object is only accessible via notifications.
    AccessibleForNotify = 1,
    /// Object can be read but not written.
    ReadOnly = 2,
    /// Object can be read and written.
    ReadWrite = 3,
    /// Object can be read, written, and used in row creation.
    ReadCreate = 4,
    /// Object can only be written (SMIv1 only, deprecated in SMIv2).
    WriteOnly = 5,
    /// Object is not implemented (AGENT-CAPABILITIES variation).
    NotImplemented = 6,
}

impl_display!(Access {
    NotAccessible => "not-accessible",
    AccessibleForNotify => "accessible-for-notify",
    ReadOnly => "read-only",
    ReadWrite => "read-write",
    ReadCreate => "read-create",
    WriteOnly => "write-only",
    NotImplemented => "not-implemented",
});

/// Lifecycle state of a MIB definition.
///
/// SMIv2 uses `Current`, `Deprecated`, and `Obsolete`. SMIv1 additionally uses
/// `Mandatory` and `Optional`. Values are not normalized across versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Status {
    /// Active and valid (SMIv2).
    #[default]
    Current = 0,
    /// Still usable but being phased out.
    Deprecated = 1,
    /// No longer in use.
    Obsolete = 2,
    /// Required for compliance (SMIv1 only).
    Mandatory = 3,
    /// Not required (SMIv1 only).
    Optional = 4,
}

impl Status {
    /// Reports whether this is an SMIv1-specific status value.
    pub fn is_smiv1(self) -> bool {
        matches!(self, Status::Mandatory | Status::Optional)
    }
}

impl_display!(Status {
    Current => "current",
    Deprecated => "deprecated",
    Obsolete => "obsolete",
    Mandatory => "mandatory",
    Optional => "optional",
});

/// SMI language version of a MIB module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Language {
    /// Version not yet determined.
    #[default]
    Unknown = 0,
    /// RFC 1155/1212 (Structure of Management Information v1).
    SMIv1 = 1,
    /// RFC 2578 (Structure of Management Information v2).
    SMIv2 = 2,
    /// RFC 3159 (Structure of Policy Provisioning Information).
    SPPI = 3,
}

impl_display!(Language {
    Unknown => "unknown",
    SMIv1 => "SMIv1",
    SMIv2 => "SMIv2",
    SPPI => "SPPI",
});

/// Fundamental SMI type that a textual convention or [`Kind::Scalar`]/[`Kind::Column`]
/// object ultimately resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum BaseType {
    /// Base type not yet resolved.
    #[default]
    Unknown = 0,
    /// 32-bit signed integer (INTEGER, Integer32).
    Integer32 = 1,
    /// 32-bit unsigned integer (Unsigned32).
    Unsigned32 = 2,
    /// 32-bit monotonically increasing counter.
    Counter32 = 3,
    /// 64-bit monotonically increasing counter.
    Counter64 = 4,
    /// 32-bit non-negative integer that can increase or decrease.
    Gauge32 = 5,
    /// Hundredths of a second since an epoch.
    TimeTicks = 6,
    /// IPv4 address (4 octets).
    IpAddress = 7,
    /// Arbitrary binary or text data.
    OctetString = 8,
    /// ASN.1 OBJECT IDENTIFIER value.
    ObjectIdentifier = 9,
    /// Named bit set.
    Bits = 10,
    /// Opaque data (wraps arbitrary ASN.1).
    Opaque = 11,
    /// SEQUENCE type used for table row definitions.
    Sequence = 12,
    /// 64-bit signed integer (SPPI).
    Integer64 = 13,
    /// 64-bit unsigned integer (SPPI).
    Unsigned64 = 14,
}

impl_display!(BaseType {
    Unknown => "unknown",
    Integer32 => "Integer32",
    Unsigned32 => "Unsigned32",
    Counter32 => "Counter32",
    Counter64 => "Counter64",
    Gauge32 => "Gauge32",
    TimeTicks => "TimeTicks",
    IpAddress => "IpAddress",
    OctetString => "OCTET STRING",
    ObjectIdentifier => "OBJECT IDENTIFIER",
    Bits => "BITS",
    Opaque => "Opaque",
    Sequence => "SEQUENCE",
    Integer64 => "Integer64",
    Unsigned64 => "Unsigned64",
});

/// How an INDEX component maps to instance-identifier sub-identifiers (RFC 2578, section 7.7).
///
/// The encoding depends on the index object's [`BaseType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum IndexEncoding {
    /// Encoding not yet determined.
    #[default]
    Unknown = 0,
    /// Single sub-identifier for integer-valued indexes.
    Integer = 1,
    /// Fixed number of sub-identifiers (SIZE-constrained OCTET STRING).
    FixedString = 2,
    /// Length prefix followed by that many sub-identifiers.
    LengthPrefixed = 3,
    /// Like `FixedString` but length is implied from the end of the OID.
    Implied = 4,
    /// Four sub-identifiers encoding an IPv4 address.
    IpAddress = 5,
}

impl_display!(IndexEncoding {
    Unknown => "unknown",
    Integer => "integer",
    FixedString => "fixed-string",
    LengthPrefixed => "length-prefixed",
    Implied => "implied",
    IpAddress => "ip-address",
});

/// Records which access keyword was used in the source MIB.
///
/// SMIv1 uses `ACCESS`, SMIv2 uses `MAX-ACCESS`, and compliance statements use `MIN-ACCESS`.
/// The resolved access value is stored separately as [`Access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum AccessKeyword {
    /// SMIv1 `ACCESS` clause.
    #[default]
    Access = 0,
    /// SMIv2 `MAX-ACCESS` clause.
    MaxAccess = 1,
    /// `MIN-ACCESS` clause in MODULE-COMPLIANCE refinements.
    MinAccess = 2,
}

impl_display!(AccessKeyword {
    Access => "ACCESS",
    MaxAccess => "MAX-ACCESS",
    MinAccess => "MIN-ACCESS",
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Fatal <= Severity::Info);
        assert!(Severity::Fatal <= Severity::Fatal);
        assert!(Severity::Info > Severity::Fatal);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Fatal.to_string(), "fatal");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn kind_classification() {
        assert!(Kind::Scalar.is_object_type());
        assert!(Kind::Table.is_object_type());
        assert!(Kind::Row.is_object_type());
        assert!(Kind::Column.is_object_type());
        assert!(!Kind::Node.is_object_type());
        assert!(!Kind::Notification.is_object_type());

        assert!(Kind::Group.is_conformance());
        assert!(Kind::Compliance.is_conformance());
        assert!(Kind::Capability.is_conformance());
        assert!(!Kind::Scalar.is_conformance());
    }

    #[test]
    fn status_smiv1() {
        assert!(Status::Mandatory.is_smiv1());
        assert!(Status::Optional.is_smiv1());
        assert!(!Status::Current.is_smiv1());
        assert!(!Status::Deprecated.is_smiv1());
    }
}
