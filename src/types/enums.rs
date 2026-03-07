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
    Fatal = 0,
    Severe = 1,
    Error = 2,
    Minor = 3,
    Style = 4,
    Warning = 5,
    Info = 6,
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

/// StrictnessLevel defines preset strictness configurations.
/// Higher values are stricter and report more diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum StrictnessLevel {
    Silent = 0,
    Permissive = 1,
    Normal = 3,
    Strict = 6,
}

impl_display!(StrictnessLevel {
    Silent => "silent",
    Permissive => "permissive",
    Normal => "normal",
    Strict => "strict",
});

/// Kind identifies what an OID node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Kind {
    #[default]
    Unknown = 0,
    Internal = 1,
    Node = 2,
    Scalar = 3,
    Table = 4,
    Row = 5,
    Column = 6,
    Notification = 7,
    Group = 8,
    Compliance = 9,
    Capability = 10,
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
});

/// Access represents the access level for OBJECT-TYPE definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Access {
    #[default]
    NotAccessible = 0,
    AccessibleForNotify = 1,
    ReadOnly = 2,
    ReadWrite = 3,
    ReadCreate = 4,
    WriteOnly = 5,
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

/// Status represents the lifecycle state of a MIB definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Status {
    #[default]
    Current = 0,
    Deprecated = 1,
    Obsolete = 2,
    Mandatory = 3,
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

/// Language identifies the SMI version of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Language {
    #[default]
    Unknown = 0,
    SMIv1 = 1,
    SMIv2 = 2,
}

impl_display!(Language {
    Unknown => "unknown",
    SMIv1 => "SMIv1",
    SMIv2 => "SMIv2",
});

/// BaseType identifies the fundamental SMI type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum BaseType {
    #[default]
    Unknown = 0,
    Integer32 = 1,
    Unsigned32 = 2,
    Counter32 = 3,
    Counter64 = 4,
    Gauge32 = 5,
    TimeTicks = 6,
    IpAddress = 7,
    OctetString = 8,
    ObjectIdentifier = 9,
    Bits = 10,
    Opaque = 11,
    Sequence = 12,
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
});

/// IndexEncoding classifies how an INDEX component maps to instance-identifier
/// sub-identifiers per RFC 2578 s7.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum IndexEncoding {
    #[default]
    Unknown = 0,
    Integer = 1,
    FixedString = 2,
    LengthPrefixed = 3,
    Implied = 4,
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

/// AccessKeyword records which keyword was used (ACCESS, MAX-ACCESS, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum AccessKeyword {
    #[default]
    Access = 0,
    MaxAccess = 1,
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
        assert!(!(Severity::Info <= Severity::Fatal));
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
