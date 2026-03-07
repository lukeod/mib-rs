use std::fmt;

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

impl Severity {
    /// Reports whether self is at least as severe as other.
    /// Lower numeric values are more severe (Fatal=0, Info=6).
    pub fn at_least(self, other: Severity) -> bool {
        (self as u8) <= (other as u8)
    }

    pub fn names() -> &'static [&'static str] {
        &[
            "fatal", "severe", "error", "minor", "style", "warning", "info",
        ]
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Severity::Fatal => "fatal",
            Severity::Severe => "severe",
            Severity::Error => "error",
            Severity::Minor => "minor",
            Severity::Style => "style",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        f.write_str(name)
    }
}

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

impl fmt::Display for StrictnessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            StrictnessLevel::Silent => "silent",
            StrictnessLevel::Permissive => "permissive",
            StrictnessLevel::Normal => "normal",
            StrictnessLevel::Strict => "strict",
        };
        f.write_str(name)
    }
}

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

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Kind::Unknown => "unknown",
            Kind::Internal => "internal",
            Kind::Node => "node",
            Kind::Scalar => "scalar",
            Kind::Table => "table",
            Kind::Row => "row",
            Kind::Column => "column",
            Kind::Notification => "notification",
            Kind::Group => "group",
            Kind::Compliance => "compliance",
            Kind::Capability => "capabilities",
        };
        f.write_str(name)
    }
}

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

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Access::NotAccessible => "not-accessible",
            Access::AccessibleForNotify => "accessible-for-notify",
            Access::ReadOnly => "read-only",
            Access::ReadWrite => "read-write",
            Access::ReadCreate => "read-create",
            Access::WriteOnly => "write-only",
            Access::NotImplemented => "not-implemented",
        };
        f.write_str(name)
    }
}

impl Access {
    pub fn names() -> &'static [&'static str] {
        &[
            "not-accessible",
            "accessible-for-notify",
            "read-only",
            "read-write",
            "read-create",
            "write-only",
            "not-implemented",
        ]
    }
}

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

    pub fn names() -> &'static [&'static str] {
        &["current", "deprecated", "obsolete", "mandatory", "optional"]
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Status::Current => "current",
            Status::Deprecated => "deprecated",
            Status::Obsolete => "obsolete",
            Status::Mandatory => "mandatory",
            Status::Optional => "optional",
        };
        f.write_str(name)
    }
}

/// Language identifies the SMI version of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Language {
    #[default]
    Unknown = 0,
    SMIv1 = 1,
    SMIv2 = 2,
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Language::Unknown => "unknown",
            Language::SMIv1 => "SMIv1",
            Language::SMIv2 => "SMIv2",
        };
        f.write_str(name)
    }
}

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

impl fmt::Display for BaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            BaseType::Unknown => "unknown",
            BaseType::Integer32 => "Integer32",
            BaseType::Unsigned32 => "Unsigned32",
            BaseType::Counter32 => "Counter32",
            BaseType::Counter64 => "Counter64",
            BaseType::Gauge32 => "Gauge32",
            BaseType::TimeTicks => "TimeTicks",
            BaseType::IpAddress => "IpAddress",
            BaseType::OctetString => "OCTET STRING",
            BaseType::ObjectIdentifier => "OBJECT IDENTIFIER",
            BaseType::Bits => "BITS",
            BaseType::Opaque => "Opaque",
            BaseType::Sequence => "SEQUENCE",
        };
        f.write_str(name)
    }
}

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

impl fmt::Display for IndexEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            IndexEncoding::Unknown => "unknown",
            IndexEncoding::Integer => "integer",
            IndexEncoding::FixedString => "fixed-string",
            IndexEncoding::LengthPrefixed => "length-prefixed",
            IndexEncoding::Implied => "implied",
            IndexEncoding::IpAddress => "ip-address",
        };
        f.write_str(name)
    }
}

/// AccessKeyword records which keyword was used (ACCESS, MAX-ACCESS, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum AccessKeyword {
    #[default]
    Access = 0,
    MaxAccess = 1,
    MinAccess = 2,
}

impl fmt::Display for AccessKeyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            AccessKeyword::Access => "ACCESS",
            AccessKeyword::MaxAccess => "MAX-ACCESS",
            AccessKeyword::MinAccess => "MIN-ACCESS",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Fatal.at_least(Severity::Info));
        assert!(Severity::Fatal.at_least(Severity::Fatal));
        assert!(!Severity::Info.at_least(Severity::Fatal));
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
