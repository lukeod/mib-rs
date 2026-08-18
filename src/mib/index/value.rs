//! Semantic values accepted and produced by index schemas.

use std::fmt;
use std::net::Ipv4Addr;

use crate::mib::Oid;

/// Stable semantic kind of an index value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IndexValueKind {
    /// A non-negative `Integer32` value encoded in one OID arc.
    Integer32,
    /// An `Unsigned32` value encoded in one OID arc.
    Unsigned32,
    /// A `Gauge32` value encoded in one OID arc.
    Gauge32,
    /// A `TimeTicks` value encoded in one OID arc.
    TimeTicks,
    /// A compatibility `Counter32` value encoded in one OID arc.
    Counter32,
    /// An IPv4 address encoded as four octet-valued arcs.
    IpAddress,
    /// An `OCTET STRING` value.
    OctetString,
    /// A `BITS` value represented by its encoded octets.
    Bits,
    /// An `Opaque` value represented by its octets.
    Opaque,
    /// An `OBJECT IDENTIFIER` value represented by its arcs.
    ObjectIdentifier,
}

impl fmt::Display for IndexValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Owned semantic table-index value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexValue {
    /// Stores a non-negative `Integer32` value.
    Integer32(i32),
    /// Stores an `Unsigned32` value.
    Unsigned32(u32),
    /// Stores a `Gauge32` value.
    Gauge32(u32),
    /// Stores a `TimeTicks` value.
    TimeTicks(u32),
    /// Stores a compatibility `Counter32` value.
    Counter32(u32),
    /// Stores the four octets of an IPv4 address.
    IpAddress([u8; 4]),
    /// Stores the octets of an `OCTET STRING` value.
    OctetString(Vec<u8>),
    /// Stores the encoded octets of a `BITS` value.
    Bits(Vec<u8>),
    /// Stores the octets of an `Opaque` value.
    Opaque(Vec<u8>),
    /// Stores the arcs of an `OBJECT IDENTIFIER` value.
    ObjectIdentifier(Oid),
}

impl IndexValue {
    /// Semantic kind of this value.
    #[must_use]
    pub const fn kind(&self) -> IndexValueKind {
        match self {
            Self::Integer32(_) => IndexValueKind::Integer32,
            Self::Unsigned32(_) => IndexValueKind::Unsigned32,
            Self::Gauge32(_) => IndexValueKind::Gauge32,
            Self::TimeTicks(_) => IndexValueKind::TimeTicks,
            Self::Counter32(_) => IndexValueKind::Counter32,
            Self::IpAddress(_) => IndexValueKind::IpAddress,
            Self::OctetString(_) => IndexValueKind::OctetString,
            Self::Bits(_) => IndexValueKind::Bits,
            Self::Opaque(_) => IndexValueKind::Opaque,
            Self::ObjectIdentifier(_) => IndexValueKind::ObjectIdentifier,
        }
    }

    /// Borrow this value without allocating.
    #[must_use]
    pub fn as_ref(&self) -> IndexValueRef<'_> {
        self.into()
    }
}

/// Borrowed semantic table-index value used by canonical encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexValueRef<'a> {
    /// Borrows no data for a non-negative `Integer32` value.
    Integer32(i32),
    /// Borrows no data for an `Unsigned32` value.
    Unsigned32(u32),
    /// Borrows no data for a `Gauge32` value.
    Gauge32(u32),
    /// Borrows no data for a `TimeTicks` value.
    TimeTicks(u32),
    /// Borrows no data for a compatibility `Counter32` value.
    Counter32(u32),
    /// Borrows no data for the four octets of an IPv4 address.
    IpAddress([u8; 4]),
    /// Borrows the octets of an `OCTET STRING` value.
    OctetString(&'a [u8]),
    /// Borrows the encoded octets of a `BITS` value.
    Bits(&'a [u8]),
    /// Borrows the octets of an `Opaque` value.
    Opaque(&'a [u8]),
    /// Borrows the arcs of an `OBJECT IDENTIFIER` value.
    ObjectIdentifier(&'a [u32]),
}

impl IndexValueRef<'_> {
    /// Semantic kind of this value.
    #[must_use]
    pub const fn kind(self) -> IndexValueKind {
        match self {
            Self::Integer32(_) => IndexValueKind::Integer32,
            Self::Unsigned32(_) => IndexValueKind::Unsigned32,
            Self::Gauge32(_) => IndexValueKind::Gauge32,
            Self::TimeTicks(_) => IndexValueKind::TimeTicks,
            Self::Counter32(_) => IndexValueKind::Counter32,
            Self::IpAddress(_) => IndexValueKind::IpAddress,
            Self::OctetString(_) => IndexValueKind::OctetString,
            Self::Bits(_) => IndexValueKind::Bits,
            Self::Opaque(_) => IndexValueKind::Opaque,
            Self::ObjectIdentifier(_) => IndexValueKind::ObjectIdentifier,
        }
    }
}

impl<'a> From<&'a IndexValue> for IndexValueRef<'a> {
    fn from(value: &'a IndexValue) -> Self {
        match value {
            IndexValue::Integer32(value) => Self::Integer32(*value),
            IndexValue::Unsigned32(value) => Self::Unsigned32(*value),
            IndexValue::Gauge32(value) => Self::Gauge32(*value),
            IndexValue::TimeTicks(value) => Self::TimeTicks(*value),
            IndexValue::Counter32(value) => Self::Counter32(*value),
            IndexValue::IpAddress(value) => Self::IpAddress(*value),
            IndexValue::OctetString(value) => Self::OctetString(value),
            IndexValue::Bits(value) => Self::Bits(value),
            IndexValue::Opaque(value) => Self::Opaque(value),
            IndexValue::ObjectIdentifier(value) => Self::ObjectIdentifier(value),
        }
    }
}

impl fmt::Display for IndexValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer32(value) => write!(f, "{value}"),
            Self::Unsigned32(value)
            | Self::Gauge32(value)
            | Self::TimeTicks(value)
            | Self::Counter32(value) => write!(f, "{value}"),
            Self::IpAddress(value) => write!(f, "{}", Ipv4Addr::from(*value)),
            Self::OctetString(value) | Self::Bits(value) | Self::Opaque(value) => {
                format_octets(value, f)
            }
            Self::ObjectIdentifier(value) => value.fmt(f),
        }
    }
}

fn format_octets(value: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match std::str::from_utf8(value) {
        Ok(text) if text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) => f.write_str(text),
        _ => {
            for (position, byte) in value.iter().enumerate() {
                if position != 0 {
                    f.write_str(":")?;
                }
                write!(f, "{byte:02X}")?;
            }
            Ok(())
        }
    }
}
