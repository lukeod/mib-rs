//! Index suffix decoding for SNMP table instance OIDs.
//!
//! When an SNMP agent returns a varbind like `ifDescr.7`, the `.7` is the
//! instance suffix that identifies which table row the value belongs to.
//! The encoding of this suffix is defined by RFC 2578 section 7.7 and
//! depends on the INDEX clause of the table's row object.
//!
//! This module provides [`decode_suffix`] to split raw OID suffix arcs
//! into typed index component values using the row's index metadata.

use std::fmt;
use std::net::Ipv4Addr;

use crate::types::{BaseType, IndexEncoding};

use super::handle::Index;

/// A typed value decoded from OID instance suffix arcs.
///
/// The variant is determined by the index component's [`IndexEncoding`]
/// and base type, following RFC 2578 section 7.7:
///
/// - **Integer types** produce [`Integer`](IndexValue::Integer) (one arc).
/// - **IpAddress** produces [`IpAddress`](IndexValue::IpAddress) (four arcs).
/// - **OCTET STRING / Opaque / BITS** produce
///   [`OctetString`](IndexValue::OctetString), either fixed-length,
///   length-prefixed, or implied.
/// - **OBJECT IDENTIFIER** produces
///   [`ObjectIdentifier`](IndexValue::ObjectIdentifier), either
///   length-prefixed or implied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue {
    /// Single-arc integer index (Integer32, Unsigned32, Gauge32, TimeTicks).
    Integer(u32),
    /// Four-arc IPv4 address, one octet per arc.
    IpAddress([u8; 4]),
    /// Octet string index (fixed-length, length-prefixed, or implied).
    /// Each arc contributes one octet.
    OctetString(Vec<u8>),
    /// Sub-OID index (length-prefixed or implied). Each arc is one
    /// sub-identifier of the OID value.
    ObjectIdentifier(Vec<u32>),
}

impl IndexValue {
    /// Return the integer value if this is an [`Integer`](IndexValue::Integer).
    #[must_use]
    pub fn as_integer(&self) -> Option<u32> {
        match self {
            IndexValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the IPv4 address if this is an [`IpAddress`](IndexValue::IpAddress).
    #[must_use]
    pub fn as_ip_addr(&self) -> Option<Ipv4Addr> {
        match self {
            IndexValue::IpAddress(b) => Some(Ipv4Addr::from(*b)),
            _ => None,
        }
    }

    /// Return the byte slice if this is an [`OctetString`](IndexValue::OctetString).
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            IndexValue::OctetString(v) => Some(v),
            _ => None,
        }
    }

    /// Return the OID arcs if this is an [`ObjectIdentifier`](IndexValue::ObjectIdentifier).
    #[must_use]
    pub fn as_oid(&self) -> Option<&[u32]> {
        match self {
            IndexValue::ObjectIdentifier(v) => Some(v),
            _ => None,
        }
    }
}

impl From<IndexValue> for Option<Ipv4Addr> {
    fn from(v: IndexValue) -> Self {
        v.as_ip_addr()
    }
}

impl fmt::Display for IndexValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexValue::Integer(v) => write!(f, "{v}"),
            IndexValue::IpAddress(ip) => write!(f, "{}", Ipv4Addr::from(*ip)),
            IndexValue::OctetString(bytes) => match std::str::from_utf8(bytes) {
                Ok(s) if s.bytes().all(|b| (0x20..=0x7E).contains(&b)) => f.write_str(s),
                _ => {
                    for (i, b) in bytes.iter().enumerate() {
                        if i > 0 {
                            f.write_str(":")?;
                        }
                        write!(f, "{b:02X}")?;
                    }
                    Ok(())
                }
            },
            IndexValue::ObjectIdentifier(arcs) => {
                for (i, arc) in arcs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    write!(f, "{arc}")?;
                }
                Ok(())
            }
        }
    }
}

/// A single decoded index component from an instance OID suffix.
///
/// Pairs the index component name (from the INDEX clause) with the
/// decoded [`IndexValue`].
#[derive(Debug, Clone)]
pub struct DecodedIndex {
    name: String,
    value: IndexValue,
}

impl DecodedIndex {
    /// The index component name from the INDEX clause (e.g. `"ifIndex"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The decoded value.
    pub fn value(&self) -> &IndexValue {
        &self.value
    }

    /// Consume the decoded index and return the value.
    pub fn into_value(self) -> IndexValue {
        self.value
    }
}

impl fmt::Display for DecodedIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// Decode an OID instance suffix into typed index values.
///
/// Takes the index definitions from a row's effective INDEX clause and
/// the raw suffix arcs (the portion of an instance OID that follows the
/// column or row OID). Returns one [`DecodedIndex`] per successfully
/// decoded component.
///
/// Decoding stops early if:
/// - The suffix arcs are exhausted before all indexes are decoded
/// - An index component has [`IndexEncoding::Unknown`]
/// - A fixed-size index has no determinable SIZE constraint
/// - There are not enough arcs for a component
/// - An octet-valued arc (IpAddress, OCTET STRING) exceeds 255
///
/// # Encoding rules (RFC 2578 section 7.7)
///
/// | Encoding | Arcs consumed | Description |
/// |----------|--------------|-------------|
/// | Integer | 1 | Single sub-identifier |
/// | IpAddress | 4 | One sub-identifier per octet |
/// | FixedString | *n* | *n* = fixed SIZE constraint |
/// | LengthPrefixed | 1 + *n* | First arc is length, then *n* data arcs |
/// | Implied | remainder | All remaining arcs (last index only) |
///
/// # Examples
///
/// ```
/// use mib_rs::mib::index;
///
/// # let source = mib_rs::source::memory(
/// #     "DOC-EXAMPLE-MIB",
/// #     include_bytes!("../../tests/data/doc-example-mib.txt").as_slice(),
/// # );
/// # let mib = mib_rs::Loader::new()
/// #     .source(source)
/// #     .modules(["DOC-EXAMPLE-MIB"])
/// #     .load()
/// #     .expect("example MIB should load");
/// let row = mib.object("docEntry").unwrap();
/// let decoded = index::decode_suffix(row.effective_indexes(), &[42]);
/// assert_eq!(decoded.len(), 1);
/// assert_eq!(decoded[0].name(), "docIndex");
/// assert_eq!(*decoded[0].value(), index::IndexValue::Integer(42));
/// ```
pub fn decode_suffix<'a>(
    indexes: impl Iterator<Item = Index<'a>>,
    suffix: &[u32],
) -> Vec<DecodedIndex> {
    let mut result = Vec::new();
    let mut pos = 0;

    for idx in indexes {
        if pos >= suffix.len() {
            break;
        }

        let (value, consumed) = match idx.encoding() {
            // RFC 2578 s7.7: "integer-valued ... a single sub-identifier
            // taking the integer value"
            IndexEncoding::Integer => (IndexValue::Integer(suffix[pos]), 1),

            // RFC 2578 s7.7: "For an object ... IpAddress, the encoding
            // is four sub-identifiers in the familiar a.b.c.d notation"
            IndexEncoding::IpAddress => {
                if pos + 4 > suffix.len() {
                    break;
                }
                let Some(bytes) = arcs_to_bytes(&suffix[pos..pos + 4]) else {
                    break;
                };
                (
                    IndexValue::IpAddress([bytes[0], bytes[1], bytes[2], bytes[3]]),
                    4,
                )
            }

            // RFC 2578 s7.7: fixed-length strings use exactly SIZE
            // sub-identifiers, one per octet, no length prefix.
            IndexEncoding::FixedString => {
                let size = fixed_size(&idx);
                if size == 0 || pos + size > suffix.len() {
                    break;
                }
                let Some(bytes) = arcs_to_bytes(&suffix[pos..pos + size]) else {
                    break;
                };
                (IndexValue::OctetString(bytes), size)
            }

            // RFC 2578 s7.7: "For ... variable-length strings ... the
            // encoding is ... n+1 sub-identifiers, where the first
            // sub-identifier is n itself"
            IndexEncoding::LengthPrefixed => {
                let len = suffix[pos] as usize;
                if pos + 1 + len > suffix.len() {
                    break;
                }
                let data = &suffix[pos + 1..pos + 1 + len];
                let base = idx.ty().map(|t| t.effective_base());
                if base == Some(BaseType::ObjectIdentifier) {
                    (IndexValue::ObjectIdentifier(data.to_vec()), 1 + len)
                } else {
                    let Some(bytes) = arcs_to_bytes(data) else {
                        break;
                    };
                    (IndexValue::OctetString(bytes), 1 + len)
                }
            }

            // RFC 2578 s7.7: "use of the IMPLIED keyword ... the
            // sub-identifiers ... are not preceded by the number"
            // Only valid for the last index component.
            IndexEncoding::Implied => {
                let remaining = &suffix[pos..];
                let base = idx.ty().map(|t| t.effective_base());
                if base == Some(BaseType::ObjectIdentifier) {
                    (
                        IndexValue::ObjectIdentifier(remaining.to_vec()),
                        remaining.len(),
                    )
                } else {
                    let Some(bytes) = arcs_to_bytes(remaining) else {
                        break;
                    };
                    (IndexValue::OctetString(bytes), remaining.len())
                }
            }

            IndexEncoding::Unknown => break,
        };

        result.push(DecodedIndex {
            name: idx.name().to_string(),
            value,
        });
        pos += consumed;
    }

    result
}

/// Convert OID arcs to bytes, returning `None` if any arc exceeds 255.
fn arcs_to_bytes(arcs: &[u32]) -> Option<Vec<u8>> {
    arcs.iter().map(|&a| u8::try_from(a).ok()).collect()
}

/// Extract the fixed size from an index component's SIZE constraint.
///
/// Prefers the object's effective sizes (matching how the encoding was
/// classified during resolution), falling back to the type chain.
/// Returns 0 if the size cannot be determined.
fn fixed_size(idx: &Index<'_>) -> usize {
    let sizes = if let Some(obj) = idx.object() {
        let s = obj.effective_sizes();
        if !s.is_empty() {
            s
        } else {
            idx.ty().map_or(&[][..], |t| t.effective_sizes())
        }
    } else {
        idx.ty().map_or(&[][..], |t| t.effective_sizes())
    };
    if super::types::is_fixed_size(sizes) {
        sizes[0].min as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_test_mib() -> crate::Mib {
        let source = crate::source::memory(
            "INDEX-TEST-MIB",
            include_bytes!("../../tests/data/index-test-mib.txt").as_slice(),
        );
        crate::Loader::new()
            .source(source)
            .modules(["INDEX-TEST-MIB"])
            .load()
            .expect("INDEX-TEST-MIB should load")
    }

    #[test]
    fn integer_index() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        let decoded = decode_suffix(row.effective_indexes(), &[42]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "simpleIndex");
        assert_eq!(*decoded[0].value(), IndexValue::Integer(42));
    }

    #[test]
    fn ip_address_index() {
        let mib = load_test_mib();
        let row = mib.object("ipEntry").unwrap();
        let decoded = decode_suffix(row.effective_indexes(), &[10, 0, 1, 99]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "ipAddr");
        assert_eq!(*decoded[0].value(), IndexValue::IpAddress([10, 0, 1, 99]));
        assert_eq!(decoded[0].value().to_string(), "10.0.1.99");
    }

    #[test]
    fn fixed_string_index() {
        let mib = load_test_mib();
        let row = mib.object("fixedEntry").unwrap();
        // MAC address AA:BB:CC:DD:EE:FF -> 6 arcs
        let decoded = decode_suffix(
            row.effective_indexes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        );
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "fixedAddr");
        assert_eq!(
            *decoded[0].value(),
            IndexValue::OctetString(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
        assert_eq!(decoded[0].value().to_string(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn variable_string_index_length_prefixed() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        // "eth0" = 4 chars, length-prefixed: [4, 101, 116, 104, 48]
        let decoded = decode_suffix(row.effective_indexes(), &[4, 101, 116, 104, 48]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "varName");
        assert_eq!(
            *decoded[0].value(),
            IndexValue::OctetString(vec![101, 116, 104, 48])
        );
        assert_eq!(decoded[0].value().to_string(), "eth0");
    }

    #[test]
    fn variable_string_index_empty() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        // Empty string: length prefix = 0
        let decoded = decode_suffix(row.effective_indexes(), &[0]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "varName");
        assert_eq!(*decoded[0].value(), IndexValue::OctetString(vec![]));
    }

    #[test]
    fn multi_index_integer_and_ip() {
        let mib = load_test_mib();
        let row = mib.object("multiEntry").unwrap();
        // slot=3, addr=192.168.1.1
        let decoded = decode_suffix(row.effective_indexes(), &[3, 192, 168, 1, 1]);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].name(), "multiSlot");
        assert_eq!(*decoded[0].value(), IndexValue::Integer(3));
        assert_eq!(decoded[1].name(), "multiAddr");
        assert_eq!(*decoded[1].value(), IndexValue::IpAddress([192, 168, 1, 1]));
    }

    #[test]
    fn implied_string_index() {
        let mib = load_test_mib();
        let row = mib.object("impliedEntry").unwrap();
        // "test" without length prefix (IMPLIED)
        let decoded = decode_suffix(row.effective_indexes(), &[116, 101, 115, 116]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "impliedName");
        assert_eq!(
            *decoded[0].value(),
            IndexValue::OctetString(vec![116, 101, 115, 116])
        );
        assert_eq!(decoded[0].value().to_string(), "test");
    }

    #[test]
    fn oid_index_length_prefixed() {
        let mib = load_test_mib();
        let row = mib.object("oidEntry").unwrap();
        // OID 1.3.6.1 = 4 arcs, length-prefixed: [4, 1, 3, 6, 1]
        let decoded = decode_suffix(row.effective_indexes(), &[4, 1, 3, 6, 1]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "oidIndex");
        assert_eq!(
            *decoded[0].value(),
            IndexValue::ObjectIdentifier(vec![1, 3, 6, 1])
        );
        assert_eq!(decoded[0].value().to_string(), "1.3.6.1");
    }

    #[test]
    fn implied_oid_index() {
        let mib = load_test_mib();
        let row = mib.object("impliedOidEntry").unwrap();
        // OID 1.3.6.1.4 without length prefix (IMPLIED)
        let decoded = decode_suffix(row.effective_indexes(), &[1, 3, 6, 1, 4]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "impliedOidIndex");
        assert_eq!(
            *decoded[0].value(),
            IndexValue::ObjectIdentifier(vec![1, 3, 6, 1, 4])
        );
    }

    #[test]
    fn insufficient_arcs_stops_early() {
        let mib = load_test_mib();
        let row = mib.object("ipEntry").unwrap();
        // IpAddress needs 4 arcs, only 2 provided
        let decoded = decode_suffix(row.effective_indexes(), &[10, 0]);
        assert!(decoded.is_empty());
    }

    #[test]
    fn empty_suffix_returns_empty() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        let decoded = decode_suffix(row.effective_indexes(), &[]);
        assert!(decoded.is_empty());
    }

    #[test]
    fn extra_arcs_are_ignored() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        // One integer index, extra arcs beyond it
        let decoded = decode_suffix(row.effective_indexes(), &[42, 99, 100]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(*decoded[0].value(), IndexValue::Integer(42));
    }

    #[test]
    fn multi_index_partial_decode() {
        let mib = load_test_mib();
        let row = mib.object("multiEntry").unwrap();
        // slot=3, then only 2 arcs for IP (needs 4) -> partial
        let decoded = decode_suffix(row.effective_indexes(), &[3, 10, 0]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(*decoded[0].value(), IndexValue::Integer(3));
    }

    #[test]
    fn length_prefixed_truncated_stops() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        // Length says 10 but only 3 data arcs follow
        let decoded = decode_suffix(row.effective_indexes(), &[10, 65, 66, 67]);
        assert!(decoded.is_empty());
    }

    #[test]
    fn display_format() {
        assert_eq!(IndexValue::Integer(42).to_string(), "42");
        assert_eq!(
            IndexValue::IpAddress([192, 168, 1, 1]).to_string(),
            "192.168.1.1"
        );
        assert_eq!(
            IndexValue::OctetString(b"eth0".to_vec()).to_string(),
            "eth0"
        );
        assert_eq!(
            IndexValue::OctetString(vec![0x00, 0xFF]).to_string(),
            "00:FF"
        );
        assert_eq!(
            IndexValue::ObjectIdentifier(vec![1, 3, 6, 1]).to_string(),
            "1.3.6.1"
        );
    }

    #[test]
    fn accessor_as_integer() {
        assert_eq!(IndexValue::Integer(42).as_integer(), Some(42));
        assert_eq!(IndexValue::IpAddress([1, 2, 3, 4]).as_integer(), None);
    }

    #[test]
    fn accessor_as_ip_addr() {
        let val = IndexValue::IpAddress([192, 168, 1, 1]);
        assert_eq!(val.as_ip_addr(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(IndexValue::Integer(0).as_ip_addr(), None);
    }

    #[test]
    fn accessor_as_bytes() {
        let val = IndexValue::OctetString(vec![1, 2, 3]);
        assert_eq!(val.as_bytes(), Some(&[1, 2, 3][..]));
        assert_eq!(IndexValue::Integer(0).as_bytes(), None);
    }

    #[test]
    fn accessor_as_oid() {
        let val = IndexValue::ObjectIdentifier(vec![1, 3, 6, 1]);
        assert_eq!(val.as_oid(), Some(&[1, 3, 6, 1][..]));
        assert_eq!(IndexValue::Integer(0).as_oid(), None);
    }

    #[test]
    fn into_value() {
        let di = DecodedIndex {
            name: "ifIndex".to_string(),
            value: IndexValue::Integer(7),
        };
        assert_eq!(di.into_value(), IndexValue::Integer(7));
    }

    #[test]
    fn decoded_index_display() {
        let di = DecodedIndex {
            name: "ifIndex".to_string(),
            value: IndexValue::Integer(7),
        };
        assert_eq!(di.to_string(), "ifIndex=7");
    }

    #[test]
    fn lookup_instance_decode() {
        let mib = load_test_mib();
        let oid = mib.resolve_oid("simpleValue.42").unwrap();
        let lookup = mib.lookup_instance(&oid);
        assert_eq!(lookup.node().name(), "simpleValue");
        assert_eq!(lookup.suffix(), &[42]);
        let decoded = lookup.decode_indexes();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "simpleIndex");
        assert_eq!(*decoded[0].value(), IndexValue::Integer(42));
    }

    #[test]
    fn lookup_instance_decode_non_column() {
        let mib = load_test_mib();
        // Table OID with no instance suffix -> empty decode
        let oid = mib.resolve_oid("simpleTable").unwrap();
        let lookup = mib.lookup_instance(&oid);
        assert!(lookup.decode_indexes().is_empty());
    }
}
