//! Index suffix decoding for SNMP table instance OIDs.
//!
//! When an SNMP agent returns a varbind like `ifDescr.7`, the `.7` is the
//! instance suffix that identifies which table row the value belongs to.
//! The encoding of this suffix is defined by RFC 2578 section 7.7 and
//! depends on the INDEX clause of the table's row object.
//!
//! Use [`decode_suffix_exact`] when an incomplete or malformed suffix must not
//! be mistaken for a complete row index. [`decode_suffix_prefix`] retains the
//! historical best-effort behavior for callers that deliberately want only
//! the successfully decoded prefix.

use std::fmt;
use std::net::Ipv4Addr;
use std::ops::Range;

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

/// Default bounds for exact index-suffix decoding.
pub const DEFAULT_INDEX_DECODE_LIMITS: IndexDecodeLimits = IndexDecodeLimits::new(64, 4096);

/// Allocation bounds applied by exact index-suffix decoding.
///
/// Raw suffix and remaining arcs are borrowed rather than copied. These limits
/// bound the number of owned component records and the number of arcs copied
/// into any decoded string or object-identifier value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexDecodeLimits {
    max_components: usize,
    max_value_arcs: usize,
}

impl IndexDecodeLimits {
    /// Construct limits for component records and value arcs.
    #[must_use]
    pub const fn new(max_components: usize, max_value_arcs: usize) -> Self {
        Self {
            max_components,
            max_value_arcs,
        }
    }

    /// Maximum number of decoded index components.
    #[must_use]
    pub const fn max_components(self) -> usize {
        self.max_components
    }

    /// Maximum arcs copied into one string or object-identifier value.
    #[must_use]
    pub const fn max_value_arcs(self) -> usize {
        self.max_value_arcs
    }
}

impl Default for IndexDecodeLimits {
    fn default() -> Self {
        DEFAULT_INDEX_DECODE_LIMITS
    }
}

/// One component produced by exact index-suffix decoding.
///
/// The raw arcs borrow the caller's suffix and include any length prefix, so
/// callers can retain the precise wire representation without another copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactDecodedIndex<'a> {
    name: String,
    value: IndexValue,
    arc_range: Range<usize>,
    raw_arcs: &'a [u32],
}

impl<'a> ExactDecodedIndex<'a> {
    /// The index component name from the INDEX clause.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The decoded value.
    #[must_use]
    pub fn value(&self) -> &IndexValue {
        &self.value
    }

    /// Half-open range occupied by this component in the complete suffix.
    #[must_use]
    pub fn arc_range(&self) -> Range<usize> {
        self.arc_range.clone()
    }

    /// Exact encoded arcs consumed by this component.
    #[must_use]
    pub fn raw_arcs(&self) -> &'a [u32] {
        self.raw_arcs
    }

    /// Consume the component and return its decoded value.
    #[must_use]
    pub fn into_value(self) -> IndexValue {
        self.value
    }
}

/// Complete, exact decoding of an index suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactIndexDecode<'a> {
    components: Vec<ExactDecodedIndex<'a>>,
    consumed_arc_range: Range<usize>,
    remaining_arcs: &'a [u32],
}

impl<'a> ExactIndexDecode<'a> {
    /// Ordered decoded components.
    #[must_use]
    pub fn components(&self) -> &[ExactDecodedIndex<'a>] {
        &self.components
    }

    /// Half-open range consumed from the supplied suffix.
    #[must_use]
    pub fn consumed_arc_range(&self) -> Range<usize> {
        self.consumed_arc_range.clone()
    }

    /// Arcs left after decoding. This is empty for every exact success.
    #[must_use]
    pub fn remaining_arcs(&self) -> &'a [u32] {
        self.remaining_arcs
    }

    /// Consume the report and return its ordered components.
    #[must_use]
    pub fn into_components(self) -> Vec<ExactDecodedIndex<'a>> {
        self.components
    }
}

/// Identity of the index component whose decoding failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailingIndexComponent {
    position: usize,
    name: String,
}

impl FailingIndexComponent {
    /// Zero-based position in the effective INDEX clause.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Component name from the effective INDEX clause.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Typed reason that exact index-suffix decoding failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexDecodeErrorKind {
    /// The suffix ended before the current component was complete.
    #[error("truncated component: expected {expected_arcs} arcs, found {available_arcs}")]
    Truncated {
        /// Required arcs for this component, including a length prefix.
        expected_arcs: usize,
        /// Arcs available from the start of this component.
        available_arcs: usize,
    },
    /// A length prefix exceeds the configured per-value bound.
    #[error("malformed length {declared_arcs}: limit is {max_arcs} arcs")]
    MalformedLength {
        /// Length declared by the suffix.
        declared_arcs: u32,
        /// Configured maximum value length.
        max_arcs: usize,
    },
    /// A fixed or implied value exceeds the configured per-value bound.
    #[error("component requires {required_arcs} value arcs: limit is {max_arcs}")]
    ValueTooLong {
        /// Required number of value arcs.
        required_arcs: usize,
        /// Configured maximum value length.
        max_arcs: usize,
    },
    /// The effective INDEX clause exceeds the configured component bound.
    #[error("component count exceeds limit of {max_components}")]
    TooManyComponents {
        /// Configured maximum component count.
        max_components: usize,
    },
    /// An octet-valued component contains an arc above 255.
    #[error("arc {arc_offset} has value {value}, which is not an octet")]
    InvalidOctet {
        /// Absolute offset in the supplied suffix.
        arc_offset: usize,
        /// Invalid arc value.
        value: u32,
    },
    /// No wire encoding could be derived for the component.
    #[error("component has unknown index encoding")]
    UnknownEncoding,
    /// A fixed string has no valid, determinable positive size.
    #[error("fixed string has no valid size constraint")]
    InvalidFixedSize,
    /// IMPLIED was used before the final index component.
    #[error("IMPLIED component is not the final index")]
    ImpliedNotLast,
    /// All index components decoded but arcs remained.
    #[error("trailing arcs after the final index component")]
    TrailingArcs,
}

/// Failure report from exact index-suffix decoding.
///
/// Successfully decoded components and the unconsumed suffix are retained.
/// Trailing arcs have no failing component; all component-specific failures do.
#[derive(Debug, Clone)]
pub struct IndexDecodeError<'a> {
    decoded_components: Vec<ExactDecodedIndex<'a>>,
    failing_component: Option<FailingIndexComponent>,
    kind: IndexDecodeErrorKind,
    consumed_arc_range: Range<usize>,
    remaining_arcs: &'a [u32],
}

impl<'a> IndexDecodeError<'a> {
    /// Components decoded completely before the failure.
    #[must_use]
    pub fn decoded_components(&self) -> &[ExactDecodedIndex<'a>] {
        &self.decoded_components
    }

    /// Component that failed, or `None` when the failure is trailing arcs.
    #[must_use]
    pub fn failing_component(&self) -> Option<&FailingIndexComponent> {
        self.failing_component.as_ref()
    }

    /// Typed failure reason.
    #[must_use]
    pub fn kind(&self) -> &IndexDecodeErrorKind {
        &self.kind
    }

    /// Half-open range consumed before the failing component or trailing arcs.
    #[must_use]
    pub fn consumed_arc_range(&self) -> Range<usize> {
        self.consumed_arc_range.clone()
    }

    /// Unconsumed arcs beginning at the failing component or trailing data.
    #[must_use]
    pub fn remaining_arcs(&self) -> &'a [u32] {
        self.remaining_arcs
    }
}

impl fmt::Display for IndexDecodeError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(component) = &self.failing_component {
            write!(
                f,
                "failed to decode index component {} ({}) at suffix arc {}: {}",
                component.position, component.name, self.consumed_arc_range.end, self.kind
            )
        } else {
            write!(
                f,
                "failed to decode index suffix at arc {}: {}",
                self.consumed_arc_range.end, self.kind
            )
        }
    }
}

impl std::error::Error for IndexDecodeError<'_> {}

/// Decode a complete OID instance suffix with bounded allocation.
///
/// Exact success requires every effective index component and every suffix arc
/// to be consumed. Each component retains its half-open arc range and borrows
/// its exact raw encoding. Failures retain the successfully decoded prefix,
/// unconsumed arcs, typed reason, and (except for trailing arcs) the failing
/// component.
///
/// [`DEFAULT_INDEX_DECODE_LIMITS`] bounds owned allocations. Use
/// [`decode_suffix_exact_with_limits`] to supply application-specific bounds.
///
/// # Example
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
/// let suffix = [42];
/// let decoded = index::decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();
/// assert_eq!(decoded.components()[0].name(), "docIndex");
/// assert_eq!(decoded.components()[0].raw_arcs(), &[42]);
/// assert!(decoded.remaining_arcs().is_empty());
/// ```
pub fn decode_suffix_exact<'m, 's>(
    indexes: impl Iterator<Item = Index<'m>>,
    suffix: &'s [u32],
) -> Result<ExactIndexDecode<'s>, IndexDecodeError<'s>> {
    decode_suffix_exact_with_limits(indexes, suffix, DEFAULT_INDEX_DECODE_LIMITS)
}

/// Decode a complete OID instance suffix using explicit allocation bounds.
pub fn decode_suffix_exact_with_limits<'m, 's>(
    indexes: impl Iterator<Item = Index<'m>>,
    suffix: &'s [u32],
    limits: IndexDecodeLimits,
) -> Result<ExactIndexDecode<'s>, IndexDecodeError<'s>> {
    let mut indexes = indexes.peekable();
    let mut components = Vec::new();
    let mut pos = 0;
    let mut component_position = 0;

    while let Some(idx) = indexes.next() {
        if component_position >= limits.max_components {
            return Err(component_error(
                components,
                idx,
                component_position,
                IndexDecodeErrorKind::TooManyComponents {
                    max_components: limits.max_components,
                },
                pos,
                suffix,
            ));
        }

        let start = pos;
        let available = suffix.len().saturating_sub(start);
        let (value, consumed) = match idx.encoding() {
            IndexEncoding::Integer => {
                let Some(&arc) = suffix.get(start) else {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::Truncated {
                            expected_arcs: 1,
                            available_arcs: 0,
                        },
                        pos,
                        suffix,
                    ));
                };
                (IndexValue::Integer(arc), 1)
            }
            IndexEncoding::IpAddress => {
                if available < 4 {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::Truncated {
                            expected_arcs: 4,
                            available_arcs: available,
                        },
                        pos,
                        suffix,
                    ));
                }
                let data = &suffix[start..start + 4];
                if let Some((offset, value)) = invalid_octet(data) {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::InvalidOctet {
                            arc_offset: start + offset,
                            value,
                        },
                        pos,
                        suffix,
                    ));
                }
                let bytes = std::array::from_fn(|offset| data[offset] as u8);
                (IndexValue::IpAddress(bytes), 4)
            }
            IndexEncoding::FixedString => {
                let (size, valid) = idx.fixed_size();
                if !valid || size == 0 {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::InvalidFixedSize,
                        pos,
                        suffix,
                    ));
                }
                if size > limits.max_value_arcs {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::ValueTooLong {
                            required_arcs: size,
                            max_arcs: limits.max_value_arcs,
                        },
                        pos,
                        suffix,
                    ));
                }
                if available < size {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::Truncated {
                            expected_arcs: size,
                            available_arcs: available,
                        },
                        pos,
                        suffix,
                    ));
                }
                let data = &suffix[start..start + size];
                if let Some((offset, value)) = invalid_octet(data) {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::InvalidOctet {
                            arc_offset: start + offset,
                            value,
                        },
                        pos,
                        suffix,
                    ));
                }
                (IndexValue::OctetString(arcs_to_bytes(data).unwrap()), size)
            }
            IndexEncoding::LengthPrefixed => {
                let Some(&declared_arcs) = suffix.get(start) else {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::Truncated {
                            expected_arcs: 1,
                            available_arcs: 0,
                        },
                        pos,
                        suffix,
                    ));
                };
                let Ok(len) = usize::try_from(declared_arcs) else {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::MalformedLength {
                            declared_arcs,
                            max_arcs: limits.max_value_arcs,
                        },
                        pos,
                        suffix,
                    ));
                };
                if len > limits.max_value_arcs {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::MalformedLength {
                            declared_arcs,
                            max_arcs: limits.max_value_arcs,
                        },
                        pos,
                        suffix,
                    ));
                }
                let Some(required) = len.checked_add(1) else {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::MalformedLength {
                            declared_arcs,
                            max_arcs: limits.max_value_arcs,
                        },
                        pos,
                        suffix,
                    ));
                };
                if available < required {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::Truncated {
                            expected_arcs: required,
                            available_arcs: available,
                        },
                        pos,
                        suffix,
                    ));
                }
                let data = &suffix[start + 1..start + required];
                let base = idx.ty().map(|ty| ty.effective_base());
                if base == Some(BaseType::ObjectIdentifier) {
                    (IndexValue::ObjectIdentifier(data.to_vec()), required)
                } else {
                    if let Some((offset, value)) = invalid_octet(data) {
                        return Err(component_error(
                            components,
                            idx,
                            component_position,
                            IndexDecodeErrorKind::InvalidOctet {
                                arc_offset: start + 1 + offset,
                                value,
                            },
                            pos,
                            suffix,
                        ));
                    }
                    (
                        IndexValue::OctetString(arcs_to_bytes(data).unwrap()),
                        required,
                    )
                }
            }
            IndexEncoding::Implied => {
                if indexes.peek().is_some() {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::ImpliedNotLast,
                        pos,
                        suffix,
                    ));
                }
                if available > limits.max_value_arcs {
                    return Err(component_error(
                        components,
                        idx,
                        component_position,
                        IndexDecodeErrorKind::ValueTooLong {
                            required_arcs: available,
                            max_arcs: limits.max_value_arcs,
                        },
                        pos,
                        suffix,
                    ));
                }
                let data = &suffix[start..];
                let base = idx.ty().map(|ty| ty.effective_base());
                if base == Some(BaseType::ObjectIdentifier) {
                    (IndexValue::ObjectIdentifier(data.to_vec()), available)
                } else {
                    if let Some((offset, value)) = invalid_octet(data) {
                        return Err(component_error(
                            components,
                            idx,
                            component_position,
                            IndexDecodeErrorKind::InvalidOctet {
                                arc_offset: start + offset,
                                value,
                            },
                            pos,
                            suffix,
                        ));
                    }
                    (
                        IndexValue::OctetString(arcs_to_bytes(data).unwrap()),
                        available,
                    )
                }
            }
            IndexEncoding::Unknown => {
                return Err(component_error(
                    components,
                    idx,
                    component_position,
                    IndexDecodeErrorKind::UnknownEncoding,
                    pos,
                    suffix,
                ));
            }
        };

        pos += consumed;
        components.push(ExactDecodedIndex {
            name: idx.name().to_string(),
            value,
            arc_range: start..pos,
            raw_arcs: &suffix[start..pos],
        });
        component_position += 1;
    }

    if pos < suffix.len() {
        return Err(IndexDecodeError {
            decoded_components: components,
            failing_component: None,
            kind: IndexDecodeErrorKind::TrailingArcs,
            consumed_arc_range: 0..pos,
            remaining_arcs: &suffix[pos..],
        });
    }

    Ok(ExactIndexDecode {
        components,
        consumed_arc_range: 0..pos,
        remaining_arcs: &suffix[pos..],
    })
}

fn component_error<'m, 's>(
    decoded_components: Vec<ExactDecodedIndex<'s>>,
    index: Index<'m>,
    position: usize,
    kind: IndexDecodeErrorKind,
    consumed: usize,
    suffix: &'s [u32],
) -> IndexDecodeError<'s> {
    IndexDecodeError {
        decoded_components,
        failing_component: Some(FailingIndexComponent {
            position,
            name: index.name().to_string(),
        }),
        kind,
        consumed_arc_range: 0..consumed,
        remaining_arcs: &suffix[consumed..],
    }
}

/// Decode only the successfully readable prefix of an OID instance suffix.
///
/// This is the historical lenient behavior. It silently stops on truncation,
/// malformed octet arcs, unknown encodings, or invalid fixed sizes, and it
/// ignores trailing arcs. It does not apply [`IndexDecodeLimits`]. Prefer
/// [`decode_suffix_exact`] whenever incomplete decoding must be distinguishable
/// from exact success or allocation must be bounded.
pub fn decode_suffix_prefix<'a>(
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
                let (size, ok) = idx.fixed_size();
                if !ok || size == 0 || pos + size > suffix.len() {
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

/// Compatibility alias for the historical prefix decoder.
#[deprecated(
    since = "0.10.0",
    note = "use decode_suffix_prefix or decode_suffix_exact"
)]
pub fn decode_suffix<'a>(
    indexes: impl Iterator<Item = Index<'a>>,
    suffix: &[u32],
) -> Vec<DecodedIndex> {
    decode_suffix_prefix(indexes, suffix)
}

/// Convert OID arcs to bytes, returning `None` if any arc exceeds 255.
fn arcs_to_bytes(arcs: &[u32]) -> Option<Vec<u8>> {
    arcs.iter().map(|&a| u8::try_from(a).ok()).collect()
}

fn invalid_octet(arcs: &[u32]) -> Option<(usize, u32)> {
    arcs.iter()
        .copied()
        .enumerate()
        .find(|(_, arc)| *arc > u32::from(u8::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
    fn exact_composite_success_preserves_component_arcs() {
        let mib = load_test_mib();
        let row = mib.object("multiEntry").unwrap();
        let suffix = [3, 192, 168, 1, 1];

        let decoded = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();

        assert_eq!(decoded.consumed_arc_range(), 0..suffix.len());
        assert!(decoded.remaining_arcs().is_empty());
        assert_eq!(decoded.components().len(), 2);
        assert_eq!(decoded.components()[0].name(), "multiSlot");
        assert_eq!(decoded.components()[0].arc_range(), 0..1);
        assert_eq!(decoded.components()[0].raw_arcs(), &[3]);
        assert_eq!(decoded.components()[1].name(), "multiAddr");
        assert_eq!(decoded.components()[1].arc_range(), 1..5);
        assert_eq!(decoded.components()[1].raw_arcs(), &[192, 168, 1, 1]);
    }

    #[test]
    fn exact_truncation_identifies_component_and_partial_decode() {
        let mib = load_test_mib();
        let row = mib.object("multiEntry").unwrap();
        let suffix = [3, 10, 0];

        let error = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap_err();

        assert_eq!(
            error.kind(),
            &IndexDecodeErrorKind::Truncated {
                expected_arcs: 4,
                available_arcs: 2,
            }
        );
        assert_eq!(error.failing_component().unwrap().position(), 1);
        assert_eq!(error.failing_component().unwrap().name(), "multiAddr");
        assert_eq!(error.decoded_components().len(), 1);
        assert_eq!(error.decoded_components()[0].raw_arcs(), &[3]);
        assert_eq!(error.consumed_arc_range(), 0..1);
        assert_eq!(error.remaining_arcs(), &[10, 0]);
    }

    #[test]
    fn exact_hostile_declared_length_is_rejected_by_limit() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        let suffix = [u32::MAX];
        let limits = IndexDecodeLimits::new(4, 8);

        let error =
            decode_suffix_exact_with_limits(row.effective_indexes(), &suffix, limits).unwrap_err();

        assert_eq!(
            error.kind(),
            &IndexDecodeErrorKind::MalformedLength {
                declared_arcs: u32::MAX,
                max_arcs: 8,
            }
        );
        assert_eq!(error.failing_component().unwrap().name(), "varName");
        assert!(error.decoded_components().is_empty());
        assert_eq!(error.remaining_arcs(), &suffix);
    }

    #[test]
    fn exact_length_prefixed_truncation_reports_declared_requirement() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        let suffix = [10, 65, 66, 67];

        let error = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap_err();

        assert_eq!(
            error.kind(),
            &IndexDecodeErrorKind::Truncated {
                expected_arcs: 11,
                available_arcs: 4,
            }
        );
        assert_eq!(error.failing_component().unwrap().name(), "varName");
        assert_eq!(error.remaining_arcs(), &suffix);
    }

    #[test]
    fn exact_trailing_arcs_have_no_failing_component() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        let suffix = [42, 99, 100];

        let error = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap_err();

        assert_eq!(error.kind(), &IndexDecodeErrorKind::TrailingArcs);
        assert!(error.failing_component().is_none());
        assert_eq!(error.decoded_components().len(), 1);
        assert_eq!(error.decoded_components()[0].raw_arcs(), &[42]);
        assert_eq!(error.remaining_arcs(), &[99, 100]);
    }

    #[test]
    fn exact_string_arc_above_255_is_typed_malformed_input() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        let suffix = [2, 65, 256];

        let error = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap_err();

        assert_eq!(
            error.kind(),
            &IndexDecodeErrorKind::InvalidOctet {
                arc_offset: 2,
                value: 256,
            }
        );
        assert_eq!(error.failing_component().unwrap().name(), "varName");
        assert_eq!(error.remaining_arcs(), &suffix);
    }

    #[test]
    fn exact_oid_accepts_arcs_above_255() {
        let mib = load_test_mib();
        let row = mib.object("oidEntry").unwrap();
        let suffix = [3, 1, 256, u32::MAX];

        let decoded = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();

        assert_eq!(decoded.components()[0].raw_arcs(), &suffix);
        assert_eq!(
            decoded.components()[0].value(),
            &IndexValue::ObjectIdentifier(vec![1, 256, u32::MAX])
        );
    }

    #[test]
    fn exact_implied_string_and_oid_consume_the_remainder() {
        let mib = load_test_mib();
        let string_row = mib.object("impliedEntry").unwrap();
        let oid_row = mib.object("impliedOidEntry").unwrap();
        let string_suffix = [116, 101, 115, 116];
        let oid_suffix = [1, 3, 6, 1, 4, 256];

        let string = decode_suffix_exact(string_row.effective_indexes(), &string_suffix).unwrap();
        let oid = decode_suffix_exact(oid_row.effective_indexes(), &oid_suffix).unwrap();

        assert_eq!(string.components()[0].raw_arcs(), &string_suffix);
        assert_eq!(oid.components()[0].raw_arcs(), &oid_suffix);
        assert_eq!(
            oid.components()[0].value(),
            &IndexValue::ObjectIdentifier(oid_suffix.to_vec())
        );
    }

    #[test]
    fn exact_limits_component_count_and_implied_value_before_allocation() {
        let mib = load_test_mib();
        let multi_row = mib.object("multiEntry").unwrap();
        let implied_row = mib.object("impliedEntry").unwrap();

        let component_error = decode_suffix_exact_with_limits(
            multi_row.effective_indexes(),
            &[3, 192, 168, 1, 1],
            IndexDecodeLimits::new(1, 8),
        )
        .unwrap_err();
        assert_eq!(
            component_error.kind(),
            &IndexDecodeErrorKind::TooManyComponents { max_components: 1 }
        );
        assert_eq!(component_error.failing_component().unwrap().position(), 1);
        assert_eq!(component_error.remaining_arcs(), &[192, 168, 1, 1]);

        let value_error = decode_suffix_exact_with_limits(
            implied_row.effective_indexes(),
            &[1, 2, 3, 4, 5],
            IndexDecodeLimits::new(1, 4),
        )
        .unwrap_err();
        assert_eq!(
            value_error.kind(),
            &IndexDecodeErrorKind::ValueTooLong {
                required_arcs: 5,
                max_arcs: 4,
            }
        );
        assert!(value_error.decoded_components().is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn exact_variable_string_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let mib = load_test_mib();
            let row = mib.object("varEntry").unwrap();
            let mut suffix = Vec::with_capacity(bytes.len() + 1);
            suffix.push(bytes.len() as u32);
            suffix.extend(bytes.iter().copied().map(u32::from));

            let decoded = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();

            prop_assert_eq!(decoded.components()[0].raw_arcs(), suffix.as_slice());
            prop_assert_eq!(decoded.components()[0].value().as_bytes(), Some(bytes.as_slice()));
            prop_assert_eq!(decoded.consumed_arc_range(), 0..suffix.len());
            prop_assert!(decoded.remaining_arcs().is_empty());
        }

        #[test]
        fn exact_oid_round_trips_all_u32_arcs(arcs in prop::collection::vec(any::<u32>(), 0..64)) {
            let mib = load_test_mib();
            let row = mib.object("oidEntry").unwrap();
            let mut suffix = Vec::with_capacity(arcs.len() + 1);
            suffix.push(arcs.len() as u32);
            suffix.extend_from_slice(&arcs);

            let decoded = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();

            prop_assert_eq!(decoded.components()[0].raw_arcs(), suffix.as_slice());
            prop_assert_eq!(decoded.components()[0].value().as_oid(), Some(arcs.as_slice()));
            prop_assert!(decoded.remaining_arcs().is_empty());
        }

        #[test]
        fn exact_composite_round_trips(slot: u32, address: [u8; 4]) {
            let mib = load_test_mib();
            let row = mib.object("multiEntry").unwrap();
            let suffix = [
                slot,
                u32::from(address[0]),
                u32::from(address[1]),
                u32::from(address[2]),
                u32::from(address[3]),
            ];

            let decoded = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();

            prop_assert_eq!(decoded.components()[0].value(), &IndexValue::Integer(slot));
            prop_assert_eq!(decoded.components()[1].value(), &IndexValue::IpAddress(address));
            prop_assert_eq!(decoded.consumed_arc_range(), 0..suffix.len());
        }

        #[test]
        fn exact_implied_string_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let mib = load_test_mib();
            let row = mib.object("impliedEntry").unwrap();
            let suffix: Vec<u32> = bytes.iter().copied().map(u32::from).collect();

            let decoded = decode_suffix_exact(row.effective_indexes(), &suffix).unwrap();

            prop_assert_eq!(decoded.components()[0].raw_arcs(), suffix.as_slice());
            prop_assert_eq!(decoded.components()[0].value().as_bytes(), Some(bytes.as_slice()));
        }
    }

    #[test]
    fn exact_fuzz_regression_corpus_is_bounded_and_never_panics() {
        let mib = load_test_mib();
        let cases = [
            ("multiEntry", vec![]),
            ("multiEntry", vec![u32::MAX, 1, 2, 3]),
            ("varEntry", vec![u32::MAX]),
            ("varEntry", vec![1, 256]),
            ("oidEntry", vec![2, 256, u32::MAX]),
            ("impliedEntry", vec![0; 33]),
            ("impliedOidEntry", vec![u32::MAX; 33]),
        ];
        let limits = IndexDecodeLimits::new(2, 32);

        for (row_name, suffix) in cases {
            let row = mib.object(row_name).unwrap();
            let result = std::panic::catch_unwind(|| {
                decode_suffix_exact_with_limits(row.effective_indexes(), &suffix, limits)
            });
            assert!(
                result.is_ok(),
                "decoder panicked for {row_name}: {suffix:?}"
            );
        }
    }

    #[test]
    fn integer_index() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[42]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "simpleIndex");
        assert_eq!(*decoded[0].value(), IndexValue::Integer(42));
    }

    #[test]
    fn ip_address_index() {
        let mib = load_test_mib();
        let row = mib.object("ipEntry").unwrap();
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[10, 0, 1, 99]);
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
        let decoded = decode_suffix_prefix(
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
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[4, 101, 116, 104, 48]);
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
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[0]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "varName");
        assert_eq!(*decoded[0].value(), IndexValue::OctetString(vec![]));
    }

    #[test]
    fn multi_index_integer_and_ip() {
        let mib = load_test_mib();
        let row = mib.object("multiEntry").unwrap();
        // slot=3, addr=192.168.1.1
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[3, 192, 168, 1, 1]);
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
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[116, 101, 115, 116]);
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
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[4, 1, 3, 6, 1]);
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
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[1, 3, 6, 1, 4]);
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
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[10, 0]);
        assert!(decoded.is_empty());
    }

    #[test]
    fn empty_suffix_returns_empty() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[]);
        assert!(decoded.is_empty());
    }

    #[test]
    fn extra_arcs_are_ignored() {
        let mib = load_test_mib();
        let row = mib.object("simpleEntry").unwrap();
        // One integer index, extra arcs beyond it
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[42, 99, 100]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(*decoded[0].value(), IndexValue::Integer(42));
    }

    #[test]
    fn multi_index_partial_decode() {
        let mib = load_test_mib();
        let row = mib.object("multiEntry").unwrap();
        // slot=3, then only 2 arcs for IP (needs 4) -> partial
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[3, 10, 0]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(*decoded[0].value(), IndexValue::Integer(3));
    }

    #[test]
    fn length_prefixed_truncated_stops() {
        let mib = load_test_mib();
        let row = mib.object("varEntry").unwrap();
        // Length says 10 but only 3 data arcs follow
        let decoded = decode_suffix_prefix(row.effective_indexes(), &[10, 65, 66, 67]);
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
        let decoded = lookup.decode_indexes_prefix();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), "simpleIndex");
        assert_eq!(*decoded[0].value(), IndexValue::Integer(42));
    }

    #[test]
    fn lookup_instance_decode_exact() {
        let mib = load_test_mib();
        let oid = mib.resolve_oid("simpleValue.42").unwrap();
        let lookup = mib.lookup_instance(&oid);

        let decoded = lookup.decode_indexes_exact().unwrap();

        assert_eq!(decoded.components().len(), 1);
        assert_eq!(decoded.components()[0].name(), "simpleIndex");
        assert_eq!(decoded.components()[0].raw_arcs(), &[42]);
    }

    #[test]
    fn lookup_instance_decode_non_column() {
        let mib = load_test_mib();
        // Table OID with no instance suffix -> empty decode
        let oid = mib.resolve_oid("simpleTable").unwrap();
        let lookup = mib.lookup_instance(&oid);
        assert!(lookup.decode_indexes_prefix().is_empty());
    }
}
