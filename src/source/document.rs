//! Compilation-local source document storage.

use std::fmt;
use std::num::NonZeroU32;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

/// Identifies a source within one compilation.
///
/// IDs can only be allocated by [`SourceSet`]. They have no default or
/// distinguished sentinel value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SourceId(NonZeroU32);

impl SourceId {
    /// Return the compilation-local numeric identifier.
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    fn for_index(index: usize) -> Result<Self, SourceRangeError> {
        let value = index
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .and_then(NonZeroU32::new)
            .ok_or(SourceRangeError::TooManySources)?;
        Ok(Self(value))
    }

    fn index(self) -> usize {
        usize::try_from(self.0.get() - 1).expect("u32 source ID fits in usize")
    }
}

/// A byte position within a source document.
///
/// The `u32` representation keeps every offset representable in the compiler
/// coordinate space. [`SourceDocument::offset`] additionally checks that an
/// offset lies within a particular document, including its exclusive end.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ByteOffset(u32);

impl ByteOffset {
    /// Create a byte offset from its `u32` representation.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return this offset as a `u32` byte index.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Return this offset as a host byte index.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<usize> for ByteOffset {
    type Error = SourceRangeError;

    fn try_from(offset: usize) -> Result<Self, Self::Error> {
        u32::try_from(offset)
            .map(Self)
            .map_err(|_| SourceRangeError::UnrepresentableOffset {
                offset,
                max: u32::MAX as usize,
            })
    }
}

impl fmt::Display for ByteOffset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A half-open byte range within one source document.
///
/// Ranges are created by [`SourceDocument::range`] and
/// [`SourceDocument::empty_range`], which ensure that their endpoints are
/// ordered and within the source bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceRange {
    source: SourceId,
    start: ByteOffset,
    end: ByteOffset,
}

impl SourceRange {
    /// Return the document containing this range.
    pub const fn source(self) -> SourceId {
        self.source
    }

    /// Return the inclusive start offset.
    pub const fn start(self) -> ByteOffset {
        self.start
    }

    /// Return the exclusive end offset.
    pub const fn end(self) -> ByteOffset {
        self.end
    }

    /// Return this range as byte indices suitable for slicing.
    pub fn byte_range(self) -> Range<usize> {
        self.start.as_usize()..self.end.as_usize()
    }

    /// Return the smallest range covering both ranges.
    ///
    /// Both ranges must identify the same source document.
    pub fn cover(first: Self, last: Self) -> Result<Self, SourceRangeError> {
        if first.source != last.source {
            return Err(SourceRangeError::SourceMismatch {
                expected: first.source,
                actual: last.source,
            });
        }
        if first.start > first.end {
            return Err(SourceRangeError::ReversedRange {
                start: first.start,
                end: first.end,
            });
        }
        if last.start > last.end {
            return Err(SourceRangeError::ReversedRange {
                start: last.start,
                end: last.end,
            });
        }

        Ok(Self {
            source: first.source,
            start: first.start.min(last.start),
            end: first.end.max(last.end),
        })
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The stable identity of source content, independent of its display label.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SourceOrigin {
    /// A file identified by its path.
    File { path: PathBuf },
    /// A source bundled into the library or another component.
    Embedded { identity: Arc<str> },
    /// An in-memory or editor buffer.
    Memory { identity: Arc<str> },
    /// A source supplied by another kind of provider.
    Custom {
        provider: Arc<str>,
        identity: Arc<str>,
    },
}

impl SourceOrigin {
    /// Identify a source by its filesystem path.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File { path: path.into() }
    }

    /// Identify content bundled into a library or application.
    pub fn embedded(identity: impl Into<Arc<str>>) -> Self {
        Self::Embedded {
            identity: identity.into(),
        }
    }

    /// Identify an in-memory or editor document.
    pub fn memory(identity: impl Into<Arc<str>>) -> Self {
        Self::Memory {
            identity: identity.into(),
        }
    }

    /// Identify content supplied by a custom kind of provider.
    pub fn custom(provider: impl Into<Arc<str>>, identity: impl Into<Arc<str>>) -> Self {
        Self::Custom {
            provider: provider.into(),
            identity: identity.into(),
        }
    }
}

/// Byte offsets at which each line in a source begins.
///
/// The first entry is always zero, including for an empty source. The basic
/// byte-based line conversion is retained here; editor encoding conversion is
/// handled separately.
#[derive(Debug)]
pub(crate) struct LineIndex {
    starts: Box<[usize]>,
}

impl LineIndex {
    fn new(bytes: &[u8]) -> Self {
        let mut starts =
            Vec::with_capacity(1 + bytes.iter().filter(|&&byte| byte == b'\n').count());
        starts.push(0);
        starts.extend(
            bytes
                .iter()
                .enumerate()
                .filter_map(|(index, &byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self {
            starts: starts.into_boxed_slice(),
        }
    }

    pub(crate) fn line_count(&self) -> usize {
        self.starts.len()
    }

    pub(crate) fn line_start(&self, line_index: usize) -> Option<usize> {
        self.starts.get(line_index).copied()
    }

    pub(crate) fn line_starts(&self) -> &[usize] {
        &self.starts
    }
}

/// Immutable source content retained by a compilation.
#[derive(Debug)]
pub struct SourceDocument {
    id: SourceId,
    origin: SourceOrigin,
    label: Arc<str>,
    bytes: Arc<[u8]>,
    line_index: LineIndex,
}

impl SourceDocument {
    /// Return this document's compilation-local identity.
    pub fn id(&self) -> SourceId {
        self.id
    }

    /// Return this document's stable physical or logical origin.
    pub fn origin(&self) -> &SourceOrigin {
        &self.origin
    }

    /// Return the display label used for this document.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the immutable source bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the source length as a validated compiler byte offset.
    pub fn len(&self) -> ByteOffset {
        ByteOffset(u32::try_from(self.bytes.len()).expect("source length was validated"))
    }

    /// Return whether this document contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Validate and convert a byte index into a compiler byte offset.
    ///
    /// The exclusive end-of-document offset is valid.
    pub fn offset(&self, offset: usize) -> Result<ByteOffset, SourceRangeError> {
        let offset = ByteOffset::try_from(offset)?;
        if offset > self.len() {
            return Err(SourceRangeError::OffsetOutOfBounds {
                offset,
                len: self.len(),
            });
        }
        Ok(offset)
    }

    /// Create a checked half-open byte range in this document.
    pub fn range(&self, range: Range<usize>) -> Result<SourceRange, SourceRangeError> {
        let start = ByteOffset::try_from(range.start)?;
        let end = ByteOffset::try_from(range.end)?;
        if start > end {
            return Err(SourceRangeError::ReversedRange { start, end });
        }
        if end > self.len() {
            return Err(SourceRangeError::OffsetOutOfBounds {
                offset: end,
                len: self.len(),
            });
        }
        Ok(SourceRange {
            source: self.id,
            start,
            end,
        })
    }

    /// Create a checked empty range at a byte offset in this document.
    pub fn empty_range(&self, offset: usize) -> Result<SourceRange, SourceRangeError> {
        self.range(offset..offset)
    }

    /// Return the bytes covered by a checked source range.
    pub fn slice(&self, range: SourceRange) -> Result<&[u8], SourceRangeError> {
        if range.source != self.id {
            return Err(SourceRangeError::SourceMismatch {
                expected: self.id,
                actual: range.source,
            });
        }
        if range.start > range.end {
            return Err(SourceRangeError::ReversedRange {
                start: range.start,
                end: range.end,
            });
        }
        if range.end > self.len() {
            return Err(SourceRangeError::OffsetOutOfBounds {
                offset: range.end,
                len: self.len(),
            });
        }
        Ok(&self.bytes[range.byte_range()])
    }

    pub(crate) fn line_index(&self) -> &LineIndex {
        &self.line_index
    }

    /// Convert a checked byte offset to a one-based line and byte column.
    ///
    /// The exclusive end-of-document offset is valid. Columns count bytes;
    /// callers needing editor character encodings must convert explicitly.
    pub fn line_column(&self, offset: ByteOffset) -> Result<(usize, usize), SourceRangeError> {
        if offset > self.len() {
            return Err(SourceRangeError::OffsetOutOfBounds {
                offset,
                len: self.len(),
            });
        }
        let offset = offset.as_usize();
        let line_index = self
            .line_index
            .line_starts()
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        Ok((
            line_index + 1,
            offset - self.line_index.line_starts()[line_index] + 1,
        ))
    }
}

/// Failure to create or use a source coordinate or retain another source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceRangeError {
    /// A host byte index cannot be represented by the compiler coordinate type.
    #[error("byte offset {offset} cannot be represented (maximum is {max})")]
    UnrepresentableOffset { offset: usize, max: usize },
    /// A byte offset is beyond the exclusive end of a source document.
    #[error("byte offset {offset} is outside a source of length {len}")]
    OffsetOutOfBounds { offset: ByteOffset, len: ByteOffset },
    /// The start of a range follows its end.
    #[error("source range start {start} follows end {end}")]
    ReversedRange { start: ByteOffset, end: ByteOffset },
    /// A range identifies a different source document.
    #[error("source range belongs to source {actual}, not source {expected}")]
    SourceMismatch {
        expected: SourceId,
        actual: SourceId,
    },
    /// Source byte offsets must fit in the compiler's `u32` coordinate space.
    #[error("source is too large ({len} bytes; maximum is {max})")]
    SourceTooLarge { len: usize, max: usize },
    /// All representable compilation-local IDs have been allocated.
    #[error("too many sources in one compilation")]
    TooManySources,
}

/// Owns the source documents retained for one compilation.
#[derive(Debug, Default)]
pub struct SourceSet {
    documents: Vec<Arc<SourceDocument>>,
}

impl SourceSet {
    /// Create an empty compilation-local source collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of retained documents.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Return whether no documents have been retained.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Retain a source document and return its compilation-local identity.
    pub fn insert(
        &mut self,
        origin: SourceOrigin,
        label: impl Into<Arc<str>>,
        bytes: Arc<[u8]>,
    ) -> Result<SourceId, SourceRangeError> {
        self.insert_shared(origin, label, bytes)
            .map(|document| document.id())
    }

    pub(crate) fn insert_shared(
        &mut self,
        origin: SourceOrigin,
        label: impl Into<Arc<str>>,
        bytes: Arc<[u8]>,
    ) -> Result<Arc<SourceDocument>, SourceRangeError> {
        validate_source_len(bytes.len())?;
        let id = SourceId::for_index(self.documents.len())?;
        let document = Arc::new(SourceDocument {
            id,
            origin,
            label: label.into(),
            line_index: LineIndex::new(&bytes),
            bytes,
        });
        self.documents.push(Arc::clone(&document));
        Ok(document)
    }

    /// Return a retained document by its compilation-local identity.
    pub fn get(&self, id: SourceId) -> Option<&SourceDocument> {
        self.documents.get(id.index()).map(Arc::as_ref)
    }

    /// Iterate over retained documents in identity allocation order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &SourceDocument> {
        self.documents.iter().map(Arc::as_ref)
    }
}

fn validate_source_len(len: usize) -> Result<(), SourceRangeError> {
    let max = u32::MAX as usize;
    if len > max {
        return Err(SourceRangeError::SourceTooLarge { len, max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_origin(identity: &str) -> SourceOrigin {
        SourceOrigin::Memory {
            identity: Arc::from(identity),
        }
    }

    #[test]
    fn source_set_allocates_nonzero_unique_ids() {
        let mut sources = SourceSet::new();
        let first = sources
            .insert(memory_origin("buffer:one"), "one", Arc::from(&b"one"[..]))
            .unwrap();
        let second = sources
            .insert(memory_origin("buffer:two"), "two", Arc::from(&b"two"[..]))
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(first.get(), 1);
        assert_eq!(second.get(), 2);
        assert_eq!(first.to_string(), "1");
        assert_eq!(second.to_string(), "2");
        assert_eq!(sources.len(), 2);
        assert!(!sources.is_empty());
        assert_eq!(
            sources.iter().map(SourceDocument::id).collect::<Vec<_>>(),
            [first, second]
        );
    }

    #[test]
    fn origin_identity_is_distinct_from_display_label() {
        let mut sources = SourceSet::new();
        let origin = SourceOrigin::Custom {
            provider: Arc::from("workspace"),
            identity: Arc::from("document/42"),
        };
        let id = sources
            .insert(origin.clone(), "ACME-MIB", Arc::from(&b"contents"[..]))
            .unwrap();
        let document = sources.get(id).unwrap();

        assert_eq!(document.origin(), &origin);
        assert_eq!(document.label(), "ACME-MIB");
        assert_ne!(document.label(), "document/42");
    }

    #[test]
    fn document_retains_shared_bytes_without_copying() {
        let bytes: Arc<[u8]> = Arc::from(&b"first\nsecond"[..]);
        let mut sources = SourceSet::new();
        let id = sources
            .insert(memory_origin("buffer"), "buffer", Arc::clone(&bytes))
            .unwrap();
        let document = sources.get(id).unwrap();

        assert_eq!(document.bytes(), bytes.as_ref());
        assert_eq!(document.bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(Arc::strong_count(&bytes), 2);
    }

    #[test]
    fn source_lookup_checks_id_bounds() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(memory_origin("buffer"), "buffer", Arc::from(&b""[..]))
            .unwrap();

        assert_eq!(sources.get(id).unwrap().id(), id);
        assert!(sources.get(SourceId::for_index(1).unwrap()).is_none());
    }

    #[test]
    fn line_index_owns_all_line_starts_and_checks_bounds() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                memory_origin("buffer"),
                "buffer",
                Arc::from(&b"first\n\nthird\n"[..]),
            )
            .unwrap();
        let document = sources.get(id).unwrap();
        let index = document.line_index();

        assert_eq!(index.line_starts(), &[0, 6, 7, 13]);
        assert_eq!(index.line_count(), 4);
        assert_eq!(index.line_start(0), Some(0));
        assert_eq!(index.line_start(3), Some(13));
        assert_eq!(index.line_start(4), None);
    }

    #[test]
    fn document_converts_checked_byte_offsets_to_one_based_positions() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                memory_origin("buffer"),
                "buffer",
                Arc::from(&b"first\nsecond"[..]),
            )
            .unwrap();
        let document = sources.get(id).unwrap();

        assert_eq!(document.line_column(ByteOffset::new(0)).unwrap(), (1, 1));
        assert_eq!(document.line_column(ByteOffset::new(6)).unwrap(), (2, 1));
        assert_eq!(document.line_column(document.len()).unwrap(), (2, 7));
        assert_eq!(
            document.line_column(ByteOffset::new(13)),
            Err(SourceRangeError::OffsetOutOfBounds {
                offset: ByteOffset::new(13),
                len: document.len(),
            })
        );
    }

    #[test]
    fn all_origin_kinds_retain_typed_identity() {
        let origins = [
            SourceOrigin::File {
                path: PathBuf::from("/mibs/IF-MIB"),
            },
            SourceOrigin::Embedded {
                identity: Arc::from("SNMPv2-SMI"),
            },
            memory_origin("untitled:1"),
            SourceOrigin::Custom {
                provider: Arc::from("database"),
                identity: Arc::from("mib/7"),
            },
        ];

        assert_eq!(origins.len(), 4);
        assert!(origins.iter().all(|origin| origins.contains(origin)));
    }

    #[test]
    fn rejects_unrepresentable_source_lengths_and_id_overflow() {
        let too_large = (u32::MAX as usize).checked_add(1).unwrap();
        assert_eq!(
            validate_source_len(too_large),
            Err(SourceRangeError::SourceTooLarge {
                len: too_large,
                max: u32::MAX as usize,
            })
        );
        assert_eq!(
            SourceId::for_index(u32::MAX as usize),
            Err(SourceRangeError::TooManySources)
        );
        let maximum = ByteOffset::try_from(u32::MAX as usize).unwrap();
        assert_eq!(maximum, ByteOffset::new(u32::MAX));
        assert_eq!(maximum.get(), u32::MAX);
        assert_eq!(maximum.as_usize(), u32::MAX as usize);
    }

    #[test]
    fn empty_document_accepts_only_its_eof_offset_and_range() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(memory_origin("empty"), "empty", Arc::from(&b""[..]))
            .unwrap();
        let document = sources.get(id).unwrap();

        assert!(document.is_empty());
        assert_eq!(document.len().get(), 0);
        assert_eq!(document.offset(0).unwrap().get(), 0);
        let range = document.empty_range(0).unwrap();
        assert_eq!(range.source(), id);
        assert_eq!(range.start().get(), 0);
        assert_eq!(range.end().get(), 0);
        assert_eq!(range.byte_range(), 0..0);
        assert_eq!(document.slice(range).unwrap(), b"");
        assert_eq!(
            document.offset(1),
            Err(SourceRangeError::OffsetOutOfBounds {
                offset: ByteOffset(1),
                len: ByteOffset(0),
            })
        );
    }

    #[test]
    fn document_ranges_include_eof_and_slice_bytes() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(memory_origin("buffer"), "buffer", Arc::from(&b"abcdef"[..]))
            .unwrap();
        let document = sources.get(id).unwrap();

        assert_eq!(document.len().get(), 6);
        assert_eq!(document.offset(6).unwrap().get(), 6);
        assert_eq!(
            document.slice(document.range(1..4).unwrap()).unwrap(),
            b"bcd"
        );
        assert_eq!(
            document.slice(document.empty_range(6).unwrap()).unwrap(),
            b""
        );
    }

    #[test]
    fn document_rejects_reversed_and_out_of_bounds_ranges() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(memory_origin("buffer"), "buffer", Arc::from(&b"abcd"[..]))
            .unwrap();
        let document = sources.get(id).unwrap();
        let reversed_start = 3;
        let reversed_end = 2;
        let out_of_bounds_start = document.bytes().len() + 1;

        assert_eq!(
            document.range(reversed_start..reversed_end),
            Err(SourceRangeError::ReversedRange {
                start: ByteOffset(3),
                end: ByteOffset(2),
            })
        );
        assert_eq!(
            document.range(0..5),
            Err(SourceRangeError::OffsetOutOfBounds {
                offset: ByteOffset(5),
                len: ByteOffset(4),
            })
        );
        assert_eq!(
            document.range(out_of_bounds_start..0),
            Err(SourceRangeError::ReversedRange {
                start: ByteOffset(5),
                end: ByteOffset(0),
            })
        );
    }

    #[test]
    fn ranges_reject_cross_source_cover_and_slice() {
        let mut sources = SourceSet::new();
        let first_id = sources
            .insert(memory_origin("first"), "first", Arc::from(&b"first"[..]))
            .unwrap();
        let second_id = sources
            .insert(memory_origin("second"), "second", Arc::from(&b"second"[..]))
            .unwrap();
        let first = sources.get(first_id).unwrap().range(1..3).unwrap();
        let second = sources.get(second_id).unwrap().range(2..4).unwrap();

        assert_eq!(
            SourceRange::cover(first, second),
            Err(SourceRangeError::SourceMismatch {
                expected: first_id,
                actual: second_id,
            })
        );
        assert_eq!(
            sources.get(first_id).unwrap().slice(second),
            Err(SourceRangeError::SourceMismatch {
                expected: first_id,
                actual: second_id,
            })
        );
    }

    #[test]
    fn cover_spans_ordered_disjoint_and_nested_ranges() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                memory_origin("buffer"),
                "buffer",
                Arc::from(&b"0123456789"[..]),
            )
            .unwrap();
        let document = sources.get(id).unwrap();
        let left = document.range(1..3).unwrap();
        let right = document.range(7..9).unwrap();
        let nested = document.range(2..8).unwrap();

        assert_eq!(
            SourceRange::cover(left, right).unwrap(),
            document.range(1..9).unwrap()
        );
        assert_eq!(
            SourceRange::cover(right, left).unwrap(),
            document.range(1..9).unwrap()
        );
        assert_eq!(
            SourceRange::cover(nested, left).unwrap(),
            document.range(1..8).unwrap()
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn offsets_beyond_u32_are_reported_as_unrepresentable() {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(memory_origin("buffer"), "buffer", Arc::from(&b"bytes"[..]))
            .unwrap();
        let document = sources.get(id).unwrap();
        let offset = u32::MAX as usize + 1;

        assert_eq!(
            document.offset(offset),
            Err(SourceRangeError::UnrepresentableOffset {
                offset,
                max: u32::MAX as usize,
            })
        );
    }
}
