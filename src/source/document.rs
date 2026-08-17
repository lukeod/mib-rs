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

/// A zero-based byte position within a source document.
///
/// Lines are separated by LF, CRLF, or lone CR. Unlike editor positions, byte
/// positions can identify every source byte, including both bytes of CRLF and
/// bytes in invalid UTF-8.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BytePosition {
    line: u32,
    column: u32,
}

impl BytePosition {
    /// Create a zero-based line and byte-column position.
    pub const fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }

    /// Return the zero-based line.
    pub const fn line(self) -> u32 {
        self.line
    }

    /// Return the zero-based byte column.
    pub const fn column(self) -> u32 {
        self.column
    }
}

/// A zero-based editor position.
///
/// The character field is measured in the explicitly selected
/// position encoding. Line terminators are excluded, matching LSP position
/// semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Position {
    line: u32,
    character: u32,
}

impl Position {
    /// Create a zero-based line and encoded-character position.
    pub const fn new(line: u32, character: u32) -> Self {
        Self { line, character }
    }

    /// Return the zero-based line.
    pub const fn line(self) -> u32 {
        self.line
    }

    /// Return the zero-based encoded-character offset.
    pub const fn character(self) -> u32 {
        self.character
    }
}

/// Encoding used for the character field of an editor position.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PositionEncoding {
    /// UTF-8 code units (bytes), restricted to Unicode scalar boundaries.
    Utf8,
    /// UTF-16 code units, as used by the original LSP position model.
    Utf16,
    /// UTF-32 code units (Unicode scalar values).
    Utf32,
}

impl fmt::Display for PositionEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Utf8 => "UTF-8",
            Self::Utf16 => "UTF-16",
            Self::Utf32 => "UTF-32",
        })
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
        let mut starts = Vec::new();
        starts.push(0);
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'\r' if bytes.get(index + 1) == Some(&b'\n') => {
                    index += 2;
                    starts.push(index);
                }
                b'\r' | b'\n' => {
                    index += 1;
                    starts.push(index);
                }
                _ => index += 1,
            }
        }
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

    /// Return the number of logical lines.
    ///
    /// Every document has at least one line. A trailing LF, CRLF, or lone CR
    /// creates a final empty line.
    pub fn line_count(&self) -> usize {
        self.line_index.starts.len()
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

    /// Convert a byte offset to a zero-based byte position.
    ///
    /// Every offset from zero through EOF is representable, including offsets
    /// on either byte of CRLF and offsets inside invalid UTF-8.
    pub fn byte_position(&self, offset: ByteOffset) -> Result<BytePosition, PositionError> {
        if offset > self.len() {
            return Err(PositionError::OffsetOutOfBounds {
                offset,
                len: self.len(),
            });
        }
        let offset = offset.as_usize();
        let line = self
            .line_index
            .starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let column = offset - self.line_index.starts[line];
        Ok(BytePosition::new(
            u32::try_from(line).expect("source line index fits in u32"),
            u32::try_from(column).expect("source byte column fits in u32"),
        ))
    }

    /// Convert a zero-based byte position to its byte offset.
    ///
    /// On non-final lines, positions identify every terminator byte. The offset
    /// immediately after an LF, CRLF, or lone CR is column zero of the next
    /// line. On the final line, its end position identifies EOF.
    pub fn byte_offset(&self, position: BytePosition) -> Result<ByteOffset, PositionError> {
        let line = position.line as usize;
        let Some(&start) = self.line_index.starts.get(line) else {
            return Err(PositionError::LineOutOfBounds {
                line: position.line,
                line_count: self.line_count(),
            });
        };
        let is_final = line + 1 == self.line_count();
        let full_end = self
            .line_index
            .starts
            .get(line + 1)
            .copied()
            .unwrap_or_else(|| self.bytes.len());
        let max_column = full_end - start - usize::from(!is_final);
        if position.column as usize > max_column {
            return Err(PositionError::ByteColumnOutOfBounds {
                line: position.line,
                column: position.column,
                max_column: u32::try_from(max_column).expect("source byte column fits in u32"),
            });
        }
        Ok(ByteOffset::new(
            u32::try_from(start + position.column as usize)
                .expect("validated source offset fits in u32"),
        ))
    }

    /// Convert a byte offset to an editor position in an explicit encoding.
    ///
    /// The source must be valid UTF-8, and the offset must lie on a Unicode
    /// scalar boundary. Line terminators are excluded from editor columns. The
    /// start of LF, CRLF, or lone CR maps to the line's end position; the
    /// offset between CR and LF has no editor-position representation.
    pub fn position(
        &self,
        offset: ByteOffset,
        encoding: PositionEncoding,
    ) -> Result<Position, PositionError> {
        let byte_position = self.byte_position(offset)?;
        let text = self.valid_utf8()?;
        let extent = self
            .line_extent(byte_position.line)
            .expect("validated byte position identifies a line");
        let offset = offset.as_usize();
        if offset > extent.content_end {
            return Err(PositionError::OffsetInsideLineTerminator {
                offset: ByteOffset::new(
                    u32::try_from(offset).expect("validated source offset fits in u32"),
                ),
                line: byte_position.line,
            });
        }
        if !text.is_char_boundary(offset) {
            return Err(PositionError::MidCodePoint {
                offset: ByteOffset::new(
                    u32::try_from(offset).expect("validated source offset fits in u32"),
                ),
            });
        }
        let prefix = &text[extent.start..offset];
        let character = match encoding {
            PositionEncoding::Utf8 => prefix.len(),
            PositionEncoding::Utf16 => prefix.encode_utf16().count(),
            PositionEncoding::Utf32 => prefix.chars().count(),
        };
        Ok(Position::new(
            byte_position.line,
            u32::try_from(character).expect("encoded source column fits in u32"),
        ))
    }

    /// Convert an editor position in an explicit encoding to a byte offset.
    ///
    /// Lines and characters are zero-based. End-of-line positions map to the
    /// first byte of LF, CRLF, or lone CR; a trailing terminator creates a final
    /// empty line whose zero position maps to EOF.
    pub fn position_offset(
        &self,
        position: Position,
        encoding: PositionEncoding,
    ) -> Result<ByteOffset, PositionError> {
        let Some(extent) = self.line_extent(position.line) else {
            return Err(PositionError::LineOutOfBounds {
                line: position.line,
                line_count: self.line_count(),
            });
        };
        let text = self.valid_utf8()?;
        let line_text = &text[extent.start..extent.content_end];
        let character = position.character as usize;
        let relative_offset = match encoding {
            PositionEncoding::Utf8 => {
                if character > line_text.len() {
                    return Err(PositionError::CharacterOutOfBounds {
                        line: position.line,
                        character: position.character,
                        max_character: u32::try_from(line_text.len())
                            .expect("encoded source column fits in u32"),
                        encoding,
                    });
                }
                if !line_text.is_char_boundary(character) {
                    return Err(PositionError::MidCodePoint {
                        offset: ByteOffset::new(
                            u32::try_from(extent.start + character)
                                .expect("validated source offset fits in u32"),
                        ),
                    });
                }
                character
            }
            PositionEncoding::Utf16 => {
                let mut units = 0usize;
                let mut result = None;
                for (byte_index, value) in line_text.char_indices() {
                    if units == character {
                        result = Some(byte_index);
                        break;
                    }
                    let next = units + value.len_utf16();
                    if character < next {
                        return Err(PositionError::MidUtf16Surrogate {
                            line: position.line,
                            character: position.character,
                        });
                    }
                    units = next;
                }
                if result.is_none() && units == character {
                    result = Some(line_text.len());
                }
                match result {
                    Some(offset) => offset,
                    None => {
                        return Err(PositionError::CharacterOutOfBounds {
                            line: position.line,
                            character: position.character,
                            max_character: u32::try_from(units)
                                .expect("encoded source column fits in u32"),
                            encoding,
                        });
                    }
                }
            }
            PositionEncoding::Utf32 => {
                let count = line_text.chars().count();
                if character > count {
                    return Err(PositionError::CharacterOutOfBounds {
                        line: position.line,
                        character: position.character,
                        max_character: u32::try_from(count)
                            .expect("encoded source column fits in u32"),
                        encoding,
                    });
                }
                line_text
                    .char_indices()
                    .map(|(byte_index, _)| byte_index)
                    .chain(std::iter::once(line_text.len()))
                    .nth(character)
                    .expect("validated UTF-32 column has a byte boundary")
            }
        };
        Ok(ByteOffset::new(
            u32::try_from(extent.start + relative_offset)
                .expect("validated source offset fits in u32"),
        ))
    }

    fn valid_utf8(&self) -> Result<&str, PositionError> {
        std::str::from_utf8(&self.bytes).map_err(|error| PositionError::InvalidUtf8 {
            valid_up_to: ByteOffset::new(
                u32::try_from(error.valid_up_to()).expect("source offset fits in u32"),
            ),
            error_len: error.error_len(),
        })
    }

    fn line_extent(&self, line: u32) -> Option<LineExtent> {
        let line = line as usize;
        let &start = self.line_index.starts.get(line)?;
        let full_end = self
            .line_index
            .starts
            .get(line + 1)
            .copied()
            .unwrap_or_else(|| self.bytes.len());
        let mut content_end = full_end;
        if line + 1 < self.line_count() {
            match self.bytes[full_end - 1] {
                b'\n' => {
                    content_end -= 1;
                    if content_end > start && self.bytes[content_end - 1] == b'\r' {
                        content_end -= 1;
                    }
                }
                b'\r' => content_end -= 1,
                _ => unreachable!("line index ends non-final lines after terminators"),
            }
        }
        Some(LineExtent { start, content_end })
    }
}

#[derive(Clone, Copy, Debug)]
struct LineExtent {
    start: usize,
    content_end: usize,
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

/// Failure to convert between byte offsets, byte positions, and editor positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PositionError {
    /// A byte offset lies beyond EOF.
    #[error("byte offset {offset} is outside a source of length {len}")]
    OffsetOutOfBounds { offset: ByteOffset, len: ByteOffset },
    /// A zero-based line does not exist.
    #[error("line {line} is outside a source with {line_count} lines")]
    LineOutOfBounds { line: u32, line_count: usize },
    /// A byte column does not identify a byte or the final EOF position.
    #[error("byte column {column} on line {line} exceeds maximum {max_column}")]
    ByteColumnOutOfBounds {
        line: u32,
        column: u32,
        max_column: u32,
    },
    /// An editor character lies beyond the logical end of its line.
    #[error("{encoding} character {character} on line {line} exceeds maximum {max_character}")]
    CharacterOutOfBounds {
        line: u32,
        character: u32,
        max_character: u32,
        encoding: PositionEncoding,
    },
    /// A byte offset falls between the CR and LF bytes of a CRLF terminator.
    #[error("byte offset {offset} falls inside the line {line} terminator")]
    OffsetInsideLineTerminator { offset: ByteOffset, line: u32 },
    /// A UTF-8 position falls within a multi-byte code point.
    #[error("byte offset {offset} falls inside a UTF-8 code point")]
    MidCodePoint { offset: ByteOffset },
    /// A UTF-16 position falls between the surrogate code units of an astral character.
    #[error("UTF-16 character {character} on line {line} falls inside a surrogate pair")]
    MidUtf16Surrogate { line: u32, character: u32 },
    /// Editor conversion requires a valid UTF-8 source document.
    #[error("source is not valid UTF-8 after byte {valid_up_to} (invalid length {error_len:?})")]
    InvalidUtf8 {
        valid_up_to: ByteOffset,
        error_len: Option<usize>,
    },
}

/// Owns the source documents retained for one compilation.
///
/// A source set is mutable while callers build a parse-only compilation, but
/// it cannot be cloned into independently mutable arenas whose future IDs
/// would alias. Resolved MIBs and diagnostic reports share one internal arena.
///
/// ```compile_fail
/// use mib_rs::SourceSet;
///
/// let sources = SourceSet::new();
/// let fork = sources.clone();
/// ```
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

    fn test_document(bytes: &[u8]) -> Arc<SourceDocument> {
        let mut sources = SourceSet::new();
        sources
            .insert_shared(
                memory_origin("position-test"),
                "position-test",
                Arc::from(bytes),
            )
            .unwrap()
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

    #[test]
    fn byte_positions_round_trip_every_offset_for_arbitrary_bytes() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"a\n",
            b"\n",
            b"a\r\nb",
            b"a\rb\n",
            &[0x00, 0xff, b'\r', b'\n', 0x80],
        ];

        for &bytes in cases {
            let document = test_document(bytes);
            for raw_offset in 0..=bytes.len() {
                let offset = document.offset(raw_offset).unwrap();
                let position = document.byte_position(offset).unwrap();
                assert_eq!(
                    document.byte_offset(position).unwrap(),
                    offset,
                    "bytes={bytes:?}, offset={raw_offset}, position={position:?}"
                );
                assert_eq!(
                    document
                        .byte_position(document.byte_offset(position).unwrap())
                        .unwrap(),
                    position
                );
            }
        }
    }

    #[test]
    fn byte_positions_cover_empty_eof_trailing_newline_and_crlf_bytes() {
        let empty = test_document(b"");
        assert_eq!(empty.line_count(), 1);
        assert_eq!(
            empty.byte_position(ByteOffset::new(0)).unwrap(),
            BytePosition::new(0, 0)
        );
        assert_eq!(
            empty.byte_offset(BytePosition::new(0, 0)).unwrap(),
            ByteOffset::new(0)
        );

        let document = test_document(b"a\r\nb\rc\n");
        assert_eq!(document.line_count(), 4);
        let expected = [
            BytePosition::new(0, 0),
            BytePosition::new(0, 1),
            BytePosition::new(0, 2),
            BytePosition::new(1, 0),
            BytePosition::new(1, 1),
            BytePosition::new(2, 0),
            BytePosition::new(2, 1),
            BytePosition::new(3, 0),
        ];
        for (offset, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                document.byte_position(ByteOffset::new(offset as u32)),
                Ok(expected)
            );
            assert_eq!(
                document.byte_offset(expected),
                Ok(ByteOffset::new(offset as u32))
            );
        }
        assert_eq!(expected[2].line(), 0);
        assert_eq!(expected[2].column(), 2);
    }

    #[test]
    fn byte_position_rejects_invalid_offset_line_and_column() {
        let document = test_document(b"a\nb");

        assert_eq!(
            document.byte_position(ByteOffset::new(4)),
            Err(PositionError::OffsetOutOfBounds {
                offset: ByteOffset::new(4),
                len: ByteOffset::new(3),
            })
        );
        assert_eq!(
            document.byte_offset(BytePosition::new(2, 0)),
            Err(PositionError::LineOutOfBounds {
                line: 2,
                line_count: 2,
            })
        );
        assert_eq!(
            document.byte_offset(BytePosition::new(0, 2)),
            Err(PositionError::ByteColumnOutOfBounds {
                line: 0,
                column: 2,
                max_column: 1,
            })
        );
        assert_eq!(
            document.byte_offset(BytePosition::new(1, 2)),
            Err(PositionError::ByteColumnOutOfBounds {
                line: 1,
                column: 2,
                max_column: 1,
            })
        );
    }

    #[test]
    fn editor_positions_use_explicit_utf_code_units() {
        let document = test_document("Aé𝄞".as_bytes());
        let cases = [
            (
                0,
                Position::new(0, 0),
                Position::new(0, 0),
                Position::new(0, 0),
            ),
            (
                1,
                Position::new(0, 1),
                Position::new(0, 1),
                Position::new(0, 1),
            ),
            (
                3,
                Position::new(0, 3),
                Position::new(0, 2),
                Position::new(0, 2),
            ),
            (
                7,
                Position::new(0, 7),
                Position::new(0, 4),
                Position::new(0, 3),
            ),
        ];

        for (offset, utf8, utf16, utf32) in cases {
            let offset = ByteOffset::new(offset);
            assert_eq!(document.position(offset, PositionEncoding::Utf8), Ok(utf8));
            assert_eq!(
                document.position(offset, PositionEncoding::Utf16),
                Ok(utf16)
            );
            assert_eq!(
                document.position(offset, PositionEncoding::Utf32),
                Ok(utf32)
            );
            assert_eq!(
                document.position_offset(utf8, PositionEncoding::Utf8),
                Ok(offset)
            );
            assert_eq!(
                document.position_offset(utf16, PositionEncoding::Utf16),
                Ok(offset)
            );
            assert_eq!(
                document.position_offset(utf32, PositionEncoding::Utf32),
                Ok(offset)
            );
        }

        assert_eq!(Position::new(2, 3).line(), 2);
        assert_eq!(Position::new(2, 3).character(), 3);
        assert_eq!(PositionEncoding::Utf8.to_string(), "UTF-8");
        assert_eq!(PositionEncoding::Utf16.to_string(), "UTF-16");
        assert_eq!(PositionEncoding::Utf32.to_string(), "UTF-32");
    }

    #[test]
    fn editor_positions_follow_lsp_line_terminator_and_eof_semantics() {
        let document = test_document(b"a\r\nb\rc\n");

        for encoding in [
            PositionEncoding::Utf8,
            PositionEncoding::Utf16,
            PositionEncoding::Utf32,
        ] {
            assert_eq!(
                document.position(ByteOffset::new(1), encoding),
                Ok(Position::new(0, 1))
            );
            assert_eq!(
                document.position(ByteOffset::new(2), encoding),
                Err(PositionError::OffsetInsideLineTerminator {
                    offset: ByteOffset::new(2),
                    line: 0,
                })
            );
            assert_eq!(
                document.position_offset(Position::new(0, 1), encoding),
                Ok(ByteOffset::new(1))
            );
            assert_eq!(
                document.position(ByteOffset::new(3), encoding),
                Ok(Position::new(1, 0))
            );
            assert_eq!(
                document.position(ByteOffset::new(4), encoding),
                Ok(Position::new(1, 1))
            );
            assert_eq!(
                document.position(ByteOffset::new(6), encoding),
                Ok(Position::new(2, 1))
            );
            assert_eq!(
                document.position(ByteOffset::new(7), encoding),
                Ok(Position::new(3, 0))
            );
            assert_eq!(
                document.position_offset(Position::new(3, 0), encoding),
                Ok(ByteOffset::new(7))
            );
        }
    }

    #[test]
    fn editor_positions_round_trip_all_representable_offsets_and_positions() {
        let cases = ["", "plain", "trailing\n", "\r\n", "é\r\n𝄞\n", "a\rb"];
        for text in cases {
            let document = test_document(text.as_bytes());
            for encoding in [
                PositionEncoding::Utf8,
                PositionEncoding::Utf16,
                PositionEncoding::Utf32,
            ] {
                for raw_offset in 0..=text.len() {
                    let offset = ByteOffset::new(raw_offset as u32);
                    match document.position(offset, encoding) {
                        Ok(position) => {
                            assert_eq!(
                                document.position_offset(position, encoding),
                                Ok(offset),
                                "text={text:?}, encoding={encoding}, offset={raw_offset}"
                            );
                        }
                        Err(
                            PositionError::MidCodePoint { .. }
                            | PositionError::OffsetInsideLineTerminator { .. },
                        ) => {}
                        Err(error) => panic!(
                            "unexpected conversion error for text={text:?}, encoding={encoding}, offset={raw_offset}: {error}"
                        ),
                    }
                }

                for line in 0..document.line_count() {
                    let extent = document.line_extent(line as u32).unwrap();
                    let end = document
                        .position(ByteOffset::new(extent.content_end as u32), encoding)
                        .unwrap();
                    for character in 0..=end.character() {
                        let position = Position::new(line as u32, character);
                        match document.position_offset(position, encoding) {
                            Ok(offset) => assert_eq!(
                                document.position(offset, encoding),
                                Ok(position),
                                "text={text:?}, encoding={encoding}, position={position:?}"
                            ),
                            Err(
                                PositionError::MidCodePoint { .. }
                                | PositionError::MidUtf16Surrogate { .. },
                            ) => {}
                            Err(error) => panic!(
                                "unexpected inverse error for text={text:?}, encoding={encoding}, position={position:?}: {error}"
                            ),
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn editor_positions_reject_mid_codepoint_mid_surrogate_and_bad_coordinates() {
        let document = test_document("Aé𝄞".as_bytes());

        for encoding in [
            PositionEncoding::Utf8,
            PositionEncoding::Utf16,
            PositionEncoding::Utf32,
        ] {
            assert_eq!(
                document.position(ByteOffset::new(2), encoding),
                Err(PositionError::MidCodePoint {
                    offset: ByteOffset::new(2),
                })
            );
        }
        assert_eq!(
            document.position_offset(Position::new(0, 2), PositionEncoding::Utf8),
            Err(PositionError::MidCodePoint {
                offset: ByteOffset::new(2),
            })
        );
        assert_eq!(
            document.position_offset(Position::new(0, 3), PositionEncoding::Utf16),
            Err(PositionError::MidUtf16Surrogate {
                line: 0,
                character: 3,
            })
        );
        assert_eq!(
            document.position_offset(Position::new(1, 0), PositionEncoding::Utf32),
            Err(PositionError::LineOutOfBounds {
                line: 1,
                line_count: 1,
            })
        );
        assert_eq!(
            document.position_offset(Position::new(0, 8), PositionEncoding::Utf8),
            Err(PositionError::CharacterOutOfBounds {
                line: 0,
                character: 8,
                max_character: 7,
                encoding: PositionEncoding::Utf8,
            })
        );
        assert_eq!(
            document.position_offset(Position::new(0, 5), PositionEncoding::Utf16),
            Err(PositionError::CharacterOutOfBounds {
                line: 0,
                character: 5,
                max_character: 4,
                encoding: PositionEncoding::Utf16,
            })
        );
        assert_eq!(
            document.position_offset(Position::new(0, 4), PositionEncoding::Utf32),
            Err(PositionError::CharacterOutOfBounds {
                line: 0,
                character: 4,
                max_character: 3,
                encoding: PositionEncoding::Utf32,
            })
        );
        assert_eq!(
            document.position(ByteOffset::new(8), PositionEncoding::Utf16),
            Err(PositionError::OffsetOutOfBounds {
                offset: ByteOffset::new(8),
                len: ByteOffset::new(7),
            })
        );
    }

    #[test]
    fn invalid_utf8_retains_byte_positions_but_rejects_editor_positions() {
        let bytes = [b'a', 0xff, b'\n', 0x80];
        let document = test_document(&bytes);

        for raw_offset in 0..=bytes.len() {
            let offset = ByteOffset::new(raw_offset as u32);
            let position = document.byte_position(offset).unwrap();
            assert_eq!(document.byte_offset(position), Ok(offset));
        }
        for encoding in [
            PositionEncoding::Utf8,
            PositionEncoding::Utf16,
            PositionEncoding::Utf32,
        ] {
            assert_eq!(
                document.position(ByteOffset::new(0), encoding),
                Err(PositionError::InvalidUtf8 {
                    valid_up_to: ByteOffset::new(1),
                    error_len: Some(1),
                })
            );
            assert_eq!(
                document.position_offset(Position::new(0, 0), encoding),
                Err(PositionError::InvalidUtf8 {
                    valid_up_to: ByteOffset::new(1),
                    error_len: Some(1),
                })
            );
        }
        assert_eq!(
            document.position(ByteOffset::new(5), PositionEncoding::Utf8),
            Err(PositionError::OffsetOutOfBounds {
                offset: ByteOffset::new(5),
                len: ByteOffset::new(4),
            })
        );
        assert_eq!(
            document.position_offset(Position::new(3, 0), PositionEncoding::Utf8),
            Err(PositionError::LineOutOfBounds {
                line: 3,
                line_count: 2,
            })
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
