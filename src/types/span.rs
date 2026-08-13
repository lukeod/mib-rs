//! Source location types for tracking positions in MIB source text.
//!
//! [`ByteOffset`] represents a single position, [`Span`] represents a half-open
//! byte range, and [`SpanDiagnostic`] is a diagnostic that carries a span
//! (later converted to line/column in [`Diagnostic`](super::Diagnostic)).

/// A byte position in source text.
///
/// Wraps a `u32` offset. The sentinel value [`ByteOffset::SYNTHETIC`] marks
/// positions that do not correspond to real source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteOffset(pub u32);

impl ByteOffset {
    /// Sentinel value for positions not backed by source text (e.g. base modules).
    pub const SYNTHETIC: ByteOffset = ByteOffset(u32::MAX);
}

/// A half-open byte range `[start, end)` in source text.
///
/// Used throughout the lexer, parser, and lowering stages to track where
/// constructs originate. See [`ByteOffset`] for the underlying offset type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Span {
    /// Start of the range (inclusive).
    pub start: ByteOffset,
    /// End of the range (exclusive).
    pub end: ByteOffset,
}

impl Span {
    /// Zero-length span at the start of input.
    pub const ZERO: Span = Span {
        start: ByteOffset(0),
        end: ByteOffset(0),
    };

    /// Span for compiler-generated constructs (base modules, built-in types).
    pub const SYNTHETIC: Span = Span {
        start: ByteOffset::SYNTHETIC,
        end: ByteOffset::SYNTHETIC,
    };

    /// Creates a span from two [`ByteOffset`] values.
    pub fn new(start: ByteOffset, end: ByteOffset) -> Self {
        Span { start, end }
    }

    /// Creates a span from raw `u32` offsets.
    pub fn from_offsets(start: u32, end: u32) -> Self {
        Span {
            start: ByteOffset(start),
            end: ByteOffset(end),
        }
    }

    /// Creates a span from `usize` offsets.
    ///
    /// Returns [`Span::SYNTHETIC`] if either offset exceeds `u32::MAX`.
    pub fn from_usize_offsets(start: usize, end: usize) -> Self {
        match (u32::try_from(start), u32::try_from(end)) {
            (Ok(start), Ok(end)) => Self::from_offsets(start, end),
            _ => Self::SYNTHETIC,
        }
    }

    /// Returns `true` if this span is the [`Span::SYNTHETIC`] sentinel.
    pub fn is_synthetic(self) -> bool {
        self == Self::SYNTHETIC
    }
}

/// Diagnostic emitted by the lexer or parser, carrying a [`Span`] instead of line/column.
///
/// Converted to [`Diagnostic`](super::Diagnostic) during lowering when module name
/// and a line table become available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanDiagnostic {
    /// Effective severity after applying diagnostic configuration overrides.
    pub severity: super::Severity,
    /// Diagnostic code identifying the issue category.
    pub code: DiagCode,
    /// Source location of the issue.
    pub span: Span,
    /// Human-readable description of the issue.
    pub message: String,
}

use super::DiagCode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_span() {
        assert!(Span::SYNTHETIC.is_synthetic());
        assert!(!Span::from_offsets(0, 10).is_synthetic());
    }
}
