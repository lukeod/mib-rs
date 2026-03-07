/// A byte position in source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteOffset(pub u32);

impl ByteOffset {
    pub const SYNTHETIC: ByteOffset = ByteOffset(u32::MAX);
}

/// Represents a range in source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Span {
    pub start: ByteOffset,
    pub end: ByteOffset,
}

impl Span {
    /// Span for compiler-generated constructs (base modules, built-in types).
    pub const SYNTHETIC: Span = Span {
        start: ByteOffset::SYNTHETIC,
        end: ByteOffset::SYNTHETIC,
    };

    pub fn new(start: ByteOffset, end: ByteOffset) -> Self {
        Span { start, end }
    }

    pub fn from_offsets(start: u32, end: u32) -> Self {
        Span {
            start: ByteOffset(start),
            end: ByteOffset(end),
        }
    }

    pub fn is_synthetic(self) -> bool {
        self == Self::SYNTHETIC
    }
}

/// Internal diagnostic from the lexer or parser.
/// Converted to Diagnostic during lowering with module name and line/column info.
#[derive(Debug, Clone)]
pub struct SpanDiagnostic {
    pub severity: super::Severity,
    pub code: DiagCode,
    pub span: Span,
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
