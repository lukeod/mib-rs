//! SMI/MIB lexer (tokenizer).
//!
//! Converts raw source bytes into a stream of [`Token`]s. Handles
//! SMIv1/SMIv2 syntax including `--` comments, hex/binary string literals,
//! MACRO body skipping, and EXPORTS body skipping. A separate lossless mode
//! retains whitespace, comments, skipped bodies, and recovery text.

pub mod token;

pub use crate::syntax::{SyntaxKind, is_forbidden_keyword, lookup_keyword};
pub use token::Token;

use crate::source::{SourceDocument, SourceRange};
use crate::types::{DiagCode, Diagnostic, DiagnosticConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerState {
    Normal,
    InMacro,
    InExports,
    InComment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerMode {
    Semantic,
    Lossless,
}

fn is_identifier_body_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// Tokenizer for SMIv1/SMIv2 MIB source text.
///
/// Operates on raw bytes and produces [`Token`]s. The lexer tracks internal
/// state to skip MACRO bodies and EXPORTS clauses, which are not needed
/// by the parser.
///
/// Can be used as an [`Iterator`] (yields tokens until EOF) or consumed
/// all at once via [`tokenize`](Lexer::tokenize).
pub struct Lexer<'src, 'cfg> {
    document: &'src SourceDocument,
    source: &'src [u8],
    pos: usize,
    state: LexerState,
    mode: LexerMode,
    comment_start: usize,
    diagnostics: Vec<Diagnostic>,
    diag_config: &'cfg DiagnosticConfig,
}

impl<'src, 'cfg> Lexer<'src, 'cfg> {
    /// Create a new lexer over a retained source document.
    pub fn new(document: &'src SourceDocument, diag_config: &'cfg DiagnosticConfig) -> Self {
        Self::with_mode(document, diag_config, LexerMode::Semantic)
    }

    /// Create a lexer that retains every source byte in its token stream.
    ///
    /// In addition to semantic tokens, this mode emits whitespace and comments
    /// as trivia tokens, skipped `MACRO` and `EXPORTS` bodies as opaque text,
    /// and lexer recovery regions as error tokens.
    pub fn new_lossless(
        document: &'src SourceDocument,
        diag_config: &'cfg DiagnosticConfig,
    ) -> Self {
        Self::with_mode(document, diag_config, LexerMode::Lossless)
    }

    fn with_mode(
        document: &'src SourceDocument,
        diag_config: &'cfg DiagnosticConfig,
        mode: LexerMode,
    ) -> Self {
        Lexer {
            document,
            source: document.bytes(),
            pos: 0,
            state: LexerState::Normal,
            mode,
            comment_start: 0,
            diagnostics: Vec::new(),
            diag_config,
        }
    }

    /// Consume all source text and return the token stream and diagnostics.
    /// The token stream always ends with `SyntaxKind::EofToken`.
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<Diagnostic>) {
        let estimated = (self.source.len() / 6).max(64);
        let mut tokens: Vec<Token> = Vec::with_capacity(estimated);
        tokens.extend(&mut self);
        // Always terminate with EOF
        tokens.push(Token {
            kind: SyntaxKind::EofToken,
            span: self.span_from(self.pos),
        });
        (tokens, self.diagnostics)
    }

    /// Advance the lexer and return the next token.
    ///
    /// Returns [`SyntaxKind::EofToken`] when the input is exhausted. Unlike the
    /// [`Iterator`] impl, this always returns a token (never `None`).
    pub fn next_token(&mut self) -> Token {
        loop {
            match self.state {
                LexerState::InComment => return self.emit_comment(),
                LexerState::InMacro => {
                    if let Some(tok) = self.skip_macro_body() {
                        return tok;
                    }
                }
                LexerState::InExports => {
                    if let Some(tok) = self.skip_exports_body() {
                        return tok;
                    }
                }
                LexerState::Normal => {
                    if let Some(tok) = self.next_normal_token() {
                        return tok;
                    }
                }
            }
        }
    }

    // -- Internal helpers --

    fn is_eof(&self) -> bool {
        self.pos >= self.source.len()
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.source.get(self.pos + offset).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.source.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.advance();
        }
    }

    fn scan_whitespace(&mut self) -> Token {
        let start = self.pos;
        self.skip_whitespace();
        self.token(SyntaxKind::Whitespace, start)
    }

    fn skip_line_ending(&mut self) {
        if let Some(b) = self.advance()
            && b == b'\r'
            && self.peek() == Some(b'\n')
        {
            self.advance();
        }
    }

    fn skip_to_eol(&mut self) {
        while let Some(b) = self.peek() {
            if b == b'\n' || b == b'\r' {
                self.skip_line_ending();
                return;
            }
            self.advance();
        }
    }

    fn span_from(&self, start: usize) -> SourceRange {
        self.document
            .range(start..self.pos)
            .expect("lexer positions remain within the source document")
    }

    fn token(&self, kind: SyntaxKind, start: usize) -> Token {
        Token {
            kind,
            span: self.span_from(start),
        }
    }

    fn remaining(&self) -> &[u8] {
        &self.source[self.pos..]
    }

    fn is_comment_start(&self) -> bool {
        self.remaining().starts_with(b"--")
    }

    fn emit_diagnostic(&mut self, code: DiagCode, span: SourceRange, message: impl Into<String>) {
        if !self.diag_config.should_collect(code) {
            return;
        }
        let severity = self.diag_config.effective_severity(code);
        self.diagnostics.push(Diagnostic {
            code,
            severity,
            message: message.into(),
            module: None,
            range: Some(span),
        });
    }

    // -- Normal state scanning --

    /// Returns None to signal retry (skipped junk or entered comment state).
    fn next_normal_token(&mut self) -> Option<Token> {
        if self.mode == LexerMode::Lossless
            && self
                .peek()
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Some(self.scan_whitespace());
        }
        self.skip_whitespace();

        let start = self.pos;

        let b = match self.peek() {
            None => return Some(self.token(SyntaxKind::EofToken, start)),
            Some(b) => b,
        };

        // Comment start: --
        if self.is_comment_start() {
            self.comment_start = start;
            self.pos += 2;
            self.state = LexerState::InComment;
            return None;
        }

        // Dot or DotDot
        if b == b'.' {
            self.advance();
            if self.peek() == Some(b'.') {
                self.advance();
                return Some(self.token(SyntaxKind::DotDot, start));
            }
            return Some(self.token(SyntaxKind::Dot, start));
        }

        // Colon or ColonColonEqual
        if b == b':' {
            self.pos += 1;
            if self.remaining().starts_with(b":=") {
                self.pos += 2;
                return Some(self.token(SyntaxKind::ColonColonEqual, start));
            }
            return Some(self.token(SyntaxKind::Colon, start));
        }

        // Minus or NegativeNumber
        if b == b'-' {
            if let Some(next) = self.peek_at(1)
                && next.is_ascii_digit()
            {
                return Some(self.scan_negative_number());
            }
            self.advance();
            return Some(self.token(SyntaxKind::Minus, start));
        }

        // Remaining single-character punctuation
        if let Some(kind) = SyntaxKind::from_punctuation_byte(b) {
            self.advance();
            return Some(self.token(kind, start));
        }

        // Number
        if b.is_ascii_digit() {
            return Some(self.scan_number());
        }

        // Quoted string
        if b == b'"' {
            return Some(self.scan_quoted_string());
        }

        // Hex or binary string
        if b == b'\'' {
            return Some(self.scan_hex_or_bin_string());
        }

        // Identifier or keyword
        if b.is_ascii_alphabetic() {
            return Some(self.scan_identifier_or_keyword());
        }

        // Unexpected character
        self.advance();
        let span = self.span_from(start);
        self.emit_diagnostic(
            DiagCode::UnexpectedCharacter,
            span,
            format!("unexpected character: 0x{:02x}", b),
        );
        if self.mode == LexerMode::Lossless {
            while self.peek().is_some_and(|b| !matches!(b, b'\n' | b'\r')) {
                self.advance();
            }
            Some(self.token(SyntaxKind::ErrorToken, start))
        } else {
            self.skip_to_eol();
            None
        }
    }

    // -- Identifier/keyword scanning --

    fn scan_identifier_or_keyword(&mut self) -> Token {
        let start = self.pos;
        let is_uppercase = self.source[self.pos].is_ascii_uppercase();
        self.pos += 1;

        loop {
            match self.peek() {
                Some(b) if b.is_ascii_alphanumeric() || b == b'_' => {
                    self.advance();
                }
                Some(b'-') => {
                    if self.is_comment_start() {
                        break;
                    }
                    self.advance();
                }
                _ => break,
            }
        }

        let text = std::str::from_utf8(&self.source[start..self.pos])
            .expect("identifier bytes should be ASCII");

        if let Some(kind) = lookup_keyword(text) {
            match kind {
                SyntaxKind::KwMacro => {
                    self.state = LexerState::InMacro;
                }
                SyntaxKind::KwExports => {
                    self.state = LexerState::InExports;
                }
                _ => {}
            }
            return self.token(kind, start);
        }

        if is_forbidden_keyword(text) {
            return self.token(SyntaxKind::ForbiddenKeyword, start);
        }

        let kind = if is_uppercase {
            SyntaxKind::UppercaseIdent
        } else {
            SyntaxKind::LowercaseIdent
        };
        self.token(kind, start)
    }

    // -- Number scanning --

    fn scan_digits(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.advance();
        }
    }

    fn scan_number(&mut self) -> Token {
        self.scan_number_impl(false)
    }

    fn scan_negative_number(&mut self) -> Token {
        self.scan_number_impl(true)
    }

    fn scan_number_impl(&mut self, negative: bool) -> Token {
        let start = self.pos;
        if negative {
            self.advance(); // consume '-'
        }
        let digit_start = self.pos;
        self.scan_digits();
        let kind = if negative {
            SyntaxKind::NegativeNumber
        } else {
            SyntaxKind::Number
        };
        let tok = self.token(kind, start);
        if self.pos - digit_start > 1 && self.source[digit_start] == b'0' {
            self.emit_diagnostic(
                DiagCode::NumberLeadingZero,
                self.span_from(start),
                "leading zero(s) on a number",
            );
        }
        tok
    }

    // -- String scanning --

    fn scan_quoted_string(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // consume opening quote

        loop {
            match self.peek() {
                None => {
                    let span = self.span_from(start);
                    self.emit_diagnostic(
                        DiagCode::UnterminatedString,
                        span,
                        "unterminated string literal",
                    );
                    return self.token(SyntaxKind::QuotedString, start);
                }
                Some(b'"') => {
                    self.advance();
                    return self.token(SyntaxKind::QuotedString, start);
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn scan_hex_or_bin_string(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // consume opening quote

        let mut content_len = 0usize;
        // Collect positions and characters of non-whitespace content for validation.
        let mut content_chars: Vec<(usize, u8)> = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\'') => break,
                Some(b) => {
                    if !matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                        content_chars.push((self.pos, b));
                        content_len += 1;
                    }
                    self.advance();
                }
            }
        }

        if self.peek() != Some(b'\'') {
            let span = self.span_from(start);
            self.emit_diagnostic(
                DiagCode::UnterminatedHexBinStr,
                span,
                "unterminated hex/binary string",
            );
            return self.token(SyntaxKind::ErrorToken, start);
        }
        self.advance(); // consume closing quote

        let suffix = self.peek();
        match suffix {
            Some(b'H' | b'h') => {
                self.advance();
                for &(char_pos, b) in &content_chars {
                    if !b.is_ascii_hexdigit() {
                        let span = self
                            .document
                            .range(char_pos..char_pos + 1)
                            .expect("scanned character lies within the source document");
                        self.emit_diagnostic(
                            DiagCode::HexStringInvalidChar,
                            span,
                            format!("invalid character '{}' in hex string", char::from(b),),
                        );
                    }
                }
                if content_len > 0 && !content_len.is_multiple_of(2) {
                    let span = self.span_from(start);
                    self.emit_diagnostic(
                        DiagCode::HexStringMul2,
                        span,
                        format!("hex string length {} is not a multiple of 2", content_len),
                    );
                }
                self.token(SyntaxKind::HexString, start)
            }
            Some(b'B' | b'b') => {
                self.advance();
                for &(char_pos, b) in &content_chars {
                    if !matches!(b, b'0' | b'1') {
                        let span = self
                            .document
                            .range(char_pos..char_pos + 1)
                            .expect("scanned character lies within the source document");
                        self.emit_diagnostic(
                            DiagCode::BinStringInvalidChar,
                            span,
                            format!("invalid character '{}' in binary string", char::from(b),),
                        );
                    }
                }
                if content_len > 0 && !content_len.is_multiple_of(8) {
                    let span = self.span_from(start);
                    self.emit_diagnostic(
                        DiagCode::BinStringMul8,
                        span,
                        format!(
                            "binary string length {} is not a multiple of 8",
                            content_len
                        ),
                    );
                }
                self.token(SyntaxKind::BinString, start)
            }
            _ => {
                let span = self.span_from(start);
                self.emit_diagnostic(
                    DiagCode::MissingHexBinSuffix,
                    span,
                    "expected 'H' or 'B' suffix for hex/binary string",
                );
                self.token(SyntaxKind::ErrorToken, start)
            }
        }
    }

    // -- Comment handling --

    fn try_consume_triple_dash_eol(&mut self) -> bool {
        if !self.remaining().starts_with(b"---") {
            return false;
        }

        match self.source.get(self.pos + 3) {
            None | Some(b'\n') | Some(b'\r') => {
                self.pos += 3;
                if self.mode == LexerMode::Semantic {
                    self.skip_line_ending();
                }
                true
            }
            _ => false,
        }
    }

    /// Consume comment text and return a Comment token.
    /// The range covers from '--' through comment text, excluding the trailing newline.
    fn emit_comment(&mut self) -> Token {
        self.skip_comment_body(true);
        let tok = self.token(SyntaxKind::Comment, self.comment_start);
        // Semantic mode historically consumes the trailing newline. Lossless
        // mode leaves it for the following whitespace token.
        if self.mode == LexerMode::Semantic
            && let Some(b) = self.peek()
            && (b == b'\n' || b == b'\r')
        {
            self.skip_line_ending();
        }
        self.state = LexerState::Normal;
        tok
    }

    /// Scan forward past comment text. Stops at EOF, newline (without consuming),
    /// or "--" terminator (consuming both dashes). When handle_triple_dash is true,
    /// "---" followed by EOL is also treated as a terminator.
    fn skip_comment_body(&mut self, handle_triple_dash: bool) {
        loop {
            match self.peek() {
                None | Some(b'\n') | Some(b'\r') => return,
                Some(b'-') => {
                    if handle_triple_dash && self.try_consume_triple_dash_eol() {
                        return;
                    }
                    if self.is_comment_start() {
                        self.pos += 2;
                        return;
                    }
                    self.advance();
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn skip_comment_inline(&mut self) {
        self.pos += 2; // consume '--'
        self.skip_comment_body(false);
    }

    // -- MACRO body skipping --

    fn skip_macro_body(&mut self) -> Option<Token> {
        let opaque_start = self.pos;
        let mut in_quoted_string = false;

        loop {
            self.skip_whitespace();

            if self.is_eof() {
                let start = self.pos;
                self.state = LexerState::Normal;
                return if self.mode == LexerMode::Lossless && start > opaque_start {
                    Some(self.token(SyntaxKind::OpaqueText, opaque_start))
                } else {
                    Some(self.token(SyntaxKind::EofToken, start))
                };
            }

            if self.peek() == Some(b'"') {
                in_quoted_string = !in_quoted_string;
                self.advance();
                continue;
            }

            if in_quoted_string {
                self.advance();
                continue;
            }

            if self.remaining().starts_with(b"END") {
                // Check that END is not embedded in an identifier body.
                let prev_is_delimiter =
                    self.pos == 0 || !is_identifier_body_byte(self.source[self.pos - 1]);
                if prev_is_delimiter {
                    let saved = self.pos;
                    self.pos += 3;
                    let is_delimiter = match self.peek() {
                        None => true,
                        Some(b'-') => self.peek_at(1) == Some(b'-'),
                        Some(b) => !is_identifier_body_byte(b),
                    };
                    if is_delimiter {
                        self.state = LexerState::Normal;
                        if self.mode == LexerMode::Lossless {
                            self.pos = saved;
                            return (saved > opaque_start)
                                .then(|| self.token(SyntaxKind::OpaqueText, opaque_start));
                        }
                        return Some(self.token(SyntaxKind::KwEnd, saved));
                    }
                    self.pos = saved;
                }
            }

            if self.is_comment_start() {
                self.skip_comment_inline();
                continue;
            }

            self.advance();
        }
    }

    // -- EXPORTS body skipping --

    fn skip_exports_body(&mut self) -> Option<Token> {
        let opaque_start = self.pos;
        loop {
            match self.peek() {
                None => {
                    let start = self.pos;
                    self.state = LexerState::Normal;
                    return if self.mode == LexerMode::Lossless && start > opaque_start {
                        Some(self.token(SyntaxKind::OpaqueText, opaque_start))
                    } else {
                        Some(self.token(SyntaxKind::EofToken, start))
                    };
                }
                Some(b';') => {
                    let start = self.pos;
                    self.state = LexerState::Normal;
                    if self.mode == LexerMode::Lossless {
                        return (start > opaque_start)
                            .then(|| self.token(SyntaxKind::OpaqueText, opaque_start));
                    }
                    self.advance();
                    return Some(self.token(SyntaxKind::Semicolon, start));
                }
                _ if self.is_comment_start() => {
                    self.skip_comment_inline();
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Returns diagnostics accumulated so far during tokenization.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// Yields tokens until EOF is reached. The EOF token itself is not yielded;
/// the iterator simply returns `None`. Use [`Lexer::tokenize`] if you need
/// the final EOF token included.
impl<'src, 'cfg> Iterator for Lexer<'src, 'cfg> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        let tok = self.next_token();
        if tok.kind == SyntaxKind::EofToken {
            None
        } else {
            Some(tok)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{SourceOrigin, SourceSet};
    use std::sync::Arc;

    fn with_document<T>(input: &str, f: impl FnOnce(&SourceDocument) -> T) -> T {
        with_bytes_document(input.as_bytes(), f)
    }

    fn with_bytes_document<T>(input: &[u8], f: impl FnOnce(&SourceDocument) -> T) -> T {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                SourceOrigin::memory("lexer-test"),
                "lexer-test",
                Arc::from(input),
            )
            .unwrap();
        f(sources.get(id).unwrap())
    }

    fn tokenize(input: &str) -> Vec<Token> {
        let cfg = DiagnosticConfig::default();
        with_document(input, |document| {
            let lexer = Lexer::new(document, &cfg);
            let (tokens, _) = lexer.tokenize();
            tokens
        })
    }

    fn tokenize_with_diags(input: &str) -> (Vec<Token>, Vec<Diagnostic>) {
        let cfg = DiagnosticConfig::verbose();
        with_document(input, |document| Lexer::new(document, &cfg).tokenize())
    }

    fn kinds(tokens: &[Token]) -> Vec<SyntaxKind> {
        tokens.iter().map(|t| t.kind).collect()
    }

    fn assert_lossless(input: &[u8]) -> (Vec<Token>, Vec<Diagnostic>) {
        let cfg = DiagnosticConfig::verbose();
        with_bytes_document(input, |document| {
            let (tokens, diagnostics) = crate::token::tokenize_lossless_with_config(document, &cfg);
            let mut cursor = 0;
            let mut reconstructed = Vec::with_capacity(input.len());

            for token in &tokens {
                let range = token.span.byte_range();
                assert_eq!(token.span.source(), document.id());
                assert_eq!(range.start, cursor, "gap or overlap before {token:?}");
                if token.kind == SyntaxKind::EofToken {
                    assert_eq!(range, input.len()..input.len());
                } else {
                    assert!(range.start < range.end, "empty non-EOF token: {token:?}");
                    reconstructed.extend_from_slice(document.slice(token.span).unwrap());
                    cursor = range.end;
                }
            }

            assert_eq!(tokens.last().unwrap().kind, SyntaxKind::EofToken);
            assert_eq!(cursor, input.len());
            assert_eq!(reconstructed, input);
            (tokens, diagnostics)
        })
    }

    fn text_of<'a>(source: &'a str, token: &Token) -> &'a str {
        &source[token.span.byte_range()]
    }

    #[test]
    fn empty_input() {
        let tokens = tokenize("");
        assert_eq!(kinds(&tokens), vec![SyntaxKind::EofToken]);
        assert_eq!(tokens[0].span.byte_range(), 0..0);
    }

    #[test]
    fn token_ranges_identify_the_lexed_document() {
        let cfg = DiagnosticConfig::default();
        let mut sources = SourceSet::new();
        let first_id = sources
            .insert(
                SourceOrigin::memory("first"),
                "first",
                Arc::from(&b"first"[..]),
            )
            .unwrap();
        let second_id = sources
            .insert(
                SourceOrigin::memory("second"),
                "second",
                Arc::from(&b"second"[..]),
            )
            .unwrap();

        let (tokens, _) = Lexer::new(sources.get(second_id).unwrap(), &cfg).tokenize();
        assert!(tokens.iter().all(|token| token.span.source() == second_id));
        assert!(tokens.iter().all(|token| token.span.source() != first_id));
        assert_eq!(tokens.last().unwrap().span.byte_range(), 6..6);
    }

    #[test]
    fn whitespace_only() {
        let tokens = tokenize("   \t\n\r\n  ");
        assert_eq!(kinds(&tokens), vec![SyntaxKind::EofToken]);
    }

    #[test]
    fn punctuation() {
        let tokens = tokenize("[ ] { } ( ) ; , |");
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LBracket,
                SyntaxKind::RBracket,
                SyntaxKind::LBrace,
                SyntaxKind::RBrace,
                SyntaxKind::LParen,
                SyntaxKind::RParen,
                SyntaxKind::Semicolon,
                SyntaxKind::Comma,
                SyntaxKind::Pipe,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn dots_and_colons() {
        let tokens = tokenize(". .. : ::=");
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::Dot,
                SyntaxKind::DotDot,
                SyntaxKind::Colon,
                SyntaxKind::ColonColonEqual,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn numbers() {
        let input = "0 42 100";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::Number,
                SyntaxKind::Number,
                SyntaxKind::Number,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(text_of(input, &tokens[0]), "0");
        assert_eq!(text_of(input, &tokens[1]), "42");
        assert_eq!(text_of(input, &tokens[2]), "100");
    }

    #[test]
    fn negative_numbers() {
        let input = "-1 -42";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::NegativeNumber,
                SyntaxKind::NegativeNumber,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(text_of(input, &tokens[0]), "-1");
        assert_eq!(text_of(input, &tokens[1]), "-42");
    }

    #[test]
    fn minus_not_negative() {
        let tokens = tokenize("- x");
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::Minus,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken
            ]
        );
    }

    #[test]
    fn leading_zero_diagnostic() {
        let (tokens, diags) = tokenize_with_diags("007 -042");
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::Number,
                SyntaxKind::NegativeNumber,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(diags.len(), 2);
        assert_eq!(diags[0].code, DiagCode::NumberLeadingZero);
        assert_eq!(diags[1].code, DiagCode::NumberLeadingZero);
        assert_eq!(diags[0].range.unwrap().byte_range(), 0..3);
        assert_eq!(diags[1].range.unwrap().byte_range(), 4..8);
        assert_eq!(
            diags[0].range.unwrap().source(),
            diags[1].range.unwrap().source()
        );
        assert!(diags.iter().all(|diagnostic| diagnostic.module.is_none()));
    }

    #[test]
    fn quoted_string() {
        let input = r#""hello world""#;
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::QuotedString, SyntaxKind::EofToken]
        );
        assert_eq!(text_of(input, &tokens[0]), r#""hello world""#);
    }

    #[test]
    fn multiline_quoted_string() {
        let input = "\"line1\nline2\"";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::QuotedString, SyntaxKind::EofToken]
        );
    }

    #[test]
    fn unterminated_string() {
        let (tokens, diags) = tokenize_with_diags("\"hello");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::QuotedString, SyntaxKind::EofToken]
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::UnterminatedString);
    }

    #[test]
    fn hex_string() {
        let input = "'0A1B'H";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::HexString, SyntaxKind::EofToken]
        );
    }

    #[test]
    fn bin_string() {
        let input = "'01010101'B";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::BinString, SyntaxKind::EofToken]
        );
    }

    #[test]
    fn hex_string_odd_length() {
        let (tokens, diags) = tokenize_with_diags("'0A1'H");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::HexString, SyntaxKind::EofToken]
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::HexStringMul2);
    }

    #[test]
    fn bin_string_bad_length() {
        let (tokens, diags) = tokenize_with_diags("'0101'B");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::BinString, SyntaxKind::EofToken]
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::BinStringMul8);
    }

    #[test]
    fn hex_string_missing_suffix() {
        let (tokens, diags) = tokenize_with_diags("'0A1B'");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::ErrorToken, SyntaxKind::EofToken]
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::MissingHexBinSuffix);
    }

    #[test]
    fn unterminated_hex_string() {
        let (tokens, diags) = tokenize_with_diags("'0A1B");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::ErrorToken, SyntaxKind::EofToken]
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::UnterminatedHexBinStr);
    }

    #[test]
    fn hex_string_invalid_chars() {
        // 0A is valid, GZ are not valid hex digits
        let (tokens, diags) = tokenize_with_diags("'0AGZ'H");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::HexString, SyntaxKind::EofToken]
        );
        let invalid_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == DiagCode::HexStringInvalidChar)
            .collect();
        assert_eq!(invalid_diags.len(), 2);
        assert!(invalid_diags[0].message.contains("'G'"));
        assert!(invalid_diags[1].message.contains("'Z'"));
    }

    #[test]
    fn bin_string_invalid_chars() {
        let (tokens, diags) = tokenize_with_diags("'0102'B");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::BinString, SyntaxKind::EofToken]
        );
        let invalid_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == DiagCode::BinStringInvalidChar)
            .collect();
        assert_eq!(invalid_diags.len(), 1);
        assert!(invalid_diags[0].message.contains("'2'"));
    }

    #[test]
    fn hex_string_valid_no_invalid_char_diag() {
        let (tokens, diags) = tokenize_with_diags("'0A1B'H");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::HexString, SyntaxKind::EofToken]
        );
        assert!(
            !diags
                .iter()
                .any(|d| d.code == DiagCode::HexStringInvalidChar),
        );
    }

    #[test]
    fn bin_string_valid_no_invalid_char_diag() {
        let (tokens, diags) = tokenize_with_diags("'01010101'B");
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::BinString, SyntaxKind::EofToken]
        );
        assert!(
            !diags
                .iter()
                .any(|d| d.code == DiagCode::BinStringInvalidChar),
        );
    }

    #[test]
    fn identifiers() {
        let input = "ifIndex SomeModule myVar";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::UppercaseIdent,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(text_of(input, &tokens[0]), "ifIndex");
        assert_eq!(text_of(input, &tokens[1]), "SomeModule");
        assert_eq!(text_of(input, &tokens[2]), "myVar");
    }

    #[test]
    fn identifier_with_hyphen() {
        let input = "some-name";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::LowercaseIdent, SyntaxKind::EofToken]
        );
        assert_eq!(text_of(input, &tokens[0]), "some-name");
    }

    #[test]
    fn identifier_with_underscore() {
        let input = "some_name";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::LowercaseIdent, SyntaxKind::EofToken]
        );
        assert_eq!(text_of(input, &tokens[0]), "some_name");
    }

    #[test]
    fn identifier_stops_at_comment() {
        let input = "name--comment";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Comment,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(text_of(input, &tokens[0]), "name");
    }

    #[test]
    fn keywords() {
        let input = "OBJECT-TYPE SYNTAX STATUS DESCRIPTION";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwObjectType,
                SyntaxKind::KwSyntax,
                SyntaxKind::KwStatus,
                SyntaxKind::KwDescription,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn status_access_keywords() {
        let input = "current deprecated read-only not-accessible";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwCurrent,
                SyntaxKind::KwDeprecated,
                SyntaxKind::KwReadOnly,
                SyntaxKind::KwNotAccessible,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn forbidden_keyword() {
        let input = "TRUE FALSE NULL OPTIONAL";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::ForbiddenKeyword,
                SyntaxKind::ForbiddenKeyword,
                SyntaxKind::ForbiddenKeyword,
                SyntaxKind::ForbiddenKeyword,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn comment_to_eol() {
        let input = "x -- this is a comment\ny";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Comment,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn comment_terminated_by_double_dash() {
        let input = "x -- comment -- y";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Comment,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(text_of(input, &tokens[1]), "-- comment --");
    }

    #[test]
    fn comment_at_eof() {
        let input = "x -- comment";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Comment,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn triple_dash_eol_terminates_comment() {
        let input = "-- comment---\nx";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::Comment,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn macro_body_skipping() {
        // MACRO transitions to InMacro immediately, so ::= BEGIN and body
        // are consumed without emitting tokens. Only END exits InMacro.
        let input = "MACRO ::= BEGIN stuff END next";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwMacro,
                SyntaxKind::KwEnd,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn macro_body_does_not_match_pretend() {
        // END inside "PRETEND" should not terminate macro body.
        let input = "MACRO ::= BEGIN PRETEND END next";
        let tokens = tokenize(input);
        let end_idx = tokens
            .iter()
            .position(|t| t.kind == SyntaxKind::KwEnd)
            .unwrap();
        // The END that terminates should be after PRETEND.
        let next_idx = tokens
            .iter()
            .position(|t| t.kind == SyntaxKind::LowercaseIdent)
            .unwrap();
        assert!(end_idx < next_idx);
    }

    #[test]
    fn macro_body_does_not_end_inside_multiline_quoted_string() {
        let input = "MACRO ::= BEGIN TYPE NOTATION ::= \"quoted\nEND\ntext\" END next";
        let (tokens, diags) = tokenize_with_diags(input);

        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwMacro,
                SyntaxKind::KwEnd,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(text_of(input, &tokens[1]), "END");
        assert_eq!(
            tokens[1].span.start().as_usize(),
            input.rfind("END").unwrap()
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn exports_body_skipping() {
        let input = "EXPORTS foo, bar; next";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwExports,
                SyntaxKind::Semicolon,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn exports_body_ignores_comment_semicolons() {
        for input in [
            "EXPORTS foo -- ignored;\nbar; next",
            "EXPORTS foo -- ignored; -- bar; next",
        ] {
            let tokens = tokenize(input);
            assert_eq!(
                kinds(&tokens),
                vec![
                    SyntaxKind::KwExports,
                    SyntaxKind::Semicolon,
                    SyntaxKind::LowercaseIdent,
                    SyntaxKind::EofToken,
                ]
            );
            assert_eq!(tokens[1].span.start().as_usize(), input.rfind(';').unwrap());
        }
    }

    #[test]
    fn unexpected_character() {
        let (tokens, diags) = tokenize_with_diags("x @ y");
        // @ is unexpected, rest of line is skipped, then y is on same line so also skipped
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::UnexpectedCharacter);
        // x should still be tokenized
        assert_eq!(tokens[0].kind, SyntaxKind::LowercaseIdent);
    }

    #[test]
    fn realistic_snippet() {
        let input = r#"IF-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI;

ifMIB MODULE-IDENTITY
    LAST-UPDATED "200006140000Z"
    ORGANIZATION "IETF"
    CONTACT-INFO ""
    DESCRIPTION
        "The MIB module to describe interfaces."
    ::= { mib-2 31 }

END
"#;
        let tokens = tokenize(input);
        // Should not panic and should end with Eof
        assert_eq!(tokens.last().unwrap().kind, SyntaxKind::EofToken);
        // Should contain expected keywords
        let k = kinds(&tokens);
        assert!(k.contains(&SyntaxKind::KwDefinitions));
        assert!(k.contains(&SyntaxKind::ColonColonEqual));
        assert!(k.contains(&SyntaxKind::KwBegin));
        assert!(k.contains(&SyntaxKind::KwImports));
        assert!(k.contains(&SyntaxKind::KwModuleIdentity));
        assert!(k.contains(&SyntaxKind::KwEnd));
    }

    #[test]
    fn hex_string_with_whitespace() {
        let input = "'0A 1B\n2C'H";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::HexString, SyntaxKind::EofToken]
        );
    }

    #[test]
    fn empty_hex_string() {
        let input = "''H";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![SyntaxKind::HexString, SyntaxKind::EofToken]
        );
    }

    #[test]
    fn type_keywords() {
        let input = "INTEGER Counter32 IpAddress OCTET STRING BITS";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwInteger,
                SyntaxKind::KwCounter32,
                SyntaxKind::KwIpAddress,
                SyntaxKind::KwOctet,
                SyntaxKind::KwString,
                SyntaxKind::KwBits,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn colon_not_cce() {
        let input = ": ::";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::Colon,
                SyntaxKind::Colon,
                SyntaxKind::Colon,
                SyntaxKind::EofToken,
            ]
        );
    }

    #[test]
    fn span_offsets_correct() {
        let input = "abc 123";
        let tokens = tokenize(input);
        assert_eq!(tokens[0].span.start().get(), 0);
        assert_eq!(tokens[0].span.end().get(), 3);
        assert_eq!(tokens[1].span.start().get(), 4);
        assert_eq!(tokens[1].span.end().get(), 7);
    }

    #[test]
    fn lossless_adjacent_trivia_and_comment_at_eof() {
        let input = b"x \t--one----two--\r\n y--tail";
        let (tokens, diagnostics) = assert_lossless(input);

        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Whitespace,
                SyntaxKind::Comment,
                SyntaxKind::Comment,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Comment,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(&input[tokens[1].span.byte_range()], b" \t");
        assert_eq!(&input[tokens[2].span.byte_range()], b"--one--");
        assert_eq!(&input[tokens[3].span.byte_range()], b"--two--");
        assert_eq!(&input[tokens[4].span.byte_range()], b"\r\n ");
        assert_eq!(&input[tokens[6].span.byte_range()], b"--tail");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn lossless_preserves_each_line_ending_form() {
        let input = b"a\rb\nc\r\nd";
        let (tokens, diagnostics) = assert_lossless(input);

        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(&input[tokens[1].span.byte_range()], b"\r");
        assert_eq!(&input[tokens[3].span.byte_range()], b"\n");
        assert_eq!(&input[tokens[5].span.byte_range()], b"\r\n");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn lossless_preserves_invalid_byte_recovery() {
        let input = b"x \xff rest\r\nz";
        let (tokens, diagnostics) = assert_lossless(input);

        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::LowercaseIdent,
                SyntaxKind::Whitespace,
                SyntaxKind::ErrorToken,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(&input[tokens[2].span.byte_range()], b"\xff rest");
        assert_eq!(&input[tokens[3].span.byte_range()], b"\r\n");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagCode::UnexpectedCharacter);
        assert_eq!(diagnostics[0].range.unwrap().byte_range(), 2..3);

        let cfg = DiagnosticConfig::verbose();
        with_bytes_document(input, |document| {
            let (semantic, semantic_diagnostics) = Lexer::new(document, &cfg).tokenize();
            assert_eq!(
                kinds(&semantic),
                vec![
                    SyntaxKind::LowercaseIdent,
                    SyntaxKind::LowercaseIdent,
                    SyntaxKind::EofToken,
                ]
            );
            assert_eq!(semantic_diagnostics, diagnostics);
        });
    }

    #[test]
    fn lossless_preserves_exports_and_macro_bodies_as_opaque_text() {
        let input =
            b"EXPORTS foo -- semi; --\r\nbar; MACRO ::= BEGIN \"END\" -- END\r\nstuff END next";
        let (tokens, diagnostics) = assert_lossless(input);

        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwExports,
                SyntaxKind::OpaqueText,
                SyntaxKind::Semicolon,
                SyntaxKind::Whitespace,
                SyntaxKind::KwMacro,
                SyntaxKind::OpaqueText,
                SyntaxKind::KwEnd,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(
            &input[tokens[1].span.byte_range()],
            b" foo -- semi; --\r\nbar"
        );
        assert_eq!(
            &input[tokens[5].span.byte_range()],
            b" ::= BEGIN \"END\" -- END\r\nstuff "
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn macro_end_inside_underscore_identifier_does_not_terminate_body() {
        let input = b"MACRO ::= BEGIN END_SUFFIX PREFIX_END FOO_END_BAR END next";
        let terminating_end = input.len() - b"END next".len();
        let (tokens, diagnostics) = assert_lossless(input);

        assert_eq!(
            kinds(&tokens),
            vec![
                SyntaxKind::KwMacro,
                SyntaxKind::OpaqueText,
                SyntaxKind::KwEnd,
                SyntaxKind::Whitespace,
                SyntaxKind::LowercaseIdent,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(
            &input[tokens[1].span.byte_range()],
            b" ::= BEGIN END_SUFFIX PREFIX_END FOO_END_BAR "
        );
        assert_eq!(tokens[2].span.start().as_usize(), terminating_end);
        assert!(diagnostics.is_empty());

        let cfg = DiagnosticConfig::verbose();
        with_bytes_document(input, |document| {
            let (semantic, semantic_diagnostics) = Lexer::new(document, &cfg).tokenize();
            assert_eq!(
                kinds(&semantic),
                vec![
                    SyntaxKind::KwMacro,
                    SyntaxKind::KwEnd,
                    SyntaxKind::LowercaseIdent,
                    SyntaxKind::EofToken,
                ]
            );
            assert_eq!(semantic[1].span.start().as_usize(), terminating_end);
            assert!(semantic_diagnostics.is_empty());
        });
    }

    #[test]
    fn lossless_handles_empty_skipped_bodies() {
        let (exports_tokens, exports_diagnostics) = assert_lossless(b"EXPORTS;");
        assert_eq!(
            kinds(&exports_tokens),
            vec![
                SyntaxKind::KwExports,
                SyntaxKind::Semicolon,
                SyntaxKind::EofToken,
            ]
        );
        assert!(exports_diagnostics.is_empty());

        // A separator is required for MACRO and END to be distinct keywords;
        // that separator is the complete opaque body in this minimal case.
        let input = b"MACRO END";
        let (macro_tokens, macro_diagnostics) = assert_lossless(input);
        assert_eq!(
            kinds(&macro_tokens),
            vec![
                SyntaxKind::KwMacro,
                SyntaxKind::OpaqueText,
                SyntaxKind::KwEnd,
                SyntaxKind::EofToken,
            ]
        );
        assert_eq!(&input[macro_tokens[1].span.byte_range()], b" ");
        assert!(macro_diagnostics.is_empty());
    }

    #[test]
    fn lossless_resumes_after_skipped_bodies_across_modules() {
        let input = b"FIRST DEFINITIONS ::= BEGIN\n\
EXPORTS firstSymbol;\n\
END\n\
SECOND DEFINITIONS ::= BEGIN\n\
Legacy MACRO ::= BEGIN\n\
END\n\
END";
        let (tokens, diagnostics) = assert_lossless(input);

        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == SyntaxKind::KwDefinitions)
                .count(),
            2
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == SyntaxKind::KwBegin)
                .count(),
            2
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == SyntaxKind::KwEnd)
                .count(),
            3
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == SyntaxKind::OpaqueText)
                .count(),
            2
        );
        let second = tokens
            .iter()
            .find(|token| {
                token.kind == SyntaxKind::UppercaseIdent
                    && &input[token.span.byte_range()] == b"SECOND"
            })
            .expect("the second module header should be tokenized after EXPORTS");
        assert!(
            second.span.start().as_usize()
                > tokens
                    .iter()
                    .find(|token| token.kind == SyntaxKind::Semicolon)
                    .unwrap()
                    .span
                    .end()
                    .as_usize()
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn lossless_preserves_opaque_body_at_eof() {
        for input in [
            b"EXPORTS foo, bar".as_slice(),
            b"MACRO ::= BEGIN body".as_slice(),
        ] {
            let (tokens, diagnostics) = assert_lossless(input);
            assert_eq!(
                kinds(&tokens),
                vec![
                    if input.starts_with(b"EXPORTS") {
                        SyntaxKind::KwExports
                    } else {
                        SyntaxKind::KwMacro
                    },
                    SyntaxKind::OpaqueText,
                    SyntaxKind::EofToken,
                ]
            );
            assert!(diagnostics.is_empty());
        }
    }
}
