//! SMI/MIB lexer (tokenizer).
//!
//! Converts raw source bytes into a stream of [`Token`]s. Handles
//! SMIv1/SMIv2 syntax including `--` comments, hex/binary string literals,
//! MACRO body skipping, and EXPORTS body skipping.

mod keyword;
pub mod token;

pub use keyword::{is_forbidden_keyword, lookup_keyword};
pub use token::{Token, TokenKind};

use crate::types::{DiagCode, DiagnosticConfig, Span, SpanDiagnostic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerState {
    Normal,
    InMacro,
    InExports,
    InComment,
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
    source: &'src [u8],
    pos: usize,
    state: LexerState,
    comment_start: usize,
    diagnostics: Vec<SpanDiagnostic>,
    diag_config: &'cfg DiagnosticConfig,
}

impl<'src, 'cfg> Lexer<'src, 'cfg> {
    /// Create a new lexer over the given source bytes.
    pub fn new(source: &'src [u8], diag_config: &'cfg DiagnosticConfig) -> Self {
        Lexer {
            source,
            pos: 0,
            state: LexerState::Normal,
            comment_start: 0,
            diagnostics: Vec::new(),
            diag_config,
        }
    }

    /// Consume all source text and return the token stream and diagnostics.
    /// The token stream always ends with `TokenKind::Eof`.
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<SpanDiagnostic>) {
        let estimated = (self.source.len() / 6).max(64);
        let mut tokens: Vec<Token> = Vec::with_capacity(estimated);
        tokens.extend(&mut self);
        // Always terminate with EOF
        tokens.push(Token {
            kind: TokenKind::Eof,
            span: self.span_from(self.pos),
        });
        (tokens, self.diagnostics)
    }

    /// Advance the lexer and return the next token.
    ///
    /// Returns [`TokenKind::Eof`] when the input is exhausted. Unlike the
    /// [`Iterator`] impl, this always returns a token (never `None`).
    pub fn next_token(&mut self) -> Token {
        loop {
            match self.state {
                LexerState::InComment => return self.emit_comment(),
                LexerState::InMacro => return self.skip_macro_body(),
                LexerState::InExports => return self.skip_exports_body(),
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

    fn span_from(&self, start: usize) -> Span {
        Span::from_usize_offsets(start, self.pos)
    }

    fn token(&self, kind: TokenKind, start: usize) -> Token {
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

    fn emit_diagnostic(&mut self, code: DiagCode, span: Span, message: impl Into<String>) {
        let severity = code.severity();
        if !self.diag_config.should_report(code) {
            return;
        }
        self.diagnostics.push(SpanDiagnostic {
            code,
            severity,
            span,
            message: message.into(),
        });
    }

    // -- Normal state scanning --

    /// Returns None to signal retry (skipped junk or entered comment state).
    fn next_normal_token(&mut self) -> Option<Token> {
        self.skip_whitespace();

        let start = self.pos;

        let b = match self.peek() {
            None => return Some(self.token(TokenKind::Eof, start)),
            Some(b) => b,
        };

        // Comment start: --
        if self.is_comment_start() {
            self.comment_start = start;
            self.pos += 2;
            self.state = LexerState::InComment;
            return None;
        }

        // Single-character punctuation
        if let Some(kind) = punctuation_kind(b) {
            self.advance();
            return Some(self.token(kind, start));
        }

        // Dot or DotDot
        if b == b'.' {
            self.advance();
            if self.peek() == Some(b'.') {
                self.advance();
                return Some(self.token(TokenKind::DotDot, start));
            }
            return Some(self.token(TokenKind::Dot, start));
        }

        // Colon or ColonColonEqual
        if b == b':' {
            self.pos += 1;
            if self.remaining().starts_with(b":=") {
                self.pos += 2;
                return Some(self.token(TokenKind::ColonColonEqual, start));
            }
            return Some(self.token(TokenKind::Colon, start));
        }

        // Minus or NegativeNumber
        if b == b'-' {
            if let Some(next) = self.peek_at(1)
                && next.is_ascii_digit()
            {
                return Some(self.scan_negative_number());
            }
            self.advance();
            return Some(self.token(TokenKind::Minus, start));
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
        self.skip_to_eol();
        None
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
                TokenKind::KwMacro => {
                    self.state = LexerState::InMacro;
                }
                TokenKind::KwExports => {
                    self.state = LexerState::InExports;
                }
                _ => {}
            }
            return self.token(kind, start);
        }

        if is_forbidden_keyword(text) {
            return self.token(TokenKind::ForbiddenKeyword, start);
        }

        let kind = if is_uppercase {
            TokenKind::UppercaseIdent
        } else {
            TokenKind::LowercaseIdent
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
            TokenKind::NegativeNumber
        } else {
            TokenKind::Number
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
                    return self.token(TokenKind::QuotedString, start);
                }
                Some(b'"') => {
                    self.advance();
                    return self.token(TokenKind::QuotedString, start);
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
            return self.token(TokenKind::Error, start);
        }
        self.advance(); // consume closing quote

        let suffix = self.peek();
        match suffix {
            Some(b'H' | b'h') => {
                self.advance();
                for &(char_pos, b) in &content_chars {
                    if !b.is_ascii_hexdigit() {
                        let span = Span::from_usize_offsets(char_pos, char_pos + 1);
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
                self.token(TokenKind::HexString, start)
            }
            Some(b'B' | b'b') => {
                self.advance();
                for &(char_pos, b) in &content_chars {
                    if !matches!(b, b'0' | b'1') {
                        let span = Span::from_usize_offsets(char_pos, char_pos + 1);
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
                self.token(TokenKind::BinString, start)
            }
            _ => {
                let span = self.span_from(start);
                self.emit_diagnostic(
                    DiagCode::MissingHexBinSuffix,
                    span,
                    "expected 'H' or 'B' suffix for hex/binary string",
                );
                self.token(TokenKind::Error, start)
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
                self.skip_line_ending();
                true
            }
            _ => false,
        }
    }

    /// Consume comment text and return a Comment token.
    /// Span covers from '--' through comment text, not including trailing newline.
    fn emit_comment(&mut self) -> Token {
        self.skip_comment_body(true);
        let tok = self.token(TokenKind::Comment, self.comment_start);
        // Consume trailing newline if present (not part of comment span).
        if let Some(b) = self.peek()
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

    fn skip_macro_body(&mut self) -> Token {
        loop {
            self.skip_whitespace();

            if self.is_eof() {
                let start = self.pos;
                self.state = LexerState::Normal;
                return self.token(TokenKind::Eof, start);
            }

            if self.remaining().starts_with(b"END") {
                // Check preceding character is a delimiter (not alphanumeric or hyphen).
                let prev_is_delimiter = self.pos == 0
                    || (!self.source[self.pos - 1].is_ascii_alphanumeric()
                        && self.source[self.pos - 1] != b'-');
                if prev_is_delimiter {
                    let saved = self.pos;
                    self.pos += 3;
                    let is_delimiter = match self.peek() {
                        None => true,
                        Some(b'-') => self.peek_at(1) == Some(b'-'),
                        Some(b) => !b.is_ascii_alphanumeric() && b != b'-',
                    };
                    if is_delimiter {
                        self.state = LexerState::Normal;
                        return self.token(TokenKind::KwEnd, saved);
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

    fn skip_exports_body(&mut self) -> Token {
        loop {
            match self.peek() {
                None => {
                    let start = self.pos;
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::Eof, start);
                }
                Some(b';') => {
                    let start = self.pos;
                    self.advance();
                    self.state = LexerState::Normal;
                    return self.token(TokenKind::Semicolon, start);
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Returns diagnostics accumulated so far during tokenization.
    pub fn diagnostics(&self) -> &[SpanDiagnostic] {
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
        if tok.kind == TokenKind::Eof {
            None
        } else {
            Some(tok)
        }
    }
}

fn punctuation_kind(b: u8) -> Option<TokenKind> {
    match b {
        b'[' => Some(TokenKind::LBracket),
        b']' => Some(TokenKind::RBracket),
        b'{' => Some(TokenKind::LBrace),
        b'}' => Some(TokenKind::RBrace),
        b'(' => Some(TokenKind::LParen),
        b')' => Some(TokenKind::RParen),
        b';' => Some(TokenKind::Semicolon),
        b',' => Some(TokenKind::Comma),
        b'|' => Some(TokenKind::Pipe),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokenize(input: &str) -> Vec<Token> {
        let cfg = DiagnosticConfig::default();
        let lexer = Lexer::new(input.as_bytes(), &cfg);
        let (tokens, _) = lexer.tokenize();
        tokens
    }

    fn tokenize_with_diags(input: &str) -> (Vec<Token>, Vec<SpanDiagnostic>) {
        let cfg = DiagnosticConfig::verbose();
        let lexer = Lexer::new(input.as_bytes(), &cfg);
        lexer.tokenize()
    }

    fn kinds(tokens: &[Token]) -> Vec<TokenKind> {
        tokens.iter().map(|t| t.kind).collect()
    }

    fn text_of<'a>(source: &'a str, token: &Token) -> &'a str {
        &source[token.span.start.0 as usize..token.span.end.0 as usize]
    }

    #[test]
    fn empty_input() {
        let tokens = tokenize("");
        assert_eq!(kinds(&tokens), vec![TokenKind::Eof]);
    }

    #[test]
    fn whitespace_only() {
        let tokens = tokenize("   \t\n\r\n  ");
        assert_eq!(kinds(&tokens), vec![TokenKind::Eof]);
    }

    #[test]
    fn punctuation() {
        let tokens = tokenize("[ ] { } ( ) ; , |");
        assert_eq!(
            kinds(&tokens),
            vec![
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::Semicolon,
                TokenKind::Comma,
                TokenKind::Pipe,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn dots_and_colons() {
        let tokens = tokenize(". .. : ::=");
        assert_eq!(
            kinds(&tokens),
            vec![
                TokenKind::Dot,
                TokenKind::DotDot,
                TokenKind::Colon,
                TokenKind::ColonColonEqual,
                TokenKind::Eof,
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
                TokenKind::Number,
                TokenKind::Number,
                TokenKind::Number,
                TokenKind::Eof,
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
                TokenKind::NegativeNumber,
                TokenKind::NegativeNumber,
                TokenKind::Eof,
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
            vec![TokenKind::Minus, TokenKind::LowercaseIdent, TokenKind::Eof]
        );
    }

    #[test]
    fn leading_zero_diagnostic() {
        let (tokens, diags) = tokenize_with_diags("007 -042");
        assert_eq!(
            kinds(&tokens),
            vec![TokenKind::Number, TokenKind::NegativeNumber, TokenKind::Eof,]
        );
        assert_eq!(diags.len(), 2);
        assert_eq!(diags[0].code, DiagCode::NumberLeadingZero);
        assert_eq!(diags[1].code, DiagCode::NumberLeadingZero);
    }

    #[test]
    fn quoted_string() {
        let input = r#""hello world""#;
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![TokenKind::QuotedString, TokenKind::Eof]
        );
        assert_eq!(text_of(input, &tokens[0]), r#""hello world""#);
    }

    #[test]
    fn multiline_quoted_string() {
        let input = "\"line1\nline2\"";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![TokenKind::QuotedString, TokenKind::Eof]
        );
    }

    #[test]
    fn unterminated_string() {
        let (tokens, diags) = tokenize_with_diags("\"hello");
        assert_eq!(
            kinds(&tokens),
            vec![TokenKind::QuotedString, TokenKind::Eof]
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::UnterminatedString);
    }

    #[test]
    fn hex_string() {
        let input = "'0A1B'H";
        let tokens = tokenize(input);
        assert_eq!(kinds(&tokens), vec![TokenKind::HexString, TokenKind::Eof]);
    }

    #[test]
    fn bin_string() {
        let input = "'01010101'B";
        let tokens = tokenize(input);
        assert_eq!(kinds(&tokens), vec![TokenKind::BinString, TokenKind::Eof]);
    }

    #[test]
    fn hex_string_odd_length() {
        let (tokens, diags) = tokenize_with_diags("'0A1'H");
        assert_eq!(kinds(&tokens), vec![TokenKind::HexString, TokenKind::Eof]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::HexStringMul2);
    }

    #[test]
    fn bin_string_bad_length() {
        let (tokens, diags) = tokenize_with_diags("'0101'B");
        assert_eq!(kinds(&tokens), vec![TokenKind::BinString, TokenKind::Eof]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::BinStringMul8);
    }

    #[test]
    fn hex_string_missing_suffix() {
        let (tokens, diags) = tokenize_with_diags("'0A1B'");
        assert_eq!(kinds(&tokens), vec![TokenKind::Error, TokenKind::Eof]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::MissingHexBinSuffix);
    }

    #[test]
    fn unterminated_hex_string() {
        let (tokens, diags) = tokenize_with_diags("'0A1B");
        assert_eq!(kinds(&tokens), vec![TokenKind::Error, TokenKind::Eof]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::UnterminatedHexBinStr);
    }

    #[test]
    fn hex_string_invalid_chars() {
        // 0A is valid, GZ are not valid hex digits
        let (tokens, diags) = tokenize_with_diags("'0AGZ'H");
        assert_eq!(kinds(&tokens), vec![TokenKind::HexString, TokenKind::Eof]);
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
        assert_eq!(kinds(&tokens), vec![TokenKind::BinString, TokenKind::Eof]);
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
        assert_eq!(kinds(&tokens), vec![TokenKind::HexString, TokenKind::Eof]);
        assert!(
            !diags
                .iter()
                .any(|d| d.code == DiagCode::HexStringInvalidChar),
        );
    }

    #[test]
    fn bin_string_valid_no_invalid_char_diag() {
        let (tokens, diags) = tokenize_with_diags("'01010101'B");
        assert_eq!(kinds(&tokens), vec![TokenKind::BinString, TokenKind::Eof]);
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
                TokenKind::LowercaseIdent,
                TokenKind::UppercaseIdent,
                TokenKind::LowercaseIdent,
                TokenKind::Eof,
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
            vec![TokenKind::LowercaseIdent, TokenKind::Eof]
        );
        assert_eq!(text_of(input, &tokens[0]), "some-name");
    }

    #[test]
    fn identifier_with_underscore() {
        let input = "some_name";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![TokenKind::LowercaseIdent, TokenKind::Eof]
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
                TokenKind::LowercaseIdent,
                TokenKind::Comment,
                TokenKind::Eof,
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
                TokenKind::KwObjectType,
                TokenKind::KwSyntax,
                TokenKind::KwStatus,
                TokenKind::KwDescription,
                TokenKind::Eof,
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
                TokenKind::KwCurrent,
                TokenKind::KwDeprecated,
                TokenKind::KwReadOnly,
                TokenKind::KwNotAccessible,
                TokenKind::Eof,
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
                TokenKind::ForbiddenKeyword,
                TokenKind::ForbiddenKeyword,
                TokenKind::ForbiddenKeyword,
                TokenKind::ForbiddenKeyword,
                TokenKind::Eof,
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
                TokenKind::LowercaseIdent,
                TokenKind::Comment,
                TokenKind::LowercaseIdent,
                TokenKind::Eof,
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
                TokenKind::LowercaseIdent,
                TokenKind::Comment,
                TokenKind::LowercaseIdent,
                TokenKind::Eof,
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
                TokenKind::LowercaseIdent,
                TokenKind::Comment,
                TokenKind::Eof,
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
                TokenKind::Comment,
                TokenKind::LowercaseIdent,
                TokenKind::Eof,
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
                TokenKind::KwMacro,
                TokenKind::KwEnd,
                TokenKind::LowercaseIdent,
                TokenKind::Eof,
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
            .position(|t| t.kind == TokenKind::KwEnd)
            .unwrap();
        // The END that terminates should be after PRETEND.
        let next_idx = tokens
            .iter()
            .position(|t| t.kind == TokenKind::LowercaseIdent)
            .unwrap();
        assert!(end_idx < next_idx);
    }

    #[test]
    fn exports_body_skipping() {
        let input = "EXPORTS foo, bar; next";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                TokenKind::KwExports,
                TokenKind::Semicolon,
                TokenKind::LowercaseIdent,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn unexpected_character() {
        let (tokens, diags) = tokenize_with_diags("x @ y");
        // @ is unexpected, rest of line is skipped, then y is on same line so also skipped
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagCode::UnexpectedCharacter);
        // x should still be tokenized
        assert_eq!(tokens[0].kind, TokenKind::LowercaseIdent);
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
        assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);
        // Should contain expected keywords
        let k = kinds(&tokens);
        assert!(k.contains(&TokenKind::KwDefinitions));
        assert!(k.contains(&TokenKind::ColonColonEqual));
        assert!(k.contains(&TokenKind::KwBegin));
        assert!(k.contains(&TokenKind::KwImports));
        assert!(k.contains(&TokenKind::KwModuleIdentity));
        assert!(k.contains(&TokenKind::KwEnd));
    }

    #[test]
    fn hex_string_with_whitespace() {
        let input = "'0A 1B\n2C'H";
        let tokens = tokenize(input);
        assert_eq!(kinds(&tokens), vec![TokenKind::HexString, TokenKind::Eof]);
    }

    #[test]
    fn empty_hex_string() {
        let input = "''H";
        let tokens = tokenize(input);
        assert_eq!(kinds(&tokens), vec![TokenKind::HexString, TokenKind::Eof]);
    }

    #[test]
    fn type_keywords() {
        let input = "INTEGER Counter32 IpAddress OCTET STRING BITS";
        let tokens = tokenize(input);
        assert_eq!(
            kinds(&tokens),
            vec![
                TokenKind::KwInteger,
                TokenKind::KwCounter32,
                TokenKind::KwIpAddress,
                TokenKind::KwOctet,
                TokenKind::KwString,
                TokenKind::KwBits,
                TokenKind::Eof,
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
                TokenKind::Colon,
                TokenKind::Colon,
                TokenKind::Colon,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn span_offsets_correct() {
        let input = "abc 123";
        let tokens = tokenize(input);
        assert_eq!(tokens[0].span.start.0, 0);
        assert_eq!(tokens[0].span.end.0, 3);
        assert_eq!(tokens[1].span.start.0, 4);
        assert_eq!(tokens[1].span.end.0, 7);
    }
}
