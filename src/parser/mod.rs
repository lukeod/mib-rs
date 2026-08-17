//! Recursive descent parser for SMI MIB modules.
//!
//! Parses SMIv1 and SMIv2 syntax (plus common vendor deviations) into
//! [`ast::Module`](crate::ast::Module) nodes. Uses a 3-token lookahead
//! buffer and recovers from errors by scanning to the next definition boundary.

use std::borrow::Cow;

use crate::ast::*;
use crate::lexer::{Lexer, Token, TokenKind};
use crate::source::{ByteOffset, SourceDocument, SourceRange};
use crate::types::{Access, AccessKeyword, DiagCode, Diagnostic, DiagnosticConfig, Status};
use tracing::{debug, debug_span, info_span, trace};

type TcBody = (
    Option<QuotedString>,
    StatusClause,
    QuotedString,
    Option<QuotedString>,
    SyntaxClause,
);

fn cover(first: SourceRange, last: SourceRange) -> SourceRange {
    SourceRange::cover(first, last).expect("parser ranges belong to one source document")
}

/// Recursive descent parser for SMI MIB modules.
///
/// Consumes tokens from a lexer and produces [`Module`] AST nodes
/// with collected diagnostics. Handles both SMIv1 and SMIv2 syntax,
/// plus common vendor deviations.
///
/// Uses a 3-token lookahead buffer and recovers from parse errors by
/// scanning forward to the next definition boundary.
pub struct Parser<'src, 'cfg> {
    document: &'src SourceDocument,
    lexer: Lexer<'src, 'cfg>,
    buf: [Token; 3],
    last_span: SourceRange,
    lexer_diagnostic_cursor: usize,
    diagnostics: Vec<Diagnostic>,
    diag_config: &'cfg DiagnosticConfig,
    eof_token: Token,
}

fn next_non_comment(lexer: &mut Lexer<'_, '_>) -> Token {
    loop {
        let tok = lexer.next_token();
        if tok.kind != TokenKind::Comment {
            return tok;
        }
    }
}

impl<'src, 'cfg> Parser<'src, 'cfg> {
    /// Create a new parser over a retained source document.
    ///
    /// Internally constructs a lexer and primes the lookahead buffer.
    pub fn new(document: &'src SourceDocument, diag_config: &'cfg DiagnosticConfig) -> Self {
        let mut lexer = Lexer::new(document, diag_config);
        let eof_span = document
            .empty_range(document.bytes().len())
            .expect("the document EOF is a valid source position");
        let eof_token = Token {
            kind: TokenKind::Eof,
            span: eof_span,
        };

        let buf = [
            next_non_comment(&mut lexer),
            next_non_comment(&mut lexer),
            next_non_comment(&mut lexer),
        ];

        debug!(
            target: "mib_rs::parser",
            component = "parser",
            "parser initialized",
        );

        Parser {
            document,
            lexer,
            buf,
            last_span: document
                .empty_range(0)
                .expect("the document start is a valid source position"),
            lexer_diagnostic_cursor: 0,
            diagnostics: Vec::new(),
            diag_config,
            eof_token,
        }
    }

    // ---- Core control flow ----

    fn peek(&self) -> Token {
        self.buf[0]
    }

    fn peek_nth(&self, n: usize) -> Token {
        if n < self.buf.len() {
            self.buf[n]
        } else {
            self.eof_token
        }
    }

    fn advance(&mut self) -> Token {
        let tok = self.buf[0];
        self.buf[0] = self.buf[1];
        self.buf[1] = self.buf[2];
        self.buf[2] = next_non_comment(&mut self.lexer);
        self.last_span = tok.span;
        tok
    }

    fn check(&self, kind: TokenKind) -> bool {
        self.peek().kind == kind
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token, Diagnostic> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            Err(self.make_error(format!("expected {}", kind.display_name())))
        }
    }

    fn current_span(&self) -> SourceRange {
        self.peek().span
    }

    fn range_to_current_start(&self, start: SourceRange) -> SourceRange {
        let current = self.current_span();
        assert_eq!(start.source(), self.document.id());
        assert_eq!(current.source(), self.document.id());
        self.document
            .range(start.start().as_usize()..current.start().as_usize())
            .expect("parser range endpoints are ordered within its source document")
    }

    fn is_eof(&self) -> bool {
        self.peek().kind == TokenKind::Eof
    }

    fn text(&self, span: SourceRange) -> Cow<'src, str> {
        String::from_utf8_lossy(
            self.document
                .slice(span)
                .expect("parser ranges belong to its source document"),
        )
    }

    fn make_error(&self, message: String) -> Diagnostic {
        Diagnostic {
            severity: self.diag_config.effective_severity(DiagCode::ParseError),
            code: DiagCode::ParseError,
            message,
            module: None,
            range: Some(self.current_span()),
        }
    }

    fn record_parse_error(&mut self, mut diag: Diagnostic) {
        if !self.diag_config.should_collect(diag.code) {
            return;
        }
        diag.severity = self.diag_config.effective_severity(diag.code);
        self.diagnostics.push(diag);
    }

    fn emit_diagnostic(&mut self, code: DiagCode, span: SourceRange, message: impl Into<String>) {
        if !self.diag_config.should_collect(code) {
            return;
        }
        self.diagnostics.push(Diagnostic {
            severity: self.diag_config.effective_severity(code),
            code,
            message: message.into(),
            module: None,
            range: Some(span),
        });
    }

    fn emit_diagnostic_with<F>(&mut self, code: DiagCode, span: SourceRange, message: F)
    where
        F: FnOnce() -> String,
    {
        if !self.diag_config.should_collect(code) {
            return;
        }
        self.diagnostics.push(Diagnostic {
            severity: self.diag_config.effective_severity(code),
            code,
            message: message(),
            module: None,
            range: Some(span),
        });
    }

    // ---- Helper methods ----

    fn make_ident(&self, token: Token) -> Ident {
        Ident {
            name: self.text(token.span).to_string(),
            span: token.span,
        }
    }

    fn make_ident_with_validation(&mut self, token: Token) -> Ident {
        let name = self.text(token.span).to_string();
        self.validate_identifier(&name, token.span);
        Ident {
            name,
            span: token.span,
        }
    }

    fn validate_identifier(&mut self, name: &str, span: SourceRange) {
        if name.contains('_') {
            self.emit_diagnostic_with(DiagCode::IdentifierUnderscore, span, || {
                format!("identifier {:?} contains underscore (RFC violation)", name)
            });
        }
        if name.ends_with('-') {
            self.emit_diagnostic_with(DiagCode::IdentifierHyphenEnd, span, || {
                format!("identifier {:?} ends with hyphen", name)
            });
        }
        if name.len() > 64 {
            self.emit_diagnostic_with(DiagCode::IdentifierLength64, span, || {
                format!(
                    "identifier {:?} exceeds 64 character limit ({} chars)",
                    name,
                    name.len()
                )
            });
        } else if name.len() > 32 {
            self.emit_diagnostic_with(DiagCode::IdentifierLength32, span, || {
                format!(
                    "identifier {:?} exceeds 32 character recommendation ({} chars)",
                    name,
                    name.len()
                )
            });
        }
    }

    fn validate_value_reference(&mut self, name: &str, span: SourceRange) {
        if let Some(first) = name.bytes().next()
            && first.is_ascii_uppercase()
        {
            self.emit_diagnostic_with(DiagCode::BadIdentifierCase, span, || {
                format!("{:?} should start with a lowercase letter", name)
            });
        }
    }

    fn expect_identifier(&mut self) -> Result<Token, Diagnostic> {
        if self.peek().kind.is_identifier() {
            return Ok(self.advance());
        }
        if self.check(TokenKind::ForbiddenKeyword) {
            let token = self.advance();
            let name = self.text(token.span).to_string();
            self.emit_diagnostic_with(DiagCode::KeywordReserved, token.span, || {
                format!("identifier {:?} is a reserved ASN.1 keyword", name)
            });
            return Ok(token);
        }
        Err(self.make_error("expected identifier".to_string()))
    }

    fn expect_index_object(&mut self) -> Result<Token, Diagnostic> {
        if self.peek().kind.is_identifier() || self.peek().kind.is_type_keyword() {
            return Ok(self.advance());
        }
        Err(self.make_error("expected index object".to_string()))
    }

    fn expect_enum_label(&mut self) -> Result<Token, Diagnostic> {
        if self.peek().kind.is_identifier() || self.peek().kind.is_keyword() {
            return Ok(self.advance());
        }
        Err(self.make_error("expected enum label".to_string()))
    }

    fn parse_identifier_as_ident(&mut self) -> Result<Ident, Diagnostic> {
        let token = self.expect_identifier()?;
        Ok(self.make_ident(token))
    }

    fn parse_quoted_string(&mut self) -> Result<QuotedString, Diagnostic> {
        if !self.check(TokenKind::QuotedString) {
            return Err(self.make_error("expected quoted string".to_string()));
        }
        let token = self.advance();
        let full_text = self.text(token.span);
        let value = if full_text.len() >= 2 && full_text.ends_with('"') {
            full_text[1..full_text.len() - 1].to_string()
        } else if !full_text.is_empty() {
            full_text[1..].to_string()
        } else {
            String::new()
        };
        Ok(QuotedString {
            value,
            span: token.span,
        })
    }

    fn parse_optional_reference(&mut self) -> Result<Option<QuotedString>, Diagnostic> {
        if !self.check(TokenKind::KwReference) {
            return Ok(None);
        }
        self.advance();
        Ok(Some(self.parse_quoted_string()?))
    }

    fn parse_u32(&mut self, span: SourceRange, context: &str) -> Result<u32, Diagnostic> {
        let text = self.text(span);
        match text.parse::<u32>() {
            Ok(v) => Ok(v),
            Err(_) => {
                self.emit_diagnostic(
                    DiagCode::InvalidU32,
                    span,
                    format!("invalid {} (not a valid u32)", context),
                );
                Err(self.make_error(format!("invalid {} (not a valid u32)", context)))
            }
        }
    }

    fn parse_i64(&mut self, span: SourceRange, context: &str) -> Result<i64, Diagnostic> {
        let text = self.text(span);
        match text.parse::<i64>() {
            Ok(v) => Ok(v),
            Err(_) => {
                self.emit_diagnostic(
                    DiagCode::InvalidI64,
                    span,
                    format!("invalid {} (not a valid i64)", context),
                );
                Err(self.make_error(format!("invalid {} (not a valid i64)", context)))
            }
        }
    }

    fn skip_braced_content(&mut self, consume_close: bool) {
        let mut depth: u32 = 1;
        while depth > 0 && !self.is_eof() {
            match self.peek().kind {
                TokenKind::LBrace => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::RBrace => {
                    depth -= 1;
                    if depth > 0 || consume_close {
                        self.advance();
                    }
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn collect_module_diagnostics(
        &mut self,
        ownership_end: ByteOffset,
        module_name: Option<&str>,
    ) -> Vec<Diagnostic> {
        let lexer_diagnostics = self.lexer.diagnostics();
        let owned_count = lexer_diagnostics[self.lexer_diagnostic_cursor..]
            .iter()
            .take_while(|diag| {
                diag.range
                    .is_some_and(|range| range.start() < ownership_end)
            })
            .count();
        let owned_end = self.lexer_diagnostic_cursor + owned_count;

        let mut combined = Vec::with_capacity(owned_count + self.diagnostics.len());
        combined.extend_from_slice(&lexer_diagnostics[self.lexer_diagnostic_cursor..owned_end]);
        self.lexer_diagnostic_cursor = owned_end;
        combined.append(&mut self.diagnostics);
        if let Some(module_name) = module_name {
            for diagnostic in &mut combined {
                diagnostic.module = Some(module_name.to_owned());
            }
        }
        combined
    }

    // ---- List helpers ----

    fn parse_identifier_list(&mut self) -> Result<Vec<Ident>, Diagnostic> {
        let mut idents = Vec::new();
        loop {
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }
            let token = self.expect_identifier()?;
            idents.push(self.make_ident(token));
            if !self.check(TokenKind::Comma) {
                break;
            }
            self.advance(); // consume comma
        }
        Ok(idents)
    }

    fn parse_braced_identifier_list(&mut self) -> Result<Vec<Ident>, Diagnostic> {
        self.expect(TokenKind::LBrace)?;
        let idents = self.parse_identifier_list()?;
        self.expect(TokenKind::RBrace)?;
        Ok(idents)
    }

    // ---- Error recovery ----

    fn recover_to_definition(&mut self) {
        while !self.is_eof() && !self.check(TokenKind::KwEnd) {
            let current = self.peek().kind;
            let next = self.peek_nth(1).kind;

            if (current.is_identifier() && next.is_macro_keyword())
                || (current.is_identifier() && next == TokenKind::ColonColonEqual)
                || (current == TokenKind::UppercaseIdent && next == TokenKind::KwTextualConvention)
                || (current == TokenKind::UppercaseIdent && next == TokenKind::KwMacro)
                || (current.is_identifier()
                    && next == TokenKind::KwObject
                    && self.peek_nth(2).kind == TokenKind::KwIdentifier)
            {
                break;
            }

            self.advance();
        }
    }

    // ---- Module parsing ----

    /// Parse all MIB modules in the source.
    ///
    /// A single source file may contain multiple modules (e.g. concatenated
    /// RFC MIB files). Each returned [`Module`] carries its own diagnostics.
    /// Parsing stops early if a module header cannot be parsed.
    pub fn parse_modules(&mut self) -> Vec<Module> {
        let mut modules = Vec::new();

        while !self.is_eof() {
            let module = self.parse_one_module();
            let failed = module.name.is_none();
            modules.push(module);
            if failed {
                break;
            }
        }

        if modules.is_empty() {
            let module = self.parse_one_module();
            modules.push(module);
        }

        modules
    }

    fn parse_one_module(&mut self) -> Module {
        self.diagnostics.clear();

        let start = self.current_span();

        let name = match self.parse_module_header() {
            Ok(name) => name,
            Err(diag) => {
                self.record_parse_error(diag);
                debug!(
                    target: "mib_rs::parser",
                    component = "parser",
                    reason = "module_header_parse_failed",
                    "failed to parse module header",
                );
                let span = cover(start, self.current_span());
                return Module {
                    name: None,
                    imports: Vec::new(),
                    body: Vec::new(),
                    span,
                    diagnostics: self.collect_module_diagnostics(self.eof_token.span.end(), None),
                };
            }
        };

        let module_name = name.name.clone();
        let module_span = debug_span!(
            target: "mib_rs::parser",
            "parse_module",
            component = "parser",
            module = %module_name,
        );
        let _module_guard = module_span.enter();

        debug!(
            target: "mib_rs::parser",
            component = "parser",
            module = %module_name,
            "parsing module",
        );

        let mut imports = Vec::new();
        if self.check(TokenKind::KwImports) {
            match self.parse_imports() {
                Ok(imp) => {
                    debug!(
                        target: "mib_rs::parser",
                        component = "parser",
                        module = %module_name,
                        import_count = imp.len(),
                        "parsed imports",
                    );
                    imports = imp;
                }
                Err(diag) => {
                    debug!(
                        target: "mib_rs::parser",
                        component = "parser",
                        module = %module_name,
                        reason = "imports_parse_failed",
                        "failed to parse imports",
                    );
                    self.record_parse_error(diag);
                }
            }
        }

        let mut body: Vec<Definition> = Vec::new();
        while !self.check(TokenKind::KwEnd) && !self.is_eof() {
            // The lexer consumes each EXPORTS body, leaving the keyword and
            // optional semicolon. Skip consecutive clauses here so their count
            // does not add recursion depth to definition parsing.
            while self.check(TokenKind::KwExports) {
                self.advance();
                if self.check(TokenKind::Semicolon) {
                    self.advance();
                }
            }

            if self.check(TokenKind::KwEnd) || self.is_eof() {
                break;
            }

            let pos_before = self.current_span();
            trace!(
                target: "mib_rs::parser",
                component = "parser",
                phase = "definitions",
                offset = pos_before.start().get(),
                first = %self.peek().kind.display_name(),
                second = %self.peek_nth(1).kind.display_name(),
                "parsing definition",
            );
            match self.parse_definition() {
                Ok(def) => body.push(def),
                Err(diag) => {
                    self.record_parse_error(diag);
                    self.recover_to_definition();
                    if self.current_span() == pos_before {
                        self.advance();
                    }
                }
            }
        }

        if self.check(TokenKind::KwEnd) {
            self.advance();
        } else {
            self.record_parse_error(self.make_error("expected END".to_string()));
        }

        let span = cover(start, self.last_span);
        let ownership_end = if self.is_eof() {
            self.eof_token.span.end()
        } else {
            self.last_span.end()
        };
        let diagnostics = self.collect_module_diagnostics(ownership_end, Some(&module_name));

        debug!(
            target: "mib_rs::parser",
            module = %name.name,
            component = "parser",
            definition_count = body.len(),
            diagnostic_count = diagnostics.len(),
            "parsing complete",
        );

        Module {
            name: Some(name),
            imports,
            body,
            span,
            diagnostics,
        }
    }

    fn parse_module_header(&mut self) -> Result<Ident, Diagnostic> {
        let name_token = self.expect_identifier()?;
        let name = self.make_ident_with_validation(name_token);

        // Skip obsolete module OID before DEFINITIONS
        if self.check(TokenKind::LBrace) {
            self.advance();
            self.skip_braced_content(true);
        }

        self.expect(TokenKind::KwDefinitions)?;
        self.expect(TokenKind::ColonColonEqual)?;
        self.expect(TokenKind::KwBegin)?;

        Ok(name)
    }

    // ---- Import parsing ----

    fn parse_imports(&mut self) -> Result<Vec<ImportClause>, Diagnostic> {
        self.expect(TokenKind::KwImports)?;

        let mut clauses = Vec::new();

        while !self.check(TokenKind::Semicolon) && !self.check(TokenKind::KwEnd) && !self.is_eof() {
            let start = self.current_span();
            let mut symbols = Vec::new();

            // Collect symbols until FROM
            loop {
                let kind = self.peek().kind;
                if kind == TokenKind::KwFrom
                    || kind == TokenKind::Semicolon
                    || kind == TokenKind::KwEnd
                    || kind == TokenKind::Eof
                {
                    break;
                }

                if kind.is_macro_keyword() || kind.is_type_keyword() || kind.is_identifier() {
                    let token = self.advance();
                    symbols.push(self.make_ident(token));
                } else {
                    return Err(self.make_error("expected symbol or FROM".to_string()));
                }

                if self.check(TokenKind::Comma) {
                    self.advance();
                }
            }

            self.expect(TokenKind::KwFrom)?;

            let module_token = self.expect(TokenKind::UppercaseIdent)?;
            let from_module = self.make_ident(module_token);

            let span = cover(start, self.last_span);
            clauses.push(ImportClause {
                symbols,
                from_module,
                span,
            });
        }

        if self.check(TokenKind::Semicolon) {
            self.advance();
        } else {
            self.record_parse_error(self.make_error("unexpected end of imports".to_string()));
        }

        Ok(clauses)
    }

    // ---- Definition dispatch ----

    fn parse_definition(&mut self) -> Result<Definition, Diagnostic> {
        let first = self.peek().kind;
        let second = self.peek_nth(1).kind;

        match second {
            // Value assignment: name OBJECT IDENTIFIER ::=
            TokenKind::KwObject
                if first.is_identifier() && self.peek_nth(2).kind == TokenKind::KwIdentifier =>
            {
                self.parse_value_assignment()
            }

            // SMI macro definitions dispatched by keyword
            TokenKind::KwObjectType if first.is_identifier() => self.parse_object_type(),
            TokenKind::KwModuleIdentity if first.is_identifier() => self.parse_module_identity(),
            TokenKind::KwObjectIdentity if first.is_identifier() => self.parse_object_identity(),
            TokenKind::KwNotificationType if first.is_identifier() => {
                self.parse_notification_type()
            }
            TokenKind::KwTrapType if first.is_identifier() => self.parse_trap_type(),
            TokenKind::KwTextualConvention if first == TokenKind::UppercaseIdent => {
                self.parse_textual_convention()
            }
            TokenKind::KwObjectGroup if first.is_identifier() => self.parse_object_group(),
            TokenKind::KwNotificationGroup if first.is_identifier() => {
                self.parse_notification_group()
            }
            TokenKind::KwModuleCompliance if first.is_identifier() => {
                self.parse_module_compliance()
            }
            TokenKind::KwAgentCapabilities if first.is_identifier() => {
                self.parse_agent_capabilities()
            }

            // Type assignment or assignment-style TC: TypeName ::= ...
            // Type keywords (IpAddress, Counter32, etc.) can appear on LHS in base
            // module definitions like SNMPv2-SMI.
            TokenKind::ColonColonEqual
                if first == TokenKind::UppercaseIdent
                    || first == TokenKind::LowercaseIdent
                    || first.is_type_keyword() =>
            {
                if self.peek_nth(2).kind == TokenKind::KwTextualConvention {
                    return self.parse_textual_convention_with_assignment();
                }
                if first == TokenKind::LowercaseIdent {
                    let name = self.text(self.peek().span).to_string();
                    self.emit_diagnostic_with(
                        DiagCode::BadIdentifierCase,
                        self.peek().span,
                        || {
                            format!(
                                "type assignment {:?} should start with an uppercase letter",
                                name
                            )
                        },
                    );
                }
                self.parse_type_assignment()
            }

            // MACRO definition (name can be a macro keyword like OBJECT-TYPE)
            TokenKind::KwMacro
                if first == TokenKind::UppercaseIdent || first.is_macro_keyword() =>
            {
                self.parse_macro_definition()
            }

            _ => Err(self.make_error(format!(
                "unexpected token: {}",
                self.peek().kind.display_name()
            ))),
        }
    }

    // ---- Definition parsers ----

    fn parse_object_type(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwObjectType)?;

        // SYNTAX (required)
        self.expect(TokenKind::KwSyntax)?;
        let syntax = self.parse_syntax_clause()?;

        // UNITS (optional)
        let units = if self.check(TokenKind::KwUnits) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // ACCESS / MAX-ACCESS / MIN-ACCESS (required)
        let access = self.parse_access_clause()?;

        // STATUS
        let status = if self.check(TokenKind::KwStatus) {
            Some(self.parse_status_clause()?)
        } else {
            None
        };

        // DESCRIPTION (optional)
        let description = if self.check(TokenKind::KwDescription) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // INDEX or AUGMENTS (optional)
        let (index, augments) = self.parse_index_or_augments()?;

        // DEFVAL (optional)
        let defval = if self.check(TokenKind::KwDefval) {
            Some(self.parse_defval_clause()?)
        } else {
            None
        };

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::ObjectType(Box::new(ObjectTypeDef {
            name,
            syntax: Some(syntax),
            units,
            access: Some(access),
            status,
            description,
            reference,
            index,
            augments,
            defval,
            oid,
            span,
        })))
    }

    fn parse_module_identity(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwModuleIdentity)?;

        // LAST-UPDATED
        self.expect(TokenKind::KwLastUpdated)?;
        let last_updated = self.parse_quoted_string()?;

        // ORGANIZATION
        self.expect(TokenKind::KwOrganization)?;
        let organization = self.parse_quoted_string()?;

        // CONTACT-INFO
        self.expect(TokenKind::KwContactInfo)?;
        let contact_info = self.parse_quoted_string()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REVISION clauses (0+)
        let mut revisions = Vec::new();
        while self.check(TokenKind::KwRevision) {
            let rev_start = self.current_span();
            self.advance();
            let date = self.parse_quoted_string()?;
            self.expect(TokenKind::KwDescription)?;
            let rev_desc = self.parse_quoted_string()?;
            let rev_span = cover(rev_start, rev_desc.span);
            revisions.push(RevisionClause {
                date,
                description: rev_desc,
                span: rev_span,
            });
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::ModuleIdentity(ModuleIdentityDef {
            name,
            last_updated,
            organization,
            contact_info,
            description,
            revisions,
            oid,
            span,
        }))
    }

    fn parse_object_identity(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwObjectIdentity)?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::ObjectIdentity(ObjectIdentityDef {
            name,
            status,
            description,
            reference,
            oid,
            span,
        }))
    }

    fn parse_notification_type(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwNotificationType)?;

        // OBJECTS (optional)
        let objects = if self.check(TokenKind::KwObjects) {
            self.advance();
            self.parse_braced_identifier_list()?
        } else {
            Vec::new()
        };

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::NotificationType(NotificationTypeDef {
            name,
            objects,
            status,
            description,
            reference,
            oid,
            span,
        }))
    }

    fn parse_trap_type(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::KwTrapType)?;

        // ENTERPRISE
        self.expect(TokenKind::KwEnterprise)?;
        let enterprise_token = self.expect_identifier()?;
        let enterprise = self.make_ident(enterprise_token);

        // VARIABLES (optional)
        let variables = if self.check(TokenKind::KwVariables) {
            self.advance();
            self.parse_braced_identifier_list()?
        } else {
            Vec::new()
        };

        // DESCRIPTION (optional)
        let description = if self.check(TokenKind::KwDescription) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // ::= number
        self.expect(TokenKind::ColonColonEqual)?;
        let num_token = self.expect(TokenKind::Number)?;
        let trap_number = self.parse_u32(num_token.span, "trap number")?;

        let span = cover(start, self.last_span);
        Ok(Definition::TrapType(TrapTypeDef {
            name,
            enterprise,
            variables,
            description,
            reference,
            trap_number,
            span,
        }))
    }

    fn parse_textual_convention(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::KwTextualConvention)?;

        let (display_hint, status, description, reference, syntax) =
            self.parse_textual_convention_body()?;

        let span = cover(start, syntax.span);
        Ok(Definition::TextualConvention(TextualConventionDef {
            name,
            display_hint,
            status,
            description,
            reference,
            syntax,
            span,
        }))
    }

    fn parse_textual_convention_with_assignment(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::ColonColonEqual)?;
        self.expect(TokenKind::KwTextualConvention)?;

        let (display_hint, status, description, reference, syntax) =
            self.parse_textual_convention_body()?;

        let span = cover(start, syntax.span);
        Ok(Definition::TextualConvention(TextualConventionDef {
            name,
            display_hint,
            status,
            description,
            reference,
            syntax,
            span,
        }))
    }

    fn parse_textual_convention_body(&mut self) -> Result<TcBody, Diagnostic> {
        // DISPLAY-HINT (optional)
        let display_hint = if self.check(TokenKind::KwDisplayHint) {
            self.advance();
            Some(self.parse_quoted_string()?)
        } else {
            None
        };

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // SYNTAX
        self.expect(TokenKind::KwSyntax)?;
        let syntax = self.parse_syntax_clause()?;

        Ok((display_hint, status, description, reference, syntax))
    }

    fn parse_type_assignment(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::ColonColonEqual)?;
        let syntax = self.parse_type_syntax()?;

        let span = cover(start, syntax.span());
        Ok(Definition::TypeAssignment(TypeAssignmentDef {
            name,
            syntax,
            span,
        }))
    }

    fn parse_value_assignment(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwObject)?;
        self.expect(TokenKind::KwIdentifier)?;
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::ValueAssignment(ValueAssignmentDef {
            name,
            oid,
            span,
        }))
    }

    fn parse_object_group(&mut self) -> Result<Definition, Diagnostic> {
        self.parse_group_def(
            TokenKind::KwObjectGroup,
            TokenKind::KwObjects,
            |name, objects, status, description, reference, oid, span| {
                Definition::ObjectGroup(ObjectGroupDef {
                    name,
                    objects,
                    status,
                    description,
                    reference,
                    oid,
                    span,
                })
            },
        )
    }

    fn parse_notification_group(&mut self) -> Result<Definition, Diagnostic> {
        self.parse_group_def(
            TokenKind::KwNotificationGroup,
            TokenKind::KwNotifications,
            |name, notifications, status, description, reference, oid, span| {
                Definition::NotificationGroup(NotificationGroupDef {
                    name,
                    notifications,
                    status,
                    description,
                    reference,
                    oid,
                    span,
                })
            },
        )
    }

    fn parse_group_def<F>(
        &mut self,
        macro_kw: TokenKind,
        members_kw: TokenKind,
        build: F,
    ) -> Result<Definition, Diagnostic>
    where
        F: FnOnce(
            Ident,
            Vec<Ident>,
            StatusClause,
            QuotedString,
            Option<QuotedString>,
            OidAssignment,
            SourceRange,
        ) -> Definition,
    {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(macro_kw)?;

        // Members keyword + braced list
        self.expect(members_kw)?;
        let members = self.parse_braced_identifier_list()?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(build(
            name,
            members,
            status,
            description,
            reference,
            oid,
            span,
        ))
    }

    fn parse_module_compliance(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwModuleCompliance)?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // MODULE clauses (0+)
        let mut modules = Vec::new();
        while self.check(TokenKind::KwModule) {
            modules.push(self.parse_compliance_module()?);
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::ModuleCompliance(ModuleComplianceDef {
            name,
            status,
            description,
            reference,
            modules,
            oid,
            span,
        }))
    }

    fn parse_compliance_module(&mut self) -> Result<ComplianceModule, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwModule)?;

        // Optional module name
        let module_name = if self.check(TokenKind::UppercaseIdent) {
            let token = self.advance();
            Some(self.make_ident(token))
        } else {
            None
        };

        // Optional module OID
        let module_oid = if self.check(TokenKind::LBrace) {
            Some(self.parse_oid_assignment()?)
        } else {
            None
        };

        // Optional MANDATORY-GROUPS
        let mandatory_groups = if self.check(TokenKind::KwMandatoryGroups) {
            self.advance();
            self.parse_braced_identifier_list()?
        } else {
            Vec::new()
        };

        // GROUP and OBJECT refinements
        let mut compliances = Vec::new();
        while self.check(TokenKind::KwGroup) || self.check(TokenKind::KwObject) {
            if self.check(TokenKind::KwGroup) {
                compliances.push(Compliance::Group(self.parse_compliance_group()?));
            } else {
                compliances.push(Compliance::Object(Box::new(
                    self.parse_compliance_object()?,
                )));
            }
        }

        let span = cover(start, self.last_span);
        Ok(ComplianceModule {
            module_name,
            module_oid,
            mandatory_groups,
            compliances,
            span,
        })
    }

    fn parse_compliance_group(&mut self) -> Result<ComplianceGroup, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwGroup)?;

        let group = self.parse_identifier_as_ident()?;

        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        let span = cover(start, description.span);
        Ok(ComplianceGroup {
            group,
            description,
            span,
        })
    }

    fn parse_compliance_object(&mut self) -> Result<ComplianceObject, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwObject)?;

        let object = self.parse_identifier_as_ident()?;

        // Optional SYNTAX and WRITE-SYNTAX
        let (syntax, write_syntax) = self.parse_optional_syntax_clauses()?;

        // Optional MIN-ACCESS
        let min_access = if self.check(TokenKind::KwMinAccess) {
            Some(self.parse_access_clause()?)
        } else {
            None
        };

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        let span = cover(start, description.span);
        Ok(ComplianceObject {
            object,
            syntax,
            write_syntax,
            min_access,
            description,
            span,
        })
    }

    fn parse_optional_syntax_clauses(
        &mut self,
    ) -> Result<(Option<SyntaxClause>, Option<SyntaxClause>), Diagnostic> {
        let syntax = if self.check(TokenKind::KwSyntax) {
            self.advance();
            Some(self.parse_syntax_clause()?)
        } else {
            None
        };

        let write_syntax = if self.check(TokenKind::KwWriteSyntax) {
            self.advance();
            Some(self.parse_syntax_clause()?)
        } else {
            None
        };

        Ok((syntax, write_syntax))
    }

    fn parse_agent_capabilities(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwAgentCapabilities)?;

        // PRODUCT-RELEASE
        self.expect(TokenKind::KwProductRelease)?;
        let product_release = self.parse_quoted_string()?;

        // STATUS
        let status = self.parse_status_clause()?;

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        // REFERENCE (optional)
        let reference = self.parse_optional_reference()?;

        // SUPPORTS clauses (0+)
        let mut supports = Vec::new();
        while self.check(TokenKind::KwSupports) {
            supports.push(self.parse_supports_module()?);
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = cover(start, oid.span);
        Ok(Definition::AgentCapabilities(AgentCapabilitiesDef {
            name,
            product_release,
            status,
            description,
            reference,
            supports,
            oid,
            span,
        }))
    }

    fn parse_supports_module(&mut self) -> Result<SupportsModule, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwSupports)?;

        let module_name = self.parse_identifier_as_ident()?;

        // Optional module OID
        let module_oid = if self.check(TokenKind::LBrace) {
            Some(self.parse_oid_assignment()?)
        } else {
            None
        };

        // INCLUDES
        self.expect(TokenKind::KwIncludes)?;
        let includes = self.parse_braced_identifier_list()?;

        // VARIATION clauses (0+)
        let mut variations = Vec::new();
        while self.check(TokenKind::KwVariation) {
            variations.push(self.parse_variation_clause()?);
        }

        let span = cover(start, self.last_span);
        Ok(SupportsModule {
            module_name,
            module_oid,
            includes,
            variations,
            span,
        })
    }

    fn parse_variation_clause(&mut self) -> Result<Variation, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwVariation)?;

        let name = self.parse_identifier_as_ident()?;

        // Optional SYNTAX and WRITE-SYNTAX
        let (syntax, write_syntax) = self.parse_optional_syntax_clauses()?;

        // Optional ACCESS
        let access = if self.check(TokenKind::KwAccess) {
            Some(self.parse_access_clause()?)
        } else {
            None
        };

        // Optional CREATION-REQUIRES
        let creation_requires = if self.check(TokenKind::KwCreationRequires) {
            self.advance();
            self.parse_braced_identifier_list()?
        } else {
            Vec::new()
        };

        // Optional DEFVAL
        let defval = if self.check(TokenKind::KwDefval) {
            Some(self.parse_defval_clause()?)
        } else {
            None
        };

        // DESCRIPTION
        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        let span = cover(start, description.span);
        Ok(Variation {
            name,
            syntax,
            write_syntax,
            access,
            creation_requires,
            defval,
            description,
            span,
        })
    }

    fn parse_macro_definition(&mut self) -> Result<Definition, Diagnostic> {
        let start = self.current_span();

        let name_token = self.advance();
        let name = self.make_ident(name_token);

        // Skip everything until END (the lexer already handles MACRO body
        // skipping via its InMacro state, which will emit END when found).
        // After the MACRO keyword token, the lexer entered InMacro state and
        // will only emit KwEnd when it finds standalone END.
        // But we already consumed the name, so the next token from our buffer
        // might already be KwEnd if the macro body was consumed by the lexer.
        // Actually the lexer transitions to InMacro when it sees the MACRO keyword.
        // So after our advance() of the name, the MACRO keyword is in buf[0].
        // We consume it, then the lexer has entered InMacro and will emit KwEnd.
        self.expect(TokenKind::KwMacro)?;
        // Now the lexer is in InMacro mode. The next non-comment token from
        // the buffer will be KwEnd (or Eof if malformed).
        if self.check(TokenKind::KwEnd) {
            self.advance();
        }

        let span = cover(start, self.last_span);
        Ok(Definition::MacroDefinition(MacroDefinitionDef {
            name,
            span,
        }))
    }

    // ---- Clause parsers ----

    fn parse_access_clause(&mut self) -> Result<AccessClause, Diagnostic> {
        let start = self.current_span();

        let keyword = if self.check(TokenKind::KwMaxAccess) {
            self.advance();
            AccessKeyword::MaxAccess
        } else if self.check(TokenKind::KwAccess) {
            self.advance();
            AccessKeyword::Access
        } else if self.check(TokenKind::KwMinAccess) {
            self.advance();
            AccessKeyword::MinAccess
        } else {
            return Err(self.make_error("expected MAX-ACCESS, MIN-ACCESS, or ACCESS".to_string()));
        };

        let value = match self.peek().kind {
            TokenKind::KwReadOnly => {
                self.advance();
                Access::ReadOnly
            }
            TokenKind::KwReadWrite => {
                self.advance();
                Access::ReadWrite
            }
            TokenKind::KwReadCreate => {
                self.advance();
                Access::ReadCreate
            }
            TokenKind::KwNotAccessible => {
                self.advance();
                Access::NotAccessible
            }
            TokenKind::KwAccessibleForNotify => {
                self.advance();
                Access::AccessibleForNotify
            }
            TokenKind::KwWriteOnly => {
                self.advance();
                Access::WriteOnly
            }
            TokenKind::KwNotImplemented => {
                self.advance();
                Access::NotImplemented
            }
            _ => return Err(self.make_error("expected access value".to_string())),
        };

        let span = cover(start, self.last_span);
        Ok(AccessClause {
            keyword,
            value,
            span,
        })
    }

    fn parse_status_clause(&mut self) -> Result<StatusClause, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwStatus)?;

        let value = match self.peek().kind {
            TokenKind::KwCurrent => {
                self.advance();
                Status::Current
            }
            TokenKind::KwDeprecated => {
                self.advance();
                Status::Deprecated
            }
            TokenKind::KwObsolete => {
                self.advance();
                Status::Obsolete
            }
            TokenKind::KwMandatory => {
                self.advance();
                Status::Mandatory
            }
            TokenKind::KwOptional => {
                self.advance();
                Status::Optional
            }
            _ => return Err(self.make_error("expected status value".to_string())),
        };

        let span = cover(start, self.last_span);
        Ok(StatusClause { value, span })
    }

    fn parse_index_or_augments(
        &mut self,
    ) -> Result<(Option<IndexClause>, Option<AugmentsClause>), Diagnostic> {
        if self.check(TokenKind::KwIndex) {
            let start = self.current_span();
            self.advance();
            self.expect(TokenKind::LBrace)?;

            let mut items = Vec::new();
            loop {
                if self.check(TokenKind::RBrace) || self.is_eof() {
                    break;
                }

                let item_start = self.current_span();
                let implied = if self.check(TokenKind::KwImplied) {
                    self.advance();
                    true
                } else {
                    false
                };

                let obj_token = self.expect_index_object()?;

                // Special case: merge OCTET STRING into single identifier
                let object =
                    if obj_token.kind == TokenKind::KwOctet && self.check(TokenKind::KwString) {
                        let string_token = self.advance();
                        Ident {
                            name: "OCTET STRING".to_string(),
                            span: cover(obj_token.span, string_token.span),
                        }
                    } else {
                        self.make_ident(obj_token)
                    };

                let item_span = cover(item_start, self.last_span);
                items.push(IndexItem {
                    implied,
                    object,
                    span: item_span,
                });

                if self.check(TokenKind::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }

            self.expect(TokenKind::RBrace)?;
            let span = cover(start, self.last_span);
            return Ok((Some(IndexClause { items, span }), None));
        }

        if self.check(TokenKind::KwAugments) {
            let start = self.current_span();
            self.advance();
            self.expect(TokenKind::LBrace)?;
            let target_token = self.expect_identifier()?;
            let target = self.make_ident(target_token);
            self.expect(TokenKind::RBrace)?;
            let span = cover(start, self.last_span);
            return Ok((None, Some(AugmentsClause { target, span })));
        }

        Ok((None, None))
    }

    fn parse_defval_clause(&mut self) -> Result<DefValClause, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::KwDefval)?;
        self.expect(TokenKind::LBrace)?;

        let value = self.parse_defval()?;

        self.expect(TokenKind::RBrace)?;
        let span = cover(start, self.last_span);
        Ok(DefValClause { value, span })
    }

    fn parse_defval(&mut self) -> Result<DefVal, Diagnostic> {
        match self.peek().kind {
            TokenKind::Number => {
                let token = self.advance();
                let text = self.text(token.span);
                // Try i64 first, then u64
                if let Ok(v) = text.parse::<i64>() {
                    Ok(DefVal::Integer(v))
                } else if let Ok(v) = text.parse::<u64>() {
                    Ok(DefVal::Unsigned(v))
                } else {
                    self.emit_diagnostic(DiagCode::InvalidI64, token.span, "invalid DEFVAL number");
                    Ok(DefVal::Integer(0))
                }
            }
            TokenKind::NegativeNumber => {
                let token = self.advance();
                let v = self.parse_i64(token.span, "DEFVAL number")?;
                Ok(DefVal::Integer(v))
            }
            TokenKind::QuotedString => {
                let qs = self.parse_quoted_string()?;
                Ok(DefVal::String(qs))
            }
            TokenKind::HexString => {
                let token = self.advance();
                let full_text = self.text(token.span);
                let content = strip_string_literal(&full_text);
                Ok(DefVal::HexString {
                    content: content.to_string(),
                    span: token.span,
                })
            }
            TokenKind::BinString => {
                let token = self.advance();
                let full_text = self.text(token.span);
                let content = strip_string_literal(&full_text);
                Ok(DefVal::BinaryString {
                    content: content.to_string(),
                    span: token.span,
                })
            }
            TokenKind::LowercaseIdent | TokenKind::UppercaseIdent => {
                let token = self.advance();
                Ok(DefVal::Identifier(self.make_ident(token)))
            }
            TokenKind::LBrace => {
                self.advance(); // consume opening brace
                self.parse_defval_braced_content()
            }
            kind if kind.is_keyword() => {
                // Enum labels can be keywords
                let token = self.advance();
                Ok(DefVal::Identifier(self.make_ident(token)))
            }
            _ => {
                // Unknown - skip to matching brace
                let start = self.current_span();
                // We're inside DEFVAL { ... }, just skip unknown content
                Ok(DefVal::Unparsed {
                    span: cover(start, self.current_span()),
                })
            }
        }
    }

    fn parse_defval_braced_content(&mut self) -> Result<DefVal, Diagnostic> {
        let start = self.current_span();

        // Empty braces: BITS {}
        if self.check(TokenKind::RBrace) {
            let span = cover(start, self.current_span());
            self.advance(); // consume inner closing brace
            return Ok(DefVal::Bits {
                labels: Vec::new(),
                span,
            });
        }

        // First token determines interpretation
        let kind = self.peek().kind;

        if kind == TokenKind::Number {
            // OID numeric: { 1 3 6 1 }
            let result = self.parse_defval_oid_components(start)?;
            self.expect(TokenKind::RBrace)?; // consume inner closing brace
            return Ok(result);
        }

        if kind.is_identifier() || kind.is_keyword() {
            let first_token = self.advance();
            let first_ident = self.make_ident(first_token);

            // If next is comma or RBrace, this is BITS labels
            if self.check(TokenKind::Comma) || self.check(TokenKind::RBrace) {
                let result = self.parse_defval_bits_labels(start, first_ident)?;
                self.expect(TokenKind::RBrace)?; // consume inner closing brace
                return Ok(result);
            }

            // Otherwise this is OID starting with a name
            let result = self.parse_defval_oid_with_first_ident(start, first_ident)?;
            self.expect(TokenKind::RBrace)?; // consume inner closing brace
            return Ok(result);
        }

        // Unknown content - skip
        self.skip_braced_content(true); // consume inner closing brace
        Ok(DefVal::Unparsed {
            span: cover(start, self.current_span()),
        })
    }

    fn parse_defval_bits_labels(
        &mut self,
        start: SourceRange,
        first: Ident,
    ) -> Result<DefVal, Diagnostic> {
        let mut labels = vec![first];

        while self.check(TokenKind::Comma) {
            self.advance(); // consume comma
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }
            let token = self.expect_enum_label()?;
            labels.push(self.make_ident(token));
        }

        Ok(DefVal::Bits {
            span: self.range_to_current_start(start),
            labels,
        })
    }

    fn parse_defval_oid_with_first_ident(
        &mut self,
        start: SourceRange,
        first: Ident,
    ) -> Result<DefVal, Diagnostic> {
        // First component might be name(number)
        let first_component = if self.check(TokenKind::LParen) {
            self.advance();
            let num_token = self.expect(TokenKind::Number)?;
            let num = self.parse_u32(num_token.span, "OID component")?;
            self.expect(TokenKind::RParen)?;
            OidComponent::NamedNumber {
                span: cover(first.span, self.last_span),
                name: first,
                num,
            }
        } else {
            OidComponent::Name(first)
        };

        let mut components = vec![first_component];
        self.collect_defval_oid_components(&mut components)?;

        Ok(DefVal::ObjectIdentifier {
            span: self.range_to_current_start(start),
            components,
        })
    }

    fn parse_defval_oid_components(&mut self, start: SourceRange) -> Result<DefVal, Diagnostic> {
        let mut components = Vec::new();
        self.collect_defval_oid_components(&mut components)?;

        Ok(DefVal::ObjectIdentifier {
            span: self.range_to_current_start(start),
            components,
        })
    }

    fn collect_defval_oid_components(
        &mut self,
        components: &mut Vec<OidComponent>,
    ) -> Result<(), Diagnostic> {
        while !self.check(TokenKind::RBrace) && !self.is_eof() {
            let kind = self.peek().kind;
            if kind == TokenKind::Number
                || kind == TokenKind::LowercaseIdent
                || kind == TokenKind::UppercaseIdent
            {
                let comp = self.parse_oid_component()?;
                components.push(comp);
            } else {
                break;
            }
        }
        Ok(())
    }

    // ---- Type syntax parsing ----

    fn parse_syntax_clause(&mut self) -> Result<SyntaxClause, Diagnostic> {
        let start = self.current_span();
        let syntax = self.parse_type_syntax()?;
        let span = cover(start, syntax.span());
        Ok(SyntaxClause { syntax, span })
    }

    fn parse_type_syntax(&mut self) -> Result<TypeSyntax, Diagnostic> {
        let start = self.current_span();

        let base = match self.peek().kind {
            TokenKind::KwInteger => {
                self.advance();
                if self.check(TokenKind::LBrace) {
                    // INTEGER { enum-values }
                    let named_numbers = self.parse_named_numbers()?;
                    let span = cover(start, self.last_span);
                    TypeSyntax::IntegerEnum {
                        base: None,
                        named_numbers,
                        span,
                    }
                } else {
                    TypeSyntax::TypeRef(Ident {
                        name: "INTEGER".to_string(),
                        span: cover(start, self.last_span),
                    })
                }
            }

            TokenKind::KwBits => {
                self.advance();
                if self.check(TokenKind::LBrace) {
                    self.expect(TokenKind::LBrace)?;
                    let named_bits = self.parse_named_number_list()?;
                    self.expect(TokenKind::RBrace)?;
                    let span = cover(start, self.last_span);
                    TypeSyntax::Bits { named_bits, span }
                } else {
                    TypeSyntax::TypeRef(Ident {
                        name: "BITS".to_string(),
                        span: cover(start, self.last_span),
                    })
                }
            }

            TokenKind::KwOctet => {
                self.advance();
                self.expect(TokenKind::KwString)?;
                if self.check(TokenKind::LParen) {
                    let constraint = self.parse_constraint()?;
                    let span = cover(start, constraint.span());
                    TypeSyntax::Constrained {
                        base: Box::new(TypeSyntax::OctetString {
                            span: cover(start, self.last_span),
                        }),
                        constraint,
                        span,
                    }
                } else {
                    TypeSyntax::OctetString {
                        span: cover(start, self.last_span),
                    }
                }
            }

            TokenKind::KwObject => {
                self.advance();
                self.expect(TokenKind::KwIdentifier)?;
                TypeSyntax::ObjectIdentifier {
                    span: cover(start, self.last_span),
                }
            }

            TokenKind::KwSequence => {
                self.advance();
                if self.check(TokenKind::KwOf) {
                    // SEQUENCE OF EntryType
                    self.advance();
                    let entry_token = self.expect_identifier()?;
                    let entry_type = self.make_ident(entry_token);
                    TypeSyntax::SequenceOf {
                        entry_type,
                        span: cover(start, self.last_span),
                    }
                } else {
                    // SEQUENCE { fields }
                    self.expect(TokenKind::LBrace)?;
                    let fields = self.parse_sequence_fields()?;
                    self.expect(TokenKind::RBrace)?;
                    TypeSyntax::Sequence {
                        fields,
                        span: cover(start, self.last_span),
                    }
                }
            }

            TokenKind::KwChoice => {
                self.advance();
                self.expect(TokenKind::LBrace)?;
                let alternatives = self.parse_sequence_fields()?;
                self.expect(TokenKind::RBrace)?;
                TypeSyntax::Choice {
                    alternatives,
                    span: cover(start, self.last_span),
                }
            }

            // Application type keywords
            TokenKind::KwCounter32
            | TokenKind::KwCounter64
            | TokenKind::KwGauge32
            | TokenKind::KwUnsigned32
            | TokenKind::KwTimeTicks
            | TokenKind::KwIpAddress
            | TokenKind::KwOpaque
            | TokenKind::KwCounter
            | TokenKind::KwGauge
            | TokenKind::KwNetworkAddress => {
                let token = self.advance();
                let name = self.text(token.span).to_string();
                TypeSyntax::TypeRef(Ident {
                    name,
                    span: token.span,
                })
            }

            // NULL occurs as an unsupported alternative in the legacy
            // SimpleSyntax CHOICE from RFC 1065 and RFC 1155. Preserve it as
            // an opaque type reference so those foundation modules can pass
            // through the ordinary parser without admitting other reserved
            // ASN.1 keywords as type names.
            TokenKind::ForbiddenKeyword if self.text(self.peek().span) == "NULL" => {
                let token = self.advance();
                TypeSyntax::TypeRef(self.make_ident(token))
            }

            // Named type reference (identifier)
            TokenKind::UppercaseIdent | TokenKind::LowercaseIdent => {
                let token = self.advance();
                let ident = self.make_ident(token);

                if token.kind == TokenKind::LowercaseIdent {
                    self.emit_diagnostic_with(DiagCode::BadIdentifierCase, token.span, || {
                        format!(
                            "type reference {:?} should start with an uppercase letter",
                            ident.name
                        )
                    });
                }

                if self.check(TokenKind::LParen) {
                    // Type with constraint
                    let constraint = self.parse_constraint()?;
                    let span = cover(start, constraint.span());
                    TypeSyntax::Constrained {
                        base: Box::new(TypeSyntax::TypeRef(ident)),
                        constraint,
                        span,
                    }
                } else if self.check(TokenKind::LBrace) {
                    // Restricted integer enum: TypeName { val1(1), val2(2) }
                    let named_numbers = self.parse_named_numbers()?;
                    let span = cover(start, self.last_span);
                    TypeSyntax::IntegerEnum {
                        base: Some(ident),
                        named_numbers,
                        span,
                    }
                } else {
                    TypeSyntax::TypeRef(ident)
                }
            }

            // Tagged type: [APPLICATION n] IMPLICIT Type
            TokenKind::LBracket => {
                self.advance();
                // Skip tag class keyword if present
                if self.check(TokenKind::KwApplication) || self.check(TokenKind::KwUniversal) {
                    self.advance();
                }
                // Skip tag number
                if self.check(TokenKind::Number) {
                    self.advance();
                }
                self.expect(TokenKind::RBracket)?;
                // Skip IMPLICIT if present
                if self.check(TokenKind::KwImplicit) {
                    self.advance();
                }
                let underlying = self.parse_type_syntax()?;
                let span = cover(start, underlying.span());
                TypeSyntax::Tagged {
                    underlying: Box::new(underlying),
                    span,
                }
            }

            _ => {
                return Err(self.make_error("expected type syntax".to_string()));
            }
        };

        // Post-processing: check for trailing constraint on non-constrained base
        if self.check(TokenKind::LParen) && !matches!(base, TypeSyntax::Constrained { .. }) {
            let constraint = self.parse_constraint()?;
            let span = cover(start, constraint.span());
            return Ok(TypeSyntax::Constrained {
                base: Box::new(base),
                constraint,
                span,
            });
        }

        Ok(base)
    }

    // ---- Constraint parsing ----

    fn parse_constraint(&mut self) -> Result<Constraint, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::LParen)?;

        if self.check(TokenKind::KwSize) {
            // SIZE constraint
            self.advance();
            self.expect(TokenKind::LParen)?;
            let ranges = self.parse_range_list()?;
            self.expect(TokenKind::RParen)?;
            self.expect(TokenKind::RParen)?;
            let span = cover(start, self.last_span);
            Ok(Constraint::Size { ranges, span })
        } else {
            // Value range constraint
            let ranges = self.parse_range_list()?;
            self.expect(TokenKind::RParen)?;
            let span = cover(start, self.last_span);
            Ok(Constraint::Range { ranges, span })
        }
    }

    fn parse_range_list(&mut self) -> Result<Vec<Range>, Diagnostic> {
        let mut ranges = Vec::new();

        loop {
            let range_start = self.current_span();
            let min = self.parse_range_value()?;

            let max = if self.check(TokenKind::DotDot) {
                self.advance();
                Some(self.parse_range_value()?)
            } else {
                None
            };

            let range_span = cover(range_start, self.last_span);
            ranges.push(Range {
                min,
                max,
                span: range_span,
            });

            if self.check(TokenKind::Pipe) {
                self.advance();
            } else {
                break;
            }
        }

        Ok(ranges)
    }

    fn parse_range_value(&mut self) -> Result<RangeValue, Diagnostic> {
        match self.peek().kind {
            TokenKind::Number => {
                let token = self.advance();
                let text = self.text(token.span);
                if let Ok(v) = text.parse::<u64>() {
                    Ok(RangeValue::Unsigned(v))
                } else {
                    self.emit_diagnostic(
                        DiagCode::UnknownRangeValue,
                        token.span,
                        format!("range value {text:?} is outside the supported integer range"),
                    );
                    Ok(RangeValue::Raw(text.into_owned()))
                }
            }
            TokenKind::NegativeNumber => {
                let token = self.advance();
                let text = self.text(token.span);
                if let Ok(v) = text.parse::<i64>() {
                    Ok(RangeValue::Signed(v))
                } else {
                    self.emit_diagnostic(
                        DiagCode::UnknownRangeValue,
                        token.span,
                        format!("range value {text:?} is outside the supported integer range"),
                    );
                    Ok(RangeValue::Raw(text.into_owned()))
                }
            }
            TokenKind::HexString => {
                let token = self.advance();
                let full_text = self.text(token.span);
                let hex_part = strip_string_literal(&full_text);
                let normalized: String = hex_part
                    .chars()
                    .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r'))
                    .collect();
                match u64::from_str_radix(&normalized, 16) {
                    Ok(v) => Ok(RangeValue::Unsigned(v)),
                    Err(_) => {
                        self.emit_diagnostic(
                            DiagCode::InvalidHexRange,
                            token.span,
                            "invalid hex range value",
                        );
                        Ok(RangeValue::Raw(full_text.into_owned()))
                    }
                }
            }
            TokenKind::UppercaseIdent | TokenKind::ForbiddenKeyword => {
                let token = self.advance();
                Ok(RangeValue::Named(self.make_ident(token)))
            }
            _ => Err(self.make_error("expected range value".to_string())),
        }
    }

    // ---- Named numbers and sequence fields ----

    fn parse_named_numbers(&mut self) -> Result<Vec<NamedNumber>, Diagnostic> {
        self.expect(TokenKind::LBrace)?;
        let list = self.parse_named_number_list()?;
        self.expect(TokenKind::RBrace)?;
        Ok(list)
    }

    fn parse_named_number_list(&mut self) -> Result<Vec<NamedNumber>, Diagnostic> {
        let mut items = Vec::new();

        loop {
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }

            let nn_start = self.current_span();
            let label_token = self.expect_enum_label()?;
            let label = self.make_ident(label_token);

            self.expect(TokenKind::LParen)?;

            let value = if self.check(TokenKind::NegativeNumber) {
                let num_token = self.advance();
                self.parse_i64(num_token.span, "named number")?
            } else {
                let num_token = self.expect(TokenKind::Number)?;
                self.parse_i64(num_token.span, "named number")?
            };

            self.expect(TokenKind::RParen)?;

            let nn_span = cover(nn_start, self.last_span);
            items.push(NamedNumber {
                name: label,
                value,
                span: nn_span,
            });

            if self.check(TokenKind::Comma) {
                self.advance();
            } else if !self.check(TokenKind::RBrace) && !self.is_eof() {
                // Recovery: missing comma before another named number.
                self.emit_diagnostic(
                    DiagCode::MissingComma,
                    self.current_span(),
                    "missing comma in named number list",
                );
            }
        }

        Ok(items)
    }

    fn parse_sequence_fields(&mut self) -> Result<Vec<SequenceField>, Diagnostic> {
        let mut fields = Vec::new();

        while !self.check(TokenKind::RBrace) && !self.is_eof() {
            let field_start = self.current_span();
            let name_token = self.expect_identifier()?;
            let name = self.make_ident(name_token);

            let syntax = self.parse_type_syntax()?;
            let field_span = cover(field_start, syntax.span());

            fields.push(SequenceField {
                name,
                syntax,
                span: field_span,
            });

            // Consume comma if present, but tolerate missing commas
            if self.check(TokenKind::Comma) {
                self.advance();
            }
        }

        Ok(fields)
    }

    // ---- OID assignment parsing ----

    fn parse_oid_assignment(&mut self) -> Result<OidAssignment, Diagnostic> {
        let start = self.current_span();
        self.expect(TokenKind::LBrace)?;

        let mut components = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.is_eof() {
            let comp = self.parse_oid_component()?;
            components.push(comp);
        }

        self.expect(TokenKind::RBrace)?;

        let span = cover(start, self.last_span);
        Ok(OidAssignment { components, span })
    }

    fn parse_oid_component(&mut self) -> Result<OidComponent, Diagnostic> {
        match self.peek().kind {
            TokenKind::Number => {
                let token = self.advance();
                let value = self.parse_u32(token.span, "OID component")?;
                Ok(OidComponent::Number {
                    value,
                    span: token.span,
                })
            }
            TokenKind::LowercaseIdent | TokenKind::UppercaseIdent => {
                let token = self.advance();
                let ident = self.make_ident(token);

                // Check for qualified name: Module.name
                if self.check(TokenKind::Dot) && token.kind == TokenKind::UppercaseIdent {
                    let next = self.peek_nth(1).kind;
                    if next == TokenKind::LowercaseIdent || next == TokenKind::UppercaseIdent {
                        self.advance(); // consume dot
                        let name_token = self.advance();
                        let name_ident = self.make_ident(name_token);

                        // Check for qualified named number: Module.name(number)
                        if self.check(TokenKind::LParen) {
                            self.advance();
                            let num_token = self.expect(TokenKind::Number)?;
                            let num = self.parse_u32(num_token.span, "OID component number")?;
                            self.expect(TokenKind::RParen)?;
                            let span = cover(ident.span, self.last_span);
                            return Ok(OidComponent::QualifiedNamedNumber {
                                module_name: ident,
                                name: name_ident,
                                num,
                                span,
                            });
                        }

                        let span = cover(ident.span, name_ident.span);
                        return Ok(OidComponent::QualifiedName {
                            module_name: ident,
                            name: name_ident,
                            span,
                        });
                    }
                }

                // Check for named number: name(number)
                if self.check(TokenKind::LParen) {
                    self.advance();
                    let num_token = self.expect(TokenKind::Number)?;
                    let num = self.parse_u32(num_token.span, "OID component number")?;
                    self.expect(TokenKind::RParen)?;
                    let span = cover(ident.span, self.last_span);
                    return Ok(OidComponent::NamedNumber {
                        name: ident,
                        num,
                        span,
                    });
                }

                Ok(OidComponent::Name(ident))
            }
            _ => Err(self.make_error("expected OID component".to_string())),
        }
    }
}

/// Strips surrounding quote characters from hex/binary string literals.
///
/// Input: `'content'H` or `'content'B`, output: `content`.
fn strip_string_literal(s: &str) -> &str {
    let s = s.strip_prefix('\'').unwrap_or(s);
    if let Some(pos) = s.rfind('\'') {
        &s[..pos]
    } else {
        s
    }
}

/// Parse source bytes into [`ast::Module`](crate::ast::Module) nodes.
///
/// This is the main entry point for parsing. A single source file may
/// contain multiple concatenated MIB modules (common in RFC files).
/// Each returned [`Module`] carries its own diagnostics.
pub fn parse(document: &SourceDocument, diag_config: &DiagnosticConfig) -> Vec<Module> {
    let span = info_span!(
        target: "mib_rs::parser",
        "parse",
        component = "parser",
        source = document.label(),
        byte_count = document.bytes().len(),
        reporting = ?diag_config.reporting,
    );
    let _guard = span.enter();

    let mut parser = Parser::new(document, diag_config);
    let modules = parser.parse_modules();
    debug!(
        target: "mib_rs::parser",
        component = "parser",
        module_count = modules.len(),
        "parse complete",
    );
    modules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{SourceOrigin, SourceSet};
    use std::sync::Arc;

    fn parse_with_config(input: &str, config: &DiagnosticConfig) -> Vec<Module> {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                SourceOrigin::memory("parser-test"),
                "parser-test",
                Arc::from(input.as_bytes()),
            )
            .unwrap();
        parse(sources.get(id).unwrap(), config)
    }

    fn parse_str(input: &str) -> Vec<Module> {
        parse_with_config(input, &DiagnosticConfig::default())
    }

    fn parse_strict(input: &str) -> Vec<Module> {
        parse_with_config(input, &DiagnosticConfig::verbose())
    }

    #[test]
    fn empty_input() {
        let modules = parse_str("");
        assert_eq!(modules.len(), 1);
        assert!(modules[0].name.is_none());
        assert_eq!(modules[0].span.byte_range(), 0..0);
    }

    #[test]
    fn minimal_module() {
        let input = "TEST-MIB DEFINITIONS ::= BEGIN\nEND\n";
        let modules = parse_str(input);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name.as_ref().unwrap().name, "TEST-MIB");
        assert!(modules[0].imports.is_empty());
        assert!(modules[0].body.is_empty());
    }

    #[test]
    fn lexer_diagnostic_in_initial_lookahead_is_preserved() {
        let input = "TEST-MIB { 01 } DEFINITIONS ::= BEGIN\nEND\n";
        let modules = parse_strict(input);

        assert_eq!(modules.len(), 1);
        let diagnostics: Vec<_> = modules[0]
            .diagnostics
            .iter()
            .filter(|diag| diag.code == DiagCode::NumberLeadingZero)
            .collect();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].range.unwrap().byte_range(), 11..13);
        assert_eq!(
            diagnostics[0].range.unwrap().source(),
            modules[0].span.source()
        );
        assert_eq!(diagnostics[0].module.as_deref(), Some("TEST-MIB"));
    }

    #[test]
    fn malformed_terminal_header_preserves_lookahead_lexer_diagnostic() {
        let input = "BAD FOO 01\n";
        let modules = parse_strict(input);

        assert_eq!(modules.len(), 1);
        assert!(modules[0].name.is_none());
        let diagnostics: Vec<_> = modules[0]
            .diagnostics
            .iter()
            .filter(|diag| diag.code == DiagCode::NumberLeadingZero)
            .collect();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].range.unwrap().byte_range(), 8..10);
        assert_eq!(
            diagnostics[0].range.unwrap().source(),
            modules[0].span.source()
        );
    }

    #[test]
    fn leading_skipped_lexer_diagnostic_is_attached_to_first_module() {
        let input = "@\nTEST-MIB DEFINITIONS ::= BEGIN\nEND\n";
        let modules = parse_strict(input);

        assert_eq!(modules.len(), 1);
        let diagnostics: Vec<_> = modules[0]
            .diagnostics
            .iter()
            .filter(|diag| diag.code == DiagCode::UnexpectedCharacter)
            .collect();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].range.unwrap().byte_range(), 0..1);
        assert_eq!(
            diagnostics[0].range.unwrap().source(),
            modules[0].span.source()
        );
    }

    #[test]
    fn trailing_skipped_lexer_diagnostic_is_attached_to_last_module() {
        let input = "TEST-MIB DEFINITIONS ::= BEGIN\n@";
        let modules = parse_strict(input);

        assert_eq!(modules.len(), 1);
        let diagnostics: Vec<_> = modules[0]
            .diagnostics
            .iter()
            .filter(|diag| diag.code == DiagCode::UnexpectedCharacter)
            .collect();
        assert_eq!(diagnostics.len(), 1);
        let at = input.find('@').unwrap();
        assert_eq!(diagnostics[0].range.unwrap().byte_range(), at..at + 1);
        assert_eq!(
            diagnostics[0].range.unwrap().source(),
            modules[0].span.source()
        );
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .any(|diag| diag.code == DiagCode::ParseError)
        );
    }

    #[test]
    fn lexer_diagnostic_from_next_module_is_not_attached_to_previous_module() {
        let input = "FIRST-MIB DEFINITIONS ::= BEGIN\nEND\n\
SECOND-MIB { 02 } DEFINITIONS ::= BEGIN\nEND\n";
        let modules = parse_strict(input);

        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name.as_ref().unwrap().name, "FIRST-MIB");
        assert_eq!(modules[1].name.as_ref().unwrap().name, "SECOND-MIB");
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|diag| diag.code != DiagCode::NumberLeadingZero)
        );
        let diagnostics: Vec<_> = modules[1]
            .diagnostics
            .iter()
            .filter(|diag| diag.code == DiagCode::NumberLeadingZero)
            .collect();
        assert_eq!(diagnostics.len(), 1);
        let number_start = input.find("02").unwrap();
        assert_eq!(
            diagnostics[0].range.unwrap().byte_range(),
            number_start..number_start + 2
        );
        assert_eq!(
            diagnostics[0].range.unwrap().source(),
            modules[1].span.source()
        );
    }

    #[test]
    fn module_with_imports() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].imports.len(), 2);
        assert_eq!(modules[0].imports[0].symbols.len(), 3);
        assert_eq!(modules[0].imports[0].from_module.name, "SNMPv2-SMI");
        assert_eq!(modules[0].imports[1].symbols.len(), 1);
        assert_eq!(modules[0].imports[1].symbols[0].name, "DisplayString");
        assert_eq!(modules[0].imports[1].from_module.name, "SNMPv2-TC");
    }

    #[test]
    fn many_exports_clauses_are_skipped_iteratively() {
        const EXPORTS_COUNT: usize = 100_000;

        let mut input = String::from("TEST-MIB DEFINITIONS ::= BEGIN\n");
        for _ in 0..EXPORTS_COUNT {
            input.push_str("EXPORTS;\n");
        }
        input.push_str("testObj OBJECT IDENTIFIER ::= { iso 3 }\nEND\n");

        let modules = parse_str(&input);

        assert_eq!(modules.len(), 1);
        assert!(modules[0].diagnostics.is_empty());
        assert_eq!(modules[0].body.len(), 1);
        assert!(matches!(
            &modules[0].body[0],
            Definition::ValueAssignment(d) if d.name.name == "testObj"
        ));
    }

    #[test]
    fn exports_comment_semicolons_do_not_expose_the_remaining_body() {
        for exports_body in ["foo -- ignored;\nbar;", "foo -- ignored; -- bar;"] {
            let input = format!(
                "TEST-MIB DEFINITIONS ::= BEGIN\nEXPORTS {exports_body}\ntestObj OBJECT IDENTIFIER ::= {{ iso 3 }}\nEND\n"
            );

            let modules = parse_str(&input);

            assert_eq!(modules.len(), 1);
            assert!(modules[0].diagnostics.is_empty());
            assert_eq!(modules[0].body.len(), 1);
            assert!(matches!(
                &modules[0].body[0],
                Definition::ValueAssignment(d) if d.name.name == "testObj"
            ));
        }
    }

    #[test]
    fn value_assignment() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT IDENTIFIER ::= { iso 3 }
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        assert!(matches!(
            &modules[0].body[0],
            Definition::ValueAssignment(d) if d.name.name == "testObj"
        ));
    }

    #[test]
    fn object_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
ifIndex OBJECT-TYPE
    SYNTAX      INTEGER
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "The index."
    ::= { ifEntry 1 }
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                assert_eq!(d.name.name, "ifIndex");
                assert!(d.syntax.is_some());
                assert!(d.access.is_some());
                assert!(d.status.is_some());
                assert_eq!(d.status.as_ref().unwrap().value, Status::Current);
                assert!(d.description.is_some());
                assert_eq!(d.oid.components.len(), 2);
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn module_identity() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testMIB MODULE-IDENTITY
    LAST-UPDATED "200606140000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "test@test"
    DESCRIPTION  "A test MIB."
    REVISION     "200606140000Z"
    DESCRIPTION  "Initial version."
    ::= { enterprises 1 }
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        match &modules[0].body[0] {
            Definition::ModuleIdentity(d) => {
                assert_eq!(d.name.name, "testMIB");
                assert_eq!(d.last_updated.value, "200606140000Z");
                assert_eq!(d.revisions.len(), 1);
            }
            other => panic!("expected ModuleIdentity, got {:?}", other),
        }
    }

    #[test]
    fn type_assignment() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= INTEGER (0..255)
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                assert_eq!(d.name.name, "TestType");
                assert!(matches!(d.syntax, TypeSyntax::Constrained { .. }));
            }
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn textual_convention() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
MyString ::= TEXTUAL-CONVENTION
    STATUS current
    DESCRIPTION "A string."
    SYNTAX OCTET STRING (SIZE (0..255))
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        assert!(matches!(
            &modules[0].body[0],
            Definition::TextualConvention(d) if d.name.name == "MyString"
        ));
    }

    #[test]
    fn notification_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testNotif NOTIFICATION-TYPE
    OBJECTS { testObj }
    STATUS  current
    DESCRIPTION "A notification."
    ::= { testMIB 1 }
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        match &modules[0].body[0] {
            Definition::NotificationType(d) => {
                assert_eq!(d.name.name, "testNotif");
                assert_eq!(d.objects.len(), 1);
            }
            other => panic!("expected NotificationType, got {:?}", other),
        }
    }

    #[test]
    fn trap_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testTrap TRAP-TYPE
    ENTERPRISE testEnterprise
    VARIABLES { testObj }
    DESCRIPTION "A trap."
    ::= 1
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        match &modules[0].body[0] {
            Definition::TrapType(d) => {
                assert_eq!(d.name.name, "testTrap");
                assert_eq!(d.enterprise.name, "testEnterprise");
                assert_eq!(d.trap_number, 1);
                assert_eq!(d.variables.len(), 1);
            }
            other => panic!("expected TrapType, got {:?}", other),
        }
    }

    #[test]
    fn object_group() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testGroup OBJECT-GROUP
    OBJECTS { testObj1, testObj2 }
    STATUS  current
    DESCRIPTION "A group."
    ::= { testMIB 2 }
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 1);
        match &modules[0].body[0] {
            Definition::ObjectGroup(d) => {
                assert_eq!(d.name.name, "testGroup");
                assert_eq!(d.objects.len(), 2);
            }
            other => panic!("expected ObjectGroup, got {:?}", other),
        }
    }

    #[test]
    fn error_recovery() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
@@@ garbage @@@
testObj OBJECT IDENTIFIER ::= { iso 3 }
END
"#;
        let modules = parse_str(input);
        // Should recover and parse the value assignment
        assert!(!modules[0].body.is_empty() || !modules[0].diagnostics.is_empty());
    }

    #[test]
    fn multiple_definitions() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= INTEGER
testObj OBJECT IDENTIFIER ::= { iso 3 }
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 2);
    }

    #[test]
    fn oid_components() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ValueAssignment(d) => {
                assert_eq!(d.oid.components.len(), 4);
                assert!(matches!(&d.oid.components[0], OidComponent::Name(id) if id.name == "iso"));
                assert!(
                    matches!(&d.oid.components[1], OidComponent::NamedNumber { name, num, .. } if name.name == "org" && *num == 3)
                );
            }
            other => panic!("expected ValueAssignment, got {:?}", other),
        }
    }

    #[test]
    fn integer_enum_syntax() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestStatus ::= INTEGER { up(1), down(2), testing(3) }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                match &d.syntax {
                    TypeSyntax::IntegerEnum {
                        base,
                        named_numbers,
                        ..
                    } => {
                        assert!(base.is_none()); // bare INTEGER
                        assert_eq!(named_numbers.len(), 3);
                        assert_eq!(named_numbers[0].name.name, "up");
                        assert_eq!(named_numbers[0].value, 1);
                    }
                    other => panic!("expected IntegerEnum, got {:?}", other),
                }
            }
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn sequence_of_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestTable ::= SEQUENCE OF TestEntry
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                assert!(
                    matches!(&d.syntax, TypeSyntax::SequenceOf { entry_type, .. } if entry_type.name == "TestEntry")
                );
            }
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn object_type_with_index() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testEntry OBJECT-TYPE
    SYNTAX TestEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "A row."
    INDEX { testIndex }
    ::= { testTable 1 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                assert!(d.index.is_some());
                assert_eq!(d.index.as_ref().unwrap().items.len(), 1);
                assert_eq!(d.index.as_ref().unwrap().items[0].object.name, "testIndex");
                assert!(!d.index.as_ref().unwrap().items[0].implied);
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn object_type_with_augments() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testEntry OBJECT-TYPE
    SYNTAX TestEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "A row."
    AUGMENTS { otherEntry }
    ::= { testTable 1 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                assert!(d.augments.is_some());
                assert_eq!(d.augments.as_ref().unwrap().target.name, "otherEntry");
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn size_constraint() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestStr ::= OCTET STRING (SIZE (0..255))
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::Constrained {
                    base, constraint, ..
                } => {
                    assert!(matches!(**base, TypeSyntax::OctetString { .. }));
                    match constraint {
                        Constraint::Size { ranges, .. } => {
                            assert_eq!(ranges.len(), 1);
                        }
                        other => panic!("expected Size constraint, got {:?}", other),
                    }
                }
                other => panic!("expected Constrained, got {:?}", other),
            },
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn defval_integer() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX INTEGER
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "test"
    DEFVAL { 42 }
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                assert!(d.defval.is_some());
                assert!(matches!(
                    d.defval.as_ref().unwrap().value,
                    DefVal::Integer(42)
                ));
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn defval_bits() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX BITS { flag1(0), flag2(1) }
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "test"
    DEFVAL { { flag1 } }
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                assert!(d.defval.is_some());
                match &d.defval.as_ref().unwrap().value {
                    DefVal::Bits { labels, span } => {
                        assert_eq!(labels.len(), 1);
                        assert_eq!(labels[0].name, "flag1");
                        let start = input.rfind("flag1 }").unwrap();
                        let end = start + "flag1 ".len();
                        assert_eq!(span.byte_range(), start..end);
                        assert_eq!(&input[span.byte_range()], "flag1 ");
                    }
                    other => panic!("expected Bits DEFVAL, got {:?}", other),
                }
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn identifier_underscore_diagnostic() {
        let input = r#"TEST_MIB DEFINITIONS ::= BEGIN
END
"#;
        let modules = parse_strict(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .any(|d| d.code == DiagCode::IdentifierUnderscore)
        );
    }

    #[test]
    fn macro_definition_skipped() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
OBJECT-TYPE MACRO ::= BEGIN
    TYPE NOTATION ::= stuff stuff
END
testObj OBJECT IDENTIFIER ::= { iso 3 }
END
"#;
        let modules = parse_str(input);
        // Should have two definitions: the macro and the value assignment
        assert_eq!(modules[0].body.len(), 2);
        assert!(matches!(
            &modules[0].body[0],
            Definition::MacroDefinition(_)
        ));
        assert!(matches!(
            &modules[0].body[1],
            Definition::ValueAssignment(_)
        ));
    }

    #[test]
    fn macro_definition_quoted_end_preserves_following_definition() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
FOO MACRO ::= BEGIN
    TYPE NOTATION ::= "END"
    VALUE NOTATION ::= value(VALUE ObjectName)
END
testObj OBJECT IDENTIFIER ::= { iso 3 }
END
"#;
        let modules = parse_strict(input);

        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].body.len(), 2);
        assert!(matches!(
            &modules[0].body[0],
            Definition::MacroDefinition(_)
        ));
        assert!(matches!(
            &modules[0].body[1],
            Definition::ValueAssignment(d) if d.name.name == "testObj"
        ));
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::UnterminatedString),
            "quoted END in a MACRO body must not corrupt following syntax"
        );
    }

    #[test]
    fn tagged_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= [APPLICATION 0] IMPLICIT OCTET STRING
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                assert!(matches!(&d.syntax, TypeSyntax::Tagged { .. }));
            }
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn module_compliance() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "Test compliance."
    MODULE
        MANDATORY-GROUPS { testGroup }
        GROUP testOptGroup
            DESCRIPTION "Optional group."
        OBJECT testObj
            MIN-ACCESS read-only
            DESCRIPTION "Object refinement."
    ::= { testMIB 3 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ModuleCompliance(d) => {
                assert_eq!(d.modules.len(), 1);
                assert_eq!(d.modules[0].mandatory_groups.len(), 1);
                assert_eq!(d.modules[0].compliances.len(), 2);
            }
            other => panic!("expected ModuleCompliance, got {:?}", other),
        }
    }

    #[test]
    fn agent_capabilities() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testCapability AGENT-CAPABILITIES
    PRODUCT-RELEASE "1.0"
    STATUS current
    DESCRIPTION "Test capability."
    SUPPORTS SNMPv2-MIB
        INCLUDES { systemGroup }
        VARIATION sysDescr
            ACCESS read-only
            DESCRIPTION "Read-only."
    ::= { testMIB 4 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::AgentCapabilities(d) => {
                assert_eq!(d.supports.len(), 1);
                assert_eq!(d.supports[0].includes.len(), 1);
                assert_eq!(d.supports[0].variations.len(), 1);
            }
            other => panic!("expected AgentCapabilities, got {:?}", other),
        }
    }

    #[test]
    fn range_constraint_with_pipe() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= INTEGER (1..10 | 20..30)
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::Constrained { constraint, .. } => match constraint {
                    Constraint::Range { ranges, .. } => {
                        assert_eq!(ranges.len(), 2);
                    }
                    other => panic!("expected Range, got {:?}", other),
                },
                other => panic!("expected Constrained, got {:?}", other),
            },
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn strip_string_literal_helper() {
        assert_eq!(strip_string_literal("'0A1B'H"), "0A1B");
        assert_eq!(strip_string_literal("'01010101'B"), "01010101");
        assert_eq!(strip_string_literal("''H"), "");
    }

    #[test]
    fn two_modules_in_one_file() {
        let input = r#"MOD-A DEFINITIONS ::= BEGIN
END
MOD-B DEFINITIONS ::= BEGIN
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name.as_ref().unwrap().name, "MOD-A");
        assert_eq!(modules[1].name.as_ref().unwrap().name, "MOD-B");
    }

    #[test]
    fn choice_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestChoice ::= CHOICE { a INTEGER, b OCTET STRING }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::Choice { alternatives, .. } => {
                    assert_eq!(alternatives.len(), 2);
                }
                other => panic!("expected Choice, got {:?}", other),
            },
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn null_type_does_not_admit_other_forbidden_keywords() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
SimpleSyntax ::= CHOICE { number INTEGER, empty NULL }
RejectedSyntax ::= TRUE
END
"#;
        let modules = parse_strict(input);

        assert!(matches!(
            &modules[0].body[0],
            Definition::TypeAssignment(d)
                if matches!(
                    &d.syntax,
                    TypeSyntax::Choice { alternatives, .. }
                        if matches!(
                            &alternatives[1].syntax,
                            TypeSyntax::TypeRef(ident) if ident.name == "NULL"
                        )
                )
        ));
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .any(|d| d.code == DiagCode::ParseError),
            "other reserved ASN.1 words must not be accepted as named types"
        );
    }

    #[test]
    fn type_keyword_type_assignment() {
        // Type keywords like IpAddress can appear on LHS of ::= (base modules)
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].body.len(), 2);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => assert_eq!(d.name.name, "IpAddress"),
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn named_number_missing_comma() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestStatus ::= INTEGER { up(1) down(2) testing(3) }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        let missing_comma_count = modules[0]
            .diagnostics
            .iter()
            .filter(|d| d.code == DiagCode::MissingComma)
            .count();
        assert_eq!(
            missing_comma_count, 2,
            "expected 2 missing-comma diagnostics"
        );
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::IntegerEnum { named_numbers, .. } => {
                    assert_eq!(named_numbers.len(), 3);
                }
                other => panic!("expected IntegerEnum, got {:?}", other),
            },
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn negative_named_number() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= INTEGER { negative(-1), zero(0), positive(1) }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::IntegerEnum { named_numbers, .. } => {
                    assert_eq!(named_numbers.len(), 3);
                    assert_eq!(named_numbers[0].value, -1);
                    assert_eq!(named_numbers[1].value, 0);
                    assert_eq!(named_numbers[2].value, 1);
                }
                other => panic!("expected IntegerEnum, got {:?}", other),
            },
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn qualified_oid_component() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT IDENTIFIER ::= { SNMPv2-SMI.enterprises 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ValueAssignment(d) => {
                assert_eq!(d.oid.components.len(), 2);
                assert!(matches!(
                    &d.oid.components[0],
                    OidComponent::QualifiedName { module_name, name, .. }
                    if module_name.name == "SNMPv2-SMI" && name.name == "enterprises"
                ));
            }
            other => panic!("expected ValueAssignment, got {:?}", other),
        }
    }

    #[test]
    fn constrained_type_ref() {
        // Named type with constraint: DisplayString (SIZE (0..255))
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX DisplayString (SIZE (0..255))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "test"
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let syntax = d.syntax.as_ref().unwrap();
                match &syntax.syntax {
                    TypeSyntax::Constrained {
                        base, constraint, ..
                    } => {
                        assert!(
                            matches!(base.as_ref(), TypeSyntax::TypeRef(id) if id.name == "DisplayString")
                        );
                        assert!(matches!(constraint, Constraint::Size { .. }));
                    }
                    other => panic!("expected Constrained, got {:?}", other),
                }
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn restricted_integer_enum() {
        // TypeName { val1(1), val2(2) } - restricted integer enum with base type
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX RowStatus { active(1), notInService(2) }
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "test"
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let syntax = d.syntax.as_ref().unwrap();
                match &syntax.syntax {
                    TypeSyntax::IntegerEnum {
                        base,
                        named_numbers,
                        ..
                    } => {
                        assert!(base.is_some());
                        assert_eq!(base.as_ref().unwrap().name, "RowStatus");
                        assert_eq!(named_numbers.len(), 2);
                    }
                    other => panic!("expected IntegerEnum, got {:?}", other),
                }
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn object_type_smiv1_access() {
        // SMIv1 uses ACCESS instead of MAX-ACCESS
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX INTEGER
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "SMIv1 style."
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let access = d.access.as_ref().unwrap();
                assert_eq!(access.keyword, AccessKeyword::Access);
                assert_eq!(access.value, Access::ReadOnly);
                assert_eq!(d.status.as_ref().unwrap().value, Status::Mandatory);
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn defval_hex_string() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX OCTET STRING
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "test"
    DEFVAL { 'FF00'H }
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => match &d.defval.as_ref().unwrap().value {
                DefVal::HexString { content, .. } => assert_eq!(content, "FF00"),
                other => panic!("expected HexString DEFVAL, got {:?}", other),
            },
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn defval_oid() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "test"
    DEFVAL { { 1 3 6 1 } }
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => match &d.defval.as_ref().unwrap().value {
                DefVal::ObjectIdentifier { components, span } => {
                    assert_eq!(components.len(), 4);
                    let start = input.find("1 3 6 1 }").unwrap();
                    let end = start + "1 3 6 1 ".len();
                    assert_eq!(span.byte_range(), start..end);
                    assert_eq!(&input[span.byte_range()], "1 3 6 1 ");
                }
                other => panic!("expected OID DEFVAL, got {:?}", other),
            },
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn defval_oid_first_ident_and_qualified_component_range() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "test"
    DEFVAL { { iso(1) SNMPv2-SMI.enterprises 7 } }
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => match &d.defval.as_ref().unwrap().value {
                DefVal::ObjectIdentifier { components, span } => {
                    assert_eq!(components.len(), 3);
                    assert!(matches!(components[0], OidComponent::NamedNumber { .. }));
                    assert!(matches!(components[1], OidComponent::QualifiedName { .. }));
                    let start = input.find("iso(1) SNMPv2-SMI.enterprises 7 }").unwrap();
                    let end = start + "iso(1) SNMPv2-SMI.enterprises 7 ".len();
                    assert_eq!(span.byte_range(), start..end);
                    assert_eq!(
                        &input[span.byte_range()],
                        "iso(1) SNMPv2-SMI.enterprises 7 "
                    );
                }
                other => panic!("expected OID DEFVAL, got {:?}", other),
            },
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn object_identity() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testOID OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "An OID registration."
    ::= { testMIB 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectIdentity(d) => {
                assert_eq!(d.name.name, "testOID");
            }
            other => panic!("expected ObjectIdentity, got {:?}", other),
        }
    }

    #[test]
    fn notification_group() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testNotifGroup NOTIFICATION-GROUP
    NOTIFICATIONS { testNotif1, testNotif2 }
    STATUS current
    DESCRIPTION "A notification group."
    ::= { testMIB 5 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::NotificationGroup(d) => {
                assert_eq!(d.name.name, "testNotifGroup");
                assert_eq!(d.notifications.len(), 2);
            }
            other => panic!("expected NotificationGroup, got {:?}", other),
        }
    }

    #[test]
    fn hex_range_value() {
        let input = "TEST-MIB DEFINITIONS ::= BEGIN\n\
Whitespace ::= INTEGER ('7f ff'H | '7f\tff'H | '7f\rff'H | '7f\nff'H)\n\
Malformed ::= INTEGER ('0G'H..'10000000000000000'H)\n\
END\n";
        let modules = parse_strict(input);
        let module = &modules[0];
        assert!(
            module
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );

        let ranges = match &module.body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::Constrained {
                    constraint: Constraint::Range { ranges, .. },
                    ..
                } => ranges,
                other => panic!("expected constrained range, got {other:?}"),
            },
            other => panic!("expected TypeAssignment, got {other:?}"),
        };
        assert_eq!(ranges.len(), 4);
        assert!(
            ranges.iter().all(|range| {
                matches!(range.min, RangeValue::Unsigned(value) if value == 0x7fff)
            })
        );

        let malformed = match &module.body[1] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::Constrained {
                    constraint: Constraint::Range { ranges, .. },
                    ..
                } => &ranges[0],
                other => panic!("expected constrained range, got {other:?}"),
            },
            other => panic!("expected TypeAssignment, got {other:?}"),
        };
        assert_eq!(malformed.min, RangeValue::Raw("'0G'H".to_string()));
        assert_eq!(
            malformed.max,
            Some(RangeValue::Raw("'10000000000000000'H".to_string()))
        );
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|d| d.code == DiagCode::InvalidHexRange)
                .count(),
            2
        );

        let mut ignored = DiagnosticConfig::verbose();
        ignored.ignore.push("invalid-hex-range".to_string());
        let ignored_modules = parse_with_config(input, &ignored);
        assert!(
            ignored_modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::InvalidHexRange)
        );
    }

    #[test]
    fn overflowing_decimal_range_values_preserve_raw_source() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
Overflow ::= INTEGER (18446744073709551616)
Underflow ::= INTEGER (-9223372036854775809)
END
"#;
        let modules = parse_strict(input);
        let module = &modules[0];

        let raw_values: Vec<&str> = module
            .body
            .iter()
            .map(|definition| match definition {
                Definition::TypeAssignment(d) => match &d.syntax {
                    TypeSyntax::Constrained {
                        constraint: Constraint::Range { ranges, .. },
                        ..
                    } => match &ranges[0].min {
                        RangeValue::Raw(raw) => raw.as_str(),
                        other => panic!("expected raw range value, got {other:?}"),
                    },
                    other => panic!("expected constrained range, got {other:?}"),
                },
                other => panic!("expected type assignment, got {other:?}"),
            })
            .collect();
        assert_eq!(raw_values, ["18446744073709551616", "-9223372036854775809"]);
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|d| d.code == DiagCode::UnknownRangeValue)
                .count(),
            2
        );
        assert!(
            module
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::InvalidI64)
        );
    }

    #[test]
    fn keyword_as_enum_label() {
        // Keywords like "current", "deprecated" can be used as enum labels
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= INTEGER { current(1), deprecated(2), optional(3) }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => match &d.syntax {
                TypeSyntax::IntegerEnum { named_numbers, .. } => {
                    assert_eq!(named_numbers.len(), 3);
                    assert_eq!(named_numbers[0].name.name, "current");
                    assert_eq!(named_numbers[1].name.name, "deprecated");
                    assert_eq!(named_numbers[2].name.name, "optional");
                }
                other => panic!("expected IntegerEnum, got {:?}", other),
            },
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn object_identifier_syntax() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testObj OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "An OID."
    ::= { test 1 }
END
"#;
        let modules = parse_str(input);
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let syntax = d.syntax.as_ref().unwrap();
                assert!(matches!(
                    &syntax.syntax,
                    TypeSyntax::ObjectIdentifier { .. }
                ));
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }

    #[test]
    fn module_oid_before_definitions() {
        // Some old-style modules have an OID block before DEFINITIONS
        let input = r#"TEST-MIB { iso 3 } DEFINITIONS ::= BEGIN
END
"#;
        let modules = parse_str(input);
        assert_eq!(modules[0].name.as_ref().unwrap().name, "TEST-MIB");
        assert!(
            modules[0]
                .diagnostics
                .iter()
                .all(|d| d.code != DiagCode::ParseError)
        );
    }

    #[test]
    fn implied_index() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
testEntry OBJECT-TYPE
    SYNTAX TestEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "row"
    INDEX { testIdx, IMPLIED testName }
    ::= { testTable 1 }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let index = d.index.as_ref().unwrap();
                assert_eq!(index.items.len(), 2);
                assert!(!index.items[0].implied);
                assert!(index.items[1].implied);
                assert_eq!(index.items[1].object.name, "testName");
            }
            other => panic!("expected ObjectType, got {:?}", other),
        }
    }
}
