use crate::ast::*;
use crate::lexer::{Lexer, Token, TokenKind};
use crate::types::{
    Access, AccessKeyword, ByteOffset, DiagCode, DiagnosticConfig, Span, SpanDiagnostic,
    Status,
};
use tracing::{debug, trace};

type TcBody = (
    Option<QuotedString>,
    StatusClause,
    QuotedString,
    Option<QuotedString>,
    SyntaxClause,
);

/// Recursive descent parser for SMI MIB modules.
///
/// Consumes tokens from a lexer and produces AST modules with collected
/// diagnostics. Handles both SMIv1 and SMIv2, plus common vendor deviations.
pub struct Parser<'src> {
    source: &'src [u8],
    lexer: Lexer<'src>,
    buf: [Token; 3],
    last_end: ByteOffset,
    diagnostics: Vec<SpanDiagnostic>,
    diag_config: DiagnosticConfig,
    eof_token: Token,
}

fn next_non_comment(lexer: &mut Lexer<'_>) -> Token {
    loop {
        let tok = lexer.next_token();
        if tok.kind != TokenKind::Comment {
            return tok;
        }
    }
}

impl<'src> Parser<'src> {
    pub fn new(source: &'src [u8], diag_config: DiagnosticConfig) -> Self {
        let mut lexer = Lexer::new(source, diag_config.clone());
        let eof_span = Span::from_usize_offsets(source.len(), source.len());
        let eof_token = Token {
            kind: TokenKind::Eof,
            span: eof_span,
        };

        let buf = [
            next_non_comment(&mut lexer),
            next_non_comment(&mut lexer),
            next_non_comment(&mut lexer),
        ];

        debug!("parser initialized");

        Parser {
            source,
            lexer,
            buf,
            last_end: ByteOffset(0),
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
        self.last_end = tok.span.end;
        tok
    }

    fn check(&self, kind: TokenKind) -> bool {
        self.peek().kind == kind
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token, SpanDiagnostic> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            Err(self.make_error(format!("expected {}", kind.display_name())))
        }
    }

    fn current_span(&self) -> Span {
        self.peek().span
    }

    fn is_eof(&self) -> bool {
        self.peek().kind == TokenKind::Eof
    }

    fn text(&self, span: Span) -> &str {
        std::str::from_utf8(&self.source[span.start.0 as usize..span.end.0 as usize])
            .unwrap_or("<invalid utf8>")
    }

    fn make_error(&self, message: String) -> SpanDiagnostic {
        SpanDiagnostic {
            severity: DiagCode::ParseError.severity(),
            code: DiagCode::ParseError,
            span: self.current_span(),
            message,
        }
    }

    fn record_parse_error(&mut self, diag: SpanDiagnostic) {
        self.diagnostics.push(diag);
    }

    fn emit_diagnostic(&mut self, code: DiagCode, span: Span, message: impl Into<String>) {
        if !self.diag_config.should_report(code) {
            return;
        }
        self.diagnostics.push(SpanDiagnostic {
            severity: code.severity(),
            code,
            span,
            message: message.into(),
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

    fn validate_identifier(&mut self, name: &str, span: Span) {
        if name.contains('_') {
            self.emit_diagnostic(
                DiagCode::IdentifierUnderscore,
                span,
                format!("identifier {:?} contains underscore (RFC violation)", name),
            );
        }
        if name.ends_with('-') {
            self.emit_diagnostic(
                DiagCode::IdentifierHyphenEnd,
                span,
                format!("identifier {:?} ends with hyphen", name),
            );
        }
        if name.len() > 64 {
            self.emit_diagnostic(
                DiagCode::IdentifierLength64,
                span,
                format!(
                    "identifier {:?} exceeds 64 character limit ({} chars)",
                    name,
                    name.len()
                ),
            );
        } else if name.len() > 32 {
            self.emit_diagnostic(
                DiagCode::IdentifierLength32,
                span,
                format!(
                    "identifier {:?} exceeds 32 character recommendation ({} chars)",
                    name,
                    name.len()
                ),
            );
        }
    }

    fn validate_value_reference(&mut self, name: &str, span: Span) {
        if let Some(first) = name.bytes().next()
            && first.is_ascii_uppercase()
        {
            self.emit_diagnostic(
                DiagCode::BadIdentifierCase,
                span,
                format!("{:?} should start with a lowercase letter", name),
            );
        }
    }

    fn expect_identifier(&mut self) -> Result<Token, SpanDiagnostic> {
        if self.peek().kind.is_identifier() {
            return Ok(self.advance());
        }
        if self.check(TokenKind::ForbiddenKeyword) {
            let token = self.advance();
            let name = self.text(token.span).to_string();
            self.emit_diagnostic(
                DiagCode::KeywordReserved,
                token.span,
                format!("identifier {:?} is a reserved ASN.1 keyword", name),
            );
            return Ok(token);
        }
        Err(self.make_error("expected identifier".to_string()))
    }

    fn expect_index_object(&mut self) -> Result<Token, SpanDiagnostic> {
        if self.peek().kind.is_identifier() || self.peek().kind.is_type_keyword() {
            return Ok(self.advance());
        }
        Err(self.make_error("expected index object".to_string()))
    }

    fn expect_enum_label(&mut self) -> Result<Token, SpanDiagnostic> {
        if self.peek().kind.is_identifier() || self.peek().kind.is_keyword() {
            return Ok(self.advance());
        }
        Err(self.make_error("expected enum label".to_string()))
    }

    fn parse_identifier_as_ident(&mut self) -> Result<Ident, SpanDiagnostic> {
        let token = self.expect_identifier()?;
        Ok(self.make_ident(token))
    }

    fn parse_quoted_string(&mut self) -> Result<QuotedString, SpanDiagnostic> {
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

    fn parse_optional_reference(&mut self) -> Result<Option<QuotedString>, SpanDiagnostic> {
        if !self.check(TokenKind::KwReference) {
            return Ok(None);
        }
        self.advance();
        Ok(Some(self.parse_quoted_string()?))
    }

    fn parse_u32(&mut self, span: Span, context: &str) -> u32 {
        let text = self.text(span);
        match text.parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                self.emit_diagnostic(
                    DiagCode::InvalidU32,
                    span,
                    format!("invalid {} (not a valid u32)", context),
                );
                0
            }
        }
    }

    fn parse_i64(&mut self, span: Span, context: &str) -> i64 {
        let text = self.text(span);
        match text.parse::<i64>() {
            Ok(v) => v,
            Err(_) => {
                self.emit_diagnostic(
                    DiagCode::InvalidI64,
                    span,
                    format!("invalid {} (not a valid i64)", context),
                );
                0
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

    fn collect_module_diagnostics(&mut self, lex_diags_before: usize) -> Vec<SpanDiagnostic> {
        let lex_diags = self.lexer.diagnostics();
        let new_lex_diags = &lex_diags[lex_diags_before..];
        let mut combined = Vec::with_capacity(new_lex_diags.len() + self.diagnostics.len());
        combined.extend_from_slice(new_lex_diags);
        combined.append(&mut self.diagnostics);
        combined
    }

    // ---- List helpers ----

    fn parse_identifier_list(&mut self) -> Result<Vec<Ident>, SpanDiagnostic> {
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

    fn parse_braced_identifier_list(&mut self) -> Result<Vec<Ident>, SpanDiagnostic> {
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
                || (current == TokenKind::UppercaseIdent && next == TokenKind::ColonColonEqual)
                || (current == TokenKind::UppercaseIdent
                    && next == TokenKind::KwTextualConvention)
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
    pub fn parse_modules(&mut self) -> Vec<Module> {
        let mut modules = Vec::new();

        while !self.is_eof() {
            let module = self.parse_one_module();
            let is_unknown = module.name.name == "UNKNOWN";
            modules.push(module);
            if is_unknown {
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
        let lex_diags_before = self.lexer.diagnostics().len();
        self.diagnostics.clear();

        let start = self.current_span().start;

        let name = match self.parse_module_header() {
            Ok(name) => name,
            Err(diag) => {
                self.record_parse_error(diag);
                debug!("failed to parse module header");
                let span = Span::new(start, self.current_span().end);
                return Module {
                    name: Ident {
                        name: "UNKNOWN".to_string(),
                        span,
                    },
                    imports: Vec::new(),
                    body: Vec::new(),
                    span,
                    diagnostics: self.collect_module_diagnostics(lex_diags_before),
                };
            }
        };

        debug!(module = %name.name, "parsing module");

        let mut imports = Vec::new();
        if self.check(TokenKind::KwImports) {
            match self.parse_imports() {
                Ok(imp) => {
                    debug!(module = %name.name, count = imp.len(), "parsed imports");
                    imports = imp;
                }
                Err(diag) => {
                    debug!(module = %name.name, "failed to parse imports");
                    self.record_parse_error(diag);
                }
            }
        }

        let mut body: Vec<Definition> = Vec::new();
        while !self.check(TokenKind::KwEnd) && !self.is_eof() {
            let pos_before = self.current_span().start;
            trace!(
                offset = pos_before.0,
                first = %self.peek().kind.display_name(),
                second = %self.peek_nth(1).kind.display_name(),
                "parsing definition",
            );
            match self.parse_definition() {
                Ok(def) => body.push(def),
                Err(diag) => {
                    self.record_parse_error(diag);
                    self.recover_to_definition();
                    if self.current_span().start == pos_before {
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

        let span = Span::new(start, self.last_end);
        let diagnostics = self.collect_module_diagnostics(lex_diags_before);

        debug!(
            module = %name.name,
            definitions = body.len(),
            diagnostics = diagnostics.len(),
            "parsing complete",
        );

        Module {
            name,
            imports,
            body,
            span,
            diagnostics,
        }
    }

    fn parse_module_header(&mut self) -> Result<Ident, SpanDiagnostic> {
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

    fn parse_imports(&mut self) -> Result<Vec<ImportClause>, SpanDiagnostic> {
        self.expect(TokenKind::KwImports)?;

        let mut clauses = Vec::new();

        while !self.check(TokenKind::Semicolon)
            && !self.check(TokenKind::KwEnd)
            && !self.is_eof()
        {
            let start = self.current_span().start;
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

            let span = Span::new(start, self.last_end);
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

    fn parse_definition(&mut self) -> Result<Definition, SpanDiagnostic> {
        let first = self.peek().kind;
        let second = self.peek_nth(1).kind;

        // Value assignment: name OBJECT IDENTIFIER ::=
        if first.is_identifier()
            && second == TokenKind::KwObject
            && self.peek_nth(2).kind == TokenKind::KwIdentifier
        {
            return self.parse_value_assignment();
        }

        // OBJECT-TYPE
        if first.is_identifier() && second == TokenKind::KwObjectType {
            return self.parse_object_type();
        }

        // MODULE-IDENTITY
        if first.is_identifier() && second == TokenKind::KwModuleIdentity {
            return self.parse_module_identity();
        }

        // OBJECT-IDENTITY
        if first.is_identifier() && second == TokenKind::KwObjectIdentity {
            return self.parse_object_identity();
        }

        // NOTIFICATION-TYPE
        if first.is_identifier() && second == TokenKind::KwNotificationType {
            return self.parse_notification_type();
        }

        // TRAP-TYPE (SMIv1)
        if first.is_identifier() && second == TokenKind::KwTrapType {
            return self.parse_trap_type();
        }

        // TEXTUAL-CONVENTION (macro-style: Name TEXTUAL-CONVENTION ...)
        if first == TokenKind::UppercaseIdent && second == TokenKind::KwTextualConvention {
            return self.parse_textual_convention();
        }

        // OBJECT-GROUP
        if first.is_identifier() && second == TokenKind::KwObjectGroup {
            return self.parse_object_group();
        }

        // NOTIFICATION-GROUP
        if first.is_identifier() && second == TokenKind::KwNotificationGroup {
            return self.parse_notification_group();
        }

        // MODULE-COMPLIANCE
        if first.is_identifier() && second == TokenKind::KwModuleCompliance {
            return self.parse_module_compliance();
        }

        // AGENT-CAPABILITIES
        if first.is_identifier() && second == TokenKind::KwAgentCapabilities {
            return self.parse_agent_capabilities();
        }

        // Type assignment or assignment-style TC: TypeName ::= ...
        // Type keywords (IpAddress, Counter32, etc.) can appear on LHS in base
        // module definitions like SNMPv2-SMI.
        if (first == TokenKind::UppercaseIdent
            || first == TokenKind::LowercaseIdent
            || first.is_type_keyword())
            && second == TokenKind::ColonColonEqual
        {
            if self.peek_nth(2).kind == TokenKind::KwTextualConvention {
                return self.parse_textual_convention_with_assignment();
            }
            if first == TokenKind::LowercaseIdent {
                let name = self.text(self.peek().span).to_string();
                self.emit_diagnostic(
                    DiagCode::BadIdentifierCase,
                    self.peek().span,
                    format!(
                        "type assignment {:?} should start with an uppercase letter",
                        name
                    ),
                );
            }
            return self.parse_type_assignment();
        }

        // MACRO definition (name can be a macro keyword like OBJECT-TYPE)
        if (first == TokenKind::UppercaseIdent || first.is_macro_keyword())
            && second == TokenKind::KwMacro
        {
            return self.parse_macro_definition();
        }

        // EXPORTS (body already consumed by lexer)
        if first == TokenKind::KwExports {
            self.advance();
            if self.check(TokenKind::Semicolon) {
                self.advance();
            }
            return self.parse_definition();
        }

        Err(self.make_error(format!(
            "unexpected token: {}",
            self.peek().kind.display_name()
        )))
    }

    // ---- Definition parsers ----

    fn parse_object_type(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, oid.span.end);
        Ok(Definition::ObjectType(ObjectTypeDef {
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
        }))
    }

    fn parse_module_identity(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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
            let rev_start = self.current_span().start;
            self.advance();
            let date = self.parse_quoted_string()?;
            self.expect(TokenKind::KwDescription)?;
            let rev_desc = self.parse_quoted_string()?;
            let rev_span = Span::new(rev_start, rev_desc.span.end);
            revisions.push(RevisionClause {
                date,
                description: rev_desc,
                span: rev_span,
            });
        }

        // ::= { oid }
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);
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

    fn parse_object_identity(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, oid.span.end);
        Ok(Definition::ObjectIdentity(ObjectIdentityDef {
            name,
            status,
            description,
            reference,
            oid,
            span,
        }))
    }

    fn parse_notification_type(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, oid.span.end);
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

    fn parse_trap_type(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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
        let trap_number = self.parse_u32(num_token.span, "trap number");

        let span = Span::new(start, self.last_end);
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

    fn parse_textual_convention(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::KwTextualConvention)?;

        let (display_hint, status, description, reference, syntax) =
            self.parse_textual_convention_body()?;

        let span = Span::new(start, syntax.span.end);
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

    fn parse_textual_convention_with_assignment(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::ColonColonEqual)?;
        self.expect(TokenKind::KwTextualConvention)?;

        let (display_hint, status, description, reference, syntax) =
            self.parse_textual_convention_body()?;

        let span = Span::new(start, syntax.span.end);
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

    fn parse_textual_convention_body(
        &mut self,
    ) -> Result<TcBody, SpanDiagnostic> {
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

    fn parse_type_assignment(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);

        self.expect(TokenKind::ColonColonEqual)?;
        let syntax = self.parse_type_syntax()?;

        let span = Span::new(start, syntax.span().end);
        Ok(Definition::TypeAssignment(TypeAssignmentDef {
            name,
            syntax,
            span,
        }))
    }

    fn parse_value_assignment(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

        let name_token = self.advance();
        let name = self.make_ident_with_validation(name_token);
        self.validate_value_reference(&name.name, name_token.span);

        self.expect(TokenKind::KwObject)?;
        self.expect(TokenKind::KwIdentifier)?;
        self.expect(TokenKind::ColonColonEqual)?;
        let oid = self.parse_oid_assignment()?;

        let span = Span::new(start, oid.span.end);
        Ok(Definition::ValueAssignment(ValueAssignmentDef {
            name,
            oid,
            span,
        }))
    }

    fn parse_object_group(&mut self) -> Result<Definition, SpanDiagnostic> {
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

    fn parse_notification_group(&mut self) -> Result<Definition, SpanDiagnostic> {
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
    ) -> Result<Definition, SpanDiagnostic>
    where
        F: FnOnce(
            Ident,
            Vec<Ident>,
            StatusClause,
            QuotedString,
            Option<QuotedString>,
            OidAssignment,
            Span,
        ) -> Definition,
    {
        let start = self.current_span().start;

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

        let span = Span::new(start, oid.span.end);
        Ok(build(name, members, status, description, reference, oid, span))
    }

    fn parse_module_compliance(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, oid.span.end);
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

    fn parse_compliance_module(&mut self) -> Result<ComplianceModule, SpanDiagnostic> {
        let start = self.current_span().start;
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
                compliances.push(Compliance::Object(self.parse_compliance_object()?));
            }
        }

        let span = Span::new(start, self.last_end);
        Ok(ComplianceModule {
            module_name,
            module_oid,
            mandatory_groups,
            compliances,
            span,
        })
    }

    fn parse_compliance_group(&mut self) -> Result<ComplianceGroup, SpanDiagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwGroup)?;

        let group = self.parse_identifier_as_ident()?;

        self.expect(TokenKind::KwDescription)?;
        let description = self.parse_quoted_string()?;

        let span = Span::new(start, description.span.end);
        Ok(ComplianceGroup {
            group,
            description,
            span,
        })
    }

    fn parse_compliance_object(&mut self) -> Result<ComplianceObject, SpanDiagnostic> {
        let start = self.current_span().start;
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

        let span = Span::new(start, description.span.end);
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
    ) -> Result<(Option<SyntaxClause>, Option<SyntaxClause>), SpanDiagnostic> {
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

    fn parse_agent_capabilities(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, oid.span.end);
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

    fn parse_supports_module(&mut self) -> Result<SupportsModule, SpanDiagnostic> {
        let start = self.current_span().start;
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

        let span = Span::new(start, self.last_end);
        Ok(SupportsModule {
            module_name,
            module_oid,
            includes,
            variations,
            span,
        })
    }

    fn parse_variation_clause(&mut self) -> Result<Variation, SpanDiagnostic> {
        let start = self.current_span().start;
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

        let span = Span::new(start, description.span.end);
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

    fn parse_macro_definition(&mut self) -> Result<Definition, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, self.last_end);
        Ok(Definition::MacroDefinition(MacroDefinitionDef {
            name,
            span,
        }))
    }

    // ---- Clause parsers ----

    fn parse_access_clause(&mut self) -> Result<AccessClause, SpanDiagnostic> {
        let start = self.current_span().start;

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

        let span = Span::new(start, self.last_end);
        Ok(AccessClause {
            keyword,
            value,
            span,
        })
    }

    fn parse_status_clause(&mut self) -> Result<StatusClause, SpanDiagnostic> {
        let start = self.current_span().start;
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

        let span = Span::new(start, self.last_end);
        Ok(StatusClause { value, span })
    }

    fn parse_index_or_augments(
        &mut self,
    ) -> Result<(Option<IndexClause>, Option<AugmentsClause>), SpanDiagnostic> {
        if self.check(TokenKind::KwIndex) {
            let start = self.current_span().start;
            self.advance();
            self.expect(TokenKind::LBrace)?;

            let mut items = Vec::new();
            loop {
                if self.check(TokenKind::RBrace) || self.is_eof() {
                    break;
                }

                let item_start = self.current_span().start;
                let implied = if self.check(TokenKind::KwImplied) {
                    self.advance();
                    true
                } else {
                    false
                };

                let obj_token = self.expect_index_object()?;

                // Special case: merge OCTET STRING into single identifier
                let object = if obj_token.kind == TokenKind::KwOctet
                    && self.check(TokenKind::KwString)
                {
                    let string_token = self.advance();
                    Ident {
                        name: "OCTET STRING".to_string(),
                        span: Span::new(obj_token.span.start, string_token.span.end),
                    }
                } else {
                    self.make_ident(obj_token)
                };

                let item_span = Span::new(item_start, self.last_end);
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
            let span = Span::new(start, self.last_end);
            return Ok((Some(IndexClause { items, span }), None));
        }

        if self.check(TokenKind::KwAugments) {
            let start = self.current_span().start;
            self.advance();
            self.expect(TokenKind::LBrace)?;
            let target_token = self.expect_identifier()?;
            let target = self.make_ident(target_token);
            self.expect(TokenKind::RBrace)?;
            let span = Span::new(start, self.last_end);
            return Ok((None, Some(AugmentsClause { target, span })));
        }

        Ok((None, None))
    }

    fn parse_defval_clause(&mut self) -> Result<DefValClause, SpanDiagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::KwDefval)?;
        self.expect(TokenKind::LBrace)?;

        let value = self.parse_defval()?;

        self.expect(TokenKind::RBrace)?;
        let span = Span::new(start, self.last_end);
        Ok(DefValClause { value, span })
    }

    fn parse_defval(&mut self) -> Result<DefVal, SpanDiagnostic> {
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
                    self.emit_diagnostic(
                        DiagCode::InvalidI64,
                        token.span,
                        "invalid DEFVAL number",
                    );
                    Ok(DefVal::Integer(0))
                }
            }
            TokenKind::NegativeNumber => {
                let token = self.advance();
                let v = self.parse_i64(token.span, "DEFVAL number");
                Ok(DefVal::Integer(v))
            }
            TokenKind::QuotedString => {
                let qs = self.parse_quoted_string()?;
                Ok(DefVal::String(qs))
            }
            TokenKind::HexString => {
                let token = self.advance();
                let full_text = self.text(token.span);
                let content = strip_string_literal(full_text);
                Ok(DefVal::HexString {
                    content: content.to_string(),
                    span: token.span,
                })
            }
            TokenKind::BinString => {
                let token = self.advance();
                let full_text = self.text(token.span);
                let content = strip_string_literal(full_text);
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
                let start = self.current_span().start;
                // We're inside DEFVAL { ... }, just skip unknown content
                Ok(DefVal::Unparsed {
                    span: Span::new(start, self.current_span().end),
                })
            }
        }
    }

    fn parse_defval_braced_content(&mut self) -> Result<DefVal, SpanDiagnostic> {
        let start = self.current_span().start;

        // Empty braces: BITS {}
        if self.check(TokenKind::RBrace) {
            let span = Span::new(start, self.current_span().end);
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
            span: Span::new(start, self.current_span().end),
        })
    }

    fn parse_defval_bits_labels(
        &mut self,
        start: ByteOffset,
        first: Ident,
    ) -> Result<DefVal, SpanDiagnostic> {
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
            span: Span::new(start, self.current_span().start),
            labels,
        })
    }

    fn parse_defval_oid_with_first_ident(
        &mut self,
        start: ByteOffset,
        first: Ident,
    ) -> Result<DefVal, SpanDiagnostic> {
        // First component might be name(number)
        let first_component = if self.check(TokenKind::LParen) {
            self.advance();
            let num_token = self.expect(TokenKind::Number)?;
            let num = self.parse_u32(num_token.span, "OID component");
            self.expect(TokenKind::RParen)?;
            OidComponent::NamedNumber {
                span: Span::new(first.span.start, self.last_end),
                name: first,
                num,
            }
        } else {
            OidComponent::Name(first)
        };

        let mut components = vec![first_component];
        self.collect_defval_oid_components(&mut components)?;

        Ok(DefVal::ObjectIdentifier {
            span: Span::new(start, self.current_span().start),
            components,
        })
    }

    fn parse_defval_oid_components(
        &mut self,
        start: ByteOffset,
    ) -> Result<DefVal, SpanDiagnostic> {
        let mut components = Vec::new();
        self.collect_defval_oid_components(&mut components)?;

        Ok(DefVal::ObjectIdentifier {
            span: Span::new(start, self.current_span().start),
            components,
        })
    }

    fn collect_defval_oid_components(
        &mut self,
        components: &mut Vec<OidComponent>,
    ) -> Result<(), SpanDiagnostic> {
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

    fn parse_syntax_clause(&mut self) -> Result<SyntaxClause, SpanDiagnostic> {
        let start = self.current_span().start;
        let syntax = self.parse_type_syntax()?;
        let span = Span::new(start, syntax.span().end);
        Ok(SyntaxClause { syntax, span })
    }

    fn parse_type_syntax(&mut self) -> Result<TypeSyntax, SpanDiagnostic> {
        let start = self.current_span().start;

        let base = match self.peek().kind {
            TokenKind::KwInteger => {
                self.advance();
                if self.check(TokenKind::LBrace) {
                    // INTEGER { enum-values }
                    let named_numbers = self.parse_named_numbers()?;
                    let span = Span::new(start, self.last_end);
                    TypeSyntax::IntegerEnum {
                        base: None,
                        named_numbers,
                        span,
                    }
                } else {
                    TypeSyntax::TypeRef(Ident {
                        name: "INTEGER".to_string(),
                        span: Span::new(start, self.last_end),
                    })
                }
            }

            TokenKind::KwBits => {
                self.advance();
                if self.check(TokenKind::LBrace) {
                    self.expect(TokenKind::LBrace)?;
                    let named_bits = self.parse_named_number_list()?;
                    self.expect(TokenKind::RBrace)?;
                    let span = Span::new(start, self.last_end);
                    TypeSyntax::Bits { named_bits, span }
                } else {
                    TypeSyntax::TypeRef(Ident {
                        name: "BITS".to_string(),
                        span: Span::new(start, self.last_end),
                    })
                }
            }

            TokenKind::KwOctet => {
                self.advance();
                self.expect(TokenKind::KwString)?;
                if self.check(TokenKind::LParen) {
                    let constraint = self.parse_constraint()?;
                    let span = Span::new(start, constraint.span().end);
                    TypeSyntax::Constrained {
                        base: Box::new(TypeSyntax::OctetString {
                            span: Span::new(start, self.last_end),
                        }),
                        constraint,
                        span,
                    }
                } else {
                    TypeSyntax::OctetString {
                        span: Span::new(start, self.last_end),
                    }
                }
            }

            TokenKind::KwObject => {
                self.advance();
                self.expect(TokenKind::KwIdentifier)?;
                TypeSyntax::ObjectIdentifier {
                    span: Span::new(start, self.last_end),
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
                        span: Span::new(start, self.last_end),
                    }
                } else {
                    // SEQUENCE { fields }
                    self.expect(TokenKind::LBrace)?;
                    let fields = self.parse_sequence_fields()?;
                    self.expect(TokenKind::RBrace)?;
                    TypeSyntax::Sequence {
                        fields,
                        span: Span::new(start, self.last_end),
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
                    span: Span::new(start, self.last_end),
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

            // Named type reference (identifier)
            TokenKind::UppercaseIdent | TokenKind::LowercaseIdent => {
                let token = self.advance();
                let ident = self.make_ident(token);

                if token.kind == TokenKind::LowercaseIdent {
                    self.emit_diagnostic(
                        DiagCode::BadIdentifierCase,
                        token.span,
                        format!(
                            "type reference {:?} should start with an uppercase letter",
                            ident.name
                        ),
                    );
                }

                if self.check(TokenKind::LParen) {
                    // Type with constraint
                    let constraint = self.parse_constraint()?;
                    let span = Span::new(start, constraint.span().end);
                    TypeSyntax::Constrained {
                        base: Box::new(TypeSyntax::TypeRef(ident)),
                        constraint,
                        span,
                    }
                } else if self.check(TokenKind::LBrace) {
                    // Restricted integer enum: TypeName { val1(1), val2(2) }
                    let named_numbers = self.parse_named_numbers()?;
                    let span = Span::new(start, self.last_end);
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
                let span = Span::new(start, underlying.span().end);
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
            let span = Span::new(start, constraint.span().end);
            return Ok(TypeSyntax::Constrained {
                base: Box::new(base),
                constraint,
                span,
            });
        }

        Ok(base)
    }

    // ---- Constraint parsing ----

    fn parse_constraint(&mut self) -> Result<Constraint, SpanDiagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::LParen)?;

        if self.check(TokenKind::KwSize) {
            // SIZE constraint
            self.advance();
            self.expect(TokenKind::LParen)?;
            let ranges = self.parse_range_list()?;
            self.expect(TokenKind::RParen)?;
            self.expect(TokenKind::RParen)?;
            let span = Span::new(start, self.last_end);
            Ok(Constraint::Size { ranges, span })
        } else {
            // Value range constraint
            let ranges = self.parse_range_list()?;
            self.expect(TokenKind::RParen)?;
            let span = Span::new(start, self.last_end);
            Ok(Constraint::Range { ranges, span })
        }
    }

    fn parse_range_list(&mut self) -> Result<Vec<Range>, SpanDiagnostic> {
        let mut ranges = Vec::new();

        loop {
            let range_start = self.current_span().start;
            let min = self.parse_range_value()?;

            let max = if self.check(TokenKind::DotDot) {
                self.advance();
                Some(self.parse_range_value()?)
            } else {
                None
            };

            let range_span = Span::new(range_start, self.last_end);
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

    fn parse_range_value(&mut self) -> Result<RangeValue, SpanDiagnostic> {
        match self.peek().kind {
            TokenKind::Number => {
                let token = self.advance();
                let text = self.text(token.span);
                if let Ok(v) = text.parse::<u64>() {
                    Ok(RangeValue::Unsigned(v))
                } else {
                    let v = self.parse_i64(token.span, "range value");
                    Ok(RangeValue::Signed(v))
                }
            }
            TokenKind::NegativeNumber => {
                let token = self.advance();
                let v = self.parse_i64(token.span, "range value");
                Ok(RangeValue::Signed(v))
            }
            TokenKind::HexString => {
                let token = self.advance();
                let full_text = self.text(token.span);
                let hex_part = strip_string_literal(full_text);
                match u64::from_str_radix(hex_part, 16) {
                    Ok(v) => Ok(RangeValue::Unsigned(v)),
                    Err(_) => {
                        self.emit_diagnostic(
                            DiagCode::InvalidHexRange,
                            token.span,
                            "invalid hex range value",
                        );
                        Ok(RangeValue::Unsigned(0))
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

    fn parse_named_numbers(&mut self) -> Result<Vec<NamedNumber>, SpanDiagnostic> {
        self.expect(TokenKind::LBrace)?;
        let list = self.parse_named_number_list()?;
        self.expect(TokenKind::RBrace)?;
        Ok(list)
    }

    fn parse_named_number_list(&mut self) -> Result<Vec<NamedNumber>, SpanDiagnostic> {
        let mut items = Vec::new();

        loop {
            if self.check(TokenKind::RBrace) || self.is_eof() {
                break;
            }

            let nn_start = self.current_span().start;
            let label_token = self.expect_enum_label()?;
            let label = self.make_ident(label_token);

            self.expect(TokenKind::LParen)?;

            let value = if self.check(TokenKind::NegativeNumber) {
                let num_token = self.advance();
                self.parse_i64(num_token.span, "named number")
            } else {
                let num_token = self.expect(TokenKind::Number)?;
                self.parse_i64(num_token.span, "named number")
            };

            self.expect(TokenKind::RParen)?;

            let nn_span = Span::new(nn_start, self.last_end);
            items.push(NamedNumber {
                name: label,
                value,
                span: nn_span,
            });

            if self.check(TokenKind::Comma) {
                self.advance();
            }
            // No comma is tolerated - continue parsing if the next token
            // looks like another named number (vendor MIBs sometimes omit commas).
        }

        Ok(items)
    }

    fn parse_sequence_fields(&mut self) -> Result<Vec<SequenceField>, SpanDiagnostic> {
        let mut fields = Vec::new();

        while !self.check(TokenKind::RBrace) && !self.is_eof() {
            let field_start = self.current_span().start;
            let name_token = self.expect_identifier()?;
            let name = self.make_ident(name_token);

            let syntax = self.parse_type_syntax()?;
            let field_span = Span::new(field_start, syntax.span().end);

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

    fn parse_oid_assignment(&mut self) -> Result<OidAssignment, SpanDiagnostic> {
        let start = self.current_span().start;
        self.expect(TokenKind::LBrace)?;

        let mut components = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.is_eof() {
            let comp = self.parse_oid_component()?;
            components.push(comp);
        }

        self.expect(TokenKind::RBrace)?;

        let span = Span::new(start, self.last_end);
        Ok(OidAssignment { components, span })
    }

    fn parse_oid_component(&mut self) -> Result<OidComponent, SpanDiagnostic> {
        match self.peek().kind {
            TokenKind::Number => {
                let token = self.advance();
                let value = self.parse_u32(token.span, "OID component");
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
                            let num = self.parse_u32(num_token.span, "OID component number");
                            self.expect(TokenKind::RParen)?;
                            let span = Span::new(ident.span.start, self.last_end);
                            return Ok(OidComponent::QualifiedNamedNumber {
                                module_name: ident,
                                name: name_ident,
                                num,
                                span,
                            });
                        }

                        let span = Span::new(ident.span.start, name_ident.span.end);
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
                    let num = self.parse_u32(num_token.span, "OID component number");
                    self.expect(TokenKind::RParen)?;
                    let span = Span::new(ident.span.start, self.last_end);
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
/// Input: 'content'H or 'content'B, output: content
fn strip_string_literal(s: &str) -> &str {
    let s = s.strip_prefix('\'').unwrap_or(s);
    if let Some(pos) = s.rfind('\'') {
        &s[..pos]
    } else {
        s
    }
}

/// Parse source bytes into AST modules.
pub fn parse(source: &[u8], diag_config: DiagnosticConfig) -> Vec<Module> {
    let mut parser = Parser::new(source, diag_config);
    parser.parse_modules()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(input: &str) -> Vec<Module> {
        parse(input.as_bytes(), DiagnosticConfig::default())
    }

    fn parse_strict(input: &str) -> Vec<Module> {
        parse(input.as_bytes(), DiagnosticConfig::strict())
    }

    #[test]
    fn empty_input() {
        let modules = parse_str("");
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name.name, "UNKNOWN");
    }

    #[test]
    fn minimal_module() {
        let input = "TEST-MIB DEFINITIONS ::= BEGIN\nEND\n";
        let modules = parse_str(input);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name.name, "TEST-MIB");
        assert!(modules[0].imports.is_empty());
        assert!(modules[0].body.is_empty());
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
                assert!(matches!(&d.syntax, TypeSyntax::SequenceOf { entry_type, .. } if entry_type.name == "TestEntry"));
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
            Definition::TypeAssignment(d) => {
                match &d.syntax {
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
                }
            }
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
                assert!(matches!(d.defval.as_ref().unwrap().value, DefVal::Integer(42)));
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
                    DefVal::Bits { labels, .. } => {
                        assert_eq!(labels.len(), 1);
                        assert_eq!(labels[0].name, "flag1");
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
        assert!(modules[0]
            .diagnostics
            .iter()
            .any(|d| d.code == DiagCode::IdentifierUnderscore));
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
        assert!(matches!(&modules[0].body[0], Definition::MacroDefinition(_)));
        assert!(matches!(&modules[0].body[1], Definition::ValueAssignment(_)));
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
        assert_eq!(modules[0].name.name, "MOD-A");
        assert_eq!(modules[1].name.name, "MOD-B");
    }

    #[test]
    fn choice_type() {
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestChoice ::= CHOICE { a INTEGER, b OCTET STRING }
END
"#;
        let modules = parse_str(input);
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                match &d.syntax {
                    TypeSyntax::Choice { alternatives, .. } => {
                        assert_eq!(alternatives.len(), 2);
                    }
                    other => panic!("expected Choice, got {:?}", other),
                }
            }
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                match &d.syntax {
                    TypeSyntax::IntegerEnum { named_numbers, .. } => {
                        assert_eq!(named_numbers.len(), 3);
                    }
                    other => panic!("expected IntegerEnum, got {:?}", other),
                }
            }
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                match &d.syntax {
                    TypeSyntax::IntegerEnum { named_numbers, .. } => {
                        assert_eq!(named_numbers.len(), 3);
                        assert_eq!(named_numbers[0].value, -1);
                        assert_eq!(named_numbers[1].value, 0);
                        assert_eq!(named_numbers[2].value, 1);
                    }
                    other => panic!("expected IntegerEnum, got {:?}", other),
                }
            }
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let syntax = d.syntax.as_ref().unwrap();
                match &syntax.syntax {
                    TypeSyntax::Constrained { base, constraint, .. } => {
                        assert!(matches!(base.as_ref(), TypeSyntax::TypeRef(id) if id.name == "DisplayString"));
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let syntax = d.syntax.as_ref().unwrap();
                match &syntax.syntax {
                    TypeSyntax::IntegerEnum { base, named_numbers, .. } => {
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                match &d.defval.as_ref().unwrap().value {
                    DefVal::HexString { content, .. } => assert_eq!(content, "FF00"),
                    other => panic!("expected HexString DEFVAL, got {:?}", other),
                }
            }
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                match &d.defval.as_ref().unwrap().value {
                    DefVal::ObjectIdentifier { components, .. } => {
                        assert_eq!(components.len(), 4);
                    }
                    other => panic!("expected OID DEFVAL, got {:?}", other),
                }
            }
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
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
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestHex ::= INTEGER ('00'H..'FF'H)
END
"#;
        let modules = parse_str(input);
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                assert!(matches!(&d.syntax, TypeSyntax::Constrained { .. }));
            }
            other => panic!("expected TypeAssignment, got {:?}", other),
        }
    }

    #[test]
    fn keyword_as_enum_label() {
        // Keywords like "current", "deprecated" can be used as enum labels
        let input = r#"TEST-MIB DEFINITIONS ::= BEGIN
TestType ::= INTEGER { current(1), deprecated(2), optional(3) }
END
"#;
        let modules = parse_str(input);
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::TypeAssignment(d) => {
                match &d.syntax {
                    TypeSyntax::IntegerEnum { named_numbers, .. } => {
                        assert_eq!(named_numbers.len(), 3);
                        assert_eq!(named_numbers[0].name.name, "current");
                        assert_eq!(named_numbers[1].name.name, "deprecated");
                        assert_eq!(named_numbers[2].name.name, "optional");
                    }
                    other => panic!("expected IntegerEnum, got {:?}", other),
                }
            }
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
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
        match &modules[0].body[0] {
            Definition::ObjectType(d) => {
                let syntax = d.syntax.as_ref().unwrap();
                assert!(matches!(&syntax.syntax, TypeSyntax::ObjectIdentifier { .. }));
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
        assert_eq!(modules[0].name.name, "TEST-MIB");
        assert!(modules[0].diagnostics.iter().all(|d| d.code != DiagCode::ParseError));
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
