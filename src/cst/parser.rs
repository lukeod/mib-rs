//! Lossless parser for module framing and imports.

use super::{ElementData, NodeData, TokenData};
use crate::source::{SourceDocument, SourceRange};
use crate::syntax::SyntaxKind;
use crate::types::{DiagCode, Diagnostic, DiagnosticConfig};

const MAX_ASSIGNMENT_HEADER_TOKENS: usize = 256;

pub(super) fn parse(
    document: &SourceDocument,
    tokens: &[TokenData],
    diag_config: &DiagnosticConfig,
) -> (NodeData, Vec<Diagnostic>) {
    Parser {
        document,
        tokens,
        diag_config,
        diagnostics: Vec::new(),
    }
    .parse_source_file()
}

struct Parser<'a> {
    document: &'a SourceDocument,
    tokens: &'a [TokenData],
    diag_config: &'a DiagnosticConfig,
    diagnostics: Vec<Diagnostic>,
}

impl Parser<'_> {
    fn parse_source_file(mut self) -> (NodeData, Vec<Diagnostic>) {
        let eof = self.tokens.len() - 1;
        let mut children = Vec::new();
        let mut cursor = 0;

        while cursor < eof {
            let Some(start) = self.find_module_start(cursor, eof, false) else {
                self.push_outside(&mut children, cursor, eof);
                break;
            };
            self.push_outside(&mut children, cursor, start);
            let (module, end) = self.parse_module(start, eof);
            children.push(ElementData::Node(module));
            cursor = end;
        }

        children.push(ElementData::Token(self.tokens[eof]));
        let root = self.node(SyntaxKind::SourceFile, children);
        (root, self.diagnostics)
    }

    fn parse_module(&mut self, start: usize, eof: usize) -> (NodeData, usize) {
        let next_module = self.find_module_start(start + 1, eof, true);
        let limit = next_module.unwrap_or(eof);
        let begin = self.find_header_begin(start, limit);
        let end_token = self.find_module_end(begin.map_or(start + 1, |begin| begin + 1), limit);
        let module_end = end_token.map_or(limit, |end| end + 1);
        let header_end = begin.map_or_else(
            || self.header_recovery_end(start, module_end),
            |begin| begin + 1,
        );

        let header = self.parse_header(start, header_end);
        let mut children = vec![ElementData::Node(header)];
        let mut cursor = header_end;

        let body_limit = end_token.unwrap_or(module_end);
        while let Some(exports) = self.next_significant(cursor, body_limit)
            && self.tokens[exports].kind == SyntaxKind::KwExports
        {
            let Some(semicolon) = self.find_kind(exports + 1, body_limit, SyntaxKind::Semicolon)
            else {
                break;
            };
            self.push_unparsed(&mut children, cursor, semicolon + 1);
            cursor = semicolon + 1;
        }

        let first_body = self.next_significant(cursor, body_limit);
        if first_body.is_some_and(|index| self.tokens[index].kind == SyntaxKind::KwImports) {
            let imports_start = first_body.expect("checked above");
            self.push_plain(&mut children, cursor, imports_start);
            let (imports, imports_end) = self.parse_imports(imports_start, body_limit);
            children.push(ElementData::Node(imports));
            cursor = imports_end;
        }

        let body_end = end_token.unwrap_or(module_end);
        self.push_structured_body(&mut children, cursor, body_end);
        if let Some(end) = end_token {
            children.push(ElementData::Token(self.tokens[end]));
        } else {
            self.emit_at(module_end, "expected END");
        }

        (self.node(SyntaxKind::Module, children), module_end)
    }

    fn parse_header(&mut self, start: usize, end: usize) -> NodeData {
        let mut children = Vec::new();
        let mut cursor = start;

        self.push_plain(&mut children, cursor, start + 1);
        cursor = start + 1;

        if let Some(open) = self.next_significant(cursor, end)
            && self.tokens[open].kind == SyntaxKind::LBrace
        {
            let close = self
                .matching_rbrace(open, end)
                .map_or(end, |index| index + 1);
            self.push_plain(&mut children, cursor, close);
            cursor = close;
        }

        for (expected, later) in [
            (
                SyntaxKind::KwDefinitions,
                &[SyntaxKind::ColonColonEqual, SyntaxKind::KwBegin][..],
            ),
            (SyntaxKind::ColonColonEqual, &[SyntaxKind::KwBegin][..]),
            (SyntaxKind::KwBegin, &[][..]),
        ] {
            if cursor >= end {
                self.emit_at(end, format!("expected {}", expected.display_name()));
                continue;
            }
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                cursor = end;
                self.emit_at(end, format!("expected {}", expected.display_name()));
                continue;
            };
            if self.tokens[current].kind == expected {
                self.push_plain(&mut children, cursor, current + 1);
                cursor = current + 1;
                continue;
            }
            if later.contains(&self.tokens[current].kind) {
                self.emit_at(current, format!("expected {}", expected.display_name()));
                continue;
            }

            let recovery_end = self
                .find_any(current + 1, end, expected, later)
                .unwrap_or(end);
            self.push_error(&mut children, cursor, recovery_end);
            self.emit_at(current, format!("expected {}", expected.display_name()));
            cursor = recovery_end;
            if cursor < end && self.tokens[cursor].kind == expected {
                self.push_plain(&mut children, cursor, cursor + 1);
                cursor += 1;
            }
        }

        if cursor < end {
            if self.only_trivia(cursor, end) {
                self.push_plain(&mut children, cursor, end);
            } else {
                self.push_error(&mut children, cursor, end);
            }
        }
        self.node(SyntaxKind::ModuleHeader, children)
    }

    fn parse_imports(&mut self, start: usize, limit: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let mut cursor = start + 1;
        let mut closed = false;

        while let Some(current) = self.next_significant(cursor, limit) {
            if self.tokens[current].kind == SyntaxKind::Semicolon {
                self.push_plain(&mut children, cursor, current + 1);
                cursor = current + 1;
                closed = true;
                break;
            }
            if self.looks_like_definition(current, limit) {
                self.push_plain(&mut children, cursor, current);
                self.emit_at(current, "unexpected end of imports");
                return (self.node(SyntaxKind::Imports, children), current);
            }
            if !is_import_symbol(self.tokens[current].kind)
                && self.tokens[current].kind != SyntaxKind::KwFrom
            {
                self.push_plain(&mut children, cursor, current);
                self.push_error(&mut children, current, current + 1);
                self.emit_at(current, "expected import symbol or FROM");
                cursor = current + 1;
                continue;
            }

            self.push_plain(&mut children, cursor, current);
            let (group, group_end) = self.parse_import_group(current, limit);
            children.push(ElementData::Node(group));
            cursor = group_end;
        }

        if !closed {
            self.push_plain(&mut children, cursor, limit);
            self.emit_at(limit, "unexpected end of imports");
            cursor = limit;
        }
        (self.node(SyntaxKind::Imports, children), cursor)
    }

    fn parse_import_group(&mut self, start: usize, limit: usize) -> (NodeData, usize) {
        let mut children = Vec::new();
        let mut cursor = start;
        let mut saw_symbol = false;
        let mut need_symbol = true;

        loop {
            let Some(current) = self.next_significant(cursor, limit) else {
                self.push_plain(&mut children, cursor, limit);
                self.emit_at(limit, "expected FROM");
                return (self.node(SyntaxKind::ImportGroup, children), limit);
            };
            let kind = self.tokens[current].kind;
            if self.looks_like_definition(current, limit) {
                self.push_plain(&mut children, cursor, current);
                self.emit_at(current, "expected FROM");
                return (self.node(SyntaxKind::ImportGroup, children), current);
            }
            if kind == SyntaxKind::Semicolon {
                self.push_plain(&mut children, cursor, current);
                self.emit_at(current, "expected FROM");
                return (self.node(SyntaxKind::ImportGroup, children), current);
            }
            if kind == SyntaxKind::KwFrom {
                if !saw_symbol {
                    self.emit_at(current, "expected import symbol");
                } else if need_symbol {
                    self.emit_at(current, "expected import symbol after ','");
                }
                self.push_plain(&mut children, cursor, current + 1);
                cursor = current + 1;
                break;
            }
            if is_import_symbol(kind) {
                if saw_symbol && !need_symbol {
                    self.emit_at(current, "expected ',' or FROM");
                }
                self.push_plain(&mut children, cursor, current + 1);
                cursor = current + 1;
                saw_symbol = true;
                need_symbol = false;
                continue;
            }
            if kind == SyntaxKind::Comma {
                if need_symbol {
                    self.emit_at(current, "expected import symbol");
                }
                self.push_plain(&mut children, cursor, current + 1);
                cursor = current + 1;
                need_symbol = true;
                continue;
            }

            self.push_plain(&mut children, cursor, current);
            self.push_error(&mut children, current, current + 1);
            self.emit_at(current, "expected import symbol or FROM");
            cursor = current + 1;
        }

        let Some(module) = self.next_significant(cursor, limit) else {
            self.push_plain(&mut children, cursor, limit);
            self.emit_at(limit, "expected module name after FROM");
            return (self.node(SyntaxKind::ImportGroup, children), limit);
        };
        if self.tokens[module].kind == SyntaxKind::UppercaseIdent {
            self.push_plain(&mut children, cursor, module + 1);
            cursor = module + 1;
        } else if self.looks_like_definition(module, limit) {
            self.push_plain(&mut children, cursor, module);
            self.emit_at(module, "expected module name after FROM");
            return (self.node(SyntaxKind::ImportGroup, children), module);
        } else {
            self.push_plain(&mut children, cursor, module);
            self.push_error(&mut children, module, module + 1);
            self.emit_at(module, "expected module name after FROM");
            cursor = module + 1;
        }
        (self.node(SyntaxKind::ImportGroup, children), cursor)
    }

    fn find_module_start(&self, from: usize, end: usize, strong: bool) -> Option<usize> {
        (from..end).find(|&index| self.is_module_start(index, end, strong))
    }

    fn is_module_start(&self, index: usize, end: usize, strong: bool) -> bool {
        if !self.tokens[index].kind.is_identifier() {
            return false;
        }
        if strong && self.tokens[index].kind != SyntaxKind::UppercaseIdent {
            return false;
        }
        let mut next = index + 1;
        if let Some(open) = self.next_significant(next, end)
            && self.tokens[open].kind == SyntaxKind::LBrace
        {
            let Some(close) = self.matching_rbrace(open, end) else {
                return !strong;
            };
            next = close + 1;
        }
        let Some(first) = self.next_significant(next, end) else {
            return false;
        };
        if self.tokens[first].kind == SyntaxKind::KwDefinitions {
            if !strong {
                return true;
            }
            let Some(assign) = self.next_significant(first + 1, end) else {
                return false;
            };
            if self.tokens[assign].kind != SyntaxKind::ColonColonEqual {
                return false;
            }
            return self
                .next_significant(assign + 1, end)
                .is_some_and(|begin| self.tokens[begin].kind == SyntaxKind::KwBegin);
        }
        if !strong {
            let mut probe = first;
            for _ in 0..8 {
                let kind = self.tokens[probe].kind;
                if kind == SyntaxKind::KwDefinitions {
                    return true;
                }
                if kind.is_identifier() {
                    break;
                }
                if matches!(
                    kind,
                    SyntaxKind::KwBegin | SyntaxKind::KwEnd | SyntaxKind::Semicolon
                ) {
                    break;
                }
                let Some(next_probe) = self.next_significant(probe + 1, end) else {
                    break;
                };
                probe = next_probe;
            }
        }
        if self.tokens[first].kind == SyntaxKind::KwBegin {
            return !strong;
        }
        if self.tokens[first].kind != SyntaxKind::ColonColonEqual {
            return false;
        }
        self.next_significant(first + 1, end)
            .is_some_and(|next| self.tokens[next].kind == SyntaxKind::KwBegin)
    }

    fn header_recovery_end(&self, start: usize, limit: usize) -> usize {
        (start + 1..limit)
            .find(|&index| {
                self.tokens[index].kind == SyntaxKind::KwEnd
                    || self.looks_like_definition(index, limit)
            })
            .unwrap_or(limit)
    }

    fn looks_like_definition(&self, index: usize, end: usize) -> bool {
        let first_kind = self.tokens[index].kind;
        if !first_kind.is_identifier()
            && !first_kind.is_macro_keyword()
            && !first_kind.is_type_keyword()
        {
            return false;
        }
        let Some(second) = self.next_significant(index + 1, end) else {
            return false;
        };
        let second_kind = self.tokens[second].kind;
        if first_kind.is_macro_keyword() {
            return second_kind == SyntaxKind::KwMacro;
        }
        if second_kind == SyntaxKind::KwMacro {
            return true;
        }

        // This is only a recovery boundary, not definition parsing. Search a
        // bounded header for a top-level assignment while balancing the
        // punctuation used by tags, constraints, and composite type syntax.
        let mut delimiters = Vec::new();
        let mut cursor = second;
        for _ in 0..MAX_ASSIGNMENT_HEADER_TOKENS {
            let kind = self.tokens[cursor].kind;
            match kind {
                SyntaxKind::LParen => delimiters.push(SyntaxKind::RParen),
                SyntaxKind::LBracket => delimiters.push(SyntaxKind::RBracket),
                SyntaxKind::LBrace => delimiters.push(SyntaxKind::RBrace),
                SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace => {
                    if delimiters.pop() != Some(kind) {
                        return false;
                    }
                }
                SyntaxKind::ColonColonEqual if delimiters.is_empty() => return true,
                SyntaxKind::KwFrom
                | SyntaxKind::Semicolon
                | SyntaxKind::KwEnd
                | SyntaxKind::KwImports
                | SyntaxKind::KwExports => return false,
                SyntaxKind::Comma if delimiters.is_empty() => return false,
                _ => {}
            }

            let Some(next) = self.next_significant(cursor + 1, end) else {
                return false;
            };
            cursor = next;
        }
        false
    }

    fn next_significant(&self, from: usize, end: usize) -> Option<usize> {
        (from..end).find(|&index| !self.tokens[index].kind.is_trivia())
    }

    fn find_kind(&self, from: usize, end: usize, kind: SyntaxKind) -> Option<usize> {
        (from..end).find(|&index| self.tokens[index].kind == kind)
    }

    fn find_header_begin(&self, start: usize, end: usize) -> Option<usize> {
        let mut cursor = start + 1;
        if let Some(open) = self.next_significant(cursor, end)
            && self.tokens[open].kind == SyntaxKind::LBrace
        {
            cursor = self.matching_rbrace(open, end)? + 1;
        }
        self.find_kind(cursor, end, SyntaxKind::KwBegin)
    }

    fn find_module_end(&self, from: usize, end: usize) -> Option<usize> {
        let mut cursor = from;
        while let Some(current) = self.next_significant(cursor, end) {
            if let Some(macro_end) = self.legacy_macro_end(current, end) {
                cursor = macro_end + 1;
                continue;
            }
            if self.tokens[current].kind == SyntaxKind::KwEnd {
                return Some(current);
            }
            cursor = current + 1;
        }
        None
    }

    fn legacy_macro_end(&self, start: usize, end: usize) -> Option<usize> {
        let name_kind = self.tokens[start].kind;
        if !name_kind.is_identifier() && !name_kind.is_macro_keyword() {
            return None;
        }
        let macro_keyword = self.next_significant(start + 1, end)?;
        if self.tokens[macro_keyword].kind != SyntaxKind::KwMacro {
            return None;
        }
        let after_macro = self.next_significant(macro_keyword + 1, end)?;
        if self.tokens[after_macro].kind == SyntaxKind::OpaqueText {
            let macro_end = self.next_significant(after_macro + 1, end)?;
            return (self.tokens[macro_end].kind == SyntaxKind::KwEnd).then_some(macro_end);
        }
        let assign = after_macro;
        if self.tokens[assign].kind != SyntaxKind::ColonColonEqual {
            return None;
        }
        let begin = self.next_significant(assign + 1, end)?;
        if self.tokens[begin].kind != SyntaxKind::KwBegin {
            return None;
        }
        self.find_kind(begin + 1, end, SyntaxKind::KwEnd)
    }

    fn find_any(
        &self,
        from: usize,
        end: usize,
        expected: SyntaxKind,
        later: &[SyntaxKind],
    ) -> Option<usize> {
        (from..end).find(|&index| {
            let kind = self.tokens[index].kind;
            kind == expected || later.contains(&kind)
        })
    }

    fn matching_rbrace(&self, open: usize, end: usize) -> Option<usize> {
        let mut depth = 0usize;
        for index in open..end {
            match self.tokens[index].kind {
                SyntaxKind::LBrace => depth += 1,
                SyntaxKind::RBrace => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn only_trivia(&self, start: usize, end: usize) -> bool {
        self.tokens[start..end]
            .iter()
            .all(|token| token.kind.is_trivia())
    }

    fn push_outside(&mut self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        if start == end {
            return;
        }
        if self.only_trivia(start, end) {
            self.push_plain(children, start, end);
        } else {
            let at = self.next_significant(start, end).unwrap_or(start);
            let recovery_end = (start..end)
                .rfind(|&index| !self.tokens[index].kind.is_trivia())
                .map_or(end, |index| index + 1);
            self.push_plain(children, start, at);
            self.push_error(children, at, recovery_end);
            self.push_plain(children, recovery_end, end);
            self.emit_at(at, "tokens outside a recognized module");
        }
    }

    fn push_unparsed(&self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        if start == end {
            return;
        }
        if self.only_trivia(start, end) {
            self.push_plain(children, start, end);
        } else {
            let body = self.elements(start, end);
            children.push(ElementData::Node(
                self.node(SyntaxKind::UnparsedRegion, body),
            ));
        }
    }

    fn push_structured_body(&mut self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        if start == end {
            return;
        }
        if self.only_trivia(start, end) {
            self.push_plain(children, start, end);
        } else {
            let body = super::body::parse_region(
                self.document,
                self.tokens,
                self.diag_config,
                &mut self.diagnostics,
                start,
                end,
            );
            children.push(ElementData::Node(body));
        }
    }

    fn push_error(&self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        if start == end {
            return;
        }
        let recovered = self.raw_elements(start, end);
        children.push(ElementData::Node(self.node(SyntaxKind::Error, recovered)));
    }

    fn push_plain(&self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        children.extend(self.elements(start, end));
    }

    fn elements(&self, start: usize, end: usize) -> Vec<ElementData> {
        self.tokens[start..end]
            .iter()
            .copied()
            .map(|token| {
                if token.kind == SyntaxKind::ErrorToken {
                    ElementData::Node(self.node(SyntaxKind::Error, vec![ElementData::Token(token)]))
                } else {
                    ElementData::Token(token)
                }
            })
            .collect()
    }

    fn raw_elements(&self, start: usize, end: usize) -> Vec<ElementData> {
        self.tokens[start..end]
            .iter()
            .copied()
            .map(ElementData::Token)
            .collect()
    }

    fn node(&self, kind: SyntaxKind, children: Vec<ElementData>) -> NodeData {
        let first = children.first().expect("CST nodes are never empty").range();
        let last = children.last().expect("CST nodes are never empty").range();
        let range = SourceRange::cover(first, last).expect("CST children are source ordered");
        NodeData {
            kind,
            range,
            children: children.into_boxed_slice(),
        }
    }

    fn emit_at(&mut self, index: usize, message: impl Into<String>) {
        if !self.diag_config.should_collect(DiagCode::ParseError) {
            return;
        }
        let range = if index < self.tokens.len() {
            self.tokens[index].range
        } else {
            self.document
                .empty_range(self.document.bytes().len())
                .expect("document end is valid")
        };
        self.diagnostics.push(Diagnostic {
            severity: self.diag_config.effective_severity(DiagCode::ParseError),
            code: DiagCode::ParseError,
            message: message.into(),
            module: None,
            range: Some(range),
        });
    }
}

impl ElementData {
    fn range(&self) -> SourceRange {
        match self {
            Self::Node(node) => node.range,
            Self::Token(token) => token.range,
        }
    }
}

fn is_import_symbol(kind: SyntaxKind) -> bool {
    kind.is_identifier() || kind.is_macro_keyword() || kind.is_type_keyword()
}
