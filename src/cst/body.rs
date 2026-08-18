//! Lossless parsing for definitions and their common clauses, OID assignments,
//! and type-syntax fragments.

use super::{ElementData, NodeData, TokenData};
use crate::source::{SourceDocument, SourceRange};
use crate::syntax::SyntaxKind;
use crate::types::{DiagCode, Diagnostic, DiagnosticConfig};

#[cfg(test)]
thread_local! {
    static DEFINITION_CONTEXT_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_definition_context_work(units: usize) {
    DEFINITION_CONTEXT_WORK.with(|work| work.set(work.get() + units));
}

#[cfg(not(test))]
fn record_definition_context_work(_units: usize) {}

#[cfg(test)]
pub(super) fn reset_definition_context_work() {
    DEFINITION_CONTEXT_WORK.with(|work| work.set(0));
}

#[cfg(test)]
pub(super) fn definition_context_work() -> usize {
    DEFINITION_CONTEXT_WORK.with(std::cell::Cell::get)
}

pub(super) fn parse_region(
    document: &SourceDocument,
    tokens: &[TokenData],
    diag_config: &DiagnosticConfig,
    diagnostics: &mut Vec<Diagnostic>,
    start: usize,
    end: usize,
) -> NodeData {
    BodyParser {
        document,
        tokens,
        diag_config,
        diagnostics,
        parse_errors: 0,
    }
    .parse_region(start, end)
}

struct BodyParser<'a, 'd> {
    document: &'a SourceDocument,
    tokens: &'a [TokenData],
    diag_config: &'a DiagnosticConfig,
    diagnostics: &'d mut Vec<Diagnostic>,
    parse_errors: usize,
}

impl BodyParser<'_, '_> {
    fn parse_region(&mut self, start: usize, end: usize) -> NodeData {
        let mut children = Vec::new();
        let mut cursor = start;
        let definition_starts = self.collect_definition_starts(start, end);

        for (position, &definition_start) in definition_starts.iter().enumerate() {
            let next_start = definition_starts.get(position + 1).copied().unwrap_or(end);
            let definition_end = self
                .previous_significant(next_start, definition_start)
                .map_or(definition_start, |last| last + 1);
            self.push_plain(&mut children, cursor, definition_start);

            if let Some(kind) = self.definition_kind(definition_start, definition_end) {
                let definition = self.parse_definition(definition_start, definition_end, kind);
                children.push(ElementData::Node(definition));
            } else {
                children.extend(self.parse_fragment(
                    definition_start,
                    definition_end,
                    Some(definition_start),
                ));
            }
            cursor = definition_end;
        }
        self.push_plain(&mut children, cursor, end);
        self.node(SyntaxKind::UnparsedRegion, children)
    }

    fn parse_definition(&mut self, start: usize, end: usize, kind: SyntaxKind) -> NodeData {
        let parse_error_start = self.parse_errors;
        let children = self.parse_fragment(start, end, Some(start));
        let definition = self.node(kind, children);
        let complete = self.definition_is_complete(&definition);
        if !complete && self.parse_errors == parse_error_start {
            self.emit_at(end, format!("incomplete {}", kind.display_name()));
        }

        if complete && self.parse_errors == parse_error_start {
            definition
        } else {
            self.node(SyntaxKind::Error, vec![ElementData::Node(definition)])
        }
    }

    fn parse_fragment(
        &mut self,
        start: usize,
        end: usize,
        current_definition: Option<usize>,
    ) -> Vec<ElementData> {
        let mut children = Vec::new();
        let mut cursor = start;
        let mut current_assignment = None;

        while let Some(current) = self.next_significant(cursor, end) {
            self.push_plain(&mut children, cursor, current);
            if self.tokens[current].kind == SyntaxKind::ColonColonEqual
                && current_assignment.is_none()
            {
                current_assignment = Some(current);
                record_definition_context_work(1);
            }
            if let Some((node, next)) = self.parse_clause(current, end) {
                children.push(ElementData::Node(node));
                cursor = next;
                continue;
            }
            if self.tokens[current].kind == SyntaxKind::ColonColonEqual
                && let Some(open) = self.next_significant(current + 1, end)
                && self.tokens[open].kind == SyntaxKind::LBrace
                && self.is_oid_assignment_context(current, current_definition, current_assignment)
            {
                self.push_plain(&mut children, current, open);
                let (oid, next) = self.parse_oid_assignment(open, end);
                children.push(ElementData::Node(oid));
                cursor = next;
                continue;
            }
            if self.is_type_context(current, start, end, current_definition, current_assignment)
                && let Some((syntax, next)) = self.parse_type_syntax(current, end)
            {
                children.push(ElementData::Node(syntax));
                cursor = next;
                continue;
            }

            children.push(self.element(current));
            cursor = current + 1;
        }
        self.push_plain(&mut children, cursor, end);
        children
    }

    fn definition_kind(&self, start: usize, end: usize) -> Option<SyntaxKind> {
        let first = self.tokens[start].kind;
        let Some(second) = self.next_significant(start + 1, end) else {
            return (first == SyntaxKind::UppercaseIdent || first.is_type_keyword())
                .then_some(SyntaxKind::TypeAssignment);
        };
        match self.tokens[second].kind {
            SyntaxKind::KwObject if first.is_identifier() => Some(SyntaxKind::ValueAssignment),
            SyntaxKind::ColonColonEqual => {
                let rhs = self.next_significant(second + 1, end);
                if rhs.is_some_and(|rhs| self.tokens[rhs].kind == SyntaxKind::KwTextualConvention) {
                    Some(SyntaxKind::TextualConventionDefinition)
                } else {
                    Some(SyntaxKind::TypeAssignment)
                }
            }
            SyntaxKind::KwTextualConvention if first == SyntaxKind::UppercaseIdent => {
                Some(SyntaxKind::TextualConventionDefinition)
            }
            SyntaxKind::KwObjectType => Some(SyntaxKind::ObjectTypeDefinition),
            SyntaxKind::KwModuleIdentity => Some(SyntaxKind::ModuleIdentityDefinition),
            SyntaxKind::KwObjectIdentity => Some(SyntaxKind::ObjectIdentityDefinition),
            SyntaxKind::KwNotificationType => Some(SyntaxKind::NotificationTypeDefinition),
            SyntaxKind::KwTrapType => Some(SyntaxKind::TrapTypeDefinition),
            SyntaxKind::KwMacro => Some(SyntaxKind::MacroDefinition),
            kind if (first == SyntaxKind::UppercaseIdent || first.is_type_keyword())
                && is_type_start(kind) =>
            {
                Some(SyntaxKind::TypeAssignment)
            }
            _ => None,
        }
    }

    fn definition_is_complete(&self, definition: &NodeData) -> bool {
        if contains_node_kind(definition, SyntaxKind::Error) {
            return false;
        }
        let parts = definition_parts(definition);
        match definition.kind {
            SyntaxKind::ValueAssignment => validate_value_assignment(&parts, definition),
            SyntaxKind::TypeAssignment => validate_type_assignment(&parts),
            SyntaxKind::TextualConventionDefinition => validate_textual_convention(&parts),
            SyntaxKind::ObjectTypeDefinition => validate_object_type(&parts, definition),
            SyntaxKind::ModuleIdentityDefinition => validate_module_identity(&parts, definition),
            SyntaxKind::ObjectIdentityDefinition => validate_object_identity(&parts, definition),
            SyntaxKind::NotificationTypeDefinition => {
                validate_notification_type(&parts, definition)
            }
            SyntaxKind::TrapTypeDefinition => validate_trap_type(&parts),
            SyntaxKind::MacroDefinition => {
                validate_macro_definition(&parts, definition, self.document)
            }
            _ => false,
        }
    }

    fn parse_clause(&mut self, start: usize, end: usize) -> Option<(NodeData, usize)> {
        let kind = self.tokens[start].kind;
        match kind {
            SyntaxKind::KwSyntax => Some(self.parse_syntax_clause(start, end)),
            SyntaxKind::KwMaxAccess | SyntaxKind::KwAccess | SyntaxKind::KwMinAccess => {
                Some(self.parse_value_clause(
                    SyntaxKind::AccessClause,
                    start,
                    end,
                    is_access_value,
                    "access value",
                ))
            }
            SyntaxKind::KwStatus => Some(self.parse_value_clause(
                SyntaxKind::StatusClause,
                start,
                end,
                is_status_value,
                "status value",
            )),
            SyntaxKind::KwDescription => {
                Some(self.parse_string_clause(SyntaxKind::DescriptionClause, start, end))
            }
            SyntaxKind::KwReference => {
                Some(self.parse_string_clause(SyntaxKind::ReferenceClause, start, end))
            }
            SyntaxKind::KwUnits => {
                Some(self.parse_string_clause(SyntaxKind::UnitsClause, start, end))
            }
            SyntaxKind::KwDisplayHint => {
                Some(self.parse_string_clause(SyntaxKind::DisplayHintClause, start, end))
            }
            SyntaxKind::KwLastUpdated => {
                Some(self.parse_string_clause(SyntaxKind::LastUpdatedClause, start, end))
            }
            SyntaxKind::KwOrganization => {
                Some(self.parse_string_clause(SyntaxKind::OrganizationClause, start, end))
            }
            SyntaxKind::KwContactInfo => {
                Some(self.parse_string_clause(SyntaxKind::ContactInfoClause, start, end))
            }
            SyntaxKind::KwProductRelease => {
                Some(self.parse_string_clause(SyntaxKind::ProductReleaseClause, start, end))
            }
            SyntaxKind::KwRevision => Some(self.parse_value_clause(
                SyntaxKind::RevisionClause,
                start,
                end,
                |value| value == SyntaxKind::QuotedString,
                "quoted revision date",
            )),
            SyntaxKind::KwEnterprise => Some(self.parse_value_clause(
                SyntaxKind::EnterpriseClause,
                start,
                end,
                SyntaxKind::is_identifier,
                "enterprise name",
            )),
            SyntaxKind::KwIndex => Some(self.parse_index_clause(start, end)),
            SyntaxKind::KwAugments => {
                Some(self.parse_single_name_braced_clause(SyntaxKind::AugmentsClause, start, end))
            }
            SyntaxKind::KwDefval => Some(self.parse_defval_clause(start, end)),
            SyntaxKind::KwObjects => {
                Some(self.parse_name_list_clause(SyntaxKind::ObjectsClause, start, end))
            }
            SyntaxKind::KwNotifications => {
                Some(self.parse_name_list_clause(SyntaxKind::NotificationsClause, start, end))
            }
            SyntaxKind::KwVariables => {
                Some(self.parse_name_list_clause(SyntaxKind::VariablesClause, start, end))
            }
            _ => None,
        }
    }

    fn parse_syntax_clause(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(syntax_start) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected type syntax after SYNTAX");
            return (self.node(SyntaxKind::SyntaxClause, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, syntax_start);
        if self.is_clause_boundary(syntax_start)
            || self.tokens[syntax_start].kind == SyntaxKind::ColonColonEqual
        {
            self.emit_at(syntax_start, "expected type syntax after SYNTAX");
            return (self.node(SyntaxKind::SyntaxClause, children), syntax_start);
        }
        if let Some((syntax, next)) = self.parse_type_syntax(syntax_start, end) {
            children.push(ElementData::Node(syntax));
            (self.node(SyntaxKind::SyntaxClause, children), next)
        } else {
            self.push_error(&mut children, syntax_start, syntax_start + 1);
            self.emit_at(syntax_start, "expected type syntax after SYNTAX");
            (
                self.node(SyntaxKind::SyntaxClause, children),
                syntax_start + 1,
            )
        }
    }

    fn parse_string_clause(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
    ) -> (NodeData, usize) {
        self.parse_value_clause(
            node_kind,
            start,
            end,
            |kind| kind == SyntaxKind::QuotedString,
            "quoted string",
        )
    }

    fn parse_value_clause(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
        accepts: impl FnOnce(SyntaxKind) -> bool,
        expected: &str,
    ) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(value) = self.next_significant(start + 1, end) else {
            self.emit_at(end, format!("expected {expected}"));
            return (self.node(node_kind, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, value);
        if accepts(self.tokens[value].kind) {
            children.push(self.element(value));
            (self.node(node_kind, children), value + 1)
        } else if self.is_clause_boundary(value)
            || self.tokens[value].kind == SyntaxKind::ColonColonEqual
        {
            self.emit_at(value, format!("expected {expected}"));
            (self.node(node_kind, children), value)
        } else {
            self.push_error(&mut children, value, value + 1);
            self.emit_at(value, format!("expected {expected}"));
            (self.node(node_kind, children), value + 1)
        }
    }

    fn parse_name_list_clause(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
    ) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(open) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected '{'");
            return (self.node(node_kind, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, open);
        if self.tokens[open].kind != SyntaxKind::LBrace {
            self.emit_at(open, "expected '{'");
            if !self.is_clause_boundary(open) {
                self.push_error(&mut children, open, open + 1);
                return (self.node(node_kind, children), open + 1);
            }
            return (self.node(node_kind, children), open);
        }
        children.push(ElementData::Token(self.tokens[open]));
        let mut cursor = open + 1;
        let mut expect_name = true;
        loop {
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                self.emit_at(end, "expected '}'");
                return (self.node(node_kind, children), end);
            };
            self.push_plain(&mut children, cursor, current);
            if self.is_nested_construct_boundary(current, open + 1) {
                self.emit_at(current, "expected '}'");
                return (self.node(node_kind, children), current);
            }
            match self.tokens[current].kind {
                SyntaxKind::RBrace => {
                    children.push(ElementData::Token(self.tokens[current]));
                    return (self.node(node_kind, children), current + 1);
                }
                kind if kind.is_identifier() => {
                    if !expect_name {
                        self.emit_at(current, "expected ','");
                    }
                    children.push(ElementData::Token(self.tokens[current]));
                    expect_name = false;
                }
                SyntaxKind::Comma => {
                    if expect_name {
                        self.emit_at(current, "expected name");
                    }
                    children.push(ElementData::Token(self.tokens[current]));
                    expect_name = true;
                }
                _ => {
                    self.push_error(&mut children, current, current + 1);
                    self.emit_at(current, "expected name, ',' or '}'");
                }
            }
            cursor = current + 1;
        }
    }

    fn parse_single_name_braced_clause(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
    ) -> (NodeData, usize) {
        let (mut node, next) = self.parse_name_list_clause(node_kind, start, end);
        let name_count = node
            .children
            .iter()
            .filter(
                |child| matches!(child, ElementData::Token(token) if token.kind.is_identifier()),
            )
            .count();
        if name_count != 1 {
            self.emit_at(next.min(end), "expected exactly one name");
        }
        // A comma is malformed for a single-name clause even though the shared
        // braced parser retained it losslessly.
        for child in &mut node.children {
            if matches!(child, ElementData::Token(token) if token.kind == SyntaxKind::Comma) {
                // The token is retained; the diagnostic carries the recovery.
                self.emit_at(next.min(end), "unexpected ','");
                break;
            }
        }
        (node, next)
    }

    fn parse_index_clause(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(open) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected '{'");
            return (self.node(SyntaxKind::IndexClause, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, open);
        if self.tokens[open].kind != SyntaxKind::LBrace {
            self.emit_at(open, "expected '{'");
            if !self.is_clause_boundary(open) {
                self.push_error(&mut children, open, open + 1);
                return (self.node(SyntaxKind::IndexClause, children), open + 1);
            }
            return (self.node(SyntaxKind::IndexClause, children), open);
        }
        children.push(ElementData::Token(self.tokens[open]));
        let mut cursor = open + 1;
        loop {
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                self.emit_at(end, "expected '}'");
                return (self.node(SyntaxKind::IndexClause, children), end);
            };
            self.push_plain(&mut children, cursor, current);
            if self.is_nested_construct_boundary(current, open + 1) {
                self.emit_at(current, "expected '}'");
                return (self.node(SyntaxKind::IndexClause, children), current);
            }
            if self.tokens[current].kind == SyntaxKind::RBrace {
                children.push(ElementData::Token(self.tokens[current]));
                return (self.node(SyntaxKind::IndexClause, children), current + 1);
            }
            if self.tokens[current].kind == SyntaxKind::Comma {
                children.push(ElementData::Token(self.tokens[current]));
                cursor = current + 1;
                continue;
            }
            let (item, next) = self.parse_index_item(current, end);
            children.push(ElementData::Node(item));
            cursor = next;
        }
    }

    fn parse_index_item(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = Vec::new();
        let mut cursor = start;
        if self.tokens[cursor].kind == SyntaxKind::KwImplied {
            children.push(ElementData::Token(self.tokens[cursor]));
            let Some(name) = self.next_significant(cursor + 1, end) else {
                self.emit_at(end, "expected index object after IMPLIED");
                return (self.node(SyntaxKind::IndexItem, children), cursor + 1);
            };
            self.push_plain(&mut children, cursor + 1, name);
            if self.tokens[name].kind == SyntaxKind::RBrace {
                self.emit_at(name, "expected index object after IMPLIED");
                return (self.node(SyntaxKind::IndexItem, children), name);
            }
            cursor = name;
        }
        if self.tokens[cursor].kind.is_identifier()
            || self.tokens[cursor].kind == SyntaxKind::KwOctet
        {
            children.push(ElementData::Token(self.tokens[cursor]));
            let mut next = cursor + 1;
            if self.tokens[cursor].kind == SyntaxKind::KwOctet
                && let Some(string) = self.next_significant(next, end)
                && self.tokens[string].kind == SyntaxKind::KwString
            {
                self.push_plain(&mut children, next, string + 1);
                next = string + 1;
            }
            (self.node(SyntaxKind::IndexItem, children), next)
        } else {
            self.push_error(&mut children, cursor, cursor + 1);
            self.emit_at(cursor, "expected index object");
            (self.node(SyntaxKind::IndexItem, children), cursor + 1)
        }
    }

    fn parse_defval_clause(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(open) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected DEFVAL content");
            return (self.node(SyntaxKind::DefvalClause, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, open);
        if self.tokens[open].kind != SyntaxKind::LBrace {
            self.emit_at(open, "expected '{' after DEFVAL");
            if !self.is_clause_boundary(open) {
                self.push_error(&mut children, open, open + 1);
                return (self.node(SyntaxKind::DefvalClause, children), open + 1);
            }
            return (self.node(SyntaxKind::DefvalClause, children), open);
        }

        let (content, next) = self.parse_balanced_content(SyntaxKind::DefvalContent, open, end);
        children.push(ElementData::Node(content));
        (self.node(SyntaxKind::DefvalClause, children), next)
    }

    fn parse_balanced_content(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
    ) -> (NodeData, usize) {
        if let Some(close) = self.matching_rbrace(start, end) {
            return (
                self.node(node_kind, self.elements(start, close + 1)),
                close + 1,
            );
        }

        let mut depth = 0usize;
        for index in start..end {
            if depth == 1 && index != start && self.is_nested_construct_boundary(index, start + 1) {
                self.emit_at(index, "expected '}'");
                return (self.node(node_kind, self.elements(start, index)), index);
            }
            match self.tokens[index].kind {
                SyntaxKind::LBrace => depth += 1,
                SyntaxKind::RBrace => {
                    depth -= 1;
                    if depth == 0 {
                        return (
                            self.node(node_kind, self.elements(start, index + 1)),
                            index + 1,
                        );
                    }
                }
                _ => {}
            }
        }
        self.emit_at(end, "expected '}'");
        (self.node(node_kind, self.elements(start, end)), end)
    }

    fn matching_rbrace(&self, start: usize, end: usize) -> Option<usize> {
        let mut depth = 0usize;
        for index in start..end {
            match self.tokens[index].kind {
                SyntaxKind::LBrace => depth += 1,
                SyntaxKind::RBrace => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn parse_oid_assignment(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let mut cursor = start + 1;
        loop {
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                self.emit_at(end, "expected '}' in OID assignment");
                return (self.node(SyntaxKind::OidAssignment, children), end);
            };
            self.push_plain(&mut children, cursor, current);
            if self.is_clause_boundary(current) && self.starts_source_line(current, start + 1) {
                self.emit_at(current, "expected '}' in OID assignment");
                return (self.node(SyntaxKind::OidAssignment, children), current);
            }
            if self.tokens[current].kind == SyntaxKind::RBrace {
                children.push(ElementData::Token(self.tokens[current]));
                return (self.node(SyntaxKind::OidAssignment, children), current + 1);
            }
            if self.tokens[current].kind == SyntaxKind::Comma {
                children.push(ElementData::Token(self.tokens[current]));
                self.emit_at(current, "unexpected ',' in OID assignment");
                cursor = current + 1;
                continue;
            }
            let (component, next) = self.parse_oid_component(current, end);
            children.push(ElementData::Node(component));
            cursor = next;
        }
    }

    fn parse_oid_component(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = Vec::new();
        let kind = self.tokens[start].kind;
        if kind == SyntaxKind::Number {
            children.push(ElementData::Token(self.tokens[start]));
            return (self.node(SyntaxKind::OidComponent, children), start + 1);
        }
        if !kind.is_identifier() {
            self.push_error(&mut children, start, start + 1);
            self.emit_at(start, "expected OID component");
            return (self.node(SyntaxKind::OidComponent, children), start + 1);
        }
        children.push(ElementData::Token(self.tokens[start]));
        let mut cursor = start + 1;

        if kind == SyntaxKind::UppercaseIdent
            && let Some(dot) = self.next_significant(cursor, end)
            && self.tokens[dot].kind == SyntaxKind::Dot
        {
            self.push_plain(&mut children, cursor, dot + 1);
            let Some(name) = self.next_significant(dot + 1, end) else {
                self.emit_at(end, "expected name after '.'");
                return (self.node(SyntaxKind::OidComponent, children), dot + 1);
            };
            self.push_plain(&mut children, dot + 1, name);
            if self.tokens[name].kind.is_identifier() {
                children.push(ElementData::Token(self.tokens[name]));
            } else if self.tokens[name].kind == SyntaxKind::RBrace {
                self.emit_at(name, "expected name after '.'");
                return (self.node(SyntaxKind::OidComponent, children), name);
            } else {
                self.push_error(&mut children, name, name + 1);
                self.emit_at(name, "expected name after '.'");
                return (self.node(SyntaxKind::OidComponent, children), name + 1);
            }
            cursor = name + 1;
        }

        if let Some(open) = self.next_significant(cursor, end)
            && self.tokens[open].kind == SyntaxKind::LParen
        {
            self.push_plain(&mut children, cursor, open + 1);
            let Some(number) = self.next_significant(open + 1, end) else {
                self.emit_at(end, "expected OID component number");
                return (self.node(SyntaxKind::OidComponent, children), open + 1);
            };
            self.push_plain(&mut children, open + 1, number);
            if self.tokens[number].kind == SyntaxKind::Number {
                children.push(ElementData::Token(self.tokens[number]));
            } else if self.tokens[number].kind == SyntaxKind::RParen {
                self.emit_at(number, "expected OID component number");
                children.push(ElementData::Token(self.tokens[number]));
                return (self.node(SyntaxKind::OidComponent, children), number + 1);
            } else {
                self.push_error(&mut children, number, number + 1);
                self.emit_at(number, "expected OID component number");
                return (self.node(SyntaxKind::OidComponent, children), number + 1);
            }
            let Some(close) = self.next_significant(number + 1, end) else {
                self.emit_at(end, "expected ')' after OID component number");
                return (self.node(SyntaxKind::OidComponent, children), number + 1);
            };
            self.push_plain(&mut children, number + 1, close);
            if self.tokens[close].kind == SyntaxKind::RParen {
                children.push(ElementData::Token(self.tokens[close]));
                cursor = close + 1;
            } else {
                self.emit_at(close, "expected ')' after OID component number");
                cursor = close;
            }
        }
        (self.node(SyntaxKind::OidComponent, children), cursor)
    }

    fn parse_type_syntax(&mut self, start: usize, end: usize) -> Option<(NodeData, usize)> {
        let kind = self.tokens[start].kind;
        let (base, mut next) = match kind {
            SyntaxKind::KwInteger => self.parse_integer_or_bits(
                SyntaxKind::IntegerEnumSyntax,
                SyntaxKind::TypeRefSyntax,
                start,
                end,
            ),
            SyntaxKind::KwBits => self.parse_integer_or_bits(
                SyntaxKind::BitsSyntax,
                SyntaxKind::TypeRefSyntax,
                start,
                end,
            ),
            SyntaxKind::KwOctet => self.parse_two_word_type(
                SyntaxKind::OctetStringSyntax,
                start,
                end,
                SyntaxKind::KwString,
            ),
            SyntaxKind::KwObject => self.parse_two_word_type(
                SyntaxKind::ObjectIdentifierSyntax,
                start,
                end,
                SyntaxKind::KwIdentifier,
            ),
            SyntaxKind::KwSequence => self.parse_sequence(start, end),
            SyntaxKind::KwChoice => self.parse_fields_type(SyntaxKind::ChoiceSyntax, start, end),
            SyntaxKind::LBracket => self.parse_tagged(start, end),
            kind if is_type_reference(kind) => {
                if self
                    .next_significant(start + 1, end)
                    .is_some_and(|next| self.tokens[next].kind == SyntaxKind::LBrace)
                {
                    self.parse_integer_or_bits(
                        SyntaxKind::IntegerEnumSyntax,
                        SyntaxKind::TypeRefSyntax,
                        start,
                        end,
                    )
                } else {
                    let node = self.node(
                        SyntaxKind::TypeRefSyntax,
                        vec![ElementData::Token(self.tokens[start])],
                    );
                    (node, start + 1)
                }
            }
            _ => return None,
        };

        if let Some(open) = self.next_significant(next, end)
            && self.tokens[open].kind == SyntaxKind::LParen
        {
            let mut children = vec![ElementData::Node(base)];
            self.push_plain(&mut children, next, open);
            let (constraint, constraint_end) = self.parse_constraint(open, end);
            children.push(ElementData::Node(constraint));
            next = constraint_end;
            return Some((self.node(SyntaxKind::ConstrainedSyntax, children), next));
        }
        Some((base, next))
    }

    fn parse_integer_or_bits(
        &mut self,
        enum_kind: SyntaxKind,
        plain_kind: SyntaxKind,
        start: usize,
        end: usize,
    ) -> (NodeData, usize) {
        let Some(open) = self.next_significant(start + 1, end) else {
            return (
                self.node(plain_kind, vec![ElementData::Token(self.tokens[start])]),
                start + 1,
            );
        };
        if self.tokens[open].kind != SyntaxKind::LBrace {
            return (
                self.node(plain_kind, vec![ElementData::Token(self.tokens[start])]),
                start + 1,
            );
        }
        let mut children = vec![ElementData::Token(self.tokens[start])];
        self.push_plain(&mut children, start + 1, open + 1);
        let mut cursor = open + 1;
        loop {
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                self.emit_at(end, "expected '}' after named numbers");
                return (self.node(enum_kind, children), end);
            };
            self.push_plain(&mut children, cursor, current);
            if self.is_nested_construct_boundary(current, open + 1) {
                self.emit_at(current, "expected '}' after named numbers");
                return (self.node(enum_kind, children), current);
            }
            if self.tokens[current].kind == SyntaxKind::RBrace {
                children.push(ElementData::Token(self.tokens[current]));
                return (self.node(enum_kind, children), current + 1);
            }
            if self.tokens[current].kind == SyntaxKind::Comma {
                children.push(ElementData::Token(self.tokens[current]));
                cursor = current + 1;
                continue;
            }
            let (number, next) = self.parse_named_number(current, end);
            children.push(ElementData::Node(number));
            cursor = next;
        }
    }

    fn parse_named_number(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = Vec::new();
        if !is_enum_label(self.tokens[start].kind) {
            self.push_error(&mut children, start, start + 1);
            self.emit_at(start, "expected named-number label");
            return (self.node(SyntaxKind::NamedNumber, children), start + 1);
        }
        children.push(ElementData::Token(self.tokens[start]));
        let Some(open) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected '(' after named-number label");
            return (self.node(SyntaxKind::NamedNumber, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, open);
        if self.tokens[open].kind != SyntaxKind::LParen {
            self.emit_at(open, "expected '(' after named-number label");
            return (self.node(SyntaxKind::NamedNumber, children), open);
        }
        children.push(ElementData::Token(self.tokens[open]));
        let Some(value) = self.next_significant(open + 1, end) else {
            self.emit_at(end, "expected named-number value");
            return (self.node(SyntaxKind::NamedNumber, children), open + 1);
        };
        self.push_plain(&mut children, open + 1, value);
        if matches!(
            self.tokens[value].kind,
            SyntaxKind::Number | SyntaxKind::NegativeNumber
        ) {
            children.push(ElementData::Token(self.tokens[value]));
        } else if self.tokens[value].kind == SyntaxKind::RParen {
            self.emit_at(value, "expected named-number value");
            children.push(ElementData::Token(self.tokens[value]));
            return (self.node(SyntaxKind::NamedNumber, children), value + 1);
        } else {
            self.push_error(&mut children, value, value + 1);
            self.emit_at(value, "expected named-number value");
            return (self.node(SyntaxKind::NamedNumber, children), value + 1);
        }
        let Some(close) = self.next_significant(value + 1, end) else {
            self.emit_at(end, "expected ')' after named-number value");
            return (self.node(SyntaxKind::NamedNumber, children), value + 1);
        };
        self.push_plain(&mut children, value + 1, close);
        if self.tokens[close].kind == SyntaxKind::RParen {
            children.push(ElementData::Token(self.tokens[close]));
            (self.node(SyntaxKind::NamedNumber, children), close + 1)
        } else {
            self.emit_at(close, "expected ')' after named-number value");
            (self.node(SyntaxKind::NamedNumber, children), close)
        }
    }

    fn parse_two_word_type(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
        expected: SyntaxKind,
    ) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(second) = self.next_significant(start + 1, end) else {
            self.emit_at(end, format!("expected {}", expected.display_name()));
            return (self.node(node_kind, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, second);
        if self.tokens[second].kind == expected {
            children.push(ElementData::Token(self.tokens[second]));
            (self.node(node_kind, children), second + 1)
        } else {
            self.emit_at(second, format!("expected {}", expected.display_name()));
            (self.node(node_kind, children), second)
        }
    }

    fn parse_sequence(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let Some(next) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected OF or '{' after SEQUENCE");
            return (
                self.node(
                    SyntaxKind::SequenceSyntax,
                    vec![ElementData::Token(self.tokens[start])],
                ),
                start + 1,
            );
        };
        if self.tokens[next].kind != SyntaxKind::KwOf {
            return self.parse_fields_type(SyntaxKind::SequenceSyntax, start, end);
        }
        let mut children = vec![ElementData::Token(self.tokens[start])];
        self.push_plain(&mut children, start + 1, next + 1);
        let Some(entry) = self.next_significant(next + 1, end) else {
            self.emit_at(end, "expected entry type after SEQUENCE OF");
            return (self.node(SyntaxKind::SequenceOfSyntax, children), next + 1);
        };
        self.push_plain(&mut children, next + 1, entry);
        if is_type_reference(self.tokens[entry].kind) {
            children.push(ElementData::Token(self.tokens[entry]));
            (self.node(SyntaxKind::SequenceOfSyntax, children), entry + 1)
        } else if self.is_clause_boundary(entry)
            || self.tokens[entry].kind == SyntaxKind::ColonColonEqual
        {
            self.emit_at(entry, "expected entry type after SEQUENCE OF");
            (self.node(SyntaxKind::SequenceOfSyntax, children), entry)
        } else {
            self.push_error(&mut children, entry, entry + 1);
            self.emit_at(entry, "expected entry type after SEQUENCE OF");
            (self.node(SyntaxKind::SequenceOfSyntax, children), entry + 1)
        }
    }

    fn parse_fields_type(
        &mut self,
        node_kind: SyntaxKind,
        start: usize,
        end: usize,
    ) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let Some(open) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected '{'");
            return (self.node(node_kind, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, open);
        if self.tokens[open].kind != SyntaxKind::LBrace {
            self.emit_at(open, "expected '{'");
            return (self.node(node_kind, children), open);
        }
        children.push(ElementData::Token(self.tokens[open]));
        let mut cursor = open + 1;
        loop {
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                self.emit_at(end, "expected '}'");
                return (self.node(node_kind, children), end);
            };
            self.push_plain(&mut children, cursor, current);
            if self.is_nested_construct_boundary(current, open + 1) {
                self.emit_at(current, "expected '}'");
                return (self.node(node_kind, children), current);
            }
            if self.tokens[current].kind == SyntaxKind::RBrace {
                children.push(ElementData::Token(self.tokens[current]));
                return (self.node(node_kind, children), current + 1);
            }
            if self.tokens[current].kind == SyntaxKind::Comma {
                children.push(ElementData::Token(self.tokens[current]));
                cursor = current + 1;
                continue;
            }
            let (field, next) = self.parse_sequence_field(current, end);
            children.push(ElementData::Node(field));
            cursor = next;
        }
    }

    fn parse_sequence_field(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = Vec::new();
        if !self.tokens[start].kind.is_identifier() {
            self.push_error(&mut children, start, start + 1);
            self.emit_at(start, "expected field name");
            return (self.node(SyntaxKind::SequenceField, children), start + 1);
        }
        children.push(ElementData::Token(self.tokens[start]));
        let Some(syntax_start) = self.next_significant(start + 1, end) else {
            self.emit_at(end, "expected field type");
            return (self.node(SyntaxKind::SequenceField, children), start + 1);
        };
        self.push_plain(&mut children, start + 1, syntax_start);
        if let Some((syntax, next)) = self.parse_type_syntax(syntax_start, end) {
            children.push(ElementData::Node(syntax));
            (self.node(SyntaxKind::SequenceField, children), next)
        } else if self.tokens[syntax_start].kind == SyntaxKind::Comma
            || self.tokens[syntax_start].kind == SyntaxKind::RBrace
        {
            self.emit_at(syntax_start, "expected field type");
            (self.node(SyntaxKind::SequenceField, children), syntax_start)
        } else {
            self.push_error(&mut children, syntax_start, syntax_start + 1);
            self.emit_at(syntax_start, "expected field type");
            (
                self.node(SyntaxKind::SequenceField, children),
                syntax_start + 1,
            )
        }
    }

    fn parse_tagged(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let mut cursor = start + 1;
        if let Some(class) = self.next_significant(cursor, end)
            && matches!(
                self.tokens[class].kind,
                SyntaxKind::KwApplication | SyntaxKind::KwUniversal
            )
        {
            self.push_plain(&mut children, cursor, class + 1);
            cursor = class + 1;
        }
        if let Some(number) = self.next_significant(cursor, end)
            && self.tokens[number].kind == SyntaxKind::Number
        {
            self.push_plain(&mut children, cursor, number + 1);
            cursor = number + 1;
        } else {
            self.emit_at(cursor.min(end), "expected tag number");
        }
        let Some(close) = self.next_significant(cursor, end) else {
            self.push_plain(&mut children, cursor, end);
            self.emit_at(end, "expected ']'");
            return (self.node(SyntaxKind::TaggedSyntax, children), end);
        };
        self.push_plain(&mut children, cursor, close);
        if self.tokens[close].kind == SyntaxKind::RBracket {
            children.push(ElementData::Token(self.tokens[close]));
            cursor = close + 1;
        } else {
            self.emit_at(close, "expected ']'");
            return (self.node(SyntaxKind::TaggedSyntax, children), close);
        }
        if let Some(implicit) = self.next_significant(cursor, end)
            && self.tokens[implicit].kind == SyntaxKind::KwImplicit
        {
            self.push_plain(&mut children, cursor, implicit + 1);
            cursor = implicit + 1;
        }
        let Some(inner) = self.next_significant(cursor, end) else {
            self.push_plain(&mut children, cursor, end);
            self.emit_at(end, "expected tagged type");
            return (self.node(SyntaxKind::TaggedSyntax, children), end);
        };
        self.push_plain(&mut children, cursor, inner);
        if let Some((syntax, next)) = self.parse_type_syntax(inner, end) {
            children.push(ElementData::Node(syntax));
            (self.node(SyntaxKind::TaggedSyntax, children), next)
        } else if self.is_clause_boundary(inner)
            || self.tokens[inner].kind == SyntaxKind::ColonColonEqual
        {
            self.emit_at(inner, "expected tagged type");
            (self.node(SyntaxKind::TaggedSyntax, children), inner)
        } else {
            self.push_error(&mut children, inner, inner + 1);
            self.emit_at(inner, "expected tagged type");
            (self.node(SyntaxKind::TaggedSyntax, children), inner + 1)
        }
    }

    fn parse_constraint(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = vec![ElementData::Token(self.tokens[start])];
        let mut cursor = start + 1;
        let mut size = false;
        if let Some(current) = self.next_significant(cursor, end)
            && self.tokens[current].kind == SyntaxKind::KwSize
        {
            self.push_plain(&mut children, cursor, current + 1);
            cursor = current + 1;
            size = true;
            if let Some(inner) = self.next_significant(cursor, end)
                && self.tokens[inner].kind == SyntaxKind::LParen
            {
                self.push_plain(&mut children, cursor, inner + 1);
                cursor = inner + 1;
            } else {
                self.emit_at(cursor.min(end), "expected '(' after SIZE");
            }
        }
        loop {
            let Some(current) = self.next_significant(cursor, end) else {
                self.push_plain(&mut children, cursor, end);
                self.emit_at(end, "expected ')' in constraint");
                return (self.node(SyntaxKind::Constraint, children), end);
            };
            self.push_plain(&mut children, cursor, current);
            if self.is_nested_construct_boundary(current, start + 1) {
                self.emit_at(current, "expected ')' in constraint");
                return (self.node(SyntaxKind::Constraint, children), current);
            }
            if self.tokens[current].kind == SyntaxKind::RParen {
                children.push(ElementData::Token(self.tokens[current]));
                cursor = current + 1;
                if size {
                    let Some(outer) = self.next_significant(cursor, end) else {
                        self.emit_at(end, "expected outer ')' after SIZE constraint");
                        return (self.node(SyntaxKind::Constraint, children), cursor);
                    };
                    self.push_plain(&mut children, cursor, outer);
                    if self.tokens[outer].kind == SyntaxKind::RParen {
                        children.push(ElementData::Token(self.tokens[outer]));
                        cursor = outer + 1;
                    } else {
                        self.emit_at(outer, "expected outer ')' after SIZE constraint");
                        cursor = outer;
                    }
                }
                return (self.node(SyntaxKind::Constraint, children), cursor);
            }
            if self.tokens[current].kind == SyntaxKind::Pipe {
                children.push(ElementData::Token(self.tokens[current]));
                cursor = current + 1;
                continue;
            }
            let (range, next) = self.parse_range(current, end);
            children.push(ElementData::Node(range));
            cursor = next;
        }
    }

    fn parse_range(&mut self, start: usize, end: usize) -> (NodeData, usize) {
        let mut children = Vec::new();
        if !is_range_value(self.tokens[start].kind) {
            self.push_error(&mut children, start, start + 1);
            self.emit_at(start, "expected constraint value");
            return (self.node(SyntaxKind::Range, children), start + 1);
        }
        children.push(ElementData::Token(self.tokens[start]));
        let mut cursor = start + 1;
        if let Some(dotdot) = self.next_significant(cursor, end)
            && self.tokens[dotdot].kind == SyntaxKind::DotDot
        {
            self.push_plain(&mut children, cursor, dotdot + 1);
            let Some(max) = self.next_significant(dotdot + 1, end) else {
                self.emit_at(end, "expected upper constraint value");
                return (self.node(SyntaxKind::Range, children), dotdot + 1);
            };
            self.push_plain(&mut children, dotdot + 1, max);
            if is_range_value(self.tokens[max].kind) {
                children.push(ElementData::Token(self.tokens[max]));
                cursor = max + 1;
            } else if matches!(self.tokens[max].kind, SyntaxKind::Pipe | SyntaxKind::RParen) {
                self.emit_at(max, "expected upper constraint value");
                cursor = max;
            } else {
                self.push_error(&mut children, max, max + 1);
                self.emit_at(max, "expected upper constraint value");
                cursor = max + 1;
            }
        }
        (self.node(SyntaxKind::Range, children), cursor)
    }

    fn is_type_context(
        &self,
        index: usize,
        start: usize,
        end: usize,
        current_definition: Option<usize>,
        current_assignment: Option<usize>,
    ) -> bool {
        if !is_type_start(self.tokens[index].kind) {
            return false;
        }
        let previous = self.previous_significant(index, start);
        if let Some(previous) = previous {
            if matches!(
                self.tokens[previous].kind,
                SyntaxKind::KwSyntax | SyntaxKind::KwWriteSyntax
            ) {
                return true;
            }
            if self.tokens[previous].kind == SyntaxKind::ColonColonEqual {
                return self.assignment_introduces_type(
                    previous,
                    current_definition,
                    current_assignment,
                );
            }
        }
        previous.is_some_and(|previous| {
            current_definition.is_some_and(|definition| previous >= definition)
                && self.tokens[previous].kind.is_identifier()
        }) && self.has_assignment_ahead(index, end)
    }

    fn has_assignment_ahead(&self, start: usize, end: usize) -> bool {
        let mut delimiters = Vec::new();
        let mut cursor = start;
        while let Some(current) = self.next_significant(cursor, end) {
            match self.tokens[current].kind {
                SyntaxKind::LParen => delimiters.push(SyntaxKind::RParen),
                SyntaxKind::LBracket => delimiters.push(SyntaxKind::RBracket),
                SyntaxKind::LBrace => delimiters.push(SyntaxKind::RBrace),
                kind @ (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace) => {
                    if delimiters.pop() != Some(kind) {
                        return false;
                    }
                }
                SyntaxKind::ColonColonEqual if delimiters.is_empty() => return true,
                kind if delimiters.is_empty() && self.is_clause_boundary_kind(kind) => {
                    return false;
                }
                SyntaxKind::KwEnd if delimiters.is_empty() => return false,
                _ => {}
            }
            cursor = current + 1;
        }
        false
    }

    fn is_clause_boundary(&self, index: usize) -> bool {
        self.is_clause_boundary_kind(self.tokens[index].kind)
    }

    fn is_clause_boundary_kind(&self, kind: SyntaxKind) -> bool {
        matches!(
            kind,
            SyntaxKind::KwSyntax
                | SyntaxKind::KwMaxAccess
                | SyntaxKind::KwMinAccess
                | SyntaxKind::KwAccess
                | SyntaxKind::KwStatus
                | SyntaxKind::KwDescription
                | SyntaxKind::KwReference
                | SyntaxKind::KwIndex
                | SyntaxKind::KwDefval
                | SyntaxKind::KwAugments
                | SyntaxKind::KwUnits
                | SyntaxKind::KwDisplayHint
                | SyntaxKind::KwObjects
                | SyntaxKind::KwNotifications
                | SyntaxKind::KwRevision
                | SyntaxKind::KwLastUpdated
                | SyntaxKind::KwOrganization
                | SyntaxKind::KwContactInfo
                | SyntaxKind::KwEnterprise
                | SyntaxKind::KwVariables
                | SyntaxKind::KwProductRelease
        )
    }

    fn is_nested_construct_boundary(&self, index: usize, lower_bound: usize) -> bool {
        self.tokens[index].kind == SyntaxKind::ColonColonEqual
            || (self.is_clause_boundary(index) && self.starts_source_line(index, lower_bound))
    }

    fn next_significant(&self, from: usize, end: usize) -> Option<usize> {
        (from..end).find(|&index| !self.tokens[index].kind.is_trivia())
    }

    fn previous_significant(&self, before: usize, start: usize) -> Option<usize> {
        (start..before)
            .rev()
            .find(|&index| !self.tokens[index].kind.is_trivia())
    }

    fn collect_definition_starts(&self, start: usize, end: usize) -> Vec<usize> {
        let mut definitions = Vec::new();
        let matched_closes = self.collect_matched_delimiter_closes(start, end);
        let Some(first) = self.next_significant(start, end) else {
            return definitions;
        };
        let mut unmatched_delimiters = Vec::new();
        let mut previous = None;
        let mut current = first;
        loop {
            record_definition_context_work(1);
            let starts_line = previous.is_none_or(|previous| {
                self.tokens[previous + 1..current].iter().any(|token| {
                    token.kind.is_trivia()
                        && self
                            .document
                            .slice(token.range)
                            .expect("CST token belongs to retained document")
                            .iter()
                            .any(|byte| matches!(byte, b'\n' | b'\r'))
                })
            });
            if starts_line {
                let looks_like_definition = self.looks_like_definition(current, end);
                if unmatched_delimiters.is_empty() && looks_like_definition {
                    definitions.push(current);
                } else if !unmatched_delimiters.is_empty()
                    && looks_like_definition
                    && self.starts_unindented_source_line(current)
                {
                    unmatched_delimiters.clear();
                    definitions.push(current);
                }
            }

            let kind = self.tokens[current].kind;
            if matches!(
                kind,
                SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace
            ) {
                if let Some(close) = matched_closes[current - start] {
                    previous = Some(close);
                    let Some(next) = self.next_significant(close + 1, end) else {
                        break;
                    };
                    current = next;
                    continue;
                }
                unmatched_delimiters.push(match kind {
                    SyntaxKind::LParen => SyntaxKind::RParen,
                    SyntaxKind::LBracket => SyntaxKind::RBracket,
                    SyntaxKind::LBrace => SyntaxKind::RBrace,
                    _ => unreachable!(),
                });
            } else if matches!(
                kind,
                SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace
            ) {
                if unmatched_delimiters.last() == Some(&kind) {
                    unmatched_delimiters.pop();
                } else {
                    unmatched_delimiters.clear();
                }
            }
            previous = Some(current);
            let Some(next) = self.next_significant(current + 1, end) else {
                break;
            };
            current = next;
        }
        definitions
    }

    fn collect_matched_delimiter_closes(&self, start: usize, end: usize) -> Vec<Option<usize>> {
        let mut closes = vec![None; end - start];
        let mut delimiters = Vec::new();
        let mut cursor = start;
        while let Some(current) = self.next_significant(cursor, end) {
            record_definition_context_work(1);
            let kind = self.tokens[current].kind;
            match kind {
                SyntaxKind::LParen => delimiters.push((current, SyntaxKind::RParen)),
                SyntaxKind::LBracket => delimiters.push((current, SyntaxKind::RBracket)),
                SyntaxKind::LBrace => delimiters.push((current, SyntaxKind::RBrace)),
                SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace => {
                    if let Some(&(open, expected)) = delimiters.last()
                        && expected == kind
                    {
                        delimiters.pop();
                        closes[open - start] = Some(current);
                    } else {
                        delimiters.clear();
                    }
                }
                _ => {}
            }
            cursor = current + 1;
        }
        closes
    }

    fn starts_unindented_source_line(&self, index: usize) -> bool {
        let offset = self.tokens[index].range.byte_range().start;
        self.document.bytes()[..offset]
            .iter()
            .rposition(|byte| matches!(byte, b'\n' | b'\r'))
            .is_some_and(|newline| newline + 1 == offset)
    }

    fn assignment_introduces_type(
        &self,
        assignment: usize,
        current_definition: Option<usize>,
        current_assignment: Option<usize>,
    ) -> bool {
        record_definition_context_work(1);
        current_assignment == Some(assignment)
            && current_definition.is_some_and(|definition| {
                self.next_significant(definition + 1, assignment + 1) == Some(assignment)
            })
    }

    fn is_oid_assignment_context(
        &self,
        assignment: usize,
        current_definition: Option<usize>,
        current_assignment: Option<usize>,
    ) -> bool {
        record_definition_context_work(1);
        if current_assignment != Some(assignment) {
            return false;
        }
        let Some(definition) = current_definition else {
            return false;
        };
        let Some(second) = self.next_significant(definition + 1, assignment) else {
            return false;
        };
        let second_kind = self.tokens[second].kind;
        if second_kind == SyntaxKind::KwObject {
            return true;
        }
        second_kind.is_macro_keyword()
            && !matches!(
                second_kind,
                SyntaxKind::KwTextualConvention | SyntaxKind::KwTrapType
            )
    }

    fn starts_source_line(&self, index: usize, lower_bound: usize) -> bool {
        let trivia_start = self
            .previous_significant(index, lower_bound)
            .map_or(lower_bound, |previous| previous + 1);
        self.tokens[trivia_start..index].iter().any(|token| {
            token.kind.is_trivia()
                && self
                    .document
                    .slice(token.range)
                    .expect("CST token belongs to retained document")
                    .iter()
                    .any(|byte| matches!(byte, b'\n' | b'\r'))
        })
    }

    fn looks_like_definition(&self, index: usize, end: usize) -> bool {
        record_definition_context_work(1);
        let first = self.tokens[index].kind;
        if !first.is_identifier() && !first.is_macro_keyword() && !first.is_type_keyword() {
            return false;
        }
        let Some(second) = self.next_significant(index + 1, end) else {
            return first == SyntaxKind::UppercaseIdent || first.is_type_keyword();
        };
        let second_kind = self.tokens[second].kind;
        if first.is_macro_keyword() {
            return second_kind == SyntaxKind::KwMacro;
        }
        if first.is_type_keyword() {
            return matches!(
                second_kind,
                SyntaxKind::KwMacro | SyntaxKind::ColonColonEqual
            ) || is_type_start(second_kind);
        }
        if second_kind == SyntaxKind::KwMacro {
            return true;
        }
        if second_kind.is_macro_keyword() {
            return true;
        }
        if first == SyntaxKind::UppercaseIdent && is_type_start(second_kind) {
            return true;
        }
        if first.is_identifier() && second_kind == SyntaxKind::KwObject {
            return true;
        }
        if self.is_clause_boundary_kind(second_kind) {
            return false;
        }

        let mut delimiters = Vec::new();
        let mut cursor = second;
        for _ in 0..256 {
            record_definition_context_work(1);
            if cursor != second
                && delimiters.is_empty()
                && self.starts_unindented_source_line(cursor)
                && (self.tokens[cursor].kind.is_identifier()
                    || self.tokens[cursor].kind.is_type_keyword()
                    || self.tokens[cursor].kind.is_macro_keyword())
            {
                return false;
            }
            let kind = self.tokens[cursor].kind;
            match kind {
                SyntaxKind::LParen => delimiters.push(SyntaxKind::RParen),
                SyntaxKind::LBracket => delimiters.push(SyntaxKind::RBracket),
                SyntaxKind::LBrace => delimiters.push(SyntaxKind::RBrace),
                kind @ (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace) => {
                    if delimiters.pop() != Some(kind) {
                        return false;
                    }
                }
                SyntaxKind::ColonColonEqual if delimiters.is_empty() => return true,
                SyntaxKind::Semicolon
                | SyntaxKind::KwEnd
                | SyntaxKind::KwImports
                | SyntaxKind::KwExports
                    if delimiters.is_empty() =>
                {
                    return false;
                }
                _ => {}
            }
            let Some(next) = self.next_significant(cursor + 1, end) else {
                return false;
            };
            cursor = next;
        }
        false
    }

    fn push_plain(&self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        children.extend(self.elements(start, end));
    }

    fn push_error(&self, children: &mut Vec<ElementData>, start: usize, end: usize) {
        let recovered = self.tokens[start..end]
            .iter()
            .copied()
            .map(ElementData::Token)
            .collect();
        children.push(ElementData::Node(self.node(SyntaxKind::Error, recovered)));
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

    fn element(&self, index: usize) -> ElementData {
        let token = self.tokens[index];
        if token.kind == SyntaxKind::ErrorToken {
            ElementData::Node(self.node(SyntaxKind::Error, vec![ElementData::Token(token)]))
        } else {
            ElementData::Token(token)
        }
    }

    fn node(&self, kind: SyntaxKind, children: Vec<ElementData>) -> NodeData {
        let first = element_range(children.first().expect("CST nodes are never empty"));
        let last = element_range(children.last().expect("CST nodes are never empty"));
        let range = SourceRange::cover(first, last).expect("CST children are source ordered");
        NodeData {
            kind,
            range,
            children: children.into_boxed_slice(),
        }
    }

    fn emit_at(&mut self, index: usize, message: impl Into<String>) {
        self.parse_errors += 1;
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

fn element_range(element: &ElementData) -> SourceRange {
    match element {
        ElementData::Node(node) => node.range,
        ElementData::Token(token) => token.range,
    }
}

fn is_type_start(kind: SyntaxKind) -> bool {
    is_type_reference(kind)
        || matches!(
            kind,
            SyntaxKind::KwSequence
                | SyntaxKind::KwChoice
                | SyntaxKind::LBracket
                | SyntaxKind::KwOctet
                | SyntaxKind::KwObject
        )
}

fn is_type_reference(kind: SyntaxKind) -> bool {
    kind.is_identifier() || kind.is_type_keyword() || matches!(kind, SyntaxKind::ForbiddenKeyword)
}

fn is_enum_label(kind: SyntaxKind) -> bool {
    kind.is_identifier() || kind.is_status_access_keyword()
}

fn is_range_value(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Number
            | SyntaxKind::NegativeNumber
            | SyntaxKind::HexString
            | SyntaxKind::UppercaseIdent
            | SyntaxKind::ForbiddenKeyword
    )
}

fn is_access_value(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::KwReadOnly
            | SyntaxKind::KwReadWrite
            | SyntaxKind::KwReadCreate
            | SyntaxKind::KwNotAccessible
            | SyntaxKind::KwAccessibleForNotify
            | SyntaxKind::KwWriteOnly
            | SyntaxKind::KwNotImplemented
    )
}

fn is_status_value(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::KwCurrent
            | SyntaxKind::KwDeprecated
            | SyntaxKind::KwObsolete
            | SyntaxKind::KwMandatory
            | SyntaxKind::KwOptional
    )
}

const TYPE_SYNTAX_KINDS: &[SyntaxKind] = &[
    SyntaxKind::TypeRefSyntax,
    SyntaxKind::IntegerEnumSyntax,
    SyntaxKind::BitsSyntax,
    SyntaxKind::ConstrainedSyntax,
    SyntaxKind::SequenceOfSyntax,
    SyntaxKind::SequenceSyntax,
    SyntaxKind::ChoiceSyntax,
    SyntaxKind::TaggedSyntax,
    SyntaxKind::OctetStringSyntax,
    SyntaxKind::ObjectIdentifierSyntax,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefinitionPart {
    Token(SyntaxKind),
    Node(SyntaxKind),
}

fn definition_parts(definition: &NodeData) -> Vec<DefinitionPart> {
    definition
        .children
        .iter()
        .filter_map(|element| match element {
            ElementData::Node(node) => Some(DefinitionPart::Node(node.kind)),
            ElementData::Token(token) if token.kind.is_trivia() => None,
            ElementData::Token(token) => Some(DefinitionPart::Token(token.kind)),
        })
        .collect()
}

struct PartCursor<'a> {
    parts: &'a [DefinitionPart],
    index: usize,
}

impl<'a> PartCursor<'a> {
    fn new(parts: &'a [DefinitionPart]) -> Self {
        Self { parts, index: 0 }
    }

    fn token(&mut self, kind: SyntaxKind) -> bool {
        self.take(DefinitionPart::Token(kind))
    }

    fn token_matching(&mut self, predicate: impl FnOnce(SyntaxKind) -> bool) -> bool {
        let Some(DefinitionPart::Token(kind)) = self.parts.get(self.index).copied() else {
            return false;
        };
        if !predicate(kind) {
            return false;
        }
        self.index += 1;
        true
    }

    fn node(&mut self, kind: SyntaxKind) -> bool {
        self.take(DefinitionPart::Node(kind))
    }

    fn optional_node(&mut self, kind: SyntaxKind) {
        let _ = self.node(kind);
    }

    fn type_syntax(&mut self) -> bool {
        let Some(DefinitionPart::Node(kind)) = self.parts.get(self.index).copied() else {
            return false;
        };
        if !TYPE_SYNTAX_KINDS.contains(&kind) {
            return false;
        }
        self.index += 1;
        true
    }

    fn peek_node(&self, kind: SyntaxKind) -> bool {
        self.parts.get(self.index) == Some(&DefinitionPart::Node(kind))
    }

    fn finish(self) -> bool {
        self.index == self.parts.len()
    }

    fn take(&mut self, expected: DefinitionPart) -> bool {
        if self.parts.get(self.index) != Some(&expected) {
            return false;
        }
        self.index += 1;
        true
    }
}

fn validate_value_assignment(parts: &[DefinitionPart], definition: &NodeData) -> bool {
    let mut cursor = PartCursor::new(parts);
    cursor.token_matching(SyntaxKind::is_identifier)
        && cursor.node(SyntaxKind::ObjectIdentifierSyntax)
        && find_node(definition, SyntaxKind::ObjectIdentifierSyntax)
            .is_some_and(|syntax| contains_token_kind(syntax, SyntaxKind::KwIdentifier))
        && cursor.token(SyntaxKind::ColonColonEqual)
        && cursor.node(SyntaxKind::OidAssignment)
        && complete_oid(definition)
        && cursor.finish()
}

fn validate_type_assignment(parts: &[DefinitionPart]) -> bool {
    let mut cursor = PartCursor::new(parts);
    cursor.token_matching(|kind| kind.is_identifier() || kind.is_type_keyword())
        && cursor.token(SyntaxKind::ColonColonEqual)
        && cursor.type_syntax()
        && cursor.finish()
}

fn validate_textual_convention(parts: &[DefinitionPart]) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(|kind| kind.is_identifier() || kind.is_type_keyword()) {
        return false;
    }
    let _ = cursor.token(SyntaxKind::ColonColonEqual);
    if !cursor.token(SyntaxKind::KwTextualConvention) {
        return false;
    }
    cursor.optional_node(SyntaxKind::DisplayHintClause);
    if !cursor.node(SyntaxKind::StatusClause) || !cursor.node(SyntaxKind::DescriptionClause) {
        return false;
    }
    cursor.optional_node(SyntaxKind::ReferenceClause);
    cursor.node(SyntaxKind::SyntaxClause) && cursor.finish()
}

fn validate_object_type(parts: &[DefinitionPart], definition: &NodeData) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(SyntaxKind::is_identifier)
        || !cursor.token(SyntaxKind::KwObjectType)
        || !cursor.node(SyntaxKind::SyntaxClause)
    {
        return false;
    }
    cursor.optional_node(SyntaxKind::UnitsClause);
    if !cursor.node(SyntaxKind::AccessClause) {
        return false;
    }
    cursor.optional_node(SyntaxKind::StatusClause);
    cursor.optional_node(SyntaxKind::DescriptionClause);
    cursor.optional_node(SyntaxKind::ReferenceClause);
    if cursor.peek_node(SyntaxKind::IndexClause) {
        let _ = cursor.node(SyntaxKind::IndexClause);
    } else {
        cursor.optional_node(SyntaxKind::AugmentsClause);
    }
    cursor.optional_node(SyntaxKind::DefvalClause);
    cursor.token(SyntaxKind::ColonColonEqual)
        && cursor.node(SyntaxKind::OidAssignment)
        && complete_oid(definition)
        && cursor.finish()
}

fn validate_module_identity(parts: &[DefinitionPart], definition: &NodeData) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(SyntaxKind::is_identifier)
        || !cursor.token(SyntaxKind::KwModuleIdentity)
        || !cursor.node(SyntaxKind::LastUpdatedClause)
        || !cursor.node(SyntaxKind::OrganizationClause)
        || !cursor.node(SyntaxKind::ContactInfoClause)
        || !cursor.node(SyntaxKind::DescriptionClause)
    {
        return false;
    }
    while cursor.peek_node(SyntaxKind::RevisionClause) {
        if !cursor.node(SyntaxKind::RevisionClause) || !cursor.node(SyntaxKind::DescriptionClause) {
            return false;
        }
    }
    cursor.token(SyntaxKind::ColonColonEqual)
        && cursor.node(SyntaxKind::OidAssignment)
        && complete_oid(definition)
        && cursor.finish()
}

fn validate_object_identity(parts: &[DefinitionPart], definition: &NodeData) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(SyntaxKind::is_identifier)
        || !cursor.token(SyntaxKind::KwObjectIdentity)
        || !cursor.node(SyntaxKind::StatusClause)
        || !cursor.node(SyntaxKind::DescriptionClause)
    {
        return false;
    }
    cursor.optional_node(SyntaxKind::ReferenceClause);
    cursor.token(SyntaxKind::ColonColonEqual)
        && cursor.node(SyntaxKind::OidAssignment)
        && complete_oid(definition)
        && cursor.finish()
}

fn validate_notification_type(parts: &[DefinitionPart], definition: &NodeData) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(SyntaxKind::is_identifier)
        || !cursor.token(SyntaxKind::KwNotificationType)
    {
        return false;
    }
    cursor.optional_node(SyntaxKind::ObjectsClause);
    if !cursor.node(SyntaxKind::StatusClause) || !cursor.node(SyntaxKind::DescriptionClause) {
        return false;
    }
    cursor.optional_node(SyntaxKind::ReferenceClause);
    cursor.token(SyntaxKind::ColonColonEqual)
        && cursor.node(SyntaxKind::OidAssignment)
        && complete_oid(definition)
        && cursor.finish()
}

fn validate_trap_type(parts: &[DefinitionPart]) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(SyntaxKind::is_identifier)
        || !cursor.token(SyntaxKind::KwTrapType)
        || !cursor.node(SyntaxKind::EnterpriseClause)
    {
        return false;
    }
    cursor.optional_node(SyntaxKind::VariablesClause);
    cursor.optional_node(SyntaxKind::DescriptionClause);
    cursor.optional_node(SyntaxKind::ReferenceClause);
    cursor.token(SyntaxKind::ColonColonEqual) && cursor.token(SyntaxKind::Number) && cursor.finish()
}

fn validate_macro_definition(
    parts: &[DefinitionPart],
    definition: &NodeData,
    document: &SourceDocument,
) -> bool {
    let mut cursor = PartCursor::new(parts);
    if !cursor.token_matching(|kind| kind == SyntaxKind::UppercaseIdent || kind.is_macro_keyword())
        || !cursor.token(SyntaxKind::KwMacro)
        || !cursor.token(SyntaxKind::OpaqueText)
        || !cursor.token(SyntaxKind::KwEnd)
        || !cursor.finish()
    {
        return false;
    }
    find_token(definition, SyntaxKind::OpaqueText).is_some_and(|body| {
        let text = document
            .slice(body.range)
            .expect("CST token belongs to retained document");
        macro_body_has_ordered_framing(text)
    })
}

fn complete_oid(definition: &NodeData) -> bool {
    find_node(definition, SyntaxKind::OidAssignment)
        .is_some_and(|oid| contains_token_kind(oid, SyntaxKind::RBrace))
}

fn macro_body_has_ordered_framing(text: &[u8]) -> bool {
    let mut cursor = 0usize;
    skip_macro_trivia(text, &mut cursor);
    if !text[cursor..].starts_with(b"::=") {
        return false;
    }
    cursor += 3;
    skip_macro_trivia(text, &mut cursor);
    if !text[cursor..].starts_with(b"BEGIN") {
        return false;
    }
    let after = cursor + 5;
    after == text.len()
        || text[after..].starts_with(b"--")
        || !matches!(text[after], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn skip_macro_trivia(text: &[u8], cursor: &mut usize) {
    loop {
        while *cursor < text.len() && text[*cursor].is_ascii_whitespace() {
            *cursor += 1;
        }
        if !text[*cursor..].starts_with(b"--") {
            return;
        }
        *cursor += 2;
        while *cursor < text.len() {
            if text[*cursor..].starts_with(b"--") {
                *cursor += 2;
                break;
            }
            if matches!(text[*cursor], b'\n' | b'\r') {
                break;
            }
            *cursor += 1;
        }
    }
}

fn contains_node_kind(node: &NodeData, kind: SyntaxKind) -> bool {
    find_node(node, kind).is_some()
}

fn find_node(node: &NodeData, kind: SyntaxKind) -> Option<&NodeData> {
    if node.kind == kind {
        return Some(node);
    }
    node.children.iter().find_map(|element| match element {
        ElementData::Node(child) => find_node(child, kind),
        ElementData::Token(_) => None,
    })
}

fn contains_token_kind(node: &NodeData, kind: SyntaxKind) -> bool {
    find_token(node, kind).is_some()
}

fn find_token(node: &NodeData, kind: SyntaxKind) -> Option<&TokenData> {
    node.children.iter().find_map(|element| match element {
        ElementData::Node(child) => find_token(child, kind),
        ElementData::Token(token) => (token.kind == kind).then_some(token),
    })
}
