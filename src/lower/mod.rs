//! Lowering pass: transforms an [`ast::Module`] into an
//! [`ir::Module`].
//!
//! Lowering normalizes SMIv1 and SMIv2 constructs into a unified IR,
//! detects the source language, flattens grouped imports into individual
//! entries, and runs validation checks (date formats, missing
//! MODULE-IDENTITY, required macro imports).

pub mod base_modules;
mod dates;

use std::collections::HashSet;

use crate::ast;
use crate::ir;
use crate::types::{DiagCode, Diagnostic, DiagnosticConfig, Language, Span, Status};
use tracing::{debug, debug_span, info_span};

/// Tracks state accumulated during the lowering pass: diagnostics,
/// detected language, and the line table for span-to-line conversion.
pub(crate) struct LoweringContext<'cfg> {
    pub diagnostics: Vec<Diagnostic>,
    pub language: Language,
    pub diag_config: &'cfg DiagnosticConfig,
    line_table: Vec<usize>,
    module_name: String,
}

impl<'cfg> LoweringContext<'cfg> {
    fn new(source: &[u8], diag_config: &'cfg DiagnosticConfig) -> Self {
        LoweringContext {
            diagnostics: Vec::new(),
            language: Language::Unknown,
            diag_config,
            line_table: crate::types::build_line_table(source),
            module_name: String::new(),
        }
    }

    /// Records a diagnostic if the current config allows it.
    pub(crate) fn emit_diagnostic(&mut self, code: DiagCode, span: Span, message: String) {
        if !self.diag_config.should_collect(code) {
            return;
        }
        let severity = self.diag_config.effective_severity(code);
        let (line, col) = crate::types::line_col_from_table(&self.line_table, span.start);
        self.diagnostics.push(Diagnostic {
            severity,
            code,
            message,
            module: Some(self.module_name.clone()),
            line: Some(line),
            column: Some(col),
        });
    }
}

/// Transforms an AST module into a normalized [`ir::Module`].
///
/// Lowering unifies SMIv1/SMIv2 constructs, flattens imports, and runs
/// validation checks. The `source` bytes are used to compute line/column
/// positions for diagnostics. The AST is not needed after this returns.
pub fn lower(ast_module: ast::Module, source: &[u8], diag_config: &DiagnosticConfig) -> ir::Module {
    let module_name = ast_module
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_default();
    let span = info_span!(
        target: "mib_rs::lower",
        "lower",
        component = "lower",
        module = %module_name,
        import_clause_count = ast_module.imports.len(),
        definition_count = ast_module.body.len(),
        byte_count = source.len(),
        reporting = ?diag_config.reporting,
    );
    let _guard = span.enter();

    let mut ctx = LoweringContext::new(source, diag_config);

    let mut module = ir::Module::new(module_name, ast_module.span);
    module.line_table = ctx.line_table.clone();
    ctx.module_name = module.name.clone();

    run_phase("imports", || {
        module.imports = lower_imports(&ast_module.imports);
        ctx.language = detect_language(&ast_module);
        module.language = ctx.language;
        debug!(
            target: "mib_rs::lower",
            component = "lower",
            phase = "imports",
            module = %module.name,
            import_count = module.imports.len(),
            language = ?module.language,
            "phase complete",
        );
    });

    run_phase("definitions", || {
        for def in &ast_module.body {
            if let Some(lowered) = lower_definition(def, &mut ctx) {
                module.definitions.push(lowered);
            }
        }
        let counts = DefinitionCounts::from_definitions(&module.definitions);
        debug!(
            target: "mib_rs::lower",
            component = "lower",
            phase = "definitions",
            module = %module.name,
            definition_count = module.definitions.len(),
            object_type_count = counts.object_types,
            module_identity_count = counts.module_identities,
            object_identity_count = counts.object_identities,
            notification_count = counts.notifications,
            type_def_count = counts.type_defs,
            value_assignment_count = counts.value_assignments,
            object_group_count = counts.object_groups,
            notification_group_count = counts.notification_groups,
            compliance_count = counts.compliances,
            capability_count = counts.capabilities,
            "phase complete",
        );
    });

    run_phase("checks", || {
        check_module_name_suffix(&mut ctx, &module);

        if module.language == Language::SMIv2 && !base_modules::is_base_module(&module.name) {
            check_module_identity(&mut ctx, &ast_module, &module);
            check_macro_imports(&mut ctx, &ast_module, &module);
        }
        debug!(
            target: "mib_rs::lower",
            component = "lower",
            phase = "checks",
            module = %module.name,
            diagnostic_count = ctx.diagnostics.len(),
            "phase complete",
        );
    });

    run_phase("diagnostics", || {
        // Convert AST span-based diagnostics to line/col diagnostics.
        for d in &ast_module.diagnostics {
            if !ctx.diag_config.should_collect(d.code) {
                continue;
            }
            let (line, col) = crate::types::line_col_from_table(&ctx.line_table, d.span.start);
            module.diagnostics.push(Diagnostic {
                severity: ctx.diag_config.effective_severity(d.code),
                code: d.code,
                message: d.message.clone(),
                module: Some(module.name.clone()),
                line: Some(line),
                column: Some(col),
            });
        }

        module.diagnostics.extend(ctx.diagnostics);
        debug!(
            target: "mib_rs::lower",
            component = "lower",
            phase = "diagnostics",
            module = %module.name,
            diagnostic_count = module.diagnostics.len(),
            "phase complete",
        );
    });

    let counts = DefinitionCounts::from_definitions(&module.definitions);
    debug!(
        target: "mib_rs::lower",
        component = "lower",
        module = %module.name,
        language = ?module.language,
        import_count = module.imports.len(),
        definition_count = module.definitions.len(),
        diagnostic_count = module.diagnostics.len(),
        object_type_count = counts.object_types,
        module_identity_count = counts.module_identities,
        object_identity_count = counts.object_identities,
        notification_count = counts.notifications,
        type_def_count = counts.type_defs,
        value_assignment_count = counts.value_assignments,
        object_group_count = counts.object_groups,
        notification_group_count = counts.notification_groups,
        compliance_count = counts.compliances,
        capability_count = counts.capabilities,
        "lower complete",
    );
    module
}

#[derive(Default)]
struct DefinitionCounts {
    object_types: usize,
    module_identities: usize,
    object_identities: usize,
    notifications: usize,
    type_defs: usize,
    value_assignments: usize,
    object_groups: usize,
    notification_groups: usize,
    compliances: usize,
    capabilities: usize,
}

impl DefinitionCounts {
    fn from_definitions(definitions: &[ir::Definition]) -> Self {
        let mut counts = Self::default();
        for definition in definitions {
            match definition {
                ir::Definition::ObjectType(_) => counts.object_types += 1,
                ir::Definition::ModuleIdentity(_) => counts.module_identities += 1,
                ir::Definition::ObjectIdentity(_) => counts.object_identities += 1,
                ir::Definition::Notification(_) => counts.notifications += 1,
                ir::Definition::TypeDef(_) => counts.type_defs += 1,
                ir::Definition::ValueAssignment(_) => counts.value_assignments += 1,
                ir::Definition::ObjectGroup(_) => counts.object_groups += 1,
                ir::Definition::NotificationGroup(_) => counts.notification_groups += 1,
                ir::Definition::ModuleCompliance(_) => counts.compliances += 1,
                ir::Definition::AgentCapabilities(_) => counts.capabilities += 1,
            }
        }
        counts
    }
}

fn run_phase<F>(phase: &'static str, f: F)
where
    F: FnOnce(),
{
    let span = debug_span!(
        target: "mib_rs::lower",
        "phase",
        component = "lower",
        phase = phase,
    );
    let _guard = span.enter();
    debug!(
        target: "mib_rs::lower",
        component = "lower",
        phase = phase,
        "starting phase",
    );
    f();
}

fn detect_language(module: &ast::Module) -> Language {
    if let Some(language) = base_modules::base_module_from_name(
        module.name.as_ref().map_or("", |name| name.name.as_str()),
    )
    .map(|base| base.language)
    {
        return language;
    }

    let mut has_smiv1_evidence = false;
    let mut has_smiv2_evidence = false;

    for clause in &module.imports {
        match base_modules::base_module_from_name(&clause.from_module.name)
            .map(|base| base.language)
        {
            Some(Language::SMIv1) => has_smiv1_evidence = true,
            Some(Language::SMIv2) => has_smiv2_evidence = true,
            _ => {}
        }
    }

    for definition in &module.body {
        match definition {
            ast::Definition::ModuleIdentity(_) => has_smiv2_evidence = true,
            ast::Definition::TrapType(_) => has_smiv1_evidence = true,
            _ => {}
        }
    }

    match (has_smiv1_evidence, has_smiv2_evidence) {
        (true, false) => Language::SMIv1,
        (false, true) => Language::SMIv2,
        _ => Language::Unknown,
    }
}

fn lower_imports(import_clauses: &[ast::ImportClause]) -> Vec<ir::Import> {
    let mut imports = Vec::new();

    for clause in import_clauses {
        let from_module = &clause.from_module.name;

        for symbol in &clause.symbols {
            imports.push(ir::Import {
                module: from_module.clone(),
                symbol: symbol.name.clone(),
                span: symbol.span,
            });
        }
    }

    imports
}

fn lower_definition(
    def: &ast::Definition,
    ctx: &mut LoweringContext<'_>,
) -> Option<ir::Definition> {
    match def {
        ast::Definition::ObjectType(d) => {
            Some(ir::Definition::ObjectType(lower_object_type(d, ctx)))
        }
        ast::Definition::ModuleIdentity(d) => Some(ir::Definition::ModuleIdentity(
            lower_module_identity(d, ctx),
        )),
        ast::Definition::ObjectIdentity(d) => Some(ir::Definition::ObjectIdentity(
            lower_object_identity(d, ctx),
        )),
        ast::Definition::NotificationType(d) => Some(ir::Definition::Notification(
            lower_notification_type(d, ctx),
        )),
        ast::Definition::TrapType(d) => Some(ir::Definition::Notification(lower_trap_type(d, ctx))),
        ast::Definition::TextualConvention(d) => {
            Some(ir::Definition::TypeDef(lower_textual_convention(d, ctx)))
        }
        ast::Definition::TypeAssignment(d) => {
            Some(ir::Definition::TypeDef(lower_type_assignment(d, ctx)))
        }
        ast::Definition::ValueAssignment(d) => Some(ir::Definition::ValueAssignment(
            lower_value_assignment(d, ctx),
        )),
        ast::Definition::ObjectGroup(d) => {
            Some(ir::Definition::ObjectGroup(lower_object_group(d, ctx)))
        }
        ast::Definition::NotificationGroup(d) => Some(ir::Definition::NotificationGroup(
            lower_notification_group(d, ctx),
        )),
        ast::Definition::ModuleCompliance(d) => Some(ir::Definition::ModuleCompliance(
            lower_module_compliance(d, ctx),
        )),
        ast::Definition::AgentCapabilities(d) => Some(ir::Definition::AgentCapabilities(
            lower_agent_capabilities(d, ctx),
        )),
        ast::Definition::MacroDefinition(d) => {
            if !base_modules::is_base_module(&ctx.module_name) {
                ctx.emit_diagnostic(
                    DiagCode::MacroNotAllowed,
                    d.span,
                    format!(
                        "MACRO definition {:?} not allowed outside base modules",
                        d.name.name
                    ),
                );
            }
            None
        }
        ast::Definition::Error(_) => None,
    }
}

// --- Helper functions ---

fn ident_names(idents: &[ast::Ident]) -> Vec<String> {
    idents.iter().map(|id| id.name.clone()).collect()
}

fn optional_string(qs: &Option<ast::QuotedString>) -> String {
    match qs {
        Some(qs) => qs.value.clone(),
        None => String::new(),
    }
}

fn optional_span(qs: &Option<ast::QuotedString>) -> Span {
    match qs {
        Some(qs) => qs.span,
        None => Span::ZERO,
    }
}

fn optional_status_span(s: &Option<ast::StatusClause>) -> Span {
    match s {
        Some(s) => s.span,
        None => Span::ZERO,
    }
}

fn check_empty_optional(
    ctx: &mut LoweringContext<'_>,
    qs: &Option<ast::QuotedString>,
    span: Span,
    def_name: &str,
    clause: &str,
    code: DiagCode,
) {
    if let Some(qs) = qs
        && qs.value.is_empty()
    {
        ctx.emit_diagnostic(
            code,
            span,
            format!("{:?}: empty {} clause", def_name, clause),
        );
    }
}

fn check_empty_required(
    ctx: &mut LoweringContext<'_>,
    value: &str,
    span: Span,
    def_name: &str,
    clause: &str,
    code: DiagCode,
) {
    if value.is_empty() {
        ctx.emit_diagnostic(
            code,
            span,
            format!("{:?}: empty {} clause", def_name, clause),
        );
    }
}

/// Check required DESCRIPTION and optional REFERENCE for emptiness.
/// Used by most SMIv2 definition types.
fn check_description_reference(
    ctx: &mut LoweringContext<'_>,
    description: &str,
    reference: &Option<ast::QuotedString>,
    span: Span,
    def_name: &str,
) {
    check_empty_required(
        ctx,
        description,
        span,
        def_name,
        "DESCRIPTION",
        DiagCode::EmptyDescription,
    );
    check_empty_optional(
        ctx,
        reference,
        span,
        def_name,
        "REFERENCE",
        DiagCode::EmptyReference,
    );
}

/// Check optional DESCRIPTION and optional REFERENCE for emptiness.
/// Used by definition types where DESCRIPTION is optional (e.g. OBJECT-TYPE, TRAP-TYPE).
fn check_optional_description_reference(
    ctx: &mut LoweringContext<'_>,
    description: &Option<ast::QuotedString>,
    reference: &Option<ast::QuotedString>,
    span: Span,
    def_name: &str,
) {
    check_empty_optional(
        ctx,
        description,
        span,
        def_name,
        "DESCRIPTION",
        DiagCode::EmptyDescription,
    );
    check_empty_optional(
        ctx,
        reference,
        span,
        def_name,
        "REFERENCE",
        DiagCode::EmptyReference,
    );
}

fn check_module_name_suffix(ctx: &mut LoweringContext<'_>, module: &ir::Module) {
    if module.language != Language::SMIv2 || base_modules::is_base_module(&module.name) {
        return;
    }
    if !module.name.ends_with("-MIB") {
        ctx.emit_diagnostic(
            DiagCode::ModuleNameSuffix,
            module.span,
            format!("module name {:?} does not end with -MIB", module.name),
        );
    }
}

fn check_module_identity(
    ctx: &mut LoweringContext<'_>,
    ast_module: &ast::Module,
    module: &ir::Module,
) {
    let mut module_identities: Vec<(usize, &ir::ModuleIdentity)> = Vec::new();
    for (i, def) in module.definitions.iter().enumerate() {
        if let ir::Definition::ModuleIdentity(mi) = def {
            module_identities.push((i, mi));
        }
    }

    if module_identities.is_empty() {
        ctx.emit_diagnostic(
            DiagCode::MissingModuleIdentity,
            module.span,
            format!("SMIv2 module {} lacks MODULE-IDENTITY", module.name),
        );
        return;
    }

    let (first_index, first_mi) = module_identities[0];

    // Check LAST-UPDATED has matching REVISION.
    check_revision_last_updated(ctx, first_mi);

    // Validate dates from AST (has per-date spans).
    let ast_mi = ast_module.body.iter().find_map(|def| {
        if let ast::Definition::ModuleIdentity(mi) = def {
            Some(mi)
        } else {
            None
        }
    });
    if let Some(ast_mi) = ast_mi {
        let revision_dates: Vec<(String, Span)> = ast_mi
            .revisions
            .iter()
            .map(|r| (r.date.value.clone(), r.date.span))
            .collect();
        dates::check_module_identity_dates(
            ctx,
            &ast_mi.last_updated.value,
            ast_mi.last_updated.span,
            &revision_dates,
        );
    }

    if first_index > 0 {
        ctx.emit_diagnostic(
            DiagCode::ModuleIdentityNotFirst,
            first_mi.span,
            format!(
                "MODULE-IDENTITY should be the first definition in {}",
                module.name
            ),
        );
    }

    for &(_, mi) in &module_identities[1..] {
        ctx.emit_diagnostic(
            DiagCode::ModuleIdentityMultiple,
            mi.span,
            format!("multiple MODULE-IDENTITY definitions in {}", module.name),
        );
    }
}

fn check_revision_last_updated(ctx: &mut LoweringContext<'_>, mi: &ir::ModuleIdentity) {
    if mi.last_updated.is_empty() {
        return;
    }
    for r in &mi.revisions {
        if r.date == mi.last_updated {
            return;
        }
    }
    ctx.emit_diagnostic(
        DiagCode::RevisionLastUpdated,
        mi.span,
        format!("revision for LAST-UPDATED {} is missing", mi.last_updated),
    );
}

fn check_macro_imports(
    ctx: &mut LoweringContext<'_>,
    ast_module: &ast::Module,
    module: &ir::Module,
) {
    let mut imported_macros = HashSet::new();
    for clause in &ast_module.imports {
        for sym in &clause.symbols {
            match sym.name.as_str() {
                "MODULE-IDENTITY" | "OBJECT-IDENTITY" | "OBJECT-TYPE" | "NOTIFICATION-TYPE"
                | "TEXTUAL-CONVENTION" | "OBJECT-GROUP" | "NOTIFICATION-GROUP"
                | "MODULE-COMPLIANCE" | "AGENT-CAPABILITIES" => {
                    imported_macros.insert(sym.name.as_str());
                }
                _ => {}
            }
        }
    }

    let mut used_macros = HashSet::new();
    for def in &module.definitions {
        match def {
            ir::Definition::ModuleIdentity(_) => {
                used_macros.insert("MODULE-IDENTITY");
            }
            ir::Definition::ObjectIdentity(_) => {
                used_macros.insert("OBJECT-IDENTITY");
            }
            ir::Definition::ObjectType(_) => {
                used_macros.insert("OBJECT-TYPE");
            }
            ir::Definition::Notification(n) => {
                if n.trap_info.is_none() {
                    used_macros.insert("NOTIFICATION-TYPE");
                }
            }
            ir::Definition::TypeDef(td) => {
                if td.is_textual_convention {
                    used_macros.insert("TEXTUAL-CONVENTION");
                }
            }
            ir::Definition::ObjectGroup(_) => {
                used_macros.insert("OBJECT-GROUP");
            }
            ir::Definition::NotificationGroup(_) => {
                used_macros.insert("NOTIFICATION-GROUP");
            }
            ir::Definition::ModuleCompliance(_) => {
                used_macros.insert("MODULE-COMPLIANCE");
            }
            ir::Definition::AgentCapabilities(_) => {
                used_macros.insert("AGENT-CAPABILITIES");
            }
            ir::Definition::ValueAssignment(_) => {}
        }
    }

    for macro_name in &used_macros {
        if !imported_macros.contains(macro_name) {
            ctx.emit_diagnostic(
                DiagCode::MacroNotImported,
                module.span,
                format!("{} used but not imported in {}", macro_name, module.name),
            );
        }
    }
}

// --- Definition lowering ---

fn lower_object_type(def: &ast::ObjectTypeDef, ctx: &mut LoweringContext<'_>) -> ir::ObjectType {
    let name = &def.name.name;
    check_optional_description_reference(ctx, &def.description, &def.reference, def.span, name);
    check_empty_optional(
        ctx,
        &def.units,
        def.span,
        name,
        "UNITS",
        DiagCode::EmptyUnits,
    );

    let augments = def
        .augments
        .as_ref()
        .map(|a| a.target.name.clone())
        .unwrap_or_default();

    let access = def.access.as_ref().map(|a| a.value).unwrap_or_default();
    let access_keyword = def.access.as_ref().map(|a| a.keyword).unwrap_or_default();
    let syntax = if let Some(s) = def.syntax.as_ref() {
        lower_type_syntax(&s.syntax, ctx)
    } else {
        // Go lowering emits unknown-type-syntax for malformed/missing syntax and
        // falls back to OCTET STRING.
        ctx.emit_diagnostic(
            DiagCode::UnknownTypeSyntax,
            def.span,
            "unknown type syntax <missing>, defaulting to OCTET STRING".to_string(),
        );
        ir::TypeSyntax::OctetString { span: def.span }
    };

    ir::ObjectType {
        name: name.clone(),
        span: def.span,
        syntax,
        units: optional_string(&def.units),
        access,
        access_keyword,
        status: def
            .status
            .as_ref()
            .map(|s| s.value)
            .unwrap_or(Status::Current),
        description: optional_string(&def.description),
        has_description: def.description.is_some(),
        reference: optional_string(&def.reference),
        index: lower_index_clause(&def.index),
        augments,
        defval: lower_optional_defval(&def.defval, ctx),
        oid: lower_oid_assignment(&def.oid),
        syntax_span: def.syntax.as_ref().map(|s| s.span).unwrap_or(Span::ZERO),
        access_span: def.access.as_ref().map(|a| a.span).unwrap_or(Span::ZERO),
        status_span: optional_status_span(&def.status),
        description_span: optional_span(&def.description),
        units_span: optional_span(&def.units),
        reference_span: optional_span(&def.reference),
        index_span: def.index.as_ref().map(|i| i.span).unwrap_or(Span::ZERO),
        augments_span: def.augments.as_ref().map(|a| a.span).unwrap_or(Span::ZERO),
        defval_span: def.defval.as_ref().map(|d| d.span).unwrap_or(Span::ZERO),
    }
}

fn lower_module_identity(
    def: &ast::ModuleIdentityDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::ModuleIdentity {
    let name = &def.name.name;
    check_empty_required(
        ctx,
        &def.description.value,
        def.span,
        name,
        "DESCRIPTION",
        DiagCode::EmptyDescription,
    );
    check_empty_required(
        ctx,
        &def.organization.value,
        def.span,
        name,
        "ORGANIZATION",
        DiagCode::EmptyOrganization,
    );
    check_empty_required(
        ctx,
        &def.contact_info.value,
        def.span,
        name,
        "CONTACT-INFO",
        DiagCode::EmptyContact,
    );

    let revisions = def
        .revisions
        .iter()
        .map(|r| {
            if r.description.value.is_empty() {
                ctx.emit_diagnostic(
                    DiagCode::EmptyRevisionDescription,
                    r.span,
                    format!("{:?}: empty REVISION DESCRIPTION clause", name),
                );
            }
            ir::Revision {
                date: r.date.value.clone(),
                description: r.description.value.clone(),
                span: r.span,
            }
        })
        .collect();

    ir::ModuleIdentity {
        name: name.clone(),
        span: def.span,
        last_updated: def.last_updated.value.clone(),
        organization: def.organization.value.clone(),
        contact_info: def.contact_info.value.clone(),
        description: def.description.value.clone(),
        revisions,
        oid: lower_oid_assignment(&def.oid),
    }
}

fn lower_object_identity(
    def: &ast::ObjectIdentityDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::ObjectIdentity {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);

    ir::ObjectIdentity {
        name: name.clone(),
        span: def.span,
        status: def.status.value,
        description: def.description.value.clone(),
        reference: optional_string(&def.reference),
        oid: lower_oid_assignment(&def.oid),
    }
}

fn lower_notification_type(
    def: &ast::NotificationTypeDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::Notification {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);

    let oid = lower_oid_assignment(&def.oid);
    ir::Notification {
        name: name.clone(),
        span: def.span,
        objects: ident_names(&def.objects),
        status: def.status.value,
        description: def.description.value.clone(),
        has_description: true,
        reference: optional_string(&def.reference),
        trap_info: None,
        oid: Some(oid),
    }
}

fn lower_trap_type(def: &ast::TrapTypeDef, ctx: &mut LoweringContext<'_>) -> ir::Notification {
    let name = &def.name.name;
    check_optional_description_reference(ctx, &def.description, &def.reference, def.span, name);

    ir::Notification {
        name: name.clone(),
        span: def.span,
        objects: ident_names(&def.variables),
        status: Status::Current,
        description: optional_string(&def.description),
        has_description: def.description.is_some(),
        reference: optional_string(&def.reference),
        trap_info: Some(ir::TrapInfo {
            enterprise: def.enterprise.name.clone(),
            trap_number: def.trap_number,
        }),
        oid: None,
    }
}

fn lower_textual_convention(
    def: &ast::TextualConventionDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::TypeDef {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);
    check_empty_optional(
        ctx,
        &def.display_hint,
        def.span,
        name,
        "DISPLAY-HINT",
        DiagCode::EmptyFormat,
    );

    ir::TypeDef {
        name: name.clone(),
        span: def.span,
        syntax: lower_type_syntax(&def.syntax.syntax, ctx),
        base_type: None,
        display_hint: optional_string(&def.display_hint),
        status: def.status.value,
        description: def.description.value.clone(),
        reference: optional_string(&def.reference),
        is_textual_convention: true,
        syntax_span: def.syntax.span,
        status_span: def.status.span,
        description_span: def.description.span,
        reference_span: optional_span(&def.reference),
        display_hint_span: optional_span(&def.display_hint),
    }
}

fn lower_type_assignment(
    def: &ast::TypeAssignmentDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::TypeDef {
    ir::TypeDef {
        name: def.name.name.clone(),
        span: def.span,
        syntax: lower_type_syntax(&def.syntax, ctx),
        base_type: None,
        display_hint: String::new(),
        status: Status::Current,
        description: String::new(),
        reference: String::new(),
        is_textual_convention: false,
        syntax_span: def.syntax.span(),
        status_span: Span::ZERO,
        description_span: Span::ZERO,
        reference_span: Span::ZERO,
        display_hint_span: Span::ZERO,
    }
}

fn lower_value_assignment(
    def: &ast::ValueAssignmentDef,
    _ctx: &mut LoweringContext<'_>,
) -> ir::ValueAssignment {
    ir::ValueAssignment {
        name: def.name.name.clone(),
        span: def.span,
        oid: lower_oid_assignment(&def.oid),
        description: String::new(),
        reference: String::new(),
    }
}

fn lower_object_group(def: &ast::ObjectGroupDef, ctx: &mut LoweringContext<'_>) -> ir::ObjectGroup {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);

    ir::ObjectGroup {
        name: name.clone(),
        span: def.span,
        objects: ident_names(&def.objects),
        status: def.status.value,
        description: def.description.value.clone(),
        reference: optional_string(&def.reference),
        oid: lower_oid_assignment(&def.oid),
    }
}

fn lower_notification_group(
    def: &ast::NotificationGroupDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::NotificationGroup {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);

    ir::NotificationGroup {
        name: name.clone(),
        span: def.span,
        notifications: ident_names(&def.notifications),
        status: def.status.value,
        description: def.description.value.clone(),
        reference: optional_string(&def.reference),
        oid: lower_oid_assignment(&def.oid),
    }
}

fn lower_module_compliance(
    def: &ast::ModuleComplianceDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::ModuleCompliance {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);

    let modules = def
        .modules
        .iter()
        .map(|m| lower_compliance_module(m, ctx))
        .collect();

    ir::ModuleCompliance {
        name: name.clone(),
        span: def.span,
        status: def.status.value,
        description: def.description.value.clone(),
        reference: optional_string(&def.reference),
        modules,
        oid: lower_oid_assignment(&def.oid),
    }
}

fn lower_compliance_module(
    m: &ast::ComplianceModule,
    ctx: &mut LoweringContext<'_>,
) -> ir::ComplianceModule {
    let mut groups = Vec::new();
    let mut objects = Vec::new();

    for c in &m.compliances {
        match c {
            ast::Compliance::Group(g) => {
                groups.push(ir::ComplianceGroup {
                    group: g.group.name.clone(),
                    description: g.description.value.clone(),
                    span: g.span,
                });
            }
            ast::Compliance::Object(o) => {
                objects.push(lower_compliance_object(o, ctx));
            }
        }
    }

    let module_name = m
        .module_name
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_default();

    ir::ComplianceModule {
        module_name,
        mandatory_groups: ident_names(&m.mandatory_groups),
        groups,
        objects,
        span: m.span,
    }
}

fn lower_compliance_object(
    o: &ast::ComplianceObject,
    ctx: &mut LoweringContext<'_>,
) -> ir::ComplianceObject {
    ir::ComplianceObject {
        object: o.object.name.clone(),
        syntax: o.syntax.as_ref().map(|s| lower_type_syntax(&s.syntax, ctx)),
        write_syntax: o
            .write_syntax
            .as_ref()
            .map(|s| lower_type_syntax(&s.syntax, ctx)),
        min_access: o.min_access.as_ref().map(|a| a.value),
        description: o.description.value.clone(),
        span: o.span,
    }
}

fn lower_agent_capabilities(
    def: &ast::AgentCapabilitiesDef,
    ctx: &mut LoweringContext<'_>,
) -> ir::AgentCapabilities {
    let name = &def.name.name;
    check_description_reference(ctx, &def.description.value, &def.reference, def.span, name);

    let supports = def
        .supports
        .iter()
        .map(|s| lower_supports_module(s, ctx))
        .collect();

    ir::AgentCapabilities {
        name: name.clone(),
        span: def.span,
        product_release: def.product_release.value.clone(),
        status: def.status.value,
        description: def.description.value.clone(),
        reference: optional_string(&def.reference),
        supports,
        oid: lower_oid_assignment(&def.oid),
    }
}

fn lower_supports_module(
    s: &ast::SupportsModule,
    ctx: &mut LoweringContext<'_>,
) -> ir::SupportsModule {
    let variations = s
        .variations
        .iter()
        .map(|v| lower_variation(v, ctx))
        .collect();

    ir::SupportsModule {
        module_name: s.module_name.name.clone(),
        includes: ident_names(&s.includes),
        variations,
        span: s.span,
    }
}

fn lower_variation(v: &ast::Variation, ctx: &mut LoweringContext<'_>) -> ir::Variation {
    ir::Variation {
        name: v.name.name.clone(),
        syntax: v.syntax.as_ref().map(|s| lower_type_syntax(&s.syntax, ctx)),
        write_syntax: v
            .write_syntax
            .as_ref()
            .map(|s| lower_type_syntax(&s.syntax, ctx)),
        access: v.access.as_ref().map(|a| a.value),
        creation_requires: ident_names(&v.creation_requires),
        defval: lower_optional_defval(&v.defval, ctx),
        description: v.description.value.clone(),
        span: v.span,
    }
}

// --- Type syntax lowering ---

fn lower_type_syntax(syntax: &ast::TypeSyntax, ctx: &mut LoweringContext<'_>) -> ir::TypeSyntax {
    match syntax {
        ast::TypeSyntax::TypeRef(ident) => ir::TypeSyntax::TypeRef {
            name: ident.name.clone(),
            span: ident.span,
        },

        ast::TypeSyntax::IntegerEnum {
            base,
            named_numbers,
            span,
        } => {
            let mut seen_names = HashSet::new();
            let mut seen_values = HashSet::new();
            let mut lowered = Vec::with_capacity(named_numbers.len());

            for nn in named_numbers {
                if !seen_names.insert(&nn.name.name) {
                    ctx.emit_diagnostic(
                        DiagCode::EnumNameRedefinition,
                        nn.span,
                        format!("duplicate enum name {:?}", nn.name.name),
                    );
                }
                if !seen_values.insert(nn.value) {
                    ctx.emit_diagnostic(
                        DiagCode::EnumValueRedefinition,
                        nn.span,
                        format!("duplicate enum value {}", nn.value),
                    );
                }
                if i32::try_from(nn.value).is_err() {
                    ctx.emit_diagnostic(
                        DiagCode::EnumValueOutOfRange,
                        nn.span,
                        format!("enum value {} is outside the Integer32 range", nn.value),
                    );
                }
                if nn.value == 0 && ctx.language == Language::SMIv1 {
                    ctx.emit_diagnostic(
                        DiagCode::EnumZero,
                        nn.span,
                        format!(
                            "enumeration contains zero value {:?}(0) in SMIv1 module",
                            nn.name.name
                        ),
                    );
                }
                lowered.push(ir::NamedNumber {
                    name: nn.name.name.clone(),
                    value: nn.value,
                    span: nn.span,
                });
            }

            let base_name = base.as_ref().map(|b| b.name.clone()).unwrap_or_default();

            ir::TypeSyntax::IntegerEnum {
                base: base_name,
                named_numbers: lowered,
                span: *span,
            }
        }

        ast::TypeSyntax::Bits { named_bits, span } => {
            let mut seen_names = HashSet::new();
            let mut seen_positions = HashSet::new();
            let mut lowered = Vec::with_capacity(named_bits.len());

            for nb in named_bits {
                if !seen_names.insert(&nb.name.name) {
                    ctx.emit_diagnostic(
                        DiagCode::BitsNameRedefinition,
                        nb.span,
                        format!("duplicate BITS name {:?}", nb.name.name),
                    );
                }
                if !seen_positions.insert(nb.value) {
                    ctx.emit_diagnostic(
                        DiagCode::BitsValueRedefinition,
                        nb.span,
                        format!("duplicate BITS position {}", nb.value),
                    );
                }
                let pos = nb.value;
                let position = if pos < 0 {
                    ctx.emit_diagnostic(
                        DiagCode::BitsNumberNegative,
                        nb.span,
                        format!("negative BITS position {} for {:?}", pos, nb.name.name),
                    );
                    0
                } else if pos >= 65535 * 8 {
                    ctx.emit_diagnostic(
                        DiagCode::BitsNumberTooLarge,
                        nb.span,
                        format!(
                            "BITS position {} for {:?} exceeds maximum ({})",
                            pos,
                            nb.name.name,
                            65535 * 8 - 1
                        ),
                    );
                    0
                } else {
                    if pos >= 128 {
                        ctx.emit_diagnostic(
                            DiagCode::BitsNumberLarge,
                            nb.span,
                            format!(
                                "BITS position {} for {:?} may cause interoperability problems",
                                pos, nb.name.name
                            ),
                        );
                    }
                    pos as u32
                };
                lowered.push(ir::NamedBit {
                    name: nb.name.name.clone(),
                    position,
                    span: nb.span,
                });
            }

            ir::TypeSyntax::Bits {
                named_bits: lowered,
                span: *span,
            }
        }

        ast::TypeSyntax::Constrained {
            base,
            constraint,
            span,
        } => ir::TypeSyntax::Constrained {
            base: Box::new(lower_type_syntax(base, ctx)),
            constraint: lower_constraint(constraint, ctx),
            span: *span,
        },

        ast::TypeSyntax::SequenceOf { entry_type, span } => ir::TypeSyntax::SequenceOf {
            entry_type: entry_type.name.clone(),
            span: *span,
        },

        ast::TypeSyntax::Sequence { fields, span } => {
            let lowered = fields
                .iter()
                .map(|f| ir::SequenceField {
                    name: f.name.name.clone(),
                    syntax: lower_type_syntax(&f.syntax, ctx),
                    span: f.span,
                })
                .collect();
            ir::TypeSyntax::Sequence {
                fields: lowered,
                span: *span,
            }
        }

        ast::TypeSyntax::Choice {
            alternatives, span, ..
        } => {
            if !base_modules::is_base_module(&ctx.module_name) {
                ctx.emit_diagnostic(
                    DiagCode::ChoiceNotAllowed,
                    *span,
                    format!(
                        "CHOICE type not allowed outside base module {:?}",
                        ctx.module_name
                    ),
                );
            }
            if let Some(first) = alternatives.first() {
                lower_type_syntax(&first.syntax, ctx)
            } else {
                ir::TypeSyntax::OctetString { span: *span }
            }
        }

        ast::TypeSyntax::Tagged {
            underlying, span, ..
        } => {
            if !base_modules::is_base_module(&ctx.module_name) {
                ctx.emit_diagnostic(
                    DiagCode::TaggedTypeNotAllowed,
                    *span,
                    format!(
                        "tagged type not allowed outside base module {:?}",
                        ctx.module_name
                    ),
                );
            }
            lower_type_syntax(underlying, ctx)
        }

        ast::TypeSyntax::OctetString { span } => ir::TypeSyntax::OctetString { span: *span },
        ast::TypeSyntax::ObjectIdentifier { span } => {
            ir::TypeSyntax::ObjectIdentifier { span: *span }
        }
    }
}

fn lower_constraint(constraint: &ast::Constraint, ctx: &mut LoweringContext<'_>) -> ir::Constraint {
    match constraint {
        ast::Constraint::Size { ranges, span } => ir::Constraint::Size {
            ranges: lower_ranges(ranges, ctx),
            span: *span,
        },
        ast::Constraint::Range { ranges, span } => ir::Constraint::Range {
            ranges: lower_ranges(ranges, ctx),
            span: *span,
        },
    }
}

fn lower_ranges(ranges: &[ast::Range], ctx: &mut LoweringContext<'_>) -> Vec<ir::Range> {
    ranges.iter().map(|r| lower_range(r, ctx)).collect()
}

fn lower_range(r: &ast::Range, ctx: &mut LoweringContext<'_>) -> ir::Range {
    ir::Range {
        min: lower_range_value(&r.min, ctx),
        max: r.max.as_ref().map(|v| lower_range_value(v, ctx)),
        span: r.span,
    }
}

fn lower_range_value(value: &ast::RangeValue, ctx: &mut LoweringContext<'_>) -> ir::RangeValue {
    match value {
        ast::RangeValue::Signed(v) => ir::RangeValue::Signed(*v),
        ast::RangeValue::Unsigned(v) => ir::RangeValue::Unsigned(*v),
        ast::RangeValue::Named(ident) => match ident.name.as_str() {
            "MIN" => {
                ctx.emit_diagnostic(
                    DiagCode::MinMaxRange,
                    ident.span,
                    "MIN is not valid in SMI constraints; preserving it as an open endpoint"
                        .to_string(),
                );
                ir::RangeValue::Min
            }
            "MAX" => {
                ctx.emit_diagnostic(
                    DiagCode::MinMaxRange,
                    ident.span,
                    "MAX is not valid in SMI constraints; preserving it as an open endpoint"
                        .to_string(),
                );
                ir::RangeValue::Max
            }
            _ => {
                ctx.emit_diagnostic(
                    DiagCode::UnknownRangeValue,
                    ident.span,
                    format!("unknown range identifier {}, defaulting to 0", ident.name),
                );
                ir::RangeValue::Unsigned(0)
            }
        },
    }
}

// --- OID lowering ---

fn lower_oid_assignment(oid: &ast::OidAssignment) -> ir::OidAssignment {
    ir::OidAssignment {
        components: oid.components.iter().map(lower_oid_component).collect(),
        span: oid.span,
    }
}

fn lower_oid_component(comp: &ast::OidComponent) -> ir::OidComponent {
    match comp {
        ast::OidComponent::Name(ident) => ir::OidComponent::Name {
            name: ident.name.clone(),
            span: ident.span,
        },
        ast::OidComponent::Number { value, span } => ir::OidComponent::Number {
            value: *value,
            span: *span,
        },
        ast::OidComponent::NamedNumber { name, num, span } => ir::OidComponent::NamedNumber {
            name: name.name.clone(),
            number: *num,
            span: *span,
        },
        ast::OidComponent::QualifiedName {
            module_name,
            name,
            span,
        } => ir::OidComponent::QualifiedName {
            module: module_name.name.clone(),
            name: name.name.clone(),
            span: *span,
        },
        ast::OidComponent::QualifiedNamedNumber {
            module_name,
            name,
            num,
            span,
        } => ir::OidComponent::QualifiedNamedNumber {
            module: module_name.name.clone(),
            name: name.name.clone(),
            number: *num,
            span: *span,
        },
    }
}

// --- Index + DefVal lowering ---

fn lower_index_clause(clause: &Option<ast::IndexClause>) -> Vec<ir::IndexItem> {
    match clause {
        Some(clause) => clause
            .items
            .iter()
            .map(|idx| ir::IndexItem {
                implied: idx.implied,
                object: idx.object.name.clone(),
                span: idx.span,
            })
            .collect(),
        None => Vec::new(),
    }
}

fn lower_optional_defval(
    clause: &Option<ast::DefValClause>,
    ctx: &mut LoweringContext<'_>,
) -> Option<ir::DefVal> {
    clause.as_ref().map(|c| lower_defval(&c.value, ctx))
}

fn lower_defval(content: &ast::DefVal, _ctx: &mut LoweringContext<'_>) -> ir::DefVal {
    match content {
        ast::DefVal::Integer(v) => ir::DefVal::Integer(*v),
        ast::DefVal::Unsigned(v) => ir::DefVal::Unsigned(*v),
        ast::DefVal::String(qs) => ir::DefVal::String(qs.value.clone()),
        ast::DefVal::Identifier(ident) => ir::DefVal::Enum(ident.name.clone()),
        ast::DefVal::Bits { labels, .. } => ir::DefVal::Bits {
            labels: labels.iter().map(|l| l.name.clone()).collect(),
        },
        ast::DefVal::HexString { content, .. } => ir::DefVal::HexString(content.clone()),
        ast::DefVal::BinaryString { content, .. } => ir::DefVal::BinaryString(content.clone()),
        ast::DefVal::ObjectIdentifier { components, .. } => ir::DefVal::OidValue {
            components: components.iter().map(lower_oid_component).collect(),
        },
        ast::DefVal::Unparsed { .. } => ir::DefVal::Unparsed,
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{Access, AccessKeyword, DiagCode, DiagnosticConfig, Span};

    use super::*;

    #[test]
    fn object_type_missing_syntax_emits_unknown_type_syntax() {
        let source = b"";
        let mut module = ast::Module::new(
            ast::Ident {
                name: "TEST-MIB".to_string(),
                span: Span::ZERO,
            },
            Span::ZERO,
        );
        module
            .body
            .push(ast::Definition::ObjectType(ast::ObjectTypeDef {
                name: ast::Ident {
                    name: "testObject".to_string(),
                    span: Span::ZERO,
                },
                span: Span::ZERO,
                syntax: None,
                units: None,
                access: Some(ast::AccessClause {
                    keyword: AccessKeyword::Access,
                    value: Access::ReadOnly,
                    span: Span::ZERO,
                }),
                status: None,
                description: None,
                reference: None,
                index: None,
                augments: None,
                defval: None,
                oid: ast::OidAssignment {
                    components: vec![ast::OidComponent::Number {
                        value: 1,
                        span: Span::ZERO,
                    }],
                    span: Span::ZERO,
                },
            }));

        let cfg = DiagnosticConfig::verbose();
        let lowered = lower(module, source, &cfg);

        assert!(
            lowered
                .diagnostics
                .iter()
                .any(|d| d.code == DiagCode::UnknownTypeSyntax)
        );
    }

    #[test]
    fn revision_empty_description_emits_diagnostic() {
        let source = b"";
        let mut module = ast::Module::new(
            ast::Ident {
                name: "TEST-MIB".to_string(),
                span: Span::ZERO,
            },
            Span::ZERO,
        );
        module
            .body
            .push(ast::Definition::ModuleIdentity(ast::ModuleIdentityDef {
                name: ast::Ident {
                    name: "testMIB".to_string(),
                    span: Span::ZERO,
                },
                span: Span::ZERO,
                last_updated: ast::QuotedString {
                    value: "200301090000Z".to_string(),
                    span: Span::ZERO,
                },
                organization: ast::QuotedString {
                    value: "Test Org".to_string(),
                    span: Span::ZERO,
                },
                contact_info: ast::QuotedString {
                    value: "Test Contact".to_string(),
                    span: Span::ZERO,
                },
                description: ast::QuotedString {
                    value: "Test module".to_string(),
                    span: Span::ZERO,
                },
                revisions: vec![ast::RevisionClause {
                    date: ast::QuotedString {
                        value: "200301090000Z".to_string(),
                        span: Span::ZERO,
                    },
                    description: ast::QuotedString {
                        value: "".to_string(),
                        span: Span::ZERO,
                    },
                    span: Span::ZERO,
                }],
                oid: ast::OidAssignment {
                    components: vec![ast::OidComponent::Number {
                        value: 1,
                        span: Span::ZERO,
                    }],
                    span: Span::ZERO,
                },
            }));

        let cfg = DiagnosticConfig::verbose();
        let lowered = lower(module, source, &cfg);

        assert!(
            lowered
                .diagnostics
                .iter()
                .any(|d| d.code == DiagCode::EmptyRevisionDescription),
            "expected EmptyRevisionDescription diagnostic, got: {:?}",
            lowered
                .diagnostics
                .iter()
                .map(|d| d.code)
                .collect::<Vec<_>>()
        );
    }
}
